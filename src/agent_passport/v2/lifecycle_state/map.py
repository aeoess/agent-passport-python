# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Expressing an existing chain-verification result in the lifecycle
vocabulary.

This is a READ-ONLY view. It takes an ``AuthorityValidationResult`` that
``verify_authority_delegation_chain`` already produced and says what that result looks
like in the six-value vocabulary. It never mutates the input, it is never called from
the verification path, and a caller that does not import it sees no change whatever. The
draft-03 four-value result stays a four-value result; this is reported ALONGSIDE it. See
``types.CompositeAuthorityResult``.

What this mapping CANNOT produce, and why: ``suspended`` and ``restricted`` never appear,
because draft-03 chain verification has no concept of a suspension or restriction cause
and the module that owns cause sets is a separate proposed surface. The ``freshness``
limb never appears either, because chain verification takes a revocation resolver that
answers active, revoked or unknown with no declared bound attached; the module that owns
multi-source status observation owns freshness. A mapping that invented either would be
claiming a finding the verifier never made.

Python port of the TypeScript SDK's src/v2/lifecycle-state/map.ts.
"""

from __future__ import annotations

from typing import Any

from .state import lifecycle_state
from .types import LifecycleStateResult

#: Which establishment limb a chain failure code leaves missing.
#:
#: Only codes chain verification can reach on an indeterminate or unsupported state
#: appear. Everything unlisted falls back to ``source``, which is the honest default: the
#: verifier had no usable answer it accepts, and it is not claiming a freshness bound it
#: was never given or coverage it was never told about.
_GAPS_BY_CODE: dict[str, tuple[str, ...]] = {
    # The resolver answered "unknown": no accepted source produced a usable determinate
    # answer.
    "REVOCATION_UNKNOWN": ("source",),
    "KEY_RESOLUTION_FAILED": ("source",),
    "KEY_NOT_FOUND": ("source",),
    "KEY_AMBIGUOUS": ("source",),
    "KEY_UNREACHABLE": ("source",),
    "KEY_MATERIAL_MALFORMED": ("source",),
    "KEY_SCHEME_UNSUPPORTED": ("source",),
    # A ceiling this implementation imposes: it declined to judge the whole record, so
    # what the answer does not cover is the record itself.
    "RESOURCE_LIMIT": ("coverage",),
    "UNSUPPORTED_VERSION": ("source",),
    "UNSUPPORTED_RECORD_TYPE": ("source",),
    "UNSUPPORTED_PROFILE": ("source",),
}

_DEFAULT_GAPS: tuple[str, ...] = ("source",)


def _codes(result: Any) -> list[str]:
    failures = getattr(result, "failures", None) or ()
    return [getattr(f, "code", None) or "" for f in failures]


def map_authority_validation_to_lifecycle(
    result: Any,
    *,
    not_yet_valid_as_not_yet_effective: bool = True,
) -> LifecycleStateResult:
    """Express an ``AuthorityValidationResult`` in the six-value lifecycle vocabulary.

    =============== ==================================================================
    chain state     lifecycle verdict
    =============== ==================================================================
    ``valid``       ``valid``, reason ``CHAIN_VALID``
    ``invalid``     ``invalid``, reason = the first failure code (see the keyword
                    argument for the one exception, ``NOT_YET_VALID``)
    ``indeterminate`` ``not_established``, reason = the first failure code, ``missing``
                    from that code
    ``unsupported`` ``not_established``, reason = the first failure code, ``missing``
                    ``("source",)``
    =============== ==================================================================

    ``not_yet_valid_as_not_yet_effective`` (default ``True``): draft-03 chain
    verification reports a delegation whose ``time.not_before`` has not been reached as
    ``invalid`` with failure code ``NOT_YET_VALID``. Under the six-value vocabulary that
    is a positive finding about a validly issued grant whose enabling date has not
    arrived, whose remedy is to wait, which is ``not_yet_effective``, not ``invalid``.
    It applies ONLY when ``NOT_YET_VALID`` is the sole failure code in the result; a
    result carrying it alongside any other failure maps to ``invalid`` on that other
    failure, because something more than the date is wrong. Pass ``False`` to keep the
    chain's own reading. The reading is contested: the ``activation-not-established``
    fixture records the present SDK behaviour as its family's central vagueness finding
    rather than asserting either answer is correct, so the switch exists. Concept source:
    aeoess/agent-authority-lifecycle, invariant candidate CAND-04. Proposed.

    ``unsupported`` mapping to ``not_established`` is a judgment call worth naming.
    Draft-03 keeps ``unsupported`` as its own value, and this vocabulary has no member
    for it. A verifier that declines to judge a record it does not recognise has not
    reached a conclusion about the artifact, which is the evidential sense of not
    established, and the missing limb is source: the record is unrecognised. The original
    chain result is unchanged and still says ``unsupported``, so nothing is lost by
    reporting both.

    Reported alongside the chain result, never in place of it.
    Proposed. Concept source: aeoess/agent-authority-lifecycle.
    """
    state = getattr(result, "state", None)
    codes = _codes(result)

    if state == "valid":
        return lifecycle_state(verdict="valid", reason_code="CHAIN_VALID")

    if state == "invalid":
        only_not_yet_valid = bool(codes) and all(c == "NOT_YET_VALID" for c in codes)
        if not_yet_valid_as_not_yet_effective and only_not_yet_valid:
            return lifecycle_state(
                verdict="not_yet_effective", reason_code="NOT_BEFORE_UNREACHED"
            )
        named = next((c for c in codes if c != "NOT_YET_VALID"), None)
        if named is None:
            named = codes[0] if codes else "CHAIN_INVALID"
        return lifecycle_state(verdict="invalid", reason_code=named or "CHAIN_INVALID")

    if state == "indeterminate":
        code = codes[0] if codes and codes[0] else "CHAIN_INDETERMINATE"
        return lifecycle_state(
            verdict="not_established",
            reason_code=code,
            missing=_GAPS_BY_CODE.get(code, _DEFAULT_GAPS),
        )

    if state == "unsupported":
        code = codes[0] if codes and codes[0] else "CHAIN_UNSUPPORTED"
        return lifecycle_state(
            verdict="not_established",
            reason_code=code,
            missing=_GAPS_BY_CODE.get(code, _DEFAULT_GAPS),
        )

    # An unrecognised state is itself something this mapping cannot establish. It does
    # not become "invalid", and it does not raise: the chain result the caller already
    # holds is untouched and still says whatever it said.
    return lifecycle_state(
        verdict="not_established",
        reason_code="CHAIN_STATE_UNRECOGNISED",
        missing=_DEFAULT_GAPS,
    )
