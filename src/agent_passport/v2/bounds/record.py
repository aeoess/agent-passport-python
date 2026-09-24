# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Issuing and verifying the two records this module declares.

Python port of the TypeScript SDK's src/v2/bounds/record.ts. Neither record is required by
draft-pidlisnyi-aps-03 and neither is an ``aps:`` record type. See ``types.py`` for what
each one attests and, more importantly, what it does not.

Records are plain dicts, which is the shape this SDK already uses for every signed wire
artifact (``agent_passport.v2.authority_revocation`` is the nearest neighbour), so a record
minted here goes straight to ``json.dumps`` and a record read off the wire goes straight
into :func:`verify_authority_exhaustion` without translation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .canonical import (
    compute_authority_exhaustion_id,
    compute_authority_exhaustion_id_for_write,
    sign_authority_bound_fulfilment,
    sign_authority_exhaustion,
    verify_authority_exhaustion_signature,
)
from .types import (
    AUTHORITY_BOUND_FULFILMENT_TYPE,
    AUTHORITY_EXHAUSTION_TYPE,
    BOUND_KINDS,
    AuthorityBoundError,
    BoundEvaluation,
)

#: The codes :func:`verify_authority_exhaustion` can report. Stable and module-local.
AUTHORITY_EXHAUSTION_FAILURE_CODES: tuple[str, ...] = (
    "SCHEMA_INVALID",
    "UNSUPPORTED_RECORD_TYPE",
    "ID_MISMATCH",
    "KEY_UNRESOLVED",
    "SIGNATURE_INVALID",
)


@dataclass(frozen=True)
class AuthorityExhaustionVerification:
    """What :func:`verify_authority_exhaustion` concludes about ONE record.

    ``status`` is ``"valid"`` or ``"invalid"`` only. This function answers a question about
    one record's bytes and its signer, which is genuinely two sided, so it does not borrow
    the lifecycle vocabulary. What the record MEANS for a grant's state is
    :func:`agent_passport.v2.bounds.evaluate_bound`'s question, and a verified record is
    evidence toward it, never a substitute for it.
    """

    status: str
    failures: tuple[str, ...] = ()


def issue_authority_bound_fulfilment(
    *,
    bound_id: str,
    delegation_id: str,
    attestor: str,
    verification_method: str,
    attested_at: str,
    outcome: str,
    reason_code: str,
    detail: str | None = None,
    private_key: str,
) -> dict[str, Any]:
    """Mint a signed fulfilment attestation.

    ``attested_at`` is a canonical UTC-millisecond time supplied by the caller. Issuance
    never reads a clock, so the same inputs produce the same bytes on every run, which is
    what makes the signature reproducible in a test and in a conformance vector.

    What this function does NOT establish: that the holder of ``private_key`` is in fact
    ``attestor``, that ``verification_method`` is one of that party's keys, or that the
    attestor holds any fulfilment-attestor role. All three are a resolver's answer, not a
    local one. :func:`agent_passport.v2.bounds.assess_fulfilment` makes those checks, and it
    asks about standing BEFORE it asks about the signature, because a record can be
    perfectly authentic and still come from somebody with no standing to make the statement.

    ``detail`` is omitted from the record entirely when not supplied, never written as
    ``None``: JCS has no canonical form for an absent value.

    Proposed. Concept source: aeoess/agent-authority-lifecycle.
    """
    for name, value in (
        ("bound_id", bound_id),
        ("delegation_id", delegation_id),
        ("attestor", attestor),
        ("verification_method", verification_method),
        ("attested_at", attested_at),
        ("reason_code", reason_code),
    ):
        if not isinstance(value, str) or not value:
            raise AuthorityBoundError(
                "FULFILMENT_ISSUE_MALFORMED", f"{name} must be a non-empty string"
            )
    if outcome not in ("fulfilled", "not_fulfilled"):
        raise AuthorityBoundError(
            "FULFILMENT_ISSUE_MALFORMED", "outcome must be fulfilled or not_fulfilled"
        )
    body: dict[str, Any] = {
        "record_type": AUTHORITY_BOUND_FULFILMENT_TYPE,
        "bound_id": bound_id,
        "delegation_id": delegation_id,
        "attestor": attestor,
        "verification_method": verification_method,
        "attested_at": attested_at,
        "outcome": outcome,
        "reason_code": reason_code,
    }
    if detail is not None:
        body["detail"] = detail
    return {**body, "signature": sign_authority_bound_fulfilment(body, private_key)}


def issue_authority_exhaustion(
    evaluation: BoundEvaluation,
    delegation_id: str,
    *,
    boundary: str,
    verification_method: str,
    found_at: str,
    detail: str | None = None,
    private_key: str,
) -> dict[str, Any]:
    """Mint the OPTIONAL signed exhaustion record for an evaluation that reached
    ``exhausted``.

    REFUSES on any other state, and the refusal is the design. A record that says "I found
    this bound exhausted" when the evaluation said ``not_established`` would be a boundary
    asserting a finding it did not make, which is precisely what invariant candidate CAND-01
    forbids. There is no flag to override it.

    ``evidence`` is derived from the evaluation's own accepted fulfilment records, and it is
    EMPTY for a ``use_count`` or ``budget`` bound. That emptiness is honest rather than
    incomplete: the basis for those two is the boundary's own ledger, which is the one thing
    an outside verifier cannot check, and a placeholder there would hide the gap. The same
    limit applies to the whole record, and ``types.py`` states it: the record attests the
    boundary's finding, not the state of the world, on the model draft-03 section 5.3.3 uses
    for an action result, verbatim: "An action-result record attests to what the enforcement
    boundary observed after dispatch.  External occurrence or settlement requires separately
    resolved evidence."

    Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L10.
    """
    if not isinstance(evaluation, BoundEvaluation):
        raise AuthorityBoundError(
            "EXHAUSTION_ISSUE_MALFORMED", "evaluation is not a BoundEvaluation"
        )
    if evaluation.bound_state != "exhausted":
        raise AuthorityBoundError(
            "EXHAUSTION_STATE_NOT_EXHAUSTED",
            "an exhaustion record can only be minted for bound_state exhausted, not "
            f"{evaluation.bound_state}",
        )
    for name, value in (
        ("boundary", boundary),
        ("verification_method", verification_method),
        ("found_at", found_at),
    ):
        if not isinstance(value, str) or not value:
            raise AuthorityBoundError(
                "EXHAUSTION_ISSUE_MALFORMED", f"{name} must be a non-empty string"
            )
    if evaluation.kind not in BOUND_KINDS:
        raise AuthorityBoundError(
            "EXHAUSTION_ISSUE_MALFORMED", f"kind must be one of {', '.join(BOUND_KINDS)}"
        )
    body: dict[str, Any] = {
        "record_type": AUTHORITY_EXHAUSTION_TYPE,
        "bound_id": evaluation.bound_id,
        "delegation_id": delegation_id,
        "kind": evaluation.kind,
        "boundary": boundary,
        "verification_method": verification_method,
        "found_at": found_at,
        "reason_code": evaluation.reason_code,
        "evidence": [
            {"attestor": a.attestor, "attested_at": a.attested_at}
            for a in evaluation.fulfilments
            if a.accepted
        ],
    }
    if detail is not None:
        body["detail"] = detail
    unsigned = {**body, "exhaustion_id": compute_authority_exhaustion_id_for_write(body)}
    return {**unsigned, "signature": sign_authority_exhaustion(unsigned, private_key)}


def verify_authority_exhaustion(
    record: Any,
    resolve_verification_key: Callable[[str, str, str], str | None],
) -> AuthorityExhaustionVerification:
    """Verify an exhaustion record's bytes, identifier and signature.

    A ``valid`` answer here means: the record recomputes its own identifier, and the key
    resolved for its ``boundary`` at its ``found_at`` signed it. It does NOT mean the bound
    is exhausted. It means the named boundary said so, at that time, over those bytes.
    Treating the two as the same thing is the substitution draft-03's own security
    considerations warn about for receipts generally, verbatim: "Verifiers MUST treat
    receipts as evidence of what was attested, not as proof of what is true."

    Proposed.
    """
    if not isinstance(record, dict):
        return AuthorityExhaustionVerification("invalid", ("SCHEMA_INVALID",))
    if record.get("record_type") != AUTHORITY_EXHAUSTION_TYPE:
        return AuthorityExhaustionVerification("invalid", ("UNSUPPORTED_RECORD_TYPE",))
    for field in (
        "bound_id",
        "delegation_id",
        "boundary",
        "verification_method",
        "found_at",
        "reason_code",
        "exhaustion_id",
        "signature",
    ):
        value = record.get(field)
        if not isinstance(value, str) or not value:
            return AuthorityExhaustionVerification("invalid", ("SCHEMA_INVALID",))
    if not isinstance(record.get("evidence"), list) or record.get("kind") not in BOUND_KINDS:
        return AuthorityExhaustionVerification("invalid", ("SCHEMA_INVALID",))

    claimed_id = record["exhaustion_id"]
    body = {k: v for k, v in record.items() if k not in ("exhaustion_id", "signature")}
    if compute_authority_exhaustion_id(body) != claimed_id:
        return AuthorityExhaustionVerification("invalid", ("ID_MISMATCH",))

    public_key = resolve_verification_key(
        record["boundary"], record["verification_method"], record["found_at"]
    )
    if not isinstance(public_key, str) or not public_key:
        return AuthorityExhaustionVerification("invalid", ("KEY_UNRESOLVED",))
    if not verify_authority_exhaustion_signature(record, public_key):
        return AuthorityExhaustionVerification("invalid", ("SIGNATURE_INVALID",))
    return AuthorityExhaustionVerification("valid", ())
