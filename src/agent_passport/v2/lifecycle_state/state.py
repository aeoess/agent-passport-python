# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Validating constructors for the lifecycle state vocabulary.

See ``types.py`` for the specification position: nothing here is required by
draft-pidlisnyi-aps-03, and nothing here changes any existing exported behaviour.

Python port of the TypeScript SDK's src/v2/lifecycle-state/state.ts.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from .types import (
    BOUNDARY_OUTCOMES,
    ESTABLISHED_NEGATIVE_SHAPES,
    ESTABLISHMENT_GAPS,
    LIFECYCLE_VERDICTS,
    EstablishedNegativeResolution,
    LifecycleStateError,
    LifecycleStateResult,
    OutstandingCause,
)

_REASON_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def is_lifecycle_verdict(value: object) -> bool:
    return isinstance(value, str) and value in LIFECYCLE_VERDICTS


def is_boundary_outcome(value: object) -> bool:
    return isinstance(value, str) and value in BOUNDARY_OUTCOMES


def is_establishment_gap(value: object) -> bool:
    return isinstance(value, str) and value in ESTABLISHMENT_GAPS


def is_established_negative_shape(value: object) -> bool:
    return isinstance(value, str) and value in ESTABLISHED_NEGATIVE_SHAPES


def _coerce_cause(candidate: Any, index: int) -> OutstandingCause:
    if isinstance(candidate, OutstandingCause):
        cause = candidate
    elif isinstance(candidate, dict):
        missing_fields = [f for f in ("id", "kind", "reason_code") if f not in candidate]
        if missing_fields:
            raise LifecycleStateError(
                "OUTSTANDING_MALFORMED",
                f"outstanding[{index}] is missing {', '.join(missing_fields)}",
            )
        extra = [k for k in candidate if k not in ("id", "kind", "reason_code")]
        if extra:
            raise LifecycleStateError(
                "OUTSTANDING_MALFORMED",
                f"outstanding[{index}] carries unknown members {', '.join(sorted(extra))}",
            )
        cause = OutstandingCause(
            id=candidate["id"], kind=candidate["kind"], reason_code=candidate["reason_code"]
        )
    else:
        raise LifecycleStateError(
            "OUTSTANDING_MALFORMED",
            f"outstanding[{index}] is neither an OutstandingCause nor a mapping",
        )
    for field in ("id", "kind", "reason_code"):
        value = getattr(cause, field)
        if not isinstance(value, str) or value == "":
            raise LifecycleStateError(
                "OUTSTANDING_MALFORMED",
                f"outstanding[{index}].{field} must be a non-empty string",
            )
    return cause


def lifecycle_state(
    *,
    verdict: str,
    reason_code: str,
    missing: Sequence[str] | None = None,
    applied_default: str | None = None,
    outstanding: Iterable[Any] | None = None,
) -> LifecycleStateResult:
    """Build a :class:`LifecycleStateResult`, enforcing the vocabulary's shape rules.

    Rules, each with the reason it exists:

    1. ``verdict`` is one of the six. There is no seventh. "Unexecutable" in particular
       is an EXECUTION OUTCOME, not a verdict: the artifact stays valid and what fails is
       the attempt to carry out the invocation, so it belongs in an execution record
       under a ``referent_unresolvable`` reason, not here.
    2. ``reason_code`` is required and SCREAMING_SNAKE_CASE. Two findings that share a
       verdict name must be told apart by their codes.
    3. ``missing`` is present with at least one member exactly when the verdict is
       ``not_established``, and absent otherwise. A denial on an unestablished state has
       to record which of source, freshness or coverage was missing, and a verdict the
       verifier DID reach has no gap to report.
    4. ``outstanding`` is present with at least one member exactly when the verdict is
       ``suspended`` or ``restricted``, and absent otherwise. Causes compose, so the
       verdict carries the set that remains rather than a flag.
    5. ``applied_default`` may not appear on ``not_established``. If a declared default
       applied, the verifier reached a conclusion and the verdict is that conclusion.

    Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 sections
    2.2, 2.3, 2.4 and 3, and candidates BROAD-L7 and CAND-05. All proposed.
    """
    if not is_lifecycle_verdict(verdict):
        raise LifecycleStateError(
            "VERDICT_UNKNOWN", f"verdict must be one of {', '.join(LIFECYCLE_VERDICTS)}"
        )
    if not isinstance(reason_code, str) or not _REASON_CODE_PATTERN.match(reason_code):
        raise LifecycleStateError(
            "REASON_CODE_INVALID",
            "reason_code must be a non-empty SCREAMING_SNAKE_CASE string",
        )

    wants_missing = verdict == "not_established"
    if wants_missing:
        if missing is None or len(tuple(missing)) == 0:
            raise LifecycleStateError(
                "MISSING_REQUIRED",
                "a not_established verdict must name at least one missing establishment limb",
            )
        for gap in missing:
            if not is_establishment_gap(gap):
                raise LifecycleStateError(
                    "MISSING_UNKNOWN",
                    f"missing must contain only {', '.join(ESTABLISHMENT_GAPS)}",
                )
    elif missing is not None:
        raise LifecycleStateError(
            "MISSING_NOT_ALLOWED",
            f"missing is only meaningful on not_established, not on {verdict}",
        )

    wants_outstanding = verdict in ("suspended", "restricted")
    causes: tuple[OutstandingCause, ...] | None = None
    if wants_outstanding:
        listed = list(outstanding) if outstanding is not None else []
        if not listed:
            raise LifecycleStateError(
                "OUTSTANDING_REQUIRED",
                f"a {verdict} verdict must name at least one outstanding cause",
            )
        causes = tuple(_coerce_cause(c, i) for i, c in enumerate(listed))
    elif outstanding is not None:
        raise LifecycleStateError(
            "OUTSTANDING_NOT_ALLOWED",
            f"outstanding is only meaningful on suspended or restricted, not on {verdict}",
        )

    if applied_default is not None:
        if not isinstance(applied_default, str) or applied_default == "":
            raise LifecycleStateError(
                "APPLIED_DEFAULT_INVALID",
                "applied_default must be a non-empty string when present",
            )
        if wants_missing:
            raise LifecycleStateError(
                "APPLIED_DEFAULT_NOT_ALLOWED",
                "applied_default cannot appear on not_established: a default that applied "
                "is a conclusion",
            )

    return LifecycleStateResult(
        verdict=verdict,
        reason_code=reason_code,
        missing=tuple(missing) if missing is not None else None,
        applied_default=applied_default,
        outstanding=causes,
    )


def not_established(missing: Sequence[str], reason_code: str) -> LifecycleStateResult:
    """Build the evidential ``not_established`` (use A) with its mandatory limbs.

    Reach for this only when the verifier CANNOT REACH a conclusion. For a negative the
    verifier HAS reached, call :func:`resolve_established_negative` instead and report
    what it gives you.
    """
    return lifecycle_state(
        verdict="not_established", reason_code=reason_code, missing=missing
    )


_ESTABLISHED_NEGATIVE_RESOLUTIONS: dict[str, EstablishedNegativeResolution] = {
    "enabling_condition_not_yet_occurred": EstablishedNegativeResolution(
        shape="enabling_condition_not_yet_occurred",
        subject="artifact",
        verdict="not_yet_effective",
        reason_code="ENABLING_CONDITION_NOT_YET_OCCURRED",
    ),
    "composition_not_satisfied": EstablishedNegativeResolution(
        shape="composition_not_satisfied",
        subject="boundary",
        outcome="denied",
        reason_code="COMPOSITION_NOT_SATISFIED",
    ),
    "pinned_referent_mismatch": EstablishedNegativeResolution(
        shape="pinned_referent_mismatch",
        subject="boundary",
        outcome="denied",
        reason_code="PINNED_REFERENT_MISMATCH",
    ),
}


def resolve_established_negative(shape: str) -> EstablishedNegativeResolution:
    """Map an established negative (use B) to the subject and output it belongs to.

    None of the three resolves to ``not_established``. Two of them are not artifact
    verdicts at all: a composition rule that is not satisfied and a pinned referent that
    is established to have changed both deny the ACTION at a boundary, and neither makes
    any artifact invalid.

    Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 section 3.
    Proposed.
    """
    if not is_established_negative_shape(shape):
        raise LifecycleStateError(
            "ESTABLISHED_NEGATIVE_UNKNOWN",
            f"shape must be one of {', '.join(ESTABLISHED_NEGATIVE_SHAPES)}",
        )
    return _ESTABLISHED_NEGATIVE_RESOLUTIONS[shape]
