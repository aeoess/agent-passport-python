# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Assessing fulfilment records and evaluating a bound's state.

Pure. No clock, no I/O, no network. Every instant compared here is supplied by the caller,
and every resolver is the caller's. Python port of the TypeScript SDK's
src/v2/bounds/evaluate.ts. Not required by draft-pidlisnyi-aps-03; see ``types.py``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ..lifecycle_state.state import lifecycle_state, not_established
from ..lifecycle_state.types import LifecycleStateResult
from .canonical import verify_authority_bound_fulfilment_signature
from .types import (
    ATTESTOR_ROLE_ANSWERS,
    AUTHORITY_BOUND_FULFILMENT_TYPE,
    AUTHORITY_BOUND_TYPE,
    BOUND_KINDS,
    AttestorRoleResolver,
    AuthorityBound,
    AuthorityBoundError,
    BoundEvaluation,
    BoundVerificationKeyResolver,
    FulfilmentAssessment,
)

_CANONICAL_UNSIGNED_INTEGER = re.compile(r"^(0|[1-9][0-9]*)$")
_DELEGATION_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE_HEX = re.compile(r"^[0-9a-f]{128}$")

BoundLike = AuthorityBound | dict[str, Any]


def is_bound_kind(value: object) -> bool:
    return isinstance(value, str) and value in BOUND_KINDS


def is_attestor_role_answer(value: object) -> bool:
    return isinstance(value, str) and value in ATTESTOR_ROLE_ANSWERS


def as_authority_bound(bound: BoundLike) -> AuthorityBound:
    """Accept either the dataclass or the JSON mapping shape and return the dataclass.

    Both shapes are accepted because a bound arrives from a conformance vector or a wire
    record as a mapping and from application code as the dataclass, and neither should have
    to be translated by the caller.
    """
    if isinstance(bound, AuthorityBound):
        coerced = bound
    elif isinstance(bound, dict):
        missing = [f for f in ("bound_id", "delegation_id", "kind", "value") if f not in bound]
        if missing:
            raise AuthorityBoundError(
                "BOUND_MALFORMED", f"bound is missing {', '.join(missing)}"
            )
        roles = bound.get("fulfilment_attestor_roles", ())
        if not isinstance(roles, (list, tuple)):
            raise AuthorityBoundError(
                "BOUND_MALFORMED",
                "fulfilment_attestor_roles must be a sequence, empty if nobody but the "
                "issuer may attest",
            )
        coerced = AuthorityBound(
            bound_id=bound["bound_id"],
            delegation_id=bound["delegation_id"],
            kind=bound["kind"],
            value=bound["value"],
            fulfilment_attestor_roles=tuple(roles),
            record_type=bound.get("record_type", AUTHORITY_BOUND_TYPE),
        )
    else:
        raise AuthorityBoundError("BOUND_MALFORMED", "bound is not a mapping or AuthorityBound")
    assert_authority_bound(coerced)
    return coerced


def assert_authority_bound(bound: AuthorityBound) -> None:
    """Shape check for a bound declaration. Raises, for the reason
    :class:`AuthorityBoundError` documents."""
    if bound.record_type != AUTHORITY_BOUND_TYPE:
        raise AuthorityBoundError(
            "BOUND_RECORD_TYPE_UNSUPPORTED", f"record_type must be {AUTHORITY_BOUND_TYPE}"
        )
    if not isinstance(bound.bound_id, str) or not bound.bound_id:
        raise AuthorityBoundError("BOUND_MALFORMED", "bound_id must be a non-empty string")
    if not isinstance(bound.delegation_id, str) or not _DELEGATION_ID.match(bound.delegation_id):
        raise AuthorityBoundError(
            "BOUND_MALFORMED", "delegation_id must be sha256:<64 lowercase hex>"
        )
    if not is_bound_kind(bound.kind):
        raise AuthorityBoundError(
            "BOUND_KIND_UNSUPPORTED", f"kind must be one of {', '.join(BOUND_KINDS)}"
        )
    if not isinstance(bound.value, str) or not bound.value:
        raise AuthorityBoundError("BOUND_MALFORMED", "value must be a non-empty string")
    if bound.kind != "purpose" and not _CANONICAL_UNSIGNED_INTEGER.match(bound.value):
        raise AuthorityBoundError(
            "BOUND_VALUE_NONCANONICAL",
            f"a {bound.kind} bound's value must be a canonical unsigned decimal integer",
        )
    for role in bound.fulfilment_attestor_roles:
        if not isinstance(role, str) or not role:
            raise AuthorityBoundError(
                "BOUND_MALFORMED",
                "fulfilment_attestor_roles must contain only non-empty strings",
            )


def _readable_fulfilment(record: Any) -> bool:
    """True only for a record this module can read far enough to assess. A record that
    fails here is rejected with FULFILMENT_SCHEMA_INVALID, never raised on."""
    if not isinstance(record, dict):
        return False
    return (
        record.get("record_type") == AUTHORITY_BOUND_FULFILMENT_TYPE
        and isinstance(record.get("bound_id"), str)
        and bool(record.get("bound_id"))
        and isinstance(record.get("delegation_id"), str)
        and bool(_DELEGATION_ID.match(record.get("delegation_id", "")))
        and isinstance(record.get("attestor"), str)
        and bool(record.get("attestor"))
        and isinstance(record.get("verification_method"), str)
        and bool(record.get("verification_method"))
        and isinstance(record.get("attested_at"), str)
        and bool(record.get("attested_at"))
        and record.get("outcome") in ("fulfilled", "not_fulfilled")
        and isinstance(record.get("reason_code"), str)
        and bool(record.get("reason_code"))
        and isinstance(record.get("signature"), str)
        and bool(_SIGNATURE_HEX.match(record.get("signature", "")))
    )


def _assessment(
    attestor: str,
    attested_at: str,
    accepted: bool,
    reason_code: str,
    role_answer: str | None = None,
    missing: Sequence[str] | None = None,
) -> FulfilmentAssessment:
    return FulfilmentAssessment(
        attestor=attestor,
        attested_at=attested_at,
        accepted=accepted,
        reason_code=reason_code,
        role_answer=role_answer,
        missing=tuple(missing) if missing is not None else None,
    )


def assess_fulfilment(
    bound: BoundLike,
    record: Any,
    at_instant: str,
    resolve_attestor_role: AttestorRoleResolver,
    resolve_verification_key: BoundVerificationKeyResolver,
) -> FulfilmentAssessment:
    """Assess ONE fulfilment record against one bound.

    The order of the checks is the substance of this function, not an implementation
    detail. Standing is asked FIRST and authenticity SECOND, and each produces its own
    code, because "authenticated by somebody who may not say this" and "not authenticated
    at all" are different failures and collapsing them loses the distinction CAND-01 turns
    on. A valid signature establishes who signed. It does not establish that the signer was
    allowed to make this statement.

    ``FULFILMENT_OUTCOME_NOT_FULFILLED`` carries no ``missing`` limbs, and that is
    deliberate: a record from a party with standing saying the purpose was NOT met is a
    conclusion the verifier reached, not a gap in its evidence. Every other rejection names
    a limb.

    Concept source: aeoess/agent-authority-lifecycle, invariant candidates CAND-01 and
    BROAD-L7. Proposed.
    """
    resolved = as_authority_bound(bound)

    if resolved.kind != "purpose":
        return _assessment("", "", False, "FULFILMENT_NOT_APPLICABLE_TO_KIND", missing=("coverage",))

    if not _readable_fulfilment(record):
        return _assessment("", "", False, "FULFILMENT_SCHEMA_INVALID", missing=("source",))

    attestor = record["attestor"]
    attested_at = record["attested_at"]

    # The record has to be about THIS bound on THIS delegation. A coverage gap: the claim
    # does not state that it covers what the verdict needed.
    if (
        record["bound_id"] != resolved.bound_id
        or record["delegation_id"] != resolved.delegation_id
    ):
        return _assessment(
            attestor, attested_at, False, "FULFILMENT_NOT_BOUND_TO_BOUND", missing=("coverage",)
        )

    if attested_at > at_instant:
        return _assessment(
            attestor, attested_at, False, "FULFILMENT_NOT_YET_ATTESTED", missing=("coverage",)
        )

    role_answer = resolve_attestor_role(
        attestor, resolved.fulfilment_attestor_roles, at_instant
    )
    if not is_attestor_role_answer(role_answer):
        return _assessment(
            attestor, attested_at, False, "FULFILMENT_ATTESTOR_ROLE_UNKNOWN", missing=("source",)
        )
    if role_answer == "unknown":
        return _assessment(
            attestor,
            attested_at,
            False,
            "FULFILMENT_ATTESTOR_ROLE_UNKNOWN",
            role_answer=role_answer,
            missing=("source",),
        )
    if role_answer == "does_not_hold_role":
        return _assessment(
            attestor,
            attested_at,
            False,
            "FULFILMENT_ATTESTOR_WITHOUT_STANDING",
            role_answer=role_answer,
            missing=("source",),
        )

    public_key = resolve_verification_key(attestor, record["verification_method"], attested_at)
    if not isinstance(public_key, str) or not public_key:
        return _assessment(
            attestor,
            attested_at,
            False,
            "FULFILMENT_KEY_UNRESOLVED",
            role_answer=role_answer,
            missing=("source",),
        )
    if not verify_authority_bound_fulfilment_signature(record, public_key):
        return _assessment(
            attestor,
            attested_at,
            False,
            "FULFILMENT_SIGNATURE_INVALID",
            role_answer=role_answer,
            missing=("source",),
        )

    if record["outcome"] != "fulfilled":
        return _assessment(
            attestor,
            attested_at,
            False,
            "FULFILMENT_OUTCOME_NOT_FULFILLED",
            role_answer=role_answer,
        )

    return _assessment(
        attestor, attested_at, True, "FULFILMENT_ACCEPTED", role_answer=role_answer
    )


def _decimal(value: str | None, fallback: str) -> int:
    raw = fallback if value is None else value
    if not isinstance(raw, str) or not _CANONICAL_UNSIGNED_INTEGER.match(raw):
        raise AuthorityBoundError(
            "COUNTER_NONCANONICAL",
            f"expected a canonical unsigned decimal integer, got {raw!r}",
        )
    return int(raw)


def _lifecycle_for(
    state: str, reason_code: str, missing: Sequence[str]
) -> LifecycleStateResult:
    if state == "not_established":
        return not_established(tuple(missing), reason_code)
    return lifecycle_state(
        verdict="invalid" if state == "exhausted" else "valid", reason_code=reason_code
    )


def evaluate_bound(
    bound: BoundLike,
    at_instant: str,
    fulfilments: Sequence[Any] | None = None,
    resolve_attestor_role: AttestorRoleResolver | None = None,
    resolve_verification_key: BoundVerificationKeyResolver | None = None,
    consumed: str | None = None,
    budget_counter: dict[str, Any] | None = None,
) -> BoundEvaluation:
    """Evaluate one bound's state at one instant.

    THE RESOLUTION RULE, and why it is this way round. For a purpose bound:

    1. If any fulfilment record was ACCEPTED, the state is ``exhausted``.
    2. Otherwise, if any record was rejected on an EVIDENTIAL ground (signature, standing,
       unresolved role, unresolved key, unreadable shape, coverage), the state is
       ``not_established``.
    3. Otherwise the state is ``not_reached``.

    Step 1 comes before step 2 on purpose, and it is invariant candidate CAND-02's rule made
    executable: an exhaustion that WAS established is never downgraded by a later claim
    nobody could authenticate. A later finding is a new record about an earlier one, never a
    rewrite of it. Because the rule is a fold over the whole set rather than a running
    mutation, the verdict is the same whatever order the records arrive in, which is what
    makes it safe for a caller to keep them in an unordered store.

    Step 3 reads ``not_reached`` from an empty record set, and that is the one reading here
    worth arguing with. It is a positive claim: the bound is declared, no evidence reaches
    it, and under the applicable authority model a purpose that nobody has recorded as met
    is a purpose that is not met. A model whose default runs the other way (absence of a
    periodic fulfilment report is itself the trigger) is a model this function cannot
    express, and a caller in that position should report ``not_established`` with a
    ``source`` limb rather than passing an empty set and reading the answer as a finding.
    CAND-01's carve-out for a declared default on absence is the reason the disclaimer is
    here and not a silent assumption.

    A ``use_count`` bound needs no records at all: the ADMISSION reaches it, so ``consumed``
    against ``value`` is the whole computation. A ``budget`` bound is answered by the
    ledger's counter, per draft-03 section 3.4, verbatim: "Signatures establish static
    limits; they do not establish the current cumulative total."

    Reported ALONGSIDE a chain result, never merged into it, and never in place of it. A
    grant can be exhausted while its chain still verifies ``valid``, which is the whole
    point: exhaustion is invisible to chain verification. A grant can also be expired AND
    exhausted, and then the chain result says EXPIRED and this says ``exhaustion`` and
    neither overwrites the other. Invariant L10.

    Concept source: aeoess/agent-authority-lifecycle, invariant L10 and invariant
    candidates CAND-01 and CAND-02. All proposed.
    """
    resolved = as_authority_bound(bound)
    if not isinstance(at_instant, str) or not at_instant:
        raise AuthorityBoundError("INSTANT_MISSING", "at_instant must be a non-empty string")

    assessments: list[FulfilmentAssessment] = []
    remaining: str | None = None
    missing: list[str] = []

    if resolved.kind == "purpose":
        records = list(fulfilments or ())
        if records:
            if not callable(resolve_attestor_role):
                raise AuthorityBoundError(
                    "ROLE_RESOLVER_MISSING",
                    "a purpose bound with fulfilment records needs resolve_attestor_role",
                )
            if not callable(resolve_verification_key):
                raise AuthorityBoundError(
                    "KEY_RESOLVER_MISSING",
                    "a purpose bound with fulfilment records needs resolve_verification_key",
                )
        role_resolver = resolve_attestor_role or (lambda *_: "unknown")
        key_resolver = resolve_verification_key or (lambda *_: None)
        for record in records:
            assessments.append(
                assess_fulfilment(resolved, record, at_instant, role_resolver, key_resolver)
            )
        accepted = any(a.accepted for a in assessments)
        unestablished = [a for a in assessments if not a.accepted and a.missing is not None]
        if accepted:
            state, reason_code = "exhausted", "PURPOSE_EXHAUSTED"
        elif unestablished:
            state, reason_code = "not_established", "BOUND_STATE_NOT_ESTABLISHED"
            for a in unestablished:
                for gap in a.missing or ():
                    if gap not in missing:
                        missing.append(gap)
        else:
            state, reason_code = "not_reached", "BOUND_NOT_REACHED"
    elif resolved.kind == "use_count":
        limit = _decimal(resolved.value, "0")
        used = _decimal(consumed, "0")
        remaining = str(0 if used >= limit else limit - used)
        state = "exhausted" if used >= limit else "not_reached"
        reason_code = "USE_COUNT_EXHAUSTED" if state == "exhausted" else "BOUND_NOT_REACHED"
    else:
        ceiling = _decimal(resolved.value, "0")
        counter = budget_counter or {}
        committed = _decimal(counter.get("committed"), "0")
        reserved = _decimal(counter.get("reserved"), "0")
        state = "exhausted" if committed + reserved >= ceiling else "not_reached"
        reason_code = "BUDGET_EXHAUSTED" if state == "exhausted" else "BOUND_NOT_REACHED"

    return BoundEvaluation(
        bound_id=resolved.bound_id,
        kind=resolved.kind,
        bound_state=state,
        reason_code=reason_code,
        ending="exhaustion" if state == "exhausted" else None,
        lifecycle=_lifecycle_for(state, reason_code, missing or ["source"]),
        fulfilments=tuple(assessments),
        remaining=remaining,
    )
