# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Deciding whether an activation condition is established at an instant.

See ``types.py`` for the specification position and for the three parameters this module
refuses to default.

Python port of the TypeScript SDK's src/v2/activation/verify.ts.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable

from ..._time import parse_rfc3339
from ...crypto import verify as verify_ed25519
from ..lifecycle_state.map import map_authority_validation_to_lifecycle
from ..lifecycle_state.state import lifecycle_state
from ..lifecycle_state.types import CompositeAuthorityResult
from .canonical import activation_attestation_signature_input
from .types import (
    ACTIVATION_ATTESTATION_TYPE,
    ACTIVATION_CONDITION_TYPE,
    ACTIVATION_GAPS_BY_REASON,
    ACTIVATION_INSTANT_BASES,
    REJECTION_RANK,
    ActivationError,
    ActivationFinding,
    ActivationRejection,
    ActivationResult,
)


def _assert_instant(value: object, label: str) -> int:
    parsed = parse_rfc3339(value)
    if not parsed.ok:
        raise ActivationError(
            "INSTANT_MALFORMED",
            f"{label} is not an RFC 3339 instant with an offset ({parsed.reason})",
        )
    return parsed.ms


def validate_activation_condition(condition: Any) -> dict:
    """Shape rules, each with the reason it exists.

    A condition that breaks one is a programming error at the caller, not a verdict about
    evidence, so this raises :class:`ActivationError`.

    Exported so a caller can validate a condition it received before reaching a boundary.
    """
    if not isinstance(condition, dict):
        raise ActivationError("CONDITION_MALFORMED", "condition is not a mapping")
    if condition.get("record_type") != ACTIVATION_CONDITION_TYPE:
        raise ActivationError(
            "CONDITION_RECORD_TYPE_UNKNOWN",
            f"condition record_type must be {ACTIVATION_CONDITION_TYPE}",
        )
    for field_name in ("condition_id", "delegation_id"):
        value = condition.get(field_name)
        if not isinstance(value, str) or value == "":
            raise ActivationError(
                "CONDITION_MALFORMED", f"condition {field_name} must be a non-empty string"
            )

    condition_type = condition.get("condition_type")

    if condition_type == "date":
        _assert_instant(condition.get("activation_date"), "condition activation_date")
        return condition

    if condition_type == "recorded_event":
        for field_name in ("event_type", "event_id"):
            value = condition.get(field_name)
            if not isinstance(value, str) or value == "":
                raise ActivationError(
                    "CONDITION_MALFORMED", f"condition {field_name} must be a non-empty string"
                )
        roles = condition.get("required_attestor_roles")
        # A condition naming no accepted source has not stated what it accepts. Accepting
        # anything would make the role check decorative, and refusing everything would be a
        # fail-closed ruling the text does not state. Refuse the CONDITION instead.
        if not isinstance(roles, (list, tuple)) or len(roles) == 0:
            raise ActivationError(
                "CONDITION_ROLES_REQUIRED",
                "required_attestor_roles must name at least one role",
            )
        for role in roles:
            if not isinstance(role, str) or role == "":
                raise ActivationError(
                    "CONDITION_ROLES_REQUIRED",
                    "required_attestor_roles must contain only non-empty strings",
                )
        threshold = condition.get("threshold")
        if type(threshold) is not int or threshold < 1:
            raise ActivationError(
                "CONDITION_THRESHOLD_INVALID",
                "threshold must be an integer of at least 1, and this module declares no default",
            )
        if condition.get("instant_basis") not in ACTIVATION_INSTANT_BASES:
            raise ActivationError(
                "CONDITION_INSTANT_BASIS_REQUIRED",
                "instant_basis must be one of "
                + ", ".join(ACTIVATION_INSTANT_BASES)
                + ", and this module declares no default",
            )
        return condition

    raise ActivationError(
        "CONDITION_TYPE_UNKNOWN", "condition_type must be date or recorded_event"
    )


def _classify(
    attestation: dict,
    condition: dict,
    action_ms: int,
    resolve_attestor_role: Callable[[str, str, str], str],
    resolve_verification_key: Callable[..., Any],
    attestation_preimage: Callable[[dict], str] | None,
    accepted_record_types: Sequence[str] | None,
) -> tuple[bool, str]:
    """Returns ``(True, finding)`` for an accepted record, ``(False, reason_code)`` otherwise."""
    uses_own_preimage = attestation_preimage is None

    # 1. Record type. A record whose type the model has not declared it accepts for this
    #    condition is not evidence, however well it verifies.
    record_type = attestation.get("record_type")
    if uses_own_preimage:
        if record_type != ACTIVATION_ATTESTATION_TYPE:
            return False, "ATTESTATION_RECORD_TYPE_NOT_ACCEPTED"
    elif record_type not in (accepted_record_types or ()):
        return False, "ATTESTATION_RECORD_TYPE_NOT_ACCEPTED"

    # 2. Signature, over the record's own bytes, under the key authorized at attested_at.
    attested_at = attestation.get("attested_at")
    if not isinstance(attested_at, str):
        return False, "ATTESTATION_INSTANT_MALFORMED"
    if not parse_rfc3339(attested_at).ok:
        return False, "ATTESTATION_INSTANT_MALFORMED"
    verification_method = attestation.get("verification_method")
    signature = attestation.get("signature")
    attestor = attestation.get("attestor")
    if (
        not isinstance(verification_method, str)
        or not isinstance(signature, str)
        or not isinstance(attestor, str)
    ):
        return False, "ATTESTATION_SIGNATURE_UNVERIFIED"
    resolved = resolve_verification_key(attestor, verification_method, attested_at)
    # A resolver failure and a missing key are the same finding here: no accepted source
    # produced a key, so the record is not usable evidence. The granular key-resolution
    # outcomes belong to chain verification, which reports them on its own result.
    if not isinstance(resolved, str) or resolved == "":
        return False, "ATTESTATION_SIGNATURE_UNVERIFIED"
    preimage = (
        activation_attestation_signature_input(attestation)
        if uses_own_preimage
        else attestation_preimage(attestation)
    )
    try:
        signature_ok = verify_ed25519(preimage, signature, resolved)
    except Exception:
        signature_ok = False
    if not signature_ok:
        return False, "ATTESTATION_SIGNATURE_UNVERIFIED"

    # 3. The verification method has to belong to the attestor the body names, or a valid
    #    signature says nothing about who attested.
    if not verification_method.startswith(attestor + "#"):
        return False, "ATTESTATION_ATTESTOR_BINDING_MISMATCH"

    # 4. The attestor's own role claim, checked AGAINST the resolver. Never believed.
    claimed_role = attestation.get("attestor_role")
    if isinstance(claimed_role, str) and claimed_role != "":
        claimed = resolve_attestor_role(attestor, claimed_role, attested_at)
        if claimed == "unknown":
            return False, "ATTESTATION_ATTESTOR_ROLE_UNKNOWN"
        if claimed != "holds":
            return False, "ATTESTATION_ROLE_CLAIM_CONFLICT"

    # 5. Does the attestor hold a role the condition requires? A source the model does not
    #    accept for THIS condition is not evidence in either direction: it cannot establish
    #    the condition and it cannot establish that the condition was unmet.
    holds_required = False
    any_unknown = False
    for role in condition["required_attestor_roles"]:
        standing = resolve_attestor_role(attestor, role, attested_at)
        if standing == "holds":
            holds_required = True
            break
        if standing == "unknown":
            any_unknown = True
    if not holds_required:
        return False, (
            "ATTESTATION_ATTESTOR_ROLE_UNKNOWN"
            if any_unknown
            else "ATTESTATION_ATTESTOR_ROLE_MISMATCH"
        )

    # 6. Condition binding.
    if (
        attestation.get("condition_id") != condition["condition_id"]
        or attestation.get("event_type") != condition["event_type"]
        or attestation.get("event_id") != condition["event_id"]
    ):
        return False, "ATTESTATION_CONDITION_MISMATCH"

    # 7. What it establishes, measured on the instant the CONDITION declares governs.
    assertion = attestation.get("assertion")
    if assertion == "condition_occurred":
        raw = (
            attested_at
            if condition["instant_basis"] == "attestation_written"
            else attestation.get("occurred_at")
        )
        if not isinstance(raw, str):
            return False, "ATTESTATION_UNKNOWN_ASSERTION"
        parsed = parse_rfc3339(raw)
        if not parsed.ok:
            return False, "ATTESTATION_INSTANT_MALFORMED"
        return True, (
            "occurred_by_action" if parsed.ms <= action_ms else "occurred_after_action"
        )

    if assertion == "condition_not_occurred_through":
        raw = attestation.get("not_occurred_through")
        if not isinstance(raw, str):
            return False, "ATTESTATION_UNKNOWN_ASSERTION"
        parsed = parse_rfc3339(raw)
        if not parsed.ok:
            return False, "ATTESTATION_INSTANT_MALFORMED"
        # A negative that stops short of the action instant says nothing about the interval
        # between where it stops and the action. That is the coverage limb, not a source
        # problem.
        if parsed.ms < action_ms:
            return False, "ATTESTATION_DOES_NOT_REACH_ACTION"
        return True, "not_occurred_through_action"

    return False, "ATTESTATION_UNKNOWN_ASSERTION"


def _not_established_for(code: str):
    return lifecycle_state(
        verdict="not_established",
        reason_code=code,
        missing=ACTIVATION_GAPS_BY_REASON.get(code, ("source",)),
    )


def verify_activation(
    *,
    condition: Any,
    delegation_id: str,
    action_instant: str,
    resolve_attestor_role: Callable[[str, str, str], str],
    resolve_verification_key: Callable[..., Any],
    attestations: Sequence[dict] | None = None,
    attestation_preimage: Callable[[dict], str] | None = None,
    accepted_attestation_record_types: Sequence[str] | None = None,
) -> ActivationResult:
    """Decide whether an activation condition is established for one action at one instant.

    Three verdicts are reachable and ``invalid`` is not one of them:

    ===============================================================  ===================
    situation                                                        verdict
    ===============================================================  ===================
    condition established at or before the action instant            ``valid``
    established as not met at that instant, or first met after it    ``not_yet_effective``
    the verifier cannot tell                                         ``not_established``
    ===============================================================  ===================

    NOT ESTABLISHED IS NOT THE NEGATION OF THE CLAIM. It says the verifier could not reach a
    conclusion and names which establishment limb was missing. ``not_yet_effective`` says the
    verifier DID reach a conclusion and it was negative. Its remedy is to wait, where
    ``not_established``'s remedy is a better source. Collapsing the two throws away a
    decidable answer the verifier already had.

    NO RETROACTIVE ACTIVATION, KEYED ON THE CONDITION'S OWN INSTANT. A record putting the
    condition's first occurrence after the action instant leaves that action
    ``not_yet_effective``, and the SAME record establishes the condition for any later
    action. What the rule keys on is the condition's instant, not the instant someone wrote
    the record: learning on Thursday that a condition was met on Monday is the normal case
    for any model built around an after-the-fact determination, and under
    ``instant_basis: condition_occurrence`` such a record establishes the condition. A model
    that reads it the other way says so with ``instant_basis: attestation_written``.

    ORDER OF RESOLUTION, and why contradiction sits above acceptance:

      1. two accepted records that disagree      ``not_established``, CONDITION_EVIDENCE_CONFLICT
      2. ``threshold`` records say occurred by it  ``valid``
      3. ``threshold`` records say not occurred    ``not_yet_effective``
      4. ``threshold`` records say occurred after  ``not_yet_effective``
      5. some accepted, fewer than ``threshold``   ``not_established``, ACTIVATION_THRESHOLD_NOT_MET
      6. none accepted                             ``not_established``, furthest rejection reason

    Contradiction is evaluated on PRESENCE, not on counts. Two acceptable records that
    disagree leave the verifier unable to tell which holds, and neither is discarded in
    favour of the other: preferring the later record, or the negative one, or a majority,
    would each be a precedence rule the concept text does not state.

    This function reads no clock and makes no network call. ``action_instant`` is a parameter.

    ``resolve_verification_key`` selects the key at the attestation's own ``attested_at``
    rather than at verification time, the same historical-key discipline draft-03 section 2.4
    states for delegations. It receives ``(attestor, verification_method, attested_at)``.

    ``attestation_preimage`` is the escape hatch for a model that accepts condition evidence
    in a shape this module does not own. Which bytes a signature covers is a property of a
    record type, and an SDK cannot dictate the signing convention of a record type it did not
    define. A caller using it must also declare ``accepted_attestation_record_types``, or the
    module has no stated basis for accepting the record at all.

    Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant candidates CAND-04
    and CAND-13 (activation half) and BROAD-L7. Not required by draft-pidlisnyi-aps-03.
    """
    if not callable(resolve_attestor_role):
        raise ActivationError(
            "ROLE_RESOLVER_REQUIRED",
            "resolve_attestor_role is required: role standing is resolved outside the record, always",
        )
    if not callable(resolve_verification_key):
        raise ActivationError("KEY_RESOLVER_REQUIRED", "resolve_verification_key is required")
    if attestation_preimage is not None:
        if (
            not isinstance(accepted_attestation_record_types, (list, tuple))
            or len(accepted_attestation_record_types) == 0
        ):
            raise ActivationError(
                "ACCEPTED_RECORD_TYPES_REQUIRED",
                "accepted_attestation_record_types must name at least one type when "
                "attestation_preimage is supplied",
            )
    if not isinstance(delegation_id, str) or delegation_id == "":
        raise ActivationError(
            "DELEGATION_ID_REQUIRED", "delegation_id must be a non-empty string"
        )

    validated = validate_activation_condition(condition)
    action_ms = _assert_instant(action_instant, "action_instant")
    presented = list(attestations or ())

    condition_id = validated["condition_id"]
    condition_type = validated["condition_type"]

    if validated["delegation_id"] != delegation_id:
        return ActivationResult(
            state=_not_established_for("CONDITION_DELEGATION_MISMATCH"),
            condition_id=condition_id,
            condition_type=condition_type,
        )

    # A date condition needs no evidence at all. The verifier reads the date off the
    # condition and compares it with the action instant, so an unreached date is a KNOWN
    # negative and never an unknown one. Presented attestations are not consulted.
    if condition_type == "date":
        reached = (
            _assert_instant(validated["activation_date"], "condition activation_date")
            <= action_ms
        )
        return ActivationResult(
            state=(
                lifecycle_state(verdict="valid", reason_code="ACTIVATION_ESTABLISHED")
                if reached
                else lifecycle_state(
                    verdict="not_yet_effective", reason_code="CONDITION_DATE_NOT_REACHED"
                )
            ),
            condition_id=condition_id,
            condition_type=condition_type,
        )

    findings: list[ActivationFinding] = []
    rejections: list[ActivationRejection] = []
    counts = {
        "occurred_by_action": 0,
        "occurred_after_action": 0,
        "not_occurred_through_action": 0,
    }

    for attestation in presented:
        if not isinstance(attestation, dict):
            raise ActivationError("ATTESTATION_MALFORMED", "an attestation is not a mapping")
        raw_id = attestation.get("attestation_id")
        attestation_id = raw_id if isinstance(raw_id, str) else ""
        raw_attestor = attestation.get("attestor")
        attestor = raw_attestor if isinstance(raw_attestor, str) else ""
        ok, outcome = _classify(
            attestation,
            validated,
            action_ms,
            resolve_attestor_role,
            resolve_verification_key,
            attestation_preimage,
            accepted_attestation_record_types,
        )
        if ok:
            counts[outcome] += 1
            findings.append(
                ActivationFinding(
                    attestation_id=attestation_id, attestor=attestor, finding=outcome
                )
            )
        else:
            rejections.append(
                ActivationRejection(
                    attestation_id=attestation_id, attestor=attestor, reason_code=outcome
                )
            )

    def result(state) -> ActivationResult:
        return ActivationResult(
            state=state,
            condition_id=condition_id,
            condition_type=condition_type,
            findings=tuple(findings),
            rejections=tuple(rejections),
        )

    threshold = validated["threshold"]

    if counts["occurred_by_action"] > 0 and counts["not_occurred_through_action"] > 0:
        return result(_not_established_for("CONDITION_EVIDENCE_CONFLICT"))
    if counts["occurred_by_action"] >= threshold:
        return result(lifecycle_state(verdict="valid", reason_code="ACTIVATION_ESTABLISHED"))
    if counts["not_occurred_through_action"] >= threshold:
        return result(
            lifecycle_state(
                verdict="not_yet_effective",
                reason_code="CONDITION_ESTABLISHED_NOT_YET_OCCURRED",
            )
        )
    if counts["occurred_after_action"] >= threshold:
        return result(
            lifecycle_state(
                verdict="not_yet_effective",
                reason_code="CONDITION_FIRST_OCCURRED_AFTER_ACTION",
            )
        )
    if findings:
        return result(_not_established_for("ACTIVATION_THRESHOLD_NOT_MET"))

    if not rejections:
        return result(_not_established_for("NO_ATTESTATION_PRESENTED"))
    furthest = sorted(
        rejections,
        key=lambda r: (-REJECTION_RANK.get(r.reason_code, 0), r.attestation_id),
    )[0]
    return result(_not_established_for(furthest.reason_code))


def compose_activation(
    chain: Any,
    activation: ActivationResult | None,
    *,
    mapping: dict | None = None,
) -> CompositeAuthorityResult:
    """Report an activation result ALONGSIDE a chain result, never merged into it.

    Two stages, in order, and the order is the point:

      1. Chain verification decides whether the grant is valid at the action instant. Its
         four-value result is returned untouched in ``chain``.
      2. Activation is asked ONLY when the chain is valid. A grant that does not verify is
         not a grant that is waiting on a condition, and reporting ``not_yet_effective`` for
         a revoked or unparented grant would say the remedy is to wait when it is not.

    This is also where CAND-13's activation half lands. A pre-committed replacement grant is
    an ordinary grant with an ordinary condition, so it needs no separate machinery here, and
    the ordering is what keeps L1 intact: if the pre-committing instrument is revoked, the
    replacement's chain is invalid and no activation evidence can make it exercisable.
    Nothing in this module can turn an invalid chain into a ``valid`` lifecycle verdict.

    ``activation`` may be ``None``, which is how a caller says no activation module ran. The
    composite then carries only the chain's own reading.

    ``mapping`` is passed through to ``map_authority_validation_to_lifecycle``. The contested
    reading lives there and stays the CALLER's: both reference SDKs answer ``invalid`` with
    ``NOT_YET_VALID`` for a grant whose time facet ``not_before`` has not been reached, while
    an activation-condition date at the same instant answers ``not_yet_effective`` here. One
    instant, two mechanisms carrying the wait, two answers, and the concept text does not say
    whether a waiting grant should be ``invalid``, ``not_yet_effective`` or something else.
    This module does not settle it by default.

    Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L1 and invariant
    candidates CAND-04 and CAND-13.
    """
    mapped = map_authority_validation_to_lifecycle(chain, **(mapping or {}))
    chain_state = chain.state if hasattr(chain, "state") else chain.get("state")
    if chain_state != "valid" or activation is None:
        return CompositeAuthorityResult(chain=chain, lifecycle=mapped)
    return CompositeAuthorityResult(chain=chain, lifecycle=activation.state)
