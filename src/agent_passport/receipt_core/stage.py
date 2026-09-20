"""APS ReceiptV1 section 5.3 stage rules: action-intent, policy-decision, action-result.

Section 5.3 stage rules for a ReceiptV1, dispatched on receipt_type. The caller never
selects the stage: the type in the record decides which rules apply, and
`expected_receipt_type` only adds the check that the caller's belief matches the record.
This runs after the closed envelope check of section 5.1 and never loosens it: a receipt
that fails validate_receipt_v1 is invalid here for that reason alone.

What a "valid" result here does NOT establish, so a caller cannot read more into it than
it carries:
  - no action_ref recomputation from an independently supplied action
  - no binding of delegation_ref to a leaf delegation_id (checked as structural form only,
    the same way validate_receipt_v1 checks it)
  - no decision_ref recomputation from decision components
  - no resolution of prev against the record it names
  - none of the approval obligations of draft lines 1093-1099, which are
    enforcement-boundary state rather than properties of one record

Those are section 5.6 composition points, outside what a single record can prove.

The failure codes below (SCHEMA_INVALID, INTENT_*, DECISION_*, RESULT_*,
BOUNDARY_IDENTITY_MISMATCH, and so on) are this SDK's own vocabulary. The draft names
states and reasons, not code strings, so a code here is not a protocol claim.
"""

from __future__ import annotations

import re

from .decision_ref import validate_core_decision_output_v1
from .receipt import UTC_MS, validate_receipt_v1

HEX64 = re.compile(r"^[0-9a-f]{64}$")

RECEIPT_STAGE_TYPES_V1 = {
    "aps:action-intent:v1": "action-intent",
    "aps:policy-decision:v1": "policy-decision",
    "aps:action-result:v1": "action-result",
}


def _utc_ms_key(value: str) -> tuple:
    """Convert an already-validated exact-UTC-millisecond string into a tuple of integers
    that sorts in instant order, using the same regex as receipt._is_exact_utc_milliseconds
    (draft A2). This avoids datetime.strptime, which raises on a second of 60."""
    match = UTC_MS.fullmatch(value)
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    return (year, month, day, hour, minute, second, int(value[20:23]))


def validate_receipt_stage_v1(receipt, *, expected_receipt_type=None, boundary_identity=None) -> dict:
    failures: list[dict] = []
    receipt_type = (
        receipt.get("receipt_type")
        if isinstance(receipt, dict) and isinstance(receipt.get("receipt_type"), str)
        else None
    )

    def fail(code: str, detail: str) -> None:
        failures.append({"code": code, "detail": detail})

    def outcome(status: str, stage, boundary: str) -> dict:
        return {
            "status": status,
            "receipt_type": receipt_type,
            "stage": stage,
            "boundary_identity": boundary,
            "failures": failures,
        }

    if not isinstance(receipt, dict):
        fail("SCHEMA_INVALID", "ReceiptV1: not a JSON object")
        return outcome("invalid", None, "not_applicable")

    profile = receipt.get("profile")
    if not isinstance(profile, str):
        fail("SCHEMA_INVALID", "ReceiptV1: profile must be a string")
        return outcome("invalid", None, "not_applicable")
    if profile != "aps-receipt-v1":
        fail("UNSUPPORTED_PROFILE", f"ReceiptV1: envelope profile {profile} is not aps-receipt-v1")
        return outcome("unsupported", None, "not_applicable")

    try:
        validate_receipt_v1(receipt)
    except (TypeError, ValueError) as exc:
        fail("SCHEMA_INVALID", str(exc))
        return outcome("invalid", None, "not_applicable")

    if expected_receipt_type is not None and expected_receipt_type != receipt["receipt_type"]:
        fail("STAGE_MISMATCH", f"expected receipt_type {expected_receipt_type}, record carries {receipt['receipt_type']}")
        return outcome("invalid", None, "not_applicable")

    stage = RECEIPT_STAGE_TYPES_V1.get(receipt["receipt_type"])
    if stage is None:
        fail("UNSUPPORTED_RECEIPT_TYPE", f"receipt_type {receipt['receipt_type']} is not a stage defined in section 5.3")
        return outcome("unsupported", None, "not_applicable")

    if stage == "action-intent":
        _check_action_intent(receipt, fail)
        return outcome("valid" if not failures else "invalid", stage, "not_applicable")

    if stage == "policy-decision":
        _check_policy_decision(receipt, fail)
    else:
        _check_action_result(receipt, fail)

    # Boundary identity, section 5.3.2 line 1072 and section 5.3.3 line 1104, as ruled: the
    # expected identity is verifier trust input; a mismatch is invalid; no supplied identity
    # leaves the axis indeterminate. There is no rule that issuer differs from subject_agent
    # here, and none that an action-result issuer equals the issuer of the decision it
    # follows: the draft states neither.
    if boundary_identity is None:
        boundary = "not_established"
    elif boundary_identity == receipt["issuer"]:
        boundary = "verified"
    else:
        boundary = "mismatch"
        fail("BOUNDARY_IDENTITY_MISMATCH", f"issuer {receipt['issuer']} is not the supplied enforcement boundary identity")

    if failures:
        return outcome("invalid", stage, boundary)
    if boundary == "not_established":
        return outcome("indeterminate", stage, boundary)
    return outcome("valid", stage, boundary)


def _check_action_intent(receipt: dict, fail) -> None:
    """Section 5.3.1, draft lines 1052-1058."""
    if receipt["issuer"] != receipt["subject_agent"]:
        fail("INTENT_ISSUER_NOT_ACTING_AGENT", "issuer and subject_agent must both be the acting agent")
    if "prev" in receipt:
        fail("INTENT_PREV_PRESENT", "prev must be absent from an action-intent record")
    if "decision_ref" in receipt:
        fail("INTENT_DECISION_REF_PRESENT", "decision_ref must be absent from an action-intent record")
    result = receipt["result"]
    if result.get("profile") != "aps-action-intent-result-v1":
        fail("INTENT_RESULT_PROFILE", "result.profile must be aps-action-intent-result-v1")
    elif set(result) != {"profile", "status"} or result.get("status") != "declared":
        fail("INTENT_RESULT_INVALID", "result must contain exactly profile aps-action-intent-result-v1 and status declared")


def _check_policy_decision(receipt: dict, fail) -> None:
    """Section 5.3.2, draft lines 1069-1099, and the conditional members at lines 984-988."""
    if "prev" not in receipt:
        fail("DECISION_PREV_MISSING", "prev is required for a policy-decision record")
    if "decision_ref" not in receipt:
        fail("DECISION_REF_MISSING", "decision_ref is required for a policy-decision record")
    try:
        output = validate_core_decision_output_v1(receipt["result"])
    except (TypeError, ValueError) as exc:
        fail("DECISION_RESULT_INVALID", str(exc))
        return
    # Line 1091: valid_until is later than issued_at for permit or narrow, compared as
    # instants against this record's own issued_at, the decision's issuance time.
    if output["verdict"] != "deny":
        valid_until = output["valid_until"]
        issued_at = receipt["issued_at"]
        if _utc_ms_key(valid_until) <= _utc_ms_key(issued_at):
            fail("DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT", f"valid_until {valid_until} is not later than issued_at {issued_at}")


def _check_action_result(receipt: dict, fail) -> None:
    """Section 5.3.3, draft lines 1101-1133, and the conditional members at lines 984-988."""
    if "prev" not in receipt:
        fail("RESULT_PREV_MISSING", "prev is required for an action-result record")
    if "decision_ref" not in receipt:
        fail("RESULT_DECISION_REF_MISSING", "decision_ref is required for an action-result record")
    result = receipt["result"]
    if result.get("profile") != "aps-action-result-v1":
        fail("RESULT_PROFILE", "result.profile must be aps-action-result-v1")
        return
    if set(result) != {"profile", "status", "effect_ref", "error_code"}:
        fail("RESULT_MEMBERS", "result must contain exactly profile, status, effect_ref and error_code")
        return
    status = result["status"]
    if status not in ("succeeded", "failed", "unknown"):
        fail("RESULT_STATUS", "status must be succeeded, failed or unknown")
        return
    effect_ref = result["effect_ref"]
    error_code = result["error_code"]
    if effect_ref is not None and (not isinstance(effect_ref, str) or not HEX64.fullmatch(effect_ref)):
        fail("RESULT_EFFECT_REF", "effect_ref must be null or 64 lowercase hexadecimal characters")
        return
    if status == "succeeded":
        # Line 1125: for succeeded, effect_ref is REQUIRED and error_code is null.
        if effect_ref is None:
            fail("RESULT_EFFECT_REF_REQUIRED", "effect_ref is required when status is succeeded")
        if error_code is not None:
            fail("RESULT_ERROR_CODE_PRESENT", "error_code must be null when status is succeeded")
        return
    if status == "failed":
        # Line 1126: for failed, error_code is a non-empty stable identifier. Stability is
        # not machine-checkable and is not claimed; the non-empty string is.
        if not isinstance(error_code, str) or error_code == "":
            fail("RESULT_ERROR_CODE_REQUIRED", "error_code must be a non-empty string when status is failed")
        return
    # Line 1128: for unknown, both are null.
    if effect_ref is not None or error_code is not None:
        fail("RESULT_UNKNOWN_NOT_NULL", "effect_ref and error_code must both be null when status is unknown")
