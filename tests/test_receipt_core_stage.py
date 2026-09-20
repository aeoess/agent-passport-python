import pytest

from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import (
    create_receipt_v1,
    validate_receipt_stage_v1,
    verify_receipt_v1,
)

PRIVATE_KEY = "00" * 32
PUBLIC_KEY = public_key_from_private(PRIVATE_KEY)
WRONG_PRIVATE_KEY = "01" * 32
WRONG_PUBLIC_KEY = public_key_from_private(WRONG_PRIVATE_KEY)

AGENT = "did:example:agent"
POLICY_ISSUER = "did:example:policy"
RESULT_ISSUER = "did:example:executor"


def hx(char):
    return char * 64


def build_receipt(fields, signer=None, key_id="key-1"):
    signer = signer or fields["issuer"]
    return create_receipt_v1(fields, [{"signer": signer, "key_id": key_id, "private_key": PRIVATE_KEY}])


def omit(fields, *keys):
    return {key: value for key, value in fields.items() if key not in keys}


def action_intent_fields(**overrides):
    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:action-intent:v1",
        "issuer": AGENT,
        "subject_agent": AGENT,
        "action_ref": hx("a"),
        "delegation_ref": "sha256:" + hx("b"),
        "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [],
        "result": {"profile": "aps-action-intent-result-v1", "status": "declared"},
    }
    fields.update(overrides)
    return fields


def policy_decision_fields(**overrides):
    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:policy-decision:v1",
        "issuer": POLICY_ISSUER,
        "subject_agent": AGENT,
        "action_ref": hx("a"),
        "delegation_ref": "sha256:" + hx("b"),
        "decision_ref": hx("c"),
        "prev": hx("d"),
        "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [],
        "result": {
            "profile": "aps-core-decision-output-v1",
            "verdict": "permit",
            "effective_authority_ref": hx("e"),
            "constraints": [],
            "valid_until": "2026-07-18T12:00:05.000Z",
        },
    }
    fields.update(overrides)
    return fields


def action_result_fields(**overrides):
    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:action-result:v1",
        "issuer": RESULT_ISSUER,
        "subject_agent": AGENT,
        "action_ref": hx("a"),
        "delegation_ref": "sha256:" + hx("b"),
        "decision_ref": hx("c"),
        "prev": hx("d"),
        "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [],
        "result": {
            "profile": "aps-action-result-v1",
            "status": "succeeded",
            "effect_ref": hx("f"),
            "error_code": None,
        },
    }
    fields.update(overrides)
    return fields


def _assert_conforming_action_intent():
    result = validate_receipt_stage_v1(build_receipt(action_intent_fields()))
    assert result["status"] == "valid"


def _assert_conforming_policy_decision():
    result = validate_receipt_stage_v1(build_receipt(policy_decision_fields()), boundary_identity=POLICY_ISSUER)
    assert result["status"] == "valid"


def _assert_conforming_action_result():
    result = validate_receipt_stage_v1(build_receipt(action_result_fields()), boundary_identity=RESULT_ISSUER)
    assert result["status"] == "valid"


# --- action-intent, draft lines 1052-1058 -----------------------------------------------

def test_action_intent_conforming_is_valid():
    receipt = build_receipt(action_intent_fields())
    assert validate_receipt_stage_v1(receipt) == {
        "status": "valid",
        "receipt_type": "aps:action-intent:v1",
        "stage": "action-intent",
        "boundary_identity": "not_applicable",
        "failures": [],
    }


def test_action_intent_issuer_not_acting_agent():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(subject_agent="did:example:other"))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_ISSUER_NOT_ACTING_AGENT"]


def test_action_intent_prev_present():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(prev=hx("f")))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_PREV_PRESENT"]


def test_action_intent_decision_ref_present():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(decision_ref=hx("c")))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_DECISION_REF_PRESENT"]


def test_action_intent_result_wrong_status():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(result={"profile": "aps-action-intent-result-v1", "status": "pending"}))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_RESULT_INVALID"]


def test_action_intent_result_extra_member():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(result={"profile": "aps-action-intent-result-v1", "status": "declared", "extra": "x"}))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_RESULT_INVALID"]


def test_action_intent_result_wrong_profile():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields(result={"profile": "not-the-right-profile", "status": "declared"}))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["INTENT_RESULT_PROFILE"]


# --- policy-decision, draft lines 1069-1099, 984-988 ------------------------------------

def test_policy_decision_conforming_is_valid():
    receipt = build_receipt(policy_decision_fields())
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "valid"
    assert result["boundary_identity"] == "verified"
    assert result["failures"] == []


def test_policy_decision_deny_with_null_effective_authority_and_valid_until():
    _assert_conforming_policy_decision()
    receipt = build_receipt(policy_decision_fields(result={
        "profile": "aps-core-decision-output-v1", "verdict": "deny",
        "effective_authority_ref": None, "constraints": [], "valid_until": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "valid"


def test_policy_decision_valid_until_equal_to_issued_at():
    _assert_conforming_policy_decision()
    fields = policy_decision_fields()
    fields["result"] = {**fields["result"], "valid_until": fields["issued_at"]}
    receipt = build_receipt(fields)
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT"]


def test_policy_decision_prev_missing():
    _assert_conforming_policy_decision()
    receipt = build_receipt(omit(policy_decision_fields(), "prev"))
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["DECISION_PREV_MISSING"]


def test_policy_decision_decision_ref_missing():
    _assert_conforming_policy_decision()
    receipt = build_receipt(omit(policy_decision_fields(), "decision_ref"))
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["DECISION_REF_MISSING"]


@pytest.mark.parametrize("result_override", [
    {"profile": "aps-core-decision-output-v1", "verdict": "approve",
     "effective_authority_ref": hx("e"), "constraints": [], "valid_until": "2026-07-18T12:00:05.000Z"},
    {"profile": "aps-core-decision-output-v1", "verdict": "permit",
     "effective_authority_ref": None, "constraints": [], "valid_until": "2026-07-18T12:00:05.000Z"},
    {"profile": "aps-core-decision-output-v1", "verdict": "permit",
     "effective_authority_ref": hx("e"), "constraints": [], "valid_until": None},
    {"profile": "aps-core-decision-output-v1", "verdict": "permit",
     "effective_authority_ref": hx("e"), "constraints": ["b", "a"], "valid_until": "2026-07-18T12:00:05.000Z"},
    {"profile": "aps-core-decision-output-v1", "verdict": "permit",
     "effective_authority_ref": hx("e"), "constraints": ["a", "a"], "valid_until": "2026-07-18T12:00:05.000Z"},
    {"profile": "aps-core-decision-output-v1", "verdict": "permit",
     "effective_authority_ref": hx("e"), "constraints": ["é"], "valid_until": "2026-07-18T12:00:05.000Z"},
    {"profile": "aps-core-decision-output-v2", "verdict": "permit",
     "effective_authority_ref": hx("e"), "constraints": [], "valid_until": "2026-07-18T12:00:05.000Z"},
])
def test_policy_decision_result_invalid(result_override):
    _assert_conforming_policy_decision()
    receipt = build_receipt(policy_decision_fields(result=result_override))
    result = validate_receipt_stage_v1(receipt, boundary_identity=POLICY_ISSUER)
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["DECISION_RESULT_INVALID"]


# --- action-result, draft lines 1101-1133, 984-988 --------------------------------------

def test_action_result_conforming_is_valid():
    receipt = build_receipt(action_result_fields())
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert result["status"] == "valid"
    assert result["failures"] == []


def test_action_result_prev_missing():
    _assert_conforming_action_result()
    receipt = build_receipt(omit(action_result_fields(), "prev"))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_PREV_MISSING"]


def test_action_result_decision_ref_missing():
    _assert_conforming_action_result()
    receipt = build_receipt(omit(action_result_fields(), "decision_ref"))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_DECISION_REF_MISSING"]


def test_action_result_wrong_profile():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "not-the-right-profile", "status": "succeeded", "effect_ref": hx("f"), "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_PROFILE"]


def test_action_result_members():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "succeeded", "effect_ref": hx("f"),
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_MEMBERS"]


def test_action_result_status():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "pending", "effect_ref": hx("f"), "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_STATUS"]


def test_action_result_effect_ref_malformed():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "succeeded", "effect_ref": "nothex", "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_EFFECT_REF"]


def test_action_result_effect_ref_required():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "succeeded", "effect_ref": None, "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_EFFECT_REF_REQUIRED"]


def test_action_result_error_code_present():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "succeeded", "effect_ref": hx("f"), "error_code": "oops",
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_ERROR_CODE_PRESENT"]


def test_action_result_error_code_required():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "failed", "effect_ref": None, "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_ERROR_CODE_REQUIRED"]


def test_action_result_unknown_not_null():
    _assert_conforming_action_result()
    receipt = build_receipt(action_result_fields(result={
        "profile": "aps-action-result-v1", "status": "unknown", "effect_ref": hx("f"), "error_code": None,
    }))
    result = validate_receipt_stage_v1(receipt, boundary_identity=RESULT_ISSUER)
    assert [f["code"] for f in result["failures"]] == ["RESULT_UNKNOWN_NOT_NULL"]


# --- boundary identity, policy-decision and action-result only --------------------------

def test_boundary_identity_not_supplied_is_indeterminate():
    receipt = build_receipt(policy_decision_fields())
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "indeterminate"
    assert result["boundary_identity"] == "not_established"
    assert result["failures"] == []


def test_boundary_identity_mismatch_is_invalid():
    _assert_conforming_policy_decision()
    receipt = build_receipt(policy_decision_fields())
    result = validate_receipt_stage_v1(receipt, boundary_identity="did:example:someone-else")
    assert result["status"] == "invalid"
    assert result["boundary_identity"] == "mismatch"
    assert [f["code"] for f in result["failures"]] == ["BOUNDARY_IDENTITY_MISMATCH"]


def test_boundary_identity_issuer_equals_subject_agent_is_not_forbidden():
    receipt = build_receipt(policy_decision_fields(issuer=AGENT, subject_agent=AGENT), signer=AGENT)
    result = validate_receipt_stage_v1(receipt, boundary_identity=AGENT)
    assert result["status"] == "valid"


# --- envelope-level dispatch -------------------------------------------------------------

def test_unknown_receipt_type_is_unsupported():
    fields = action_intent_fields(receipt_type="aps:action:v1", result={"status": "success"})
    receipt = build_receipt(fields)
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "unsupported"
    assert result["stage"] is None
    assert [f["code"] for f in result["failures"]] == ["UNSUPPORTED_RECEIPT_TYPE"]


def test_foreign_envelope_profile_is_unsupported():
    result = validate_receipt_stage_v1({"profile": "some-other-profile-v1"})
    assert result["status"] == "unsupported"
    assert result["receipt_type"] is None
    assert result["stage"] is None
    assert result["boundary_identity"] == "not_applicable"
    assert [f["code"] for f in result["failures"]] == ["UNSUPPORTED_PROFILE"]


def test_malformed_envelope_is_invalid():
    result = validate_receipt_stage_v1({"profile": "aps-receipt-v1"})
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["SCHEMA_INVALID"]


def test_non_dict_envelope_is_invalid():
    result = validate_receipt_stage_v1(["not", "an", "object"])
    assert result["status"] == "invalid"
    assert result["stage"] is None
    assert result["boundary_identity"] == "not_applicable"
    assert [f["code"] for f in result["failures"]] == ["SCHEMA_INVALID"]


def test_expected_receipt_type_mismatch():
    _assert_conforming_action_intent()
    receipt = build_receipt(action_intent_fields())
    result = validate_receipt_stage_v1(receipt, expected_receipt_type="aps:policy-decision:v1")
    assert result["status"] == "invalid"
    assert [f["code"] for f in result["failures"]] == ["STAGE_MISMATCH"]


# --- verify_receipt_v1 four-state result --------------------------------------------------

def test_verify_receipt_v1_unresolved_key_is_indeterminate():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"
    result = verify_receipt_v1(receipt, lambda *_: None)
    assert result["status"] == "indeterminate"
    assert result["signer_authority"] == "not_established"
    assert "signer_authority_indeterminate" in result["errors"]
    assert "signature_invalid" not in result["errors"]


def test_verify_receipt_v1_wrong_key_is_invalid():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"
    result = verify_receipt_v1(receipt, lambda *_: WRONG_PUBLIC_KEY)
    assert result["status"] == "invalid"
    assert result["signer_authority"] == "invalid"
    assert "signature_invalid" in result["errors"]


def test_verify_receipt_v1_foreign_profile_is_unsupported():
    result = verify_receipt_v1({"profile": "some-other-profile-v1"}, lambda *_: PUBLIC_KEY)
    assert result["status"] == "unsupported"
    assert result["signer_authority"] == "not_checked"
    assert result["errors"] == ["unsupported_profile"]


# --- envelope rules from section A --------------------------------------------------------

def test_bare_hex_delegation_ref_is_refused():
    with pytest.raises(ValueError, match="delegation_ref"):
        build_receipt(action_intent_fields(delegation_ref=hx("b")))


def test_leap_second_issued_at_at_month_end_is_accepted():
    receipt = build_receipt(action_intent_fields(issued_at="2026-06-30T23:59:60.000Z"))
    result = validate_receipt_stage_v1(receipt)
    assert result["status"] == "valid"


@pytest.mark.parametrize("issued_at", ["2026-06-29T23:59:60.000Z", "2026-06-30T22:59:60.000Z"])
def test_leap_second_issued_at_elsewhere_is_refused(issued_at):
    with pytest.raises(ValueError, match="issued_at"):
        build_receipt(action_intent_fields(issued_at=issued_at))


def test_noncharacter_in_string_value_is_refused():
    with pytest.raises(ValueError, match="noncharacter"):
        build_receipt(action_intent_fields(issuer="did:example:agent﷐", subject_agent="did:example:agent﷐"), signer="did:example:agent﷐")


def test_noncharacter_in_object_key_is_refused():
    with pytest.raises(ValueError, match="noncharacter"):
        build_receipt(action_intent_fields(result={"profile": "aps-action-intent-result-v1", "status": "declared", "﷐x": "y"}))
