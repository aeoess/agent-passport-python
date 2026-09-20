import copy

import pytest

from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import (
    create_receipt_v1,
    validate_receipt_stage_v1,
    verify_receipt_v1,
    verify_receipt_v1_serialized,
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


# --- the verifier enforces the type-specific schema, and the serialized route exists ----


def _resolve(signer, key_id, issued_at):
    return PUBLIC_KEY


def test_verifier_refuses_a_record_that_breaks_its_own_stage():
    """Draft line 1214: a verifier enforces the closed ReceiptV1 schema AND the
    type-specific schema. Before this, a gateway-issued action intent carrying prev, a
    decision_ref and a free-form result came back valid from verify_receipt_v1."""
    control = build_receipt(action_intent_fields())
    assert verify_receipt_v1(control, _resolve)["status"] == "valid"

    bad = build_receipt(
        action_intent_fields(
            issuer="did:example:gateway",
            decision_ref=hx("c"),
            prev=hx("d"),
            result={"profile": "anything-at-all", "status": "whatever", "extra": [1, 2, 3]},
        ),
        signer="did:example:gateway",
    )
    verified = verify_receipt_v1(bad, _resolve)
    assert verified["status"] == "invalid"
    assert verified["valid"] is False
    assert "stage_invalid" in verified["errors"]
    for code in ("INTENT_ISSUER_NOT_ACTING_AGENT", "INTENT_PREV_PRESENT", "INTENT_DECISION_REF_PRESENT", "INTENT_RESULT_PROFILE"):
        assert code in verified["errors"]


def test_verifier_carries_the_stage_result_and_the_unchecked_markers():
    control = build_receipt(action_intent_fields())
    verified = verify_receipt_v1(control, _resolve)
    assert verified["stage"]["stage"] == "action-intent"
    assert verified["receipt_id_valid"] is True

    foreign = {**control, "profile": "aps-receipt-v2"}
    unsupported = verify_receipt_v1(foreign, _resolve)
    assert unsupported["status"] == "unsupported"
    # Neither check ran, so neither reports a result. Reporting False said the identifier
    # did not match when it was never computed.
    assert unsupported["receipt_id_valid"] == "not_checked"
    assert unsupported["stage"] == "not_checked"


def test_an_unsupported_receipt_type_is_unsupported_through_the_verifier():
    odd = build_receipt(action_intent_fields(receipt_type="aps:action:v1"))
    verified = verify_receipt_v1(odd, _resolve)
    assert verified["status"] == "unsupported"
    assert "stage_unsupported" in verified["errors"]


def test_a_decision_with_no_supplied_boundary_identity_is_indeterminate():
    decision = build_receipt(policy_decision_fields(), signer=POLICY_ISSUER)
    assert verify_receipt_v1(decision, _resolve)["status"] == "indeterminate"
    assert verify_receipt_v1(decision, _resolve, boundary_identity=POLICY_ISSUER)["status"] == "valid"


def test_serialized_route_rejects_a_duplicate_member_the_object_route_cannot_see():
    """Draft line 1213: parse bounded I-JSON while preserving duplicate names. Once bytes
    have become a dict the later member has overwritten the earlier one, so the object
    entry point cannot detect it however carefully it validates."""
    import json

    control = build_receipt(action_intent_fields())
    clean = json.dumps(control, separators=(",", ":"))
    assert verify_receipt_v1_serialized(clean, _resolve)["status"] == "valid"

    for spliced in (
        clean.replace(f'"issuer":"{AGENT}"', f'"issuer":"{AGENT}","issuer":"did:example:attacker"', 1),
        clean.replace(f'"issuer":"{AGENT}"', f'"issuer":"{AGENT}","\\u0069ssuer":"did:example:attacker"', 1),
    ):
        assert spliced != clean, "the duplicate was not spliced in"
        result = verify_receipt_v1_serialized(spliced, _resolve)
        assert result["status"] == "invalid"
        assert result["errors"][0] == "parse_error"
        assert "duplicate object member" in result["errors"][1]


def test_serialized_route_reports_a_resource_ceiling_as_indeterminate():
    """A resource ceiling is not a statement about the artifact.

    Both ceilings belong to this parser, not to the draft, so hitting one says this verifier
    stopped, never that the receipt is bad. Previously both returned invalid/parse_error,
    which made validity depend on verifier capacity: the same bytes verify under a higher
    ceiling. Genuine parse failures are unchanged.
    """
    control = build_receipt(action_intent_fields())
    import json

    raw = json.dumps(control, separators=(",", ":"))
    assert verify_receipt_v1_serialized(raw, _resolve)["status"] == "valid"

    over_wire = verify_receipt_v1_serialized(raw, _resolve, max_utf8_bytes=10)
    assert over_wire["status"] == "indeterminate"
    assert over_wire["errors"][0] == "RESOURCE_LIMIT"
    assert "parse_error" not in over_wire["errors"]
    assert over_wire["valid"] is False

    over_depth = verify_receipt_v1_serialized('{"a":' * 200 + "1" + "}" * 200, _resolve)
    assert over_depth["status"] == "indeterminate"
    assert over_depth["errors"][0] == "RESOURCE_LIMIT"
    assert "parse_error" not in over_depth["errors"]

    malformed = verify_receipt_v1_serialized('{"a": }', _resolve)
    assert malformed["status"] == "invalid"
    assert malformed["errors"][0] == "parse_error"

    duplicate = verify_receipt_v1_serialized('{"a":1,"a":2}', _resolve)
    assert duplicate["status"] == "invalid"
    assert duplicate["errors"][0] == "parse_error"

    # A caller misconfiguring the limit is an argument error, not a ceiling this parser hit.
    bad_config = verify_receipt_v1_serialized(raw, _resolve, max_utf8_bytes=0)
    assert bad_config["status"] == "invalid"
    assert bad_config["errors"][0] == "parse_error"


def test_a_deeply_nested_document_never_escapes_or_reads_as_malformed():
    """A stack or decoder ceiling is this implementation stopping, not a bad artifact.

    The depth walk used to recurse once per nesting level, so a valid document nested past
    the interpreter's recursion limit raised an uncaught RecursionError out of the public
    entry point when a caller raised max_depth. It now walks iteratively, and a decoder
    recursion ceiling, reachable on interpreters whose json module still recurses, carries
    the resource-limit class rather than reading as invalid JSON.
    """
    for depth in (1000, 5000, 50000):
        raw = '{"a":' * depth + "1" + "}" * depth
        result = verify_receipt_v1_serialized(raw, _resolve, max_depth=10_000_000)
        # Parsed through to the validator, which rejects it for what it actually is: a
        # document that is not a receipt. Never a parse failure, never an escape.
        assert result["status"] == "invalid"
        assert result["errors"][0] != "parse_error"
        assert "RESOURCE_LIMIT" not in result["errors"]

    # The configured ceiling still reports itself, and still on the resource axis.
    at_ceiling = verify_receipt_v1_serialized('{"a":' * 200 + "1" + "}" * 200, _resolve)
    assert at_ceiling["status"] == "indeterminate"
    assert at_ceiling["errors"][0] == "RESOURCE_LIMIT"


# --- rule A: only required signatures decide a receipt's state -------------------------
# Draft line 1041 has a verifier verify every REQUIRED signature, and line 999 names one:
# "one signature MUST be from issuer". Draft lines 1003-1009 compute receipt_id with
# signatures absent, so the signatures array sits outside the content address and a third
# party can append a descriptor to a published receipt without changing any digest.


def test_appended_non_required_signature_does_not_flip_a_conforming_receipt():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"
    assert control["other_signatures"] == "none"

    tampered = copy.deepcopy(receipt)
    tampered["signatures"].append({
        "signer": "did:example:bystander",
        "key_id": "did:example:bystander#k",
        "alg": "Ed25519",
        "value": "0" * 128,
    })
    result = verify_receipt_v1(tampered, lambda *_: PUBLIC_KEY)
    assert result["status"] == "valid"
    assert result["other_signatures"] == "not_all_verified"
    assert "signature_invalid" not in result["errors"]
    by_signer = {item["signer"]: item for item in result["signature_results"]}
    assert by_signer[AGENT]["required"] is True
    assert by_signer["did:example:bystander"]["required"] is False
    assert by_signer["did:example:bystander"]["valid"] is False


def test_appended_second_issuer_signature_that_fails_makes_it_invalid():
    """The pair with the test above: appending from the issuer, who IS in the required
    set, decides the aggregate state; appending from a bystander, who is not, does not.
    The axis is the required set, not the signature count."""
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    tampered = copy.deepcopy(receipt)
    tampered["signatures"].append({
        "signer": AGENT,
        "key_id": "key-2",
        "alg": "Ed25519",
        "value": "0" * 128,
    })
    result = verify_receipt_v1(tampered, lambda *_: PUBLIC_KEY)
    assert result["status"] == "invalid"
    assert result["signer_authority"] == "invalid"
    assert "signature_invalid" in result["errors"]
    assert result["other_signatures"] == "none"
    by_key_id = {item["key_id"]: item for item in result["signature_results"]}
    assert by_key_id["key-1"]["required"] is True
    assert by_key_id["key-2"]["required"] is True


def test_required_signer_the_receipt_does_not_carry_is_missing():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    result = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY, required_signers=["did:example:cosigner"])
    assert result["status"] == "invalid"
    assert "required_signature_missing" in result["errors"]
    # The signer that IS present still verified; the missing one is a separate finding
    # from signer authority, which describes only the signatures actually carried.
    assert result["signer_authority"] == "verified"


# --- rule B: key resolution outcomes are kept apart -------------------------------------
# Draft section 2.5 lines 360-364 require a resolver to distinguish six outcomes: resolved;
# subject or key not found; ambiguous; structurally malformed key material; transport
# unreachability; and an unsupported identifier scheme.


@pytest.mark.parametrize(
    "outcome,expected_reason,expected_status,expected_error",
    [
        ("not_found", "key_not_found", "indeterminate", "signer_authority_indeterminate"),
        ("ambiguous", "key_ambiguous", "indeterminate", "signer_authority_indeterminate"),
        ("unreachable", "key_unreachable", "indeterminate", "signer_authority_indeterminate"),
        ("malformed", "key_material_malformed", "indeterminate", "signer_authority_indeterminate"),
        ("unsupported_scheme", "key_scheme_unsupported", "unsupported", "signer_key_scheme_unsupported"),
    ],
)
def test_resolver_outcome_mapping(outcome, expected_reason, expected_status, expected_error):
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    result = verify_receipt_v1(receipt, lambda *_: {"outcome": outcome})
    assert result["status"] == expected_status
    assert expected_error in result["errors"]
    assert "signature_invalid" not in result["errors"]
    entry = next(item for item in result["signature_results"] if item["signer"] == AGENT)
    assert entry["reason"] == expected_reason


def test_resolver_returning_none_keeps_key_unresolved():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    result = verify_receipt_v1(receipt, lambda *_: None)
    assert result["status"] == "indeterminate"
    entry = next(item for item in result["signature_results"] if item["signer"] == AGENT)
    assert entry["reason"] == "key_unresolved"
    assert "signature_invalid" not in result["errors"]


def test_resolver_raising_keeps_key_resolution_error():
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    def raises(*_):
        raise RuntimeError("resolver unavailable")

    result = verify_receipt_v1(receipt, raises)
    assert result["status"] == "indeterminate"
    entry = next(item for item in result["signature_results"] if item["signer"] == AGENT)
    assert entry["reason"] == "key_resolution_error"
    assert "signature_invalid" not in result["errors"]


@pytest.mark.parametrize(
    "bad_key",
    ["ab" * 16, "ab" * 33, "g" + "0" * 63, ""],
    ids=["too_short", "too_long", "non_hex_character", "empty_string"],
)
def test_malformed_key_material_never_reaches_the_signature_check(bad_key):
    """Material that is not 32 bytes of hexadecimal must not reach the signature check.
    Before this, it reached the check, which returns False on a length mismatch, so it
    was reported as signature_invalid, saying the bytes were checked and failed when
    nothing was checked."""
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    result = verify_receipt_v1(receipt, lambda *_: bad_key)
    assert result["status"] == "indeterminate"
    assert result["signer_authority"] == "not_established"
    assert "signature_invalid" not in result["errors"]
    entry = next(item for item in result["signature_results"] if item["signer"] == AGENT)
    assert entry["reason"] == "key_material_malformed"


def test_well_formed_wrong_key_is_still_signature_invalid():
    """Control for the malformed-key-material cases above: a key that IS well-formed (32
    bytes of hex) but simply did not sign the receipt reaches the check and fails it,
    which is a real signature_invalid, not a resolution failure."""
    receipt = build_receipt(action_intent_fields())
    control = verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)
    assert control["status"] == "valid"

    result = verify_receipt_v1(receipt, lambda *_: WRONG_PUBLIC_KEY)
    assert result["status"] == "invalid"
    assert "signature_invalid" in result["errors"]
    entry = next(item for item in result["signature_results"] if item["signer"] == AGENT)
    assert "reason" not in entry
