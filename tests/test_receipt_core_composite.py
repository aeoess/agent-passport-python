"""The section 5.6 composite receipt and decision verifier, mirroring
tests/receipt-core-composite.test.ts in the TypeScript reference case for case, plus the
frozen no-predecessor table from tests/receipt-core-predecessor.test.ts.
"""

from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import (
    build_decision_ref_v1,
    create_receipt_v1,
    verify_receipt_with_decision_v1,
)

PRIVATE_KEY = "00" * 32
PUBLIC_KEY = public_key_from_private(PRIVATE_KEY)

BOUNDARY = "did:example:issuer"
AGENT = "did:example:agent"
ISSUED_AT = "2026-04-08T12:00:00.000Z"


def hx(char):
    return char * 64


ACTION_REF = hx("a")
DELEGATION_REF = "sha256:" + hx("c")


def resolve_key(signer, key_id, issued_at):
    return PUBLIC_KEY


def resolve_nothing(signer, key_id, issued_at):
    return None


def decision_output(valid_until, verdict="permit"):
    return {
        "profile": "aps-core-decision-output-v1",
        "verdict": verdict,
        "effective_authority_ref": None if verdict == "deny" else hx("b"),
        "constraints": [],
        "valid_until": valid_until,
    }


def decision_evidence(valid_until, policy_id="p1", verdict="permit"):
    """The decision a receipt will reference. Any component change alters decision_ref."""
    return {
        "authority_state": {"scope": ["read"], "revoked": False},
        "policy_input": {"id": policy_id, "version": "1"},
        "decision_context": {"tenant": "t1"},
        "decision_output": decision_output(valid_until, verdict),
    }


def sign_as(issuer, fields):
    return create_receipt_v1(fields, [{"signer": issuer, "key_id": "k1", "private_key": PRIVATE_KEY}])


def receipt_for(decision, with_decision_ref=True):
    """A signed policy-decision receipt carrying the decision_ref for the supplied decision,
    and, as section 5.4 lines 1183-1184 require, that decision's own output as its result."""
    decision_ref = build_decision_ref_v1(action_ref=ACTION_REF, **decision)["decision_ref"]
    fields = {
        "profile": "aps-receipt-v1",
        "receipt_type": "aps:policy-decision:v1",
        "issuer": BOUNDARY,
        "subject_agent": AGENT,
        "action_ref": ACTION_REF,
        "delegation_ref": DELEGATION_REF,
        "prev": hx("d"),
        "issued_at": ISSUED_AT,
        "evidence_refs": [],
        "result": decision["decision_output"],
    }
    if with_decision_ref:
        fields["decision_ref"] = decision_ref
    return sign_as(BOUNDARY, fields)


def action_result_for(decision, issued_at):
    decision_ref = build_decision_ref_v1(action_ref=ACTION_REF, **decision)["decision_ref"]
    return sign_as(
        BOUNDARY,
        {
            "profile": "aps-receipt-v1",
            "receipt_type": "aps:action-result:v1",
            "issuer": BOUNDARY,
            "subject_agent": AGENT,
            "action_ref": ACTION_REF,
            "delegation_ref": DELEGATION_REF,
            "decision_ref": decision_ref,
            "prev": hx("d"),
            "issued_at": issued_at,
            "evidence_refs": [],
            "result": {
                "profile": "aps-action-result-v1",
                "status": "succeeded",
                "effect_ref": hx("f"),
                "error_code": None,
            },
        },
    )


def verify(receipt, decision):
    """The boundary identity is verifier trust input, so every call that expects a decided
    answer supplies it; the axis has its own test below."""
    return verify_receipt_with_decision_v1(receipt, decision, resolve_key, boundary_identity=BOUNDARY)


def test_positive_case_bound_decision_with_a_later_valid_until():
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    result = verify(receipt_for(decision), decision)
    assert result["valid"] is True
    assert result["errors"] == []
    assert result["receipt"]["valid"] is True
    assert result["decision_ref_present"] is True
    assert result["decision_ref_bound"] is True
    assert result["temporal_relation_valid"] is True


def test_temporal_negative_valid_until_equal_to_issued_at_rejects():
    # Strictly later is required, so the boundary value must fail. The window lives in the
    # receipt's own result, so the record fails its section 5.3.2 stage rule and the
    # composite reports that rather than reaching the cross-document comparison. Either way
    # the pair is refused, and the stage failure names the record that carries the defect.
    decision = decision_evidence(ISSUED_AT)
    result = verify(receipt_for(decision), decision)
    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert "stage_invalid" in result["errors"]
    assert "DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT" in result["errors"]
    assert "stage_indeterminate" not in result["errors"]
    assert result["temporal_relation_valid"] is False


def test_temporal_negative_valid_until_earlier_than_issued_at_rejects():
    decision = decision_evidence("2026-04-08T11:59:59.999Z")
    result = verify(receipt_for(decision), decision)
    assert result["valid"] is False
    assert "DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT" in result["errors"]


def test_substitution_negative_a_valid_decision_with_the_wrong_digest_rejects():
    # The receipt commits to decision A. Decision B is fully valid on its own and its
    # valid_until is comfortably later than issued_at, so every check except the binding
    # would pass. This is the substitution hole: without binding, B would be accepted as
    # evidence about a receipt that never referenced it.
    committed = decision_evidence("2026-04-08T12:00:05.000Z", policy_id="p1")
    substituted = decision_evidence("2026-04-08T23:00:00.000Z", policy_id="p2-attacker")
    receipt = receipt_for(committed)

    ref_a = build_decision_ref_v1(action_ref=ACTION_REF, **committed)["decision_ref"]
    ref_b = build_decision_ref_v1(action_ref=ACTION_REF, **substituted)["decision_ref"]
    assert ref_a != ref_b
    assert receipt["decision_ref"] == ref_a
    assert substituted["decision_output"]["valid_until"] > ISSUED_AT

    result = verify(receipt, substituted)
    assert result["valid"] is False
    assert "decision_ref_mismatch" in result["errors"]
    # The temporal stage must not have run: an ordering result over an unbound pair says
    # nothing about this receipt.
    assert result["temporal_relation_valid"] is False
    assert "valid_until_not_after_issued_at" not in result["errors"]


def test_absent_decision_ref_rejects_rather_than_passing():
    # A policy-decision record without decision_ref breaks its own stage rule (line 984), so
    # that is what the composite reports. It is refused either way; the code names the
    # record's defect rather than the missing relation.
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    receipt = receipt_for(decision, with_decision_ref=False)
    assert "decision_ref" not in receipt
    result = verify(receipt, decision)
    assert result["valid"] is False
    assert "DECISION_REF_MISSING" in result["errors"]
    assert result["decision_ref_present"] is False
    assert result["decision_ref_bound"] is False

    # For a stage where decision_ref is absent by rule, passing a decision is still an error
    # rather than a silent pass: the relation was never examined.
    intent = sign_as(
        AGENT,
        {
            "profile": "aps-receipt-v1",
            "receipt_type": "aps:action-intent:v1",
            "issuer": AGENT,
            "subject_agent": AGENT,
            "action_ref": ACTION_REF,
            "delegation_ref": DELEGATION_REF,
            "issued_at": ISSUED_AT,
            "evidence_refs": [],
            "result": {"profile": "aps-action-intent-result-v1", "status": "declared"},
        },
    )
    intent_result = verify(intent, decision)
    assert intent_result["valid"] is False
    assert "decision_ref_absent" in intent_result["errors"]


def test_a_correct_deny_decision_verifies_it_is_not_a_temporal_failure():
    # Draft line 1090 requires valid_until to be null for deny. Treating that absence as a
    # failure made every conforming deny decision fail this verifier, which is the opposite
    # of what the rule says.
    decision = decision_evidence(None, verdict="deny")
    result = verify(receipt_for(decision), decision)
    assert result["valid"] is True
    assert result["status"] == "valid"
    assert result["errors"] == []
    assert result["decision_ref_bound"] is True
    assert result["decision_output_bound"] is True
    assert result["temporal_relation_valid"] is True


def test_the_decision_output_must_be_the_result_the_receipt_carries_and_signs():
    # The digest binding alone did not establish this. decision_ref commits to a digest of
    # the output; nothing compared that output with receipt["result"], so a decision object
    # whose output differed from the signed result could still bind.
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    receipt = receipt_for(decision)
    swapped = {**receipt, "result": {**decision["decision_output"], "verdict": "narrow"}}
    result = verify(swapped, decision)
    assert result["valid"] is False
    # The swap changes the signed body, so integrity fails first; the point of the case is
    # that a caller cannot reach a valid composite with a result that is not the output.
    assert "receipt_invalid" in result["errors"] or "decision_output_mismatch" in result["errors"]

    # And the same check with the signature kept intact, by re-signing the swapped body.
    re_signed = sign_as(
        BOUNDARY,
        {
            "profile": "aps-receipt-v1",
            "receipt_type": "aps:policy-decision:v1",
            "issuer": BOUNDARY,
            "subject_agent": AGENT,
            "action_ref": ACTION_REF,
            "delegation_ref": DELEGATION_REF,
            "decision_ref": receipt["decision_ref"],
            "prev": hx("d"),
            "issued_at": ISSUED_AT,
            "evidence_refs": [],
            "result": {**decision["decision_output"], "verdict": "narrow"},
        },
    )
    re_signed_result = verify(re_signed, decision)
    assert re_signed_result["valid"] is False
    assert re_signed_result["decision_ref_bound"] is True
    assert re_signed_result["decision_output_bound"] is False
    assert "decision_output_mismatch" in re_signed_result["errors"]


def test_an_unresolvable_signing_key_is_indeterminate_not_a_failed_signature():
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    result = verify_receipt_with_decision_v1(
        receipt_for(decision), decision, resolve_nothing, boundary_identity=BOUNDARY
    )
    assert result["valid"] is False
    assert result["status"] == "indeterminate"
    assert result["receipt"]["signer_authority"] == "not_established"
    assert "signer_authority_indeterminate" in result["errors"]
    assert "signature_invalid" not in result["errors"]
    # The sub-result code names the status it reports, so a caller reading the codes is not
    # told the receipt was invalid when an axis was merely unestablished.
    assert "receipt_indeterminate" in result["errors"]
    assert "receipt_invalid" not in result["errors"]


def test_with_no_boundary_identity_supplied_the_composite_is_indeterminate():
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    result = verify_receipt_with_decision_v1(receipt_for(decision), decision, resolve_key)
    assert result["valid"] is False
    assert result["status"] == "indeterminate"
    assert result["stage"]["boundary_identity"] == "not_established"
    assert "stage_indeterminate" in result["errors"]
    assert "stage_invalid" not in result["errors"]
    # Indeterminate here is an unestablished axis, not a failed rule.
    assert result["stage"]["failures"] == []


def test_an_unverifiable_receipt_fails_at_stage_one_and_later_stages_do_not_run():
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    tampered = {**receipt_for(decision), "result": {"status": "tampered"}}
    result = verify(tampered, decision)
    assert result["valid"] is False
    assert "receipt_invalid" in result["errors"]
    assert result["decision_ref_present"] is False
    assert result["decision_ref_bound"] is False
    assert result["temporal_relation_valid"] is False


def test_an_action_result_does_not_claim_a_temporal_check_that_was_not_made():
    # The window belongs to the decision, and the draft states no relation between it and
    # the issuance time of a later record, so the comparison is deliberately skipped for
    # this stage. Reporting True said a check had passed that never ran.
    decision = decision_evidence("2026-04-08T12:00:05.000Z")
    verified = verify(action_result_for(decision, "2099-01-01T00:00:00.000Z"), decision)
    assert verified["valid"] is True
    # Issued 73 years after the window closed.
    assert verified["temporal_relation_valid"] == "not_applicable"
    assert verified["decision_output_bound"] == "not_applicable"
    # The policy-decision stage still reports a real answer.
    assert verify(receipt_for(decision), decision)["temporal_relation_valid"] is True


def test_a_decision_output_that_is_not_canonical_cannot_bind():
    # build_decision_ref_v1 normalizes before hashing, so ["b","a","a"] and ["a","b"] produce
    # the same decision_ref. On an action-result record the output is not compared with the
    # receipt's result, so without validating the supplied output first, a component this
    # SDK's own verifier rejects would bind.
    canonical = decision_evidence("2026-04-08T12:00:05.000Z")
    result = action_result_for(canonical, ISSUED_AT)
    assert verify(result, canonical)["valid"] is True, "control: the canonical output binds"

    non_canonical = {
        **canonical,
        "decision_output": {**canonical["decision_output"], "constraints": ["b", "a", "a"]},
    }
    refused = verify(result, non_canonical)
    assert refused["valid"] is False
    assert "decision_input_invalid" in refused["errors"]
    assert refused["decision_ref_bound"] is False


def test_without_the_predecessor_argument_every_existing_result_is_unchanged():
    # The frozen table below is the answer this composite gives on each of the inputs above
    # with no predecessor argument. If the opt-in axis ever moves an existing caller's valid,
    # status, errors or per-axis flags, one of these fails.
    keys = [
        "valid", "status", "receipt", "stage", "decision_ref_present", "decision_ref_bound",
        "decision_output_bound", "temporal_relation_valid", "predecessor_bound", "errors",
    ]

    def check(name, actual, expected):
        assert list(actual) == keys, f"{name}: the key set is the eight original members, predecessor_bound and errors"
        assert actual["predecessor_bound"] == "not_checked", f"{name}: unrequested axis is not_checked"
        rest = {key: value for key, value in actual.items() if key not in ("predecessor_bound", "receipt", "stage")}
        assert {
            **rest,
            "receipt_status": actual["receipt"]["status"],
            "stage_status": actual["stage"]["status"],
        } == expected, name

    permit = decision_evidence("2026-04-08T12:00:05.000Z")
    check("permit_bound", verify(receipt_for(permit), permit), {
        "valid": True, "status": "valid", "decision_ref_present": True, "decision_ref_bound": True,
        "decision_output_bound": True, "temporal_relation_valid": True, "errors": [],
        "receipt_status": "valid", "stage_status": "valid",
    })

    equal = decision_evidence(ISSUED_AT)
    check("valid_until_equal", verify(receipt_for(equal), equal), {
        "valid": False, "status": "invalid", "decision_ref_present": False, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["receipt_invalid", "stage_invalid", "DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT"],
        "receipt_status": "invalid", "stage_status": "invalid",
    })

    earlier = decision_evidence("2026-04-08T11:59:59.999Z")
    check("valid_until_earlier", verify(receipt_for(earlier), earlier), {
        "valid": False, "status": "invalid", "decision_ref_present": False, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["receipt_invalid", "stage_invalid", "DECISION_VALID_UNTIL_NOT_AFTER_ISSUED_AT"],
        "receipt_status": "invalid", "stage_status": "invalid",
    })

    committed = decision_evidence("2026-04-08T12:00:05.000Z", policy_id="p1")
    substituted = decision_evidence("2026-04-08T23:00:00.000Z", policy_id="p2-attacker")
    check("substitution", verify(receipt_for(committed), substituted), {
        "valid": False, "status": "invalid", "decision_ref_present": True, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["decision_ref_mismatch"], "receipt_status": "valid", "stage_status": "valid",
    })

    check("no_decision_ref", verify(receipt_for(permit, with_decision_ref=False), permit), {
        "valid": False, "status": "invalid", "decision_ref_present": False, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["receipt_invalid", "stage_invalid", "DECISION_REF_MISSING"],
        "receipt_status": "invalid", "stage_status": "invalid",
    })

    deny = decision_evidence(None, verdict="deny")
    check("deny", verify(receipt_for(deny), deny), {
        "valid": True, "status": "valid", "decision_ref_present": True, "decision_ref_bound": True,
        "decision_output_bound": True, "temporal_relation_valid": True, "errors": [],
        "receipt_status": "valid", "stage_status": "valid",
    })

    check("unresolvable_key", verify_receipt_with_decision_v1(
        receipt_for(permit), permit, resolve_nothing, boundary_identity=BOUNDARY,
    ), {
        "valid": False, "status": "indeterminate", "decision_ref_present": False, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["receipt_indeterminate", "signer_authority_indeterminate"],
        "receipt_status": "indeterminate", "stage_status": "valid",
    })

    check("no_boundary", verify_receipt_with_decision_v1(receipt_for(permit), permit, resolve_key), {
        "valid": False, "status": "indeterminate", "decision_ref_present": False, "decision_ref_bound": False,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": False,
        "errors": ["receipt_indeterminate", "stage_indeterminate"],
        "receipt_status": "indeterminate", "stage_status": "indeterminate",
    })

    check("action_result", verify(action_result_for(permit, "2099-01-01T00:00:00.000Z"), permit), {
        "valid": True, "status": "valid", "decision_ref_present": True, "decision_ref_bound": True,
        "decision_output_bound": "not_applicable", "temporal_relation_valid": "not_applicable",
        "errors": [], "receipt_status": "valid", "stage_status": "valid",
    })

    non_canonical = {
        **permit,
        "decision_output": {**permit["decision_output"], "constraints": ["b", "a", "a"]},
    }
    non_canonical_result = verify(action_result_for(permit, ISSUED_AT), non_canonical)
    assert list(non_canonical_result) == keys
    assert non_canonical_result["predecessor_bound"] == "not_checked"
    assert non_canonical_result["valid"] is False
    assert non_canonical_result["status"] == "invalid"
    assert non_canonical_result["decision_ref_present"] is True
    assert non_canonical_result["decision_ref_bound"] is False
    assert non_canonical_result["errors"][0] == "decision_input_invalid"


def test_decision_evidence_missing_a_component_is_a_decision_input_failure():
    # A Python caller can omit a member of the evidence mapping where the TypeScript type
    # would have refused the object at compile time. The observable answer is the same one
    # TypeScript gives at run time for the same hole: decision_input_invalid, never a raise
    # out of the verifier and never a pass.
    permit = decision_evidence("2026-04-08T12:00:05.000Z")
    for missing in ("authority_state", "policy_input", "decision_context", "decision_output"):
        evidence = {key: value for key, value in permit.items() if key != missing}
        result = verify(receipt_for(permit), evidence)
        assert result["valid"] is False, missing
        assert result["status"] == "invalid", missing
        assert result["errors"][0] == "decision_input_invalid", missing
        assert result["decision_ref_present"] is True, missing
        assert result["decision_ref_bound"] is False, missing
