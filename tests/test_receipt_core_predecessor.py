"""The section 5.3.3 prev binding primitive, mirroring tests/receipt-core-predecessor.test.ts
in the TypeScript reference case for case.

Every digest below comes from create_receipt_v1 and compute_receipt_id_v1; none is written
by hand, so a test that passes here passes against bytes this SDK itself produces.
"""

from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import (
    build_decision_ref_v1,
    compute_receipt_id_v1,
    create_receipt_v1,
    verify_receipt_predecessor_v1,
    verify_receipt_with_decision_v1,
)

PRIVATE_KEY = "00" * 32
PUBLIC_KEY = public_key_from_private(PRIVATE_KEY)

BOUNDARY = "did:example:issuer"
AGENT = "did:example:agent"
INTENT_AT = "2026-04-08T11:59:00.000Z"
DECISION_AT = "2026-04-08T12:00:00.000Z"
RESULT_AT = "2026-04-08T12:00:01.000Z"


def hx(char):
    return char * 64


ACTION_REF = hx("a")
DELEGATION_REF = "sha256:" + hx("c")


def resolve_key(signer, key_id, issued_at):
    return PUBLIC_KEY


def decision_output(valid_until, verdict="permit"):
    return {
        "profile": "aps-core-decision-output-v1",
        "verdict": verdict,
        "effective_authority_ref": None if verdict == "deny" else hx("b"),
        "constraints": [],
        "valid_until": valid_until,
    }


def decision_evidence(policy_id="p1"):
    return {
        "authority_state": {"scope": ["read"], "revoked": False},
        "policy_input": {"id": policy_id, "version": "1"},
        "decision_context": {"tenant": "t1"},
        "decision_output": decision_output("2026-04-08T12:00:05.000Z"),
    }


def sign_as(issuer, fields):
    return create_receipt_v1(fields, [{"signer": issuer, "key_id": "k1", "private_key": PRIVATE_KEY}])


def action_result(decision_ref, prev, issued_at=RESULT_AT):
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
            "prev": prev,
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


def mint_chain(policy_id="p1"):
    """A REAL three-record chain, minted end to end by the SDK."""
    decision = decision_evidence(policy_id)
    decision_ref = build_decision_ref_v1(action_ref=ACTION_REF, **decision)["decision_ref"]

    intent = sign_as(
        AGENT,
        {
            "profile": "aps-receipt-v1",
            "receipt_type": "aps:action-intent:v1",
            "issuer": AGENT,
            "subject_agent": AGENT,
            "action_ref": ACTION_REF,
            "delegation_ref": DELEGATION_REF,
            "issued_at": INTENT_AT,
            "evidence_refs": [],
            "result": {"profile": "aps-action-intent-result-v1", "status": "declared"},
        },
    )
    policy_decision = sign_as(
        BOUNDARY,
        {
            "profile": "aps-receipt-v1",
            "receipt_type": "aps:policy-decision:v1",
            "issuer": BOUNDARY,
            "subject_agent": AGENT,
            "action_ref": ACTION_REF,
            "delegation_ref": DELEGATION_REF,
            "decision_ref": decision_ref,
            "prev": intent["receipt_id"],
            "issued_at": DECISION_AT,
            "evidence_refs": [],
            "result": decision["decision_output"],
        },
    )
    return {
        "decision": decision,
        "decision_ref": decision_ref,
        "intent": intent,
        "policy_decision": policy_decision,
        "action_result": action_result(decision_ref, policy_decision["receipt_id"]),
    }


def test_the_correct_policy_decision_record_binds():
    chain = mint_chain()
    result = verify_receipt_predecessor_v1(chain["action_result"], chain["policy_decision"])
    assert result["status"] == "valid"
    assert result["bound"] is True
    assert result["failure"] is None
    assert result["detail"] is None
    # The identifier reported is the recomputed one, and for an untampered record it is also
    # the claimed one.
    assert result["recomputed_predecessor_receipt_id"] == chain["policy_decision"]["receipt_id"]
    assert result["recomputed_predecessor_receipt_id"] == chain["action_result"]["prev"]


def test_a_prev_that_names_the_action_intent_record_does_not_bind():
    # The chain's own earlier record, so the digest is real and the link is genuinely wrong
    # rather than wrong because the value is nonsense.
    chain = mint_chain()
    names_intent = action_result(chain["decision_ref"], chain["intent"]["receipt_id"])

    assert chain["intent"]["receipt_id"] != chain["policy_decision"]["receipt_id"]
    result = verify_receipt_predecessor_v1(names_intent, chain["policy_decision"])
    assert result["status"] == "invalid"
    assert result["bound"] is False
    assert result["failure"] == "predecessor_receipt_id_mismatch"
    assert result["recomputed_predecessor_receipt_id"] == chain["policy_decision"]["receipt_id"]


def test_the_action_intent_record_in_the_predecessor_slot_is_the_wrong_type():
    # Section 5.3.3 line 1104 names the consumed POLICY DECISION. An action-intent record is
    # refused on its type before any digest is compared, so a chain cannot skip the decision.
    chain = mint_chain()
    names_intent = action_result(chain["decision_ref"], chain["intent"]["receipt_id"])

    # The digest would match: prev really is this record's receipt_id. Only the type refuses
    # it, which is the point of the case.
    assert compute_receipt_id_v1(chain["intent"]) == names_intent["prev"]
    result = verify_receipt_predecessor_v1(names_intent, chain["intent"])
    assert result["status"] == "invalid"
    assert result["failure"] == "predecessor_not_policy_decision"
    # Refused before the recomputation.
    assert result["recomputed_predecessor_receipt_id"] is None


def test_a_missing_predecessor_is_indeterminate_never_valid_and_never_a_refusal():
    chain = mint_chain()
    result = verify_receipt_predecessor_v1(chain["action_result"], None)
    assert result["status"] == "indeterminate"
    assert result["bound"] is False
    assert result["failure"] == "predecessor_not_supplied"
    assert result["recomputed_predecessor_receipt_id"] is None
    # Calling with the argument omitted entirely is the same state. TypeScript's undefined
    # and null both map to Python's None, so the reference's two absent values are one here.
    assert verify_receipt_predecessor_v1(chain["action_result"])["status"] == "indeterminate"


def test_a_receipt_id_edited_to_match_prev_does_not_bind_the_body_is_recomputed():
    # THE CASE THE RECOMPUTATION EXISTS FOR. receipt_id sits outside its own preimage (lines
    # 1003-1009), so anyone can rewrite the field to whatever prev names without touching a
    # signature or a digest. Reading the claimed field would accept this pair.
    chain = mint_chain()
    names_intent = action_result(chain["decision_ref"], chain["intent"]["receipt_id"])

    # Relabel the policy-decision record's identifier to the value prev names. Its body is
    # untouched, so it still recomputes to its real identifier.
    relabelled = {**chain["policy_decision"], "receipt_id": chain["intent"]["receipt_id"]}
    assert relabelled["receipt_id"] == names_intent["prev"], "fixture guard: the CLAIMED field matches prev"
    assert compute_receipt_id_v1(relabelled) != names_intent["prev"], "fixture guard: the BODY does not"

    result = verify_receipt_predecessor_v1(names_intent, relabelled)
    assert result["status"] == "invalid"
    assert result["failure"] == "predecessor_receipt_id_mismatch"
    # The reported identifier is the recomputed one, not the claimed one.
    assert result["recomputed_predecessor_receipt_id"] == chain["policy_decision"]["receipt_id"]


def test_a_decision_ref_that_differs_from_the_predecessor_does_not_bind():
    # Section 5.3.3 line 1105: decision_ref MUST equal that decision's decision_ref. The
    # digest link can hold while the two records name different decisions, so the equality is
    # its own check. The second decision is a real one, built from different policy input.
    chain = mint_chain()
    other = build_decision_ref_v1(action_ref=ACTION_REF, **decision_evidence("p2-other"))["decision_ref"]
    assert other != chain["policy_decision"]["decision_ref"], "fixture guard: the two decisions differ"

    disagrees = action_result(other, chain["policy_decision"]["receipt_id"])
    result = verify_receipt_predecessor_v1(disagrees, chain["policy_decision"])
    assert result["status"] == "invalid"
    assert result["failure"] == "decision_ref_mismatch"
    # The prev link itself held, so the recomputation ran and is reported.
    assert result["recomputed_predecessor_receipt_id"] == chain["policy_decision"]["receipt_id"]


def test_a_record_that_is_not_an_action_result_is_not_applicable():
    # Including the policy-decision to action-intent link of section 5.3.2 line 1072, which is
    # out of scope for this primitive. not_applicable is not a pass.
    chain = mint_chain()
    for subject, name in ((chain["intent"], "action-intent"), (chain["policy_decision"], "policy-decision")):
        result = verify_receipt_predecessor_v1(subject, chain["intent"])
        assert result["status"] == "not_applicable", name
        assert result["bound"] is False, f"{name}: not_applicable is never a pass"
        assert result["failure"] is None
    # The policy-decision record's own prev really does name the intent, and this primitive
    # still declines to judge it.
    assert chain["policy_decision"]["prev"] == chain["intent"]["receipt_id"]
    assert verify_receipt_predecessor_v1(chain["policy_decision"], chain["intent"])["bound"] is False
    # A malformed predecessor is refused for an action-result subject, so the type dispatch
    # above is what produced not_applicable rather than a lenient structural check.
    malformed = {**chain["policy_decision"], "issued_at": "nope"}
    assert verify_receipt_predecessor_v1(chain["action_result"], malformed)["failure"] == "predecessor_malformed"


def test_a_predecessor_that_is_not_an_object_at_all_is_malformed_not_a_raise():
    # The TypeScript type says ReceiptV1 | null and its validator refuses anything else. In
    # Python nothing stops a caller passing a list, a string or an int, and the same
    # structural refusal answers all of them rather than an exception escaping.
    chain = mint_chain()
    for value in ([], "not-a-receipt", 7, True):
        result = verify_receipt_predecessor_v1(chain["action_result"], value)
        assert result["status"] == "invalid", value
        assert result["failure"] == "predecessor_malformed", value
        assert result["recomputed_predecessor_receipt_id"] is None


def test_a_subject_that_is_not_an_object_at_all_is_not_applicable():
    # The primitive is exported, so it can be handed something that never passed
    # validate_receipt_v1. Reading receipt_type through a type check rather than a member
    # access is what keeps this a defined result.
    for value in (None, [], "x", 7):
        assert verify_receipt_predecessor_v1(value, None)["status"] == "not_applicable", value


def test_an_action_result_with_no_prev_reports_prev_absent():
    # Reachable only when the primitive is called on its own: the stage layer already
    # reports the same record as RESULT_PREV_MISSING, and the composite never reaches here.
    chain = mint_chain()
    no_prev = {key: value for key, value in chain["action_result"].items() if key != "prev"}
    result = verify_receipt_predecessor_v1(no_prev, chain["policy_decision"])
    assert result["status"] == "invalid"
    assert result["failure"] == "prev_absent"
    assert result["recomputed_predecessor_receipt_id"] is None


def test_an_action_result_with_no_decision_ref_reports_decision_ref_absent():
    chain = mint_chain()
    no_ref = {key: value for key, value in chain["action_result"].items() if key != "decision_ref"}
    result = verify_receipt_predecessor_v1(no_ref, chain["policy_decision"])
    assert result["status"] == "invalid"
    assert result["failure"] == "decision_ref_absent"
    # The prev link held, so the recomputation ran before this refusal.
    assert result["recomputed_predecessor_receipt_id"] == chain["policy_decision"]["receipt_id"]


def test_composite_a_wrong_predecessor_is_invalid_the_right_one_is_valid():
    chain = mint_chain()
    decision = chain["decision"]

    # Control: the same call with no predecessor argument is valid and reports not_checked.
    unchecked = verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key, boundary_identity=BOUNDARY
    )
    assert unchecked["valid"] is True
    assert unchecked["predecessor_bound"] == "not_checked"

    # The correct predecessor: the only field that moves is the new one.
    bound = verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key,
        boundary_identity=BOUNDARY, predecessor=chain["policy_decision"],
    )
    assert bound["valid"] is True
    assert bound["status"] == "valid"
    assert bound["predecessor_bound"] is True
    assert {**bound, "predecessor_bound": "not_checked"} == unchecked, (
        "supplying a predecessor that binds changes nothing but the predecessor axis"
    )

    # The wrong predecessor: the composite is invalid and names its own code.
    wrong = verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key,
        boundary_identity=BOUNDARY, predecessor=chain["intent"],
    )
    assert wrong["valid"] is False
    assert wrong["status"] == "invalid"
    assert wrong["predecessor_bound"] is False
    assert "predecessor_not_bound" in wrong["errors"]
    assert "predecessor_not_policy_decision" in wrong["errors"]
    # The earlier binding axes still report what they established before this one ran.
    assert wrong["decision_ref_present"] is True
    assert wrong["decision_ref_bound"] is True

    # A predecessor supplied for a policy-decision record: the axis does not apply, and that
    # does not make the composite fail.
    not_applicable = verify_receipt_with_decision_v1(
        chain["policy_decision"], decision, resolve_key,
        boundary_identity=BOUNDARY, predecessor=chain["intent"],
    )
    assert not_applicable["valid"] is True
    assert not_applicable["predecessor_bound"] == "not_applicable"


def test_composite_the_opt_in_is_the_argument_not_the_value_it_holds():
    # THE CASE THIS DISTINCTION EXISTS FOR. `predecessor=store.get(receipt["prev"])` is how a
    # caller asks for the binding, and a lookup miss puts None in that argument. Read by
    # value, the request evaporates and the composite answers valid for a check nobody ran.
    # Read by whether the argument was passed, the caller learns the axis was not established.
    chain = mint_chain()
    decision = chain["decision"]

    # No argument at all: the default, and the axis is untouched.
    omitted = verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key, boundary_identity=BOUNDARY
    )
    assert omitted["status"] == "valid"
    assert omitted["predecessor_bound"] == "not_checked"
    assert omitted["valid"] is True
    assert omitted["errors"] == []

    # The argument passed as None, which is what a store returning nothing produces and what
    # both TypeScript absent values, undefined and null, map to here.
    explicit_none = verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key, boundary_identity=BOUNDARY, predecessor=None
    )
    assert explicit_none["status"] == "indeterminate"
    assert explicit_none["predecessor_bound"] == "not_established"
    assert explicit_none["valid"] is False
    # The primitive's own code, so the errors say the record was never in hand.
    assert "predecessor_not_supplied" in explicit_none["errors"]

    # not_established is not a refusal: the code for a comparison that refused the pair is
    # absent, and every axis established before this one still reports what it found.
    assert "predecessor_not_bound" not in explicit_none["errors"]
    assert explicit_none["decision_ref_present"] is True
    assert explicit_none["decision_ref_bound"] is True

    # A dict splat that carries the argument through is the same as writing it, which is how
    # this reaches a caller who never typed `predecessor` at the call site.
    carried = {"boundary_identity": BOUNDARY, "predecessor": None}
    assert verify_receipt_with_decision_v1(
        chain["action_result"], decision, resolve_key, **carried
    )["predecessor_bound"] == "not_established"

    # A record that is not an action-result reports not_applicable whatever the argument
    # holds: no rule this axis knows applies to it, so nothing was asked that could fail.
    result = verify_receipt_with_decision_v1(
        chain["policy_decision"], decision, resolve_key, boundary_identity=BOUNDARY, predecessor=None
    )
    assert result["predecessor_bound"] == "not_applicable"
    assert result["status"] == "valid"
    assert result["valid"] is True


def test_composite_the_three_predecessor_states_are_pinned_independently():
    # Each of not_checked, not_established and a decided boolean is asserted on its own, so a
    # regression that moves one of them cannot hide behind another.
    chain = mint_chain()
    decision = chain["decision"]
    call = lambda **kwargs: verify_receipt_with_decision_v1(  # noqa: E731
        chain["action_result"], decision, resolve_key, boundary_identity=BOUNDARY, **kwargs
    )

    not_checked = call()
    assert (not_checked["predecessor_bound"], not_checked["status"], not_checked["valid"]) == (
        "not_checked", "valid", True,
    )
    assert not_checked["errors"] == []

    not_established = call(predecessor=None)
    assert (not_established["predecessor_bound"], not_established["status"], not_established["valid"]) == (
        "not_established", "indeterminate", False,
    )
    assert not_established["errors"] == ["predecessor_not_supplied"]

    decided_true = call(predecessor=chain["policy_decision"])
    assert (decided_true["predecessor_bound"], decided_true["status"], decided_true["valid"]) == (
        True, "valid", True,
    )

    decided_false = call(predecessor=chain["intent"])
    assert (decided_false["predecessor_bound"], decided_false["status"], decided_false["valid"]) == (
        False, "invalid", False,
    )


def test_composite_a_malformed_predecessor_value_makes_the_composite_invalid():
    # Passing something that is not a receipt at all is a decided refusal, not an
    # unestablished axis: the caller supplied an artifact and it is not the one prev names.
    chain = mint_chain()
    result = verify_receipt_with_decision_v1(
        chain["action_result"], chain["decision"], resolve_key,
        boundary_identity=BOUNDARY, predecessor={"not": "a receipt"},
    )
    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert result["predecessor_bound"] is False
    assert "predecessor_not_bound" in result["errors"]
    assert "predecessor_malformed" in result["errors"]
