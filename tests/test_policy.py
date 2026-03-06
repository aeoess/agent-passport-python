"""Tests for Policy Engine (Layer 5b — 3-signature chain)."""

from datetime import datetime, timedelta, timezone

from agent_passport import (
    generate_key_pair,
    create_action_intent,
    verify_action_intent,
    evaluate_intent,
    verify_policy_decision,
    create_policy_receipt,
    verify_policy_receipt,
    FloorValidatorV1,
    request_action,
    create_delegation,
    create_action_receipt,
)


def _valid_context(agent_kp, delegation):
    return {
        "agentRegistered": True,
        "agentAttestationValid": True,
        "floorVersion": "0.1",
        "delegation": delegation,
        "floorPrinciples": [],
    }


def test_create_and_verify_action_intent():
    kp = generate_key_pair()
    intent = create_action_intent(
        agent_id="agent-1", agent_public_key=kp["publicKey"],
        delegation_id="del-1",
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"},
        private_key=kp["privateKey"],
    )
    assert intent["signature"]
    result = verify_action_intent(intent)
    assert result["valid"]


def test_tampered_intent_fails():
    kp = generate_key_pair()
    intent = create_action_intent(
        agent_id="agent-1", agent_public_key=kp["publicKey"],
        delegation_id="del-1",
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"},
        private_key=kp["privateKey"],
    )
    intent["agentId"] = "hacker"
    result = verify_action_intent(intent)
    assert not result["valid"]


def test_floor_validator_permits_valid_action():
    agent_kp = generate_key_pair()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["code_execution"],
        private_key=evaluator_kp["privateKey"],
        spend_limit=100,
    )
    intent = create_action_intent(
        agent_id="agent-1", agent_public_key=agent_kp["publicKey"],
        delegation_id=delegation["delegationId"],
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"},
        private_key=agent_kp["privateKey"],
    )
    ctx = _valid_context(agent_kp, delegation)
    validator = FloorValidatorV1()
    decision = evaluate_intent(
        intent=intent, validator=validator, validation_context=ctx,
        evaluator_id="eval-1", evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert decision["verdict"] == "permit"
    assert decision["signature"]
    check = verify_policy_decision(decision)
    assert check["valid"]


def test_scope_violation_denies():
    agent_kp = generate_key_pair()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["web_search"],
        private_key=evaluator_kp["privateKey"],
    )
    intent = create_action_intent(
        agent_id="agent-1", agent_public_key=agent_kp["publicKey"],
        delegation_id=delegation["delegationId"],
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "evil.py"},
        private_key=agent_kp["privateKey"],
    )
    ctx = _valid_context(agent_kp, delegation)
    validator = FloorValidatorV1()
    decision = evaluate_intent(
        intent=intent, validator=validator, validation_context=ctx,
        evaluator_id="eval-1", evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert decision["verdict"] == "deny"


def test_revoked_delegation_denies():
    agent_kp = generate_key_pair()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["code_execution"],
        private_key=evaluator_kp["privateKey"],
    )
    delegation["revoked"] = True
    intent = create_action_intent(
        agent_id="agent-1", agent_public_key=agent_kp["publicKey"],
        delegation_id=delegation["delegationId"],
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"},
        private_key=agent_kp["privateKey"],
    )
    ctx = _valid_context(agent_kp, delegation)
    validator = FloorValidatorV1()
    decision = evaluate_intent(
        intent=intent, validator=validator, validation_context=ctx,
        evaluator_id="eval-1", evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert decision["verdict"] == "deny"


def test_full_three_signature_chain():
    agent_kp = generate_key_pair()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["code_execution"],
        private_key=evaluator_kp["privateKey"],
        spend_limit=100,
    )
    result = request_action(
        agent_id="agent-1", agent_public_key=agent_kp["publicKey"],
        agent_private_key=agent_kp["privateKey"],
        delegation_id=delegation["delegationId"],
        action={"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"},
        validator=FloorValidatorV1(),
        validation_context=_valid_context(agent_kp, delegation),
        evaluator_id="eval-1", evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert result["decision"]["verdict"] == "permit"

    # Create action receipt and policy receipt
    receipt = create_action_receipt(
        agent_id="agent-1", delegation=delegation,
        action_type="code_execution", target="main.py",
        scope_used="code_execution", result_status="success",
        result_summary="Executed main.py", private_key=agent_kp["privateKey"],
    )
    pr = create_policy_receipt(
        intent=result["intent"], decision=result["decision"],
        receipt=receipt, verifier_private_key=evaluator_kp["privateKey"],
    )
    assert pr["policyReceiptId"]
    check = verify_policy_receipt(pr, evaluator_kp["publicKey"])
    assert check["valid"]


def test_request_action_convenience():
    agent_kp = generate_key_pair()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["web_search"],
        private_key=evaluator_kp["privateKey"],
        spend_limit=50,
    )
    result = request_action(
        agent_id="searcher", agent_public_key=agent_kp["publicKey"],
        agent_private_key=agent_kp["privateKey"],
        delegation_id=delegation["delegationId"],
        action={"type": "web_search", "scopeRequired": "web_search", "target": "query"},
        validator=FloorValidatorV1(),
        validation_context=_valid_context(agent_kp, delegation),
        evaluator_id="eval-1", evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert result["intent"]["intentId"]
    assert result["decision"]["verdict"] == "permit"
