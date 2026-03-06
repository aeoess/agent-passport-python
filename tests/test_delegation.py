"""Tests for delegation chains, sub-delegation, and revocation."""

import pytest
from agent_passport import (
    generate_key_pair,
    create_delegation,
    verify_delegation,
    sub_delegate,
    revoke_delegation,
    create_action_receipt,
)


def test_creates_valid_delegation():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    d = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution", "web_search"],
        private_key=kp_a["privateKey"],
        spend_limit=500,
    )
    status = verify_delegation(d)
    assert status["valid"]
    assert d["scope"] == ["code_execution", "web_search"]


def test_rejects_forged_signature():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    d = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
    )
    d["scope"].append("ESCALATED")
    status = verify_delegation(d)
    assert not status["valid"]


def test_sub_delegation_within_depth():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    kp_c = generate_key_pair()
    parent = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution", "web_search"],
        private_key=kp_a["privateKey"],
        spend_limit=500,
        max_depth=2,
    )
    child = sub_delegate(parent, kp_c["publicKey"], ["web_search"], kp_b["privateKey"])
    assert child["currentDepth"] == 1
    assert verify_delegation(child)["valid"]


def test_rejects_depth_exceeded():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    kp_c = generate_key_pair()
    parent = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
        max_depth=1,
    )
    child = sub_delegate(parent, kp_c["publicKey"], ["code_execution"], kp_b["privateKey"])
    kp_d = generate_key_pair()
    with pytest.raises(ValueError, match="Depth limit exceeded"):
        sub_delegate(child, kp_d["publicKey"], ["code_execution"], kp_c["privateKey"])


def test_rejects_scope_escalation():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    kp_c = generate_key_pair()
    parent = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
    )
    with pytest.raises(ValueError, match="Scope violation"):
        sub_delegate(parent, kp_c["publicKey"], ["email_management"], kp_b["privateKey"])


def test_revocation():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    d = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
    )
    assert verify_delegation(d)["valid"]
    revoke_delegation(d, kp_a["privateKey"], reason="task_complete")
    status = verify_delegation(d)
    assert not status["valid"]
    assert status["revoked"]


def test_action_receipt():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    d = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
        spend_limit=500,
    )
    receipt = create_action_receipt(
        agent_id="agent-b",
        delegation=d,
        action_type="code_execution",
        target="github.com/test",
        scope_used="code_execution",
        result_status="success",
        result_summary="Test passed",
        private_key=kp_b["privateKey"],
        spend_amount=50,
    )
    assert receipt["receiptId"].startswith("rcpt_")
    assert receipt["result"]["status"] == "success"


def test_receipt_rejects_wrong_scope():
    kp_a = generate_key_pair()
    kp_b = generate_key_pair()
    d = create_delegation(
        delegated_by=kp_a["publicKey"],
        delegated_to=kp_b["publicKey"],
        scope=["code_execution"],
        private_key=kp_a["privateKey"],
        spend_limit=500,
    )
    with pytest.raises(ValueError, match="Scope violation"):
        create_action_receipt(
            agent_id="agent-b",
            delegation=d,
            action_type="email",
            target="test",
            scope_used="email_management",
            result_status="success",
            result_summary="Should fail",
            private_key=kp_b["privateKey"],
        )
