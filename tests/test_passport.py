"""Tests for passport creation, signing, and verification."""

from agent_passport import (
    create_passport,
    verify_passport,
    update_passport,
    sign_passport,
    is_expired,
)


RUNTIME = {
    "platform": "python-test",
    "models": ["test-model"],
    "toolsCount": 3,
    "memoryType": "session",
}


def test_creates_valid_passport():
    result = create_passport(
        agent_id="test-agent-001",
        agent_name="Test Agent",
        owner_alias="tester",
        mission="Run tests",
        capabilities=["code_execution", "web_search"],
        runtime=RUNTIME,
    )
    passport = result["signedPassport"]
    key_pair = result["keyPair"]

    assert passport["passport"]["agentId"] == "test-agent-001"
    assert passport["passport"]["publicKey"] == key_pair["publicKey"]
    assert passport["passport"]["voteWeight"] >= 1
    assert len(passport["signature"]) == 128  # 64 bytes hex

    # Verify
    check = verify_passport(passport)
    assert check["valid"]
    assert check["errors"] == []


def test_rejects_tampered():
    result = create_passport(
        agent_id="tamper-test",
        agent_name="Tamper",
        owner_alias="tester",
        mission="Test tampering",
        capabilities=["code_execution"],
        runtime=RUNTIME,
    )
    passport = result["signedPassport"]
    passport["passport"]["agentId"] = "TAMPERED"
    check = verify_passport(passport)
    assert not check["valid"]
    assert "Invalid signature" in check["errors"]


def test_vote_weight():
    result = create_passport(
        agent_id="weight-test",
        agent_name="Weight",
        owner_alias="tester",
        mission="Vote weight test",
        capabilities=["code_execution", "system_control", "git_operations"],
        runtime=RUNTIME,
    )
    assert result["signedPassport"]["passport"]["voteWeight"] == 2


def test_update_and_resign():
    result = create_passport(
        agent_id="update-test",
        agent_name="Original",
        owner_alias="tester",
        mission="Update test",
        capabilities=["code_execution"],
        runtime=RUNTIME,
    )
    kp = result["keyPair"]
    passport = result["signedPassport"]["passport"]

    updated = update_passport(passport, {"agentName": "Updated"}, kp["privateKey"])
    assert updated["passport"]["agentName"] == "Updated"
    check = verify_passport(updated)
    assert check["valid"]
