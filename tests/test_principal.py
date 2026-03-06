"""Tests for Principal Identity."""

from agent_passport import (
    generate_key_pair,
    create_principal_identity,
    endorse_agent_as_principal,
    verify_endorsement,
    revoke_endorsement,
    create_disclosure,
    verify_disclosure,
    create_fleet,
    add_to_fleet,
    get_fleet_status,
    revoke_from_fleet,
)


def test_create_principal():
    result = create_principal_identity(
        display_name="Tima", domain="aeoess.com",
        jurisdiction="US", contact_channel="telegram:@aeoess",
    )
    p = result["principal"]
    kp = result["keyPair"]
    assert p["principalId"].startswith("principal-")
    assert p["displayName"] == "Tima"
    assert p["domain"] == "aeoess.com"
    assert p["disclosureLevel"] == "public"
    assert kp["publicKey"]
    assert kp["privateKey"]


def test_endorse_and_verify():
    result = create_principal_identity(display_name="Owner")
    p, kp = result["principal"], result["keyPair"]

    endorsement = endorse_agent_as_principal(
        principal=p, principal_private_key=kp["privateKey"],
        agent_id="agent-001", agent_public_key="a" * 64,
        scope=["web_search", "code_execution"], relationship="creator",
    )
    assert endorsement["endorsementId"].startswith("endorsement-")
    assert endorsement["relationship"] == "creator"
    assert not endorsement["revoked"]

    v = verify_endorsement(endorsement)
    assert v["valid"]
    assert len(v["errors"]) == 0


def test_tampered_endorsement():
    result = create_principal_identity(display_name="Owner")
    p, kp = result["principal"], result["keyPair"]

    endorsement = endorse_agent_as_principal(
        principal=p, principal_private_key=kp["privateKey"],
        agent_id="agent-001", agent_public_key="b" * 64,
        scope=["web_search"], relationship="operator",
    )
    endorsement["scope"] = ["admin"]
    v = verify_endorsement(endorsement)
    assert not v["valid"]
    assert "Invalid signature" in v["errors"]


def test_revoke_endorsement():
    result = create_principal_identity(display_name="Owner")
    p, kp = result["principal"], result["keyPair"]
    endorsement = endorse_agent_as_principal(
        principal=p, principal_private_key=kp["privateKey"],
        agent_id="agent-001", agent_public_key="c" * 64,
        scope=["web_search"], relationship="creator",
    )
    revoked = revoke_endorsement(endorsement, "Compromised")
    assert revoked["revoked"]
    assert revoked["revokedReason"] == "Compromised"
    v = verify_endorsement(revoked)
    assert not v["valid"]
    assert v["revoked"]


def test_disclosure_public():
    result = create_principal_identity(
        display_name="Tima", domain="aeoess.com",
        jurisdiction="US", contact_channel="telegram:@aeoess",
    )
    p, kp = result["principal"], result["keyPair"]
    d = create_disclosure(p, kp["privateKey"], "public")
    assert d["level"] == "public"
    assert d["revealedFields"]["displayName"] == "Tima"
    assert d["revealedFields"]["domain"] == "aeoess.com"
    v = verify_disclosure(d)
    assert v["valid"]


def test_disclosure_minimal():
    result = create_principal_identity(display_name="Tima")
    p, kp = result["principal"], result["keyPair"]
    d = create_disclosure(p, kp["privateKey"], "minimal")
    assert d["level"] == "minimal"
    assert "idHash" in d["revealedFields"]
    assert "did" in d["revealedFields"]
    assert "displayName" not in d["revealedFields"]
    v = verify_disclosure(d)
    assert v["valid"]


def test_disclosure_tampered():
    result = create_principal_identity(display_name="Tima")
    p, kp = result["principal"], result["keyPair"]
    d = create_disclosure(p, kp["privateKey"], "public")
    d["revealedFields"]["displayName"] = "HACKED"
    v = verify_disclosure(d)
    assert not v["valid"]


def test_fleet_management():
    result = create_principal_identity(display_name="Owner")
    p, kp = result["principal"], result["keyPair"]
    fleet = create_fleet(p)
    assert len(fleet["agents"]) == 0

    e1 = endorse_agent_as_principal(
        principal=p, principal_private_key=kp["privateKey"],
        agent_id="bot-1", agent_public_key="a" * 64,
        scope=["web_search"], relationship="creator",
    )
    e2 = endorse_agent_as_principal(
        principal=p, principal_private_key=kp["privateKey"],
        agent_id="bot-2", agent_public_key="b" * 64,
        scope=["code_execution"], relationship="operator",
    )
    fleet = add_to_fleet(fleet, e1)
    fleet = add_to_fleet(fleet, e2)
    status = get_fleet_status(fleet)
    assert status["totalAgents"] == 2
    assert status["activeAgents"] == 2

    fleet = revoke_from_fleet(fleet, "bot-1")
    status = get_fleet_status(fleet)
    assert status["activeAgents"] == 1
    assert status["revokedAgents"] == 1
