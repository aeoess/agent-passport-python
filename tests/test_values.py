"""Tests for the Values Floor module (Layer 2)."""

from __future__ import annotations

import os
import pytest

from agent_passport import (
    generate_key_pair,
    create_passport,
    create_delegation,
    create_action_receipt,
    load_floor,
    load_floor_from_file,
    resolve_enforcement_mode,
    effective_enforcement_mode,
    attest_floor,
    verify_attestation,
    evaluate_compliance,
    negotiate_common_ground,
)


FLOOR_YAML_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "..", "agent-passport-system", "values", "floor.yaml"
)

FLOOR_JSON = """{
  "version": "0.1",
  "schema": "agent-social-contract/values-floor",
  "lastUpdated": "2026-02-20",
  "governanceUri": "https://aeoess.com/protocol.html",
  "floor": [
    {"id": "F-001", "name": "Traceability", "enforcement": {"technical": true, "mechanism": "delegation-chain", "mode": "inline"}, "weight": "mandatory"},
    {"id": "F-002", "name": "Honest Identity", "enforcement": {"technical": true, "mechanism": "passport-verification", "mode": "inline"}, "weight": "mandatory"},
    {"id": "F-003", "name": "Scoped Authority", "enforcement": {"technical": true, "mechanism": "scope-check", "mode": "inline"}, "weight": "mandatory"},
    {"id": "F-004", "name": "Revocability", "enforcement": {"technical": true, "mechanism": "revocation-check", "mode": "inline"}, "weight": "mandatory"},
    {"id": "F-005", "name": "Auditability", "enforcement": {"technical": true, "mechanism": "signed-receipts", "mode": "inline"}, "weight": "mandatory"},
    {"id": "F-006", "name": "Non-Deception", "enforcement": {"technical": false, "mechanism": "reputation", "mode": "audit"}, "weight": "strong_consideration"},
    {"id": "F-007", "name": "Proportionality", "enforcement": {"technical": false, "mechanism": "reputation", "mode": "audit"}, "weight": "strong_consideration"}
  ]
}"""


# ── Floor Loading ──


class TestFloorLoading:
    def test_loads_from_json(self):
        floor = load_floor(FLOOR_JSON)
        assert floor["version"] == "0.1"
        assert len(floor["floor"]) == 7

    def test_loads_from_yaml_file(self):
        if not os.path.exists(FLOOR_YAML_PATH):
            pytest.skip("floor.yaml not found")
        floor = load_floor_from_file(FLOOR_YAML_PATH)
        assert floor["version"] == "0.1"
        assert len(floor["floor"]) == 7

    def test_enforcement_modes_resolved(self):
        floor = load_floor(FLOOR_JSON)
        for p in floor["floor"]:
            assert "mode" in p["enforcement"]
            assert p["enforcement"]["mode"] in ("inline", "audit", "warn")


# ── Enforcement Mode ──


class TestEnforcementMode:
    def test_returns_explicit_mode(self):
        assert resolve_enforcement_mode({"mode": "warn"}) == "warn"

    def test_falls_back_to_technical(self):
        assert resolve_enforcement_mode({"technical": True}) == "inline"
        assert resolve_enforcement_mode({"technical": False}) == "audit"

    def test_defaults_to_audit(self):
        assert resolve_enforcement_mode({}) == "audit"

    def test_effective_escalation(self):
        assert effective_enforcement_mode("audit", "inline") == "inline"
        assert effective_enforcement_mode("warn", "audit") == "audit"
        assert effective_enforcement_mode("inline", "audit") == "inline"

    def test_effective_no_extensions(self):
        assert effective_enforcement_mode("warn") == "warn"


# ── Floor Attestation ──


class TestAttestation:
    def test_creates_and_verifies(self):
        kp = generate_key_pair()
        att = attest_floor("agent-1", kp["publicKey"], "0.1", [], kp["privateKey"])
        result = verify_attestation(att)
        assert result["valid"]
        assert att["floorVersion"] == "0.1"

    def test_includes_extensions(self):
        kp = generate_key_pair()
        att = attest_floor("agent-1", kp["publicKey"], "0.1", ["healthcare"], kp["privateKey"])
        assert "healthcare" in att["extensions"]

    def test_rejects_tampered(self):
        kp = generate_key_pair()
        att = attest_floor("agent-1", kp["publicKey"], "0.1", [], kp["privateKey"])
        att["floorVersion"] = "0.2"
        result = verify_attestation(att)
        assert not result["valid"]

    def test_detects_expired(self):
        kp = generate_key_pair()
        att = attest_floor("agent-1", kp["publicKey"], "0.1", [], kp["privateKey"], expires_in_days=-1)
        result = verify_attestation(att)
        assert not result["valid"]
        assert any("expired" in e.lower() for e in result["errors"])


# ── Compliance ──


class TestCompliance:
    def _setup(self):
        human_kp = generate_key_pair()
        p = create_passport(
            agent_id="agent-1", agent_name="Test", owner_alias="owner",
            mission="test", capabilities=["code_execution"],
            runtime={"platform": "python", "models": [], "toolsCount": 1, "memoryType": "none"},
        )
        agent_kp = p["keyPair"]
        d = create_delegation(
            delegated_by=human_kp["publicKey"],
            delegated_to=agent_kp["publicKey"],
            scope=["code_execution"], spend_limit=100, private_key=human_kp["privateKey"],
        )
        r = create_action_receipt(
            agent_id="agent-1", delegation=d,
            action_type="code_execution", scope_used="code_execution",
            target="test", result_status="success", result_summary="done",
            spend_amount=10, delegation_chain=[human_kp["publicKey"], agent_kp["publicKey"]],
            private_key=agent_kp["privateKey"],
        )
        delegations = {d["delegationId"]: {"scope": ["code_execution"], "revoked": False}}
        return human_kp, p, d, r, delegations

    def test_fully_compliant(self):
        kp, p, d, r, delegations = self._setup()
        floor = load_floor(FLOOR_JSON)
        verifier = generate_key_pair()
        report = evaluate_compliance("agent-1", [r], floor, delegations, verifier["privateKey"])
        assert report["overallCompliance"] > 0.9
        enforced = [c for c in report["checks"] if c["status"] == "enforced"]
        assert len(enforced) == 5

    def test_detects_revoked_delegation(self):
        kp, p, d, r, delegations = self._setup()
        did = list(delegations.keys())[0]
        delegations[did]["revoked"] = True
        floor = load_floor(FLOOR_JSON)
        verifier = generate_key_pair()
        report = evaluate_compliance("agent-1", [r], floor, delegations, verifier["privateKey"])
        violations = [c for c in report["checks"] if c["status"] == "violation"]
        assert len(violations) >= 1


# ── Common Ground Negotiation ──


class TestCommonGround:
    def test_compatible_agents(self):
        kp_a = generate_key_pair()
        kp_b = generate_key_pair()
        pa = create_passport(agent_id="a", agent_name="A", owner_alias="o", mission="m",
                             capabilities=["code_execution"],
                             runtime={"platform": "py", "models": [], "toolsCount": 1, "memoryType": "none"})
        pb = create_passport(agent_id="b", agent_name="B", owner_alias="o", mission="m",
                             capabilities=["web_search"],
                             runtime={"platform": "py", "models": [], "toolsCount": 1, "memoryType": "none"})
        att_a = attest_floor("a", pa["keyPair"]["publicKey"], "0.1", [], pa["keyPair"]["privateKey"])
        att_b = attest_floor("b", pb["keyPair"]["publicKey"], "0.1", [], pb["keyPair"]["privateKey"])
        result = negotiate_common_ground(pa["signedPassport"], att_a, pb["signedPassport"], att_b)
        assert result["compatible"]

    def test_incompatible_versions(self):
        kp_a = generate_key_pair()
        kp_b = generate_key_pair()
        pa = create_passport(agent_id="a", agent_name="A", owner_alias="o", mission="m",
                             capabilities=["code_execution"],
                             runtime={"platform": "py", "models": [], "toolsCount": 1, "memoryType": "none"})
        pb = create_passport(agent_id="b", agent_name="B", owner_alias="o", mission="m",
                             capabilities=["web_search"],
                             runtime={"platform": "py", "models": [], "toolsCount": 1, "memoryType": "none"})
        att_a = attest_floor("a", pa["keyPair"]["publicKey"], "0.1", [], pa["keyPair"]["privateKey"])
        att_b = attest_floor("b", pb["keyPair"]["publicKey"], "1.0", [], pb["keyPair"]["privateKey"])
        result = negotiate_common_ground(pa["signedPassport"], att_a, pb["signedPassport"], att_b)
        assert not result["compatible"]
        assert any("Incompatible" in r for r in result["incompatibilityReasons"])
