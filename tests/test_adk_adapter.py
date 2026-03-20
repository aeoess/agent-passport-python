"""Tests for APSPolicyEvaluator — ADK GovernancePlugin adapter."""

import asyncio
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_passport.crypto import generate_key_pair
from agent_passport.integrations.adk_adapter import (
    APSPolicyEvaluator,
    APSPolicyDecision,
    Decision,
)


def make_context(**overrides):
    """Build a valid APS validation context with sensible defaults."""
    ctx = {
        "agentRegistered": True,
        "agentAttestationValid": True,
        "delegationValid": True,
        "delegationRevoked": False,
        "delegationExpired": False,
        "delegationScope": ["tool:*"],
        "floorVersion": "0.1",
    }
    ctx.update(overrides)
    return ctx


def make_evaluator(**ctx_overrides):
    """Create an APSPolicyEvaluator with fresh keys."""
    keys = generate_key_pair()
    return APSPolicyEvaluator(
        agent_id="agent_test",
        agent_public_key=keys["publicKey"],
        agent_private_key=keys["privateKey"],
        delegation_id="del_test_001",
        validation_context=make_context(**ctx_overrides),
    )


# ══════════════════════════════════════
# Suite 1: Tool call evaluation
# ══════════════════════════════════════


class TestToolCallEvaluation:
    """Tests for evaluate_tool_call mapping to APS 3-sig chain."""

    def test_allow_valid_tool_call(self):
        ev = make_evaluator()
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={"query": "test"},
            agent_name="agent_test",
        ))
        assert result.decision == Decision.ALLOW
        assert result.metadata.get("aps_verdict") == "permit"
        assert result.metadata.get("aps_signature") is not None
        assert result.metadata.get("aps_intent_id") is not None

    def test_deny_unregistered_agent(self):
        ev = make_evaluator(agentRegistered=False)
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={},
            agent_name="agent_test",
        ))
        assert result.decision == Decision.DENY
        assert "Traceability" in result.reason

    def test_deny_revoked_delegation(self):
        ev = make_evaluator(delegationRevoked=True)
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={},
            agent_name="agent_test",
        ))
        assert result.decision == Decision.DENY

    def test_deny_expired_delegation(self):
        ev = make_evaluator(delegationExpired=True)
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={},
            agent_name="agent_test",
        ))
        assert result.decision == Decision.DENY

    def test_deny_invalid_attestation(self):
        ev = make_evaluator(agentAttestationValid=False)
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={},
            agent_name="agent_test",
        ))
        assert result.decision == Decision.DENY

    def test_metadata_contains_proof_chain(self):
        ev = make_evaluator()
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="read_file", tool_args={"path": "/data"},
            agent_name="agent_test",
        ))
        m = result.metadata
        assert m.get("aps_intent_id", "").startswith("intent_")
        assert m.get("aps_decision_id", "").startswith("pdec_")
        assert m.get("aps_signature") is not None
        assert m.get("aps_floor_version") == "0.1"
        assert m.get("aps_principles_evaluated") is not None
        assert len(m["aps_principles_evaluated"]) >= 5

    def test_scope_narrowing_via_tool_name(self):
        """Tool name is mapped to scope 'tool:{name}' in the intent."""
        ev = make_evaluator(delegationScope=["tool:search"])
        result = asyncio.run(ev.evaluate_tool_call(
            tool_name="search", tool_args={},
            agent_name="agent_test",
        ))
        # With specific scope, should still pass if tool matches
        assert result.decision == Decision.ALLOW


# ══════════════════════════════════════
# Suite 2: Agent delegation evaluation
# ══════════════════════════════════════


class TestDelegationEvaluation:
    """Tests for evaluate_agent_delegation with monotonic narrowing."""

    def test_allow_no_constraints(self):
        ev = make_evaluator()
        result = asyncio.run(ev.evaluate_agent_delegation(
            parent_agent_name="parent",
            child_agent_name="child",
            delegation_scope=None,
        ))
        assert result.decision == Decision.ALLOW

    def test_allow_child_within_scope(self):
        ev = make_evaluator(delegationScope=["tool:search", "tool:read_file"])
        result = asyncio.run(ev.evaluate_agent_delegation(
            parent_agent_name="parent",
            child_agent_name="child",
            delegation_scope={"allowed_tools": {"search"}},
        ))
        assert result.decision == Decision.ALLOW
        assert result.metadata.get("narrowing") == "valid"

    def test_deny_child_outside_scope(self):
        ev = make_evaluator(delegationScope=["tool:search"])
        result = asyncio.run(ev.evaluate_agent_delegation(
            parent_agent_name="parent",
            child_agent_name="child",
            delegation_scope={"allowed_tools": {"search", "delete_all"}},
        ))
        assert result.decision == Decision.DENY
        assert "delete_all" in result.reason

    def test_allow_wildcard_parent_scope(self):
        ev = make_evaluator(delegationScope=["tool:*"])
        result = asyncio.run(ev.evaluate_agent_delegation(
            parent_agent_name="parent",
            child_agent_name="child",
            delegation_scope={"allowed_tools": {"anything", "whatever"}},
        ))
        assert result.decision == Decision.ALLOW

    def test_deny_max_depth_exceeded(self):
        ev = make_evaluator(currentDelegationDepth=5)
        result = asyncio.run(ev.evaluate_agent_delegation(
            parent_agent_name="parent",
            child_agent_name="child",
            delegation_scope={"max_delegation_depth": 3},
        ))
        assert result.decision == Decision.DENY
        assert "depth" in result.reason.lower()


# ══════════════════════════════════════
# Suite 3: PolicyDecision compatibility
# ══════════════════════════════════════


class TestPolicyDecisionCompat:
    """Verify duck-type compatibility with sunilp's schema."""

    def test_allow_has_expected_fields(self):
        d = APSPolicyDecision.allow(reason="ok")
        assert d.decision == Decision.ALLOW
        assert d.reason == "ok"
        assert d.evaluator == "aps-floor-validator-v1"
        assert d.timestamp > 0

    def test_deny_has_expected_fields(self):
        d = APSPolicyDecision.deny(reason="blocked")
        assert d.decision == Decision.DENY
        assert d.reason == "blocked"

    def test_decision_is_frozen(self):
        d = APSPolicyDecision.allow()
        with pytest.raises(AttributeError):
            d.decision = Decision.DENY  # type: ignore

    def test_metadata_carries_aps_proof(self):
        d = APSPolicyDecision.allow(
            metadata={"aps_signature": "abc123", "aps_intent_id": "intent_xyz"},
        )
        assert d.metadata["aps_signature"] == "abc123"
        assert d.metadata["aps_intent_id"] == "intent_xyz"
