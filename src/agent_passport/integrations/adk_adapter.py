"""APSPolicyEvaluator — Agent Passport System adapter for Google ADK GovernancePlugin.

Maps ADK's PolicyEvaluator protocol to APS's 3-signature policy chain:
  evaluate_tool_call()       → create_action_intent() → evaluate_intent()
  evaluate_agent_delegation() → delegation scope narrowing check

Usage with sunilp's GovernancePlugin (google/adk-python-community#102):

    from agent_passport.integrations.adk_adapter import APSPolicyEvaluator
    from google.adk_community.governance import GovernancePlugin

    evaluator = APSPolicyEvaluator(
        agent_id="agent_alice",
        agent_public_key=alice_keys.public_key,
        agent_private_key=alice_keys.private_key,
        delegation_id="del_abc123",
        validation_context={
            "agentRegistered": True,
            "agentAttestationValid": True,
            "delegationValid": True,
            "delegationRevoked": False,
            "delegationExpired": False,
            "delegationScope": ["tool:*"],
            "floorVersion": "0.1",
        },
    )
    plugin = GovernancePlugin(policy_evaluator=evaluator)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from ..policy import (
    create_action_intent,
    evaluate_intent,
    FloorValidatorV1,
)
from ..delegation import create_delegation, sub_delegate


# ══════════════════════════════════════
# Compatible PolicyDecision (duck-typed)
# ══════════════════════════════════════
# Structurally compatible with sunilp's PolicyDecision from
# google.adk_community.governance.governance_plugin without importing it.


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"



@dataclass(frozen=True)
class APSPolicyDecision:
    """APS-flavored PolicyDecision, duck-type compatible with sunilp's schema.

    ADK GovernancePlugin checks for .decision and .reason attributes.
    We add APS-specific fields in .metadata for cryptographic proof chain.
    """
    decision: Decision
    reason: str = ""
    evaluator: str = "aps-floor-validator-v1"
    timestamp: float = field(default_factory=time.time)
    # APS extensions — the cryptographic proof chain
    metadata: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(reason: str = "", metadata: Optional[Dict[str, Any]] = None) -> APSPolicyDecision:
        return APSPolicyDecision(
            decision=Decision.ALLOW, reason=reason,
            metadata=metadata or {},
        )

    @staticmethod
    def deny(reason: str = "", metadata: Optional[Dict[str, Any]] = None) -> APSPolicyDecision:
        return APSPolicyDecision(
            decision=Decision.DENY, reason=reason,
            metadata=metadata or {},
        )


# ══════════════════════════════════════
# APS POLICY EVALUATOR
# ══════════════════════════════════════


# Verdict mapping: APS → ADK
_VERDICT_MAP = {
    "permit": Decision.ALLOW,
    "narrow": Decision.ALLOW,   # narrow = allowed with constraints
    "deny": Decision.DENY,
}


class APSPolicyEvaluator:
    """PolicyEvaluator implementation backed by APS 3-signature policy chain.

    Implements sunilp's PolicyEvaluator protocol (evaluate_tool_call,
    evaluate_agent_delegation) using APS's FloorValidatorV1.

    Every evaluation produces a signed PolicyDecision with the full
    cryptographic proof chain in metadata. The ADK GovernancePlugin
    sees a standard ALLOW/DENY. Anyone who inspects metadata gets
    the APS signature, principle evaluations, and delegation context.
    """

    def __init__(
        self,
        agent_id: str,
        agent_public_key: str,
        agent_private_key: str,
        delegation_id: str,
        validation_context: Dict[str, Any],
        evaluator_id: Optional[str] = None,
        evaluator_public_key: Optional[str] = None,
        evaluator_private_key: Optional[str] = None,
        validator: Optional[FloorValidatorV1] = None,
    ):
        self.agent_id = agent_id
        self.agent_public_key = agent_public_key
        self.agent_private_key = agent_private_key
        self.delegation_id = delegation_id
        self.validation_context = validation_context
        # Evaluator defaults to agent (self-evaluation) if not provided
        self.evaluator_id = evaluator_id or agent_id
        self.evaluator_public_key = evaluator_public_key or agent_public_key
        self.evaluator_private_key = evaluator_private_key or agent_private_key
        self.validator = validator or FloorValidatorV1()

    def _build_internal_context(self, scope_required: str) -> Dict[str, Any]:
        """Translate user-friendly context to FloorValidatorV1 format.

        FloorValidatorV1 reads scope from ctx["delegation"]["scope"].
        The adapter accepts a flat delegationScope list for convenience.
        Wildcards (tool:*) are expanded to include the specific scope.
        """
        ctx = dict(self.validation_context)
        raw_scope = ctx.pop("delegationScope", [])

        # Expand wildcards: "tool:*" means all tools are allowed
        resolved_scope = list(raw_scope)
        if "tool:*" in resolved_scope and scope_required not in resolved_scope:
            resolved_scope.append(scope_required)

        # Build delegation object in the format FloorValidatorV1 expects
        delegation = ctx.get("delegation", {})
        if not isinstance(delegation, dict):
            delegation = {}
        delegation["scope"] = resolved_scope
        delegation["delegationId"] = self.delegation_id

        # Map flat fields to delegation sub-fields
        if ctx.get("delegationRevoked"):
            delegation["revoked"] = True
        if ctx.get("delegationExpired"):
            delegation["expiresAt"] = "2020-01-01T00:00:00Z"
        delegation["currentDepth"] = ctx.get("currentDelegationDepth", 0)
        delegation["maxDepth"] = ctx.get("maxDelegationDepth", 10)

        ctx["delegation"] = delegation
        return ctx

    async def evaluate_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_name: str,
        context: Optional[Any] = None,
    ) -> APSPolicyDecision:
        """Evaluate a tool call through APS 3-signature policy chain.

        1. Creates an ActionIntent (signature 1)
        2. Evaluates via FloorValidatorV1 (signature 2)
        3. Returns decision with proof chain in metadata
        """
        scope_required = f"tool:{tool_name}"

        # Build internal context: translate user-friendly format to what
        # FloorValidatorV1 expects (delegation.scope, not delegationScope)
        internal_ctx = self._build_internal_context(scope_required)

        # Step 1: Create APS ActionIntent
        action = {
            "toolName": tool_name,
            "toolArgs": tool_args,
            "scopeRequired": scope_required,
            "agentName": agent_name,
        }
        try:
            intent = create_action_intent(
                agent_id=self.agent_id,
                agent_public_key=self.agent_public_key,
                delegation_id=self.delegation_id,
                action=action,
                private_key=self.agent_private_key,
            )
        except Exception as e:
            return APSPolicyDecision.deny(
                reason=f"Failed to create intent: {e}",
                metadata={"error": str(e), "stage": "intent_creation"},
            )

        # Step 2: Evaluate intent through FloorValidatorV1
        try:
            decision = evaluate_intent(
                intent=intent,
                validator=self.validator,
                validation_context=internal_ctx,
                evaluator_id=self.evaluator_id,
                evaluator_public_key=self.evaluator_public_key,
                evaluator_private_key=self.evaluator_private_key,
            )
        except Exception as e:
            return APSPolicyDecision.deny(
                reason=f"Policy evaluation failed: {e}",
                metadata={"error": str(e), "stage": "evaluation"},
            )

        # Step 3: Map APS verdict to ADK decision
        verdict = decision.get("verdict", "deny")
        adk_decision = _VERDICT_MAP.get(verdict, Decision.DENY)

        # Build proof metadata
        metadata = {
            "aps_intent_id": intent.get("intentId"),
            "aps_decision_id": decision.get("decisionId"),
            "aps_verdict": verdict,
            "aps_signature": decision.get("signature"),
            "aps_evaluator_id": decision.get("evaluatorId"),
            "aps_principles_evaluated": decision.get("principlesEvaluated"),
            "aps_constraints": decision.get("constraints"),
            "aps_floor_version": decision.get("floorVersion"),
            "aps_expires_at": decision.get("expiresAt"),
            "aps_audit_findings": decision.get("auditFindings"),
            "aps_warnings": decision.get("warnings"),
        }

        return APSPolicyDecision(
            decision=adk_decision,
            reason=decision.get("reason", ""),
            evaluator="aps-floor-validator-v1",
            metadata=metadata,
        )

    async def evaluate_agent_delegation(
        self,
        *,
        parent_agent_name: str,
        child_agent_name: str,
        delegation_scope: Optional[Any] = None,
        context: Optional[Any] = None,
    ) -> APSPolicyDecision:
        """Evaluate whether agent delegation is permitted.

        Checks monotonic narrowing: child's requested tools must be
        a subset of parent's delegation scope.
        """
        parent_scope = self.validation_context.get("delegationScope", [])

        # If no delegation scope provided by ADK, allow (no constraints)
        if delegation_scope is None:
            return APSPolicyDecision.allow(
                reason="No delegation constraints specified",
                metadata={"parent_scope": parent_scope},
            )

        # Extract child's requested tools from ADK DelegationScope
        child_tools = set()
        if hasattr(delegation_scope, "allowed_tools"):
            child_tools = delegation_scope.allowed_tools
        elif isinstance(delegation_scope, dict):
            child_tools = set(delegation_scope.get("allowed_tools", []))

        # Monotonic narrowing: child tools must be subset of parent scope
        # Parent scope "tool:*" means all tools allowed
        has_wildcard = "tool:*" in parent_scope
        if not has_wildcard and child_tools:
            parent_tool_set = {
                s.replace("tool:", "") for s in parent_scope
                if s.startswith("tool:")
            }
            violations = child_tools - parent_tool_set
            if violations:
                return APSPolicyDecision.deny(
                    reason=f"Delegation scope violation: {violations} not in parent scope",
                    metadata={
                        "parent_scope": parent_scope,
                        "child_requested": list(child_tools),
                        "violations": list(violations),
                    },
                )

        # Check max delegation depth
        max_depth = 0
        if hasattr(delegation_scope, "max_delegation_depth"):
            max_depth = delegation_scope.max_delegation_depth
        elif isinstance(delegation_scope, dict):
            max_depth = delegation_scope.get("max_delegation_depth", 0)

        ctx_depth = self.validation_context.get("currentDelegationDepth", 0)
        if max_depth > 0 and ctx_depth >= max_depth:
            return APSPolicyDecision.deny(
                reason=f"Max delegation depth exceeded ({ctx_depth}/{max_depth})",
                metadata={"current_depth": ctx_depth, "max_depth": max_depth},
            )

        return APSPolicyDecision.allow(
            reason="Delegation within scope",
            metadata={
                "parent_scope": parent_scope,
                "child_tools": list(child_tools) if child_tools else [],
                "narrowing": "valid",
            },
        )
