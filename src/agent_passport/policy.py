"""Policy Engine — Three-signature chain for Values Floor enforcement.

Layer 5b of the Agent Social Contract.
ActionIntent -> PolicyDecision -> PolicyReceipt.

v1 validator covers 90%% of real attacks:
  - Agent registered + active (attestation valid)
  - Delegation non-expired and non-revoked
  - Action within delegated scope
  - Spend within limits
  - Depth within bounds

Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize


ENFORCEMENT_ESCALATION: dict[str, int] = {
    "warn": 1,
    "audit": 2,
    "inline": 3,
}


# ══════════════════════════════════════
# ACTION INTENT — Signature 1 of 3
# ══════════════════════════════════════


def create_action_intent(
    agent_id: str,
    agent_public_key: str,
    delegation_id: str,
    action: dict,
    private_key: str,
    context: Optional[str] = None,
) -> dict:
    """Agent declares what it wants to do before doing it."""
    intent = {
        "intentId": f"intent_{uuid.uuid4().hex[:12]}",
        "agentId": agent_id,
        "agentPublicKey": agent_public_key,
        "delegationId": delegation_id,
        "action": action,
        "context": context,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    signature = sign(canonicalize(intent), private_key)
    return {**intent, "signature": signature}


def verify_action_intent(intent: dict) -> dict:
    """Verify an action intent's signature and structure."""
    errors: list[str] = []
    unsigned = {k: v for k, v in intent.items() if k != "signature"}
    if not verify(canonicalize(unsigned), intent.get("signature", ""), intent.get("agentPublicKey", "")):
        errors.append("Invalid intent signature")
    if not intent.get("agentId"):
        errors.append("Missing agentId")
    if not intent.get("delegationId"):
        errors.append("Missing delegationId")
    if not intent.get("action", {}).get("scopeRequired"):
        errors.append("Missing required scope")
    return {"valid": len(errors) == 0, "errors": errors}


# ══════════════════════════════════════
# POLICY DECISION — Signature 2 of 3
# ══════════════════════════════════════


def evaluate_intent(
    intent: dict,
    validator: "FloorValidatorV1",
    validation_context: dict,
    evaluator_id: str,
    evaluator_public_key: str,
    evaluator_private_key: str,
    decision_ttl_minutes: int = 5,
) -> dict:
    """Evaluate an intent against the floor using a validator."""
    check = verify_action_intent(intent)
    if not check["valid"]:
        raise ValueError(f"Invalid intent: {', '.join(check['errors'])}")

    unsigned_intent = {k: v for k, v in intent.items() if k != "signature"}
    result = validator.evaluate(unsigned_intent, validation_context)

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=decision_ttl_minutes)

    decision = {
        "decisionId": f"pdec_{uuid.uuid4().hex[:12]}",
        "intentId": intent["intentId"],
        "evaluatorId": evaluator_id,
        "evaluatorPublicKey": evaluator_public_key,
        "verdict": result["verdict"],
        "principlesEvaluated": result["principlesEvaluated"],
        "constraints": result.get("constraints"),
        "reason": result["reason"],
        "floorVersion": validation_context.get("floorVersion", ""),
        "evaluatedAt": now.isoformat(),
        "expiresAt": expires.isoformat(),
    }

    signature = sign(canonicalize(decision), evaluator_private_key)
    return {**decision, "signature": signature}


def verify_policy_decision(decision: dict) -> dict:
    """Verify a policy decision's signature and expiry."""
    errors: list[str] = []
    unsigned = {k: v for k, v in decision.items() if k != "signature"}
    if not verify(canonicalize(unsigned), decision.get("signature", ""), decision.get("evaluatorPublicKey", "")):
        errors.append("Invalid decision signature")
    exp = decision.get("expiresAt", "")
    if exp:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00")) if "Z" in exp else datetime.fromisoformat(exp)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt < datetime.now(timezone.utc):
            errors.append("Policy decision expired")
    if not decision.get("intentId"):
        errors.append("Missing intentId")
    return {"valid": len(errors) == 0, "errors": errors}


# ══════════════════════════════════════
# POLICY RECEIPT — Links all 3 signatures
# ══════════════════════════════════════


def create_policy_receipt(
    intent: dict,
    decision: dict,
    receipt: dict,
    verifier_private_key: str,
) -> dict:
    """Create a policy receipt linking intent, decision, and action receipt."""
    if decision.get("intentId") != intent.get("intentId"):
        raise ValueError("Decision does not reference this intent")
    if decision.get("verdict") == "deny":
        raise ValueError("Cannot create receipt for denied intent")

    pr = {
        "policyReceiptId": f"prec_{uuid.uuid4().hex[:12]}",
        "intentId": intent["intentId"],
        "decisionId": decision["decisionId"],
        "receiptId": receipt["receiptId"],
        "chain": {
            "intentSignature": intent["signature"],
            "decisionSignature": decision["signature"],
            "receiptSignature": receipt["signature"],
        },
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
    }
    signature = sign(canonicalize(pr), verifier_private_key)
    return {**pr, "signature": signature}


def verify_policy_receipt(policy_receipt: dict, verifier_public_key: str) -> dict:
    """Verify a policy receipt's signature and chain integrity."""
    errors: list[str] = []
    unsigned = {k: v for k, v in policy_receipt.items() if k != "signature"}
    if not verify(canonicalize(unsigned), policy_receipt.get("signature", ""), verifier_public_key):
        errors.append("Invalid policy receipt signature")
    chain = policy_receipt.get("chain", {})
    if not chain.get("intentSignature"):
        errors.append("Missing intent signature in chain")
    if not chain.get("decisionSignature"):
        errors.append("Missing decision signature in chain")
    if not chain.get("receiptSignature"):
        errors.append("Missing receipt signature in chain")
    return {"valid": len(errors) == 0, "errors": errors}


# ══════════════════════════════════════
# V1 VALIDATOR — The Simple Engine
# ══════════════════════════════════════


def _scope_authorizes(delegation_scope: list[str], required: str) -> bool:
    """Check if a delegation's scope list authorizes a required scope."""
    for s in delegation_scope:
        if s == required or required.startswith(s + ":"):
            return True
    return False


def _get_enforcement_mode(principle_id: str, ctx: dict) -> str:
    """Look up enforcement mode for a principle from context."""
    for fp in ctx.get("floorPrinciples", []):
        if fp.get("id") == principle_id:
            enf = fp.get("enforcement", {})
            if enf.get("mode"):
                return enf["mode"]
            if enf.get("technical") is True:
                return "inline"
            if enf.get("technical") is False:
                return "audit"
    num = int(principle_id.replace("F-", ""))
    return "inline" if num <= 5 else "audit"


class FloorValidatorV1:
    """V1 policy validator covering 90%% of real attacks."""

    version = "1.0"
    name = "floor-validator-v1"

    def evaluate(self, intent: dict, ctx: dict) -> dict:
        evals: list[dict] = []
        audit_findings: list[dict] = []
        warnings: list[dict] = []
        dominated = "permit"
        constraints: list[str] = []
        reasons: list[str] = []

        def handle(ev: dict) -> None:
            mode = _get_enforcement_mode(ev["principleId"], ctx)
            ev["enforcementMode"] = mode
            evals.append(ev)
            if ev["status"] == "fail":
                if mode == "inline":
                    reasons.append(f"{ev['principleName']}: {ev['detail']}")
                elif mode == "audit":
                    audit_findings.append(ev)
                elif mode == "warn":
                    warnings.append(ev)

        handle(self._check_traceability(ctx))
        handle(self._check_identity(ctx))
        handle(self._check_scope(intent, ctx))
        handle(self._check_revocability(ctx))
        handle(self._check_auditability(ctx))

        # F-006, F-007: not technically checkable in v1
        f006_mode = _get_enforcement_mode("F-006", ctx)
        evals.append({"principleId": "F-006", "principleName": "Non-Deception",
                       "status": "not_applicable", "detail": "Requires reasoning-level evaluation (v2+)",
                       "enforcementMode": f006_mode})
        f007_mode = _get_enforcement_mode("F-007", ctx)
        evals.append({"principleId": "F-007", "principleName": "Proportionality",
                       "status": "not_applicable", "detail": "Requires reputation context (v2+)",
                       "enforcementMode": f007_mode})

        # Spend check
        spend = self._check_spend(intent, ctx)
        if spend:
            if spend["verdict"] == "narrow":
                dominated = "narrow"
                constraints.append(spend["constraint"])
                reasons.append(spend["reason"])
            elif spend["verdict"] == "deny":
                dominated = "deny"
                reasons.append(spend["reason"])

        inline_failures = [e for e in evals if e["status"] == "fail" and e.get("enforcementMode") == "inline"]
        if inline_failures:
            dominated = "deny"

        reason = (
            "; ".join(reasons) if reasons
            else f"Permitted with {len(audit_findings)} audit finding(s)" if audit_findings
            else f"Permitted with {len(warnings)} warning(s)" if warnings
            else "All checks passed"
        )

        return {
            "verdict": dominated,
            "principlesEvaluated": evals,
            "constraints": constraints if constraints else None,
            "reason": reason,
            "auditFindings": audit_findings if audit_findings else None,
            "warnings": warnings if warnings else None,
            "enforcement": {
                "inlinePassed": len(inline_failures) == 0,
                "auditIssueCount": len(audit_findings),
                "warningCount": len(warnings),
            },
        }

    def _check_traceability(self, ctx: dict) -> dict:
        if not ctx.get("agentRegistered"):
            return {"principleId": "F-001", "principleName": "Traceability",
                    "status": "fail", "detail": "Agent not registered in protocol"}
        return {"principleId": "F-001", "principleName": "Traceability",
                "status": "pass", "detail": "Agent registered and traceable"}

    def _check_identity(self, ctx: dict) -> dict:
        if not ctx.get("agentAttestationValid"):
            return {"principleId": "F-002", "principleName": "Honest Identity",
                    "status": "fail", "detail": "Agent attestation invalid or expired"}
        return {"principleId": "F-002", "principleName": "Honest Identity",
                "status": "pass", "detail": "Attestation verified"}

    def _check_scope(self, intent: dict, ctx: dict) -> dict:
        delegation = ctx.get("delegation", {})
        scope_req = intent.get("action", {}).get("scopeRequired", "")
        if not _scope_authorizes(delegation.get("scope", []), scope_req):
            return {"principleId": "F-003", "principleName": "Scoped Authority",
                    "status": "fail",
                    "detail": f"Scope '{scope_req}' not in delegation {delegation.get('scope', [])}"}
        return {"principleId": "F-003", "principleName": "Scoped Authority",
                "status": "pass", "detail": f"Scope '{scope_req}' authorized"}

    def _check_revocability(self, ctx: dict) -> dict:
        if ctx.get("delegation", {}).get("revoked"):
            return {"principleId": "F-004", "principleName": "Revocability",
                    "status": "fail", "detail": "Delegation has been revoked"}
        return {"principleId": "F-004", "principleName": "Revocability",
                "status": "pass", "detail": "Delegation active"}

    def _check_auditability(self, ctx: dict) -> dict:
        delegation = ctx.get("delegation", {})
        issues: list[str] = []
        exp = delegation.get("expiresAt", "")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00")) if "Z" in exp else datetime.fromisoformat(exp)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    issues.append("Delegation expired")
            except (ValueError, TypeError):
                pass
        if delegation.get("currentDepth", 0) > delegation.get("maxDepth", 1):
            issues.append("Depth limit exceeded")
        if issues:
            return {"principleId": "F-005", "principleName": "Auditability",
                    "status": "fail", "detail": ", ".join(issues)}
        return {"principleId": "F-005", "principleName": "Auditability",
                "status": "pass", "detail": "Delegation valid and within depth limits"}

    def _check_spend(self, intent: dict, ctx: dict) -> Optional[dict]:
        spend = intent.get("action", {}).get("spend")
        if not spend:
            return None
        delegation = ctx.get("delegation", {})
        limit = delegation.get("spendLimit")
        if limit is None:
            return None
        remaining = limit - delegation.get("spentAmount", 0)
        if spend["amount"] > remaining:
            if remaining > 0:
                return {"verdict": "narrow", "reason": f"Spend {spend['amount']} exceeds remaining {remaining}",
                        "constraint": f"max_spend:{remaining}"}
            return {"verdict": "deny", "reason": f"No spend budget remaining (limit: {limit}, spent: {delegation.get('spentAmount', 0)})"}
        return None


# ══════════════════════════════════════
# CONVENIENCE — Full chain in one call
# ══════════════════════════════════════


def request_action(
    agent_id: str,
    agent_public_key: str,
    agent_private_key: str,
    delegation_id: str,
    action: dict,
    validator: FloorValidatorV1,
    validation_context: dict,
    evaluator_id: str,
    evaluator_public_key: str,
    evaluator_private_key: str,
    context: Optional[str] = None,
) -> dict:
    """Execute the full three-signature chain in one call.

    Returns:
        dict with 'intent' and 'decision'.
    """
    intent = create_action_intent(
        agent_id=agent_id,
        agent_public_key=agent_public_key,
        delegation_id=delegation_id,
        action=action,
        private_key=agent_private_key,
        context=context,
    )
    decision = evaluate_intent(
        intent=intent,
        validator=validator,
        validation_context=validation_context,
        evaluator_id=evaluator_id,
        evaluator_public_key=evaluator_public_key,
        evaluator_private_key=evaluator_private_key,
    )
    return {"intent": intent, "decision": decision}
