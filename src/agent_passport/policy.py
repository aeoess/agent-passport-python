# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
from typing import Any, Optional, TypedDict

from .crypto import sign, verify
from ._time import now_ms, parse_rfc3339
from .canonical import canonicalize, canonicalize_for_write


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
    signature = sign(canonicalize_for_write(intent), private_key)
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

    signature = sign(canonicalize_for_write(decision), evaluator_private_key)
    return {**decision, "signature": signature}


def verify_policy_decision(decision: dict) -> dict:
    """Verify a policy decision's signature and expiry."""
    errors: list[str] = []
    unsigned = {k: v for k, v in decision.items() if k != "signature"}
    if not verify(canonicalize(unsigned), decision.get("signature", ""), decision.get("evaluatorPublicKey", "")):
        errors.append("Invalid decision signature")
    exp = decision.get("expiresAt", "")
    if exp:
        parsed = parse_rfc3339(exp)
        if parsed.ms is None:
            # A verifier states a result; it does not raise at a caller that
            # handed it an artifact. This parse had no guard at all, so a
            # malformed expiresAt left through a function whose contract is a
            # result dict.
            errors.append(f"Unreadable expiresAt ({parsed.reason})")
        elif parsed.ms < now_ms():
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
    signature = sign(canonicalize_for_write(pr), verifier_private_key)
    return {**pr, "signature": signature}


class PolicyReceiptChainInputs(TypedDict):
    """What a relying party must supply to have the chain checked.

    A policy receipt carries three signature STRINGS and not the objects they
    were made over, so the preimages cannot be reconstructed from it. They
    come from the relying party, which is also where the three trust anchors
    belong: an anchor read out of the artifact being checked is the artifact's
    claim about itself.
    """

    intent: dict[str, Any]
    decision: dict[str, Any]
    receipt: dict[str, Any]
    #: Agent whose intent signature this relying party accepts.
    intentSignerPublicKey: str
    #: Evaluator whose decision signature this relying party accepts.
    decisionSignerPublicKey: str
    #: Executor whose action-receipt signature this relying party accepts.
    receiptSignerPublicKey: str


def verify_policy_receipt_envelope(
    policy_receipt: dict[str, Any], verifier_public_key: str
) -> dict[str, Any]:
    """Verify only that the receipt envelope was signed by the given key.

    Establishes: the bytes of this policy receipt were signed by
    ``verifier_public_key`` and have not been altered since.

    Does NOT establish anything about the intent, decision or action receipt
    the envelope names. Their signatures are copied into ``chain`` as strings
    and are not checked here, because the objects they were made over are not
    in the receipt. Use :func:`verify_policy_receipt` with chain inputs for
    that.

    The name is the point. A caller reaching for this one is saying it does
    not need the chain checked; a caller that does need it cannot get this
    answer by accident.
    """
    errors: list[str] = []
    unsigned = {k: v for k, v in policy_receipt.items() if k != "signature"}
    envelope_signature_valid = verify(
        canonicalize(unsigned), policy_receipt.get("signature", ""), verifier_public_key
    )
    if not envelope_signature_valid:
        errors.append("Invalid policy receipt signature")
    return {
        "valid": envelope_signature_valid,
        "envelope_signature_valid": envelope_signature_valid,
        "errors": errors,
    }


def _policy_chain_mismatches(
    policy_receipt: dict[str, Any], chain: PolicyReceiptChainInputs
) -> list[str]:
    """Verify the three inner signatures against the caller's anchors and
    check that every id in the receipt links the objects it names.

    One entry per failure; empty means the chain holds.
    """
    errors: list[str] = []
    intent, decision, receipt = chain["intent"], chain["decision"], chain["receipt"]

    # Each inner signature is verified over its own object, against the anchor
    # the caller named, never against a key the object carries about itself.
    intent_sig = intent.get("signature", "")
    unsigned_intent = {k: v for k, v in intent.items() if k != "signature"}
    if not verify(canonicalize(unsigned_intent), intent_sig, chain["intentSignerPublicKey"]):
        errors.append("Intent signature does not verify under the supplied intent signer")
    decision_sig = decision.get("signature", "")
    unsigned_decision = {k: v for k, v in decision.items() if k != "signature"}
    if not verify(canonicalize(unsigned_decision), decision_sig, chain["decisionSignerPublicKey"]):
        errors.append("Decision signature does not verify under the supplied decision signer")
    receipt_sig = receipt.get("signature", "")
    unsigned_receipt = {k: v for k, v in receipt.items() if k != "signature"}
    if not verify(canonicalize(unsigned_receipt), receipt_sig, chain["receiptSignerPublicKey"]):
        errors.append("Action receipt signature does not verify under the supplied receipt signer")

    # The signature strings the receipt copied must be the signatures on those
    # objects. Without this a receipt could carry three real signatures taken
    # from some other chain.
    carried = policy_receipt.get("chain") or {}
    if carried.get("intentSignature") != intent_sig:
        errors.append("Receipt carries an intent signature that is not the supplied intent's")
    if carried.get("decisionSignature") != decision_sig:
        errors.append("Receipt carries a decision signature that is not the supplied decision's")
    if carried.get("receiptSignature") != receipt_sig:
        errors.append("Receipt carries an action-receipt signature that is not the supplied receipt's")

    # Linkage. Each id must name the object presented for it, and the decision
    # must decide the intent presented rather than some other one.
    if policy_receipt.get("intentId") != intent.get("intentId"):
        errors.append("Receipt intentId does not name the supplied intent")
    if policy_receipt.get("decisionId") != decision.get("decisionId"):
        errors.append("Receipt decisionId does not name the supplied decision")
    if policy_receipt.get("receiptId") != receipt.get("receiptId"):
        errors.append("Receipt receiptId does not name the supplied action receipt")
    if decision.get("intentId") != intent.get("intentId"):
        errors.append("Decision does not decide the supplied intent: intentId mismatch")

    # A receipt is proof of a permitted action. A denied decision has no
    # receipt to attest to; create_policy_receipt refuses to build one, and a
    # verifier must refuse to accept one built another way.
    if decision.get("verdict") == "deny":
        errors.append("Receipt attests to a denied decision")

    expiry = parse_rfc3339(decision.get("expiresAt"))
    if expiry.ms is None:
        errors.append(f"Invalid decision expiresAt ({expiry.reason})")

    return errors


def verify_policy_receipt(
    policy_receipt: dict[str, Any],
    verifier_public_key: str,
    chain: Optional[PolicyReceiptChainInputs] = None,
) -> dict[str, Any]:
    """Verify a policy receipt AND the three-signature chain it attests to.

    SCOPE OF CLAIM.
      Establishes, when ``valid`` is true: the receipt envelope was signed by
        ``verifier_public_key``; the intent, decision and action receipt
        supplied by the caller were signed by the three anchors the caller
        supplied; the decision decides that intent; the receipt records that
        intent; and the three signature strings the receipt carries are the
        signatures on those three objects.
      Does NOT establish: that the four keys are the right ones, that they
        belong to four different parties, that the action described actually
        happened, or that the evaluator was entitled to permit it.

    ``chain`` is required in substance. Older callers passed two arguments and
    received ``valid: True`` for a receipt whose three inner signature strings
    were arbitrary text: the strings were tested for presence, never verified,
    and the objects they were made over were never seen. A caller that still
    omits it gets ``valid: False`` with ``chain_verified: False`` rather than
    an exception, because a verifier states a result. A relying party that
    only wants envelope integrity should say so by name with
    :func:`verify_policy_receipt_envelope`.
    """
    envelope = verify_policy_receipt_envelope(policy_receipt, verifier_public_key)
    errors: list[str] = list(envelope["errors"])

    if chain is None:
        errors.append(
            "Chain not verified: the intent, decision and action receipt, and a "
            "trust anchor for each, are required. Use "
            "verify_policy_receipt_envelope for an envelope-integrity check."
        )
        return {
            "valid": False,
            "envelope_signature_valid": envelope["envelope_signature_valid"],
            "chain_verified": False,
            "errors": errors,
        }

    chain_errors = _policy_chain_mismatches(policy_receipt, chain)
    errors.extend(chain_errors)
    return {
        "valid": len(errors) == 0,
        "envelope_signature_valid": envelope["envelope_signature_valid"],
        "chain_verified": len(chain_errors) == 0,
        "errors": errors,
    }


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
            parsed = parse_rfc3339(exp)
            if parsed.ms is None:
                # An expiry that cannot be read is not an expiry that has not
                # passed. This parse used to be wrapped in a bare `pass`, which
                # made writing garbage into expiresAt strictly better for the
                # holder than writing an honest date: the honest expired
                # delegation failed Auditability and the unreadable one did not.
                issues.append(f"Delegation expiresAt unreadable ({parsed.reason})")
            elif parsed.ms < now_ms():
                issues.append("Delegation expired")
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
