# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Integration Wiring — Cross-layer bridges connecting isolated modules.

Layer 7 of the Agent Social Contract.
Bridges: Commerce -> Intent/Policy, Commerce -> Attribution,
Commerce -> Delegation, Coordination -> Agora.
Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

from typing import Any, Optional

from .policy import create_action_intent, evaluate_intent
from .commerce import commerce_preflight
from .agora import create_agora_message, append_to_feed
from .delegation import verify_delegation
from .canonical import canonicalize
from .crypto import sign


# ══════════════════════════════════════
# 1. COMMERCE -> INTENT/POLICY
# ══════════════════════════════════════


def commerce_with_intent(
    signed_passport: dict,
    agent_private_key: str,
    delegation: dict,
    commerce_delegation: dict,
    merchant_name: str,
    estimated_total: dict,
    action_description: str,
    validator: Any,
    validation_context: dict,
    evaluator_id: str,
    evaluator_public_key: str,
    evaluator_private_key: str,
) -> dict:
    """Full commerce flow: Intent -> Policy -> Preflight."""
    intent = create_action_intent(
        agent_id=signed_passport["passport"]["agentId"],
        agent_public_key=signed_passport["passport"]["publicKey"],
        delegation_id=delegation["delegationId"],
        action={
            "type": "commerce:checkout",
            "scopeRequired": "commerce:checkout",
            "target": merchant_name,
            "spend": {"amount": estimated_total["amount"], "currency": estimated_total["currency"]},
        },
        context=f"Commerce: {merchant_name} — {estimated_total['amount']} {estimated_total['currency']}. {action_description}",
        private_key=agent_private_key,
    )

    decision = evaluate_intent(
        intent=intent,
        validator=validator,
        validation_context=validation_context,
        evaluator_id=evaluator_id,
        evaluator_public_key=evaluator_public_key,
        evaluator_private_key=evaluator_private_key,
    )

    if decision["verdict"] != "permit":
        return {
            "intent": intent, "decision": decision,
            "preflight": {
                "permitted": False, "checks": [], "delegation": commerce_delegation,
                "warnings": [], "blockedReason": f"Policy denied: {decision['verdict']} — {decision['reason']}",
            },
            "permitted": False, "blockedAt": "policy", "reason": decision["reason"],
        }

    pf = commerce_preflight(
        signed_passport=signed_passport,
        delegation=commerce_delegation,
        merchant_name=merchant_name,
        estimated_total=estimated_total,
    )
    return {
        "intent": intent, "decision": decision, "preflight": pf,
        "permitted": pf["permitted"],
        "blockedAt": None if pf["permitted"] else "preflight",
        "reason": None if pf["permitted"] else pf.get("blockedReason"),
    }


# ══════════════════════════════════════
# 2. COMMERCE -> ATTRIBUTION
# ══════════════════════════════════════


def commerce_receipt_to_action_receipt(
    commerce_receipt: dict,
    result_status: str = "success",
) -> dict:
    """Convert a CommerceActionReceipt to a standard ActionReceipt."""
    checkout = commerce_receipt.get("checkout", {})
    items = checkout.get("items", [])
    return {
        "receiptId": commerce_receipt["receiptId"],
        "version": commerce_receipt.get("version", "1.0"),
        "timestamp": commerce_receipt["timestamp"],
        "agentId": commerce_receipt["agentId"],
        "delegationId": commerce_receipt["delegationId"],
        "action": {
            "type": commerce_receipt["action"]["type"],
            "target": commerce_receipt["action"]["target"],
            "method": commerce_receipt["action"].get("method"),
            "scopeUsed": commerce_receipt["action"]["scopeUsed"],
            "spend": commerce_receipt["action"].get("spend"),
        },
        "result": {
            "status": result_status,
            "summary": f"{checkout.get('merchantName')}: {len(items)} items, "
                       f"{checkout.get('totalAmount')} {checkout.get('totalCurrency')} — "
                       f"{checkout.get('status')}",
        },
        "delegationChain": commerce_receipt.get("delegationChain", []),
        "signature": commerce_receipt["signature"],
    }


# ══════════════════════════════════════
# 3. COMMERCE -> DELEGATION
# ══════════════════════════════════════


def validate_commerce_delegation(
    commerce_delegation: dict,
    protocol_delegation: dict,
) -> dict:
    """Validate a CommerceDelegation against its backing protocol Delegation."""
    errors: list[str] = []

    if commerce_delegation.get("delegationId") != protocol_delegation.get("delegationId"):
        errors.append(
            f"Delegation ID mismatch: commerce={commerce_delegation.get('delegationId')}, "
            f"protocol={protocol_delegation.get('delegationId')}"
        )

    not_revoked = not protocol_delegation.get("revoked", False)
    if not not_revoked:
        errors.append(f"Delegation revoked at {protocol_delegation.get('revokedAt', 'unknown')}")

    verify_result = verify_delegation(protocol_delegation)
    if not verify_result["valid"]:
        errors.extend(verify_result["errors"])

    proto_scope = protocol_delegation.get("scope", [])
    scope_match = all(s in proto_scope for s in commerce_delegation.get("scope", []))
    if not scope_match:
        errors.append(
            f"Commerce scopes {commerce_delegation.get('scope')} not within "
            f"protocol scopes {proto_scope}"
        )

    proto_limit = protocol_delegation.get("spendLimit", float("inf"))
    within_spend = commerce_delegation.get("spendLimit", 0) <= proto_limit
    if not within_spend:
        errors.append(
            f"Commerce spend limit {commerce_delegation.get('spendLimit')} exceeds "
            f"protocol limit {proto_limit}"
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "scopeMatch": scope_match,
        "withinSpendLimit": within_spend,
        "notRevoked": not_revoked,
    }


# ══════════════════════════════════════
# 4. COORDINATION -> AGORA
# ══════════════════════════════════════


_COORD_SUBJECTS = {
    "task_created": "New task: {}",
    "task_assigned": "Agent assigned to {}",
    "evidence_submitted": "Evidence submitted for {}",
    "review_completed": "Review completed on {}",
    "evidence_handed_off": "Evidence handed off in {}",
    "deliverable_submitted": "Deliverable submitted for {}",
    "task_completed": "Task completed: {}",
}


def coordination_to_agora(
    event: str,
    task_id: str,
    agent_id: str,
    agent_name: str,
    public_key: str,
    private_key: str,
    feed: dict,
    registry: dict,
    detail: str,
) -> dict:
    """Post a coordination lifecycle event to the Agora.

    Returns:
        dict with 'message' and 'feed'.
    """
    subject = _COORD_SUBJECTS.get(event, f"{event}: {task_id}").format(task_id)
    message = create_agora_message(
        agent_id=agent_id,
        agent_name=agent_name,
        public_key=public_key,
        private_key=private_key,
        topic=f"coordination:{task_id}",
        msg_type="announcement",
        subject=subject,
        content=detail,
    )
    updated_feed = append_to_feed(feed, message)
    return {"message": message, "feed": updated_feed}


def post_task_created(brief: dict, agent_id: str, agent_name: str,
                      public_key: str, private_key: str, feed: dict, registry: dict) -> dict:
    detail = (
        f'Task "{brief["title"]}" created with {len(brief["roles"])} roles and '
        f'{len(brief["deliverables"])} deliverables. {brief["description"]}'
    )
    return coordination_to_agora("task_created", brief["taskId"],
                                  agent_id, agent_name, public_key, private_key, feed, registry, detail)


def post_review_completed(review: dict, agent_id: str, agent_name: str,
                          public_key: str, private_key: str, feed: dict, registry: dict) -> dict:
    detail = f"Review verdict: {review['verdict']} (score: {review['score']}/{review['threshold']}). {review['rationale']}"
    return coordination_to_agora("review_completed", review["taskId"],
                                  agent_id, agent_name, public_key, private_key, feed, registry, detail)


def post_task_completed(completion: dict, agent_id: str, agent_name: str,
                        public_key: str, private_key: str, feed: dict, registry: dict) -> dict:
    m = completion["metrics"]
    detail = (
        f"Status: {completion['status']}. Agents: {m['agentCount']}, "
        f"Duration: {m['totalDuration']}s, Rework cycles: {m['reworkCount']}. "
        f"{completion.get('retrospective', '')}"
    )
    return coordination_to_agora("task_completed", completion["taskId"],
                                  agent_id, agent_name, public_key, private_key, feed, registry, detail)
