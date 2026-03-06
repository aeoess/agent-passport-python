"""Agentic Commerce — 4-gate checkout pipeline with human approval.

Layer 8 of the Agent Social Contract.
Every commerce action flows through passport, delegation, spend, and merchant gates.
Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize
from .passport import verify_passport


def _rand_hex(n: int = 8) -> str:
    return os.urandom(n).hex()


def _has_scope(delegation: dict, required: str) -> bool:
    return required in delegation.get("scope", []) or "commerce:*" in delegation.get("scope", [])


# ── Preflight Check: 4-Gate Pipeline ──


def commerce_preflight(
    signed_passport: dict,
    delegation: dict,
    merchant_name: str,
    estimated_total: dict,
) -> dict:
    """Run the 4-gate preflight check for a commerce action.

    Returns:
        CommercePreflightResult dict.
    """
    checks: list[dict] = []
    warnings: list[str] = []

    # Gate 1: Passport verification
    passport_result = verify_passport(signed_passport)
    checks.append({
        "check": "passport_valid", "passed": passport_result["valid"],
        "detail": (
            f"Passport verified for {signed_passport['passport']['agentId']}"
            if passport_result["valid"]
            else f"Passport failed: {', '.join(passport_result['errors'])}"
        ),
    })

    # Gate 2: Delegation scope
    has_checkout = _has_scope(delegation, "commerce:checkout")
    checks.append({
        "check": "delegation_scope", "passed": has_checkout,
        "detail": (
            f"Agent has commerce:checkout scope via delegation {delegation.get('delegationId')}"
            if has_checkout
            else f"Agent lacks commerce:checkout scope. Has: {delegation.get('scope', [])}"
        ),
    })

    # Gate 3: Spend limit
    amount = estimated_total.get("amount", 0)
    remaining = delegation.get("spendLimit", 0) - delegation.get("spentAmount", 0)
    within_budget = amount <= remaining
    checks.append({
        "check": "spend_limit", "passed": within_budget,
        "detail": (
            f"Purchase {amount} within budget ({remaining} remaining of {delegation.get('spendLimit', 0)})"
            if within_budget
            else f"Purchase {amount} exceeds remaining budget of {remaining}"
        ),
    })

    # Gate 3b: Human approval threshold
    if delegation.get("requireHumanApproval") and delegation.get("humanApprovalThreshold"):
        if amount > delegation["humanApprovalThreshold"]:
            warnings.append(
                f"Purchase of {amount} exceeds human approval threshold of "
                f"{delegation['humanApprovalThreshold']}. Human confirmation required."
            )

    # Gate 4: Merchant allowlist
    approved = delegation.get("approvedMerchants")
    if approved and len(approved) > 0:
        merchant_ok = merchant_name in approved
        checks.append({
            "check": "merchant_approved", "passed": merchant_ok,
            "detail": (
                f'Merchant "{merchant_name}" is on approved list'
                if merchant_ok
                else f'Merchant "{merchant_name}" is NOT on approved list: {approved}'
            ),
        })

    permitted = all(c["passed"] for c in checks)
    return {
        "permitted": permitted, "checks": checks, "delegation": delegation,
        "warnings": warnings,
        "blockedReason": None if permitted else next((c["detail"] for c in checks if not c["passed"]), None),
    }


# ── Human Approval Request ──


def request_human_approval(
    agent_id: str,
    delegation_id: str,
    merchant_name: str,
    items: list[dict],
    total_amount: dict,
    reason: str,
    expires_in_minutes: int = 30,
) -> dict:
    """Create a human approval request for a high-value purchase."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=expires_in_minutes)
    return {
        "requestId": f"approval-{_rand_hex()}",
        "agentId": agent_id,
        "merchantName": merchant_name,
        "items": items,
        "totalAmount": total_amount,
        "delegationId": delegation_id,
        "reason": reason,
        "createdAt": now.isoformat(),
        "expiresAt": expires.isoformat(),
        "status": "pending",
    }


# ── Commerce Delegation Factory ──


def create_commerce_delegation(
    agent_id: str,
    delegation_id: str,
    spend_limit: float,
    currency: str = "usd",
    approved_merchants: Optional[list[str]] = None,
    require_human_approval: bool = True,
    human_approval_threshold: Optional[float] = None,
    additional_scopes: Optional[list[str]] = None,
) -> dict:
    """Create a CommerceDelegation."""
    return {
        "agentId": agent_id,
        "delegationId": delegation_id,
        "scope": ["commerce:checkout", "commerce:browse", *(additional_scopes or [])],
        "spendLimit": spend_limit,
        "spentAmount": 0,
        "currency": currency,
        "approvedMerchants": approved_merchants,
        "requireHumanApproval": require_human_approval,
        "humanApprovalThreshold": human_approval_threshold,
    }


# ── Spend Analytics ──


def get_spend_summary(delegation: dict) -> dict:
    """Get spend analytics for a commerce delegation."""
    limit = delegation.get("spendLimit", 0)
    spent = delegation.get("spentAmount", 0)
    remaining = limit - spent
    utilization = (spent / limit * 100) if limit > 0 else 0
    return {
        "limit": limit,
        "spent": spent,
        "remaining": remaining,
        "currency": delegation.get("currency", "usd"),
        "utilizationPercent": round(utilization, 2),
        "nearLimit": utilization >= 80,
    }


# ── Commerce Receipt Signing ──


def sign_commerce_receipt(
    agent_id: str,
    delegation_id: str,
    action_type: str,
    target: str,
    method: str,
    merchant_name: str,
    session_id: str,
    items: list[dict],
    total_amount: float,
    total_currency: str,
    status: str,
    delegation_chain: list[str],
    beneficiary: str,
    private_key: str,
) -> dict:
    """Create a signed commerce action receipt."""
    receipt = {
        "receiptId": f"rcpt-commerce-{_rand_hex()}",
        "version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agentId": agent_id,
        "delegationId": delegation_id,
        "action": {
            "type": action_type,
            "target": target,
            "method": method,
            "scopeUsed": "commerce:checkout",
            "spend": {"amount": total_amount, "currency": total_currency},
        },
        "checkout": {
            "sessionId": session_id,
            "merchantName": merchant_name,
            "items": items,
            "totalAmount": total_amount,
            "totalCurrency": total_currency,
            "status": status,
        },
        "delegationChain": delegation_chain,
        "beneficiary": beneficiary,
    }
    payload = canonicalize(receipt)
    sig = sign(payload, private_key)
    return {**receipt, "signature": sig}


def verify_commerce_receipt(receipt: dict, public_key: str) -> dict:
    """Verify a commerce receipt's signature and required fields."""
    errors: list[str] = []
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), receipt.get("signature", ""), public_key):
            errors.append("Commerce receipt signature is invalid")
    except Exception:
        errors.append("Failed to verify commerce receipt signature")

    if not receipt.get("receiptId"):
        errors.append("Missing receiptId")
    if not receipt.get("agentId"):
        errors.append("Missing agentId")
    if not receipt.get("delegationId"):
        errors.append("Missing delegationId")
    if not receipt.get("action", {}).get("type"):
        errors.append("Missing action type")
    if not receipt.get("action", {}).get("scopeUsed"):
        errors.append("Missing scopeUsed")
    if not receipt.get("beneficiary"):
        errors.append("Missing beneficiary")
    if not receipt.get("checkout", {}).get("sessionId"):
        errors.append("Missing checkout sessionId")

    return {"valid": len(errors) == 0, "errors": errors}
