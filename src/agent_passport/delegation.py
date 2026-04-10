# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Delegation chains — scoped authority with depth limits and revocation.

Layer 1 delegation operations for the Agent Passport System.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize


def create_delegation(
    delegated_by: str,
    delegated_to: str,
    scope: list[str],
    private_key: str,
    spend_limit: float = 0,
    max_depth: int = 1,
    expires_in_days: int = 30,
) -> dict:
    """Create a signed delegation from one agent to another.

    Args:
        delegated_by: Public key of the delegator.
        delegated_to: Public key of the delegate.
        scope: List of permitted action scopes.
        private_key: Delegator's private key for signing.
        spend_limit: Maximum spend allowed under this delegation.
        max_depth: Maximum sub-delegation depth.
        expires_in_days: Days until delegation expires.

    Returns:
        Signed Delegation dict.
    """
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=expires_in_days)

    delegation = {
        "delegationId": f"del_{str(uuid.uuid4())[:12]}",
        "delegatedTo": delegated_to,
        "delegatedBy": delegated_by,
        "scope": scope,
        "expiresAt": expiry.isoformat(),
        "spendLimit": spend_limit,
        "spentAmount": 0,
        "maxDepth": max_depth,
        "currentDepth": 0,
        "createdAt": now.isoformat(),
    }

    # Sign delegation (excluding signature field)
    canonical = canonicalize(delegation)
    delegation["signature"] = sign(canonical, private_key)
    return delegation


def verify_delegation(delegation: dict) -> dict:
    """Verify a delegation's signature and status.

    Returns:
        DelegationStatus dict with valid, revoked, expired, errors.
    """
    errors = []
    sig = delegation.get("signature", "")
    delegated_by = delegation.get("delegatedBy", "")

    if not sig or not delegated_by:
        errors.append("Missing signature or delegator key")
    else:
        without_sig = {k: v for k, v in delegation.items() if k != "signature"}
        canonical = canonicalize(without_sig)
        if not verify(canonical, sig, delegated_by):
            errors.append("Invalid delegation signature")

    expired = False
    expires_at = delegation.get("expiresAt", "")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            expired = exp < datetime.now(timezone.utc)
        except (ValueError, TypeError):
            pass
    if expired:
        errors.append(f"Expired at {expires_at}")

    revoked = delegation.get("revoked", False)
    if revoked:
        errors.append(f"Revoked at {delegation.get('revokedAt', 'unknown')}")

    return {
        "valid": len(errors) == 0,
        "revoked": revoked,
        "expired": expired,
        "depthExceeded": False,
        "errors": errors,
    }


def sub_delegate(
    parent: dict,
    delegated_to: str,
    scope: list[str],
    private_key: str,
    spend_limit: Optional[float] = None,
    expires_in_days: int = 30,
) -> dict:
    """Create a sub-delegation from an existing delegation.

    Enforces scope narrowing, spend limits, and depth limits.

    Raises:
        ValueError: If depth limit exceeded or scope escalation attempted.
    """
    if parent["currentDepth"] + 1 > parent["maxDepth"]:
        raise ValueError(
            f"Depth limit exceeded: would be depth {parent['currentDepth'] + 1}, "
            f"max allowed is {parent['maxDepth']}"
        )

    # Scope narrowing: sub-delegation scope must be subset of parent
    parent_scope = set(parent["scope"])
    for s in scope:
        if s not in parent_scope:
            raise ValueError(
                f"Scope violation: [{s}] not in parent scope {parent['scope']}"
            )

    # Spend limit narrowing
    effective_limit = spend_limit if spend_limit is not None else parent.get("spendLimit", 0)
    if effective_limit > parent.get("spendLimit", 0):
        raise ValueError("Spend limit escalation: sub-delegation cannot exceed parent")

    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=expires_in_days)

    delegation = {
        "delegationId": f"del_{str(uuid.uuid4())[:12]}",
        "delegatedTo": delegated_to,
        "delegatedBy": parent["delegatedTo"],  # sub-delegator is parent's delegate
        "scope": scope,
        "expiresAt": expiry.isoformat(),
        "spendLimit": effective_limit,
        "spentAmount": 0,
        "maxDepth": parent["maxDepth"],
        "currentDepth": parent["currentDepth"] + 1,
        "createdAt": now.isoformat(),
    }

    canonical = canonicalize(delegation)
    delegation["signature"] = sign(canonical, private_key)
    return delegation


def revoke_delegation(
    delegation: dict,
    private_key: str,
    reason: str = "manual",
) -> dict:
    """Revoke a delegation.

    Returns:
        RevocationRecord dict.
    """
    now = datetime.now(timezone.utc)
    revocation = {
        "revocationId": f"rev_{uuid.uuid4()}",
        "delegationId": delegation["delegationId"],
        "revokedBy": delegation["delegatedBy"],
        "revokedAt": now.isoformat(),
        "reason": reason,
    }
    canonical = canonicalize(revocation)
    revocation["signature"] = sign(canonical, private_key)

    # Mark original delegation as revoked
    delegation["revoked"] = True
    delegation["revokedAt"] = now.isoformat()

    return revocation


def scope_covers(parent_scope: list[str], child_scope: list[str]) -> bool:
    """Check if parent scope covers all child scopes."""
    return all(any(s == c or c.startswith(s + ":") for s in parent_scope) for c in child_scope)


def scope_authorizes(delegation_scope: list[str], required: str) -> bool:
    """Check if a delegation scope list authorizes a required scope."""
    for s in delegation_scope:
        if s == required or required.startswith(s + ":"):
            return True
    return False


def create_action_receipt(
    agent_id: str,
    delegation: dict,
    action_type: str,
    target: str,
    scope_used: str,
    result_status: str,
    result_summary: str,
    private_key: str,
    spend_amount: float = 0,
    delegation_chain: Optional[list] = None,
) -> dict:
    """Create a signed action receipt for completed work.

    Validates scope and spend limits before creating receipt.

    Raises:
        ValueError: If scope violation or spend limit exceeded.
    """
    status = verify_delegation(delegation)
    if not status["valid"]:
        raise ValueError(
            f"Cannot create receipt: delegation invalid — {', '.join(status['errors'])}"
        )

    if scope_used not in delegation["scope"]:
        raise ValueError(f"Scope violation: {scope_used} not in {delegation['scope']}")

    if spend_amount > delegation.get("spendLimit", 0):
        raise ValueError(
            f"Spend limit exceeded: {spend_amount} > {delegation.get('spendLimit', 0)}"
        )

    receipt = {
        "receiptId": f"rcpt_{uuid.uuid4()}",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agentId": agent_id,
        "delegationId": delegation["delegationId"],
        "action": {
            "type": action_type,
            "target": target,
            "scopeUsed": scope_used,
            "spend": {"amount": spend_amount, "currency": "usd"},
        },
        "result": {
            "status": result_status,
            "summary": result_summary,
        },
        "delegationChain": delegation_chain or [],
    }

    canonical = canonicalize(receipt)
    receipt["signature"] = sign(canonical, private_key)
    return receipt
