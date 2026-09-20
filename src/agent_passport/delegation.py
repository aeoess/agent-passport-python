# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Delegation chains — scoped authority with depth limits and revocation.

Layer 1 delegation operations for the Agent Passport System.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize, has_non_finite, canonicalize_for_write
from ._time import parse_iso_utc


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

    Legacy Delegation, a pre-draft compatibility surface. Deprecated.

    The delegated authority record of draft-pidlisnyi-aps-03 is AuthorityDelegationV1
    (section 3.1, record_type "aps:authority-delegation:v1"), in
    agent_passport.v2.authority_delegation. This record is not that one: it predates the
    draft's wire format, carries a different member set, and is not on the draft path. It
    is kept so existing deployments keep working, and its authority semantics are frozen.
    New work uses issue_authority_delegation, issue_sub_authority_delegation and
    verify_authority_delegation_chain.

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
    canonical = canonicalize_for_write(delegation)
    delegation["signature"] = sign(canonical, private_key)
    return delegation


def verify_delegation(delegation: dict) -> dict:
    """Verify a delegation's signature and status.

    Pre-draft compatibility surface, deprecated and frozen: see create_delegation. This is
    not the draft-03 chain verifier. Section 3.3 runs a root-to-leaf chain through a fixed
    order of checks and returns one of valid, invalid, indeterminate or unsupported; that
    is verify_authority_delegation_chain. This function checks one legacy record.

    Returns:
        DelegationStatus dict with valid, revoked, expired, errors.
    """
    errors = []
    sig = delegation.get("signature", "")
    delegated_by = delegation.get("delegatedBy", "")

    if not sig or not delegated_by:
        errors.append("Missing signature or delegator key")
    elif has_non_finite(delegation):
        # json.loads accepts NaN/Infinity by default, but canonicalize() raises
        # on them. Fail closed instead of letting the verifier crash.
        errors.append("Delegation contains non-finite numeric field")
    else:
        without_sig = {k: v for k, v in delegation.items() if k != "signature"}
        canonical = canonicalize(without_sig)
        if not verify(canonical, sig, delegated_by):
            errors.append("Invalid delegation signature")

    expired = False
    expires_at = delegation.get("expiresAt", "")
    if expires_at:
        try:
            expired = parse_iso_utc(expires_at) < datetime.now(timezone.utc)
        except (ValueError, TypeError):
            # Fail closed: an expiresAt that is present but unparseable is
            # treated as expired, not ignored. (parse_iso_utc handles the 'Z'
            # form the SDK/TS reference emits on Python 3.9+.)
            expired = True
            errors.append(f"Unparseable expiresAt: {expires_at!r}")
    if expired:
        errors.append(f"Expired at {expires_at}")

    # ADVISORY ONLY: this in-band field is unsigned and mutable, so it is NOT a security boundary.
    # A holder of a revoked delegation can simply strip it, and an attacker cannot be stopped by it.
    # Authoritative revocation requires a trusted registry or a signed RevocationRecord, which a
    # stateless verifier cannot consult. This matches the TS SDK, whose verifyDelegation defaults to
    # fail_open and notes the SDK cannot check revocation statelessly. Full registry/cached-state
    # parity is a protocol decision flagged for review; do not treat a missing flag as proof of
    # non-revocation.
    revoked = delegation.get("revoked", False)
    if revoked:
        errors.append(f"Revoked at {delegation.get('revokedAt', 'unknown')}")

    # Depth enforcement: a delegation whose currentDepth exceeds its own maxDepth is invalid.
    # This was hardcoded False, so the verifier (the enforcement point) never checked depth and a
    # hand-crafted delegation with currentDepth > maxDepth verified as valid. sub_delegate guards
    # depth at creation, but the verifier must check it independently.
    current_depth = delegation.get("currentDepth", 0)
    max_depth = delegation.get("maxDepth", 0)
    depth_exceeded = (
        isinstance(current_depth, (int, float)) and not isinstance(current_depth, bool)
        and isinstance(max_depth, (int, float)) and not isinstance(max_depth, bool)
        and current_depth > max_depth
    )
    if depth_exceeded:
        errors.append(f"Depth exceeded: currentDepth {current_depth} > maxDepth {max_depth}")

    return {
        "valid": len(errors) == 0,
        "revoked": revoked,
        "expired": expired,
        "depthExceeded": depth_exceeded,
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

    Pre-draft compatibility surface, deprecated and frozen: see create_delegation.

    Scope narrowing here is exact membership: a child scope string must appear in the
    parent's list. That is stricter than both of the other two rules in play. Draft
    section 3.2 (published lines 516 to 521) lets "*" cover every grant and a terminal
    "p:*" cover p and every grant beginning "p:", so it admits narrowing "*" to
    "data:read", which this function rejects. The TypeScript legacy rule additionally lets
    a bare grant "p" cover "p:x", which section 3.2 does not allow. The three rules are
    deliberately not converged: changing any of them would change what records already
    signed under it authorize. The draft-path narrowing check is compare_authority in
    agent_passport.v2.authority_delegation.

    Raises:
        ValueError: If depth limit exceeded or scope escalation attempted.
    """
    # The parent must itself be valid before it can mint a child. Previously sub_delegate minted a
    # child from any parent dict, including an expired, revoked, or signature-invalid one.
    parent_status = verify_delegation(parent)
    if not parent_status["valid"]:
        raise ValueError(
            f"Cannot sub-delegate from an invalid parent: {', '.join(parent_status['errors'])}"
        )

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

    # Spend limit narrowing: the child cannot exceed the parent's REMAINING budget
    # (spendLimit - spentAmount), not just its nominal spendLimit.
    parent_remaining = parent.get("spendLimit", 0) - parent.get("spentAmount", 0)
    effective_limit = spend_limit if spend_limit is not None else parent_remaining
    if effective_limit > parent_remaining:
        raise ValueError(
            "Spend limit escalation: sub-delegation cannot exceed parent remaining budget"
        )

    now = datetime.now(timezone.utc)
    requested_expiry = now + timedelta(days=expires_in_days)
    # Temporal narrowing: a sub-delegation may not outlive its parent. Cap the child expiry to the
    # parent's expiresAt when the parent carries one.
    parent_expiry = None
    parent_expires_at = parent.get("expiresAt")
    if isinstance(parent_expires_at, str) and parent_expires_at:
        try:
            parent_expiry = parse_iso_utc(parent_expires_at)
        except (ValueError, TypeError):
            # Fail closed: a parent whose expiry cannot be parsed is treated as
            # already expired, so the child cannot outlive an unknowable bound.
            parent_expiry = now
    expiry = min(requested_expiry, parent_expiry) if parent_expiry is not None else requested_expiry

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

    canonical = canonicalize_for_write(delegation)
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
    canonical = canonicalize_for_write(revocation)
    revocation["signature"] = sign(canonical, private_key)

    # Mark original delegation as revoked
    delegation["revoked"] = True
    delegation["revokedAt"] = now.isoformat()

    return revocation


def scope_covers(parent_scope: list[str], child_scope: list[str]) -> bool:
    """Check if parent scope covers all child scopes.

    Pre-draft scope matching, not the section 3.2 rule: here a bare grant "p" covers
    "p:x", and "*" is an ordinary string with no wildcard meaning. Draft lines 516 to 521
    give the section 3.2 rule, implemented by scope_grant_covers in
    agent_passport.v2.authority_delegation.scope. Frozen: draft-path code uses
    scope_grant_covers and never this.
    """
    return all(any(s == c or c.startswith(s + ":") for s in parent_scope) for c in child_scope)


def scope_authorizes(delegation_scope: list[str], required: str) -> bool:
    """Check if a delegation scope list authorizes a required scope.

    Pre-draft scope matching, with the same difference from section 3.2 that
    scope_covers documents. Frozen.
    """
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

    # Check the spend against the REMAINING budget (spendLimit - spentAmount), not the nominal
    # spendLimit, so an already-partly-spent delegation cannot authorize a fresh full-limit action.
    _remaining = delegation.get("spendLimit", 0) - delegation.get("spentAmount", 0)
    if spend_amount > _remaining:
        raise ValueError(
            f"Spend limit exceeded: {spend_amount} > {_remaining} remaining "
            f"(limit {delegation.get('spendLimit', 0)}, spent {delegation.get('spentAmount', 0)})"
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

    canonical = canonicalize_for_write(receipt)
    receipt["signature"] = sign(canonical, private_key)
    return receipt


def verify_action_receipt(receipt: dict, agent_public_key: str) -> dict:
    """Verify an action receipt's signature against the executing agent's public key.

    Mirrors create_action_receipt's signing convention exactly: the signature covers
    canonicalize(receipt-without-signature). This is the receipt-level counterpart of
    verify_delegation and the Python equivalent of the TypeScript verifyReceipt. It checks
    only the signature; freshness/scope are enforced elsewhere.

    Returns:
        dict with ``valid`` (bool) and ``errors`` (list[str]).
    """
    errors = []
    sig = receipt.get("signature", "")
    if not sig or not agent_public_key:
        errors.append("Missing signature or agent key")
    else:
        without_sig = {k: v for k, v in receipt.items() if k != "signature"}
        canonical = canonicalize(without_sig)
        if not verify(canonical, sig, agent_public_key):
            errors.append("Invalid receipt signature")
    return {"valid": len(errors) == 0, "errors": errors}
