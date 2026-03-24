# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Agent Passport — create, sign, verify, and manage agent identity.

Core Layer 1 operations for the Agent Passport System.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import generate_key_pair, sign, verify
from .canonical import canonicalize

DEFAULT_EXPIRY_DAYS = 365

CAPABILITY_WEIGHTS: dict[str, float] = {
    "code_execution": 0.5,
    "system_control": 0.5,
    "web_search": 0.2,
    "email_management": 0.3,
    "file_management": 0.3,
    "git_operations": 0.3,
    "browser_automation": 0.2,
    "voice_transcription": 0.1,
    "social_media_posting": 0.1,
}


def _calculate_vote_weight(capabilities: list[str]) -> int:
    bonus = sum(CAPABILITY_WEIGHTS.get(cap, 0.1) for cap in capabilities)
    return max(1, round(1 + bonus))


def _default_reputation() -> dict:
    return {
        "overall": 1,
        "collaborationsCompleted": 0,
        "proposalsSubmitted": 0,
        "proposalsApproved": 0,
        "tokensContributed": 0,
        "tasksCompleted": 0,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
    }


def create_passport(
    agent_id: str,
    agent_name: str,
    owner_alias: str,
    mission: str,
    capabilities: list[str],
    runtime: dict,
    expires_in_days: int = DEFAULT_EXPIRY_DAYS,
    delegations: Optional[list] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Create a new agent passport with Ed25519 identity.

    Returns:
        dict with 'signedPassport' and 'keyPair'. Cross-language compatible
        with the TypeScript SDK's createPassport().
    """
    key_pair = generate_key_pair()
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=expires_in_days)

    passport = {
        "version": "1.0.0",
        "agentId": agent_id,
        "agentName": agent_name,
        "ownerAlias": owner_alias,
        "publicKey": key_pair["publicKey"],
        "mission": mission,
        "capabilities": capabilities,
        "runtime": runtime,
        "createdAt": now.isoformat(),
        "expiresAt": expiry.isoformat(),
        "voteWeight": _calculate_vote_weight(capabilities),
        "reputation": _default_reputation(),
        "delegations": delegations or [],
        "metadata": metadata or {},
    }

    signed = sign_passport(passport, key_pair["privateKey"])
    return {"signedPassport": signed, "keyPair": key_pair}


def sign_passport(passport: dict, private_key: str) -> dict:
    """Sign a passport with Ed25519.

    Args:
        passport: AgentPassport dict (without signature).
        private_key: Hex-encoded 32-byte private key.

    Returns:
        SignedPassport dict with passport, signature, and signedAt.
    """
    canonical = canonicalize(passport)
    signature = sign(canonical, private_key)
    return {
        "passport": passport,
        "signature": signature,
        "signedAt": datetime.now(timezone.utc).isoformat(),
    }


def verify_passport(signed_passport: dict) -> dict:
    """Verify a signed passport's signature.

    Args:
        signed_passport: SignedPassport dict.

    Returns:
        VerificationResult with valid, errors, warnings, passport.
    """
    errors = []
    warnings = []
    passport = signed_passport.get("passport", {})
    signature = signed_passport.get("signature", "")
    public_key = passport.get("publicKey", "")

    if not signature:
        errors.append("Missing signature")
    if not public_key:
        errors.append("Missing public key")

    if not errors:
        canonical = canonicalize(passport)
        if not verify(canonical, signature, public_key):
            errors.append("Invalid signature")

    if is_expired(passport):
        warnings.append("Passport is expired")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "passport": passport if len(errors) == 0 else None,
    }


def update_passport(passport: dict, updates: dict, private_key: str) -> dict:
    """Update and re-sign a passport."""
    updated = {**passport, **updates}
    if "capabilities" in updates:
        updated["voteWeight"] = _calculate_vote_weight(updates["capabilities"])
    return sign_passport(updated, private_key)


def is_expired(passport: dict) -> bool:
    """Check if a passport has expired."""
    expires_at = passport.get("expiresAt", "")
    if not expires_at:
        return False
    try:
        expiry = datetime.fromisoformat(expires_at)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False
