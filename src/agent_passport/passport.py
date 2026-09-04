# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Agent Passport — create, sign, verify, and manage agent identity.

Core Layer 1 operations for the Agent Passport System.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import generate_key_pair, sign, verify
from .canonical import canonicalize, has_non_finite, canonicalize_for_write
from ._time import parse_iso_utc

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
    canonical = canonicalize_for_write(passport)
    signature = sign(canonical, private_key)
    return {
        "passport": passport,
        "signature": signature,
        "signedAt": datetime.now(timezone.utc).isoformat(),
    }


def issuer_signature_preimage(signed_passport: dict[str, Any]) -> str:
    """The bytes an issuer countersignature is made over.

    ``canonicalize({passport, signature, signedAt})``, which is exactly the
    payload the TypeScript reference builds at
    src/verification/verify.ts:102-106 and the Rust and Go suites pin against
    the same vectors. Exposed so a caller can compute or compare it without
    reimplementing the shape.
    """
    return canonicalize({
        "passport": signed_passport.get("passport"),
        "signature": signed_passport.get("signature"),
        "signedAt": signed_passport.get("signedAt"),
    })


def _normalize_trust_anchors(trusted_issuers: Any) -> tuple[list[str], Optional[str]]:
    """Read the caller's trust input, or say why it cannot be read.

    A caller that fumbles its own trust list must not thereby land on the
    permissive path, so a malformed value is an error rather than an empty
    anchor set.
    """
    if trusted_issuers is None:
        return [], None
    if not isinstance(trusted_issuers, (list, tuple)):
        return [], f"trusted_issuers must be a list of hex public keys, got {type(trusted_issuers).__name__}"
    anchors = []
    for item in trusted_issuers:
        if not isinstance(item, str) or not item:
            return [], "trusted_issuers must contain only non-empty hex public keys"
        anchors.append(item)
    return anchors, None


def verify_passport(
    signed_passport: dict[str, Any],
    *,
    trusted_issuers: Optional[list[str]] = None,
    allow_self_signed: bool = False,
) -> dict[str, Any]:
    """Verify a signed passport, and establish whether anyone vouches for it.

    A signature over a passport says who signed it, not who vouches for it.
    The verifying key is carried by the passport itself, so a good signature
    is available to anyone who can generate a key pair: it establishes
    integrity and never authority. Authority comes from the caller.

    Args:
        signed_passport: SignedPassport dict.
        trusted_issuers: Public keys whose countersignature this relying party
            accepts. When supplied, the passport must carry an
            ``issuerSignature`` from one of them, over
            :func:`issuer_signature_preimage`.
        allow_self_signed: Accept a passport that carries no countersignature,
            on its own signature alone. Off by default. Only consulted when
            ``trusted_issuers`` was not supplied: a caller that named issuers
            asked for that check, and this flag does not rescue a failed one.

    Returns:
        dict with ``valid``, ``errors``, ``warnings``, ``passport``, plus:
          - ``issuer_trust_checked``: whether an issuer-trust check ran at all,
            i.e. whether a non-empty ``trusted_issuers`` was supplied.
          - ``self_signed_accepted``: whether this result was reached with no
            trust root consulted. A caller that must not act on a
            self-vouching credential branches on this rather than on warning
            text.

    ``valid`` is false when authority could not be established. That is
    deliberately stricter than the frozen TypeScript ``verifyPassport``, whose
    ``selfSignedAccepted`` field documents keeping ``valid`` true for a
    self-signed passport for backward compatibility. The trust shape is
    mirrored; the permissive default is not.
    """
    errors: list[str] = []
    warnings: list[str] = []
    passport = signed_passport.get("passport", {}) if isinstance(signed_passport, dict) else {}
    signature = signed_passport.get("signature", "") if isinstance(signed_passport, dict) else ""
    public_key = passport.get("publicKey", "") if isinstance(passport, dict) else ""

    anchors, anchor_error = _normalize_trust_anchors(trusted_issuers)
    issuer_trust_checked = len(anchors) > 0
    if anchor_error is not None:
        return {
            "valid": False,
            "errors": [f"Invalid trusted_issuers option: {anchor_error}"],
            "warnings": warnings,
            "passport": None,
            "issuer_trust_checked": False,
            "self_signed_accepted": False,
        }

    if not signature:
        errors.append("Missing signature")
    if not public_key:
        errors.append("Missing public key")

    if not errors:
        # Guard non-finite numerics before canonicalize(): json.loads accepts
        # NaN/Infinity by default, but canonicalize() raises on them. Fail
        # closed instead of letting the verifier crash.
        if has_non_finite(passport):
            errors.append("Passport contains non-finite numeric field")
        else:
            canonical = canonicalize(passport)
            if not verify(canonical, signature, public_key):
                errors.append("Invalid signature")

    # Expiry is an ERROR, not a warning: an expired passport with a valid
    # signature is not valid. Matches the TS reference (verifyPassport pushes
    # 'Passport expired' to errors) and this repo's verify_delegation /
    # verify_endorsement, which already treat expiry as an error.
    if is_expired(passport):
        errors.append("Passport expired")

    # Authority. Integrity above, trust here, and the two are never merged.
    self_signed_accepted = False
    issuer_sig = signed_passport.get("issuerSignature") if isinstance(signed_passport, dict) else None
    if issuer_trust_checked:
        if not isinstance(issuer_sig, dict) or not issuer_sig.get("signature") \
                or not issuer_sig.get("issuerPublicKey"):
            errors.append("No issuer countersignature: passport is self-signed")
        elif issuer_sig["issuerPublicKey"] not in anchors:
            errors.append(
                f"Issuer {issuer_sig['issuerPublicKey'][:16]}... not in trusted issuers list"
            )
        elif not verify(
            issuer_signature_preimage(signed_passport),
            issuer_sig["signature"],
            issuer_sig["issuerPublicKey"],
        ):
            errors.append("Invalid issuer countersignature")
    elif allow_self_signed:
        self_signed_accepted = len(errors) == 0
        warnings.append("Self-signed passport accepted: no trust root was consulted")
    else:
        errors.append(
            "Authority not established: no trusted_issuers were supplied. The key a "
            "passport carries is its own claim about itself. Pass trusted_issuers, or "
            "allow_self_signed=True to accept a self-vouching passport deliberately."
        )

    valid = len(errors) == 0
    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "passport": passport if valid else None,
        "issuer_trust_checked": issuer_trust_checked,
        "self_signed_accepted": self_signed_accepted and valid,
    }


def update_passport(passport: dict, updates: dict, private_key: str) -> dict:
    """Update and re-sign a passport."""
    updated = {**passport, **updates}
    if "capabilities" in updates:
        updated["voteWeight"] = _calculate_vote_weight(updates["capabilities"])
    return sign_passport(updated, private_key)


def is_expired(passport: dict) -> bool:
    """Check if a passport has expired.

    Fail-closed: a passport whose expiresAt is present but unparseable is
    treated as expired. parse_iso_utc accepts the 'Z' form the SDK/TS reference
    emits on Python 3.9+ (bare datetime.fromisoformat only learned 'Z' in 3.11).
    """
    expires_at = passport.get("expiresAt", "")
    if not expires_at:
        return False
    try:
        return parse_iso_utc(expires_at) < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return True
