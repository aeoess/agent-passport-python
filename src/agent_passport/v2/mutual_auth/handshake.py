# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Handshake primitives. Mirrors src/v2/mutual-auth/handshake.ts.

Four-step flow:
  1. Initiator sends MutualAuthHello (nonce_i, supp_versions)
  2. Responder replies with MutualAuthAttest (chosen_version, nonce_r,
     nonce_i, own cert, sig committing to all four).
  3. Initiator verifies, produces its own Attest with nonces swapped.
  4. Responder verifies. Both sides derive the same session_id.
"""

import base64
import hashlib
import os
from typing import List, Optional

from ...canonical import canonicalize_jcs
from ...crypto import sign as ed_sign, verify as ed_verify
from .certificate import (
    certificate_id,
    check_anchor,
    is_certificate_temporally_valid,
    verify_certificate_signature,
)
from .types import (
    MutualAuthAttest,
    MutualAuthCertificate,
    MutualAuthHello,
    MutualAuthPolicy,
    MutualAuthSession,
    TrustAnchor,
)


SPEC_VERSION = "1.0"


def new_nonce() -> str:
    """128-bit random nonce, base64-encoded."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


def build_hello(
    role: str,
    supported_versions: List[str],
    now_ms: int,
    nonce_b64: Optional[str] = None,
) -> MutualAuthHello:
    return {
        "spec_version": SPEC_VERSION,
        "role": role,
        "supported_versions": supported_versions,
        "nonce_b64": nonce_b64 or new_nonce(),
        "timestamp": now_ms,
    }


def choose_version(
    peer_supported: List[str], own_accepted: List[str]
) -> Optional[str]:
    """Return the highest mutually supported version, or None."""
    for v in own_accepted:
        if v in peer_supported:
            return v
    return None


def build_attest(
    role: str,
    chosen_version: str,
    own_nonce_b64: str,
    peer_nonce_b64: str,
    certificate: MutualAuthCertificate,
    now_ms: int,
    own_sk_hex: str,
) -> MutualAuthAttest:
    unsigned = {
        "spec_version": SPEC_VERSION,
        "role": role,
        "chosen_version": chosen_version,
        "own_nonce_b64": own_nonce_b64,
        "peer_nonce_b64": peer_nonce_b64,
        "certificate": certificate,
        "timestamp": now_ms,
    }
    canonical = canonicalize_jcs(unsigned)
    sig_hex = ed_sign(canonical, own_sk_hex)
    sig_b64 = base64.b64encode(bytes.fromhex(sig_hex)).decode("ascii")
    signed = dict(unsigned)
    signed["signature_b64"] = sig_b64
    return signed


def verify_attest(
    attest: MutualAuthAttest,
    expected_peer_nonce_b64: str,
    expected_own_nonce_b64: str,
    policy: MutualAuthPolicy,
    trust_anchors: List[TrustAnchor],
    now_ms: int,
    revoked_anchor_ids: Optional[List[str]] = None,
) -> dict:
    """Run all 10 verification checks. Returns {"ok": bool, "reason"?, "detail"?}."""
    accepted = policy.get("accepted_versions") or []
    skew = policy.get("max_clock_skew_ms") or 0

    # 1. Version negotiated must be one we accept
    if attest["chosen_version"] not in accepted:
        return {"ok": False, "reason": "version_unsupported"}

    # 2. Nonces must match what we expect
    if attest["peer_nonce_b64"] != expected_peer_nonce_b64:
        return {"ok": False, "reason": "nonce_mismatch", "detail": "peer_nonce"}
    if attest["own_nonce_b64"] != expected_own_nonce_b64:
        return {"ok": False, "reason": "nonce_mismatch", "detail": "own_nonce"}

    # 3. Timestamp must be within clock skew (min 60s)
    if abs(now_ms - attest["timestamp"]) > max(skew, 60_000):
        return {"ok": False, "reason": "replay_detected", "detail": "timestamp_skew"}

    # 4. Certificate temporal validity
    cert = attest["certificate"]
    temporal = is_certificate_temporally_valid(cert, now_ms, skew)
    if not temporal["ok"]:
        if temporal["reason"] == "expired":
            return {"ok": False, "reason": "expired_certificate"}
        elif temporal["reason"] == "not_yet_valid":
            return {"ok": False, "reason": "not_yet_valid_certificate"}
        return {"ok": False, "reason": "signature_invalid"}

    # 5. Certificate signature
    cert_sig = verify_certificate_signature(cert)
    if not cert_sig["ok"]:
        return {"ok": False, "reason": "signature_invalid", "detail": "certificate"}

    # 6. Trust anchor check
    anchor = check_anchor(cert, trust_anchors, revoked_anchor_ids)
    if not anchor["ok"]:
        reason_map = {
            "unknown_issuer": "unknown_issuer",
            "revoked_anchor": "revoked_anchor",
            "binding_mismatch": "binding_mismatch",
        }
        return {"ok": False, "reason": reason_map.get(anchor["reason"], "signature_invalid")}

    # 7. Downgrade detection
    peer_supported = cert.get("supported_versions", [])
    expected_choice = choose_version(peer_supported, accepted)
    if expected_choice is not None and expected_choice != attest["chosen_version"]:
        return {"ok": False, "reason": "downgrade_detected"}

    # 8. Agent grade (only if peer is an agent)
    min_grade = policy.get("min_agent_grade")
    if cert.get("role") == "agent" and min_grade is not None:
        grade = cert.get("attestation_grade") or 0
        if grade < min_grade:
            return {"ok": False, "reason": "grade_insufficient"}

    # 9. Required capabilities
    required = policy.get("required_capabilities") or []
    if required:
        caps = cert.get("capabilities") or []
        for req in required:
            if req not in caps:
                return {
                    "ok": False,
                    "reason": "binding_mismatch",
                    "detail": f"missing_capability:{req}",
                }

    # 10. Attest signature (commits to version + nonces + cert)
    rest = {k: v for k, v in attest.items() if k != "signature_b64"}
    canonical = canonicalize_jcs(rest)
    try:
        sig_hex = base64.b64decode(attest["signature_b64"]).hex()
    except Exception:
        return {"ok": False, "reason": "signature_invalid", "detail": "attest"}
    sig_ok = ed_verify(canonical, sig_hex, cert["subject_pubkey_hex"])
    if not sig_ok:
        return {"ok": False, "reason": "signature_invalid", "detail": "attest"}

    return {"ok": True}


def derive_session(
    agent_attest: MutualAuthAttest,
    is_attest: MutualAuthAttest,
    policy: MutualAuthPolicy,
    now_ms: int,
) -> dict:
    """Derive shared session record. Both sides compute identical session_id."""
    if agent_attest["chosen_version"] != is_attest["chosen_version"]:
        return {"ok": False, "failure": {"reason": "downgrade_detected"}}
    if agent_attest["certificate"].get("role") != "agent":
        return {
            "ok": False,
            "failure": {"reason": "binding_mismatch", "detail": "agent_attest_role"},
        }
    if is_attest["certificate"].get("role") != "information_system":
        return {
            "ok": False,
            "failure": {"reason": "binding_mismatch", "detail": "is_attest_role"},
        }

    agent_cert_id = certificate_id(agent_attest["certificate"])
    is_cert_id = certificate_id(is_attest["certificate"])

    material = canonicalize_jcs({
        "spec_version": SPEC_VERSION,
        "chosen_version": agent_attest["chosen_version"],
        "agent_cert_id": agent_cert_id,
        "is_cert_id": is_cert_id,
        "agent_nonce_b64": agent_attest["own_nonce_b64"],
        "is_nonce_b64": is_attest["own_nonce_b64"],
    })
    session_id = "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    max_session = policy.get("max_session_ms")
    if max_session is None:
        max_session = min(
            agent_attest["certificate"]["not_after"],
            is_attest["certificate"]["not_after"],
        ) - now_ms

    session: MutualAuthSession = {
        "spec_version": SPEC_VERSION,
        "session_id": session_id,
        "agent_cert": agent_attest["certificate"],
        "is_cert": is_attest["certificate"],
        "chosen_version": agent_attest["chosen_version"],
        "agent_nonce_b64": agent_attest["own_nonce_b64"],
        "is_nonce_b64": is_attest["own_nonce_b64"],
        "established_at": now_ms,
        "expires_at": now_ms + max(0, max_session),
    }

    if session["expires_at"] <= session["established_at"]:
        return {"ok": False, "failure": {"reason": "expired_session"}}

    return {"ok": True, "session": session}


def is_session_active(session: MutualAuthSession, now_ms: int) -> bool:
    return (
        session["established_at"] <= now_ms <= session["expires_at"]
        and now_ms <= session["agent_cert"]["not_after"]
        and now_ms <= session["is_cert"]["not_after"]
    )
