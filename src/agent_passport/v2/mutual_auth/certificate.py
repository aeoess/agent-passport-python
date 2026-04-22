# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Certificate build, sign, verify. Mirrors src/v2/mutual-auth/certificate.ts."""

import base64
import hashlib
from typing import Optional, List

from ...canonical import canonicalize_jcs
from ...crypto import sign as ed_sign, verify as ed_verify
from .types import MutualAuthCertificate, TrustAnchor


SPEC_VERSION = "1.0"


def build_certificate(
    role: str,
    subject_id: str,
    subject_pubkey_hex: str,
    issuer_id: str,
    issuer_role: str,
    issuer_pubkey_hex: str,
    binding: str,
    not_before: int,
    not_after: int,
    supported_versions: List[str],
    attestation_grade: Optional[int] = None,
    capabilities: Optional[List[str]] = None,
) -> dict:
    """Build an unsigned certificate. Call sign_certificate next.

    Returns the unsigned dict with the exact field layout the TypeScript
    SDK produces, so cross-language signatures match.
    """
    cert = {
        "spec_version": SPEC_VERSION,
        "role": role,
        "subject_id": subject_id,
        "issuer_id": issuer_id,
        "issuer_role": issuer_role,
        "issuer_pubkey_hex": issuer_pubkey_hex,
        "subject_pubkey_hex": subject_pubkey_hex,
        "not_before": not_before,
        "not_after": not_after,
        "binding": binding,
        "attestation_grade": attestation_grade,
        "supported_versions": supported_versions,
        "capabilities": capabilities,
    }
    return cert


def sign_certificate(unsigned: dict, issuer_sk_hex: str) -> MutualAuthCertificate:
    """Sign an unsigned certificate. Signature is Ed25519 over JCS canonical form."""
    canonical = canonicalize_jcs(unsigned)
    sig_hex = ed_sign(canonical, issuer_sk_hex)
    sig_b64 = base64.b64encode(bytes.fromhex(sig_hex)).decode("ascii")
    signed = dict(unsigned)
    signed["signature_b64"] = sig_b64
    return signed


def certificate_id(cert: MutualAuthCertificate) -> str:
    """Stable content-hash id for a certificate. Excludes signature."""
    rest = {k: v for k, v in cert.items() if k != "signature_b64"}
    canonical = canonicalize_jcs(rest).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def verify_certificate_signature(cert: MutualAuthCertificate) -> dict:
    """Verify only the certificate's own signature. Returns {"ok": bool, "reason"?: str}."""
    if not cert.get("supported_versions"):
        return {"ok": False, "reason": "version_empty"}
    rest = {k: v for k, v in cert.items() if k != "signature_b64"}
    canonical = canonicalize_jcs(rest)
    sig_b64 = cert.get("signature_b64", "")
    try:
        sig_hex = base64.b64decode(sig_b64).hex()
    except Exception:
        return {"ok": False, "reason": "signature_invalid"}
    ok = ed_verify(canonical, sig_hex, cert["issuer_pubkey_hex"])
    if not ok:
        return {"ok": False, "reason": "signature_invalid"}
    return {"ok": True}


def is_certificate_temporally_valid(
    cert: MutualAuthCertificate,
    now_ms: int,
    max_clock_skew_ms: int = 0,
) -> dict:
    """Check cert is within its validity window with optional skew tolerance."""
    if now_ms + max_clock_skew_ms < cert["not_before"]:
        return {"ok": False, "reason": "not_yet_valid"}
    if now_ms - max_clock_skew_ms > cert["not_after"]:
        return {"ok": False, "reason": "expired"}
    return {"ok": True}


def _match_binding(pattern: str, binding: str) -> bool:
    if pattern == binding:
        return True
    if pattern.endswith("*"):
        return binding.startswith(pattern[:-1])
    return False


def check_anchor(
    cert: MutualAuthCertificate,
    anchors: List[TrustAnchor],
    revoked_anchor_ids: Optional[List[str]] = None,
) -> dict:
    """Determine if the certificate was issued by a trusted anchor and whether
    the anchor's binding constraints (if any) permit this cert's binding."""
    revoked = revoked_anchor_ids or []
    anchor = next(
        (a for a in anchors if a.get("pubkey_hex") == cert.get("issuer_pubkey_hex")),
        None,
    )
    if anchor is None:
        return {"ok": False, "reason": "unknown_issuer"}
    if anchor["anchor_id"] in revoked:
        return {"ok": False, "reason": "revoked_anchor", "anchor": anchor}
    constraints = anchor.get("binding_constraints")
    if constraints:
        matched = any(_match_binding(p, cert["binding"]) for p in constraints)
        if not matched:
            return {"ok": False, "reason": "binding_mismatch", "anchor": anchor}
    return {"ok": True, "anchor": anchor}
