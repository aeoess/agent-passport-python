# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Trust anchor bundle build, sign, verify. Mirrors src/v2/mutual-auth/trust-bundle.ts."""

import base64
from typing import List, Optional

from ...canonical import canonicalize_jcs
from ...crypto import sign as ed_sign, verify as ed_verify
from .types import TrustAnchorBundle, TrustAnchor


SPEC_VERSION = "1.0"


def build_bundle(
    bundle_id: str,
    anchors: List[TrustAnchor],
    issued_at: int,
    refresh_after: int,
    publisher_pubkey_hex: str,
    revoked_anchors: Optional[List[str]] = None,
) -> dict:
    """Build an unsigned bundle."""
    return {
        "spec_version": SPEC_VERSION,
        "bundle_id": bundle_id,
        "issued_at": issued_at,
        "anchors": anchors,
        "refresh_after": refresh_after,
        "revoked_anchors": revoked_anchors,
        "publisher_pubkey_hex": publisher_pubkey_hex,
    }


def sign_bundle(unsigned: dict, publisher_sk_hex: str) -> TrustAnchorBundle:
    canonical = canonicalize_jcs(unsigned)
    sig_hex = ed_sign(canonical, publisher_sk_hex)
    sig_b64 = base64.b64encode(bytes.fromhex(sig_hex)).decode("ascii")
    signed = dict(unsigned)
    signed["signature_b64"] = sig_b64
    return signed


def verify_bundle(
    bundle: TrustAnchorBundle,
    trusted_publisher_pubkeys_hex: List[str],
    now_ms: int,
) -> dict:
    """Verify bundle signature + freshness + publisher whitelist."""
    if bundle.get("publisher_pubkey_hex") not in trusted_publisher_pubkeys_hex:
        return {"ok": False, "reason": "untrusted_publisher"}
    rest = {k: v for k, v in bundle.items() if k != "signature_b64"}
    canonical = canonicalize_jcs(rest)
    sig_b64 = bundle.get("signature_b64", "")
    try:
        sig_hex = base64.b64decode(sig_b64).hex()
    except Exception:
        return {"ok": False, "reason": "signature_invalid"}
    ok = ed_verify(canonical, sig_hex, bundle["publisher_pubkey_hex"])
    if not ok:
        return {"ok": False, "reason": "signature_invalid"}
    if now_ms < bundle["issued_at"]:
        return {"ok": False, "reason": "not_yet_valid"}
    if now_ms > bundle["refresh_after"]:
        return {"ok": False, "reason": "bundle_expired"}
    return {"ok": True}
