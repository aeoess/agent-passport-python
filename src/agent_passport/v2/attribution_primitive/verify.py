# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Projection + primitive verification — Python port."""

import re

from ...crypto import verify as ed25519_verify
from .canonical import envelope_bytes, hash_axis_leaf
from .merkle import reconstruct_root
from .types import AttributionPrimitive, AttributionProjection

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_VALID_TAGS = {"D", "P", "G", "C"}


def _is_well_formed(p) -> bool:
    if not isinstance(p, dict):
        return False
    if not isinstance(p.get("action_ref"), str) or not _HEX64.match(p["action_ref"]):
        return False
    if not isinstance(p.get("merkle_root"), str) or not _HEX64.match(p["merkle_root"]):
        return False
    if not isinstance(p.get("signature"), str) or not _HEX128.match(p["signature"]):
        return False
    if not isinstance(p.get("issuer"), str) or not p["issuer"]:
        return False
    if not isinstance(p.get("timestamp"), str) or not p["timestamp"]:
        return False
    path = p.get("merkle_path")
    if not isinstance(path, (list, tuple)) or len(path) != 2:
        return False
    for h in path:
        if not isinstance(h, str) or not _HEX64.match(h):
            return False
    return True


def verify_attribution_projection(projection: AttributionProjection, issuer_public_key_hex: str) -> dict:
    """Spec §2.3. Returns {'valid': True} or {'valid': False, 'reason': ...}."""
    if not _is_well_formed(projection):
        return {"valid": False, "reason": "MALFORMED"}
    if projection["axis_tag"] not in _VALID_TAGS:
        return {"valid": False, "reason": "INVALID_AXIS_TAG"}

    axis_leaf = hash_axis_leaf(projection["axis_data"])
    try:
        computed = reconstruct_root(axis_leaf, projection["merkle_path"], projection["axis_tag"])
    except Exception:
        return {"valid": False, "reason": "MALFORMED"}
    if computed.hex() != projection["merkle_root"].lower():
        return {"valid": False, "reason": "MERKLE_MISMATCH"}

    envelope = envelope_bytes({
        "action_ref": projection["action_ref"],
        "merkle_root": projection["merkle_root"],
        "issuer": projection["issuer"],
        "timestamp": projection["timestamp"],
    })
    try:
        ok = ed25519_verify(envelope, projection["signature"], issuer_public_key_hex)
    except Exception:
        ok = False
    if not ok:
        return {"valid": False, "reason": "SIGNATURE_INVALID"}
    return {"valid": True}


def verify_attribution_primitive(primitive: AttributionPrimitive, issuer_public_key_hex: str) -> dict:
    """Verify all four axis projections under one issuer key."""
    # Local import to avoid circular import at module load.
    from .project import project_attribution
    for tag in ("D", "P", "G", "C"):
        proj = project_attribution(primitive, tag)
        res = verify_attribution_projection(proj, issuer_public_key_hex)
        if not res.get("valid"):
            return res
    return {"valid": True}


def check_projection_consistency(p1: AttributionProjection, p2: AttributionProjection) -> dict:
    """Spec §2.4."""
    if p1["action_ref"] != p2["action_ref"]:
        return {"same_receipt": False, "reason": "DIFFERENT_ACTIONS"}
    if p1["merkle_root"] != p2["merkle_root"]:
        return {"same_receipt": False, "reason": "DIFFERENT_RECEIPTS"}
    if p1["signature"] != p2["signature"]:
        return {"same_receipt": False, "reason": "DIFFERENT_SIGNATURES"}
    if p1["issuer"] != p2["issuer"] or p1["timestamp"] != p2["timestamp"]:
        return {"same_receipt": False, "reason": "METADATA_MISMATCH"}
    return {"same_receipt": True}
