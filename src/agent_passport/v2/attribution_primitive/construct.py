# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Construction — Python port of src/v2/attribution-primitive/construct.ts."""

from typing import Optional

from ...crypto import sign
from .canonical import (
    assert_canonical_timestamp,
    canonical_hash_hex,
    canonical_timestamp,
    envelope_bytes,
)
from .merkle import build_merkle_frame
from .types import AttributionAction, AttributionAxes, AttributionPrimitive


def compute_attribution_action_ref(action: AttributionAction) -> str:
    """Derive action_ref from an action tuple. §1.2 / §3.4."""
    if not action.get("agentId"):
        raise ValueError("attribution-primitive: action.agentId required")
    if not action.get("actionType"):
        raise ValueError("attribution-primitive: action.actionType required")
    if not action.get("nonce"):
        raise ValueError("attribution-primitive: action.nonce required")
    if not isinstance(action.get("params"), dict):
        raise ValueError("attribution-primitive: action.params must be an object")
    return canonical_hash_hex({
        "agentId": action["agentId"],
        "actionType": action["actionType"],
        "params": action["params"],
        "nonce": action["nonce"],
    })


def construct_attribution_primitive(
    *,
    action: AttributionAction,
    axes: AttributionAxes,
    issuer: str,
    issuer_private_key: str,
    timestamp: Optional[str] = None,
) -> AttributionPrimitive:
    """Build and sign a complete AttributionPrimitive. §2.7."""
    if not issuer:
        raise ValueError("attribution-primitive: issuer required")
    if not issuer_private_key:
        raise ValueError("attribution-primitive: issuer_private_key required")

    action_ref = compute_attribution_action_ref(action)
    frame = build_merkle_frame(axes)
    merkle_root = frame["root"].hex()
    ts = timestamp if timestamp is not None else canonical_timestamp()
    assert_canonical_timestamp(ts)

    envelope = envelope_bytes({
        "action_ref": action_ref,
        "merkle_root": merkle_root,
        "issuer": issuer,
        "timestamp": ts,
    })
    signature = sign(envelope, issuer_private_key)

    return {
        "action_ref": action_ref,
        "axes": frame["axes"],
        "merkle_root": merkle_root,
        "issuer": issuer,
        "timestamp": ts,
        "signature": signature,
    }


def resign_attribution_primitive(
    primitive: AttributionPrimitive,
    issuer_private_key: str,
    *,
    timestamp: Optional[str] = None,
    axes: Optional[AttributionAxes] = None,
    action: Optional[AttributionAction] = None,
) -> AttributionPrimitive:
    """Re-sign a primitive whose axes or metadata have changed."""
    new_axes = axes if axes is not None else primitive["axes"]
    action_ref = (
        compute_attribution_action_ref(action) if action is not None else primitive["action_ref"]
    )
    frame = build_merkle_frame(new_axes)
    merkle_root = frame["root"].hex()
    ts = timestamp if timestamp is not None else canonical_timestamp()
    assert_canonical_timestamp(ts)
    envelope = envelope_bytes({
        "action_ref": action_ref,
        "merkle_root": merkle_root,
        "issuer": primitive["issuer"],
        "timestamp": ts,
    })
    signature = sign(envelope, issuer_private_key)
    return {
        "action_ref": action_ref,
        "axes": frame["axes"],
        "merkle_root": merkle_root,
        "issuer": primitive["issuer"],
        "timestamp": ts,
        "signature": signature,
    }
