# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Projections — Python port of src/v2/attribution-primitive/project.ts."""

from .canonical import normalize_axes
from .merkle import build_merkle_frame, projection_path
from .types import AttributionPrimitive, AttributionProjection


def _select(axes, axis):
    return axes[axis]


def project_attribution(primitive: AttributionPrimitive, axis: str) -> AttributionProjection:
    if axis not in ("D", "P", "G", "C"):
        raise ValueError(f"attribution-primitive: invalid axis tag {axis!r}")
    normalized = normalize_axes(primitive["axes"])
    frame = build_merkle_frame(normalized)
    path = projection_path(frame, axis)
    return {
        "action_ref": primitive["action_ref"],
        "axis_tag": axis,
        "axis_data": _select(frame["axes"], axis),
        "merkle_path": list(path),
        "merkle_root": primitive["merkle_root"],
        "issuer": primitive["issuer"],
        "timestamp": primitive["timestamp"],
        "signature": primitive["signature"],
    }


def project_all_axes(primitive: AttributionPrimitive):
    return {
        axis: project_attribution(primitive, axis) for axis in ("D", "P", "G", "C")
    }
