# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Role weight lookup — Python port."""

from .types import AttributionRole, WeightProfile


def role_weight(role: AttributionRole, profile: WeightProfile) -> float:
    w = profile["role_weights"].get(role)
    if not isinstance(w, (int, float)) or isinstance(w, bool) or w != w or w == float("inf") or w == float("-inf") or w < 0:
        raise ValueError(
            f"attribution-weights: role {role!r} has invalid weight in profile "
            "(must be non-negative finite number)"
        )
    return float(w)
