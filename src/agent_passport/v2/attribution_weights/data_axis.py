# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Compute D-axis fractional weights — Python port."""

from typing import Any, Dict, List, Sequence

from ..attribution_primitive.canonical import to_weight_string
from .length import content_length_weight
from .profile import DEFAULT_WEIGHT_PROFILE, validate_weight_profile
from .recency import recency_decay
from .roles import role_weight
from .types import DataAxisEntry, WeightProfile


def compute_data_axis_weights(
    sources: Sequence[Dict[str, Any]],
    *,
    action_timestamp: str,
    profile: WeightProfile = None,
) -> List[DataAxisEntry]:
    """Compute the normalized D-axis weight vector.

    Parity with the TS computeDataAxisWeights. Empty input → empty
    output. All-zero raw weights → ValueError. Output is a list of
    DataAxisEntry dicts with canonical 6-digit decimal weight strings
    ready to feed into construct_attribution_primitive.
    """
    if not isinstance(sources, (list, tuple)):
        raise ValueError("attribution-weights: sources must be a list")
    if len(sources) == 0:
        return []
    if not isinstance(action_timestamp, str) or not action_timestamp:
        raise ValueError("attribution-weights: action_timestamp required")

    prof = profile if profile is not None else DEFAULT_WEIGHT_PROFILE
    validation = validate_weight_profile(prof)
    if not validation["valid"]:
        raise ValueError(
            "attribution-weights: invalid profile — " + "; ".join(validation["errors"])
        )

    raws: List[float] = []
    for s in sources:
        if not isinstance(s, dict):
            raise ValueError("attribution-weights: each source must be a dict")
        r = role_weight(s["role"], prof)
        d = recency_decay(action_timestamp, s["timestamp"], prof)
        ln = content_length_weight(s["content_length"], prof)
        raws.append(r * d * ln)

    total = sum(raws)
    if not (total > 0):
        raise ValueError(
            "attribution-weights: total D-axis raw weight is zero — malformed "
            "input (every contributor has zero effective weight)"
        )

    return [
        {
            "source_did": s["source_did"],
            "contribution_weight": to_weight_string(raws[i] / total),
            "access_receipt_hash": s["access_receipt_hash"],
        }
        for i, s in enumerate(sources)
    ]
