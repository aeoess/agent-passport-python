# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Compute C-axis fractional weights — Python port."""

import math
from typing import Any, Dict, List, Sequence

from ..attribution_primitive.canonical import to_weight_string
from .profile import DEFAULT_WEIGHT_PROFILE, validate_weight_profile
from .types import ComputeAxisEntry, WeightProfile


def _nonneg_finite(v: Any) -> bool:
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and not (isinstance(v, float) and (math.isnan(v) or math.isinf(v)))
        and v >= 0
    )


def compute_compute_axis_weights(
    providers: Sequence[Dict[str, Any]],
    *,
    profile: WeightProfile = None,
) -> List[ComputeAxisEntry]:
    """Compute the normalized C-axis weight vector. Parity with TS."""
    if not isinstance(providers, (list, tuple)):
        raise ValueError("attribution-weights: providers must be a list")
    if len(providers) == 0:
        return []

    prof = profile if profile is not None else DEFAULT_WEIGHT_PROFILE
    validation = validate_weight_profile(prof)
    if not validation["valid"]:
        raise ValueError(
            "attribution-weights: invalid profile — " + "; ".join(validation["errors"])
        )
    mult = float(prof["compute"]["completion_multiplier"])

    raws: List[float] = []
    for p in providers:
        if not isinstance(p, dict):
            raise ValueError("attribution-weights: each provider must be a dict")
        prompt = p.get("prompt_tokens")
        completion = p.get("completion_tokens")
        if not _nonneg_finite(prompt):
            raise ValueError(
                f"attribution-weights: prompt_tokens must be non-negative finite, got {prompt!r}"
            )
        if not _nonneg_finite(completion):
            raise ValueError(
                f"attribution-weights: completion_tokens must be non-negative finite, got {completion!r}"
            )
        raws.append(prompt + completion * mult)

    total = sum(raws)
    if not (total > 0):
        raise ValueError(
            "attribution-weights: total C-axis raw weight is zero — malformed "
            "input (all providers have zero tokens)"
        )

    return [
        {
            "provider_did": p["provider_did"],
            "compute_share": to_weight_string(raws[i] / total),
            "hardware_attestation_hash": p["hardware_attestation_hash"],
        }
        for i, p in enumerate(providers)
    ]
