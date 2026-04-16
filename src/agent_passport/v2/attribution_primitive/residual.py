# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Residual aggregation §4.1 — Python port."""

import hashlib
from typing import List

from ...canonical import canonicalize
from .canonical import to_weight_string
from .types import (
    ComputeAxisEntry,
    ComputeAxisItem,
    DataAxisEntry,
    DataAxisItem,
    ProtocolAxisEntry,
    ProtocolAxisItem,
    ResidualBucket,
)

DEFAULT_MIN_WEIGHT = 0.001


def _is_residual(x) -> bool:
    return (
        isinstance(x, dict)
        and isinstance(x.get("residual_id"), str)
        and x["residual_id"].startswith("residual:")
    )


def _pooled_hash(entries) -> str:
    sorted_entries = sorted(entries, key=lambda e: e["did"])
    return hashlib.sha256(canonicalize(sorted_entries).encode("utf-8")).hexdigest()


def aggregate_data_axis(entries: List[DataAxisItem], *, min_weight: float = DEFAULT_MIN_WEIGHT) -> dict:
    retained: List[DataAxisItem] = []
    pooled = []
    total = 0.0
    for e in entries:
        if _is_residual(e):
            retained.append(e)
            continue
        canonical_weight = to_weight_string(e["contribution_weight"])
        w = float(canonical_weight)
        if w < min_weight:
            pooled.append({"did": e["source_did"], "weight": canonical_weight})
            total += w
        else:
            retained.append({**e, "contribution_weight": canonical_weight})
    if not pooled:
        return {"retained": retained, "residual": None, "pooled_count": 0}
    residual: ResidualBucket = {
        "residual_id": "residual:D",
        "total_pooled_weight": to_weight_string(total),
        "count_of_pooled_contributors": len(pooled),
        "pooled_contributors_hash": _pooled_hash(pooled),
    }
    return {"retained": retained, "residual": residual, "pooled_count": len(pooled)}


def aggregate_protocol_axis(entries: List[ProtocolAxisItem], *, min_weight: float = DEFAULT_MIN_WEIGHT) -> dict:
    retained: List[ProtocolAxisItem] = []
    pooled = []
    total = 0.0
    for e in entries:
        if _is_residual(e):
            retained.append(e)
            continue
        if e.get("weight") is None:
            retained.append(e)
            continue
        canonical_weight = to_weight_string(e["weight"])
        w = float(canonical_weight)
        if w < min_weight:
            pooled.append({"did": f"{e['module_id']}@{e['module_version']}", "weight": canonical_weight})
            total += w
        else:
            retained.append({**e, "weight": canonical_weight})
    if not pooled:
        return {"retained": retained, "residual": None, "pooled_count": 0}
    residual: ResidualBucket = {
        "residual_id": "residual:P",
        "total_pooled_weight": to_weight_string(total),
        "count_of_pooled_contributors": len(pooled),
        "pooled_contributors_hash": _pooled_hash(pooled),
    }
    return {"retained": retained, "residual": residual, "pooled_count": len(pooled)}


def aggregate_compute_axis(entries: List[ComputeAxisItem], *, min_weight: float = DEFAULT_MIN_WEIGHT) -> dict:
    retained: List[ComputeAxisItem] = []
    pooled = []
    total = 0.0
    for e in entries:
        if _is_residual(e):
            retained.append(e)
            continue
        canonical_weight = to_weight_string(e["compute_share"])
        w = float(canonical_weight)
        if w < min_weight:
            pooled.append({"did": e["provider_did"], "weight": canonical_weight})
            total += w
        else:
            retained.append({**e, "compute_share": canonical_weight})
    if not pooled:
        return {"retained": retained, "residual": None, "pooled_count": 0}
    residual: ResidualBucket = {
        "residual_id": "residual:C",
        "total_pooled_weight": to_weight_string(total),
        "count_of_pooled_contributors": len(pooled),
        "pooled_contributors_hash": _pooled_hash(pooled),
    }
    return {"retained": retained, "residual": residual, "pooled_count": len(pooled)}
