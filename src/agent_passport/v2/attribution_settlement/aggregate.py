# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Settlement aggregation — Python port of
src/v2/attribution-settlement/aggregate.ts.

Half-open [t0, t1); per-axis weight sourcing matches the TS file's
header comment verbatim. See that file for the design notes.
"""

import hashlib
import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ...canonical import canonicalize
from ..attribution_primitive.canonical import assert_canonical_timestamp
from .merkle import build_merkle_root, empty_axis_merkle_root, leaf_hash
from .types import (
    SettlementAxisIndex,
    SettlementContributor,
    SettlementPeriod,
    SettlementRecord,
    SettlementResidualBucket,
)


def _is_residual(x) -> bool:
    return (
        isinstance(x, dict)
        and isinstance(x.get("residual_id"), str)
        and x["residual_id"].startswith("residual:")
    )


def _weight_number(w: str) -> float:
    try:
        n = float(w)
    except (TypeError, ValueError):
        raise ValueError(f"attribution-settlement: invalid weight string {w!r}")
    if not math.isfinite(n):
        raise ValueError(f"attribution-settlement: weight must be finite, got {w!r}")
    return n


def format_settlement_weight(v: float) -> str:
    """6-digit decimal form for settlement weights (can exceed 1.0)."""
    if not math.isfinite(v):
        raise ValueError(f"attribution-settlement: weight must be finite, got {v}")
    if v < 0:
        raise ValueError(f"attribution-settlement: weight must be non-negative, got {v}")
    return f"{v:.6f}"


def contributor_leaf_hash_hex(c) -> str:
    body = {
        "contributor_did": c["contributor_did"],
        "total_weight": c["total_weight"],
        "contribution_count": c["contribution_count"],
    }
    return hashlib.sha256(canonicalize(body).encode("utf-8")).hexdigest()


def residual_leaf_hash_hex(r) -> str:
    return hashlib.sha256(canonicalize(r).encode("utf-8")).hexdigest()


class _AxisAccum:
    __slots__ = (
        "map",
        "pooled_weight",
        "pooled_member_count",
        "per_receipt_residual_hashes",
        "total_actions",
    )

    def __init__(self):
        self.map: Dict[str, Dict[str, float]] = {}
        self.pooled_weight = 0.0
        self.pooled_member_count = 0
        self.per_receipt_residual_hashes: List[str] = []
        self.total_actions = 0


def _add_contributor(accum: _AxisAccum, did: str, weight: float) -> None:
    cur = accum.map.get(did)
    if cur:
        cur["total"] += weight
        cur["count"] += 1
    else:
        accum.map[did] = {"total": weight, "count": 1}


def _accumulate_residual(accum: _AxisAccum, bucket) -> None:
    accum.pooled_weight += _weight_number(bucket["total_pooled_weight"])
    accum.pooled_member_count += bucket["count_of_pooled_contributors"]
    accum.per_receipt_residual_hashes.append(bucket["pooled_contributors_hash"])


def _pooled_weight_of_receipt(residuals) -> float:
    return sum(_weight_number(r["total_pooled_weight"]) for r in residuals)


def _process_data_axis(items, accum: _AxisAccum) -> None:
    if not items:
        return
    accum.total_actions += 1
    for item in items:
        if _is_residual(item):
            _accumulate_residual(accum, item)
        else:
            _add_contributor(accum, item["source_did"], _weight_number(item["contribution_weight"]))


def _process_compute_axis(items, accum: _AxisAccum) -> None:
    if not items:
        return
    accum.total_actions += 1
    for item in items:
        if _is_residual(item):
            _accumulate_residual(accum, item)
        else:
            _add_contributor(accum, item["provider_did"], _weight_number(item["compute_share"]))


def _protocol_entry_did(e) -> str:
    return f"{e['module_id']}@{e['module_version']}"


def _process_protocol_axis(items, accum: _AxisAccum) -> None:
    if not items:
        return
    accum.total_actions += 1
    explicit = [x for x in items if not _is_residual(x)]
    residuals = [x for x in items if _is_residual(x)]
    for r in residuals:
        _accumulate_residual(accum, r)

    any_weighted = any(e.get("weight") is not None for e in explicit)
    if any_weighted:
        for e in explicit:
            if e.get("weight") is None:
                continue
            _add_contributor(accum, _protocol_entry_did(e), _weight_number(e["weight"]))
    elif explicit:
        budget = max(0.0, 1.0 - _pooled_weight_of_receipt(residuals))
        w = budget / len(explicit)
        for e in explicit:
            _add_contributor(accum, _protocol_entry_did(e), w)


def _process_governance_axis(items, accum: _AxisAccum) -> None:
    if not items:
        return
    accum.total_actions += 1
    w = 1.0 / len(items)
    for e in items:
        _add_contributor(accum, e["signer_did"], w)


def _finalize_axis(axis: str, accum: _AxisAccum, period: SettlementPeriod) -> SettlementAxisIndex:
    dids = sorted(accum.map.keys())
    contributors: List[SettlementContributor] = []
    for did in dids:
        slot = accum.map[did]
        total_str = format_settlement_weight(slot["total"])
        leaf_body = {
            "contributor_did": did,
            "total_weight": total_str,
            "contribution_count": slot["count"],
        }
        merkle_leaf_hash = hashlib.sha256(canonicalize(leaf_body).encode("utf-8")).hexdigest()
        contributors.append({
            "contributor_did": did,
            "total_weight": total_str,
            "contribution_count": slot["count"],
            "merkle_leaf_hash": merkle_leaf_hash,
        })

    residual_bucket: Optional[SettlementResidualBucket] = None
    if accum.pooled_member_count > 0 or accum.per_receipt_residual_hashes:
        if axis == "G":
            raise ValueError("attribution-settlement: governance axis cannot carry a residual bucket")
        sorted_hashes = sorted(accum.per_receipt_residual_hashes)
        pooled_contributors_hash = hashlib.sha256(
            canonicalize(sorted_hashes).encode("utf-8")
        ).hexdigest()
        residual_bucket = {
            "residual_id": f"residual:{axis}",  # type: ignore[typeddict-item]
            "total_pooled_weight": format_settlement_weight(accum.pooled_weight),
            "count_of_pooled_contributors": accum.pooled_member_count,
            "pooled_contributors_hash": pooled_contributors_hash,
        }

    leaves = [bytes.fromhex(c["merkle_leaf_hash"]) for c in contributors]
    if residual_bucket:
        leaves.append(bytes.fromhex(residual_leaf_hash_hex(residual_bucket)))
    axis_merkle_root = (
        empty_axis_merkle_root() if not leaves else build_merkle_root(leaves).hex()
    )
    return {
        "axis": axis,  # type: ignore[typeddict-item]
        "period": period,
        "total_actions": accum.total_actions,
        "contributors": contributors,
        "residual_bucket": residual_bucket,
        "axis_merkle_root": axis_merkle_root,
    }


def _assert_period(period: SettlementPeriod) -> None:
    if not isinstance(period, dict):
        raise ValueError("attribution-settlement: period required")
    assert_canonical_timestamp(period["t0"])
    assert_canonical_timestamp(period["t1"])
    if _parse_ms(period["t0"]) >= _parse_ms(period["t1"]):
        raise ValueError("attribution-settlement: period.t0 must be strictly before period.t1")
    pid = period.get("period_id")
    if not isinstance(pid, str) or len(pid) == 0:
        raise ValueError("attribution-settlement: period.period_id required")


def _parse_ms(ts: str) -> int:
    # The canonical timestamp regex guarantees shape; fromisoformat does
    # not accept the trailing Z before Python 3.11, so we strip it.
    trimmed = ts[:-1] if ts.endswith("Z") else ts
    dt = datetime.fromisoformat(trimmed).replace(tzinfo=timezone.utc)
    # .timestamp() already includes microseconds; round to integer ms.
    return round(dt.timestamp() * 1000)


def _now_iso_ms() -> str:
    now = datetime.now(timezone.utc)
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def aggregate_attribution_primitives(
    receipts,
    period: SettlementPeriod,
    *,
    gateway_did: str,
    issued_at: Optional[str] = None,
    skip_out_of_period: bool = True,
) -> dict:
    """Compute the unsigned settlement record. Half-open [t0, t1)."""
    if not isinstance(receipts, list):
        raise ValueError("attribution-settlement: receipts must be a list")
    if not isinstance(gateway_did, str) or not gateway_did:
        raise ValueError("attribution-settlement: gateway_did required")
    _assert_period(period)

    t0 = _parse_ms(period["t0"])
    t1 = _parse_ms(period["t1"])

    accums = {
        "D": _AxisAccum(),
        "P": _AxisAccum(),
        "G": _AxisAccum(),
        "C": _AxisAccum(),
    }

    in_period = []
    for r in receipts:
        assert_canonical_timestamp(r["timestamp"])
        ts = _parse_ms(r["timestamp"])
        if ts < t0 or ts >= t1:
            if not skip_out_of_period:
                raise ValueError(
                    f"attribution-settlement: receipt {r['action_ref']} timestamp "
                    f"{r['timestamp']} outside period [{period['t0']}, {period['t1']})"
                )
            continue
        in_period.append(r)

    for r in in_period:
        _process_data_axis(r["axes"]["D"], accums["D"])
        _process_protocol_axis(r["axes"]["P"], accums["P"])
        _process_governance_axis(r["axes"]["G"], accums["G"])
        _process_compute_axis(r["axes"]["C"], accums["C"])

    # Distinct period dict per axis — mirrors the TS workaround for the
    # shared-reference cycle check in canonicalize().
    def clone_period() -> SettlementPeriod:
        return {"t0": period["t0"], "t1": period["t1"], "period_id": period["period_id"]}

    axes = {
        "D": _finalize_axis("D", accums["D"], clone_period()),
        "P": _finalize_axis("P", accums["P"], clone_period()),
        "G": _finalize_axis("G", accums["G"], clone_period()),
        "C": _finalize_axis("C", accums["C"], clone_period()),
    }

    sorted_refs = sorted(r["action_ref"] for r in in_period)
    ref_leaves = [leaf_hash(ref) for ref in sorted_refs]
    input_receipts_hash = (
        empty_axis_merkle_root() if not ref_leaves else build_merkle_root(ref_leaves).hex()
    )

    issued = issued_at if issued_at is not None else _now_iso_ms()
    assert_canonical_timestamp(issued)

    return {
        "schema": "aps.settlement.v1",
        "period": period,
        "gateway_did": gateway_did,
        "axes": axes,
        "input_receipts_hash": input_receipts_hash,
        "total_input_count": len(in_period),
        "issued_at": issued,
    }
