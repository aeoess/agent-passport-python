# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Canonicalization, ordering, numeric format — Python port.

Spec §2.5. Byte-identical output with the TypeScript SDK.
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, List, Union

from ...canonical import canonicalize
from .types import (
    AttributionAxes,
    ComputeAxisEntry,
    ComputeAxisItem,
    DataAxisEntry,
    DataAxisItem,
    GovernanceAxisEntry,
    ProtocolAxisEntry,
    ProtocolAxisItem,
    ResidualBucket,
)


_WEIGHT_PATTERN = re.compile(r"^\d+\.\d{6}$")
_ISO_8601_MS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def to_weight_string(value) -> str:
    """Canonical 6-digit-after-point decimal string. Accepts a number in
    [0, 1] or an already-canonical string. Raises on anything else."""
    if isinstance(value, str):
        if not _WEIGHT_PATTERN.match(value):
            raise ValueError(
                f"attribution-primitive: weight string {value!r} must match "
                r"/^\d+\.\d{6}$/ (§2.5)"
            )
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"attribution-primitive: weight must be number or string, got {type(value).__name__}")
    f = float(value)
    if f != f or f == float("inf") or f == float("-inf"):
        raise ValueError(f"attribution-primitive: weight must be finite, got {value}")
    if f < 0 or f > 1:
        raise ValueError(f"attribution-primitive: weight must be in [0, 1], got {value}")
    return f"{f:.6f}"


def assert_canonical_timestamp(ts: str) -> None:
    """Spec §2.5 — ISO-8601 UTC with millisecond precision and trailing Z."""
    if not isinstance(ts, str) or not _ISO_8601_MS.match(ts):
        raise ValueError(
            f"attribution-primitive: timestamp {ts!r} must be ISO-8601 UTC "
            "with millisecond precision and trailing Z (§2.5)"
        )


def canonical_timestamp(now: datetime = None) -> str:
    """Canonical timestamp string for 'now' or a supplied datetime."""
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    # Match TypeScript toISOString() exactly: millisecond precision, trailing Z.
    ms = now.microsecond // 1000
    s = now.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"
    assert_canonical_timestamp(s)
    return s


def _is_residual(x: Any) -> bool:
    return (
        isinstance(x, dict)
        and "residual_id" in x
        and isinstance(x["residual_id"], str)
        and x["residual_id"].startswith("residual:")
    )


def sort_data_axis(items: List[DataAxisItem]) -> List[DataAxisItem]:
    residuals = [x for x in items if _is_residual(x)]
    if len(residuals) > 1:
        raise ValueError("attribution-primitive: at most one residual bucket permitted in axis D")
    explicit = [x for x in items if not _is_residual(x)]
    explicit_sorted = sorted(explicit, key=lambda e: e["source_did"])
    return [*explicit_sorted, *residuals]


def sort_protocol_axis(items: List[ProtocolAxisItem]) -> List[ProtocolAxisItem]:
    residuals = [x for x in items if _is_residual(x)]
    if len(residuals) > 1:
        raise ValueError("attribution-primitive: at most one residual bucket permitted in axis P")
    explicit = [x for x in items if not _is_residual(x)]
    explicit_sorted = sorted(explicit, key=lambda e: f"{e['module_id']}\x00{e['module_version']}")
    return [*explicit_sorted, *residuals]


def sort_compute_axis(items: List[ComputeAxisItem]) -> List[ComputeAxisItem]:
    residuals = [x for x in items if _is_residual(x)]
    if len(residuals) > 1:
        raise ValueError("attribution-primitive: at most one residual bucket permitted in axis C")
    explicit = [x for x in items if not _is_residual(x)]
    explicit_sorted = sorted(explicit, key=lambda e: e["provider_did"])
    return [*explicit_sorted, *residuals]


def order_governance_axis(items: List[GovernanceAxisEntry]) -> List[GovernanceAxisEntry]:
    ordered = sorted(items, key=lambda e: e["depth"])
    for i in range(1, len(ordered)):
        if ordered[i]["depth"] == ordered[i - 1]["depth"]:
            raise ValueError(
                f"attribution-primitive: governance axis has duplicate depth {ordered[i]['depth']}"
            )
    return ordered


def normalize_axes(axes: AttributionAxes) -> AttributionAxes:
    return {
        "D": sort_data_axis(axes["D"]),
        "P": sort_protocol_axis(axes["P"]),
        "G": order_governance_axis(axes["G"]),
        "C": sort_compute_axis(axes["C"]),
    }


def hash_axis_leaf(axis: Any) -> bytes:
    return hashlib.sha256(canonicalize(axis).encode("utf-8")).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def canonical_hash_hex(obj: Any) -> str:
    return hashlib.sha256(canonicalize(obj).encode("utf-8")).hexdigest()


def envelope_bytes(env) -> str:
    """Canonical envelope string §2.3. Accepts TypedDict or plain dict."""
    assert_canonical_timestamp(env["timestamp"])
    return canonicalize({
        "action_ref": env["action_ref"],
        "merkle_root": env["merkle_root"],
        "issuer": env["issuer"],
        "timestamp": env["timestamp"],
    })
