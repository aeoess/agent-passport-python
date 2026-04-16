# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Recency decay — Python port.

recency_decay(t) = max(MIN_RECENCY, exp(-lambda * (t_action - t_source) / tau))
"""

import math
from datetime import datetime, timezone

from .types import WeightProfile

_MS_PER_DAY = 86_400_000


def _parse_iso_ms(ts: str) -> float:
    """Parse an ISO-8601 string to an epoch-millisecond float. Accepts
    strings with a trailing Z or an explicit +00:00 offset."""
    if not isinstance(ts, str) or not ts:
        raise ValueError(f"attribution-weights: invalid timestamp {ts!r}")
    try:
        # datetime.fromisoformat accepts offsets but rejects trailing Z
        # until Python 3.11. Normalize to +00:00 for wider compatibility.
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(normalized)
    except ValueError as e:
        raise ValueError(f"attribution-weights: invalid timestamp {ts!r} ({e})") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp() * 1000.0


def recency_decay(t_action: str, t_source: str, profile: WeightProfile) -> float:
    action_ms = _parse_iso_ms(t_action)
    source_ms = _parse_iso_ms(t_source)
    age_days = max(0.0, (action_ms - source_ms) / _MS_PER_DAY)
    recency = profile["recency"]
    min_recency = float(recency["min_recency"])
    # Accept both "lambda" (JSON wire) and "lambda_" (TypedDict-safe key).
    lam = recency.get("lambda", recency.get("lambda_"))
    if lam is None:
        raise ValueError("attribution-weights: profile.recency.lambda missing")
    lam = float(lam)
    tau_days = float(recency["tau_days"])
    if tau_days <= 0:
        raise ValueError(
            f"attribution-weights: profile.recency.tau_days must be > 0, got {tau_days}"
        )
    decayed = math.exp((-lam * age_days) / tau_days)
    return max(min_recency, decayed)
