# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Content length weight — Python port.

content_length_weight(len) = log(1 + len) / log(1 + REF_LEN)
"""

import math

from .types import WeightProfile


def content_length_weight(length: float, profile: WeightProfile) -> float:
    if not isinstance(length, (int, float)) or isinstance(length, bool):
        raise ValueError(
            f"attribution-weights: content_length must be non-negative finite, got {length!r}"
        )
    length = float(length)
    if math.isnan(length) or math.isinf(length) or length < 0:
        raise ValueError(
            f"attribution-weights: content_length must be non-negative finite, got {length}"
        )
    ref = float(profile["length"]["reference_length"])
    if math.isnan(ref) or math.isinf(ref) or ref <= 0:
        raise ValueError(
            f"attribution-weights: profile.length.reference_length must be > 0, got {ref}"
        )
    return math.log(1 + length) / math.log(1 + ref)
