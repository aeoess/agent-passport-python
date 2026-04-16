# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Weights — Python port of src/v2/attribution-weights.

Spec: BUILD-B-FRACTIONAL-WEIGHTS.md. Parity with the TypeScript SDK so
that a Python computation and a TS computation produce byte-identical
canonical output (cross-language fixtures enforce this).
"""

from .types import (
    ATTRIBUTION_ROLES,
    AccessReceiptWithRole,
    AttributionRole,
    ComputeAxisEntry,
    ComputeComputeAxisOptions,
    ComputeDataAxisOptions,
    DataAxisEntry,
    InferenceBillingRecord,
    ValidationResult,
    WeightProfile,
)
from .roles import role_weight
from .recency import recency_decay
from .length import content_length_weight
from .profile import (
    DEFAULT_WEIGHT_PROFILE,
    hash_weight_profile,
    validate_weight_profile,
)
from .data_axis import compute_data_axis_weights
from .compute_axis import compute_compute_axis_weights

__all__ = [
    "ATTRIBUTION_ROLES",
    "AccessReceiptWithRole",
    "AttributionRole",
    "ComputeAxisEntry",
    "ComputeComputeAxisOptions",
    "ComputeDataAxisOptions",
    "DEFAULT_WEIGHT_PROFILE",
    "DataAxisEntry",
    "InferenceBillingRecord",
    "ValidationResult",
    "WeightProfile",
    "compute_compute_axis_weights",
    "compute_data_axis_weights",
    "content_length_weight",
    "hash_weight_profile",
    "recency_decay",
    "role_weight",
    "validate_weight_profile",
]
