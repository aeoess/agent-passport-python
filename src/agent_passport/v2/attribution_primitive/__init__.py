# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Primitive — Python port of src/v2/attribution-primitive.

Spec: ATTRIBUTION-PRIMITIVE-v1.1.md. Byte-identical canonicalization and
envelope format with the TypeScript SDK, so a TS-signed primitive verifies
in Python and vice versa.
"""

from .types import (
    ATTRIBUTION_AXIS_TAGS,
    AttributionAction,
    AttributionAxes,
    AttributionEnvelope,
    AttributionPrimitive,
    AttributionProjection,
    ComputeAxisEntry,
    DataAxisEntry,
    GovernanceAxisEntry,
    ProtocolAxisEntry,
    ResidualBucket,
)
from .canonical import (
    assert_canonical_timestamp,
    canonical_timestamp,
    canonical_hash_hex,
    envelope_bytes,
    hash_axis_leaf,
    hash_node,
    normalize_axes,
    order_governance_axis,
    sort_compute_axis,
    sort_data_axis,
    sort_protocol_axis,
    to_weight_string,
)
from .merkle import (
    build_merkle_frame,
    projection_path,
    reconstruct_root,
)
from .construct import (
    compute_attribution_action_ref,
    construct_attribution_primitive,
    resign_attribution_primitive,
)
from .project import (
    project_all_axes,
    project_attribution,
)
from .verify import (
    check_projection_consistency,
    verify_attribution_primitive,
    verify_attribution_projection,
)
from .residual import (
    DEFAULT_MIN_WEIGHT,
    aggregate_compute_axis,
    aggregate_data_axis,
    aggregate_protocol_axis,
)

__all__ = [
    "ATTRIBUTION_AXIS_TAGS",
    "DEFAULT_MIN_WEIGHT",
    "AttributionAction",
    "AttributionAxes",
    "AttributionEnvelope",
    "AttributionPrimitive",
    "AttributionProjection",
    "ComputeAxisEntry",
    "DataAxisEntry",
    "GovernanceAxisEntry",
    "ProtocolAxisEntry",
    "ResidualBucket",
    "aggregate_compute_axis",
    "aggregate_data_axis",
    "aggregate_protocol_axis",
    "assert_canonical_timestamp",
    "build_merkle_frame",
    "canonical_hash_hex",
    "canonical_timestamp",
    "check_projection_consistency",
    "compute_attribution_action_ref",
    "construct_attribution_primitive",
    "envelope_bytes",
    "hash_axis_leaf",
    "hash_node",
    "normalize_axes",
    "order_governance_axis",
    "project_all_axes",
    "project_attribution",
    "projection_path",
    "reconstruct_root",
    "resign_attribution_primitive",
    "sort_compute_axis",
    "sort_data_axis",
    "sort_protocol_axis",
    "to_weight_string",
    "verify_attribution_primitive",
    "verify_attribution_projection",
]
