# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Settlement — Python port of src/v2/attribution-settlement.

Spec: BUILD-C-SETTLEMENT-PIPELINE.md. Byte-identical canonicalization
and envelope format with the TypeScript SDK, so a TS-signed settlement
record verifies in Python and vice versa.
"""

from .types import (
    ContributorQueryAxisBody,
    ContributorQueryPerAxis,
    ContributorQueryResponse,
    SettlementAxes,
    SettlementAxisIndex,
    SettlementContributor,
    SettlementPeriod,
    SettlementRecord,
    SettlementResidualBucket,
    SettlementVerifyResult,
)
from .merkle import (
    build_contributor_merkle_path,
    build_merkle_root,
    empty_axis_merkle_root,
    leaf_hash,
    verify_merkle_path,
)
from .aggregate import (
    aggregate_attribution_primitives,
    contributor_leaf_hash_hex,
    format_settlement_weight,
    residual_leaf_hash_hex,
)
from .sign import (
    settlement_record_hash,
    settlement_signing_payload,
    sign_settlement_record,
    verify_settlement_signature,
)
from .verify import verify_settlement_record
from .contributor_query import (
    build_contributor_query_response,
    verify_contributor_query_response,
)

__all__ = [
    "ContributorQueryAxisBody",
    "ContributorQueryPerAxis",
    "ContributorQueryResponse",
    "SettlementAxes",
    "SettlementAxisIndex",
    "SettlementContributor",
    "SettlementPeriod",
    "SettlementRecord",
    "SettlementResidualBucket",
    "SettlementVerifyResult",
    "aggregate_attribution_primitives",
    "build_contributor_merkle_path",
    "build_contributor_query_response",
    "build_merkle_root",
    "contributor_leaf_hash_hex",
    "empty_axis_merkle_root",
    "format_settlement_weight",
    "leaf_hash",
    "residual_leaf_hash_hex",
    "settlement_record_hash",
    "settlement_signing_payload",
    "sign_settlement_record",
    "verify_contributor_query_response",
    "verify_merkle_path",
    "verify_settlement_record",
    "verify_settlement_signature",
]
