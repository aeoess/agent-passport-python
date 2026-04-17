# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Settlement types — Python mirror of
src/v2/attribution-settlement/types.ts.

Wire format is plain dict so canonicalize() output is byte-identical
across languages. Keys match the TypeScript SDK exactly.
"""

from typing import Any, List, Literal, Optional, TypedDict


class SettlementPeriod(TypedDict):
    t0: str
    t1: str
    period_id: str


class SettlementContributor(TypedDict):
    contributor_did: str
    total_weight: str
    contribution_count: int
    merkle_leaf_hash: str


class SettlementResidualBucket(TypedDict):
    residual_id: Literal["residual:D", "residual:P", "residual:C"]
    total_pooled_weight: str
    count_of_pooled_contributors: int
    pooled_contributors_hash: str


class SettlementAxisIndex(TypedDict):
    axis: Literal["D", "P", "G", "C"]
    period: SettlementPeriod
    total_actions: int
    contributors: List[SettlementContributor]
    residual_bucket: Optional[SettlementResidualBucket]
    axis_merkle_root: str


class SettlementAxes(TypedDict):
    D: SettlementAxisIndex
    P: SettlementAxisIndex
    G: SettlementAxisIndex
    C: SettlementAxisIndex


class SettlementRecord(TypedDict):
    schema: Literal["aps.settlement.v1"]
    period: SettlementPeriod
    gateway_did: str
    axes: SettlementAxes
    input_receipts_hash: str
    total_input_count: int
    issued_at: str
    signature: str


class ContributorQueryAxisBody(TypedDict):
    total_weight: str
    contribution_count: int
    leaf_index: int
    merkle_path: List[str]
    axis_root: str


class ContributorQueryPerAxis(TypedDict, total=False):
    D: ContributorQueryAxisBody
    P: ContributorQueryAxisBody
    G: ContributorQueryAxisBody
    C: ContributorQueryAxisBody


class ContributorQueryResponse(TypedDict, total=False):
    settlement_record: SettlementRecord
    settlement_record_hash: str
    contributor_did: str
    per_axis: ContributorQueryPerAxis
    gateway_jwks: str


# Discriminated result shape mirroring the TS SettlementVerifyResult:
#   {"valid": True} | {"valid": False, "reason": str, "detail": Optional[str]}
SettlementVerifyResult = dict
