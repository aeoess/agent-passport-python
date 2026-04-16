# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Primitive types — Python mirror of src/v2/attribution-primitive/types.ts.

Wire format is plain dict so canonicalize() output is byte-identical across
languages. Keys match the TypeScript SDK exactly.
"""

from typing import Any, Dict, List, Literal, TypedDict, Union


ATTRIBUTION_AXIS_TAGS = ("D", "P", "G", "C")


class DataAxisEntry(TypedDict):
    source_did: str
    contribution_weight: str
    access_receipt_hash: str


class ProtocolAxisEntry(TypedDict, total=False):
    module_id: str
    module_version: str
    evaluation_outcome: str
    evaluation_receipt_hash: str
    # Optional post-decay weight (spec §4.2)
    weight: str


class GovernanceAxisEntry(TypedDict):
    delegation_id: str
    signer_did: str
    scope_hash: str
    depth: int


class ComputeAxisEntry(TypedDict):
    provider_did: str
    compute_share: str
    hardware_attestation_hash: str


class ResidualBucket(TypedDict):
    residual_id: Literal["residual:D", "residual:P", "residual:C"]
    total_pooled_weight: str
    count_of_pooled_contributors: int
    pooled_contributors_hash: str


DataAxisItem = Union[DataAxisEntry, ResidualBucket]
ProtocolAxisItem = Union[ProtocolAxisEntry, ResidualBucket]
ComputeAxisItem = Union[ComputeAxisEntry, ResidualBucket]


class AttributionAxes(TypedDict):
    D: List[DataAxisItem]
    P: List[ProtocolAxisItem]
    G: List[GovernanceAxisEntry]
    C: List[ComputeAxisItem]


class AttributionAction(TypedDict):
    agentId: str
    actionType: str
    params: Dict[str, Any]
    nonce: str


class AttributionPrimitive(TypedDict):
    action_ref: str
    axes: AttributionAxes
    merkle_root: str
    issuer: str
    timestamp: str
    signature: str


class AttributionProjection(TypedDict):
    action_ref: str
    axis_tag: Literal["D", "P", "G", "C"]
    axis_data: Any
    merkle_path: List[str]
    merkle_root: str
    issuer: str
    timestamp: str
    signature: str


class AttributionEnvelope(TypedDict):
    action_ref: str
    merkle_root: str
    issuer: str
    timestamp: str
