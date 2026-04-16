# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Weights — type surface (Build B, Python port).

Spec: BUILD-B-FRACTIONAL-WEIGHTS.md. Parity with
src/v2/attribution-weights/types.ts. Types are plain TypedDicts so the
module stays dependency-free and JSON-round-trippable.
"""

from typing import Any, Dict, List, Literal, TypedDict, Union


AttributionRole = Literal[
    "primary_source",
    "supporting_evidence",
    "context_only",
    "background_retrieval",
]

ATTRIBUTION_ROLES: List[AttributionRole] = [
    "primary_source",
    "supporting_evidence",
    "context_only",
    "background_retrieval",
]


class AccessReceiptWithRole(TypedDict):
    source_did: str
    access_receipt_hash: str
    role: AttributionRole
    # ISO-8601 UTC with millisecond precision + Z. The spec's t_source.
    timestamp: str
    # Content length in tokens. Non-negative integer.
    content_length: int


class InferenceBillingRecord(TypedDict):
    provider_did: str
    hardware_attestation_hash: str
    prompt_tokens: int
    completion_tokens: int


class RoleWeights(TypedDict):
    primary_source: float
    supporting_evidence: float
    context_only: float
    background_retrieval: float


class RecencyParams(TypedDict):
    min_recency: float
    # Decay rate. ln(2) gives a half-life of tau_days.
    lambda_: float  # "lambda" is reserved in Python; wire key is still "lambda".
    tau_days: float


class LengthParams(TypedDict):
    reference_length: float


class ComputeParams(TypedDict):
    completion_multiplier: float


class WeightProfile(TypedDict):
    version: str
    role_weights: RoleWeights
    recency: RecencyParams
    length: LengthParams
    compute: ComputeParams


class ComputeDataAxisOptions(TypedDict, total=False):
    action_timestamp: str  # required
    profile: WeightProfile  # optional


class ComputeComputeAxisOptions(TypedDict, total=False):
    profile: WeightProfile  # optional


class ValidationResult(TypedDict):
    valid: bool
    errors: List[str]


class DataAxisEntry(TypedDict):
    source_did: str
    contribution_weight: str  # canonical 6-digit decimal
    access_receipt_hash: str


class ComputeAxisEntry(TypedDict):
    provider_did: str
    compute_share: str  # canonical 6-digit decimal
    hardware_attestation_hash: str


# Helper aliases used by callers that don't care about the TypedDict
# layer; the module's public functions accept plain dicts too.
SourceLike = Union[AccessReceiptWithRole, Dict[str, Any]]
ProviderLike = Union[InferenceBillingRecord, Dict[str, Any]]
