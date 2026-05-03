# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — types.

Mirrors src/v2/cognitive-attestation/types.ts. Source of truth for the
schema is papers/paper-4/poc/schema/cognitive_attestation.schema.json.

Every nullable field in the JSON schema becomes Optional[T] here so that
JCS canonicalization preserves null (RFC 8785 requirement, and the
cross-implementation contract with the TypeScript SDK and the Python
reference impl).

Field names are snake_case in TS already, so Python attribute names
match the canonical wire form directly.
"""

from dataclasses import dataclass, field
from typing import List, Literal, Optional


# ── Closed taxonomies ──────────────────────────────────────────────────

Precision = Literal["fp32", "fp16", "bf16", "int8"]
AttachmentPoint = Literal["residual_stream", "attention_output", "mlp_output"]
SAEType = Literal["standard", "topk", "jumprelu", "gated", "batchtopk"]
ActivationStatistic = Literal["max", "mean", "sum", "integral", "last"]
CompletenessClaim = Literal["top_k_only", "all_above_threshold", "dictionary_exhaustive"]
TiebreakerRule = Literal["lowest_feature_id", "highest_feature_id"]
SignerRole = Literal["agent", "operator", "provider", "third_party_attester"]


# ── Nested types ───────────────────────────────────────────────────────


@dataclass
class ExecutionEnvironment:
    hardware_family: str
    precision: Precision
    inference_engine: str
    deterministic_mode: bool

    def to_canonical_dict(self) -> dict:
        return {
            "deterministic_mode": self.deterministic_mode,
            "hardware_family": self.hardware_family,
            "inference_engine": self.inference_engine,
            "precision": self.precision,
        }


@dataclass
class ModelRef:
    model_id: str
    model_version_hash: str  # 64-char lowercase hex
    tokenizer_version_hash: str
    inference_provider: Optional[str]  # nullable, must round-trip null
    execution_environment: ExecutionEnvironment

    def to_canonical_dict(self) -> dict:
        return {
            "execution_environment": self.execution_environment.to_canonical_dict(),
            "inference_provider": self.inference_provider,  # None -> null
            "model_id": self.model_id,
            "model_version_hash": self.model_version_hash,
            "tokenizer_version_hash": self.tokenizer_version_hash,
        }


@dataclass
class DictionaryRef:
    dictionary_id: str
    dictionary_version_hash: str
    training_corpus_hash: Optional[str]  # nullable
    layer_index: int
    attachment_point: AttachmentPoint
    sae_type: SAEType

    def to_canonical_dict(self) -> dict:
        return {
            "attachment_point": self.attachment_point,
            "dictionary_id": self.dictionary_id,
            "dictionary_version_hash": self.dictionary_version_hash,
            "layer_index": self.layer_index,
            "sae_type": self.sae_type,
            "training_corpus_hash": self.training_corpus_hash,
        }


@dataclass
class TokenRange:
    absolute_sequence_hash: str
    prior_state_hash: Optional[str]  # nullable, NOT a KV-cache hash
    start_token_index: int
    end_token_index: int
    token_count: int

    def to_canonical_dict(self) -> dict:
        return {
            "absolute_sequence_hash": self.absolute_sequence_hash,
            "end_token_index": self.end_token_index,
            "prior_state_hash": self.prior_state_hash,
            "start_token_index": self.start_token_index,
            "token_count": self.token_count,
        }


@dataclass
class FeatureActivation:
    feature_id: int
    feature_label: Optional[str]  # nullable
    activation_statistic: ActivationStatistic
    activation_value: float
    tokens_active: int

    def to_canonical_dict(self) -> dict:
        return {
            "activation_statistic": self.activation_statistic,
            "activation_value": self.activation_value,
            "feature_id": self.feature_id,
            "feature_label": self.feature_label,
            "tokens_active": self.tokens_active,
        }


@dataclass
class AggregationPolicy:
    """Aggregation policy.

    `attestation_epsilon` and `required_signer_roles` are REQUIRED per the
    normative schema. The Python reference's smoke test omitted them at
    one point — this dataclass makes the omission a runtime error.
    """

    top_k: Optional[int]  # >=1 or null
    threshold: Optional[float]  # >=0 or null
    attestation_epsilon: float  # > 0
    feature_allowlist_hash: Optional[str]  # 64-char hex or null
    completeness_claim: CompletenessClaim
    tiebreaker_rule: TiebreakerRule
    required_signer_roles: List[SignerRole]

    def to_canonical_dict(self) -> dict:
        return {
            "attestation_epsilon": self.attestation_epsilon,
            "completeness_claim": self.completeness_claim,
            "feature_allowlist_hash": self.feature_allowlist_hash,
            "required_signer_roles": list(self.required_signer_roles),
            "threshold": self.threshold,
            "tiebreaker_rule": self.tiebreaker_rule,
            "top_k": self.top_k,
        }


@dataclass
class Signature:
    signer_did: str
    signer_role: SignerRole
    signature: str  # base64-encoded Ed25519 over JCS payload (signatures=[] elided)

    def to_canonical_dict(self) -> dict:
        return {
            "signature": self.signature,
            "signer_did": self.signer_did,
            "signer_role": self.signer_role,
        }


# ── CognitiveAttestation ───────────────────────────────────────────────


@dataclass
class CognitiveAttestation:
    spec_version: str  # always "1.0"
    model_ref: ModelRef
    dictionary_ref: DictionaryRef
    token_range: TokenRange
    feature_activations: List[FeatureActivation]
    aggregation_policy: AggregationPolicy
    signatures: List[Signature]
    attestation_timestamp: str  # ISO 8601 UTC

    def to_canonical_dict(self, *, signatures_for_canonical: Optional[List[Signature]] = None) -> dict:
        """Canonical dict for JCS canonicalization.

        `signatures_for_canonical` overrides self.signatures when not None.
        Pass [] for the canonicalization-for-signing form (signatures: []
        elided so all signers produce byte-identical input regardless of
        order). Pass None to use self.signatures (the digest path).
        """
        sigs = signatures_for_canonical if signatures_for_canonical is not None else self.signatures
        return {
            "aggregation_policy": self.aggregation_policy.to_canonical_dict(),
            "attestation_timestamp": self.attestation_timestamp,
            "dictionary_ref": self.dictionary_ref.to_canonical_dict(),
            "feature_activations": [fa.to_canonical_dict() for fa in self.feature_activations],
            "model_ref": self.model_ref.to_canonical_dict(),
            "signatures": [s.to_canonical_dict() for s in sigs],
            "spec_version": self.spec_version,
            "token_range": self.token_range.to_canonical_dict(),
        }


# ── BuildAttestationInput ──────────────────────────────────────────────


@dataclass
class BuildAttestationInput:
    """Flat input shape mirroring TS BuildAttestationInput."""

    # model_ref
    model_id: str
    model_version_hash: str
    tokenizer_version_hash: str
    inference_provider: Optional[str]
    hardware_family: str
    precision: Precision
    inference_engine: str
    deterministic_mode: bool
    # dictionary_ref
    dictionary_id: str
    dictionary_version_hash: str
    training_corpus_hash: Optional[str]
    layer_index: int
    attachment_point: AttachmentPoint
    sae_type: SAEType
    # token_range
    absolute_sequence_hash: str
    prior_state_hash: Optional[str]
    start_token_index: int
    end_token_index: int
    token_count: int
    # aggregation
    feature_activations: List[FeatureActivation]
    aggregation_policy: AggregationPolicy
    # optional
    timestamp: Optional[str] = None
