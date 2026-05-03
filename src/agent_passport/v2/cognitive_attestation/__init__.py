# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — public surface.

Mirrors src/v2/cognitive-attestation/index.ts. Paper 4 (Zenodo DOI
10.5281/zenodo.19646276). Normative schema:
papers/paper-4/poc/schema/cognitive_attestation.schema.json.

SDK scope: envelope construction, JCS canonicalization, Ed25519 signing,
Stage 1 (cryptographic) verification, Stage 2 (registry) interface,
Stage 3 (replay) stub, typed dispute primitives.

Out of scope: dispute resolution, re-verification scheduling, cross-
tenant correlation, transparency-log publishing, bulk compliance
reports. These live in the private aeoess-gateway.
"""

from .types import (
    ActivationStatistic,
    AggregationPolicy,
    AttachmentPoint,
    CognitiveAttestation,
    CompletenessClaim,
    DictionaryRef,
    ExecutionEnvironment,
    FeatureActivation,
    ModelRef,
    Precision,
    SAEType,
    Signature,
    SignerRole,
    TiebreakerRule,
    TokenRange,
    BuildAttestationInput,
)

from .envelope import (
    build_attestation,
    canonicalize_attestation,
    cognitive_attestation_digest,
    sign_attestation,
    sort_feature_activations,
    validate_attestation_shape,
)

from .verify import (
    RegistryResolver,
    RegistryVerificationResult,
    ReplayBackend,
    ReplayVerificationResult,
    RequiredRoleCoverage,
    verify_against_registry,
    verify_by_replay,
    verify_required_signer_roles,
    verify_signature,
)

from .disputes import (
    ComputationalDispute,
    DecompositionAdequacyDispute,
    Dispute,
    ExclusionDispute,
    FacetedReinterpretationDispute,
    InterpretiveDispute,
    ThresholdDispute,
)

__all__ = [
    # types
    "ActivationStatistic",
    "AggregationPolicy",
    "AttachmentPoint",
    "BuildAttestationInput",
    "CognitiveAttestation",
    "CompletenessClaim",
    "DictionaryRef",
    "ExecutionEnvironment",
    "FeatureActivation",
    "ModelRef",
    "Precision",
    "SAEType",
    "Signature",
    "SignerRole",
    "TiebreakerRule",
    "TokenRange",
    # envelope
    "build_attestation",
    "canonicalize_attestation",
    "cognitive_attestation_digest",
    "sign_attestation",
    "sort_feature_activations",
    "validate_attestation_shape",
    # verify
    "RegistryResolver",
    "RegistryVerificationResult",
    "ReplayBackend",
    "ReplayVerificationResult",
    "RequiredRoleCoverage",
    "verify_against_registry",
    "verify_by_replay",
    "verify_required_signer_roles",
    "verify_signature",
    # disputes
    "ComputationalDispute",
    "DecompositionAdequacyDispute",
    "Dispute",
    "ExclusionDispute",
    "FacetedReinterpretationDispute",
    "InterpretiveDispute",
    "ThresholdDispute",
]
