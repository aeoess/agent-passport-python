# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""read_fidelity_receipt (v2): public surface.

Mirrors src/v2/read_fidelity_receipt/index.ts in the TypeScript SDK.

A signed record of a sampled readback challenge over perceived
content. A read fidelity receipt proves sampled readback fidelity at
the stated n under the declared sampling assumptions. It does not
prove every byte was read correctly, does not prove perception or
comprehension, does not prove which channel was used, and carries no
normative pass threshold: the consumer judges k of n. Pure functions:
no I/O, no clock, no randomness. See types.py for the record shape,
the seed derivation, and the verification order.
"""

from .sampler import (
    commit_spans,
    derive_seed,
    sample_spans,
    score_responses,
)

from .receipt import (
    canonical_no_sig,
    create_read_fidelity_receipt,
    verify_against_source,
    verify_read_fidelity_receipt,
    verify_responses,
)

from .types import (
    ReadFidelityChallenge,
    ReadFidelityReceipt,
    ReadFidelityReceiptType,
    ReadFidelitySamplingAlgorithm,
    ReadFidelityScoringMethod,
    ReadFidelityVerificationMethod,
    ReadFidelityVerifyReason,
    ReadFidelityVerifyResult,
    SampledSpan,
    ScoreResponsesResult,
    VerifyAgainstSourceResult,
    VerifyResponsesResult,
)

__all__ = [
    # sampler
    "commit_spans",
    "derive_seed",
    "sample_spans",
    "score_responses",
    # receipt
    "canonical_no_sig",
    "create_read_fidelity_receipt",
    "verify_against_source",
    "verify_read_fidelity_receipt",
    "verify_responses",
    # types
    "ReadFidelityChallenge",
    "ReadFidelityReceipt",
    "ReadFidelityReceiptType",
    "ReadFidelitySamplingAlgorithm",
    "ReadFidelityScoringMethod",
    "ReadFidelityVerificationMethod",
    "ReadFidelityVerifyReason",
    "ReadFidelityVerifyResult",
    "SampledSpan",
    "ScoreResponsesResult",
    "VerifyAgainstSourceResult",
    "VerifyResponsesResult",
]
