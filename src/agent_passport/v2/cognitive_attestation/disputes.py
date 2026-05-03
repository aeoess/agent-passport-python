# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — dispute primitives (typed shapes only).

Mirrors src/v2/cognitive-attestation/disputes.ts.

The SDK ships the dispute VOCABULARY, not the workflow. Dispute
submission, resolution, scheduling, rate-limiting, and governance
annotations live in the private gateway.
"""

from dataclasses import dataclass, field
from typing import List, Literal, Union


# ── Computational disputes — resolved by replay (Stage 3) ─────────────


@dataclass
class ThresholdDispute:
    """The envelope claimed a feature activation that differs from replay
    by more than `epsilon_applied`."""

    feature_id: int
    attested_value: float
    claimed_value: float
    delta: float
    epsilon_applied: float
    kind: Literal["threshold"] = "threshold"


@dataclass
class ExclusionDispute:
    """A feature active in replay was not present in the envelope's
    reported activations. `reason` distinguishes the aggregation-policy
    mechanism that excluded it."""

    feature_id: int
    claimed_activation: float
    reason: Literal["missing_from_top_k", "below_threshold", "allowlist_violation"]
    kind: Literal["exclusion"] = "exclusion"


ComputationalDispute = Union[ThresholdDispute, ExclusionDispute]


# ── Interpretive disputes — governance annotations, no replay ──────────


@dataclass
class DecompositionAdequacyDispute:
    """Claim that the dictionary's feature decomposition is inadequate to
    describe the attested behavior. Resolved by governance, not math."""

    claim: str
    evidence_refs: List[str]
    annotator_did: str
    kind: Literal["decomposition_adequacy"] = "decomposition_adequacy"


@dataclass
class FacetedReinterpretationDispute:
    """Claim that a feature's conventional label misrepresents the concept
    it detects in the attested context. Resolved by governance annotation."""

    feature_id: int
    original_label: object  # str | None
    proposed_reinterpretation: str
    evidence_refs: List[str]
    annotator_did: str
    kind: Literal["faceted_reinterpretation"] = "faceted_reinterpretation"


InterpretiveDispute = Union[DecompositionAdequacyDispute, FacetedReinterpretationDispute]


Dispute = Union[ComputationalDispute, InterpretiveDispute]
