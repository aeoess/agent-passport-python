# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — typed dispute primitives."""

from agent_passport.v2.cognitive_attestation import (
    DecompositionAdequacyDispute,
    ExclusionDispute,
    FacetedReinterpretationDispute,
    ThresholdDispute,
)


def test_threshold_dispute_kind_locked():
    d = ThresholdDispute(
        feature_id=42, attested_value=0.7, claimed_value=0.5,
        delta=0.2, epsilon_applied=0.001,
    )
    assert d.kind == "threshold"


def test_exclusion_dispute_with_reason():
    d = ExclusionDispute(feature_id=7, claimed_activation=0.3, reason="below_threshold")
    assert d.kind == "exclusion"
    assert d.reason == "below_threshold"


def test_decomposition_adequacy_dispute_carries_evidence_refs():
    d = DecompositionAdequacyDispute(
        claim="Dictionary V1 cannot distinguish syntactic vs semantic parens.",
        evidence_refs=["ipfs://bafy...", "doi://10.5281/zenodo.0"],
        annotator_did="did:aps:reviewer-001",
    )
    assert d.kind == "decomposition_adequacy"
    assert len(d.evidence_refs) == 2


def test_faceted_reinterpretation_dispute_with_null_original_label():
    d = FacetedReinterpretationDispute(
        feature_id=12,
        original_label=None,
        proposed_reinterpretation="closing-paren-in-arg-list",
        evidence_refs=["doi://10.5281/zenodo.1"],
        annotator_did="did:aps:reviewer-002",
    )
    assert d.kind == "faceted_reinterpretation"
    assert d.original_label is None
