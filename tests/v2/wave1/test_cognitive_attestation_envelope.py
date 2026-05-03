# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — envelope construction + canonicalization + digest."""

import json
from pathlib import Path

import pytest

from agent_passport.v2.cognitive_attestation import (
    AggregationPolicy,
    BuildAttestationInput,
    FeatureActivation,
    build_attestation,
    canonicalize_attestation,
    cognitive_attestation_digest,
    sort_feature_activations,
    validate_attestation_shape,
)
from agent_passport.crypto import public_key_from_private

PRIV_HEX = "11" * 32

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "wave1" / "cognitive-attestation"


def _base_input(**overrides):
    base = dict(
        model_id="meta-llama/Llama-3.1-8B-Instruct",
        model_version_hash="a" * 64,
        tokenizer_version_hash="b" * 64,
        inference_provider="openai",
        hardware_family="nvidia/hopper/h100-sxm5",
        precision="fp16",
        inference_engine="vllm@0.6.3",
        deterministic_mode=True,
        dictionary_id="aeoess/sae-llama-3.1-8b/v1",
        dictionary_version_hash="c" * 64,
        training_corpus_hash=None,
        layer_index=12,
        attachment_point="residual_stream",
        sae_type="topk",
        absolute_sequence_hash="d" * 64,
        prior_state_hash=None,
        start_token_index=0,
        end_token_index=16,
        token_count=16,
        feature_activations=[
            FeatureActivation(feature_id=7, feature_label="syntax-paren", activation_statistic="max", activation_value=0.91, tokens_active=4),
            FeatureActivation(feature_id=3, feature_label=None, activation_statistic="mean", activation_value=0.42, tokens_active=9),
        ],
        aggregation_policy=AggregationPolicy(
            top_k=5, threshold=0.05, attestation_epsilon=0.001,
            feature_allowlist_hash=None, completeness_claim="top_k_only",
            tiebreaker_rule="lowest_feature_id", required_signer_roles=["agent", "provider"],
        ),
        timestamp="2026-05-02T12:00:00.000Z",
    )
    base.update(overrides)
    return BuildAttestationInput(**base)


def test_build_returns_unsigned_envelope():
    att = build_attestation(_base_input())
    assert att.spec_version == "1.0"
    assert att.signatures == []
    assert att.attestation_timestamp == "2026-05-02T12:00:00.000Z"


def test_features_sorted_by_id_then_statistic():
    att = build_attestation(_base_input())
    assert [(f.feature_id, f.activation_statistic) for f in att.feature_activations] == [
        (3, "mean"),
        (7, "max"),
    ]


def test_sort_feature_activations_does_not_mutate_input():
    fa = [
        FeatureActivation(feature_id=2, feature_label=None, activation_statistic="max", activation_value=0.5, tokens_active=1),
        FeatureActivation(feature_id=1, feature_label=None, activation_statistic="max", activation_value=0.5, tokens_active=1),
    ]
    sorted_fa = sort_feature_activations(fa)
    assert [f.feature_id for f in fa] == [2, 1]
    assert [f.feature_id for f in sorted_fa] == [1, 2]


def test_canonicalize_attestation_returns_utf8_bytes():
    att = build_attestation(_base_input())
    bs = canonicalize_attestation(att)
    assert isinstance(bs, bytes)
    decoded = bs.decode("utf-8")
    # Signatures should be elided in the canonicalize-for-signing form.
    assert '"signatures":[]' in decoded


def test_validate_attestation_shape_accepts_signed_fixture():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    result = validate_attestation_shape(f)
    assert result["ok"] is True, result["errors"]


def test_validate_attestation_shape_rejects_missing_signatures():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    f["signatures"] = []
    result = validate_attestation_shape(f)
    assert result["ok"] is False
    assert any("signatures" in e for e in result["errors"])


# ── Cross-impl byte-parity ────────────────────────────────────────────


def test_canonical_bytes_byte_parity_with_ts():
    """The canonical-bytes-for-signing JSON produced by Python must match
    what TS produces for the same input.
    """
    fix = json.loads((FIXTURE_DIR / "canonical-bytes.fixture.json").read_text())
    inp = fix["input"]
    att = build_attestation(BuildAttestationInput(
        model_id=inp["model_id"], model_version_hash=inp["model_version_hash"],
        tokenizer_version_hash=inp["tokenizer_version_hash"],
        inference_provider=inp["inference_provider"], hardware_family=inp["hardware_family"],
        precision=inp["precision"], inference_engine=inp["inference_engine"],
        deterministic_mode=inp["deterministic_mode"],
        dictionary_id=inp["dictionary_id"], dictionary_version_hash=inp["dictionary_version_hash"],
        training_corpus_hash=inp["training_corpus_hash"], layer_index=inp["layer_index"],
        attachment_point=inp["attachment_point"], sae_type=inp["sae_type"],
        absolute_sequence_hash=inp["absolute_sequence_hash"],
        prior_state_hash=inp["prior_state_hash"], start_token_index=inp["start_token_index"],
        end_token_index=inp["end_token_index"], token_count=inp["token_count"],
        feature_activations=[
            FeatureActivation(
                feature_id=fa["feature_id"], feature_label=fa["feature_label"],
                activation_statistic=fa["activation_statistic"],
                activation_value=fa["activation_value"], tokens_active=fa["tokens_active"],
            )
            for fa in inp["feature_activations"]
        ],
        aggregation_policy=AggregationPolicy(
            top_k=inp["aggregation_policy"]["top_k"],
            threshold=inp["aggregation_policy"]["threshold"],
            attestation_epsilon=inp["aggregation_policy"]["attestation_epsilon"],
            feature_allowlist_hash=inp["aggregation_policy"]["feature_allowlist_hash"],
            completeness_claim=inp["aggregation_policy"]["completeness_claim"],
            tiebreaker_rule=inp["aggregation_policy"]["tiebreaker_rule"],
            required_signer_roles=inp["aggregation_policy"]["required_signer_roles"],
        ),
        timestamp=inp["timestamp"],
    ))
    py_canonical = canonicalize_attestation(att).decode("utf-8")
    assert py_canonical == fix["canonical_jcs"], (
        f"canonical drift\n  python: {py_canonical[:200]}...\n  ts:     {fix['canonical_jcs'][:200]}..."
    )
