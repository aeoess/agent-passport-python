# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — verification (Stage 1, 2, 3 stubs) + byte-parity."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from agent_passport.v2.cognitive_attestation import (
    AggregationPolicy,
    CognitiveAttestation,
    DictionaryRef,
    ExecutionEnvironment,
    FeatureActivation,
    ModelRef,
    RegistryResolver,
    Signature,
    TokenRange,
    cognitive_attestation_digest,
    verify_against_registry,
    verify_by_replay,
    verify_required_signer_roles,
    verify_signature,
)

PRIV_HEX = "11" * 32
FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "wave1" / "cognitive-attestation"


def _att_from_dict(d):
    """Reconstruct CognitiveAttestation dataclass from fixture JSON."""
    m = d["model_ref"]
    ee = m["execution_environment"]
    dr = d["dictionary_ref"]
    tr = d["token_range"]
    ap = d["aggregation_policy"]
    return CognitiveAttestation(
        spec_version=d["spec_version"],
        model_ref=ModelRef(
            model_id=m["model_id"],
            model_version_hash=m["model_version_hash"],
            tokenizer_version_hash=m["tokenizer_version_hash"],
            inference_provider=m["inference_provider"],
            execution_environment=ExecutionEnvironment(
                hardware_family=ee["hardware_family"],
                precision=ee["precision"],
                inference_engine=ee["inference_engine"],
                deterministic_mode=ee["deterministic_mode"],
            ),
        ),
        dictionary_ref=DictionaryRef(
            dictionary_id=dr["dictionary_id"],
            dictionary_version_hash=dr["dictionary_version_hash"],
            training_corpus_hash=dr["training_corpus_hash"],
            layer_index=dr["layer_index"],
            attachment_point=dr["attachment_point"],
            sae_type=dr["sae_type"],
        ),
        token_range=TokenRange(
            absolute_sequence_hash=tr["absolute_sequence_hash"],
            prior_state_hash=tr["prior_state_hash"],
            start_token_index=tr["start_token_index"],
            end_token_index=tr["end_token_index"],
            token_count=tr["token_count"],
        ),
        feature_activations=[
            FeatureActivation(
                feature_id=fa["feature_id"], feature_label=fa["feature_label"],
                activation_statistic=fa["activation_statistic"],
                activation_value=fa["activation_value"], tokens_active=fa["tokens_active"],
            )
            for fa in d["feature_activations"]
        ],
        aggregation_policy=AggregationPolicy(
            top_k=ap["top_k"], threshold=ap["threshold"],
            attestation_epsilon=ap["attestation_epsilon"],
            feature_allowlist_hash=ap["feature_allowlist_hash"],
            completeness_claim=ap["completeness_claim"],
            tiebreaker_rule=ap["tiebreaker_rule"],
            required_signer_roles=ap["required_signer_roles"],
        ),
        signatures=[
            Signature(signer_did=s["signer_did"], signer_role=s["signer_role"], signature=s["signature"])
            for s in d["signatures"]
        ],
        attestation_timestamp=d["attestation_timestamp"],
    )


# ── Stage 1a — verify_signature ────────────────────────────────────────


def test_signature_verifies_against_correct_pubkey():
    """TS-issued single-signed fixture verifies under the publishing pubkey.

    Cross-impl byte-parity for sign + verify.
    """
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    pub_hex = f["signatures"][0]["signer_did"]
    pub_bytes = bytes.fromhex(pub_hex)
    assert verify_signature(att, pub_bytes, pub_hex) is True


def test_signature_fails_for_wrong_pubkey():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    wrong_pub = bytes(32)  # all zeros
    assert verify_signature(att, wrong_pub, f["signatures"][0]["signer_did"]) is False


def test_signature_fails_for_unknown_signer_did():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    pub_bytes = bytes.fromhex(f["signatures"][0]["signer_did"])
    assert verify_signature(att, pub_bytes, "did:aps:nobody-signed-this") is False


def test_signature_fails_with_wrong_pubkey_length():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    short = bytes(16)
    assert verify_signature(att, short, f["signatures"][0]["signer_did"]) is False


def test_tampered_envelope_breaks_signature():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    pub_bytes = bytes.fromhex(f["signatures"][0]["signer_did"])
    # Mutate token_count — covered by the canonical bytes.
    tampered = replace(att, token_range=replace(att.token_range, token_count=999))
    assert verify_signature(tampered, pub_bytes, f["signatures"][0]["signer_did"]) is False


# ── Stage 1b — verify_required_signer_roles ───────────────────────────


def test_required_roles_complete_with_two_signers():
    f = json.loads((FIXTURE_DIR / "two-signers.fixture.json").read_text())
    att = _att_from_dict(f)
    cov = verify_required_signer_roles(att)
    assert cov.ok is True
    assert cov.missing == []


def test_required_roles_incomplete_with_one_signer():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    cov = verify_required_signer_roles(att)
    # required_signer_roles is ['agent', 'provider'] but only 'agent' is signed
    assert cov.ok is False
    assert "provider" in cov.missing


# ── Stage 2 — verify_against_registry ─────────────────────────────────


def test_registry_known_model_and_dictionary():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    resolver = RegistryResolver(
        is_known_model=lambda mid, mvh: True,
        is_known_dictionary=lambda did, dvh: True,
    )
    res = verify_against_registry(att, resolver)
    assert res.ok is True
    assert res.model_known is True
    assert res.dictionary_known is True


def test_registry_unknown_model():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    resolver = RegistryResolver(
        is_known_model=lambda mid, mvh: False,
        is_known_dictionary=lambda did, dvh: True,
    )
    res = verify_against_registry(att, resolver)
    assert res.ok is False
    assert res.model_known is False


def test_registry_resolver_exception_surfaces_as_error():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    def boom(*_a):
        raise RuntimeError("registry offline")
    resolver = RegistryResolver(is_known_model=boom, is_known_dictionary=lambda *a: True)
    res = verify_against_registry(att, resolver)
    assert res.ok is False
    assert any("registry offline" in e for e in res.errors)


# ── Stage 3 — verify_by_replay (stub) ─────────────────────────────────


def test_replay_raises_without_backend():
    f = json.loads((FIXTURE_DIR / "single-signed.fixture.json").read_text())
    att = _att_from_dict(f)
    with pytest.raises(NotImplementedError):
        verify_by_replay(att, None)


# ── Cross-impl digest byte-parity ──────────────────────────────────────


def test_digest_byte_parity_with_ts():
    """cognitive_attestation_digest must produce byte-identical hex to TS."""
    fix = json.loads((FIXTURE_DIR / "digest.fixture.json").read_text())
    att = _att_from_dict(fix["envelope"])
    py_digest = cognitive_attestation_digest(att)
    assert py_digest == fix["digest"], f"digest drift: py={py_digest} ts={fix['digest']}"
