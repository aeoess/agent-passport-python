# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tests for v2 attribution_consent — Python parity with the TS module."""

import json
import os
import time

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.v2.attribution_consent import (
    create_attribution_receipt,
    sign_attribution_consent,
    verify_attribution_consent,
    check_artifact_citations,
    receipt_core,
)


def _stamp(gw="g1", offset_ms=0, drift=1000, logical=1):
    now_ms = int(time.time() * 1000) + offset_ms
    return {
        "logicalTime": logical,
        "wallClockEarliest": now_ms - drift,
        "wallClockLatest": now_ms + drift,
        "gatewayId": gw,
    }


@pytest.fixture
def keys():
    return {
        "citer": generate_key_pair(),
        "principal": generate_key_pair(),
        "stranger": generate_key_pair(),
    }


def _build_receipt(keys, **overrides):
    base = dict(
        citer="agent:citer",
        citer_public_key=keys["citer"]["publicKey"],
        citer_private_key=keys["citer"]["privateKey"],
        cited_principal="principal:cited",
        cited_principal_public_key=keys["principal"]["publicKey"],
        citation_content="X said Y about Z",
        binding_context="charter:abc",
        created_at=_stamp(offset_ms=-1000, logical=1),
        expires_at=_stamp(offset_ms=60_000, logical=2),
    )
    base.update(overrides)
    return create_attribution_receipt(**base)


# ── Constructor ──

def test_create_returns_receipt_with_id_and_citer_signature(keys):
    r = _build_receipt(keys)
    assert "id" in r and len(r["id"]) == 64
    assert "citer_signature" in r and len(r["citer_signature"]) == 128
    assert "cited_principal_signature" not in r


def test_create_id_matches_sha256_of_core(keys):
    import hashlib
    r = _build_receipt(keys)
    expected = hashlib.sha256(receipt_core(r).encode()).hexdigest()
    assert r["id"] == expected


def test_create_rejects_empty_citation_content(keys):
    with pytest.raises(ValueError, match="citation_content"):
        _build_receipt(keys, citation_content="")


def test_create_rejects_missing_binding_context(keys):
    with pytest.raises(ValueError, match="binding_context"):
        _build_receipt(keys, binding_context="")


# ── Verify before consent ──

def test_verify_fails_without_consent_signature(keys):
    r = _build_receipt(keys)
    v = verify_attribution_consent(r)
    assert v["valid"] is False
    assert v["reason"] == "no consent signature"


# ── Sign consent ──

def test_sign_consent_attaches_principal_signature(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    assert "cited_principal_signature" in signed
    assert "cited_principal_signature" not in r  # input not mutated


def test_sign_consent_rejects_wrong_private_key(keys):
    r = _build_receipt(keys)
    with pytest.raises(ValueError, match="cited_principal_public_key"):
        sign_attribution_consent(r, keys["stranger"]["privateKey"])


# ── Verify happy path ──

def test_verify_passes_when_both_sigs_present(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    v = verify_attribution_consent(signed)
    assert v["valid"] is True


def test_verify_detects_tampered_id(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    signed["id"] = "0" * 64
    v = verify_attribution_consent(signed)
    assert v["valid"] is False
    assert "tampered" in v["reason"]


def test_verify_detects_tampered_citation_content(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    signed["citation_content"] = "different claim"
    v = verify_attribution_consent(signed)
    assert v["valid"] is False


def test_verify_rejects_swapped_citer_signature(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    signed["citer_signature"] = "00" * 64
    v = verify_attribution_consent(signed)
    assert v["valid"] is False
    assert "citer signature invalid" in v["reason"]


def test_verify_rejects_expired(keys):
    past = _stamp(offset_ms=-120_000, logical=1)
    expired_at = _stamp(offset_ms=-60_000, logical=2)
    r = _build_receipt(keys, created_at=past, expires_at=expired_at)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    v = verify_attribution_consent(signed)
    assert v["valid"] is False
    assert v["reason"] == "expired"


def test_verify_rejects_not_yet_valid(keys):
    future_start = _stamp(offset_ms=120_000, logical=1)
    future_end = _stamp(offset_ms=180_000, logical=2)
    r = _build_receipt(keys, created_at=future_start, expires_at=future_end)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    v = verify_attribution_consent(signed)
    assert v["valid"] is False
    assert v["reason"] == "not yet valid"


# ── Artifact citations ──

def test_artifact_with_no_citations_passes(keys):
    res = check_artifact_citations({}, [])
    assert res["valid"] is True


def test_artifact_with_matching_signed_citation_passes(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    artifact = {"citations": [{
        "receipt_id": signed["id"],
        "cited_principal": signed["cited_principal"],
        "citation_content": signed["citation_content"],
    }]}
    res = check_artifact_citations(artifact, [signed], binding_context="charter:abc")
    assert res["valid"] is True


def test_artifact_rejects_missing_receipt(keys):
    artifact = {"citations": [{
        "receipt_id": "deadbeef" * 8,
        "cited_principal": "principal:cited",
        "citation_content": "anything",
    }]}
    res = check_artifact_citations(artifact, [])
    assert res["valid"] is False
    assert "no receipt provided" in res["reason"]


def test_artifact_rejects_content_mismatch(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    artifact = {"citations": [{
        "receipt_id": signed["id"],
        "cited_principal": signed["cited_principal"],
        "citation_content": "different",
    }]}
    res = check_artifact_citations(artifact, [signed])
    assert res["valid"] is False
    assert "content mismatch" in res["reason"]


def test_artifact_rejects_wrong_binding_context(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    artifact = {"citations": [{
        "receipt_id": signed["id"],
        "cited_principal": signed["cited_principal"],
        "citation_content": signed["citation_content"],
    }]}
    res = check_artifact_citations(artifact, [signed], binding_context="settlement:xyz")
    assert res["valid"] is False
    assert "different binding context" in res["reason"]


def test_artifact_rejects_replayed_receipt(keys):
    r = _build_receipt(keys)
    signed = sign_attribution_consent(r, keys["principal"]["privateKey"])
    cit = {
        "receipt_id": signed["id"],
        "cited_principal": signed["cited_principal"],
        "citation_content": signed["citation_content"],
    }
    artifact = {"citations": [cit, cit]}
    res = check_artifact_citations(artifact, [signed])
    assert res["valid"] is False
    assert "replay" in res["reason"]


# ── Cross-language: TS-produced fixture verifies in Python ──

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "attribution_receipt_from_ts.json")


def _load_ts_fixture():
    if not os.path.exists(FIXTURE_PATH):
        pytest.xfail("fixture generation pending, TS→Python verify loop")
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_ts_fixture_verify_attribution_receipt():
    fx = _load_ts_fixture()
    res = verify_attribution_consent(fx)
    assert res["valid"] is True, f"TS fixture failed Python verify: {res.get('reason')}"


def test_ts_fixture_id_matches_python_core_hash():
    import hashlib
    fx = _load_ts_fixture()
    expected = hashlib.sha256(receipt_core(fx).encode()).hexdigest()
    assert expected == fx["id"]
