# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mutual Authentication v1 tests — Python parity + cross-language vectors."""

import base64
import hashlib
import json
import os
import pytest

from agent_passport import (
    build_certificate, sign_certificate, certificate_id,
    verify_certificate_signature, is_certificate_temporally_valid,
    check_anchor,
    build_bundle, sign_bundle, verify_bundle,
    new_nonce, build_hello, choose_version,
    build_attest, verify_attest, derive_session, is_session_active,
    generate_key_pair,
    canonicalize_jcs,
)


NOW = 1_745_000_000_000
HOUR = 60 * 60 * 1000
DAY = 24 * HOUR
VERSIONS = ["1.2", "1.1", "1.0"]

# Path to the SDK source repo containing cross-language conformance vectors.
# Override with APS_SDK_PATH env var if the SDK lives elsewhere.
APS_SDK_PATH = os.environ.get(
    'APS_SDK_PATH',
    os.path.expanduser('~/agent-passport-system'),
)


def _mk_cert(role, subject_pk, issuer_pk, issuer_sk,
             versions=None, binding=None, grade=None, caps=None):
    if versions is None:
        versions = ["1.0"]
    if binding is None:
        binding = "agent:a" if role == "agent" else "mcp://api.example.com"
    if grade is None and role == "agent":
        grade = 2
    unsigned = build_certificate(
        role=role, subject_id=binding, subject_pubkey_hex=subject_pk,
        issuer_id="root", issuer_role="trust_anchor",
        issuer_pubkey_hex=issuer_pk, binding=binding,
        not_before=NOW - HOUR, not_after=NOW + DAY,
        supported_versions=versions,
        attestation_grade=grade,
        capabilities=caps,
    )
    return sign_certificate(unsigned, issuer_sk)


def _mk_anchor(pk):
    return {
        "anchor_id": "root", "display_name": "root",
        "role": "trust_anchor", "pubkey_hex": pk,
        "not_before": NOW - DAY, "not_after": NOW + 365 * DAY,
    }


def _policy(**overrides):
    p = {
        "accepted_versions": VERSIONS,
        "max_clock_skew_ms": 60_000,
        "max_session_ms": HOUR,
    }
    p.update(overrides)
    return p


# ── Certificate primitives ──

def test_cert_sign_verify():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    r = verify_certificate_signature(cert)
    assert r["ok"] is True


def test_cert_tamper_detected():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    cert["binding"] = "agent:attacker"
    r = verify_certificate_signature(cert)
    assert r["ok"] is False
    assert r["reason"] == "signature_invalid"


def test_cert_empty_versions_rejected():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    cert["supported_versions"] = []
    r = verify_certificate_signature(cert)
    assert r["ok"] is False
    assert r["reason"] == "version_empty"


def test_cert_temporal_valid():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    assert is_certificate_temporally_valid(cert, NOW)["ok"] is True
    assert is_certificate_temporally_valid(cert, cert["not_before"] - 1)["reason"] == "not_yet_valid"
    assert is_certificate_temporally_valid(cert, cert["not_after"] + 1)["reason"] == "expired"


def test_cert_id_stable_under_signature_change():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    id1 = certificate_id(cert)
    cert2 = dict(cert)
    cert2["signature_b64"] = "AAAA" + cert["signature_b64"][4:]
    assert certificate_id(cert2) == id1


def test_check_anchor_binding_constraints():
    root = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"],
                    binding="mcp://api.example.com")
    anchor = _mk_anchor(root["publicKey"])
    anchor["binding_constraints"] = ["mcp://api.example.com"]
    assert check_anchor(cert, [anchor])["ok"] is True
    anchor["binding_constraints"] = ["mcp://api.other.com"]
    r = check_anchor(cert, [anchor])
    assert r["ok"] is False
    assert r["reason"] == "binding_mismatch"


def test_check_anchor_revoked():
    root = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"])
    r = check_anchor(cert, [_mk_anchor(root["publicKey"])], ["root"])
    assert r["ok"] is False
    assert r["reason"] == "revoked_anchor"


def test_check_anchor_unknown_issuer():
    root = generate_key_pair()
    other = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"])
    r = check_anchor(cert, [_mk_anchor(other["publicKey"])])
    assert r["ok"] is False
    assert r["reason"] == "unknown_issuer"


# ── Bundle primitives ──

def test_bundle_sign_verify():
    pub = generate_key_pair()
    root = generate_key_pair()
    b = sign_bundle(
        build_bundle(
            bundle_id="b1", anchors=[_mk_anchor(root["publicKey"])],
            issued_at=NOW, refresh_after=NOW + 7 * DAY,
            publisher_pubkey_hex=pub["publicKey"],
        ),
        pub["privateKey"],
    )
    r = verify_bundle(b, [pub["publicKey"]], NOW + HOUR)
    assert r["ok"] is True


def test_bundle_untrusted_publisher():
    pub = generate_key_pair()
    rogue = generate_key_pair()
    b = sign_bundle(
        build_bundle("b", [], NOW, NOW + DAY, pub["publicKey"]),
        pub["privateKey"],
    )
    r = verify_bundle(b, [rogue["publicKey"]], NOW)
    assert r["ok"] is False
    assert r["reason"] == "untrusted_publisher"


def test_bundle_expired():
    pub = generate_key_pair()
    b = sign_bundle(
        build_bundle("b", [], NOW - DAY, NOW - HOUR, pub["publicKey"]),
        pub["privateKey"],
    )
    r = verify_bundle(b, [pub["publicKey"]], NOW)
    assert r["ok"] is False
    assert r["reason"] == "bundle_expired"


# ── Handshake ──

def test_full_handshake_produces_shared_session_id():
    root = generate_key_pair()
    agent = generate_key_pair()
    is_kp = generate_key_pair()
    agent_cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"])
    is_cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"])
    anchor = _mk_anchor(root["publicKey"])
    policy = _policy()

    an = new_nonce()
    isn = new_nonce()

    is_attest = build_attest(
        role="information_system", chosen_version="1.0",
        own_nonce_b64=isn, peer_nonce_b64=an,
        certificate=is_cert, now_ms=NOW,
        own_sk_hex=is_kp["privateKey"],
    )
    r1 = verify_attest(is_attest, an, isn, policy, [anchor], NOW)
    assert r1["ok"] is True, r1

    agent_attest = build_attest(
        role="agent", chosen_version="1.0",
        own_nonce_b64=an, peer_nonce_b64=isn,
        certificate=agent_cert, now_ms=NOW,
        own_sk_hex=agent["privateKey"],
    )
    r2 = verify_attest(agent_attest, isn, an, policy, [anchor], NOW)
    assert r2["ok"] is True, r2

    sess = derive_session(agent_attest, is_attest, policy, NOW)
    assert sess["ok"] is True
    assert sess["session"]["session_id"].startswith("sha256:")
    assert is_session_active(sess["session"], NOW) is True


# ── Adversarial ──

def test_downgrade_detected():
    root = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"],
                    versions=VERSIONS)  # cert advertises 1.2
    an, isn = new_nonce(), new_nonce()
    attest = build_attest(
        role="information_system", chosen_version="1.0",  # but chose 1.0
        own_nonce_b64=isn, peer_nonce_b64=an,
        certificate=cert, now_ms=NOW,
        own_sk_hex=is_kp["privateKey"],
    )
    r = verify_attest(attest, an, isn, _policy(), [_mk_anchor(root["publicKey"])], NOW)
    assert r["ok"] is False
    assert r["reason"] == "downgrade_detected"


def test_replay_clock_skew_rejected():
    root = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"])
    an, isn = new_nonce(), new_nonce()
    attest = build_attest(
        role="information_system", chosen_version="1.0",
        own_nonce_b64=isn, peer_nonce_b64=an,
        certificate=cert, now_ms=NOW - 2 * HOUR,  # stale
        own_sk_hex=is_kp["privateKey"],
    )
    r = verify_attest(attest, an, isn, _policy(), [_mk_anchor(root["publicKey"])], NOW)
    assert r["ok"] is False
    assert r["reason"] == "replay_detected"


def test_nonce_mismatch_rejected():
    root = generate_key_pair()
    is_kp = generate_key_pair()
    cert = _mk_cert("information_system", is_kp["publicKey"], root["publicKey"], root["privateKey"])
    an, isn = new_nonce(), new_nonce()
    wrong = new_nonce()
    attest = build_attest(
        role="information_system", chosen_version="1.0",
        own_nonce_b64=isn, peer_nonce_b64=wrong,
        certificate=cert, now_ms=NOW,
        own_sk_hex=is_kp["privateKey"],
    )
    r = verify_attest(attest, an, isn, _policy(), [_mk_anchor(root["publicKey"])], NOW)
    assert r["ok"] is False
    assert r["reason"] == "nonce_mismatch"


def test_attest_signed_by_wrong_key():
    root = generate_key_pair()
    real = generate_key_pair()
    attacker = generate_key_pair()
    cert = _mk_cert("information_system", real["publicKey"], root["publicKey"], root["privateKey"])
    an, isn = new_nonce(), new_nonce()
    attest = build_attest(
        role="information_system", chosen_version="1.0",
        own_nonce_b64=isn, peer_nonce_b64=an,
        certificate=cert, now_ms=NOW,
        own_sk_hex=attacker["privateKey"],  # wrong key
    )
    r = verify_attest(attest, an, isn, _policy(), [_mk_anchor(root["publicKey"])], NOW)
    assert r["ok"] is False
    assert r["reason"] == "signature_invalid"
    assert r.get("detail") == "attest"


def test_grade_insufficient():
    root = generate_key_pair()
    agent = generate_key_pair()
    cert = _mk_cert("agent", agent["publicKey"], root["publicKey"], root["privateKey"],
                    versions=["1.0"], grade=1)
    an, isn = new_nonce(), new_nonce()
    attest = build_attest(
        role="agent", chosen_version="1.0",
        own_nonce_b64=an, peer_nonce_b64=isn,
        certificate=cert, now_ms=NOW,
        own_sk_hex=agent["privateKey"],
    )
    r = verify_attest(attest, isn, an, _policy(min_agent_grade=3), [_mk_anchor(root["publicKey"])], NOW)
    assert r["ok"] is False
    assert r["reason"] == "grade_insufficient"


# ── Cross-language conformance vectors ──

def test_conformance_vec01_certificate_minimal():
    """Read the TypeScript-generated vec01 and check Python produces the same canonical bytes."""
    # Path to TS SDK conformance vectors
    ts_sdk_path = f"{APS_SDK_PATH}/src/conformance/mutual-auth-vectors/vec01-certificate-canonical.json"
    if not os.path.exists(ts_sdk_path):
        pytest.skip("TS conformance vectors not present locally")
    with open(ts_sdk_path) as f:
        vec = json.load(f)

    # Reproduce the input in Python
    inp = vec["input"]
    # Need to pull issuer_pubkey_hex out and pass the rest to build_certificate
    issuer_pubkey_hex = inp.pop("issuer_pubkey_hex")
    unsigned = build_certificate(issuer_pubkey_hex=issuer_pubkey_hex, **inp)
    canonical_str = canonicalize_jcs(unsigned)
    canonical_bytes = canonical_str.encode("utf-8")
    canonical_b64 = base64.b64encode(canonical_bytes).decode("ascii")
    sha = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    assert canonical_b64 == vec["expected"]["canonical_bytes_b64"]
    assert sha == vec["expected"]["canonical_sha256"]


def test_conformance_vec02_certificate_all_fields():
    ts_sdk_path = f"{APS_SDK_PATH}/src/conformance/mutual-auth-vectors/vec02-certificate-all-fields.json"
    if not os.path.exists(ts_sdk_path):
        pytest.skip("TS conformance vectors not present locally")
    with open(ts_sdk_path) as f:
        vec = json.load(f)
    inp = vec["input"]
    issuer_pubkey_hex = inp.pop("issuer_pubkey_hex")
    unsigned = build_certificate(issuer_pubkey_hex=issuer_pubkey_hex, **inp)
    canonical_str = canonicalize_jcs(unsigned)
    canonical_b64 = base64.b64encode(canonical_str.encode("utf-8")).decode("ascii")
    sha = "sha256:" + hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
    assert canonical_b64 == vec["expected"]["canonical_bytes_b64"]
    assert sha == vec["expected"]["canonical_sha256"]


def test_conformance_vec05_session_id_derivation():
    ts_sdk_path = f"{APS_SDK_PATH}/src/conformance/mutual-auth-vectors/vec05-session-derivation.json"
    if not os.path.exists(ts_sdk_path):
        pytest.skip("TS conformance vectors not present locally")
    with open(ts_sdk_path) as f:
        vec = json.load(f)
    inp = vec["input"]
    material = canonicalize_jcs({
        "spec_version": "1.0",
        "chosen_version": inp["chosen_version"],
        "agent_cert_id": inp["agent_cert_id"],
        "is_cert_id": inp["is_cert_id"],
        "agent_nonce_b64": inp["agent_nonce_b64"],
        "is_nonce_b64": inp["is_nonce_b64"],
    })
    computed = "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    assert computed == vec["expected"]["session_id"]
