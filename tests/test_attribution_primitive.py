# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tests for Attribution Primitive — parity with TS attribution-primitive."""

import hashlib
import json
import os
import subprocess
import uuid

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.v2.attribution_primitive import (
    ATTRIBUTION_AXIS_TAGS,
    aggregate_data_axis,
    assert_canonical_timestamp,
    build_merkle_frame,
    canonical_timestamp,
    check_projection_consistency,
    compute_attribution_action_ref,
    construct_attribution_primitive,
    envelope_bytes,
    hash_axis_leaf,
    hash_node,
    normalize_axes,
    order_governance_axis,
    project_all_axes,
    project_attribution,
    projection_path,
    reconstruct_root,
    sort_data_axis,
    to_weight_string,
    verify_attribution_primitive,
    verify_attribution_projection,
)


def demo_axes():
    return {
        "D": [
            {"source_did": "did:data:kff-2025", "contribution_weight": "0.583000", "access_receipt_hash": "a" * 64},
            {"source_did": "did:data:cms-archive-2025", "contribution_weight": "0.417000", "access_receipt_hash": "b" * 64},
        ],
        "P": [
            {"module_id": "redact-pii-v2.3", "module_version": "2.3.1", "evaluation_outcome": "approved", "evaluation_receipt_hash": "c" * 64},
            {"module_id": "cite-verify-v1.7", "module_version": "1.7.4", "evaluation_outcome": "approved", "evaluation_receipt_hash": "d" * 64},
        ],
        "G": [
            {"delegation_id": "root", "signer_did": "did:aps:r", "scope_hash": "e" * 64, "depth": 0},
            {"delegation_id": "agent", "signer_did": "did:aps:a", "scope_hash": "f" * 64, "depth": 1},
        ],
        "C": [
            {"provider_did": "did:compute:x", "compute_share": "0.500000", "hardware_attestation_hash": "1" * 64},
            {"provider_did": "did:compute:y", "compute_share": "0.500000", "hardware_attestation_hash": "2" * 64},
        ],
    }


def demo_action(**overrides):
    return {
        "agentId": overrides.get("agentId", "did:aps:agent-py"),
        "actionType": overrides.get("actionType", "query.summarize"),
        "params": overrides.get("params", {"q": "hello", "region": "us-west"}),
        "nonce": overrides.get("nonce", str(uuid.uuid4())),
    }


def _issuer_kp():
    kp = generate_key_pair()
    return "did:aps:issuer-py", kp["publicKey"], kp["privateKey"]


def _build(axes_overrides=None):
    issuer, pub, priv = _issuer_kp()
    axes = {**demo_axes(), **(axes_overrides or {})}
    primitive = construct_attribution_primitive(
        action=demo_action(),
        axes=axes,
        issuer=issuer,
        issuer_private_key=priv,
    )
    return primitive, pub, priv


# ─────────────────────────────────────────────────────────────
# Canonicalization
# ─────────────────────────────────────────────────────────────


def test_to_weight_string_forces_six_digit_precision():
    assert to_weight_string(0.5) == "0.500000"
    assert to_weight_string(1 / 3) == "0.333333"
    assert to_weight_string("0.123456") == "0.123456"


def test_to_weight_string_rejects_bad_input():
    with pytest.raises(ValueError):
        to_weight_string(-0.01)
    with pytest.raises(ValueError):
        to_weight_string(1.01)
    with pytest.raises(ValueError):
        to_weight_string("0.5")
    with pytest.raises(ValueError):
        to_weight_string("0.3333333")


def test_timestamp_strict_format():
    assert_canonical_timestamp("2026-04-12T17:42:08.342Z")
    with pytest.raises(ValueError):
        assert_canonical_timestamp("2026-04-12T17:42:08Z")
    with pytest.raises(ValueError):
        assert_canonical_timestamp("2026-04-12T17:42:08.342+00:00")


def test_canonical_timestamp_now():
    ts = canonical_timestamp()
    assert_canonical_timestamp(ts)


# ─────────────────────────────────────────────────────────────
# Axis ordering
# ─────────────────────────────────────────────────────────────


def test_sort_data_axis_by_source_did():
    unsorted = [
        {"source_did": "did:data:z", "contribution_weight": "0.100000", "access_receipt_hash": "a" * 64},
        {"source_did": "did:data:a", "contribution_weight": "0.200000", "access_receipt_hash": "b" * 64},
    ]
    sorted_ = sort_data_axis(unsorted)
    assert sorted_[0]["source_did"] == "did:data:a"


def test_order_governance_axis():
    unsorted = [
        {"delegation_id": "d2", "signer_did": "s2", "scope_hash": "a" * 64, "depth": 2},
        {"delegation_id": "d0", "signer_did": "s0", "scope_hash": "b" * 64, "depth": 0},
        {"delegation_id": "d1", "signer_did": "s1", "scope_hash": "c" * 64, "depth": 1},
    ]
    ordered = order_governance_axis(unsorted)
    assert [g["depth"] for g in ordered] == [0, 1, 2]


def test_normalize_axes_idempotent():
    a = demo_axes()
    once = normalize_axes(a)
    twice = normalize_axes(once)
    assert once == twice


# ─────────────────────────────────────────────────────────────
# action_ref
# ─────────────────────────────────────────────────────────────


def test_action_ref_deterministic():
    a = demo_action()
    assert compute_attribution_action_ref(a) == compute_attribution_action_ref(dict(a))


def test_action_ref_distinguishes_nonce():
    a = compute_attribution_action_ref(demo_action(nonce="aaa"))
    b = compute_attribution_action_ref(demo_action(nonce="bbb"))
    assert a != b


def test_action_ref_rejects_empty_tuple():
    with pytest.raises(ValueError):
        compute_attribution_action_ref({"agentId": "", "actionType": "t", "params": {}, "nonce": "n"})


# ─────────────────────────────────────────────────────────────
# Merkle tree + projections
# ─────────────────────────────────────────────────────────────


def test_merkle_root_structural_correctness():
    frame = build_merkle_frame(demo_axes())
    expected_content = hashlib.sha256(frame["leaves"]["D"] + frame["leaves"]["P"]).digest()
    expected_auth = hashlib.sha256(frame["leaves"]["G"] + frame["leaves"]["C"]).digest()
    expected_root = hashlib.sha256(expected_content + expected_auth).digest()
    assert frame["nodes"]["N_content"] == expected_content
    assert frame["nodes"]["N_auth_infra"] == expected_auth
    assert frame["root"] == expected_root


def test_all_paths_length_two():
    frame = build_merkle_frame(demo_axes())
    for tag in ATTRIBUTION_AXIS_TAGS:
        path = projection_path(frame, tag)
        assert len(path) == 2


def test_reconstruct_root_round_trip():
    frame = build_merkle_frame(demo_axes())
    for tag in ATTRIBUTION_AXIS_TAGS:
        path = projection_path(frame, tag)
        leaf = hash_axis_leaf(frame["axes"][tag])
        assert reconstruct_root(leaf, path, tag) == frame["root"]


# ─────────────────────────────────────────────────────────────
# Construction + verification
# ─────────────────────────────────────────────────────────────


def test_construct_and_verify_each_axis():
    primitive, pub, _ = _build()
    for tag in ATTRIBUTION_AXIS_TAGS:
        proj = project_attribution(primitive, tag)
        res = verify_attribution_projection(proj, pub)
        assert res == {"valid": True}


def test_verify_attribution_primitive_end_to_end():
    primitive, pub, _ = _build()
    res = verify_attribution_primitive(primitive, pub)
    assert res == {"valid": True}


def test_tampered_axis_data_fails_merkle():
    primitive, pub, _ = _build()
    proj = project_attribution(primitive, "D")
    proj["axis_data"] = [dict(proj["axis_data"][0], contribution_weight="0.999999")]
    res = verify_attribution_projection(proj, pub)
    assert res == {"valid": False, "reason": "MERKLE_MISMATCH"}


def test_wrong_public_key_fails_signature():
    primitive, _, _ = _build()
    other_pub = generate_key_pair()["publicKey"]
    proj = project_attribution(primitive, "G")
    res = verify_attribution_projection(proj, other_pub)
    assert res == {"valid": False, "reason": "SIGNATURE_INVALID"}


def test_deterministic_under_axis_reordering():
    issuer, pub, priv = _issuer_kp()
    axes1 = demo_axes()
    axes2 = {k: list(reversed(v)) for k, v in axes1.items()}
    # Shared action so action_ref + envelope + signature are all determined
    # purely by axes ordering (which the canonicalizer normalizes away).
    action = demo_action(nonce="fixed-nonce-for-determinism")
    p1 = construct_attribution_primitive(
        action=action, axes=axes1, issuer=issuer, issuer_private_key=priv, timestamp="2026-04-12T17:42:08.342Z"
    )
    p2 = construct_attribution_primitive(
        action=action, axes=axes2, issuer=issuer, issuer_private_key=priv, timestamp="2026-04-12T17:42:08.342Z"
    )
    assert p1["merkle_root"] == p2["merkle_root"]
    assert p1["signature"] == p2["signature"]


# ─────────────────────────────────────────────────────────────
# Cross-projection consistency
# ─────────────────────────────────────────────────────────────


def test_same_receipt_consistency():
    primitive, _, _ = _build()
    pd = project_attribution(primitive, "D")
    pc = project_attribution(primitive, "C")
    assert check_projection_consistency(pd, pc) == {"same_receipt": True}


def test_different_action_detected():
    issuer, pub, priv = _issuer_kp()
    p1 = construct_attribution_primitive(action=demo_action(nonce="a"), axes=demo_axes(), issuer=issuer, issuer_private_key=priv, timestamp="2026-04-12T17:42:08.342Z")
    p2 = construct_attribution_primitive(action=demo_action(nonce="b"), axes=demo_axes(), issuer=issuer, issuer_private_key=priv, timestamp="2026-04-12T17:42:08.342Z")
    r = check_projection_consistency(project_attribution(p1, "D"), project_attribution(p2, "D"))
    assert r == {"same_receipt": False, "reason": "DIFFERENT_ACTIONS"}


# ─────────────────────────────────────────────────────────────
# Residual §4.1
# ─────────────────────────────────────────────────────────────


def test_aggregate_data_axis_pools_sub_threshold():
    entries = [
        {"source_did": "did:data:big", "contribution_weight": "0.800000", "access_receipt_hash": "a" * 64},
        {"source_did": "did:data:small1", "contribution_weight": "0.000500", "access_receipt_hash": "b" * 64},
        {"source_did": "did:data:small2", "contribution_weight": "0.000400", "access_receipt_hash": "c" * 64},
    ]
    r = aggregate_data_axis(entries)
    assert r["pooled_count"] == 2
    assert r["residual"] is not None
    assert r["residual"]["residual_id"] == "residual:D"
    assert r["residual"]["count_of_pooled_contributors"] == 2


# ─────────────────────────────────────────────────────────────
# Envelope stability — byte-for-byte with TS
# ─────────────────────────────────────────────────────────────


def test_envelope_bytes_fixture_matches_ts():
    env = {
        "action_ref": "0000000000000000000000000000000000000000000000000000000000000001",
        "merkle_root": "0000000000000000000000000000000000000000000000000000000000000002",
        "issuer": "did:aps:test",
        "timestamp": "2026-04-12T17:42:08.342Z",
    }
    expected = (
        '{"action_ref":"0000000000000000000000000000000000000000000000000000000000000001",'
        '"issuer":"did:aps:test",'
        '"merkle_root":"0000000000000000000000000000000000000000000000000000000000000002",'
        '"timestamp":"2026-04-12T17:42:08.342Z"}'
    )
    assert envelope_bytes(env) == expected


# ─────────────────────────────────────────────────────────────
# Cross-language: TS constructs → Python verifies
# and Python constructs → TS verifies.
# ─────────────────────────────────────────────────────────────


TS_SDK_ROOT = os.path.expanduser("~/agent-passport-system")
CROSS_LANG_SCRIPT = os.path.join(os.path.dirname(__file__), "_cross_language_attribution.mjs")


def _have_tsx() -> bool:
    tsx = os.path.join(TS_SDK_ROOT, "node_modules/.bin/tsx")
    return os.path.isdir(TS_SDK_ROOT) and os.path.isfile(tsx)


@pytest.mark.skipif(not _have_tsx(), reason="TS SDK not available for cross-language test")
def test_cross_language_ts_to_python():
    """Call the TS SDK (via tsx) to construct a primitive; verify in Python."""
    script = os.path.join(os.path.dirname(__file__), "_cross_language_attribution_build.mjs")
    if not os.path.isfile(script):
        pytest.skip("helper script missing")
    result = subprocess.run(
        [os.path.join(TS_SDK_ROOT, "node_modules/.bin/tsx"), script],
        capture_output=True,
        text=True,
        cwd=TS_SDK_ROOT,
        check=True,
    )
    payload = json.loads(result.stdout)
    primitive = payload["primitive"]
    pub = payload["publicKey"]

    # End-to-end verify
    res = verify_attribution_primitive(primitive, pub)
    assert res == {"valid": True}, f"verification failed: {res}"

    # Per-axis projections
    for tag in ATTRIBUTION_AXIS_TAGS:
        proj = project_attribution(primitive, tag)
        assert verify_attribution_projection(proj, pub) == {"valid": True}


@pytest.mark.skipif(not _have_tsx(), reason="TS SDK not available for cross-language test")
def test_cross_language_python_to_ts():
    """Python constructs; TS SDK verifies."""
    verifier = os.path.join(os.path.dirname(__file__), "_cross_language_attribution_verify.mjs")
    if not os.path.isfile(verifier):
        pytest.skip("verifier script missing")
    issuer, pub, priv = _issuer_kp()
    primitive = construct_attribution_primitive(
        action=demo_action(),
        axes=demo_axes(),
        issuer=issuer,
        issuer_private_key=priv,
    )
    payload = json.dumps({"primitive": primitive, "publicKey": pub})
    result = subprocess.run(
        [os.path.join(TS_SDK_ROOT, "node_modules/.bin/tsx"), verifier],
        input=payload,
        capture_output=True,
        text=True,
        cwd=TS_SDK_ROOT,
        check=True,
    )
    assert result.stdout.strip() == "VALID", f"TS verifier rejected Python primitive: stdout={result.stdout!r} stderr={result.stderr!r}"
