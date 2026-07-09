# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance + cross-SDK interop for the Python CompositionCheckReceipt v0 verifier.

The vectors in conformance/composition-check/v0/vectors.json were generated and SIGNED by
the TypeScript SDK. Verifying them here proves BOTH Python parity (matching hand-specified
expectations) AND TS -> Python signature interop in one pass. Expectations are hand-specified
in the vectors (not computed by this verifier), so the test is non-circular.
"""
import json
import math
import os

import pytest

from agent_passport import (
    COMPOSITION_CHECK_RESULTS,
    composition_check_signing_payload,
    verify_composition_check,
)
from agent_passport.crypto import generate_key_pair, sign

_VECTORS = json.load(
    open(
        os.path.join(os.path.dirname(__file__), "..", "conformance", "composition-check", "v0", "vectors.json"),
        encoding="utf-8",
    )
)


def test_vector_count():
    assert _VECTORS["count"] == len(_VECTORS["vectors"])
    assert len(_VECTORS["vectors"]) >= 6


@pytest.mark.parametrize("vec", _VECTORS["vectors"], ids=[v["id"] for v in _VECTORS["vectors"]])
def test_ts_signed_vector_verifies_under_python(vec):
    """Each TS-signed vector verifies under the Python verifier with the hand-specified result."""
    r = verify_composition_check(vec["input_receipt"], vec["verification_context"])
    exp = vec["expected"]
    assert r["anchor_verified"] == exp["anchor_verified"], f"{vec['id']} anchor_verified"
    for need in exp["violations_include"]:
        assert need in r["violations"], f"{vec['id']} expected violation {need}, got {r['violations']}"
    if r["anchor_verified"]:
        assert r["violations"] == [], f"{vec['id']} accepted receipt must have no violations"
    if "independence_is_second_anchor" in exp:
        assert r["independence_is_second_anchor"] == exp["independence_is_second_anchor"], f"{vec['id']} independence"


def test_no_safe_field_in_any_output():
    for vec in _VECTORS["vectors"]:
        r = verify_composition_check(vec["input_receipt"], vec["verification_context"])
        offending = [k for k in r if "safe" in k.lower()]
        assert offending == [], f"{vec['id']} output must not carry any 'safe' field, got {offending}"
        for k in ("safe", "composition_safe", "is_safe", "globally_safe"):
            assert k not in r


def test_result_enum_has_no_safe_member():
    assert sorted(COMPOSITION_CHECK_RESULTS) == ["fail", "indeterminate", "not_checked", "pass"]
    assert all("safe" not in m for m in COMPOSITION_CHECK_RESULTS)


def test_gateway_self_is_never_a_second_anchor():
    for vec in _VECTORS["vectors"]:
        r = verify_composition_check(vec["input_receipt"], vec["verification_context"])
        if r["attestor_independence_class"] == "gateway_self":
            assert r["independence_is_second_anchor"] is False


def test_strong_requires_context_corroboration_not_self_declaration():
    by_id = {v["id"]: v for v in _VECTORS["vectors"]}
    r1 = verify_composition_check(by_id["V01"]["input_receipt"], by_id["V01"]["verification_context"])
    r7 = verify_composition_check(by_id["V07"]["input_receipt"], by_id["V07"]["verification_context"])
    assert r1["attestor_independence_class"] == "independent_registered"
    assert r7["attestor_independence_class"] == "independent_registered"
    assert r1["independence_is_second_anchor"] is True  # corroborated
    assert r7["independence_is_second_anchor"] is False  # uncorroborated self-claim -> downgraded


def test_f1_independence_gated_on_anchor_verified():
    # V09: expired but independent attestor -> anchor fails, so NOT a usable second anchor.
    v09 = next(v for v in _VECTORS["vectors"] if v["id"] == "V09")
    r = verify_composition_check(v09["input_receipt"], v09["verification_context"])
    assert r["anchor_verified"] is False
    assert r["attestor_independence_class"] == "independent_registered"
    assert r["independence_is_second_anchor"] is False


def test_f2_non_finite_now_ms_fails_closed():
    v09 = next(v for v in _VECTORS["vectors"] if v["id"] == "V09")
    for bad_now in (None, math.nan):
        ctx = dict(v09["verification_context"])
        ctx["now_ms"] = bad_now
        r = verify_composition_check(v09["input_receipt"], ctx)
        assert r["anchor_verified"] is False
        assert "now_malformed" in r["violations"], f"now_ms={bad_now!r} must fail closed"


def test_python_roundtrip_sign_then_verify():
    """A Python-signed receipt verifies under the Python verifier (envelope round-trip)."""
    att = generate_key_pair()
    receipt = {
        "profile": "aps-composition-check-v0",
        "receipt_id": "py-rt-1",
        "chain_hash": "c",
        "action_ref": "a",
        "context_hash": "x",
        "policy_profile_ids": ["p-v1"],
        "checks_run": ["p-v1:c1"],
        "result_per_check": ["pass"],
        "attestor_key_id": "k1",
        "attestor_independence_class": "independent_registered",
        "issued_at": "2026-06-29T00:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z",
    }
    receipt["signature"] = sign(composition_check_signing_payload(receipt), att["privateKey"])
    ctx = {
        "trusted_attestors": {"k1": {"publicKey": att["publicKey"], "registered_by_operator": False, "profiles": ["p-v1"]}},
        "expected_chain_hash": "c",
        "expected_action_ref": "a",
        "expected_context_hash": "x",
        "now_ms": 1790000000000,  # ~Sep 2026: within [issued_at 2026-06-29, expires_at 2099]
    }
    r = verify_composition_check(receipt, ctx)
    assert r["anchor_verified"] is True
    assert r["independence_is_second_anchor"] is True
    assert r["violations"] == []
