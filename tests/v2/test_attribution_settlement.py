# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Build C — Settlement Pipeline property tests (Python parity).

Mirrors tests/v2/build-c-settlement.test.ts. Spec:
BUILD-C-SETTLEMENT-PIPELINE.md §'Property tests'.
"""

import copy
import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from agent_passport.crypto import public_key_from_private
from agent_passport.v2.attribution_primitive import (
    construct_attribution_primitive,
)
from agent_passport.v2.attribution_settlement import (
    aggregate_attribution_primitives,
    build_contributor_query_response,
    empty_axis_merkle_root,
    sign_settlement_record,
    verify_contributor_query_response,
    verify_settlement_record,
    verify_settlement_signature,
)


GATEWAY_PRIV = "a" * 64
GATEWAY_PUB = public_key_from_private(GATEWAY_PRIV)
GATEWAY_DID = f"did:gateway:test-{GATEWAY_PUB[:12]}"


def _iso_at(base_ms: int, offset_ms: int) -> str:
    dt = datetime.fromtimestamp((base_ms + offset_ms) / 1000.0, tz=timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def _mk_axes(rng: random.Random, *, d_sources: int, c_providers: int, g_chain: int, receipt_index: int):
    d_raw = [rng.random() for _ in range(d_sources)]
    d_sum = sum(d_raw) or 1.0
    d_norm = [r / d_sum for r in d_raw]
    d = [
        {
            "source_did": f"did:data:s-{receipt_index}-{i}",
            "contribution_weight": f"{w:.6f}",
            "access_receipt_hash": "a" * 64,
        }
        for i, w in enumerate(d_norm)
    ]
    c_raw = [rng.random() for _ in range(c_providers)]
    c_sum = sum(c_raw) or 1.0
    c_norm = [r / c_sum for r in c_raw]
    c = [
        {
            "provider_did": f"did:compute:p-{receipt_index}-{i}",
            "compute_share": f"{w:.6f}",
            "hardware_attestation_hash": "1" * 64,
        }
        for i, w in enumerate(c_norm)
    ]
    g = [
        {
            "delegation_id": f"del-{receipt_index}-{depth}",
            "signer_did": f"did:gov:root-{depth}",
            "scope_hash": "f" * 64,
            "depth": depth,
        }
        for depth in range(g_chain)
    ]
    return {"D": d, "P": [], "G": g, "C": c}


def _mk_receipt(rng, ts, i, *, d_sources=2, c_providers=2, g_chain=1):
    return construct_attribution_primitive(
        action={"agentId": f"did:agent:rng-{i}", "actionType": "generate", "params": {"i": i}, "nonce": f"nonce-{i}"},
        axes=_mk_axes(rng, d_sources=d_sources, c_providers=c_providers, g_chain=g_chain, receipt_index=i),
        issuer=GATEWAY_DID,
        issuer_private_key=GATEWAY_PRIV,
        timestamp=ts,
    )


# ─────────────────────────────────────────────────────────────
# Test 1 — Smaller-than-TS fuzz (Python's pure-Python crypto is slow)
# ─────────────────────────────────────────────────────────────


def test_build_c_test1_fuzz_conservation():
    rng = random.Random(0x51151100)
    n = 500  # downsized from TS 10k; conservation invariant is the same
    t0 = "2026-04-01T00:00:00.000Z"
    t1 = "2026-04-02T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-test-day-1"}
    base_ms = int(datetime.fromisoformat(t0[:-1]).replace(tzinfo=timezone.utc).timestamp() * 1000)

    receipts = []
    for i in range(n):
        offset_ms = int(rng.random() * (24 * 3600 * 1000 - 1))
        ts = _iso_at(base_ms, offset_ms)
        d = 1 + rng.randrange(5)
        c = 1 + rng.randrange(3)
        g = 1 + rng.randrange(3)
        receipts.append(_mk_receipt(rng, ts, i, d_sources=d, c_providers=c, g_chain=g))

    unsigned = aggregate_attribution_primitives(
        receipts, period, gateway_did=GATEWAY_DID, issued_at="2026-04-02T00:00:00.001Z"
    )
    signature = sign_settlement_record(unsigned, GATEWAY_PRIV)
    record = {**unsigned, "signature": signature}

    result = verify_settlement_record(record, gateway_public_key_hex=GATEWAY_PUB)
    assert result["valid"], f"verify failed: {result}"

    for tag in ("D", "C", "G"):
        axis = record["axes"][tag]
        total = sum(float(c["total_weight"]) for c in axis["contributors"])
        if axis.get("residual_bucket"):
            total += float(axis["residual_bucket"]["total_pooled_weight"])
        delta = abs(total - axis["total_actions"])
        assert delta <= max(1e-6, axis["total_actions"] * 5e-6), f"axis {tag} drift {delta}"


# ─────────────────────────────────────────────────────────────
# Test 2 — Contributor-query round trip
# ─────────────────────────────────────────────────────────────


def test_build_c_test2_contributor_query_roundtrip():
    rng = random.Random(0x22220002)
    t0 = "2026-04-10T00:00:00.000Z"
    t1 = "2026-04-11T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-query"}
    base_ms = int(datetime.fromisoformat(t0[:-1]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    receipts = [_mk_receipt(rng, _iso_at(base_ms, 60_000 * i), i, d_sources=2, c_providers=2, g_chain=2) for i in range(30)]
    unsigned = aggregate_attribution_primitives(
        receipts, period, gateway_did=GATEWAY_DID, issued_at="2026-04-11T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}

    for tag in ("D", "C", "G"):
        for c in record["axes"][tag]["contributors"]:
            resp = build_contributor_query_response(record, c["contributor_did"])
            assert resp, f"no response for {c['contributor_did']}"
            verdict = verify_contributor_query_response(resp, gateway_public_key_hex=GATEWAY_PUB)
            assert verdict["valid"], f"verify failed for {c['contributor_did']}: {verdict}"


# ─────────────────────────────────────────────────────────────
# Test 3 — Empty period
# ─────────────────────────────────────────────────────────────


def test_build_c_test3_empty_period():
    period = {
        "t0": "2026-04-12T00:00:00.000Z",
        "t1": "2026-04-13T00:00:00.000Z",
        "period_id": "py-empty",
    }
    unsigned = aggregate_attribution_primitives(
        [], period, gateway_did=GATEWAY_DID, issued_at="2026-04-13T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}
    verdict = verify_settlement_record(record, gateway_public_key_hex=GATEWAY_PUB)
    assert verdict["valid"], verdict
    assert record["total_input_count"] == 0
    empty_root = empty_axis_merkle_root()
    for tag in ("D", "P", "G", "C"):
        axis = record["axes"][tag]
        assert axis["contributors"] == []
        assert axis["total_actions"] == 0
        assert axis["residual_bucket"] is None
        assert axis["axis_merkle_root"] == empty_root
    assert record["input_receipts_hash"] == empty_root


# ─────────────────────────────────────────────────────────────
# Test 4 — Tampering total_weight
# ─────────────────────────────────────────────────────────────


def test_build_c_test4_tamper_total_weight():
    rng = random.Random(0x44440004)
    t0 = "2026-04-14T00:00:00.000Z"
    t1 = "2026-04-15T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-tamper-4"}
    base_ms = int(datetime.fromisoformat(t0[:-1]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    receipts = [_mk_receipt(rng, _iso_at(base_ms, i * 60_000), i) for i in range(5)]
    unsigned = aggregate_attribution_primitives(
        receipts, period, gateway_did=GATEWAY_DID, issued_at="2026-04-15T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}

    tampered = copy.deepcopy(record)
    c = tampered["axes"]["D"]["contributors"][0]
    orig = float(c["total_weight"])
    c["total_weight"] = f"{orig + 0.000001:.6f}"

    verdict = verify_settlement_record(tampered, gateway_public_key_hex=GATEWAY_PUB)
    assert not verdict["valid"]
    assert verdict["reason"] in ("MERKLE_ROOT_MISMATCH", "SIGNATURE_INVALID", "CONSERVATION_VIOLATION"), verdict

    # Corrupted signature fails S1.
    sig_tampered = copy.deepcopy(record)
    sig_tampered["signature"] = "b" * 128
    assert not verify_settlement_signature(sig_tampered, GATEWAY_PUB)


# ─────────────────────────────────────────────────────────────
# Test 5 — Swap DIDs
# ─────────────────────────────────────────────────────────────


def test_build_c_test5_swap_dids():
    rng = random.Random(0x55550005)
    t0 = "2026-04-16T00:00:00.000Z"
    t1 = "2026-04-17T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-tamper-5"}
    base_ms = int(datetime.fromisoformat(t0[:-1]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    receipts = [_mk_receipt(rng, _iso_at(base_ms, i * 1000), i, d_sources=3, c_providers=2) for i in range(4)]
    unsigned = aggregate_attribution_primitives(
        receipts, period, gateway_did=GATEWAY_DID, issued_at="2026-04-17T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}

    tampered = copy.deepcopy(record)
    assert len(tampered["axes"]["D"]["contributors"]) >= 2
    a = tampered["axes"]["D"]["contributors"][0]
    b = tampered["axes"]["D"]["contributors"][1]
    a["contributor_did"], b["contributor_did"] = b["contributor_did"], a["contributor_did"]

    verdict = verify_settlement_record(tampered, gateway_public_key_hex=GATEWAY_PUB)
    assert not verdict["valid"]
    assert verdict["reason"] == "MERKLE_ROOT_MISMATCH", verdict


# ─────────────────────────────────────────────────────────────
# Test 6 — Residual bucket round trip
# ─────────────────────────────────────────────────────────────


def test_build_c_test6_residual_bucket_roundtrip():
    t0 = "2026-04-18T00:00:00.000Z"
    t1 = "2026-04-19T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-residual-6"}
    base_ms = int(datetime.fromisoformat(t0[:-1]).replace(tzinfo=timezone.utc).timestamp() * 1000)
    receipts = []
    for i in range(8):
        axes = {
            "D": [
                {"source_did": f"did:data:big-{i}", "contribution_weight": "0.800000", "access_receipt_hash": "a" * 64},
                {
                    "residual_id": "residual:D",
                    "total_pooled_weight": "0.200000",
                    "count_of_pooled_contributors": 5,
                    "pooled_contributors_hash": "c" * 64,
                },
            ],
            "P": [],
            "G": [{"delegation_id": f"d-{i}", "signer_did": "did:gov:root", "scope_hash": "f" * 64, "depth": 0}],
            "C": [{"provider_did": f"did:compute:p-{i}", "compute_share": "1.000000", "hardware_attestation_hash": "1" * 64}],
        }
        receipts.append(construct_attribution_primitive(
            action={"agentId": "did:agent:x", "actionType": "x", "params": {"i": i}, "nonce": f"n-{i}"},
            axes=axes, issuer=GATEWAY_DID, issuer_private_key=GATEWAY_PRIV,
            timestamp=_iso_at(base_ms, i * 1000),
        ))
    unsigned = aggregate_attribution_primitives(
        receipts, period, gateway_did=GATEWAY_DID, issued_at="2026-04-19T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}

    verdict = verify_settlement_record(record, gateway_public_key_hex=GATEWAY_PUB)
    assert verdict["valid"], verdict
    bucket = record["axes"]["D"]["residual_bucket"]
    assert bucket is not None
    assert bucket["total_pooled_weight"] == "1.600000"
    assert bucket["count_of_pooled_contributors"] == 40
    assert bucket["residual_id"] == "residual:D"


# ─────────────────────────────────────────────────────────────
# Test 7 — Half-open boundary
# ─────────────────────────────────────────────────────────────


def test_build_c_test7_half_open_boundary():
    t0 = "2026-04-20T00:00:00.000Z"
    t1 = "2026-04-21T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-boundary-7"}

    def mk(ts, did_suffix, nonce):
        axes = {
            "D": [{"source_did": f"did:data:{did_suffix}", "contribution_weight": "1.000000", "access_receipt_hash": "a" * 64}],
            "P": [],
            "G": [{"delegation_id": f"d-{did_suffix}", "signer_did": f"did:gov:{did_suffix}", "scope_hash": "f" * 64, "depth": 0}],
            "C": [{"provider_did": f"did:compute:{did_suffix}", "compute_share": "1.000000", "hardware_attestation_hash": "1" * 64}],
        }
        return construct_attribution_primitive(
            action={"agentId": f"did:agent:{did_suffix}", "actionType": "x", "params": {}, "nonce": nonce},
            axes=axes, issuer=GATEWAY_DID, issuer_private_key=GATEWAY_PRIV, timestamp=ts,
        )

    at_t0 = mk(t0, "t0", "n-t0")
    at_t1 = mk(t1, "t1", "n-t1")
    just_before_t1 = mk("2026-04-20T23:59:59.999Z", "mid", "n-mid")

    unsigned = aggregate_attribution_primitives(
        [at_t0, at_t1, just_before_t1], period,
        gateway_did=GATEWAY_DID, issued_at="2026-04-21T00:00:00.001Z",
    )
    assert unsigned["total_input_count"] == 2
    d_dids = sorted(c["contributor_did"] for c in unsigned["axes"]["D"]["contributors"])
    assert d_dids == ["did:data:mid", "did:data:t0"]


# ─────────────────────────────────────────────────────────────
# Test 8 — Multi-axis contributor
# ─────────────────────────────────────────────────────────────


def test_build_c_test8_multi_axis_contributor():
    t0 = "2026-04-22T00:00:00.000Z"
    t1 = "2026-04-23T00:00:00.000Z"
    period = {"t0": t0, "t1": t1, "period_id": "py-multiaxis-8"}
    shared = "did:aeoess:hybrid-actor"

    r1 = construct_attribution_primitive(
        action={"agentId": "did:agent:r1", "actionType": "x", "params": {}, "nonce": "n1"},
        axes={
            "D": [
                {"source_did": shared, "contribution_weight": "0.600000", "access_receipt_hash": "a" * 64},
                {"source_did": "did:data:other", "contribution_weight": "0.400000", "access_receipt_hash": "b" * 64},
            ],
            "P": [],
            "G": [{"delegation_id": "d1", "signer_did": "did:gov:root", "scope_hash": "f" * 64, "depth": 0}],
            "C": [{"provider_did": "did:compute:cpu", "compute_share": "1.000000", "hardware_attestation_hash": "1" * 64}],
        },
        issuer=GATEWAY_DID, issuer_private_key=GATEWAY_PRIV,
        timestamp="2026-04-22T01:00:00.000Z",
    )
    r2 = construct_attribution_primitive(
        action={"agentId": "did:agent:r2", "actionType": "x", "params": {}, "nonce": "n2"},
        axes={
            "D": [{"source_did": "did:data:elsewhere", "contribution_weight": "1.000000", "access_receipt_hash": "c" * 64}],
            "P": [],
            "G": [{"delegation_id": "d2", "signer_did": "did:gov:root", "scope_hash": "f" * 64, "depth": 0}],
            "C": [
                {"provider_did": shared, "compute_share": "0.800000", "hardware_attestation_hash": "1" * 64},
                {"provider_did": "did:compute:other", "compute_share": "0.200000", "hardware_attestation_hash": "2" * 64},
            ],
        },
        issuer=GATEWAY_DID, issuer_private_key=GATEWAY_PRIV,
        timestamp="2026-04-22T02:00:00.000Z",
    )

    unsigned = aggregate_attribution_primitives(
        [r1, r2], period, gateway_did=GATEWAY_DID, issued_at="2026-04-23T00:00:00.001Z"
    )
    record = {**unsigned, "signature": sign_settlement_record(unsigned, GATEWAY_PRIV)}

    d = next((c for c in record["axes"]["D"]["contributors"] if c["contributor_did"] == shared), None)
    cc = next((c for c in record["axes"]["C"]["contributors"] if c["contributor_did"] == shared), None)
    assert d and cc
    assert d["total_weight"] == "0.600000"
    assert cc["total_weight"] == "0.800000"

    resp = build_contributor_query_response(record, shared)
    assert resp
    verdict = verify_contributor_query_response(resp, gateway_public_key_hex=GATEWAY_PUB)
    assert verdict["valid"], verdict
    assert "D" in resp["per_axis"] and "C" in resp["per_axis"]
