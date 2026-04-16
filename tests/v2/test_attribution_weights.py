# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Build B — Fractional Weights property tests (Python parity).

Mirrors tests/v2/build-b-fractional-weights.test.ts. Spec:
BUILD-B-FRACTIONAL-WEIGHTS.md § 'Property tests'.
"""

import math
import random
from datetime import datetime, timedelta, timezone

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.v2.attribution_primitive import (
    construct_attribution_primitive,
    project_attribution,
    verify_attribution_projection,
    aggregate_data_axis,
)
from agent_passport.v2.attribution_weights import (
    ATTRIBUTION_ROLES,
    DEFAULT_WEIGHT_PROFILE,
    compute_compute_axis_weights,
    compute_data_axis_weights,
    hash_weight_profile,
    recency_decay,
    validate_weight_profile,
)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _rand_source(rng: random.Random, action_ms: float, i: int):
    age_ms = rng.random() * 90 * 86_400_000
    ts = datetime.fromtimestamp((action_ms - age_ms) / 1000.0, tz=timezone.utc)
    ms = ts.microsecond // 1000
    return {
        "source_did": f"did:data:src-{i}-{rng.randrange(10**9)}",
        "access_receipt_hash": "a" * 64,
        "role": ATTRIBUTION_ROLES[rng.randrange(len(ATTRIBUTION_ROLES))],
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z",
        "content_length": 1 + rng.randrange(50_000),
    }


def _rand_provider(rng: random.Random, i: int):
    return {
        "provider_did": f"did:compute:prv-{i}-{rng.randrange(10**9)}",
        "hardware_attestation_hash": "1" * 64,
        "prompt_tokens": rng.randrange(10_000),
        "completion_tokens": rng.randrange(10_000),
    }


def _sum_weights(entries, field):
    return sum(float(e[field]) for e in entries)


ACTION_TS = "2026-04-16T12:00:00.000Z"
ACTION_MS = datetime.fromisoformat("2026-04-16T12:00:00+00:00").timestamp() * 1000.0


# ─────────────────────────────────────────────────────────────
# I-B1, I-B2: sum-to-one (1e5 trials)
# ─────────────────────────────────────────────────────────────


def test_i_b1_d_axis_sum_to_one_over_1e5_trials():
    rng = _rng(0xB1B1B1B1)
    worst = 0.0
    for i in range(100_000):
        n = 1 + rng.randrange(100)
        sources = [_rand_source(rng, ACTION_MS, j) for j in range(n)]
        weights = compute_data_axis_weights(sources, action_timestamp=ACTION_TS)
        total = _sum_weights(weights, "contribution_weight")
        diff = abs(total - 1.0)
        worst = max(worst, diff)
        # After 6-digit rounding each of N terms errs by up to 5e-7.
        bound = n * 5e-7 + 1e-12
        assert diff <= bound, f"trial {i}: sum={total} diff={diff} n={n} bound={bound}"
    assert worst < 1e-4


def test_i_b2_c_axis_sum_to_one_over_1e5_trials():
    rng = _rng(0xC2C2C2C2)
    worst = 0.0
    for i in range(100_000):
        n = 1 + rng.randrange(100)
        providers = [_rand_provider(rng, j) for j in range(n)]
        if all(p["prompt_tokens"] == 0 and p["completion_tokens"] == 0 for p in providers):
            providers[0]["prompt_tokens"] = 1
        weights = compute_compute_axis_weights(providers)
        total = _sum_weights(weights, "compute_share")
        diff = abs(total - 1.0)
        worst = max(worst, diff)
        bound = n * 5e-7 + 1e-12
        assert diff <= bound, f"trial {i}: sum={total} diff={diff} n={n} bound={bound}"
    assert worst < 1e-4


def test_i_b1_strict_raw_ratios_sum_to_one_within_1e_9():
    # Spec I-B1: sum within 1e-9 at IEEE-754 double precision.
    rng = _rng(0xD1D1D1D1)
    for i in range(10_000):
        n = 1 + rng.randrange(50)
        sources = [_rand_source(rng, ACTION_MS, j) for j in range(n)]
        raws = []
        for s in sources:
            r = DEFAULT_WEIGHT_PROFILE["role_weights"][s["role"]]
            dec = recency_decay(ACTION_TS, s["timestamp"], DEFAULT_WEIGHT_PROFILE)
            ln = math.log(1 + s["content_length"]) / math.log(1 + 1000)
            raws.append(r * dec * ln)
        total = sum(raws)
        if total <= 0:
            continue
        sum_ratios = sum(x / total for x in raws)
        assert abs(sum_ratios - 1) < 1e-9, f"trial {i}: {sum_ratios}"


# ─────────────────────────────────────────────────────────────
# I-B3: empty-axis handling, malformed all-zero rejected
# ─────────────────────────────────────────────────────────────


def test_i_b3_empty_d():
    assert compute_data_axis_weights([], action_timestamp=ACTION_TS) == []


def test_i_b3_empty_c():
    assert compute_compute_axis_weights([]) == []


def test_i_b3_all_zero_d_rejected():
    src = {
        "source_did": "did:data:x",
        "access_receipt_hash": "0" * 64,
        "role": "primary_source",
        "timestamp": ACTION_TS,
        "content_length": 0,
    }
    with pytest.raises(ValueError, match="total D-axis raw weight is zero"):
        compute_data_axis_weights([src], action_timestamp=ACTION_TS)


def test_i_b3_all_zero_c_rejected():
    prv = {
        "provider_did": "did:compute:x",
        "hardware_attestation_hash": "0" * 64,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }
    with pytest.raises(ValueError, match="total C-axis raw weight is zero"):
        compute_compute_axis_weights([prv])


# ─────────────────────────────────────────────────────────────
# I-B5: insertion-order invariance
# ─────────────────────────────────────────────────────────────


def test_i_b5_ordering_invariance():
    a = {"source_did": "did:data:A", "access_receipt_hash": "a" * 64, "role": "primary_source", "timestamp": "2026-04-10T00:00:00.000Z", "content_length": 800}
    b = {"source_did": "did:data:B", "access_receipt_hash": "b" * 64, "role": "supporting_evidence", "timestamp": "2026-04-12T00:00:00.000Z", "content_length": 1200}
    c = {"source_did": "did:data:C", "access_receipt_hash": "c" * 64, "role": "context_only", "timestamp": "2026-04-14T00:00:00.000Z", "content_length": 200}
    weights_by_did = {}
    for order in ([a, b, c], [c, b, a], [b, c, a], [a, c, b]):
        out = compute_data_axis_weights(order, action_timestamp=ACTION_TS)
        for e in out:
            weights_by_did.setdefault(e["source_did"], set()).add(e["contribution_weight"])
    for did, ws in weights_by_did.items():
        assert len(ws) == 1, f"{did}: {ws}"


def test_i_b5_identical_inputs_identical_weights():
    base = {"access_receipt_hash": "a" * 64, "role": "primary_source", "timestamp": "2026-04-16T00:00:00.000Z", "content_length": 500}
    sources = [
        {**base, "source_did": "did:data:aaa", "access_receipt_hash": "a" * 64},
        {**base, "source_did": "did:data:bbb", "access_receipt_hash": "b" * 64},
        {**base, "source_did": "did:data:ccc", "access_receipt_hash": "c" * 64},
    ]
    out = compute_data_axis_weights(sources, action_timestamp=ACTION_TS)
    assert len({e["contribution_weight"] for e in out}) == 1


# ─────────────────────────────────────────────────────────────
# Length-scaling invariance (spec property test 4)
# ─────────────────────────────────────────────────────────────


def test_uniform_length_scale_preserves_rank():
    base = [
        {"source_did": "did:data:a", "access_receipt_hash": "a" * 64, "role": "primary_source", "timestamp": "2026-04-10T00:00:00.000Z", "content_length": 500},
        {"source_did": "did:data:b", "access_receipt_hash": "b" * 64, "role": "supporting_evidence", "timestamp": "2026-04-11T00:00:00.000Z", "content_length": 800},
        {"source_did": "did:data:c", "access_receipt_hash": "c" * 64, "role": "context_only", "timestamp": "2026-04-12T00:00:00.000Z", "content_length": 200},
    ]
    doubled = [{**s, "content_length": s["content_length"] * 2} for s in base]
    w1 = compute_data_axis_weights(base, action_timestamp=ACTION_TS)
    w2 = compute_data_axis_weights(doubled, action_timestamp=ACTION_TS)
    rank1 = [x["source_did"] for x in sorted(w1, key=lambda x: -float(x["contribution_weight"]))]
    rank2 = [x["source_did"] for x in sorted(w2, key=lambda x: -float(x["contribution_weight"]))]
    assert rank1 == rank2


# ─────────────────────────────────────────────────────────────
# Recency invariant (spec property test 5)
# ─────────────────────────────────────────────────────────────


def test_one_day_old_decay_at_least_0_977():
    d = recency_decay(ACTION_TS, "2026-04-15T12:00:00.000Z", DEFAULT_WEIGHT_PROFILE)
    assert d >= 0.977


def test_min_recency_floor():
    d = recency_decay("2027-04-16T12:00:00.000Z", "2010-01-01T00:00:00.000Z", DEFAULT_WEIGHT_PROFILE)
    assert d == DEFAULT_WEIGHT_PROFILE["recency"]["min_recency"]


# ─────────────────────────────────────────────────────────────
# I-B4: residual bucket preserves pre-threshold weights
# ─────────────────────────────────────────────────────────────


def test_i_b4_residual_sum_equals_pooled_pre_threshold_weight():
    dominant = {
        "source_did": "did:data:dominant",
        "access_receipt_hash": "d" * 64,
        "role": "primary_source",
        "timestamp": "2026-04-16T00:00:00.000Z",
        "content_length": 100_000,
    }
    tail = [
        {
            "source_did": f"did:data:tail-{i:04d}",
            "access_receipt_hash": str(i).zfill(64),
            "role": "background_retrieval",
            "timestamp": "2025-12-01T00:00:00.000Z",
            "content_length": 1,
        }
        for i in range(1500)
    ]
    weights = compute_data_axis_weights([dominant] + tail, action_timestamp=ACTION_TS)
    agg = aggregate_data_axis(weights, min_weight=0.001)
    assert agg["residual"] is not None
    pooled = [e for e in weights if float(e["contribution_weight"]) < 0.001]
    expected = sum(float(e["contribution_weight"]) for e in pooled)
    reported = float(agg["residual"]["total_pooled_weight"])
    assert abs(reported - expected) < 1e-6, f"residual={reported} expected={expected}"
    assert agg["residual"]["count_of_pooled_contributors"] == len(pooled)


# ─────────────────────────────────────────────────────────────
# I-B6: profile hash binding
# ─────────────────────────────────────────────────────────────


def test_i_b6_profile_hash_stable_and_discriminating():
    h0 = hash_weight_profile(DEFAULT_WEIGHT_PROFILE)
    assert h0 == hash_weight_profile(DEFAULT_WEIGHT_PROFILE)
    assert len(h0) == 64

    import copy

    variants = []
    for mutator in [
        lambda p: p.__setitem__("version", "v0.2"),
        lambda p: p["role_weights"].__setitem__("primary_source", 0.95),
        lambda p: p["recency"].__setitem__("tau_days", 60),
        lambda p: p["length"].__setitem__("reference_length", 2000),
        lambda p: p["compute"].__setitem__("completion_multiplier", 4.0),
    ]:
        p = copy.deepcopy(DEFAULT_WEIGHT_PROFILE)
        mutator(p)
        variants.append(p)
    for v in variants:
        assert hash_weight_profile(v) != h0


def test_validate_weight_profile_rejects_bad():
    import copy

    bad = copy.deepcopy(DEFAULT_WEIGHT_PROFILE)
    bad["recency"]["tau_days"] = -1
    result = validate_weight_profile(bad)
    assert not result["valid"]
    assert any("tau_days" in e for e in result["errors"])


# ─────────────────────────────────────────────────────────────
# Build A + Build B integration test
# ─────────────────────────────────────────────────────────────


def test_integration_compute_then_construct_project_verify():
    kp = generate_key_pair()
    pub = kp["publicKey"]
    priv = kp["privateKey"]
    sources = [
        {"source_did": "did:data:kff-2025", "access_receipt_hash": "a" * 64, "role": "primary_source", "timestamp": "2026-04-15T00:00:00.000Z", "content_length": 3500},
        {"source_did": "did:data:cms-archive", "access_receipt_hash": "b" * 64, "role": "supporting_evidence", "timestamp": "2026-04-10T00:00:00.000Z", "content_length": 1200},
        {"source_did": "did:data:news-blurb", "access_receipt_hash": "c" * 64, "role": "context_only", "timestamp": "2026-04-14T00:00:00.000Z", "content_length": 400},
    ]
    providers = [
        {"provider_did": "did:compute:anthropic", "hardware_attestation_hash": "1" * 64, "prompt_tokens": 1200, "completion_tokens": 800},
        {"provider_did": "did:compute:openai", "hardware_attestation_hash": "2" * 64, "prompt_tokens": 900, "completion_tokens": 600},
    ]

    D = compute_data_axis_weights(sources, action_timestamp=ACTION_TS)
    C = compute_compute_axis_weights(providers)
    # Canonical 6-digit strings.
    import re

    for e in D:
        assert re.match(r"^\d+\.\d{6}$", e["contribution_weight"])
    for e in C:
        assert re.match(r"^\d+\.\d{6}$", e["compute_share"])

    primitive = construct_attribution_primitive(
        action={
            "agentId": "did:aps:agent-alpha",
            "actionType": "query.summarize",
            "params": {"topic": "healthcare-reform-march-2026"},
            "nonce": "77777777-7777-7777-7777-777777777777",
        },
        axes={
            "D": D,
            "P": [{"module_id": "redact-pii", "module_version": "2.3.1", "evaluation_outcome": "approved", "evaluation_receipt_hash": "e" * 64}],
            "G": [
                {"delegation_id": "delegation:root", "signer_did": "did:aps:customer", "scope_hash": "f" * 64, "depth": 0},
                {"delegation_id": "delegation:agent", "signer_did": "did:aps:agent-alpha", "scope_hash": "e" * 64, "depth": 1},
            ],
            "C": C,
        },
        issuer="did:aps:issuer-test",
        issuer_private_key=priv,
        timestamp=ACTION_TS,
    )
    projection = project_attribution(primitive, "D")
    verdict = verify_attribution_projection(projection, pub)
    assert verdict["valid"], verdict.get("reason")

    axis_d = projection["axis_data"]
    assert len(axis_d) == len(D)
    for original in D:
        match = next(x for x in axis_d if x["source_did"] == original["source_did"])
        assert match["contribution_weight"] == original["contribution_weight"]
        assert match["access_receipt_hash"] == original["access_receipt_hash"]
