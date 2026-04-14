# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tests for v2 provisional_statement — Python parity with the TS module."""

import json
import os
import time

import pytest

from agent_passport.crypto import generate_key_pair, sign
from agent_passport.canonical import canonicalize
from agent_passport.v2.provisional_statement import (
    create_provisional,
    is_binding,
    verify_author_signature,
    withdraw_provisional,
    withdrawal_payload,
    promote_statement,
    process_dead_man,
    promotion_signing_payload,
    verify_promotion,
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
        "author": generate_key_pair(),
        "principal": generate_key_pair(),
        "stranger": generate_key_pair(),
    }


def _make(keys, **kw):
    return create_provisional(
        author=keys["author"]["publicKey"],
        author_principal=keys["principal"]["publicKey"],
        content=kw.get("content", "I propose X"),
        author_private_key=keys["author"]["privateKey"],
        gateway_id=kw.get("gateway_id", "gw-1"),
        dead_man_expires_at=kw.get("dead_man_expires_at"),
        id=kw.get("id"),
    )


# ── Constructor ──

def test_create_default_status_is_provisional(keys):
    s = _make(keys)
    assert s["status"] == "provisional"


def test_create_carries_author_signature_verifying(keys):
    s = _make(keys)
    assert verify_author_signature(s) is True


def test_is_binding_false_for_provisional(keys):
    s = _make(keys)
    assert is_binding(s) is False


def test_create_with_dead_man_includes_field(keys):
    s = _make(keys, dead_man_expires_at=_stamp(offset_ms=60_000, logical=99))
    assert "dead_man_expires_at" in s


# ── Withdraw ──

def test_withdraw_with_valid_author_sig(keys):
    s = _make(keys)
    sig = sign(withdrawal_payload(s["id"]), keys["author"]["privateKey"])
    out = withdraw_provisional(s, sig)
    assert out["status"] == "withdrawn"


def test_withdraw_rejects_wrong_author_sig(keys):
    s = _make(keys)
    sig = sign(withdrawal_payload(s["id"]), keys["stranger"]["privateKey"])
    with pytest.raises(ValueError, match="Invalid withdrawal"):
        withdraw_provisional(s, sig)


def test_withdraw_idempotent_on_withdrawn(keys):
    s = _make(keys)
    sig = sign(withdrawal_payload(s["id"]), keys["author"]["privateKey"])
    out1 = withdraw_provisional(s, sig)
    out2 = withdraw_provisional(out1, sig)
    assert out2["status"] == "withdrawn"


# ── Promote ──

def _promotion_for(s, principal_pub, principal_priv, *, policy_id="p1", offset_ms=100):
    promoted_at = _stamp(offset_ms=offset_ms, logical=10)
    payload = promotion_signing_payload({
        "statement_id": s["id"],
        "kind": "principal_signature",
        "promoted_at": promoted_at,
        "promoter": principal_pub,
        "policy_reference": policy_id,
    })
    return {
        "kind": "principal_signature",
        "promoted_at": promoted_at,
        "promoter": principal_pub,
        "promoter_signature": sign(payload, principal_priv),
        "policy_reference": policy_id,
    }


def test_promote_sets_status_to_promoted_and_is_binding(keys):
    s = _make(keys)
    policy = {
        "id": "p1",
        "required_signers": [keys["principal"]["publicKey"]],
        "threshold": 1,
        "max_time_to_promote": 60_000,
    }
    pe = _promotion_for(s, keys["principal"]["publicKey"], keys["principal"]["privateKey"])
    out = promote_statement(s, pe, policy)
    assert out["status"] == "promoted"
    assert is_binding(out) is True


def test_promote_rejects_dead_man_elapsed(keys):
    s = _make(keys)
    policy = {"id": "p1", "required_signers": [keys["principal"]["publicKey"]], "threshold": 1, "max_time_to_promote": 60_000}
    pe = _promotion_for(s, keys["principal"]["publicKey"], keys["principal"]["privateKey"])
    pe["kind"] = "dead_man_elapsed"
    with pytest.raises(ValueError, match="dead_man_elapsed"):
        promote_statement(s, pe, policy)


def test_promote_rejects_already_promoted(keys):
    s = _make(keys)
    policy = {"id": "p1", "required_signers": [keys["principal"]["publicKey"]], "threshold": 1, "max_time_to_promote": 60_000}
    pe = _promotion_for(s, keys["principal"]["publicKey"], keys["principal"]["privateKey"])
    out = promote_statement(s, pe, policy)
    with pytest.raises(ValueError, match="already promoted"):
        promote_statement(out, pe, policy)


# ── verify_promotion ──

def test_verify_promotion_threshold_gt_one_fails(keys):
    s = _make(keys)
    p2 = generate_key_pair()
    policy = {
        "id": "p1",
        "required_signers": [keys["principal"]["publicKey"], p2["publicKey"]],
        "threshold": 2,
        "max_time_to_promote": 60_000,
    }
    pe = _promotion_for(s, keys["principal"]["publicKey"], keys["principal"]["privateKey"])
    with pytest.raises(ValueError, match="Threshold 2"):
        promote_statement(s, pe, policy)


def test_verify_promotion_unauthorized_promoter_fails(keys):
    s = _make(keys)
    policy = {"id": "p1", "required_signers": [keys["principal"]["publicKey"]], "threshold": 1, "max_time_to_promote": 60_000}
    pe = _promotion_for(s, keys["stranger"]["publicKey"], keys["stranger"]["privateKey"])
    with pytest.raises(ValueError, match="not in policy.required_signers"):
        promote_statement(s, pe, policy)


def test_verify_promotion_exceeds_max_time_fails(keys):
    s = _make(keys)
    policy = {"id": "p1", "required_signers": [keys["principal"]["publicKey"]], "threshold": 1, "max_time_to_promote": 50}
    pe = _promotion_for(s, keys["principal"]["publicKey"], keys["principal"]["privateKey"], offset_ms=10 * 60_000)
    with pytest.raises(ValueError, match="max_time_to_promote"):
        promote_statement(s, pe, policy)


# ── process_dead_man ──

def test_process_dead_man_no_op_when_not_elapsed(keys):
    deadline = _stamp(offset_ms=60_000, logical=2)
    s = _make(keys, dead_man_expires_at=deadline)
    out = process_dead_man(s)
    assert out["status"] == "provisional"


def test_process_dead_man_transitions_to_withdrawn(keys):
    deadline = _stamp(offset_ms=-60_000, logical=2)
    s = _make(keys, dead_man_expires_at=deadline)
    future = int(time.time() * 1000) + 1
    out = process_dead_man(s, now=future)
    assert out["status"] == "withdrawn"
    assert out["promotion"]["kind"] == "dead_man_elapsed"


# ── Cross-language: TS-produced fixture verifies in Python ──

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "provisional_statement_from_ts.json")


def _load_ts_fixture():
    if not os.path.exists(FIXTURE_PATH):
        pytest.xfail("fixture generation pending, TS→Python verify loop")
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_ts_fixture_author_signature_verifies():
    s = _load_ts_fixture()
    assert verify_author_signature(s) is True


def test_ts_fixture_promotion_verifies_against_policy():
    fx = _load_ts_fixture()
    policy = fx.get("__policy__")
    if policy is None:
        pytest.xfail("fixture missing __policy__ block")
    statement = {k: v for k, v in fx.items() if not k.startswith("__")}
    res = verify_promotion(statement, policy)
    assert res["valid"] is True, f"TS fixture failed Python verify: {res['errors']}"
