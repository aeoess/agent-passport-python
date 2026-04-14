# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tests for v2 human_escalation — Python parity with the TS module."""

import json
import os
import time

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.v2.human_escalation import (
    check_escalation_required,
    request_owner_confirmation,
    record_owner_confirmation,
    verify_owner_confirmation,
    is_confirmation_valid,
    verify_v2_delegation_for_action,
    hash_action_details,
    DEFAULT_FLAGGED_ACTION_CLASSES,
)


@pytest.fixture
def keys():
    return {"owner": generate_key_pair(), "stranger": generate_key_pair()}


def _delegation(keys, requirements=None):
    """A minimal v2-shaped delegation dict — only the fields the
    escalation module reads."""
    scope = {"action_categories": ["org_creation", "spend", "read"]}
    if requirements:
        scope["escalation_requirements"] = requirements
    return {
        "id": "del-" + os.urandom(4).hex(),
        "delegator": keys["owner"]["publicKey"],
        "scope": scope,
    }


PER_ACTION = {
    "action_class": "org_creation",
    "requires_owner_confirmation": True,
    "confirmation_ttl_ms": 60_000,
    "confirmation_scope": "per_action",
}
PER_SESSION = {
    "action_class": "spend",
    "requires_owner_confirmation": True,
    "confirmation_ttl_ms": 60_000,
    "confirmation_scope": "per_session",
}
TIME_WINDOW = {
    "action_class": "org_creation",
    "requires_owner_confirmation": True,
    "confirmation_ttl_ms": 60_000,
    "confirmation_scope": "time_window",
}


def test_default_flagged_classes_present():
    for c in ("org_creation", "third_party_attribution", "spend_above_threshold",
              "charter_amendment", "delegation_scope_expansion"):
        assert c in DEFAULT_FLAGGED_ACTION_CLASSES


def test_unflagged_action_passes(keys):
    d = _delegation(keys, [])
    r = check_escalation_required(d, {"action_class": "read", "action_details": {}})
    assert r["required"] is False


def test_flagged_action_required_true(keys):
    d = _delegation(keys, [PER_ACTION])
    r = check_escalation_required(d, {"action_class": "org_creation", "action_details": {"name": "Foo"}})
    assert r["required"] is True
    assert r["requirement"]["action_class"] == "org_creation"


def test_disabled_requirement_does_not_require(keys):
    disabled = {**PER_ACTION, "requires_owner_confirmation": False}
    d = _delegation(keys, [disabled])
    r = check_escalation_required(d, {"action_class": "org_creation", "action_details": {}})
    assert r["required"] is False


def test_verify_chain_unflagged_passes(keys):
    d = _delegation(keys, [])
    r = verify_v2_delegation_for_action(d, {"action_class": "read", "action_details": {}})
    assert r["valid"] is True


def test_verify_chain_flagged_without_confirmation_fails(keys):
    d = _delegation(keys, [PER_ACTION])
    r = verify_v2_delegation_for_action(d, {"action_class": "org_creation", "action_details": {"n": 1}})
    assert r["valid"] is False
    assert r["reason"] == "action_requires_confirmation"


def test_verify_chain_flagged_with_confirmation_passes(keys):
    d = _delegation(keys, [PER_ACTION])
    action = {"action_class": "org_creation", "action_details": {"n": 1}}
    req = request_owner_confirmation(d, action)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    r = verify_v2_delegation_for_action(d, action, [conf])
    assert r["valid"] is True


def test_per_action_hash_match(keys):
    d = _delegation(keys, [PER_ACTION])
    a = {"action_class": "org_creation", "action_details": {"name": "Acme"}}
    req = request_owner_confirmation(d, a)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    assert verify_owner_confirmation(conf, a, d)["valid"] is True


def test_per_action_different_details_fails(keys):
    d = _delegation(keys, [PER_ACTION])
    a1 = {"action_class": "org_creation", "action_details": {"name": "Acme"}}
    a2 = {"action_class": "org_creation", "action_details": {"name": "Other"}}
    req = request_owner_confirmation(d, a1)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    v = verify_owner_confirmation(conf, a2, d)
    assert v["valid"] is False


def test_per_session_covers_multiple_actions(keys):
    d = _delegation(keys, [PER_SESSION])
    a1 = {"action_class": "spend", "action_details": {"amt": 10}, "session_id": "S1"}
    a2 = {"action_class": "spend", "action_details": {"amt": 20}, "session_id": "S1"}
    req = request_owner_confirmation(d, a1)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    assert verify_owner_confirmation(conf, a1, d)["valid"] is True
    assert verify_owner_confirmation(conf, a2, d)["valid"] is True


def test_per_session_rejects_other_session(keys):
    d = _delegation(keys, [PER_SESSION])
    a1 = {"action_class": "spend", "action_details": {"amt": 10}, "session_id": "S1"}
    a2 = {"action_class": "spend", "action_details": {"amt": 20}, "session_id": "S2"}
    req = request_owner_confirmation(d, a1)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    assert verify_owner_confirmation(conf, a2, d)["valid"] is False


def test_request_per_session_without_session_id_raises(keys):
    d = _delegation(keys, [PER_SESSION])
    with pytest.raises(ValueError, match="session_id"):
        request_owner_confirmation(d, {"action_class": "spend", "action_details": {}})


def test_time_window_covers_any_same_class_action(keys):
    d = _delegation(keys, [TIME_WINDOW])
    a1 = {"action_class": "org_creation", "action_details": {"n": 1}}
    a2 = {"action_class": "org_creation", "action_details": {"n": 99}}
    req = request_owner_confirmation(d, a1)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    assert verify_owner_confirmation(conf, a1, d)["valid"] is True
    assert verify_owner_confirmation(conf, a2, d)["valid"] is True


def test_expired_confirmation_fails(keys):
    short = {**TIME_WINDOW, "confirmation_ttl_ms": 1}
    d = _delegation(keys, [short])
    a = {"action_class": "org_creation", "action_details": {}}
    req = request_owner_confirmation(d, a)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["owner"]["privateKey"])
    future = int(time.time() * 1000) + 60_000
    assert is_confirmation_valid(conf, future) is False
    v = verify_owner_confirmation(conf, a, d, future)
    assert v["valid"] is False and "expired" in v["reason"]


def test_wrong_principal_signature_fails(keys):
    d = _delegation(keys, [PER_ACTION])
    a = {"action_class": "org_creation", "action_details": {"n": 1}}
    req = request_owner_confirmation(d, a)
    conf = record_owner_confirmation(request=req, delegation=d, owner_private_key=keys["stranger"]["privateKey"])
    v = verify_owner_confirmation(conf, a, d)
    assert v["valid"] is False
    assert "signature" in v["reason"]


def test_record_rejects_mismatched_delegation(keys):
    d1 = _delegation(keys, [PER_ACTION])
    d2 = _delegation(keys, [PER_ACTION])
    a = {"action_class": "org_creation", "action_details": {"n": 1}}
    req = request_owner_confirmation(d1, a)
    with pytest.raises(ValueError, match="delegation_id"):
        record_owner_confirmation(request=req, delegation=d2, owner_private_key=keys["owner"]["privateKey"])


def test_hash_action_details_deterministic():
    h1 = hash_action_details({"a": 1})
    h2 = hash_action_details({"a": 1})
    h3 = hash_action_details({"a": 2})
    assert h1 == h2 and h1 != h3


# ── Cross-language: TS-produced fixture verifies in Python ──

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "owner_confirmation_from_ts.json")


def _load_ts_fixture():
    if not os.path.exists(FIXTURE_PATH):
        pytest.xfail("fixture generation pending, TS→Python verify loop")
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_ts_fixture_owner_confirmation_verifies():
    fx = _load_ts_fixture()
    delegation = fx.get("__delegation__")
    action = fx.get("__action__")
    if delegation is None or action is None:
        pytest.xfail("fixture missing __delegation__ / __action__ blocks")
    confirmation = {k: v for k, v in fx.items() if not k.startswith("__")}
    res = verify_owner_confirmation(confirmation, action, delegation)
    assert res["valid"] is True, f"TS fixture failed Python verify: {res.get('reason')}"


def test_ts_fixture_chain_passes_with_confirmation():
    fx = _load_ts_fixture()
    delegation = fx.get("__delegation__")
    action = fx.get("__action__")
    if delegation is None or action is None:
        pytest.xfail("fixture missing __delegation__ / __action__ blocks")
    confirmation = {k: v for k, v in fx.items() if not k.startswith("__")}
    res = verify_v2_delegation_for_action(delegation, action, [confirmation])
    assert res["valid"] is True
