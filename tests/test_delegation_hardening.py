# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Regression tests for the Day 128 delegation hardening (same-class sweep findings).

Each test fails on the pre-fix source: depthExceeded was hardcoded False; sub_delegate had no
temporal narrowing, did not verify the parent, and compared spend to the nominal limit instead of
remaining; create_action_receipt compared spend to the nominal limit. All are monotonic-narrowing
or no-op-enforcement violations of the stated invariants (authority only decreases per hop).
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_passport import (
    generate_key_pair, create_delegation, verify_delegation, sub_delegate,
    sign, canonicalize, create_action_receipt,
)


def _resign(d: dict, priv: str) -> dict:
    d = {k: v for k, v in d.items() if k != "signature"}
    d["signature"] = sign(canonicalize(d), priv)
    return d


def _iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _delegation(spend_limit=100, max_depth=2, expires_in_days=10, scope=("commerce:checkout",)):
    h, a = generate_key_pair(), generate_key_pair()
    d = create_delegation(
        delegated_by=h["publicKey"], delegated_to=a["publicKey"], scope=list(scope),
        private_key=h["privateKey"], spend_limit=spend_limit, max_depth=max_depth,
        expires_in_days=expires_in_days,
    )
    return d, h, a


def test_verify_flags_depth_exceeded():
    d, h, _ = _delegation(max_depth=1)
    bad = dict(d)
    bad["currentDepth"] = 3  # > maxDepth 1
    bad = _resign(bad, h["privateKey"])  # otherwise-valid signature over the bad depth
    status = verify_delegation(bad)
    assert status["depthExceeded"] is True
    assert status["valid"] is False


def test_sub_delegate_caps_child_expiry_to_parent():
    parent, _, a = _delegation(expires_in_days=1)
    child = sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                         scope=["commerce:checkout"], private_key=a["privateKey"], expires_in_days=365)
    assert _iso(child["expiresAt"]) <= _iso(parent["expiresAt"])


def test_sub_delegate_rejects_invalid_parent():
    parent, _, a = _delegation()
    tampered = dict(parent)
    tampered["signature"] = "00" * 64  # signature no longer verifies
    with pytest.raises(ValueError, match="invalid parent"):
        sub_delegate(tampered, delegated_to=generate_key_pair()["publicKey"],
                     scope=["commerce:checkout"], private_key=a["privateKey"])


def test_sub_delegate_rejects_spend_escalation():
    parent, _, a = _delegation(spend_limit=100)
    with pytest.raises(ValueError, match="escalation"):
        sub_delegate(parent, delegated_to=generate_key_pair()["publicKey"],
                     scope=["commerce:checkout"], private_key=a["privateKey"], spend_limit=101)


def test_action_receipt_uses_remaining_not_nominal_limit():
    d, h, a = _delegation(spend_limit=100)
    spent = dict(d)
    spent["spentAmount"] = 60
    spent = _resign(spent, h["privateKey"])  # a delegation that has already spent 60 of 100
    # 50 is under the nominal limit (100) but over the remaining (40): must be rejected.
    with pytest.raises(ValueError, match="Spend limit exceeded"):
        create_action_receipt(
            delegation=spent, agent_id=a["publicKey"], action_type="purchase",
            target="store", scope_used="commerce:checkout", result_status="success",
            result_summary="x", private_key=a["privateKey"], spend_amount=50,
        )
