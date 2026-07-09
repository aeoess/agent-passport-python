# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Regression: spend accumulation (record_spend).

Guards the read-but-never-written spentAmount bug: the spend gate reads spentAmount, which was
created at 0 and never incremented, so one delegation passed unlimited purchases against its cap.
record_spend is the stateless write primitive that closes the loop. The cumulative-overspend test
fails before the fix (record_spend did not exist) and passes after.
"""
import pytest
from agent_passport import create_commerce_delegation, record_spend, commerce_preflight  # noqa: F401
from agent_passport.commerce import record_spend as record_spend_direct


def _gate_passed(delegation, amount):
    # Mirror the spend gate: a purchase is within budget when amount <= remaining.
    remaining = delegation.get("spendLimit", 0) - delegation.get("spentAmount", 0)
    return amount <= remaining


def test_second_purchase_over_cap_is_denied_after_recording():
    d0 = create_commerce_delegation(agent_id="a", delegation_id="del_1", spend_limit=100)
    assert _gate_passed(d0, 60) is True
    d1 = record_spend(d0, 60)
    assert d1["spentAmount"] == 60
    assert _gate_passed(d1, 60) is False  # only 40 remaining


def test_pure_does_not_mutate_input():
    d0 = create_commerce_delegation(agent_id="a", delegation_id="del_2", spend_limit=100)
    record_spend(d0, 25)
    assert d0["spentAmount"] == 0


def test_refuses_spend_over_limit():
    d0 = create_commerce_delegation(agent_id="a", delegation_id="del_3", spend_limit=100)
    d1 = record_spend(d0, 80)
    with pytest.raises(ValueError, match="would exceed the spend limit"):
        record_spend(d1, 30)


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), float("-inf"), True, "5"])
def test_refuses_invalid_amounts(bad):
    d0 = create_commerce_delegation(agent_id="a", delegation_id="del_4", spend_limit=100)
    with pytest.raises(ValueError, match="non-negative finite number"):
        record_spend(d0, bad)


def test_accumulates_across_purchases():
    d = create_commerce_delegation(agent_id="a", delegation_id="del_5", spend_limit=100)
    d = record_spend(d, 30)
    d = record_spend(d, 30)
    d = record_spend(d, 40)
    assert d["spentAmount"] == 100
    assert _gate_passed(d, 1) is False
