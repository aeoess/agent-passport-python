# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Regression (round-3): the commerce spend gate must check currency.

commerce_preflight's spend_limit gate compared amounts without checking currency, so a EUR purchase
passed a USD budget (the SDK does no conversion). It now denies a declared currency mismatch.
"""
from agent_passport import create_passport, create_commerce_delegation, commerce_preflight


def _passport():
    r = create_passport(
        agent_id="shopper-ccy", agent_name="Shopper", owner_alias="tima", mission="buy",
        capabilities=["web_search"],
        runtime={"platform": "python", "models": [], "toolsCount": 1, "memoryType": "none"},
    )
    return r["signedPassport"]


def _spend_check(sp, deleg, total):
    result = commerce_preflight(signed_passport=sp, delegation=deleg, merchant_name="TestShop", estimated_total=total)
    return next(c for c in result["checks"] if c["check"] == "spend_limit")


def test_denies_foreign_currency_purchase():
    sp = _passport()
    deleg = create_commerce_delegation(agent_id="shopper-ccy", delegation_id="del-1", spend_limit=1000, currency="usd", approved_merchants=["TestShop"])
    chk = _spend_check(sp, deleg, {"amount": 50, "currency": "eur"})
    assert chk["passed"] is False
    assert "Currency mismatch" in chk["detail"]


def test_allows_same_currency_case_insensitive():
    sp = _passport()
    deleg = create_commerce_delegation(agent_id="shopper-ccy", delegation_id="del-1", spend_limit=1000, currency="usd", approved_merchants=["TestShop"])
    assert _spend_check(sp, deleg, {"amount": 50, "currency": "USD"})["passed"] is True


def test_still_enforces_amount_in_matching_currency():
    sp = _passport()
    deleg = create_commerce_delegation(agent_id="shopper-ccy", delegation_id="del-1", spend_limit=100, currency="usd", approved_merchants=["TestShop"])
    assert _spend_check(sp, deleg, {"amount": 500, "currency": "usd"})["passed"] is False
