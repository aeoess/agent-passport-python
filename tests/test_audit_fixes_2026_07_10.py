# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the 2026-07-10 audit fixes.

Covers: Z-timestamp expiry parsing + fail-closed, ECMAScript number
serialization, UTF-16 key ordering, and action_ref naive-timestamp rejection.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agent_passport._time import parse_iso_utc
from agent_passport.canonical import _es_number, canonicalize_jcs, canonicalize
from agent_passport.delegation import create_delegation, verify_delegation
from agent_passport.passport import is_expired
from agent_passport.crypto import generate_key_pair
from agent_passport.action_ref import compute_action_ref


def test_parse_iso_utc_accepts_Z():
    dt = parse_iso_utc("2026-01-01T00:00:00Z")
    assert dt.tzinfo is not None and dt.utcoffset() == timedelta(0)


def test_expired_Z_delegation_is_rejected():
    kp = generate_key_pair()
    d = create_delegation(kp["publicKey"], "did:aps:recipient", ["scope:x"],
                          kp["privateKey"], expires_in_days=1)
    # Force an already-past Z-form expiry (the TS/SDK standard shape).
    d["expiresAt"] = "2000-01-01T00:00:00Z"
    d["signature"] = ""  # signature is checked separately; we assert the expiry gate
    status = verify_delegation(d)
    assert status["expired"] is True


def test_unparseable_expiry_fails_closed():
    assert is_expired({"expiresAt": "not-a-timestamp"}) is True
    kp = generate_key_pair()
    d = create_delegation(kp["publicKey"], "did:aps:r", ["s:x"], kp["privateKey"])
    d["expiresAt"] = "garbage"
    assert verify_delegation(d)["expired"] is True


def test_valid_future_Z_passport_not_expired():
    future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert is_expired({"expiresAt": future}) is False


# ECMAScript Number::toString table (validated against Node JSON.stringify).
ES_CASES = [
    (1e21, "1e+21"), (1.5e21, "1.5e+21"), (1e-6, "0.000001"), (1e-7, "1e-7"),
    (1e-8, "1e-8"), (0.1, "0.1"), (100.5, "100.5"), (1e16, "10000000000000000"),
    (5e-324, "5e-324"), (1e308, "1e+308"), (-0.0001, "-0.0001"), (6.022e23, "6.022e+23"),
    (0.0, "0"), (-0.0, "0"), (1.0, "1"),
]


@pytest.mark.parametrize("value,expected", ES_CASES)
def test_es_number(value, expected):
    assert _es_number(value) == expected


def test_utf16_key_order_matches_ts():
    # Empty string first, then digits, upper, lower, astral (D834...) before U+FF61.
    obj = {"\U0001D306": 2, "": 1, "b": 3, "a": 4, "｡": 5, "Z": 6, "10": 7, "2": 8}
    out = canonicalize_jcs(obj)
    assert out.index('"":') < out.index('"10":') < out.index('"2":') < out.index('"Z":')
    assert out.index('"b":') < out.index('"\U0001D306":') < out.index('"｡":')


def test_float_canonical_matches_es():
    assert canonicalize_jcs({"a": 1e-7, "b": 1e21}) == '{"a":1e-7,"b":1e+21}'
    assert canonicalize({"a": 0.000001}) == '{"a":0.000001}'


def test_action_ref_rejects_naive_timestamp():
    with pytest.raises(ValueError):
        compute_action_ref("did:aps:a", "act", ["s:r"], "2026-01-01T12:00:00")


def test_action_ref_accepts_zoned():
    ref = compute_action_ref("did:aps:a", "act", ["s:r"], "2026-01-01T12:00:00Z")
    assert len(ref) == 64 and all(c in "0123456789abcdef" for c in ref)
