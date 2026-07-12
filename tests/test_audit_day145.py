# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Day-145 audit fixes.

C1 (passport.py): an expired passport with a valid signature must be
    INVALID — expiry is an error, not a mere warning (matches the TS
    reference verifyPassport and the repo's verify_delegation).
C2 (canonical.py): a signed-shaped object carrying a NaN/Infinity numeric
    field must make the verifier return valid=False WITHOUT raising, rather
    than crashing inside canonicalize().
"""

from agent_passport import (
    create_passport,
    verify_passport,
    generate_key_pair,
)
from agent_passport.delegation import create_delegation, verify_delegation


RUNTIME = {
    "platform": "python-test",
    "models": ["test-model"],
    "toolsCount": 1,
    "memoryType": "session",
}


def _signed_passport(expires_in_days: int = 365) -> dict:
    return create_passport(
        agent_id="day145-agent",
        agent_name="Day145",
        owner_alias="tester",
        mission="audit regression",
        capabilities=["web_search"],
        runtime=RUNTIME,
        expires_in_days=expires_in_days,
    )["signedPassport"]


# --- C1: expiry is an error, not a warning ---------------------------------

def test_expired_passport_with_valid_signature_is_invalid():
    # Signed while already expired, so the signature is genuinely valid over
    # the (expired) passport bytes — the ONLY thing making it invalid is expiry.
    signed = _signed_passport(expires_in_days=-1)
    check = verify_passport(signed)
    assert check["valid"] is False
    assert any("expired" in e.lower() for e in check["errors"]), check["errors"]
    assert check["passport"] is None


def test_unexpired_passport_still_valid():
    signed = _signed_passport(expires_in_days=365)
    check = verify_passport(signed)
    assert check["valid"] is True
    assert check["errors"] == []


# --- C2: non-finite numeric field fails closed, does not raise -------------

def test_non_finite_passport_field_fails_closed_without_raising():
    signed = _signed_passport()
    # Poison a numeric field with a non-finite float. json.loads would accept
    # this by default; canonicalize() rejects it — the verifier must not crash.
    signed["passport"]["metadata"] = {"score": float("nan")}
    check = verify_passport(signed)  # must not raise
    assert check["valid"] is False


def test_non_finite_delegation_field_fails_closed_without_raising():
    kp = generate_key_pair()
    d = create_delegation(
        kp["publicKey"], "did:aps:recipient", ["scope:x"], kp["privateKey"]
    )
    d["metadata"] = {"weight": float("inf")}
    status = verify_delegation(d)  # must not raise
    assert status["valid"] is False
