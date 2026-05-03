# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""ActionReceipt — construct + verify + cross-impl byte-parity."""

import json
from pathlib import Path

import pytest

from agent_passport.v2.accountability import (
    ActionPayload,
    ActionReceipt,
    ScopeOfClaim,
    create_action_receipt,
    verify_action_receipt,
)

PRIVATE_KEY = "11" * 32
FIXED_TS = "2026-04-30T00:00:00.000Z"
FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "wave1"
    / "accountability"
    / "action.fixture.json"
)


def _scope():
    return ScopeOfClaim(
        asserts="Agent issued an HTTP POST to the target URL.",
        does_not_assert=[
            "That the agent understood the consequences of the request.",
            "That the request was authorized by the principal.",
        ],
        capture_mode="gateway_observed",
        completeness="complete",
        self_attested=False,
    )


def _base_input():
    return dict(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        agent_did="did:aps:test-agent-001",
        delegation_chain_root="a" * 64,
        action=ActionPayload(kind="http_request", target="https://example.com/api/v1/users"),
        side_effect_classes=["external_message", "data_modification"],
    )


def test_round_trips_through_verify():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    v = verify_action_receipt(r)
    assert v["valid"] is True
    assert v["reason"] is None


def test_deterministic_for_identical_inputs():
    a = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    b = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    assert a.receipt_id == b.receipt_id
    assert a.signature == b.signature


def test_claim_type_locked():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    assert r.claim_type == "aps:action:v1"


def test_tampered_target_yields_receipt_id_mismatch():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    r.action = ActionPayload(kind=r.action.kind, target="https://attacker.example/api/v1/users")
    v = verify_action_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "RECEIPT_ID_MISMATCH"


def test_tampered_signature_yields_signature_invalid():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    last = r.signature[-1]
    r.signature = r.signature[:-1] + ("1" if last == "0" else "0")
    v = verify_action_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "SIGNATURE_INVALID"


def test_wrong_claim_type_invalid():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    r.claim_type = "aps:other:v1"
    v = verify_action_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "INVALID_CLAIM_TYPE"


def test_tampered_scope_yields_receipt_id_mismatch():
    r = create_action_receipt(**_base_input(), signer_private_key=PRIVATE_KEY)
    r.scope_of_claim = ScopeOfClaim(
        asserts="Different assertion text.",
        does_not_assert=r.scope_of_claim.does_not_assert,
        capture_mode=r.scope_of_claim.capture_mode,
        completeness=r.scope_of_claim.completeness,
        self_attested=r.scope_of_claim.self_attested,
    )
    v = verify_action_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "RECEIPT_ID_MISMATCH"


# ── Cross-impl byte-parity ─────────────────────────────────────────────


def _load_fixture_as_dataclass(fixture_path):
    """Reconstruct an ActionReceipt from the TS-issued fixture JSON."""
    f = json.loads(Path(fixture_path).read_text())
    s = f["scope_of_claim"]
    a = f["action"]
    return ActionReceipt(
        claim_type=f["claim_type"],
        receipt_id=f["receipt_id"],
        timestamp=f["timestamp"],
        signer_did=f["signer_did"],
        scope_of_claim=ScopeOfClaim(
            asserts=s["asserts"],
            does_not_assert=s["does_not_assert"],
            capture_mode=s["capture_mode"],
            completeness=s["completeness"],
            self_attested=s["self_attested"],
        ),
        agent_did=f["agent_did"],
        delegation_chain_root=f["delegation_chain_root"],
        action=ActionPayload(
            kind=a["kind"],
            target=a["target"],
            parameters=a.get("parameters"),
            resource_version=a.get("resource_version"),
        ),
        side_effect_classes=f["side_effect_classes"],
        intent_ref=f.get("intent_ref"),
        policy_ref=f.get("policy_ref"),
        transparency_log_inclusion=None,
        rfc3161_timestamp=f.get("rfc3161_timestamp"),
        signature=f["signature"],
    )


def test_ts_fixture_verifies_against_python_byte_parity():
    """Cross-impl byte-parity: the TS-issued action.fixture.json must
    verify against the Python verifier without any bytes drifting.
    """
    receipt = _load_fixture_as_dataclass(FIXTURE)
    v = verify_action_receipt(receipt)
    assert v["valid"] is True, f"byte-parity drift detected: {v}"
