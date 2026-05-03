# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""CustodyReceipt — construct + verify + cross-impl byte-parity."""

import json
from pathlib import Path

import pytest

from agent_passport.v2.accountability import (
    CustodyReceipt,
    ScopeOfClaim,
    SubjectReceiptBatch,
    create_custody_receipt,
    verify_custody_receipt,
)

PRIVATE_KEY = "33" * 32
FIXED_TS = "2026-04-30T00:00:00.000Z"
FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "wave1"
    / "accountability"
    / "custody.fixture.json"
)


def _scope():
    return ScopeOfClaim(
        asserts="Custodian held the named receipt batch at the named time.",
        does_not_assert=["That the underlying receipts are factually correct."],
        capture_mode="self_attested",
        completeness="complete",
        self_attested=True,
    )


def _base_input(**overrides):
    base = dict(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        custodian_did="did:aps:custodian-001",
        event_type="created",
        subject_receipt_batch=SubjectReceiptBatch(merkle_root="a" * 64, count=3),
        purpose="internal_audit",
    )
    base.update(overrides)
    return base


def test_round_trip_basic():
    r = create_custody_receipt(**_base_input(), custodian_private_key=PRIVATE_KEY)
    v = verify_custody_receipt(r)
    assert v["valid"] is True


def test_chained_custody_via_previous_id():
    r = create_custody_receipt(
        **_base_input(previous_custody_id="prev" + "0" * 60),
        custodian_private_key=PRIVATE_KEY,
    )
    v = verify_custody_receipt(r)
    assert v["valid"] is True


def test_transferred_with_next_custodian():
    r = create_custody_receipt(
        **_base_input(event_type="transferred", next_custodian_did="did:aps:next"),
        custodian_private_key=PRIVATE_KEY,
    )
    v = verify_custody_receipt(r)
    assert v["valid"] is True


@pytest.mark.parametrize(
    "event",
    ["created", "sealed", "transferred", "disclosed", "redacted", "erased", "expired", "verified"],
)
def test_all_event_types_verify(event):
    r = create_custody_receipt(**_base_input(event_type=event), custodian_private_key=PRIVATE_KEY)
    v = verify_custody_receipt(r)
    assert v["valid"] is True, f"event={event} did not verify: {v}"


@pytest.mark.parametrize(
    "purpose",
    [
        "internal_audit",
        "regulator_disclosure",
        "subject_access",
        "litigation_discovery",
        "vendor_handoff",
        "archival",
        "incident_response",
    ],
)
def test_all_purposes_verify(purpose):
    r = create_custody_receipt(**_base_input(purpose=purpose), custodian_private_key=PRIVATE_KEY)
    v = verify_custody_receipt(r)
    assert v["valid"] is True


def test_invalid_event_type_rejected():
    r = create_custody_receipt(**_base_input(), custodian_private_key=PRIVATE_KEY)
    r.event_type = "smuggled"
    v = verify_custody_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "INVALID_EVENT_TYPE"


def test_invalid_purpose_rejected():
    r = create_custody_receipt(**_base_input(), custodian_private_key=PRIVATE_KEY)
    r.purpose = "exfiltration"
    v = verify_custody_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "INVALID_PURPOSE"


def test_ts_fixture_byte_parity():
    f = json.loads(FIXTURE.read_text())
    s = f["scope_of_claim"]
    b = f["subject_receipt_batch"]
    receipt = CustodyReceipt(
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
        custodian_did=f["custodian_did"],
        event_type=f["event_type"],
        subject_receipt_batch=SubjectReceiptBatch(merkle_root=b["merkle_root"], count=b["count"]),
        purpose=f["purpose"],
        previous_custody_id=f.get("previous_custody_id"),
        next_custodian_did=f.get("next_custodian_did"),
        signature=f["signature"],
    )
    v = verify_custody_receipt(receipt)
    assert v["valid"] is True, f"byte-parity drift: {v}"
