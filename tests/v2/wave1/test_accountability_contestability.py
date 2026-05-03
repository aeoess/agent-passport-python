# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""ContestabilityReceipt — construct + attach response + verify + byte-parity."""

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport.crypto import public_key_from_private
from agent_passport.v2.accountability import (
    ContestabilityContestant,
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    ScopeOfClaim,
    attach_controller_response,
    create_contestability_receipt,
    verify_contestability_receipt,
)

CONTESTANT_PRIV = "44" * 32
CONTROLLER_PRIV = "55" * 32
FIXED_TS = "2026-04-30T00:00:00.000Z"
RESPONDED_TS = "2026-04-30T01:00:00.000Z"
FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "wave1"
    / "accountability"
    / "contestability.fixture.json"
)


def _scope():
    return ScopeOfClaim(
        asserts="Named contestant filed a challenge against the named action with the named grounds.",
        does_not_assert=[
            "that the contestation is meritorious",
            "that the standing is legally valid",
        ],
        capture_mode="self_attested",
        completeness="complete",
        self_attested=True,
    )


def _base():
    return dict(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        contestant=ContestabilityContestant(did="did:aps:test-subject-001", standing_basis="data_subject"),
        action_id="0" * 63 + "2",
        grounds="Automated decision affected my access without disclosed criteria.",
        requested_remedy="explanation",
    )


def test_filing_round_trips():
    r = create_contestability_receipt(**_base(), contestant_private_key=CONTESTANT_PRIV)
    v = verify_contestability_receipt(r)
    assert v["valid"] is True
    assert r.controller_response is None


def test_with_controller_response_round_trips():
    filed = create_contestability_receipt(**_base(), contestant_private_key=CONTESTANT_PRIV)
    controller_did = public_key_from_private(CONTROLLER_PRIV)
    responded = attach_controller_response(
        filed,
        status="under_review",
        responded_at=RESPONDED_TS,
        responder_did=controller_did,
        controller_private_key=CONTROLLER_PRIV,
        response_detail="Acknowledged. Routed to data-subject access team.",
    )
    assert responded.controller_response is not None
    assert len(responded.controller_response.response_signature) == 128
    # Outer (contestant) signature unchanged.
    assert responded.signature == filed.signature
    assert responded.receipt_id == filed.receipt_id
    v = verify_contestability_receipt(responded)
    assert v["valid"] is True


def test_pseudonymous_filing_accepted():
    pseudo = hashlib.sha256(b"subject-handle-42").hexdigest()
    r = create_contestability_receipt(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        contestant=ContestabilityContestant(pseudonym_hash=pseudo, standing_basis="data_subject"),
        action_id="0" * 63 + "2",
        grounds="grounds",
        requested_remedy="explanation",
        contestant_private_key=CONTESTANT_PRIV,
    )
    assert r.contestant.did is None
    assert r.contestant.pseudonym_hash == pseudo
    v = verify_contestability_receipt(r)
    assert v["valid"] is True


def test_construct_rejects_no_identity():
    with pytest.raises(ValueError, match="must have at least one of did or pseudonym_hash"):
        create_contestability_receipt(
            timestamp=FIXED_TS,
            scope_of_claim=_scope(),
            contestant=ContestabilityContestant(standing_basis="data_subject"),
            action_id="0" * 63 + "2",
            grounds="grounds",
            requested_remedy="explanation",
            contestant_private_key=CONTESTANT_PRIV,
        )


def test_verify_missing_contestant_identity():
    r = create_contestability_receipt(**_base(), contestant_private_key=CONTESTANT_PRIV)
    r.contestant = ContestabilityContestant(standing_basis="data_subject")
    v = verify_contestability_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "MISSING_CONTESTANT_IDENTITY"


def test_tampered_grounds_yields_receipt_id_mismatch():
    r = create_contestability_receipt(**_base(), contestant_private_key=CONTESTANT_PRIV)
    r.grounds = "rewritten grounds after the fact"
    v = verify_contestability_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "RECEIPT_ID_MISMATCH"


def test_tampered_response_detail_yields_controller_signature_invalid():
    filed = create_contestability_receipt(**_base(), contestant_private_key=CONTESTANT_PRIV)
    controller_did = public_key_from_private(CONTROLLER_PRIV)
    responded = attach_controller_response(
        filed,
        status="under_review",
        responded_at=RESPONDED_TS,
        responder_did=controller_did,
        controller_private_key=CONTROLLER_PRIV,
        response_detail="original response detail",
    )
    responded.controller_response = ContestabilityControllerResponse(
        status=responded.controller_response.status,
        responded_at=responded.controller_response.responded_at,
        responder_did=responded.controller_response.responder_did,
        response_signature=responded.controller_response.response_signature,
        response_detail="rewritten response detail",
    )
    v = verify_contestability_receipt(responded)
    assert v["valid"] is False
    assert v["reason"] == "CONTROLLER_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    "standing",
    ["data_subject", "third_party", "regulator", "court", "internal_audit", "insurer", "principal"],
)
def test_all_standing_basis_values_verify(standing):
    r = create_contestability_receipt(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        contestant=ContestabilityContestant(did="did:aps:s", standing_basis=standing),
        action_id="0" * 63 + "2",
        grounds="g",
        requested_remedy="explanation",
        contestant_private_key=CONTESTANT_PRIV,
    )
    v = verify_contestability_receipt(r)
    assert v["valid"] is True


def test_ts_fixture_byte_parity():
    f = json.loads(FIXTURE.read_text())
    s = f["scope_of_claim"]
    contestant = ContestabilityContestant(
        did=f["contestant"].get("did"),
        pseudonym_hash=f["contestant"].get("pseudonym_hash"),
        standing_basis=f["contestant"]["standing_basis"],
    )
    response = None
    if f.get("controller_response"):
        cr = f["controller_response"]
        response = ContestabilityControllerResponse(
            status=cr["status"],
            responded_at=cr["responded_at"],
            responder_did=cr["responder_did"],
            response_signature=cr["response_signature"],
            response_detail=cr.get("response_detail"),
        )
    r = ContestabilityReceipt(
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
        contestant=contestant,
        action_id=f["action_id"],
        grounds=f["grounds"],
        requested_remedy=f["requested_remedy"],
        grounds_class=f.get("grounds_class"),
        controller_response=response,
        signature=f["signature"],
    )
    v = verify_contestability_receipt(r)
    assert v["valid"] is True, f"byte-parity drift: {v}"
