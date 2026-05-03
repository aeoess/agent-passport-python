# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""AuthorityBoundaryReceipt — construct + verify + cross-impl byte-parity."""

import json
from pathlib import Path

from agent_passport.v2.accountability import (
    AuthorityBoundaryReceipt,
    ScopeOfClaim,
    create_authority_boundary_receipt,
    verify_authority_boundary_receipt,
)

PRIVATE_KEY = "22" * 32
FIXED_TS = "2026-04-30T00:00:00.000Z"
FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "wave1"
    / "accountability"
    / "authority-boundary.fixture.json"
)


def _scope():
    return ScopeOfClaim(
        asserts="Gateway evaluated the action against the agent's delegation chain.",
        does_not_assert=["That the action was correct or beneficial."],
        capture_mode="gateway_observed",
        completeness="complete",
        self_attested=False,
    )


def _base_input():
    return dict(
        timestamp=FIXED_TS,
        scope_of_claim=_scope(),
        action_id="b" * 64,
        evaluator_did="did:aps:gateway-001",
        delegation_chain_root="a" * 64,
        result="inside",
    )


def test_round_trip_inside():
    r = create_authority_boundary_receipt(**_base_input(), evaluator_private_key=PRIVATE_KEY)
    v = verify_authority_boundary_receipt(r)
    assert v["valid"] is True


def test_round_trip_outside_with_detail():
    r = create_authority_boundary_receipt(
        **{**_base_input(), "result": "outside", "result_detail": "scope 'commerce.purchase' not in delegation"},
        evaluator_private_key=PRIVATE_KEY,
    )
    v = verify_authority_boundary_receipt(r)
    assert v["valid"] is True
    assert r.result_detail is not None


def test_round_trip_indeterminate():
    r = create_authority_boundary_receipt(
        **{**_base_input(), "result": "indeterminate"}, evaluator_private_key=PRIVATE_KEY
    )
    v = verify_authority_boundary_receipt(r)
    assert v["valid"] is True


def test_tampered_result_yields_receipt_id_mismatch():
    r = create_authority_boundary_receipt(**_base_input(), evaluator_private_key=PRIVATE_KEY)
    r.result = "outside"
    v = verify_authority_boundary_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "RECEIPT_ID_MISMATCH"


def test_wrong_claim_type_invalid():
    r = create_authority_boundary_receipt(**_base_input(), evaluator_private_key=PRIVATE_KEY)
    r.claim_type = "aps:other:v1"
    v = verify_authority_boundary_receipt(r)
    assert v["valid"] is False
    assert v["reason"] == "INVALID_CLAIM_TYPE"


def test_ts_fixture_byte_parity():
    f = json.loads(FIXTURE.read_text())
    s = f["scope_of_claim"]
    receipt = AuthorityBoundaryReceipt(
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
        action_id=f["action_id"],
        evaluator_did=f["evaluator_did"],
        delegation_chain_root=f["delegation_chain_root"],
        result=f["result"],
        result_detail=f.get("result_detail"),
        signature=f["signature"],
    )
    v = verify_authority_boundary_receipt(receipt)
    assert v["valid"] is True, f"byte-parity drift detected: {v}"
