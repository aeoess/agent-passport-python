# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Claim verifier — Module 2.

Two test sections:
  1. Unit tests — same logic checks as the TS test suite.
  2. Cross-impl byte-parity — load TS-generated fixtures, run the
     Python verifier, canonicalize, assert the canonical bytes and
     sha256 match TS exactly. Required for cross-implementation
     verifier verdict consistency.
"""

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport import (
    ClaimType,
    ClaimVerificationInput,
    EvidenceEntry,
    OpenContestationLookup,
    RecordType,
    canonicalize,
    verify_evidence_claim,
)

SUBJECT = "aps:test:subject-001"

FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "evidentiary-type-safety" / "fixtures.json"
)


def _load_fixtures():
    with FIXTURE_PATH.open() as f:
        return json.load(f)


def _make_input(claim_type, evidence, resolver=None):
    return ClaimVerificationInput(
        claim_type=claim_type,
        subject=SUBJECT,
        evidence=evidence,
        open_contestation_resolver=resolver,
    )


# ── Unit tests (mirror tests/v2/claim-verifier.test.ts in the TS SDK) ──


def test_binding_commitment_with_only_action_receipt_returns_forbidden_substitution():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.BINDING_COMMITMENT,
            [EvidenceEntry(record_type=RecordType.ActionReceipt, record={})],
        )
    )
    assert result.status == "forbidden_substitution"
    assert result.claimType == ClaimType.BINDING_COMMITMENT
    assert result.offendingRecord == RecordType.ActionReceipt
    assert (
        result.reason
        == "Action receipts prove execution or communication, not binding commitment."
    )


def test_binding_commitment_with_promotion_and_provisional_returns_valid():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.BINDING_COMMITMENT,
            [
                EvidenceEntry(record_type=RecordType.PromotionEvent, record={}),
                EvidenceEntry(record_type=RecordType.ProvisionalStatement, record={}),
            ],
        )
    )
    assert result.status == "valid"
    assert result.satisfiedBy == [
        RecordType.PromotionEvent,
        RecordType.ProvisionalStatement,
    ]


def test_authority_to_execute_with_authority_boundary_returns_valid():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.AUTHORITY_TO_EXECUTE,
            [
                EvidenceEntry(
                    record_type=RecordType.AuthorityBoundaryReceipt, record={}
                )
            ],
        )
    )
    assert result.status == "valid"
    assert result.satisfiedBy == [RecordType.AuthorityBoundaryReceipt]


def test_authority_to_execute_with_no_evidence_returns_missing_evidence():
    result = verify_evidence_claim(_make_input(ClaimType.AUTHORITY_TO_EXECUTE, []))
    assert result.status == "missing_evidence"
    assert result.missing == [RecordType.AuthorityBoundaryReceipt]
    assert result.provided == []


def test_batch_attested_with_aps_bundle_returns_valid():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.BATCH_ATTESTED,
            [EvidenceEntry(record_type=RecordType.APSBundle, record={})],
        )
    )
    assert result.status == "valid"
    assert result.satisfiedBy == [RecordType.APSBundle]


def test_binding_commitment_with_aps_bundle_returns_bundle_requires_inclusion_proof():
    bundle_rec = {"claim_type": "aps:bundle:v1", "merkle_root": "deadbeef"}
    result = verify_evidence_claim(
        _make_input(
            ClaimType.BINDING_COMMITMENT,
            [EvidenceEntry(record_type=RecordType.APSBundle, record=bundle_rec)],
        )
    )
    assert result.status == "bundle_requires_inclusion_proof"
    assert result.bundleRecord == bundle_rec


def test_evidence_custody_held_with_action_receipt_forbidden():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.EVIDENCE_CUSTODY_HELD,
            [EvidenceEntry(record_type=RecordType.ActionReceipt, record={})],
        )
    )
    assert result.status == "forbidden_substitution"
    assert result.offendingRecord == RecordType.ActionReceipt
    assert "held the evidence" in result.reason.lower()


def test_evidence_custody_held_with_custody_receipt_valid():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.EVIDENCE_CUSTODY_HELD,
            [EvidenceEntry(record_type=RecordType.CustodyReceipt, record={})],
        )
    )
    assert result.status == "valid"
    assert result.satisfiedBy == [RecordType.CustodyReceipt]


def test_effect_safety_attested_with_full_chain_returns_profile_not_populated():
    """Compliance-complete failure: a fully-populated procedural chain
    cannot satisfy a stub claim. The protocol acknowledges it cannot
    answer rather than vacuously approving.
    """
    result = verify_evidence_claim(
        _make_input(
            ClaimType.EFFECT_SAFETY_ATTESTED,
            [
                EvidenceEntry(record_type=RecordType.AuthorityBoundaryReceipt, record={}),
                EvidenceEntry(record_type=RecordType.DecisionReceipt, record={}),
                EvidenceEntry(record_type=RecordType.ActionReceipt, record={}),
                EvidenceEntry(record_type=RecordType.DerivationReceipt, record={}),
            ],
        )
    )
    assert result.status == "profile_not_populated"
    assert result.claimType == ClaimType.EFFECT_SAFETY_ATTESTED


def test_unsupported_claim_type():
    """Force a registry miss by passing a string the enum doesn't know.

    Construct the input by hand to bypass the enum constructor.
    """
    input = ClaimVerificationInput(
        claim_type="NOT_A_REAL_CLAIM",  # type: ignore[arg-type]
        subject=SUBJECT,
        evidence=[],
    )
    result = verify_evidence_claim(input)
    assert result.status == "unsupported_claim_type"


# ── Module 4 contestation hook ──


def test_resolver_absent_returns_valid():
    result = verify_evidence_claim(
        _make_input(
            ClaimType.AUTHORITY_TO_EXECUTE,
            [
                EvidenceEntry(
                    record_type=RecordType.AuthorityBoundaryReceipt,
                    record={},
                    receipt_id="auth_001",
                )
            ],
        )
    )
    assert result.status == "valid"


def test_resolver_filed_returns_contested():
    def resolver(record_id):
        return OpenContestationLookup(contestation_id="contest_xyz", status="filed")

    result = verify_evidence_claim(
        _make_input(
            ClaimType.AUTHORITY_TO_EXECUTE,
            [
                EvidenceEntry(
                    record_type=RecordType.AuthorityBoundaryReceipt,
                    record={},
                    receipt_id="auth_001",
                )
            ],
            resolver=resolver,
        )
    )
    assert result.status == "contested"
    assert result.contestedRecordId == "auth_001"
    assert result.contestationId == "contest_xyz"
    assert result.contestationStatus == "filed"


def test_resolver_rejected_returns_valid():
    def resolver(record_id):
        return OpenContestationLookup(contestation_id="contest_xyz", status="rejected")

    result = verify_evidence_claim(
        _make_input(
            ClaimType.AUTHORITY_TO_EXECUTE,
            [
                EvidenceEntry(
                    record_type=RecordType.AuthorityBoundaryReceipt,
                    record={},
                    receipt_id="auth_001",
                )
            ],
            resolver=resolver,
        )
    )
    assert result.status == "valid"


def test_resolver_upheld_returns_contested():
    def resolver(record_id):
        return OpenContestationLookup(contestation_id="contest_xyz", status="upheld")

    result = verify_evidence_claim(
        _make_input(
            ClaimType.AUTHORITY_TO_EXECUTE,
            [
                EvidenceEntry(
                    record_type=RecordType.AuthorityBoundaryReceipt,
                    record={},
                    receipt_id="auth_001",
                )
            ],
            resolver=resolver,
        )
    )
    assert result.status == "contested"
    assert result.contestationStatus == "upheld"


# ── Cross-impl byte-parity (load TS fixtures, assert byte-identical output) ──

VERIFIER_FIXTURES = _load_fixtures()["verifier_scenarios"]


@pytest.mark.parametrize(
    "fixture",
    VERIFIER_FIXTURES,
    ids=[f["name"] for f in VERIFIER_FIXTURES],
)
def test_verifier_byte_parity_with_ts(fixture):
    """Run the fixture's input through the Python verifier, canonicalize
    the result minus the bundleRecord field, and assert the canonical
    bytes + sha256 match what TS produced.

    bundleRecord skipped because TS passes the literal record object
    through; both sides treat it as opaque pass-through, so excluding
    it from the canonical hash is the correct cross-impl contract.
    """
    raw_input = fixture["input"]
    claim_type_str = raw_input["claim"]["type"]
    try:
        claim_type = ClaimType(claim_type_str)
    except ValueError:
        # Unknown claim type — pass the raw string so the verifier can
        # produce the unsupported_claim_type result.
        claim_type = claim_type_str  # type: ignore[assignment]

    evidence = [
        EvidenceEntry(
            record_type=RecordType(e["recordType"]),
            record=e["record"],
            receipt_id=e.get("receiptId"),
        )
        for e in raw_input["evidence"]
    ]
    input = ClaimVerificationInput(
        claim_type=claim_type,
        subject=raw_input["claim"]["subject"],
        evidence=evidence,
    )
    result = verify_evidence_claim(input)
    result_dict = result.to_dict()
    result_dict.pop("bundleRecord", None)
    canonical = canonicalize(result_dict)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert canonical == fixture["canonicalJsonNoBundle"], (
        f"canonical JSON drift for fixture {fixture['name']}\n"
        f"  python: {canonical}\n"
        f"  ts:     {fixture['canonicalJsonNoBundle']}"
    )
    assert digest == fixture["canonicalSha256NoBundle"], (
        f"sha256 drift for fixture {fixture['name']}\n"
        f"  python: {digest}\n"
        f"  ts:     {fixture['canonicalSha256NoBundle']}"
    )
