# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Claim/evidence registry — Module 1.

Verifies the Python registry has the same enum values, profile keys,
and forbidden-substitution rationales as the TS SDK. Reads the cross-
impl fixture file to lock both SDKs to the same registry vocabulary.
"""

import json
from pathlib import Path

from agent_passport import (
    ClaimType,
    EvidenceProfiles,
    RecordType,
    required_evidence_for,
)

FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "evidentiary-type-safety" / "fixtures.json"
)


def _load_fixtures():
    with FIXTURE_PATH.open() as f:
        return json.load(f)


def test_claim_type_values_match_ts_registry():
    fix = _load_fixtures()
    expected = fix["registry"]["claim_types"]
    actual = [c.value for c in ClaimType]
    assert actual == expected, f"ClaimType list drift\n  expected {expected}\n  actual   {actual}"


def test_record_type_values_match_ts_registry():
    fix = _load_fixtures()
    expected = fix["registry"]["record_types"]
    actual = [r.value for r in RecordType]
    assert actual == expected, f"RecordType list drift\n  expected {expected}\n  actual   {actual}"


def test_every_claim_type_has_an_evidence_profile_entry():
    for c in ClaimType:
        profile = EvidenceProfiles[c]
        assert profile is not None, f"missing profile for {c}"
        assert isinstance(profile.required, list)
        assert isinstance(profile.forbidden_substitutions, dict)


def test_required_evidence_for_authority_to_execute():
    profile = required_evidence_for(ClaimType.AUTHORITY_TO_EXECUTE)
    assert profile.required == [RecordType.AuthorityBoundaryReceipt]
    assert (
        RecordType.ActionReceipt in profile.forbidden_substitutions
    ), "ActionReceipt must be forbidden for AUTHORITY_TO_EXECUTE"


def test_binding_commitment_forbids_action_receipt_with_canonical_rationale():
    profile = required_evidence_for(ClaimType.BINDING_COMMITMENT)
    rationale = profile.forbidden_substitutions[RecordType.ActionReceipt]
    assert rationale == (
        "Action receipts prove execution or communication, not binding commitment."
    ), "BINDING_COMMITMENT rationale must be byte-identical to TS canonical wording"


def test_evidence_custody_held_forbids_action_receipt():
    profile = required_evidence_for(ClaimType.EVIDENCE_CUSTODY_HELD)
    rationale = profile.forbidden_substitutions[RecordType.ActionReceipt]
    assert "held the evidence" in rationale.lower()


def test_batch_attested_requires_aps_bundle():
    profile = required_evidence_for(ClaimType.BATCH_ATTESTED)
    assert profile.required == [RecordType.APSBundle]
    assert profile.forbidden_substitutions == {}


def test_stub_claim_types_have_empty_required_and_no_forbidden():
    """Claims that haven't been populated yet stay stubbed.

    Module 2's verifier returns 'profile_not_populated' for these so
    the protocol acknowledges it cannot answer the claim rather than
    vacuously approving it.
    """
    stubbed = [
        ClaimType.IDENTITY_VERIFIED,
        ClaimType.ACTION_EXECUTED,
        ClaimType.EFFECT_SAFETY_ATTESTED,
        ClaimType.DERIVATION_TRACED,
        ClaimType.CLAIM_CONTESTED,
        ClaimType.CLAIM_RESOLVED,
    ]
    for c in stubbed:
        profile = required_evidence_for(c)
        assert profile.required == [], f"{c} should be stub but has required"
        assert (
            profile.forbidden_substitutions == {}
        ), f"{c} should be stub but has forbidden substitutions"
