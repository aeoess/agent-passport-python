# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Claim → Evidence types (Module 1 of the Evidentiary Type Safety set).

Mirrors src/v2/claim-evidence-types.ts in the TypeScript SDK at
agent-passport-system 2.6.0-alpha.0.

Names a closed set of claims an APS receipt can substantiate, the
record types the protocol can produce, and the mapping between
them. Receipts substantiate specific claims; not every receipt
can substitute for another. This module is the static surface of
that mapping. Verification logic lives in claim_verifier.

Enum string values are byte-identical to the TypeScript SDK so
any serialized form (registry export, audit-log entry, fixture
JSON) interops across implementations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ClaimType(str, Enum):
    """Closed taxonomy of claims an evidence bundle can substantiate."""

    IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
    AUTHORITY_TO_EXECUTE = "AUTHORITY_TO_EXECUTE"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    BINDING_COMMITMENT = "BINDING_COMMITMENT"
    EFFECT_SAFETY_ATTESTED = "EFFECT_SAFETY_ATTESTED"
    DERIVATION_TRACED = "DERIVATION_TRACED"
    CLAIM_CONTESTED = "CLAIM_CONTESTED"
    CLAIM_RESOLVED = "CLAIM_RESOLVED"
    BATCH_ATTESTED = "BATCH_ATTESTED"
    EVIDENCE_CUSTODY_HELD = "EVIDENCE_CUSTODY_HELD"


class RecordType(str, Enum):
    """Mirrors the existing record-producing primitives the SDK ships.

    Names match the TypeScript types in `src/index.ts`. Wave 1
    accountability primitives (ActionReceipt, AuthorityBoundaryReceipt,
    CustodyReceipt, ContestabilityReceipt, APSBundle) are referenced
    here even though their full Python ports haven't shipped yet — the
    registry vocabulary is independent of which receipts the Python
    SDK can construct.
    """

    ActionReceipt = "ActionReceipt"
    AuthorityBoundaryReceipt = "AuthorityBoundaryReceipt"
    CustodyReceipt = "CustodyReceipt"
    ContestabilityReceipt = "ContestabilityReceipt"
    APSBundle = "APSBundle"
    AccessReceipt = "AccessReceipt"
    DerivationReceipt = "DerivationReceipt"
    DecisionReceipt = "DecisionReceipt"
    ProvisionalStatement = "ProvisionalStatement"
    PromotionEvent = "PromotionEvent"
    Withdrawal = "Withdrawal"
    InstructionProvenanceReceipt = "InstructionProvenanceReceipt"
    CognitiveAttestation = "CognitiveAttestation"


@dataclass(frozen=True)
class EvidenceProfile:
    """Static schema for what evidence a given ClaimType requires.

    `forbidden_substitutions` maps a RecordType to a human-readable
    rationale string. The rationale text is byte-identical across
    implementations so audit logs and paper appendices reference the
    same canonical wording.
    """

    required: List[RecordType]
    forbidden_substitutions: Dict[RecordType, str] = field(default_factory=dict)
    optional: Optional[List[RecordType]] = None


EvidenceProfiles: Dict[ClaimType, EvidenceProfile] = {
    ClaimType.AUTHORITY_TO_EXECUTE: EvidenceProfile(
        required=[RecordType.AuthorityBoundaryReceipt],
        optional=[RecordType.DecisionReceipt],
        forbidden_substitutions={
            RecordType.ActionReceipt: (
                "Action receipts prove execution, not authority. The boundary "
                "ruling is a separate signer (the gateway/evaluator), and "
                "conflating them collapses the trust split that makes the "
                "audit chain meaningful."
            ),
        },
    ),

    ClaimType.BINDING_COMMITMENT: EvidenceProfile(
        required=[RecordType.PromotionEvent, RecordType.ProvisionalStatement],
        optional=[RecordType.DecisionReceipt],
        forbidden_substitutions={
            RecordType.ActionReceipt: (
                "Action receipts prove execution or communication, not "
                "binding commitment."
            ),
        },
    ),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.IDENTITY_VERIFIED: EvidenceProfile(required=[]),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.ACTION_EXECUTED: EvidenceProfile(required=[]),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.EFFECT_SAFETY_ATTESTED: EvidenceProfile(required=[]),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.DERIVATION_TRACED: EvidenceProfile(required=[]),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.CLAIM_CONTESTED: EvidenceProfile(required=[]),

    # TODO: populate required/optional records and forbidden_substitutions.
    ClaimType.CLAIM_RESOLVED: EvidenceProfile(required=[]),

    ClaimType.BATCH_ATTESTED: EvidenceProfile(
        required=[RecordType.APSBundle],
    ),

    ClaimType.EVIDENCE_CUSTODY_HELD: EvidenceProfile(
        required=[RecordType.CustodyReceipt],
        forbidden_substitutions={
            RecordType.ActionReceipt: (
                "Action receipts prove what was done, not who held the "
                "evidence afterward."
            ),
        },
    ),
}


def required_evidence_for(claim_type: ClaimType) -> EvidenceProfile:
    """Return the EvidenceProfile registered for a claim type."""
    return EvidenceProfiles[claim_type]
