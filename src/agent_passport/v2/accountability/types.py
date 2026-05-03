# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Wave 1 accountability — receipt types.

Mirrors src/v2/accountability/types/ in agent-passport-system 2.6.0-alpha.0.
Five primitives:

  ActionReceipt              — what was emitted, by whom, under what authority
  AuthorityBoundaryReceipt   — was the action inside or outside delegation
  CustodyReceipt             — provenance trail of receipt-handling events
  ContestabilityReceipt      — affected-party challenge with controller response
  APSBundle                  — signed aggregation envelope with Merkle commitment

Every receipt extends AccountabilityReceiptBase and MUST declare its
scope_of_claim explicitly.

Python attribute names are snake_case per PEP 8. The TypeScript source uses
snake_case for these field names too, so the canonical wire form matches the
Python attribute names directly. None-valued optional fields drop from the
canonical-dict output via to_canonical_dict() so each receipt's JSON shape
matches what TS produces.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union


# ── Base types ──────────────────────────────────────────────────────────

CaptureMode = Literal[
    "gateway_observed",
    "runtime_attested",
    "self_attested",
    "partial",
    "unknown",
]
Completeness = Literal["complete", "partial", "best_effort"]


@dataclass
class ScopeOfClaim:
    """Mandatory honest scope declaration for every receipt."""

    asserts: str
    does_not_assert: List[str]
    capture_mode: CaptureMode
    completeness: Completeness
    self_attested: bool

    def to_canonical_dict(self) -> dict:
        return {
            "asserts": self.asserts,
            "capture_mode": self.capture_mode,
            "completeness": self.completeness,
            "does_not_assert": list(self.does_not_assert),
            "self_attested": self.self_attested,
        }


# ── ActionReceipt ───────────────────────────────────────────────────────

SideEffectClass = Literal[
    "financial",
    "data_modification",
    "external_message",
    "irreversible",
    "subject_affecting",
    "internal_only",
]


@dataclass
class ActionPayload:
    kind: str
    target: str
    parameters: Optional[Dict[str, Any]] = None
    resource_version: Optional[str] = None

    def to_canonical_dict(self) -> dict:
        out: dict = {"kind": self.kind, "target": self.target}
        if self.parameters is not None:
            out["parameters"] = self.parameters
        if self.resource_version is not None:
            out["resource_version"] = self.resource_version
        return out


@dataclass
class TransparencyLogInclusion:
    log_url: str
    leaf_hash: str

    def to_canonical_dict(self) -> dict:
        return {"leaf_hash": self.leaf_hash, "log_url": self.log_url}


@dataclass
class ActionReceipt:
    claim_type: str  # always 'aps:action:v1'
    receipt_id: str
    timestamp: str
    signer_did: str
    scope_of_claim: ScopeOfClaim
    agent_did: str
    delegation_chain_root: str
    action: ActionPayload
    side_effect_classes: List[SideEffectClass]
    signature: str
    intent_ref: Optional[str] = None
    policy_ref: Optional[str] = None
    transparency_log_inclusion: Optional[TransparencyLogInclusion] = None
    rfc3161_timestamp: Optional[str] = None

    def to_canonical_dict(self, *, drop_signature_field: bool = False) -> dict:
        """Canonical JSON dict for hashing / signing.

        drop_signature_field=False: signature field present (possibly empty).
        Used by Action/AuthorityBoundary/Custody/Contestability where receipt_id
        is computed over JCS({...receipt, signature: ""}). Bundle is the
        exception — see APSBundle.to_canonical_dict.
        """
        out: dict = {
            "action": self.action.to_canonical_dict(),
            "agent_did": self.agent_did,
            "claim_type": self.claim_type,
            "delegation_chain_root": self.delegation_chain_root,
            "receipt_id": self.receipt_id,
            "scope_of_claim": self.scope_of_claim.to_canonical_dict(),
            "side_effect_classes": list(self.side_effect_classes),
            "signer_did": self.signer_did,
            "timestamp": self.timestamp,
        }
        if self.intent_ref is not None:
            out["intent_ref"] = self.intent_ref
        if self.policy_ref is not None:
            out["policy_ref"] = self.policy_ref
        if self.transparency_log_inclusion is not None:
            out["transparency_log_inclusion"] = self.transparency_log_inclusion.to_canonical_dict()
        if self.rfc3161_timestamp is not None:
            out["rfc3161_timestamp"] = self.rfc3161_timestamp
        if not drop_signature_field:
            out["signature"] = self.signature
        return out


# ── AuthorityBoundaryReceipt ────────────────────────────────────────────

BoundaryResult = Literal["inside", "outside", "indeterminate"]


@dataclass
class AuthorityBoundaryReceipt:
    claim_type: str  # always 'aps:authority_boundary:v1'
    receipt_id: str
    timestamp: str
    signer_did: str
    scope_of_claim: ScopeOfClaim
    action_id: str
    evaluator_did: str
    delegation_chain_root: str
    result: BoundaryResult
    signature: str
    result_detail: Optional[str] = None

    def to_canonical_dict(self, *, drop_signature_field: bool = False) -> dict:
        out: dict = {
            "action_id": self.action_id,
            "claim_type": self.claim_type,
            "delegation_chain_root": self.delegation_chain_root,
            "evaluator_did": self.evaluator_did,
            "receipt_id": self.receipt_id,
            "result": self.result,
            "scope_of_claim": self.scope_of_claim.to_canonical_dict(),
            "signer_did": self.signer_did,
            "timestamp": self.timestamp,
        }
        if self.result_detail is not None:
            out["result_detail"] = self.result_detail
        if not drop_signature_field:
            out["signature"] = self.signature
        return out


# ── CustodyReceipt ──────────────────────────────────────────────────────

CustodyEventType = Literal[
    "created",
    "sealed",
    "transferred",
    "disclosed",
    "redacted",
    "erased",
    "expired",
    "verified",
]
CustodyPurpose = Literal[
    "internal_audit",
    "regulator_disclosure",
    "subject_access",
    "litigation_discovery",
    "vendor_handoff",
    "archival",
    "incident_response",
]


@dataclass
class SubjectReceiptBatch:
    merkle_root: str
    count: int

    def to_canonical_dict(self) -> dict:
        return {"count": self.count, "merkle_root": self.merkle_root}


@dataclass
class CustodyReceipt:
    claim_type: str  # always 'aps:custody:v1'
    receipt_id: str
    timestamp: str
    signer_did: str
    scope_of_claim: ScopeOfClaim
    custodian_did: str
    event_type: CustodyEventType
    subject_receipt_batch: SubjectReceiptBatch
    purpose: CustodyPurpose
    signature: str
    previous_custody_id: Optional[str] = None
    next_custodian_did: Optional[str] = None

    def to_canonical_dict(self, *, drop_signature_field: bool = False) -> dict:
        out: dict = {
            "claim_type": self.claim_type,
            "custodian_did": self.custodian_did,
            "event_type": self.event_type,
            "purpose": self.purpose,
            "receipt_id": self.receipt_id,
            "scope_of_claim": self.scope_of_claim.to_canonical_dict(),
            "signer_did": self.signer_did,
            "subject_receipt_batch": self.subject_receipt_batch.to_canonical_dict(),
            "timestamp": self.timestamp,
        }
        if self.previous_custody_id is not None:
            out["previous_custody_id"] = self.previous_custody_id
        if self.next_custodian_did is not None:
            out["next_custodian_did"] = self.next_custodian_did
        if not drop_signature_field:
            out["signature"] = self.signature
        return out


# ── ContestabilityReceipt (full surface, replaces v2.4.0a0 minimal stub) ─

StandingBasis = Literal[
    "data_subject",
    "third_party",
    "regulator",
    "court",
    "internal_audit",
    "insurer",
    "principal",
]
RequestedRemedy = Literal[
    "rollback",
    "review",
    "explanation",
    "compensation",
    "erasure",
    "modification",
]
ContestStatus = Literal[
    "filed",
    "under_review",
    "upheld",
    "rejected",
    "remedied",
    "expired",
    "abandoned",
]
GroundsClassValue = Literal[
    "evidence_insufficient",
    "factual_dispute",
    "scope_violation",
    "superseded_by_new_evidence",
    "identity_dispute",
    "unclassified",
]


class GroundsClass(str, Enum):
    """Closed taxonomy for protocol-level routing of contestations.

    Members are strings via the str-mixin, so a ContestabilityReceipt
    can carry either the Enum member or the raw string. Both round-trip
    through to_canonical_dict and JCS canonicalization to byte-identical
    output. Mirrors the GroundsClass enum that originally lived in the
    minimal downstream_taint stub.
    """

    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    FACTUAL_DISPUTE = "factual_dispute"
    SCOPE_VIOLATION = "scope_violation"
    SUPERSEDED_BY_NEW_EVIDENCE = "superseded_by_new_evidence"
    IDENTITY_DISPUTE = "identity_dispute"
    UNCLASSIFIED = "unclassified"


@dataclass
class ContestabilityContestant:
    standing_basis: StandingBasis
    did: Optional[str] = None
    pseudonym_hash: Optional[str] = None

    def to_canonical_dict(self) -> dict:
        out: dict = {"standing_basis": self.standing_basis}
        if self.did is not None:
            out["did"] = self.did
        if self.pseudonym_hash is not None:
            out["pseudonym_hash"] = self.pseudonym_hash
        return out


@dataclass
class ContestabilityControllerResponse:
    """Controller response attached after filing.

    Carries an independent signature from the controller. The contestant's
    outer signature does not cover this response, so the response cannot
    retroactively rewrite the original claim.
    """

    status: ContestStatus
    responded_at: str
    responder_did: str
    response_signature: str
    response_detail: Optional[str] = None

    def to_canonical_dict(self, *, drop_response_signature: bool = False) -> dict:
        out: dict = {
            "responded_at": self.responded_at,
            "responder_did": self.responder_did,
            "status": self.status,
        }
        if not drop_response_signature:
            out["response_signature"] = self.response_signature
        if self.response_detail is not None:
            out["response_detail"] = self.response_detail
        return out


@dataclass
class ContestabilityReceipt:
    claim_type: str  # always 'aps:contestability:v1'
    receipt_id: str
    timestamp: str
    signer_did: str
    scope_of_claim: ScopeOfClaim
    contestant: ContestabilityContestant
    action_id: str
    grounds: str
    requested_remedy: RequestedRemedy
    signature: str
    grounds_class: Optional[GroundsClassValue] = None
    controller_response: Optional[ContestabilityControllerResponse] = None

    def to_canonical_dict(
        self,
        *,
        drop_signature_field: bool = False,
        drop_controller_response: bool = False,
        drop_response_signature: bool = False,
    ) -> dict:
        """Canonical dict for hashing / signing.

        Receipt_id derivation: drop_signature_field=False (signature: ""
        present), drop_controller_response=True (no response in filing form).
        Outer signature: same as id derivation but on populated receipt_id.
        Controller-response signature: drop_response_signature=True so the
        response signature is over the response body without itself.
        """
        out: dict = {
            "action_id": self.action_id,
            "claim_type": self.claim_type,
            "contestant": self.contestant.to_canonical_dict(),
            "grounds": self.grounds,
            "receipt_id": self.receipt_id,
            "requested_remedy": self.requested_remedy,
            "scope_of_claim": self.scope_of_claim.to_canonical_dict(),
            "signer_did": self.signer_did,
            "timestamp": self.timestamp,
        }
        if self.grounds_class is not None:
            out["grounds_class"] = self.grounds_class
        if not drop_signature_field:
            out["signature"] = self.signature
        if not drop_controller_response and self.controller_response is not None:
            out["controller_response"] = self.controller_response.to_canonical_dict(
                drop_response_signature=drop_response_signature,
            )
        return out


# ── APSBundle ───────────────────────────────────────────────────────────


@dataclass
class BundledReceiptRef:
    """Lightweight reference for tree construction."""

    receipt_id: str
    claim_type: str

    def to_canonical_dict(self) -> dict:
        return {"claim_type": self.claim_type, "receipt_id": self.receipt_id}


@dataclass
class APSBundle:
    """Signed aggregation envelope over a Merkle-rooted batch of receipts.

    Bundle differs from the other 4 receipt types in how its receipt_id and
    signature payload are derived. TS uses {...skeleton, signature: undefined}
    which JSON.stringify drops entirely. Python equivalent: drop_signature_field
    on to_canonical_dict drops the signature key from the output dict.
    """

    claim_type: str  # always 'aps:bundle:v1'
    receipt_id: str
    timestamp: str
    signer_did: str
    scope_of_claim: ScopeOfClaim
    bundler_did: str
    period_start: str
    period_end: str
    merkle_root: str
    receipt_count: int
    profile_conformance: List[str]
    signature: str
    subject_scope: Optional[List[str]] = None

    def to_canonical_dict(self, *, drop_signature_field: bool = False) -> dict:
        """For Bundle, drop_signature_field=True replaces signature with null.

        TS bundle.ts uses `{...skeleton, signature: undefined}` and TS's
        canonicalizeJCS converts undefined to null per RFC 8785 (see TS
        src/core/canonical-jcs.ts). The canonical bytes therefore contain
        `"signature":null`, not an absent signature key. Python preserves
        null values in canonicalize_jcs output, so setting the signature
        slot to None reproduces the exact TS canonical bytes.
        """
        out: dict = {
            "bundler_did": self.bundler_did,
            "claim_type": self.claim_type,
            "merkle_root": self.merkle_root,
            "period_end": self.period_end,
            "period_start": self.period_start,
            "profile_conformance": list(self.profile_conformance),
            "receipt_count": self.receipt_count,
            "receipt_id": self.receipt_id,
            "scope_of_claim": self.scope_of_claim.to_canonical_dict(),
            "signature": None if drop_signature_field else self.signature,
            "signer_did": self.signer_did,
            "timestamp": self.timestamp,
        }
        if self.subject_scope is not None:
            out["subject_scope"] = list(self.subject_scope)
        return out
