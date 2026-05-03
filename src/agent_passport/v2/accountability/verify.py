# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Wave 1 accountability — verification for Action / AuthorityBoundary /
Custody / Contestability.

Mirrors src/v2/accountability/verify/*.ts (everything except bundle, which
lives in bundle.py).

Returns shape across all verifiers:
  {"valid": bool, "reason": Optional[str]}
where `reason` is one of the closed-taxonomy strings exactly matching the
TS implementation.
"""

from hashlib import sha256
from typing import Optional

from ...canonical import canonicalize_jcs
from ...crypto import verify as ed_verify
from .types import (
    ActionReceipt,
    AuthorityBoundaryReceipt,
    ContestabilityReceipt,
    CustodyReceipt,
)


def _sha256_hex(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


# ── ActionReceipt ───────────────────────────────────────────────────────


def verify_action_receipt(receipt: ActionReceipt) -> dict:
    """Verify an ActionReceipt.

    Reasons: INVALID_CLAIM_TYPE, RECEIPT_ID_MISMATCH, SIGNATURE_INVALID.
    """
    if receipt.claim_type != "aps:action:v1":
        return {"valid": False, "reason": "INVALID_CLAIM_TYPE"}

    # Re-derive receipt_id over the empty-id, empty-signature form.
    draft_for_id = ActionReceipt(
        claim_type=receipt.claim_type,
        receipt_id="",
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        agent_did=receipt.agent_did,
        delegation_chain_root=receipt.delegation_chain_root,
        action=receipt.action,
        side_effect_classes=list(receipt.side_effect_classes),
        intent_ref=receipt.intent_ref,
        policy_ref=receipt.policy_ref,
        transparency_log_inclusion=receipt.transparency_log_inclusion,
        rfc3161_timestamp=receipt.rfc3161_timestamp,
        signature="",
    )
    expected_id = _sha256_hex(canonicalize_jcs(draft_for_id.to_canonical_dict()))
    if receipt.receipt_id != expected_id:
        return {"valid": False, "reason": "RECEIPT_ID_MISMATCH"}

    # Signature over populated-id, empty-signature form.
    draft_for_sig = ActionReceipt(
        claim_type=receipt.claim_type,
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        agent_did=receipt.agent_did,
        delegation_chain_root=receipt.delegation_chain_root,
        action=receipt.action,
        side_effect_classes=list(receipt.side_effect_classes),
        intent_ref=receipt.intent_ref,
        policy_ref=receipt.policy_ref,
        transparency_log_inclusion=receipt.transparency_log_inclusion,
        rfc3161_timestamp=receipt.rfc3161_timestamp,
        signature="",
    )
    if not ed_verify(
        canonicalize_jcs(draft_for_sig.to_canonical_dict()),
        receipt.signature,
        receipt.signer_did,
    ):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    return {"valid": True, "reason": None}


# ── AuthorityBoundaryReceipt ────────────────────────────────────────────


def verify_authority_boundary_receipt(receipt: AuthorityBoundaryReceipt) -> dict:
    """Verify an AuthorityBoundaryReceipt.

    Reasons: INVALID_CLAIM_TYPE, RECEIPT_ID_MISMATCH, SIGNATURE_INVALID.
    """
    if receipt.claim_type != "aps:authority_boundary:v1":
        return {"valid": False, "reason": "INVALID_CLAIM_TYPE"}

    draft_for_id = AuthorityBoundaryReceipt(
        claim_type=receipt.claim_type,
        receipt_id="",
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        action_id=receipt.action_id,
        evaluator_did=receipt.evaluator_did,
        delegation_chain_root=receipt.delegation_chain_root,
        result=receipt.result,
        result_detail=receipt.result_detail,
        signature="",
    )
    expected_id = _sha256_hex(canonicalize_jcs(draft_for_id.to_canonical_dict()))
    if receipt.receipt_id != expected_id:
        return {"valid": False, "reason": "RECEIPT_ID_MISMATCH"}

    draft_for_sig = AuthorityBoundaryReceipt(
        claim_type=receipt.claim_type,
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        action_id=receipt.action_id,
        evaluator_did=receipt.evaluator_did,
        delegation_chain_root=receipt.delegation_chain_root,
        result=receipt.result,
        result_detail=receipt.result_detail,
        signature="",
    )
    if not ed_verify(
        canonicalize_jcs(draft_for_sig.to_canonical_dict()),
        receipt.signature,
        receipt.signer_did,
    ):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    return {"valid": True, "reason": None}


# ── CustodyReceipt ──────────────────────────────────────────────────────


_VALID_EVENT_TYPES = frozenset(
    [
        "created",
        "sealed",
        "transferred",
        "disclosed",
        "redacted",
        "erased",
        "expired",
        "verified",
    ]
)
_VALID_PURPOSES = frozenset(
    [
        "internal_audit",
        "regulator_disclosure",
        "subject_access",
        "litigation_discovery",
        "vendor_handoff",
        "archival",
        "incident_response",
    ]
)


def verify_custody_receipt(receipt: CustodyReceipt) -> dict:
    """Verify a CustodyReceipt.

    Reasons: INVALID_CLAIM_TYPE, INVALID_EVENT_TYPE, INVALID_PURPOSE,
    RECEIPT_ID_MISMATCH, SIGNATURE_INVALID.
    """
    if receipt.claim_type != "aps:custody:v1":
        return {"valid": False, "reason": "INVALID_CLAIM_TYPE"}
    if receipt.event_type not in _VALID_EVENT_TYPES:
        return {"valid": False, "reason": "INVALID_EVENT_TYPE"}
    if receipt.purpose not in _VALID_PURPOSES:
        return {"valid": False, "reason": "INVALID_PURPOSE"}

    draft_for_id = CustodyReceipt(
        claim_type=receipt.claim_type,
        receipt_id="",
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        custodian_did=receipt.custodian_did,
        event_type=receipt.event_type,
        subject_receipt_batch=receipt.subject_receipt_batch,
        purpose=receipt.purpose,
        previous_custody_id=receipt.previous_custody_id,
        next_custodian_did=receipt.next_custodian_did,
        signature="",
    )
    expected_id = _sha256_hex(canonicalize_jcs(draft_for_id.to_canonical_dict()))
    if receipt.receipt_id != expected_id:
        return {"valid": False, "reason": "RECEIPT_ID_MISMATCH"}

    draft_for_sig = CustodyReceipt(
        claim_type=receipt.claim_type,
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        custodian_did=receipt.custodian_did,
        event_type=receipt.event_type,
        subject_receipt_batch=receipt.subject_receipt_batch,
        purpose=receipt.purpose,
        previous_custody_id=receipt.previous_custody_id,
        next_custodian_did=receipt.next_custodian_did,
        signature="",
    )
    if not ed_verify(
        canonicalize_jcs(draft_for_sig.to_canonical_dict()),
        receipt.signature,
        receipt.signer_did,
    ):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    return {"valid": True, "reason": None}


# ── ContestabilityReceipt ───────────────────────────────────────────────


_VALID_STANDING = frozenset(
    [
        "data_subject",
        "third_party",
        "regulator",
        "court",
        "internal_audit",
        "insurer",
        "principal",
    ]
)
_VALID_REMEDY = frozenset(
    [
        "rollback",
        "review",
        "explanation",
        "compensation",
        "erasure",
        "modification",
    ]
)
_VALID_STATUS = frozenset(
    [
        "filed",
        "under_review",
        "upheld",
        "rejected",
        "remedied",
        "expired",
        "abandoned",
    ]
)


def verify_contestability_receipt(receipt: ContestabilityReceipt) -> dict:
    """Verify a ContestabilityReceipt (filing + optional response).

    Reasons: INVALID_CLAIM_TYPE, MISSING_CONTESTANT_IDENTITY,
    INVALID_STANDING_BASIS, INVALID_REMEDY, INVALID_CONTEST_STATUS,
    RECEIPT_ID_MISMATCH, SIGNATURE_INVALID, CONTROLLER_SIGNATURE_INVALID.
    """
    if receipt.claim_type != "aps:contestability:v1":
        return {"valid": False, "reason": "INVALID_CLAIM_TYPE"}

    has_did = receipt.contestant.did is not None and receipt.contestant.did != ""
    has_pseudo = (
        receipt.contestant.pseudonym_hash is not None
        and receipt.contestant.pseudonym_hash != ""
    )
    if not has_did and not has_pseudo:
        return {"valid": False, "reason": "MISSING_CONTESTANT_IDENTITY"}

    if receipt.contestant.standing_basis not in _VALID_STANDING:
        return {"valid": False, "reason": "INVALID_STANDING_BASIS"}
    if receipt.requested_remedy not in _VALID_REMEDY:
        return {"valid": False, "reason": "INVALID_REMEDY"}
    if (
        receipt.controller_response is not None
        and receipt.controller_response.status not in _VALID_STATUS
    ):
        return {"valid": False, "reason": "INVALID_CONTEST_STATUS"}

    # Re-derive receipt_id over the filing form: empty receipt_id, empty
    # signature, NO controller_response.
    filing_form = ContestabilityReceipt(
        claim_type=receipt.claim_type,
        receipt_id="",
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        contestant=receipt.contestant,
        action_id=receipt.action_id,
        grounds=receipt.grounds,
        requested_remedy=receipt.requested_remedy,
        grounds_class=receipt.grounds_class,
        controller_response=None,
        signature="",
    )
    expected_id = _sha256_hex(
        canonicalize_jcs(filing_form.to_canonical_dict(drop_controller_response=True))
    )
    if receipt.receipt_id != expected_id:
        return {"valid": False, "reason": "RECEIPT_ID_MISMATCH"}

    # Outer signature over filing-form with populated receipt_id and empty signature.
    sig_form = ContestabilityReceipt(
        claim_type=receipt.claim_type,
        receipt_id=receipt.receipt_id,
        timestamp=receipt.timestamp,
        signer_did=receipt.signer_did,
        scope_of_claim=receipt.scope_of_claim,
        contestant=receipt.contestant,
        action_id=receipt.action_id,
        grounds=receipt.grounds,
        requested_remedy=receipt.requested_remedy,
        grounds_class=receipt.grounds_class,
        controller_response=None,
        signature="",
    )
    if not ed_verify(
        canonicalize_jcs(sig_form.to_canonical_dict(drop_controller_response=True)),
        receipt.signature,
        receipt.signer_did,
    ):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    # Controller response signature, if present.
    if receipt.controller_response is not None:
        full_with_response = ContestabilityReceipt(
            claim_type=receipt.claim_type,
            receipt_id=receipt.receipt_id,
            timestamp=receipt.timestamp,
            signer_did=receipt.signer_did,
            scope_of_claim=receipt.scope_of_claim,
            contestant=receipt.contestant,
            action_id=receipt.action_id,
            grounds=receipt.grounds,
            requested_remedy=receipt.requested_remedy,
            grounds_class=receipt.grounds_class,
            controller_response=receipt.controller_response,
            signature=receipt.signature,
        )
        if not ed_verify(
            canonicalize_jcs(
                full_with_response.to_canonical_dict(drop_response_signature=True)
            ),
            receipt.controller_response.response_signature,
            receipt.controller_response.responder_did,
        ):
            return {"valid": False, "reason": "CONTROLLER_SIGNATURE_INVALID"}

    return {"valid": True, "reason": None}
