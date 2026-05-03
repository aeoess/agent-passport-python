# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Wave 1 accountability — receipt construction.

Mirrors src/v2/accountability/construct/{action,authority-boundary,custody,
contestability}.ts. APSBundle construction lives in bundle.py because it
needs computeMerkleRoot.

For Action / AuthorityBoundary / Custody / Contestability, the id-then-
signature ordering is identical:
  receipt_id = sha256(canonicalize_jcs({...receipt, receipt_id: '', signature: ''}))
  signature = Ed25519(canonicalize_jcs({...receipt with computed receipt_id, signature: ''}))

The signature covers the receipt_id, so any post-signing tampering breaks
the signature.

ContestabilityReceipt has an extra wrinkle: filing-time receipt_id and
signature are computed without controller_response. attachControllerResponse
adds a controller_response with its own signature later, leaving the outer
contestant signature unchanged.
"""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional

from ...canonical import canonicalize_jcs
from ...crypto import public_key_from_private, sign
from .types import (
    ActionPayload,
    ActionReceipt,
    AuthorityBoundaryReceipt,
    BoundaryResult,
    ContestabilityContestant,
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    ContestStatus,
    CustodyEventType,
    CustodyPurpose,
    CustodyReceipt,
    GroundsClassValue,
    RequestedRemedy,
    ScopeOfClaim,
    SideEffectClass,
    StandingBasis,
    SubjectReceiptBatch,
    TransparencyLogInclusion,
)


def _now_iso() -> str:
    """ISO 8601 UTC with millisecond precision and Z suffix.

    Matches TS new Date().toISOString() exactly.
    """
    now = datetime.now(timezone.utc)
    # Python isoformat gives microseconds; trim to ms + Z.
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _sha256_hex(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


# ── ActionReceipt ───────────────────────────────────────────────────────


def create_action_receipt(
    *,
    scope_of_claim: ScopeOfClaim,
    agent_did: str,
    delegation_chain_root: str,
    action: ActionPayload,
    side_effect_classes: List[SideEffectClass],
    signer_private_key: str,
    intent_ref: Optional[str] = None,
    policy_ref: Optional[str] = None,
    transparency_log_inclusion: Optional[TransparencyLogInclusion] = None,
    rfc3161_timestamp: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ActionReceipt:
    """Construct a signed ActionReceipt."""
    signer_did = public_key_from_private(signer_private_key)
    ts = timestamp if timestamp is not None else _now_iso()

    draft = ActionReceipt(
        claim_type="aps:action:v1",
        receipt_id="",
        timestamp=ts,
        signer_did=signer_did,
        scope_of_claim=scope_of_claim,
        agent_did=agent_did,
        delegation_chain_root=delegation_chain_root,
        action=action,
        side_effect_classes=list(side_effect_classes),
        intent_ref=intent_ref,
        policy_ref=policy_ref,
        transparency_log_inclusion=transparency_log_inclusion,
        rfc3161_timestamp=rfc3161_timestamp,
        signature="",
    )

    receipt_id = _sha256_hex(canonicalize_jcs(draft.to_canonical_dict()))
    draft.receipt_id = receipt_id
    signature = sign(canonicalize_jcs(draft.to_canonical_dict()), signer_private_key)
    draft.signature = signature
    return draft


# ── AuthorityBoundaryReceipt ────────────────────────────────────────────


def create_authority_boundary_receipt(
    *,
    scope_of_claim: ScopeOfClaim,
    action_id: str,
    evaluator_did: str,
    delegation_chain_root: str,
    result: BoundaryResult,
    evaluator_private_key: str,
    result_detail: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> AuthorityBoundaryReceipt:
    """Construct a signed AuthorityBoundaryReceipt."""
    signer_did = public_key_from_private(evaluator_private_key)
    ts = timestamp if timestamp is not None else _now_iso()

    draft = AuthorityBoundaryReceipt(
        claim_type="aps:authority_boundary:v1",
        receipt_id="",
        timestamp=ts,
        signer_did=signer_did,
        scope_of_claim=scope_of_claim,
        action_id=action_id,
        evaluator_did=evaluator_did,
        delegation_chain_root=delegation_chain_root,
        result=result,
        result_detail=result_detail,
        signature="",
    )

    receipt_id = _sha256_hex(canonicalize_jcs(draft.to_canonical_dict()))
    draft.receipt_id = receipt_id
    signature = sign(canonicalize_jcs(draft.to_canonical_dict()), evaluator_private_key)
    draft.signature = signature
    return draft


# ── CustodyReceipt ──────────────────────────────────────────────────────


def create_custody_receipt(
    *,
    scope_of_claim: ScopeOfClaim,
    custodian_did: str,
    event_type: CustodyEventType,
    subject_receipt_batch: SubjectReceiptBatch,
    purpose: CustodyPurpose,
    custodian_private_key: str,
    previous_custody_id: Optional[str] = None,
    next_custodian_did: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> CustodyReceipt:
    """Construct a signed CustodyReceipt."""
    signer_did = public_key_from_private(custodian_private_key)
    ts = timestamp if timestamp is not None else _now_iso()

    draft = CustodyReceipt(
        claim_type="aps:custody:v1",
        receipt_id="",
        timestamp=ts,
        signer_did=signer_did,
        scope_of_claim=scope_of_claim,
        custodian_did=custodian_did,
        event_type=event_type,
        subject_receipt_batch=subject_receipt_batch,
        purpose=purpose,
        previous_custody_id=previous_custody_id,
        next_custodian_did=next_custodian_did,
        signature="",
    )

    receipt_id = _sha256_hex(canonicalize_jcs(draft.to_canonical_dict()))
    draft.receipt_id = receipt_id
    signature = sign(canonicalize_jcs(draft.to_canonical_dict()), custodian_private_key)
    draft.signature = signature
    return draft


# ── ContestabilityReceipt ───────────────────────────────────────────────


def create_contestability_receipt(
    *,
    scope_of_claim: ScopeOfClaim,
    contestant: ContestabilityContestant,
    action_id: str,
    grounds: str,
    requested_remedy: RequestedRemedy,
    contestant_private_key: str,
    grounds_class: Optional[GroundsClassValue] = None,
    timestamp: Optional[str] = None,
) -> ContestabilityReceipt:
    """Construct a signed ContestabilityReceipt at filing time.

    No controller_response yet. Outer signature is computed over the
    filing-form canonical bytes (receipt without controller_response).
    """
    if (contestant.did is None or contestant.did == "") and (
        contestant.pseudonym_hash is None or contestant.pseudonym_hash == ""
    ):
        raise ValueError(
            "create_contestability_receipt: contestant must have at least "
            "one of did or pseudonym_hash"
        )

    signer_did = public_key_from_private(contestant_private_key)
    ts = timestamp if timestamp is not None else _now_iso()

    draft = ContestabilityReceipt(
        claim_type="aps:contestability:v1",
        receipt_id="",
        timestamp=ts,
        signer_did=signer_did,
        scope_of_claim=scope_of_claim,
        contestant=contestant,
        action_id=action_id,
        grounds=grounds,
        requested_remedy=requested_remedy,
        grounds_class=grounds_class,
        controller_response=None,
        signature="",
    )

    # Receipt_id and signature are computed over the filing form: no
    # controller_response, signature: "" present.
    receipt_id = _sha256_hex(
        canonicalize_jcs(draft.to_canonical_dict(drop_controller_response=True))
    )
    draft.receipt_id = receipt_id
    signature = sign(
        canonicalize_jcs(draft.to_canonical_dict(drop_controller_response=True)),
        contestant_private_key,
    )
    draft.signature = signature
    return draft


def attach_controller_response(
    receipt: ContestabilityReceipt,
    *,
    status: ContestStatus,
    responded_at: str,
    responder_did: str,
    controller_private_key: str,
    response_detail: Optional[str] = None,
) -> ContestabilityReceipt:
    """Attach a controller response with its own independent signature.

    The outer (contestant) signature is unchanged. The response signature
    covers JCS(receipt with controller_response present and response_signature
    emptied), so anyone with both DIDs can verify the two assertions
    separately.
    """
    response_draft = ContestabilityControllerResponse(
        status=status,
        responded_at=responded_at,
        responder_did=responder_did,
        response_signature="",
        response_detail=response_detail,
    )

    # Build the receipt-with-response form for signing. Response signature
    # is over JCS({...receipt with controller_response present, but the
    # response_signature field omitted from the response object}).
    receipt_with_response = ContestabilityReceipt(
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
        controller_response=response_draft,
        signature=receipt.signature,
    )
    response_signature = sign(
        canonicalize_jcs(
            receipt_with_response.to_canonical_dict(drop_response_signature=True)
        ),
        controller_private_key,
    )

    final_response = ContestabilityControllerResponse(
        status=status,
        responded_at=responded_at,
        responder_did=responder_did,
        response_signature=response_signature,
        response_detail=response_detail,
    )

    return ContestabilityReceipt(
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
        controller_response=final_response,
        signature=receipt.signature,
    )
