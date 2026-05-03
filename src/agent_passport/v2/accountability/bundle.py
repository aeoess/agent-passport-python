# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Wave 1 accountability — APSBundle construction + verification.

Mirrors src/v2/accountability/{construct,verify}/bundle.ts. The bundle's
canonical-bytes contract differs from the other 4 receipts: TS uses
`{...skeleton, signature: undefined}` for both receipt_id derivation and
signature payload, which JSON.stringify drops entirely. The Python port
calls APSBundle.to_canonical_dict(drop_signature_field=True) for both,
so the canonical dict has no `signature` key at all (rather than
`signature: ""`).

Merkle commitment over receipt_ids:
  - Sort lexicographically
  - Hash each leaf via sha256(receipt_id_string)
  - Pair-wise sha256 over `hex_left + hex_right` string concatenation
  - Odd-length layers duplicate the trailing leaf
  - Empty input returns sha256("") as the canonical sentinel
"""

from datetime import datetime, timezone
from hashlib import sha256
from typing import List, Optional

from ...canonical import canonicalize_jcs
from ...crypto import public_key_from_private, sign, verify
from .types import (
    APSBundle,
    BundledReceiptRef,
    ScopeOfClaim,
)


def _sha256_hex(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def compute_merkle_root(receipt_ids: List[str]) -> str:
    """Balanced binary Merkle tree over sorted receipt ids.

    Empty input returns sha256("") as the canonical sentinel.
    Odd-length layers duplicate the trailing element.
    """
    if len(receipt_ids) == 0:
        return _sha256_hex("")
    sorted_ids = sorted(receipt_ids)
    layer = [_sha256_hex(rid) for rid in sorted_ids]
    while len(layer) > 1:
        next_layer: List[str] = []
        i = 0
        while i < len(layer):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            next_layer.append(_sha256_hex(left + right))
            i += 2
        layer = next_layer
    return layer[0]


def create_aps_bundle(
    *,
    bundler_did: str,
    period_start: str,
    period_end: str,
    receipts: List[BundledReceiptRef],
    profile_conformance: List[str],
    scope_of_claim: ScopeOfClaim,
    bundler_private_key: str,
    subject_scope: Optional[List[str]] = None,
    timestamp: Optional[str] = None,
) -> APSBundle:
    """Construct a signed APSBundle.

    Receipt_id and signature are both computed over the canonical form
    WITHOUT the signature key (TS `signature: undefined` semantics).
    """
    ts = timestamp if timestamp is not None else _now_iso()
    signer_did = public_key_from_private(bundler_private_key)
    merkle_root = compute_merkle_root([r.receipt_id for r in receipts])
    receipt_count = len(receipts)

    draft = APSBundle(
        claim_type="aps:bundle:v1",
        receipt_id="",
        timestamp=ts,
        signer_did=signer_did,
        scope_of_claim=scope_of_claim,
        bundler_did=bundler_did,
        period_start=period_start,
        period_end=period_end,
        merkle_root=merkle_root,
        receipt_count=receipt_count,
        profile_conformance=list(profile_conformance),
        signature="",
        subject_scope=list(subject_scope) if subject_scope is not None else None,
    )

    # Receipt_id over canonical form WITHOUT signature key.
    receipt_id = _sha256_hex(
        canonicalize_jcs(draft.to_canonical_dict(drop_signature_field=True))
    )
    draft.receipt_id = receipt_id

    # Signature payload over the SAME form (without signature key), with
    # the receipt_id now populated.
    signature = sign(
        canonicalize_jcs(draft.to_canonical_dict(drop_signature_field=True)),
        bundler_private_key,
    )
    draft.signature = signature
    return draft


# ── Verification ────────────────────────────────────────────────────────


APSBundleVerifyReason = str  # one of the literals below


def verify_aps_bundle(bundle: APSBundle) -> dict:
    """Verify an APSBundle.

    Returns: {"valid": bool, "reason": Optional[APSBundleVerifyReason]}.
    Reasons match TS exactly: INVALID_CLAIM_TYPE, INVALID_MERKLE_ROOT,
    INVALID_RECEIPT_COUNT, RECEIPT_ID_MISMATCH, SIGNATURE_INVALID.
    """
    if bundle.claim_type != "aps:bundle:v1":
        return {"valid": False, "reason": "INVALID_CLAIM_TYPE"}
    if not isinstance(bundle.merkle_root, str) or len(bundle.merkle_root) != 64:
        return {"valid": False, "reason": "INVALID_MERKLE_ROOT"}
    if not isinstance(bundle.receipt_count, int) or bundle.receipt_count < 0:
        return {"valid": False, "reason": "INVALID_RECEIPT_COUNT"}

    # Re-derive receipt_id from canonical form WITHOUT signature key, with
    # the bundle's receipt_id field cleared for the derivation form.
    derive_form = APSBundle(
        claim_type=bundle.claim_type,
        receipt_id="",
        timestamp=bundle.timestamp,
        signer_did=bundle.signer_did,
        scope_of_claim=bundle.scope_of_claim,
        bundler_did=bundle.bundler_did,
        period_start=bundle.period_start,
        period_end=bundle.period_end,
        merkle_root=bundle.merkle_root,
        receipt_count=bundle.receipt_count,
        profile_conformance=list(bundle.profile_conformance),
        signature="",
        subject_scope=list(bundle.subject_scope) if bundle.subject_scope is not None else None,
    )
    expected_id = _sha256_hex(
        canonicalize_jcs(derive_form.to_canonical_dict(drop_signature_field=True))
    )
    if bundle.receipt_id != expected_id:
        return {"valid": False, "reason": "RECEIPT_ID_MISMATCH"}

    # Signature payload: same form with populated receipt_id, no signature key.
    sig_payload = canonicalize_jcs(bundle.to_canonical_dict(drop_signature_field=True))
    if not verify(sig_payload, bundle.signature, bundle.signer_did):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    return {"valid": True, "reason": None}
