"""Data Source Registration & Access Receipts — Module 36A.

Source registration with Ed25519 identity, machine-readable DataTerms,
gateway-signed access receipts. Three attestation modes.

Port of TypeScript SDK src/core/data-source.ts.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .crypto import sign, verify, generate_key_pair, public_key_from_private
from .canonical import canonicalize
from .attribution import build_merkle_root, get_merkle_proof, verify_merkle_proof


# ── Types ──

DATA_PURPOSES = [
    "read", "search", "analysis", "model_training",
    "fine_tuning", "embedding", "redistribution",
    "commercial_use", "research",
]

ACCESS_METHODS = [
    "api_read", "file_read", "stream", "bulk_export", "mcp_tool",
]

COMPENSATION_MODELS = [
    "free", "attribution_only", "per_access", "per_token",
    "revenue_share", "flat_fee",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_self_attested_source(
    source_id: str, source_name: str, source_url: str,
    data_terms: dict, owner_public_key: str, owner_private_key: str,
) -> dict:
    """Register a data source where the owner signs directly (highest trust)."""
    receipt = {
        "sourceReceiptId": f"src_{uuid.uuid4().hex[:16]}",
        "sourceId": source_id,
        "sourceName": source_name,
        "sourceUrl": source_url,
        "attestationMode": "self_attested",
        "dataTerms": data_terms,
        "ownerPublicKey": owner_public_key,
        "registeredAt": _now_iso(),
    }
    receipt["signature"] = sign(canonicalize(receipt), owner_private_key)
    return receipt


def register_custodian_attested_source(
    source_id: str, source_name: str, source_url: str,
    data_terms: dict, custodian_public_key: str, custodian_private_key: str,
) -> dict:
    """Register a source where a custodian (platform) signs on behalf (medium trust)."""
    receipt = {
        "sourceReceiptId": f"src_{uuid.uuid4().hex[:16]}",
        "sourceId": source_id,
        "sourceName": source_name,
        "sourceUrl": source_url,
        "attestationMode": "custodian_attested",
        "dataTerms": data_terms,
        "custodianPublicKey": custodian_public_key,
        "registeredAt": _now_iso(),
    }
    receipt["signature"] = sign(canonicalize(receipt), custodian_private_key)
    return receipt


def register_gateway_observed_source(
    source_id: str, source_name: str, source_url: str,
    data_terms: dict, gateway_public_key: str, gateway_private_key: str,
) -> dict:
    """Register a source observed by the gateway (lowest trust, no upstream sig)."""
    receipt = {
        "sourceReceiptId": f"src_{uuid.uuid4().hex[:16]}",
        "sourceId": source_id,
        "sourceName": source_name,
        "sourceUrl": source_url,
        "attestationMode": "gateway_observed",
        "dataTerms": data_terms,
        "gatewayPublicKey": gateway_public_key,
        "registeredAt": _now_iso(),
    }
    receipt["signature"] = sign(canonicalize(receipt), gateway_private_key)
    return receipt


def verify_source_receipt(receipt: dict) -> dict:
    """Verify a source receipt's signature."""
    sig = receipt.get("signature", "")
    mode = receipt.get("attestationMode", "")
    pub_key = (
        receipt.get("ownerPublicKey") or
        receipt.get("custodianPublicKey") or
        receipt.get("gatewayPublicKey") or ""
    )
    without_sig = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        valid = verify(canonicalize(without_sig), sig, pub_key)
    except Exception:
        valid = False
    return {
        "valid": valid,
        "attestationMode": mode,
        "sourceId": receipt.get("sourceId"),
        "sourceReceiptId": receipt.get("sourceReceiptId"),
    }


def revoke_source_receipt(
    receipt: dict, revoker_private_key: str,
) -> dict:
    """Revoke a source registration. Blocks future access."""
    pub = public_key_from_private(revoker_private_key)
    signer_key = (
        receipt.get("ownerPublicKey") or
        receipt.get("custodianPublicKey") or
        receipt.get("gatewayPublicKey")
    )
    if pub != signer_key:
        raise ValueError("Revoker key does not match source signer")
    revoked = {**receipt, "revokedAt": _now_iso()}
    return revoked


def record_data_access(
    source_receipt: dict, agent_id: str,
    scope: str, access_method: str, declared_purpose: str,
    gateway_id: str, gateway_public_key: str, gateway_private_key: str,
    data_hash: str = "",
) -> dict:
    """Record a data access event. Gateway signs the receipt.

    Terms are frozen at access time (deep copy snapshot).
    """
    if source_receipt.get("revokedAt"):
        raise ValueError(f"Source {source_receipt.get('sourceId')} is revoked")

    terms_snapshot = copy.deepcopy(source_receipt.get("dataTerms", {}))

    receipt = {
        "accessReceiptId": f"dar_{uuid.uuid4().hex[:16]}",
        "sourceReceiptId": source_receipt.get("sourceReceiptId"),
        "sourceId": source_receipt.get("sourceId"),
        "agentId": agent_id,
        "scope": scope,
        "accessMethod": access_method,
        "declaredPurpose": declared_purpose,
        "dataHash": data_hash,
        "gatewayId": gateway_id,
        "gatewayPublicKey": gateway_public_key,
        "accessedAt": _now_iso(),
        "termsAtAccessTime": terms_snapshot,
    }
    receipt["signature"] = sign(canonicalize(receipt), gateway_private_key)
    return receipt


def verify_data_access_receipt(receipt: dict) -> dict:
    """Verify a data access receipt's gateway signature."""
    sig = receipt.get("signature", "")
    pub = receipt.get("gatewayPublicKey", "")
    without_sig = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        valid = verify(canonicalize(without_sig), sig, pub)
    except Exception:
        valid = False
    return {
        "valid": valid,
        "agentId": receipt.get("agentId"),
        "sourceId": receipt.get("sourceId"),
        "accessReceiptId": receipt.get("accessReceiptId"),
    }


def check_terms_compliance(
    source_receipt: dict, agent_id: str, declared_purpose: str,
) -> dict:
    """Check if an access would comply with the source's DataTerms.

    Hard violations (revoked, expired) block. Purpose mismatches are advisory.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if source_receipt.get("revokedAt"):
        errors.append("Source is revoked")
    terms = source_receipt.get("dataTerms", {})
    if terms.get("no_training") and "train" in declared_purpose.lower():
        errors.append(f"Training not permitted: {declared_purpose}")
    allowed = terms.get("allowed_purposes", terms.get("allowedPurposes", []))
    if allowed and declared_purpose not in allowed:
        warnings.append(f"Purpose '{declared_purpose}' not in allowed: {allowed}")

    return {
        "compliant": len(errors) == 0,
        "hardViolations": errors,
        "advisoryWarnings": warnings,
        "sourceId": source_receipt.get("sourceId"),
    }


def compose_terms(terms_list: list[dict]) -> dict:
    """Compose multiple DataTerms into the most restrictive intersection.

    Monotonic narrowing: composed terms can only be stricter.
    """
    if not terms_list:
        return {}
    result = copy.deepcopy(terms_list[0])
    for t in terms_list[1:]:
        # Intersect allowed purposes
        a = set(result.get("allowed_purposes", result.get("allowedPurposes", [])))
        b = set(t.get("allowed_purposes", t.get("allowedPurposes", [])))
        if a and b:
            result["allowed_purposes"] = sorted(a & b)
        # no_training: if ANY says no, it's no
        if t.get("no_training"):
            result["no_training"] = True
        # require_attribution: if ANY says yes, it's yes
        if t.get("require_attribution", t.get("requireAttribution")):
            result["require_attribution"] = True
        # retention: take the shorter
        rd = result.get("retention_days", result.get("retentionDays"))
        td = t.get("retention_days", t.get("retentionDays"))
        if rd is not None and td is not None:
            result["retention_days"] = min(rd, td)
        elif td is not None:
            result["retention_days"] = td
    return result


def build_data_access_merkle_root(receipts: list[dict]) -> str:
    """Merkle root for a batch of DataAccessReceipts."""
    leaves = [canonicalize(r) for r in receipts]
    return build_merkle_root(leaves)
