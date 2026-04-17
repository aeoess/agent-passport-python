# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Contributor-query response — Python port of
src/v2/attribution-settlement/contributor-query.ts.
"""

from typing import Optional

from .aggregate import residual_leaf_hash_hex
from .merkle import build_contributor_merkle_path, verify_merkle_path
from .sign import settlement_record_hash, verify_settlement_signature
from .verify import verify_settlement_record


def _build_axis_leaves(axis) -> list:
    leaves = [bytes.fromhex(c["merkle_leaf_hash"]) for c in axis["contributors"]]
    if axis.get("residual_bucket"):
        leaves.append(bytes.fromhex(residual_leaf_hash_hex(axis["residual_bucket"])))
    return leaves


def _find_index(axis, did: str) -> int:
    for i, c in enumerate(axis["contributors"]):
        if c["contributor_did"] == did:
            return i
    return -1


def build_contributor_query_response(record: dict, contributor_did: str, *, gateway_jwks: Optional[str] = None) -> Optional[dict]:
    if not contributor_did or not isinstance(contributor_did, str):
        raise ValueError("attribution-settlement: contributor_did required")

    per_axis = {}
    any_found = False
    for tag in ("D", "P", "G", "C"):
        axis = record["axes"][tag]
        idx = _find_index(axis, contributor_did)
        if idx < 0:
            continue
        leaves = _build_axis_leaves(axis)
        path = build_contributor_merkle_path(leaves, idx)
        per_axis[tag] = {
            "total_weight": axis["contributors"][idx]["total_weight"],
            "contribution_count": axis["contributors"][idx]["contribution_count"],
            "leaf_index": idx,
            "merkle_path": path,
            "axis_root": axis["axis_merkle_root"],
        }
        any_found = True

    if not any_found:
        return None

    body = dict(record)
    body.pop("signature", None)

    response = {
        "settlement_record": record,
        "settlement_record_hash": settlement_record_hash(body),
        "contributor_did": contributor_did,
        "per_axis": per_axis,
    }
    if gateway_jwks is not None:
        response["gateway_jwks"] = gateway_jwks
    return response


def verify_contributor_query_response(response: dict, *, gateway_public_key_hex: str) -> dict:
    if not isinstance(response, dict):
        return {"valid": False, "reason": "MALFORMED", "detail": "response must be an object"}
    if not gateway_public_key_hex:
        return {"valid": False, "reason": "MALFORMED", "detail": "gateway_public_key_hex required"}
    rec = response.get("settlement_record")
    if not isinstance(rec, dict):
        return {"valid": False, "reason": "MALFORMED", "detail": "settlement_record required"}

    inner = verify_settlement_record(rec, gateway_public_key_hex=gateway_public_key_hex)
    if not inner.get("valid"):
        return inner
    if not verify_settlement_signature(rec, gateway_public_key_hex):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}

    body = dict(rec)
    body.pop("signature", None)
    expected_hash = settlement_record_hash(body)
    if expected_hash != response["settlement_record_hash"].lower():
        return {"valid": False, "reason": "MERKLE_ROOT_MISMATCH", "detail": "settlement_record_hash mismatch"}

    for tag, axis_body in response.get("per_axis", {}).items():
        axis = rec["axes"][tag]
        if axis_body["axis_root"].lower() != axis["axis_merkle_root"].lower():
            return {"valid": False, "reason": "MERKLE_ROOT_MISMATCH", "detail": f"axes.{tag}.axis_root mismatch"}
        idx = axis_body["leaf_index"]
        if idx < 0 or idx >= len(axis["contributors"]):
            return {"valid": False, "reason": "MALFORMED", "detail": f"axes.{tag}.leaf_index out of range"}
        row = axis["contributors"][idx]
        if row["contributor_did"] != response["contributor_did"]:
            return {"valid": False, "reason": "MERKLE_ROOT_MISMATCH", "detail": f"axes.{tag}.leaf_index points to a different DID"}
        if row["total_weight"] != axis_body["total_weight"]:
            return {"valid": False, "reason": "MALFORMED", "detail": f"axes.{tag}.total_weight claim mismatch"}
        if row["contribution_count"] != axis_body["contribution_count"]:
            return {"valid": False, "reason": "MALFORMED", "detail": f"axes.{tag}.contribution_count claim mismatch"}
        leaf = bytes.fromhex(row["merkle_leaf_hash"])
        if not verify_merkle_path(leaf, idx, axis_body["merkle_path"], axis_body["axis_root"]):
            return {"valid": False, "reason": "MERKLE_ROOT_MISMATCH", "detail": f"axes.{tag} merkle_path does not reconstruct axis_root"}

    return {"valid": True}
