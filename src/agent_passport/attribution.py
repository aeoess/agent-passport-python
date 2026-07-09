# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Beneficiary attribution — Merkle proofs and contribution tracking.

Layer 3 operations for the Agent Passport System.
"""

from __future__ import annotations

import hashlib
import math
import uuid
from typing import Any


def trace_beneficiary(receipt: dict, delegations: list, beneficiary_map: dict) -> dict:
    """Follow the delegation chain from an action receipt back to the human beneficiary.

    Reports two DISTINCT, honestly-named properties (mirrors the TypeScript traceBeneficiary):

      resolved  Lookup success only. Every hop's (from, to) key pair maps to a known
                delegation record AND the principal resolves to a known beneficiary. NO
                cryptographic claim: a creator-supplied chain that matches known records can
                be resolved.
      verified  Cryptographic. The receipt signature verifies at the chain tail
                (verify_action_receipt) AND every delegation in the lineage verifies
                (some matching delegation per hop passes verify_delegation). A forged or
                tampered chain cannot be verified.

    The reported lineage is deterministic (valid-first, then delegationId) with the TAIL hop
    tied to receipt.delegationId, so the same inputs always report the same chain. Reuses the
    canonical verify_delegation / verify_action_receipt; no crypto is reimplemented. ``verified``
    attests lineage signature authenticity only; it does not check action authorization or
    inter-hop scope narrowing.
    """
    from .delegation import verify_action_receipt, verify_delegation  # local: avoid import cycle

    key_chain = receipt.get("delegationChain") or []
    n = len(key_chain)
    chain: list[dict] = []
    every_hop_authentic = True

    for i in range(n - 1):
        frm = key_chain[i]
        to = key_chain[i + 1]
        is_tail = i == n - 2
        matches = [
            {"d": d, "valid": bool(verify_delegation(d).get("valid"))}
            for d in delegations
            if d.get("delegatedBy") == frm and d.get("delegatedTo") == to
        ]
        if not any(m["valid"] for m in matches):
            every_hop_authentic = False
        # Deterministic selection: valid first, then delegationId ascending.
        ordered = sorted(matches, key=lambda m: (0 if m["valid"] else 1, m["d"].get("delegationId") or ""))
        chosen = None
        if is_tail:
            chosen = next(
                (m for m in ordered if m["d"].get("delegationId") == receipt.get("delegationId")), None
            )
        if chosen is None and ordered:
            chosen = ordered[0]
        chain.append(
            {
                "from": frm,
                "to": to,
                "delegationId": (chosen["d"].get("delegationId") if chosen else None) or "unknown",
                "scope": (chosen["d"].get("scope") if chosen else None) or [],
                "depth": i,
            }
        )

    principal_key = key_chain[0] if key_chain else None
    beneficiary_info = beneficiary_map.get(principal_key) if principal_key is not None else None

    # resolved: previous lookup semantics, honestly named. No cryptographic claim.
    resolved = bool(beneficiary_info) and n > 1 and all(h["delegationId"] != "unknown" for h in chain)

    # verified: real cryptographic verification. Receipt signed by the executor (chain tail),
    # every hop has a verifying delegation, at least one hop.
    executor_key = key_chain[-1] if key_chain else None
    receipt_authentic = n > 0 and verify_action_receipt(receipt, executor_key).get("valid", False)
    verified = n > 1 and receipt_authentic and every_hop_authentic

    return {
        "traceId": "trace_" + uuid.uuid4().hex[:12],
        "receiptId": receipt.get("receiptId"),
        "executorAgent": receipt.get("agentId"),
        "beneficiary": (beneficiary_info.get("principalId") if beneficiary_info else principal_key),
        "chain": chain,
        "totalDepth": len(chain),
        "resolved": resolved,
        "verified": verified,
    }


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_merkle_root(receipt_hashes: list[str]) -> str:
    """Build a Merkle root from receipt hashes.

    Args:
        receipt_hashes: List of hex-encoded SHA-256 hashes.

    Returns:
        Hex-encoded Merkle root hash. Empty string for empty input.
    """
    if not receipt_hashes:
        return ""
    if len(receipt_hashes) == 1:
        return receipt_hashes[0]

    # Pad to even
    leaves = list(receipt_hashes)
    if len(leaves) % 2 != 0:
        leaves.append(leaves[-1])

    # Build tree bottom-up
    level = leaves
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            combined = _sha256(left + right)
            next_level.append(combined)
        level = next_level

    return level[0]


def get_merkle_proof(
    receipt_hashes: list[str], target_hash: str
) -> dict | None:
    """Generate an inclusion proof for a receipt hash.

    Args:
        receipt_hashes: All receipt hashes in the tree.
        target_hash: The hash to prove inclusion of.

    Returns:
        MerkleProof dict or None if hash not found.
    """
    if target_hash not in receipt_hashes:
        return None
    if len(receipt_hashes) == 1:
        return {
            "receiptHash": target_hash,
            "root": target_hash,
            "proof": [],
            "index": 0,
        }

    leaves = list(receipt_hashes)
    if len(leaves) % 2 != 0:
        leaves.append(leaves[-1])

    index = leaves.index(target_hash)
    proof_nodes = []
    level = leaves

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left

            if i == index or i + 1 == index:
                if i == index:
                    proof_nodes.append({"hash": right, "position": "right"})
                else:
                    proof_nodes.append({"hash": left, "position": "left"})

            combined = _sha256(left + right)
            next_level.append(combined)

        index = index // 2
        level = next_level

    root = level[0]
    return {
        "receiptHash": target_hash,
        "root": root,
        "proof": proof_nodes,
        "index": receipt_hashes.index(target_hash),
    }


def verify_merkle_proof(proof: dict) -> bool:
    """Verify a Merkle inclusion proof.

    Args:
        proof: MerkleProof dict from get_merkle_proof().

    Returns:
        True if the proof is valid.
    """
    if not proof or not proof.get("proof"):
        return proof is not None and proof.get("receiptHash") == proof.get("root")

    current = proof["receiptHash"]
    for node in proof["proof"]:
        if node["position"] == "left":
            current = _sha256(node["hash"] + current)
        else:
            current = _sha256(current + node["hash"])

    return current == proof["root"]
