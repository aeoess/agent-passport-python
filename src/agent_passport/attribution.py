"""Beneficiary attribution — Merkle proofs and contribution tracking.

Layer 3 operations for the Agent Passport System.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any


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
