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


# Domain separation (CVE-2012-2459 class), Day-145 audit, receipt format
# v1.1 -> v1.2. Leaves are hashed under a 0x00 prefix and internal nodes
# under a 0x01 prefix so an internal node value can never be reinterpreted
# as a leaf. Odd nodes are promoted unchanged rather than duplicated (RFC
# 6962 style), so distinct receipt multisets (for example [a,b,c] versus
# [a,b,c,c]) can never fold to the same root. Byte-identical to
# hashLeafNode / hashInternalNode in the TypeScript src/core/attribution.ts
# and to the Go attribution package.
def _hash_leaf_node(leaf: str) -> str:
    return _sha256("\x00" + leaf)


def _hash_internal_node(left: str, right: str) -> str:
    return _sha256("\x01" + left + right)


def _reduce_merkle_level(level: list[str]) -> list[str]:
    """Fold one tree level: adjacent pairs hash under the internal-node tag;
    a trailing odd node is promoted unchanged, never duplicated."""
    nxt = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            nxt.append(_hash_internal_node(level[i], level[i + 1]))
        else:
            nxt.append(level[i])
    return nxt


def build_merkle_root(receipt_hashes: list[str]) -> str:
    """Build a Merkle root from receipt hashes, byte-identical to
    buildMerkleRoot in the TypeScript SDK: leaves are sorted ascending for
    determinism, hashed under the 0x00 leaf tag, then folded pairwise under
    the 0x01 internal-node tag with an odd trailing node promoted unchanged.

    Args:
        receipt_hashes: List of hex-encoded SHA-256 hashes.

    Returns:
        Hex-encoded Merkle root. Empty input returns sha256("empty"); a
        single leaf returns sha256(0x00 || leaf), not the leaf itself.
    """
    if not receipt_hashes:
        return _sha256("empty")

    level = [_hash_leaf_node(leaf) for leaf in sorted(receipt_hashes)]
    while len(level) > 1:
        level = _reduce_merkle_level(level)
    return level[0]


def get_merkle_proof(
    receipt_hashes: list[str], target_hash: str
) -> dict | None:
    """Generate an inclusion proof for a receipt hash, byte-identical to
    generateMerkleProof in the TypeScript SDK. A lone odd node at any level
    is promoted unchanged: it has no sibling, so it contributes no proof
    node at that level. A single-leaf tree yields an empty proof whose root
    is the domain-separated leaf hash.

    Args:
        receipt_hashes: All receipt hashes in the tree.
        target_hash: The hash to prove inclusion of.

    Returns:
        MerkleProof dict or None if hash not found.
    """
    if not receipt_hashes:
        return None

    sorted_leaves = sorted(receipt_hashes)
    if target_hash not in sorted_leaves:
        return None
    target_index = sorted_leaves.index(target_hash)

    proof_nodes = []
    level = [_hash_leaf_node(leaf) for leaf in sorted_leaves]
    index = target_index

    while len(level) > 1:
        is_right_child = index % 2 == 1
        sibling_index = index - 1 if is_right_child else index + 1

        if sibling_index < len(level):
            proof_nodes.append(
                {
                    "hash": level[sibling_index],
                    "position": "left" if is_right_child else "right",
                }
            )

        level = _reduce_merkle_level(level)
        index = index // 2

    return {
        "receiptHash": target_hash,
        "root": level[0],
        "proof": proof_nodes,
        "index": target_index,
    }


def verify_merkle_proof(proof: dict) -> bool:
    """Verify a Merkle inclusion proof against the proof's own embedded
    root. The embedded root is claimed by the proof itself; callers holding
    an independently trusted root should use
    verify_merkle_proof_against_root().

    Args:
        proof: MerkleProof dict from get_merkle_proof().

    Returns:
        True if the proof is valid.
    """
    if not proof:
        return False
    return verify_merkle_proof_against_root(proof, proof.get("root"))


def verify_merkle_proof_against_root(proof: dict, trusted_root: str) -> bool:
    """Recompute the root from the proof and compare it against a
    caller-supplied trusted root, ignoring the proof's embedded root field.

    An empty proof path recomputes to sha256(0x00 || leaf), so it is
    accepted only for the single-leaf tree whose committed root IS that
    value; against any multi-leaf root an empty proof is rejected. The old
    construction accepted any empty proof whose leaf equalled the claimed
    root, which allowed a self-claimed forgery.
    """
    if not proof or not isinstance(trusted_root, str):
        return False

    current = _hash_leaf_node(proof["receiptHash"])
    for node in proof.get("proof") or []:
        if node["position"] == "left":
            current = _hash_internal_node(node["hash"], current)
        else:
            current = _hash_internal_node(current, node["hash"])

    return current == trusted_root
