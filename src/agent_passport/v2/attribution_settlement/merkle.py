# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Balanced binary Merkle tree — Python port of
src/v2/attribution-settlement/merkle.ts.

The construction (Day-145 audit, receipt format v1.1 -> v1.2):

1. Compute leaf hashes over canonicalized contributor bodies.
2. Domain-separate: every leaf is re-hashed as sha256(0x00 || leaf) and
   every internal node as sha256(0x01 || left || right), so an internal
   node value can never be reinterpreted as a leaf.
3. Adjacent-pair reduction: pair (2i, 2i+1) -> internal(left, right).
4. If a level has an odd number of nodes, the trailing node is promoted
   unchanged (NOT duplicated). Duplicating it would let a set like
   [a,b,c] collide with [a,b,c,c] and forge phantom-duplicate inclusion
   (CVE-2012-2459 class).
5. Recurse until one root remains.

Empty input raises; callers use :func:`empty_axis_merkle_root` for the
empty-axis convention (I-C5).
"""

import hashlib
import re
from typing import List

from ...canonical import canonicalize


_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"

# Path token marking a level where the target was the lone odd node and was
# promoted unchanged. It cannot collide with a 64-hex digest, so
# verify_merkle_path() disambiguates promotion from a real sibling.
# Byte-identical to PROMOTED_LEVEL in the TypeScript reference.
PROMOTED_LEVEL = "promoted"


def _hash_leaf_node(leaf: bytes) -> bytes:
    """Domain-separated leaf hash: sha256(0x00 || leaf)."""
    return hashlib.sha256(_LEAF_TAG + leaf).digest()


def _hash_internal_node(left: bytes, right: bytes) -> bytes:
    """Domain-separated internal node: sha256(0x01 || left || right)."""
    return hashlib.sha256(_NODE_TAG + left + right).digest()


def _reduce_level(level: List[bytes]) -> List[bytes]:
    nxt = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            nxt.append(_hash_internal_node(level[i], level[i + 1]))
        else:
            # Odd node promoted unchanged, never duplicated.
            nxt.append(level[i])
    return nxt


def leaf_hash(obj) -> bytes:
    """sha256(canonicalize(obj)) as raw 32 bytes."""
    return hashlib.sha256(canonicalize(obj).encode("utf-8")).digest()


def build_merkle_root(leaves: List[bytes]) -> bytes:
    """Build a balanced binary Merkle tree over raw leaf hashes and return
    the root bytes. Leaves and internal nodes are domain-separated; an odd
    trailing node is promoted unchanged (never duplicated) to avoid the
    CVE-2012-2459 duplicate-leaf collision. Raises on empty input."""
    if not leaves:
        raise ValueError("attribution-settlement: build_merkle_root requires at least one leaf")
    level = [_hash_leaf_node(leaf) for leaf in leaves]
    while len(level) > 1:
        level = _reduce_level(level)
    return level[0]


def build_contributor_merkle_path(leaves: List[bytes], target_index: int) -> List[str]:
    """Return the per-level path entries (hex, bottom-up) needed to
    reconstruct the root from ``leaves[target_index]``.

    Exactly one entry per level keeps the verifier's index arithmetic in
    sync. When the target is the lone odd node it has no sibling and is
    promoted unchanged, recorded as :data:`PROMOTED_LEVEL` rather than a
    self-duplicate (which would reintroduce the collision)."""
    if not leaves:
        raise ValueError("attribution-settlement: merkle path requires at least one leaf")
    if target_index < 0 or target_index >= len(leaves):
        raise ValueError(
            f"attribution-settlement: target_index {target_index} out of range for {len(leaves)} leaves"
        )
    path: List[str] = []
    level = [_hash_leaf_node(leaf) for leaf in leaves]
    idx = target_index
    while len(level) > 1:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        path.append(level[sibling_idx].hex() if sibling_idx < len(level) else PROMOTED_LEVEL)
        level = _reduce_level(level)
        idx = idx // 2
    return path


def verify_merkle_path(leaf: bytes, leaf_index: int, path: List[str], expected_root_hex: str) -> bool:
    """Reconstruct the root from (leaf, leaf_index, path) and compare
    against ``expected_root_hex`` (case-insensitive)."""
    if leaf_index < 0:
        return False
    acc = _hash_leaf_node(leaf)
    idx = leaf_index
    for sibling_hex in path:
        if sibling_hex == PROMOTED_LEVEL:
            # Lone odd node promoted unchanged: nothing to combine here.
            idx = idx // 2
            continue
        if not isinstance(sibling_hex, str) or not _HEX64.match(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex)
        if len(sibling) != 32:
            return False
        is_right = idx % 2 == 1
        acc = _hash_internal_node(sibling, acc) if is_right else _hash_internal_node(acc, sibling)
        idx = idx // 2
    return acc.hex() == expected_root_hex.lower()


def empty_axis_merkle_root() -> str:
    """Hex sha256 of canonicalize([]) — the empty-axis convention (I-C5)."""
    return hashlib.sha256(canonicalize([]).encode("utf-8")).hexdigest()
