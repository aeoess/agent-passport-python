# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Balanced binary Merkle tree — Python port of
src/v2/attribution-settlement/merkle.ts.

Adjacent-pair reduction: pair (2i, 2i+1) → hashNode(left, right). Odd
levels duplicate the trailing node. Empty input throws; callers use
:func:`empty_axis_merkle_root` for the empty-axis convention (I-C5).
"""

import hashlib
import re
from typing import List

from ...canonical import canonicalize
from ..attribution_primitive.canonical import hash_node


_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def leaf_hash(obj) -> bytes:
    """sha256(canonicalize(obj)) as raw 32 bytes."""
    return hashlib.sha256(canonicalize(obj).encode("utf-8")).digest()


def build_merkle_root(leaves: List[bytes]) -> bytes:
    """Build a balanced binary Merkle tree over raw leaf hashes and
    return the root bytes. Throws on empty input."""
    if not leaves:
        raise ValueError("attribution-settlement: build_merkle_root requires at least one leaf")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hash_node(left, right))
        level = nxt
    return level[0]


def build_contributor_merkle_path(leaves: List[bytes], target_index: int) -> List[str]:
    """Return the sibling hashes (hex, bottom-up) needed to reconstruct
    the root from ``leaves[target_index]``."""
    if not leaves:
        raise ValueError("attribution-settlement: merkle path requires at least one leaf")
    if target_index < 0 or target_index >= len(leaves):
        raise ValueError(
            f"attribution-settlement: target_index {target_index} out of range for {len(leaves)} leaves"
        )
    path: List[str] = []
    level = list(leaves)
    idx = target_index
    while len(level) > 1:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
        path.append(sibling.hex())
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hash_node(left, right))
        level = nxt
        idx = idx // 2
    return path


def verify_merkle_path(leaf: bytes, leaf_index: int, path: List[str], expected_root_hex: str) -> bool:
    """Reconstruct the root from (leaf, leaf_index, path) and compare
    against ``expected_root_hex`` (case-insensitive)."""
    if leaf_index < 0:
        return False
    acc = leaf
    idx = leaf_index
    for sibling_hex in path:
        if not isinstance(sibling_hex, str) or not _HEX64.match(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex)
        if len(sibling) != 32:
            return False
        is_right = idx % 2 == 1
        acc = hash_node(sibling, acc) if is_right else hash_node(acc, sibling)
        idx = idx // 2
    return acc.hex() == expected_root_hex.lower()


def empty_axis_merkle_root() -> str:
    """Hex sha256 of canonicalize([]) — the empty-axis convention (I-C5)."""
    return hashlib.sha256(canonicalize([]).encode("utf-8")).hexdigest()
