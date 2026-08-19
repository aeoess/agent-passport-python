# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Balanced four-leaf Merkle tree — spec §2.1. Python port."""

from typing import Dict, List, Tuple

from .canonical import (
    hash_axis_leaf,
    hash_axis_leaf_for_write,
    hash_node,
    normalize_axes,
)
from .types import AttributionAxes


def _build_merkle_frame_impl(raw_axes: AttributionAxes, _leaf) -> dict:
    """Shared body so the read and write twins can never drift apart."""
    axes = normalize_axes(raw_axes)
    leaf_d = _leaf(axes["D"])
    leaf_p = _leaf(axes["P"])
    leaf_g = _leaf(axes["G"])
    leaf_c = _leaf(axes["C"])
    n_content = hash_node(leaf_d, leaf_p)
    n_auth_infra = hash_node(leaf_g, leaf_c)
    root = hash_node(n_content, n_auth_infra)
    return {
        "axes": axes,
        "leaves": {"D": leaf_d, "P": leaf_p, "G": leaf_g, "C": leaf_c},
        "nodes": {"N_content": n_content, "N_auth_infra": n_auth_infra},
        "root": root,
    }


def build_merkle_frame(raw_axes: AttributionAxes) -> dict:
    """Returns {axes, leaves, nodes, root} mirroring TS MerkleFrame."""
    return _build_merkle_frame_impl(raw_axes, hash_axis_leaf)


def build_merkle_frame_for_write(raw_axes: AttributionAxes) -> dict:
    """Write-boundary twin of :func:`build_merkle_frame`.

    Produces the same frame as :func:`build_merkle_frame` for every value it accepts.
    The only difference is that an integer-valued number outside the interoperable
    IEEE 754 range is refused instead of hashed into a leaf. Use when CONSTRUCTING a
    primitive; projection and verification keep calling :func:`build_merkle_frame` so
    a primitive built before this rule still reconstructs.
    """
    return _build_merkle_frame_impl(raw_axes, hash_axis_leaf_for_write)


def projection_path(frame: dict, axis: str) -> Tuple[str, str]:
    leaves = frame["leaves"]
    nodes = frame["nodes"]
    if axis == "D":
        return (leaves["P"].hex(), nodes["N_auth_infra"].hex())
    if axis == "P":
        return (leaves["D"].hex(), nodes["N_auth_infra"].hex())
    if axis == "G":
        return (leaves["C"].hex(), nodes["N_content"].hex())
    if axis == "C":
        return (leaves["G"].hex(), nodes["N_content"].hex())
    raise ValueError(f"attribution-primitive: unknown axis tag {axis!r}")


def reconstruct_root(axis_leaf: bytes, path, axis: str) -> bytes:
    if not isinstance(path, (list, tuple)) or len(path) != 2:
        raise ValueError("attribution-primitive: merkle path must have length 2")
    sibling = bytes.fromhex(path[0])
    sibling_internal = bytes.fromhex(path[1])
    if len(sibling) != 32 or len(sibling_internal) != 32:
        raise ValueError(
            "attribution-primitive: merkle path hashes must be 32-byte sha256"
        )
    if axis == "D":
        internal = hash_node(axis_leaf, sibling)
        return hash_node(internal, sibling_internal)
    if axis == "P":
        internal = hash_node(sibling, axis_leaf)
        return hash_node(internal, sibling_internal)
    if axis == "G":
        internal = hash_node(axis_leaf, sibling)
        return hash_node(sibling_internal, internal)
    if axis == "C":
        internal = hash_node(sibling, axis_leaf)
        return hash_node(sibling_internal, internal)
    raise ValueError(f"attribution-primitive: unknown axis tag {axis!r}")
