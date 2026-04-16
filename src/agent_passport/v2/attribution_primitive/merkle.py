# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Balanced four-leaf Merkle tree — spec §2.1. Python port."""

from typing import Dict, List, Tuple

from .canonical import hash_axis_leaf, hash_node, normalize_axes
from .types import AttributionAxes


def build_merkle_frame(raw_axes: AttributionAxes) -> dict:
    """Returns {axes, leaves, nodes, root} mirroring TS MerkleFrame."""
    axes = normalize_axes(raw_axes)
    leaf_d = hash_axis_leaf(axes["D"])
    leaf_p = hash_axis_leaf(axes["P"])
    leaf_g = hash_axis_leaf(axes["G"])
    leaf_c = hash_axis_leaf(axes["C"])
    n_content = hash_node(leaf_d, leaf_p)
    n_auth_infra = hash_node(leaf_g, leaf_c)
    root = hash_node(n_content, n_auth_infra)
    return {
        "axes": axes,
        "leaves": {"D": leaf_d, "P": leaf_p, "G": leaf_g, "C": leaf_c},
        "nodes": {"N_content": n_content, "N_auth_infra": n_auth_infra},
        "root": root,
    }


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
