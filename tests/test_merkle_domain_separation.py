# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Merkle domain separation (CVE-2012-2459 class) — Day-145 audit, receipt
format v1.1 -> v1.2.

The previous Bitcoin-style construction duplicated the trailing odd node and
hashed leaves and internal nodes under one function, so distinct receipt
multisets collided to one root: build_merkle_root([a,b,c]) equalled
build_merkle_root([a,b,c,c]). These tests fail on that construction and pass
once leaves hash under a 0x00 tag, internal nodes under a 0x01 tag, and odd
nodes are promoted unchanged.

The verify_merkle_proof_against_root import happens inside its tests so the
collision tests in this file still run against unfixed code (fail-before).
"""

import hashlib

from agent_passport import build_merkle_root, get_merkle_proof, verify_merkle_proof

A = "a" * 64
B = "b" * 64
C = "c" * 64


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_duplicate_leaf_collision_defeated():
    """A 3-leaf set and its odd-duplicate 4-leaf sibling produce DIFFERENT roots."""
    three = build_merkle_root([A, B, C])
    dup = build_merkle_root([A, B, C, C])
    assert three != dup, "CVE-2012-2459: distinct multisets must not collide to one root"


def test_genuine_inclusion_proof_still_verifies():
    leaves = [A, B, C]
    three = build_merkle_root(leaves)
    for target in leaves:
        proof = get_merkle_proof(leaves, target)
        assert proof is not None
        assert proof["root"] == three
        assert verify_merkle_proof(proof)


def test_phantom_duplicate_root_differs():
    """A proof over the forged 4-leaf duplicate view is internally consistent
    against ITS OWN root, but that root must not equal the honest 3-leaf
    commitment, so the phantom cannot be replayed."""
    three = build_merkle_root([A, B, C])
    phantom = get_merkle_proof([A, B, C, C], C)
    assert phantom is not None
    assert verify_merkle_proof(phantom)
    assert phantom["root"] != three, "phantom-duplicate root must not equal the honest root"


def test_pinned_cross_language_roots():
    """Known-answer roots shared verbatim with the TypeScript reference
    (audit/day145/sdk-merkle-domain-separation), the Go SDK tests, and
    fixtures/merkle-root-parity in the conformance suite. Leaves are
    sha256("aps-merkle-parity-<i>")."""
    leaves = [_sha256_hex(f"aps-merkle-parity-{i}") for i in range(8)]
    pinned = {
        1: "44e90912f4e083b9d12a68a327611fae945976dd062a696dbd1b4c159b2e206d",
        2: "bb4dae845225140a964afd1ea33eac2f49db0845d829a1deed974c6576210a9c",
        3: "53fc826f785d4c225cde4fcec9e44d3523f9989be4d112b7be065378f54ae436",
        5: "1837e308723f0acf6a8e9605a721def4dc95a60a4e57cd6a07c4af80df1c80a7",
        8: "fb88356945f6f9b347aec2a7a4d14f788dbba44472fd911e201f6399cb843096",
    }
    for n, want in pinned.items():
        assert build_merkle_root(leaves[:n]) == want, f"n={n}: root diverged from TS reference"


def test_verify_against_trusted_root_genuine_and_phantom():
    from agent_passport import verify_merkle_proof_against_root

    leaves = [A, B, C]
    three = build_merkle_root(leaves)
    proof = get_merkle_proof(leaves, C)
    assert verify_merkle_proof_against_root(proof, three)
    other = build_merkle_root([A, B])
    assert not verify_merkle_proof_against_root(proof, other)

    phantom = get_merkle_proof([A, B, C, C], C)
    assert not verify_merkle_proof_against_root(phantom, three), (
        "phantom-duplicate proof must not verify against the honest root"
    )


def test_empty_proof_rejected_unless_single_leaf():
    from agent_passport import verify_merkle_proof_against_root

    solo_root = build_merkle_root(["only-leaf"])
    solo_proof = get_merkle_proof(["only-leaf"], "only-leaf")
    assert solo_proof is not None
    assert solo_proof["proof"] == []
    assert verify_merkle_proof_against_root(solo_proof, solo_root)

    # Self-claim forgery: leaf value equals the multi-leaf root, empty path.
    multi_root = build_merkle_root([A, B, C])
    forged = {"receiptHash": multi_root, "root": multi_root, "proof": [], "index": 0}
    assert not verify_merkle_proof(forged)
    assert not verify_merkle_proof_against_root(forged, multi_root)
