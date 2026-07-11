"""Tests for Merkle tree and attribution proofs."""

import hashlib
from agent_passport import build_merkle_root, get_merkle_proof, verify_merkle_proof


def _hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def test_deterministic_root():
    hashes = [_hash("a"), _hash("b"), _hash("c")]
    root1 = build_merkle_root(hashes)
    root2 = build_merkle_root(hashes)
    assert root1 == root2


def test_different_inputs_different_roots():
    r1 = build_merkle_root([_hash("a"), _hash("b")])
    r2 = build_merkle_root([_hash("x"), _hash("y")])
    assert r1 != r2


def test_single_element():
    # Day-145 audit (receipt format v1.1 -> v1.2): a single leaf hashes under
    # the 0x00 leaf tag instead of passing through, so an internal node value
    # can never be replayed as a single-leaf root.
    h = _hash("only")
    root = build_merkle_root([h])
    assert root != h
    assert root == hashlib.sha256(("\x00" + h).encode("utf-8")).hexdigest()


def test_empty():
    # Day-145 audit: empty input returns sha256("empty"), matching the
    # TypeScript reference, instead of the old empty-string sentinel.
    assert build_merkle_root([]) == hashlib.sha256(b"empty").hexdigest()


def test_proof_and_verify():
    hashes = [_hash(f"receipt_{i}") for i in range(5)]
    target = hashes[2]
    proof = get_merkle_proof(hashes, target)
    assert proof is not None
    assert verify_merkle_proof(proof)


def test_tampered_proof_fails():
    hashes = [_hash(f"receipt_{i}") for i in range(5)]
    proof = get_merkle_proof(hashes, hashes[1])
    assert proof is not None
    proof["receiptHash"] = _hash("TAMPERED")
    assert not verify_merkle_proof(proof)


def test_nonexistent_hash():
    hashes = [_hash("a"), _hash("b")]
    proof = get_merkle_proof(hashes, _hash("nonexistent"))
    assert proof is None
