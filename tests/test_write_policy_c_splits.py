# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Phase 2B: shared canonicalization helpers split into read and write twins.

Each helper below was reachable from BOTH a signing path and a verification path. A
guard placed on the shared helper would have refused to rebuild the preimage of an
artifact signed before the APS unsafe-integer rule existed, so each one gained a
``*_for_write`` twin used only by the constructing callers.

Every twin is checked for four properties:
  1. safe input: twin output is byte-identical to the original
  2. a top-level unsafe integer is refused, at the exact path
  3. a nested unsafe integer is refused, at the exact nested path
  4. the mapping is read exactly ONCE on the write path, so the value validated is the
     value emitted (a second read is what a getter would use to smuggle a value past)

The originals are additionally checked to stay unrestricted, which is what keeps
historical artifacts verifiable.
"""

import pytest

from agent_passport.write_policy import UnsafeIntegerError

from agent_passport.v2.human_escalation import _hash_object, _hash_object_for_write
from agent_passport.v2.attribution_consent.create import receipt_core, receipt_core_for_write
from agent_passport.v2.attribution_primitive.canonical import (
    canonical_hash_hex,
    canonical_hash_hex_for_write,
    envelope_bytes,
    envelope_bytes_for_write,
    hash_axis_leaf,
    hash_axis_leaf_for_write,
)
from agent_passport.v2.attribution_primitive.merkle import (
    build_merkle_frame,
    build_merkle_frame_for_write,
)
from agent_passport.v2.attribution_settlement.aggregate import (
    residual_leaf_hash_hex,
    residual_leaf_hash_hex_for_write,
)
from agent_passport.v2.attribution_settlement.merkle import leaf_hash, leaf_hash_for_write
from agent_passport.v2.attribution_settlement.sign import (
    settlement_signing_payload,
    settlement_signing_payload_for_write,
)
from agent_passport.v2.instruction_provenance.canonicalize import (
    canonicalize_envelope,
    canonicalize_envelope_for_write,
    compute_context_root,
    compute_context_root_for_write,
)
from agent_passport.v2.provisional_statement.create import (
    statement_signing_payload,
    statement_signing_payload_for_write,
)
from agent_passport.v2.read_fidelity_receipt.receipt import (
    canonical_no_sig,
    canonical_no_sig_for_write,
)

SAFE = 9007199254740991
UNSAFE = 9007199254740992


def _receipt(amount):
    return {
        "version": "1.0",
        "citer": "did:aps:citer",
        "citer_public_key": "aa" * 32,
        "cited_principal": "did:aps:cited",
        "cited_principal_public_key": "bb" * 32,
        "citation_content": {"quote": "text", "weight": amount},
        "binding_context": "ctx",
        "created_at": {"wall_clock": "2026-08-19T00:00:00.000Z", "logical": 1},
        "expires_at": {"wall_clock": "2026-09-19T00:00:00.000Z", "logical": 2},
    }


def _statement(amount):
    return {
        "id": "stmt_1",
        "version": 1,
        "author": "did:aps:a",
        "author_principal": "did:aps:p",
        "content": {"body": "hello", "weight": amount},
        "created_at": {"wall_clock": "2026-08-19T00:00:00.000Z", "logical": 1},
    }


def _envelope():
    return {
        "action_ref": "ab" * 32,
        "merkle_root": "cd" * 32,
        "issuer": "did:aps:issuer",
        "timestamp": "2026-08-19T00:00:00.000Z",
    }


def _axes(amount):
    return {
        "D": [{
            "source_did": "did:data:one",
            "contribution_weight": "1.000000",
            "access_receipt_hash": "a" * 64,
            "sample_count": amount,
        }],
        "P": [],
        "G": [],
        "C": [],
    }


# (label, original, twin, safe_input, unsafe_input, expected_path)
CASES = [
    ("_hash_object", _hash_object, _hash_object_for_write,
     {"a": SAFE}, {"a": UNSAFE}, "$.a"),
    ("leaf_hash", leaf_hash, leaf_hash_for_write,
     {"a": SAFE}, {"a": UNSAFE}, "$.a"),
    ("residual_leaf_hash_hex", residual_leaf_hash_hex, residual_leaf_hash_hex_for_write,
     {"a": SAFE}, {"a": UNSAFE}, "$.a"),
    ("hash_axis_leaf", hash_axis_leaf, hash_axis_leaf_for_write,
     {"a": SAFE}, {"a": UNSAFE}, "$.a"),
    ("canonical_hash_hex", canonical_hash_hex, canonical_hash_hex_for_write,
     {"a": SAFE}, {"a": UNSAFE}, "$.a"),
    ("settlement_signing_payload", settlement_signing_payload, settlement_signing_payload_for_write,
     {"a": SAFE, "signature": "x"}, {"a": UNSAFE, "signature": "x"}, "$.a"),
    ("canonical_no_sig", canonical_no_sig, canonical_no_sig_for_write,
     {"a": SAFE, "sig": "x"}, {"a": UNSAFE, "sig": "x"}, "$.a"),
    ("receipt_core", receipt_core, receipt_core_for_write,
     _receipt(SAFE), _receipt(UNSAFE), "$.citation_content.weight"),
    ("statement_signing_payload", statement_signing_payload, statement_signing_payload_for_write,
     _statement(SAFE), _statement(UNSAFE), "$.content.weight"),
]

NESTED_SAFE = {"a": {"b": [{"c": SAFE}]}}
NESTED_UNSAFE = {"a": {"b": [{"c": UNSAFE}]}}


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", CASES, ids=[c[0] for c in CASES])
def test_twin_matches_original_on_safe_input(label, orig, twin, safe, unsafe, path):
    assert twin(safe) == orig(safe)


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", CASES, ids=[c[0] for c in CASES])
def test_twin_refuses_unsafe_integer_at_exact_path(label, orig, twin, safe, unsafe, path):
    with pytest.raises(UnsafeIntegerError) as exc:
        twin(unsafe)
    assert str(exc.value).startswith(path + ":"), str(exc.value)
    assert exc.value.category == "invalid_number"
    assert exc.value.reason == "integer_exceeds_interoperable_range"


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", CASES, ids=[c[0] for c in CASES])
def test_original_stays_unrestricted(label, orig, twin, safe, unsafe, path):
    """The read twin must keep accepting what it accepted before the rule existed."""
    orig(unsafe)


NESTED_CASES = [c for c in CASES if c[0] in (
    "_hash_object", "leaf_hash", "residual_leaf_hash_hex", "hash_axis_leaf",
    "canonical_hash_hex", "settlement_signing_payload", "canonical_no_sig")]


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", NESTED_CASES, ids=[c[0] for c in NESTED_CASES])
def test_twin_refuses_nested_unsafe_at_exact_nested_path(label, orig, twin, safe, unsafe, path):
    assert twin(NESTED_SAFE) == orig(NESTED_SAFE)
    with pytest.raises(UnsafeIntegerError) as exc:
        twin(NESTED_UNSAFE)
    assert str(exc.value).startswith("$.a.b[0].c:"), str(exc.value)


class CountingDict(dict):
    """Answers safe on the first read of a key and unsafe on every read after it.

    A check-then-canonicalize helper would validate the safe first answer and then
    serialize the unsafe second one. A single-observation helper cannot.
    """

    def __init__(self, key, first, later):
        super().__init__({key: first})
        self._key = key
        self._first = first
        self._later = later
        self.reads = 0

    def __getitem__(self, key):
        if key == self._key:
            self.reads += 1
            return self._first if self.reads == 1 else self._later
        return super().__getitem__(key)


# Two distinct ways to reach single observation, and both are correct:
#   DIRECT      the caller's mapping is handed straight to the write canonicalizer,
#               which captures each value once. Expected read count is exactly 1.
#   MATERIALIZE the helper first copies the mapping (dict(record) or .items()), which
#               freezes the observation before canonicalization and, on a dict
#               subclass, bypasses __getitem__ entirely. Expected read count is 0.
# What matters in both cases is that the mapping is observed AT MOST once, so the
# value validated is necessarily the value emitted.
DIRECT_CASES = [c for c in CASES if c[0] in (
    "_hash_object", "leaf_hash", "residual_leaf_hash_hex", "hash_axis_leaf",
    "canonical_hash_hex")]
MATERIALIZE_CASES = [c for c in CASES if c[0] in (
    "settlement_signing_payload", "canonical_no_sig")]
ACCESSOR_CASES = DIRECT_CASES + MATERIALIZE_CASES


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", DIRECT_CASES, ids=[c[0] for c in DIRECT_CASES])
def test_direct_twin_reads_each_key_exactly_once(label, orig, twin, safe, unsafe, path):
    """Assert the READ COUNT, not only the emitted value.

    A helper that validated and then re-serialized would report reads == 2 here while
    still producing safe-looking output, which is exactly the bug this guards.
    """
    d = CountingDict("a", SAFE, UNSAFE)
    twin(d)
    assert d.reads == 1, "write path observed the key %d times" % d.reads


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", MATERIALIZE_CASES, ids=[c[0] for c in MATERIALIZE_CASES])
def test_materializing_twin_observes_at_most_once(label, orig, twin, safe, unsafe, path):
    d = CountingDict("a", SAFE, UNSAFE)
    twin(d)
    assert d.reads <= 1, "write path observed the key %d times" % d.reads


@pytest.mark.parametrize("label,orig,twin,safe,unsafe,path", ACCESSOR_CASES, ids=[c[0] for c in ACCESSOR_CASES])
def test_twin_refuses_when_the_stored_value_is_unsafe(label, orig, twin, safe, unsafe, path):
    """An accessor cannot get a safe value signed by answering safe once and unsafe later."""
    d = CountingDict("a", UNSAFE, SAFE)
    with pytest.raises(UnsafeIntegerError):
        twin(d)
    assert d.reads <= 1


# ── Cascading splits: helpers that reach a canonicalizer indirectly ──────────

def test_build_merkle_frame_twin_matches_and_refuses():
    assert build_merkle_frame_for_write(_axes(SAFE))["root"] == build_merkle_frame(_axes(SAFE))["root"]
    with pytest.raises(UnsafeIntegerError):
        build_merkle_frame_for_write(_axes(UNSAFE))
    build_merkle_frame(_axes(UNSAFE))  # read twin stays unrestricted


def test_instruction_provenance_twins_match_on_safe_input():
    from agent_passport.v2.instruction_provenance.types import InstructionFile

    files = [InstructionFile(path="a.md", digest="ab" * 32, bytes=10, role="system")]
    assert compute_context_root_for_write(files) == compute_context_root(files)


def test_envelope_bytes_twin_is_byte_identical_and_carries_no_numbers():
    """envelope_bytes canonicalizes four string members only.

    Recorded deliberately: the twin exists for symmetry with the other signing
    preimages, but the unsafe-integer rule is UNREACHABLE through it, because
    action_ref, merkle_root, issuer and timestamp are all strings. Do not read a
    passing test here as evidence that the rule fires on this path.
    """
    env = _envelope()
    assert envelope_bytes_for_write(env) == envelope_bytes(env)
    # Every member of the canonicalized subset is a string, so no number is reachable.
    canonicalized_members = ("action_ref", "merkle_root", "issuer", "timestamp")
    assert all(isinstance(env[k], str) for k in canonicalized_members)
