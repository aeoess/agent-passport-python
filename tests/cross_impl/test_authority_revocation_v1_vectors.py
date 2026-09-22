# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Check the Python aps:authority-revocation:v1 port against the committed TypeScript vector.

The vector is `tests/cross_impl/authority-revocation-v1-vectors.json`, vendored
byte for byte from the TypeScript SDK; see the PROVENANCE.md beside it for the
source path, the two commits and the SHA-256 this file asserts.

No Node runs here and nothing calls into the TypeScript SDK. Every expected
value is read out of the JSON, and the assertions are that the Python port
produces exactly what a different implementation, in a different language,
wrote down:

  - from the vector's own seeds and inputs, Python issuance reproduces the valid
    record byte for byte under JCS, the three preimages as hex, and
    revocation_id, cascade_transaction_id and signature;
  - Python verification of all nine negative cases returns the recorded state
    and the recorded first failure code.

Agreement here shows the two implementations produce the same bytes and reach
the same outcomes for these inputs, not more. The failure codes are the
TypeScript SDK's vocabulary, which the Python port shares; they are not protocol
vocabulary.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_revocation import (
    AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
    AUTHORITY_REVOCATION_ID_DOMAIN,
    AUTHORITY_REVOCATION_SIGNATURE_DOMAIN,
    authority_revocation_body,
    authority_revocation_cascade_origin,
    authority_revocation_cascade_transaction_input,
    authority_revocation_id_input,
    authority_revocation_signature_input,
    issue_authority_revocation,
    verify_authority_revocation,
)

_PATH = pathlib.Path(__file__).parent / "authority-revocation-v1-vectors.json"

# The bytes this port was checked against. Recorded in PROVENANCE.md beside the
# file and asserted below, so a silent edit to the vendored copy fails a test
# rather than quietly re-baselining the Python port against different bytes.
_VECTOR_SHA256 = "43dbe7fed137269405be38bf829681bc18525a1eccb8e8236e37f03720147ee2"
_SDK_MERGE_COMMIT = "2afe124"
_GENERATOR_COMMIT = "f6792af732f2102b239cca6b18840f6fa7d8fe87"

_RAW = _PATH.read_bytes()
_VECTORS = json.loads(_RAW.decode("utf-8"))
_VALID = _VECTORS["valid_case"]
_DELEGATION = _VALID["target_delegation"]
_REVOCATION = _VALID["revocation"]
_NEGATIVES = _VECTORS["negative_cases"]
_KEYS = {entry["label"]: entry for entry in _VECTORS["keys"]}


def _resolve_verification_key(controller, verification_method, at):
    """The resolver the vector file describes, rebuilt from its own committed table.

    Look up the (controller, verification_method) pair; when no entry matches,
    or when the record's revoked_at is earlier than the entry's key_valid_from,
    answer the section 2.5 outcome "not_found"; otherwise answer public_key_hex.
    Timestamps are compared as strings, which is exact for this canonical
    UTC-millisecond form, and is what the TypeScript generator's `<` does.
    """
    for entry in _VECTORS["key_resolver"]["entries"]:
        if entry["controller"] == controller and entry["verification_method"] == verification_method:
            if at < entry["key_valid_from"]:
                return {"outcome": "not_found"}
            return entry["public_key_hex"]
    return {"outcome": "not_found"}


def _verify(candidate):
    return verify_authority_revocation(
        candidate, _DELEGATION, resolve_verification_key=_resolve_verification_key
    )


def test_vendored_vector_is_the_bytes_this_port_was_checked_against():
    assert hashlib.sha256(_RAW).hexdigest() == _VECTOR_SHA256
    assert _VECTORS["record_type"] == "aps:authority-revocation:v1"
    assert _VECTORS["record_version"] == "1.0"
    assert _VECTORS["sdk_reference"]["repository"] == "aeoess/agent-passport-system"
    assert _VECTORS["sdk_reference"]["commit"] == _GENERATOR_COMMIT
    assert _GENERATOR_COMMIT.startswith(_VECTORS["sdk_reference"]["commit"][:7])
    # The SDK merge commit is not inside the JSON; it is recorded in
    # PROVENANCE.md, which is asserted to name both commits and the digest.
    provenance = (_PATH.parent / "authority-revocation-v1-vectors.PROVENANCE.md").read_text(
        encoding="utf-8"
    )
    assert _VECTOR_SHA256 in provenance
    assert _SDK_MERGE_COMMIT in provenance
    assert _GENERATOR_COMMIT in provenance


def test_vector_file_shape():
    assert len(_NEGATIVES) == 9
    names = [case["name"] for case in _NEGATIVES]
    assert len(set(names)) == len(names)
    assert all(case["defect"] for case in _NEGATIVES)
    assert _VALID["verification"]["state"] == "valid"


def test_seed_labels_derive_the_published_keys():
    """sha256(utf8(seed_label)) IS the Ed25519 seed, so the vector carries no
    opaque constant: every key re-derives from the label alone, in any language."""
    for entry in _VECTORS["keys"]:
        seed = hashlib.sha256(entry["seed_label"].encode("utf-8")).hexdigest()
        assert seed == entry["private_key_hex"], entry["label"]
        assert public_key_from_private(seed) == entry["public_key_hex"], entry["label"]


def test_domain_tags_match_the_published_hex():
    """The three frozen domain tags, byte exact, trailing NUL included."""
    tags = _VECTORS["domain_tags"]
    assert AUTHORITY_REVOCATION_ID_DOMAIN.hex() == tags["revocation_id"]["hex"]
    assert AUTHORITY_REVOCATION_SIGNATURE_DOMAIN.hex() == tags["signature"]["hex"]
    assert (
        AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN.hex()
        == tags["cascade_transaction_id"]["hex"]
    )
    for tag in (
        AUTHORITY_REVOCATION_ID_DOMAIN,
        AUTHORITY_REVOCATION_SIGNATURE_DOMAIN,
        AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
    ):
        assert tag.endswith(b"\x00")
        assert b"\x00" not in tag[:-1]


def _issue_from_vector_inputs() -> dict:
    """Mint the valid record from the vector's own inputs and seed.

    Nothing recorded in the vector's `revocation` is copied into the call: every
    argument is an input the vector states elsewhere, so what comes back is the
    Python port's own record, not an echo of the file's.
    """
    return issue_authority_revocation(
        _DELEGATION,
        now=_REVOCATION["revoked_at"],
        revoker=_REVOCATION["revoker"],
        verification_method=_REVOCATION["verification_method"],
        reason_code=_REVOCATION["reason_code"],
        detail=_REVOCATION["detail"],
        nonce=_REVOCATION["nonce"],
        private_key=_KEYS[_VALID["derived"]["signing_key_label"]]["private_key_hex"],
    )


def test_issuance_reproduces_the_valid_record_byte_for_byte():
    issued = _issue_from_vector_inputs()
    assert canonicalize_jcs(issued) == canonicalize_jcs(_REVOCATION)
    assert issued == _REVOCATION


def test_issuance_reproduces_the_derived_identifiers_and_signature():
    issued = _issue_from_vector_inputs()
    derived = _VALID["derived"]
    assert issued["cascade_transaction_id"] == derived["cascade_transaction_id"]
    assert issued["revocation_id"] == derived["revocation_id"]
    assert issued["signature"] == derived["signature"]
    # The two identifiers are not the same digest: separate domain tags over
    # separate content.
    assert issued["revocation_id"] != issued["cascade_transaction_id"]


def test_the_three_preimages_are_the_recorded_hex():
    """The exact bytes hashed and signed, hex for hex, NUL byte and all."""
    issued = _issue_from_vector_inputs()
    preimages = _VALID["preimages"]
    body = authority_revocation_body(issued)
    origin = authority_revocation_cascade_origin(body)
    unsigned = {key: value for key, value in issued.items() if key != "signature"}

    assert (
        authority_revocation_cascade_transaction_input(origin).hex()
        == preimages["cascade_transaction_id_preimage_hex"]
    )
    assert authority_revocation_id_input(body).hex() == preimages["revocation_id_preimage_hex"]
    assert (
        authority_revocation_signature_input(unsigned).hex()
        == preimages["signature_preimage_hex"]
    )
    # revocation_id IS inside the signature preimage and is not inside its own.
    assert issued["revocation_id"].encode("utf-8").hex() in preimages["signature_preimage_hex"]
    assert issued["revocation_id"].encode("utf-8").hex() not in preimages["revocation_id_preimage_hex"]


def test_the_valid_case_verifies_with_the_recorded_outcome():
    result = _verify(_REVOCATION)
    recorded = _VALID["verification"]
    assert result.state == recorded["state"]
    assert result.valid is recorded["valid"]
    assert result.failures == ()


@pytest.mark.parametrize("case", _NEGATIVES, ids=[case["name"] for case in _NEGATIVES])
def test_negative_case_returns_the_recorded_state_and_first_failure_code(case):
    result = _verify(case["record"])
    recorded = case["verification"]
    assert result.state == recorded["state"], case["name"]
    assert result.valid is False
    assert result.failures, case["name"]
    assert result.failures[0].code == recorded["failures"][0]["code"], case["name"]
