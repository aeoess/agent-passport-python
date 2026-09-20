"""Replay the ReceiptV1 stage vectors against this implementation.

The vector file fixes every expected acceptance, rejection and state from the draft
text (draft-pidlisnyi-aps-03 sections 5.1, 5.2, 5.3 and 5.6), cited per case in its
derivation. The generator that produced it refuses to write the file when the
TypeScript reference disagrees with one of those expectations, so a case that passes
here means the two implementations agree with the same fixed reading, not with each
other.

For a case whose signed flag is true, this module also recomputes receipt_id and
verifies the signature with this implementation, which is the cross-implementation
byte parity claim: those bytes were produced by the TypeScript issuer.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_passport.crypto import verify as verify_signature
from agent_passport.receipt_core import (
    compute_receipt_id_v1,
    receipt_signature_payload_v1,
    validate_receipt_stage_v1,
    validate_receipt_v1,
    verify_receipt_v1,
)

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "receipt-v1-stage-vectors.json").read_text(encoding="utf-8")
)
CASES = VECTORS["cases"]


def _cases(kind: str) -> list:
    return [case for case in CASES if case["kind"] == kind]


def test_vector_file_is_self_describing() -> None:
    assert VECTORS["counts"]["total"] == len(CASES)
    by_provenance = VECTORS["counts"]["by_provenance"]
    assert sum(by_provenance.values()) == len(CASES)
    for label, count in by_provenance.items():
        assert label in VECTORS["provenance_definitions"], label
        assert count == sum(1 for case in CASES if case["expected_provenance"] == label)
    # A ruling-derived case is one the draft names without fixing its outcome. Its count is
    # asserted here so that silently relabelling a case as draft-derived breaks a test.
    assert by_provenance["ruling-derived"] == 17
    for case in CASES:
        assert case["derivation"]["lines"], case["id"]
        assert case["derivation"]["note"], case["id"]


@pytest.mark.parametrize("case", _cases("envelope"), ids=lambda case: case["id"])
def test_envelope_vectors(case: dict) -> None:
    if case["expected"]["accepts"]:
        validate_receipt_v1(case["receipt"])
        return
    with pytest.raises((TypeError, ValueError)):
        validate_receipt_v1(case["receipt"])


@pytest.mark.parametrize("case", _cases("stage"), ids=lambda case: case["id"])
def test_stage_vectors(case: dict) -> None:
    context = case["context"]
    result = validate_receipt_stage_v1(
        case["receipt"],
        expected_receipt_type=context["expected_receipt_type"],
        boundary_identity=context["boundary_identity"],
    )
    expected = case["expected"]
    assert result["status"] == expected["status"], result["failures"]
    assert result["stage"] == expected["stage"]
    assert result["boundary_identity"] == expected["boundary_identity"]
    assert sorted(f["code"] for f in result["failures"]) == sorted(expected["sdk_failure_codes"])


@pytest.mark.parametrize("case", _cases("verify"), ids=lambda case: case["id"])
def test_verify_vectors(case: dict) -> None:
    public_keys = case["public_keys"]
    other = case["other_public_key"]

    def correct(signer, key_id, issued_at):
        return public_keys.get(signer)

    def none(signer, key_id, issued_at):
        return None

    def raises(signer, key_id, issued_at):
        raise RuntimeError("resolver unavailable")

    def other_key(signer, key_id, issued_at):
        return other

    def malformed_material(signer, key_id, issued_at):
        return "ab" * 16

    def _outcome(name):
        def resolve(signer, key_id, issued_at):
            return {"outcome": name}

        return resolve

    resolver = {
        "correct": correct,
        "none": none,
        "raises": raises,
        "other_key": other_key,
        "malformed_material": malformed_material,
        "not_found": _outcome("not_found"),
        "ambiguous": _outcome("ambiguous"),
        "unreachable": _outcome("unreachable"),
        "malformed": _outcome("malformed"),
        "unsupported_scheme": _outcome("unsupported_scheme"),
    }[case["resolver"]]
    required_signers = case.get("required_signers") or []
    result = verify_receipt_v1(case["receipt"], resolver, required_signers=required_signers)
    expected = case["expected"]
    assert result["status"] == expected["status"], result["errors"]
    assert result["signer_authority"] == expected["signer_authority"]
    assert sorted(result["errors"]) == sorted(expected["sdk_errors"])
    if "other_signatures" in expected:
        assert result["other_signatures"] == expected["other_signatures"]
    for signer, reason in (expected.get("sdk_reasons") or {}).items():
        entry = next(item for item in result["signature_results"] if item["signer"] == signer)
        assert entry.get("reason") == reason, entry


@pytest.mark.parametrize("case", [c for c in CASES if c["signed"]], ids=lambda case: case["id"])
def test_signed_records_reproduce_the_reference_bytes(case: dict) -> None:
    """receipt_id and the signature value were produced by the TypeScript issuer."""
    receipt = case["receipt"]
    assert compute_receipt_id_v1(receipt) == receipt["receipt_id"]
    keys = {entry["id"]: entry["public_key"] for entry in VECTORS["keys"].values() if isinstance(entry, dict) and "id" in entry}
    # A descriptor the case appended after minting is not the reference issuer's output:
    # it is what a third party can add to a published receipt, and one case deliberately
    # carries an all-zero value from the issuer's own name. The parity claim covers the
    # bytes the issuer produced, so that descriptor is skipped here and is what the
    # verify case itself asserts on.
    appended = case.get("appended_signature_key_id")
    for proof in receipt["signatures"]:
        if appended is not None and proof["key_id"] == appended:
            continue
        public_key = keys.get(proof["signer"])
        if public_key is None:
            continue
        descriptor = {"signer": proof["signer"], "key_id": proof["key_id"], "alg": proof["alg"]}
        assert verify_signature(receipt_signature_payload_v1(receipt, descriptor), proof["value"], public_key)
