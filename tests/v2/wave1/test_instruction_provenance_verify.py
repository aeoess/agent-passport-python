# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — verification end-to-end + cross-impl byte-parity."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_passport.v2.instruction_provenance import (
    InstructionFile,
    InstructionProvenanceReceipt,
    InstructionProvenanceReceiptBoundTo,
    create_instruction_provenance_receipt,
    verify_action_time_context_root,
    verify_instruction_provenance_receipt,
)
from agent_passport.crypto import generate_key_pair

KEYS = generate_key_pair()
FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "wave1" / "instruction-provenance"


def _base():
    return dict(
        delegation_chain_root="a" * 64,
        agent_did="did:aps:test",
        discovery_patterns=["**/CLAUDE.md", "**/AGENTS.md"],
        working_root="/test/root",
        filesystem_mode="case-sensitive",
        instruction_files=[
            InstructionFile(path="AGENTS.md", digest="b" * 64, bytes=100, role="agent_md"),
            InstructionFile(path="CLAUDE.md", digest="c" * 64, bytes=200, role="agent_md"),
        ],
        bound_to=InstructionProvenanceReceiptBoundTo(type="session", ref="sess_001"),
        private_key_hex=KEYS["privateKey"],
        public_key_hex=KEYS["publicKey"],
        issued_at="2026-05-02T00:00:00.000Z",
    )


def test_round_trip_verifies_clean():
    ipr = create_instruction_provenance_receipt(**_base())
    res = verify_instruction_provenance_receipt(
        ipr, public_key_hex=KEYS["publicKey"]
    )
    assert res.valid is True, f"errors: {res.errors}"
    assert res.tier == "self-asserted"


def test_tampered_path_breaks_signature():
    ipr = create_instruction_provenance_receipt(**_base())
    ipr.instruction_files[0].path = "different.md"
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=KEYS["publicKey"])
    assert res.valid is False


def test_tampered_signature_caught():
    ipr = create_instruction_provenance_receipt(**_base())
    ipr.signature = "0" * 128
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=KEYS["publicKey"])
    assert res.valid is False
    assert any("signature" in e.lower() for e in res.errors)


def test_wrong_pubkey_rejected():
    ipr = create_instruction_provenance_receipt(**_base())
    other = generate_key_pair()
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=other["publicKey"])
    assert res.valid is False


def test_signing_key_id_mismatch_caught():
    ipr = create_instruction_provenance_receipt(**_base())
    ipr.signing_key_id = "ed25519:" + "0" * 16
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=KEYS["publicKey"])
    assert res.valid is False


def test_path_smuggling_caught_via_pattern_mismatch():
    ipr = create_instruction_provenance_receipt(**_base())
    # Force a file that no discovery pattern matches.
    ipr.instruction_files.append(
        InstructionFile(path="malicious.bin", digest="0" * 64, bytes=1, role="other")
    )
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=KEYS["publicKey"])
    assert res.valid is False


def test_expired_envelope_rejected():
    ipr = create_instruction_provenance_receipt(
        **{**_base(), "expires_at": "2020-01-01T00:00:00.000Z"}
    )
    res = verify_instruction_provenance_receipt(ipr, public_key_hex=KEYS["publicKey"])
    assert res.valid is False
    assert any("expired" in e.lower() for e in res.errors)


def test_action_time_recompute_check_matches():
    ipr = create_instruction_provenance_receipt(
        **{**_base(), "recompute_at_action": True}
    )
    res = verify_action_time_context_root(ipr, ipr.context_root)
    assert res.valid is True


def test_action_time_recompute_check_mismatch():
    ipr = create_instruction_provenance_receipt(
        **{**_base(), "recompute_at_action": True}
    )
    res = verify_action_time_context_root(ipr, "0" * 64)
    assert res.valid is False
    assert any("context_drift" in e for e in res.errors)


def test_action_time_check_not_applicable_when_flag_unset():
    ipr = create_instruction_provenance_receipt(**_base())  # recompute=False default
    res = verify_action_time_context_root(ipr, ipr.context_root)
    assert res.valid is False
    assert any("not applicable" in e for e in res.errors)


# ── Cross-impl byte-parity ────────────────────────────────────────────


def _ipr_from_dict(d):
    return InstructionProvenanceReceipt(
        receipt_id=d["receipt_id"],
        delegation_chain_root=d["delegation_chain_root"],
        agent_did=d["agent_did"],
        discovery_patterns=d["discovery_patterns"],
        working_root=d["working_root"],
        filesystem_mode=d["filesystem_mode"],
        instruction_files=[
            InstructionFile(
                path=f["path"], digest=f["digest"], bytes=f["bytes"],
                role=f["role"], is_symlink=f.get("is_symlink"),
                symlink_target=f.get("symlink_target"),
            )
            for f in d["instruction_files"]
        ],
        context_root=d["context_root"],
        attestation_tier=d["attestation_tier"],
        recompute_at_action=d["recompute_at_action"],
        issued_at=d["issued_at"],
        expires_at=d.get("expires_at"),
        bound_to=InstructionProvenanceReceiptBoundTo(
            type=d["bound_to"]["type"], ref=d["bound_to"]["ref"]
        ),
        signing_key_id=d["signing_key_id"],
        signature=d["signature"],
    )


def test_basic_fixture_byte_parity():
    """TS-issued IPR fixture must verify under Python."""
    f = json.loads((FIXTURE_DIR / "basic.fixture.json").read_text())
    ipr = _ipr_from_dict(f)
    # The fixture's signing_key_id encodes the first 16 hex chars of the public key.
    pub_hex = f["signing_key_id"].removeprefix("ed25519:") + "0" * 48
    # Need the actual full pubkey from the fixture meta.
    meta = json.loads((FIXTURE_DIR.parent / "META.json").read_text())
    pub_hex = meta["ed25519_pubkey_hex"]
    res = verify_instruction_provenance_receipt(
        ipr, public_key_hex=pub_hex,
        # Anchor verifier clock to the fixture timestamp so issued_at is
        # not flagged as future on wall-clock drift.
        now=datetime(2026, 5, 2, 1, 0, 0, tzinfo=timezone.utc),
    )
    assert res.valid is True, f"byte-parity drift: {res.errors}"


def test_recompute_action_bound_fixture_byte_parity():
    f = json.loads((FIXTURE_DIR / "recompute-and-action-bound.fixture.json").read_text())
    ipr = _ipr_from_dict(f)
    meta = json.loads((FIXTURE_DIR.parent / "META.json").read_text())
    res = verify_instruction_provenance_receipt(
        ipr, public_key_hex=meta["ed25519_pubkey_hex"],
        now=datetime(2026, 5, 2, 1, 0, 0, tzinfo=timezone.utc),
    )
    assert res.valid is True, f"byte-parity drift: {res.errors}"


def test_case_insensitive_fixture_byte_parity():
    f = json.loads((FIXTURE_DIR / "case-insensitive.fixture.json").read_text())
    ipr = _ipr_from_dict(f)
    meta = json.loads((FIXTURE_DIR.parent / "META.json").read_text())
    res = verify_instruction_provenance_receipt(
        ipr, public_key_hex=meta["ed25519_pubkey_hex"],
        now=datetime(2026, 5, 2, 1, 0, 0, tzinfo=timezone.utc),
    )
    assert res.valid is True, f"byte-parity drift: {res.errors}"
