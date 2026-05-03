# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — envelope construction (createInstructionProvenanceReceipt)."""

import pytest

from agent_passport.v2.instruction_provenance import (
    InstructionFile,
    InstructionProvenanceReceiptBoundTo,
    IPRConstructionError,
    create_instruction_provenance_receipt,
)
from agent_passport.crypto import generate_key_pair

KEYS = generate_key_pair()


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


def test_basic_envelope_construction():
    ipr = create_instruction_provenance_receipt(**_base())
    assert ipr.attestation_tier == "self-asserted"
    assert ipr.recompute_at_action is False
    assert len(ipr.instruction_files) == 2
    assert len(ipr.receipt_id) == 64
    assert len(ipr.signature) == 128
    assert ipr.signing_key_id == f"ed25519:{KEYS['publicKey'][:16]}"


def test_files_are_canonical_sort_order():
    ipr = create_instruction_provenance_receipt(**_base())
    paths = [f.path for f in ipr.instruction_files]
    assert paths == sorted(paths)


def test_tier_lock_rejects_witnessed():
    inp = _base()
    inp["attestation_tier"] = "witnessed"
    with pytest.raises(IPRConstructionError) as exc:
        create_instruction_provenance_receipt(**inp)
    assert exc.value.code == "TIER_RESERVED"


def test_empty_patterns_rejected():
    inp = _base()
    inp["discovery_patterns"] = []
    with pytest.raises(IPRConstructionError) as exc:
        create_instruction_provenance_receipt(**inp)
    assert exc.value.code == "EMPTY_PATTERNS"


def test_relative_working_root_rejected():
    inp = _base()
    inp["working_root"] = "test/root"
    with pytest.raises(IPRConstructionError) as exc:
        create_instruction_provenance_receipt(**inp)
    assert exc.value.code == "WORKING_ROOT_NOT_ABSOLUTE"


def test_malformed_digest_rejected():
    inp = _base()
    inp["instruction_files"] = [
        InstructionFile(path="a.md", digest="not-hex", bytes=1, role="other")
    ]
    with pytest.raises(IPRConstructionError) as exc:
        create_instruction_provenance_receipt(**inp)
    assert exc.value.code == "BAD_DIGEST"


def test_symlink_missing_target_rejected():
    inp = _base()
    inp["instruction_files"] = [
        InstructionFile(
            path="a.md", digest="0" * 64, bytes=1, role="other",
            is_symlink=True, symlink_target=None,
        )
    ]
    with pytest.raises(IPRConstructionError) as exc:
        create_instruction_provenance_receipt(**inp)
    assert exc.value.code == "SYMLINK_MISSING_TARGET"


def test_recompute_at_action_flag_persists():
    inp = _base()
    inp["recompute_at_action"] = True
    ipr = create_instruction_provenance_receipt(**inp)
    assert ipr.recompute_at_action is True


def test_optional_expires_at_carried_through():
    inp = _base()
    inp["expires_at"] = "2026-06-01T00:00:00.000Z"
    ipr = create_instruction_provenance_receipt(**inp)
    assert ipr.expires_at == "2026-06-01T00:00:00.000Z"
