# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — envelope construction (create_instruction_provenance_receipt).

Mirrors src/v2/instruction-provenance/envelope.ts. Tier-locked to
'self-asserted' in v0.2 per spec §4.1. Construction errors carry typed
codes via IPRConstructionError.
"""

from datetime import datetime, timezone
import re
from typing import List, Optional

from ...crypto import sign as ed_sign_hex
from .canonicalize import (
    canonicalize_envelope,
    canonicalize_path,
    compute_context_root,
    sha256_hex,
    sort_instruction_files,
)
from .types import (
    FilesystemMode,
    InstructionFile,
    InstructionProvenanceReceipt,
    InstructionProvenanceReceiptBoundTo,
)


class IPRConstructionError(Exception):
    """Typed error for IPR construction failures."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def sign_ed25519(message: str, private_key_hex: str) -> str:
    """Ed25519 sign via the project crypto module. Returns hex (128 chars).

    TS uses Node's createPrivateKey with PKCS8 DER prefix; Python uses
    pynacl. Output bytes are identical (Ed25519 deterministic).
    """
    return ed_sign_hex(message, private_key_hex)


def create_instruction_provenance_receipt(
    *,
    delegation_chain_root: str,
    agent_did: str,
    discovery_patterns: List[str],
    working_root: str,
    filesystem_mode: FilesystemMode,
    instruction_files: List[InstructionFile],
    bound_to: InstructionProvenanceReceiptBoundTo,
    private_key_hex: str,
    public_key_hex: str,
    recompute_at_action: bool = False,
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    attestation_tier: str = "self-asserted",
) -> InstructionProvenanceReceipt:
    """Build, sign, and return a complete InstructionProvenanceReceipt.

    Performs all v0.2 invariants:
      - tier locked to 'self-asserted'
      - discovery_patterns non-empty
      - every path canonicalized
      - instruction_files sorted in canonical order
      - context_root derived from sorted files
      - receipt_id = sha256(canonical envelope bytes)
      - signature = Ed25519 over canonical envelope bytes
    """
    if attestation_tier != "self-asserted":
        raise IPRConstructionError(
            "TIER_RESERVED",
            f"attestation_tier '{attestation_tier}' reserved for v0.3+; v0.2 only emits 'self-asserted'",
        )

    if not isinstance(discovery_patterns, list) or len(discovery_patterns) == 0:
        raise IPRConstructionError(
            "EMPTY_PATTERNS", "discovery_patterns must be a non-empty list"
        )

    if not working_root.startswith("/"):
        raise IPRConstructionError(
            "WORKING_ROOT_NOT_ABSOLUTE",
            f"working_root must be absolute POSIX: {working_root}",
        )

    if not _HEX64.match(delegation_chain_root):
        raise IPRConstructionError(
            "BAD_DELEGATION_ROOT", "delegation_chain_root must be 64-char lowercase hex"
        )
    if not _HEX64.match(public_key_hex):
        raise IPRConstructionError(
            "BAD_PUBLIC_KEY", "public_key_hex must be 64-char lowercase hex"
        )
    if not _HEX64.match(private_key_hex):
        raise IPRConstructionError(
            "BAD_PRIVATE_KEY",
            "private_key_hex must be 64-char lowercase hex (Ed25519 seed)",
        )

    canonical_files: List[InstructionFile] = []
    for f in instruction_files:
        canonical_files.append(
            InstructionFile(
                path=canonicalize_path(
                    f.path,
                    working_root=working_root,
                    filesystem_mode=filesystem_mode,
                ),
                digest=f.digest,
                bytes=f.bytes,
                role=f.role,
                is_symlink=f.is_symlink,
                symlink_target=f.symlink_target,
            )
        )

    for f in canonical_files:
        if not _HEX64.match(f.digest):
            raise IPRConstructionError(
                "BAD_DIGEST",
                f"instruction_files entry has malformed digest: {f.path}",
            )
        if f.is_symlink and not f.symlink_target:
            raise IPRConstructionError(
                "SYMLINK_MISSING_TARGET",
                f"instruction_files entry is_symlink=true but symlink_target is missing: {f.path}",
            )

    sorted_files = sort_instruction_files(canonical_files)
    context_root = compute_context_root(sorted_files)
    issued = issued_at if issued_at is not None else _now_iso()
    signing_key_id = f"ed25519:{public_key_hex[:16]}"

    # Build the unsigned envelope (signature and receipt_id absent).
    unsigned = InstructionProvenanceReceipt(
        receipt_id="",
        delegation_chain_root=delegation_chain_root,
        agent_did=agent_did,
        discovery_patterns=list(discovery_patterns),
        working_root=working_root,
        filesystem_mode=filesystem_mode,
        instruction_files=sorted_files,
        context_root=context_root,
        attestation_tier="self-asserted",
        recompute_at_action=recompute_at_action,
        issued_at=issued,
        bound_to=bound_to,
        signing_key_id=signing_key_id,
        signature="",
        expires_at=expires_at,
    )

    canonical_bytes = canonicalize_envelope(unsigned)
    receipt_id = sha256_hex(canonical_bytes)
    signature_hex = sign_ed25519(canonical_bytes, private_key_hex)

    unsigned.receipt_id = receipt_id
    unsigned.signature = signature_hex
    return unsigned
