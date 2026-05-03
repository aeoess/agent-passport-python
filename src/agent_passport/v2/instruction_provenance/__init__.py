# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""InstructionProvenanceReceipt — public surface.

Mirrors src/v2/instruction-provenance/index.ts. Spec:
~/aeoess_web/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md.

Tier scope this version: 'self-asserted' only.
"""

from .canonicalize import (
    IPRPathError,
    canonicalize_envelope,
    canonicalize_path,
    compute_context_root,
    sha256_hex,
    sort_instruction_files,
)

from .envelope import (
    IPRConstructionError,
    create_instruction_provenance_receipt,
    sign_ed25519,
)

from .types import (
    AttestationTier,
    FilesystemMode,
    InstructionFile,
    InstructionProvenanceReceipt,
    InstructionProvenanceReceiptBoundTo,
    InstructionRole,
    VerificationResult,
)

from .verify import (
    matches_any_pattern,
    verify_action_time_context_root,
    verify_instruction_provenance_receipt,
)

__all__ = [
    # canonicalize
    "IPRPathError",
    "canonicalize_envelope",
    "canonicalize_path",
    "compute_context_root",
    "sha256_hex",
    "sort_instruction_files",
    # envelope
    "IPRConstructionError",
    "create_instruction_provenance_receipt",
    "sign_ed25519",
    # types
    "AttestationTier",
    "FilesystemMode",
    "InstructionFile",
    "InstructionProvenanceReceipt",
    "InstructionProvenanceReceiptBoundTo",
    "InstructionRole",
    "VerificationResult",
    # verify
    "matches_any_pattern",
    "verify_action_time_context_root",
    "verify_instruction_provenance_receipt",
]
