# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""InstructionProvenanceReceipt — types.

Mirrors src/v2/instruction-provenance/types.ts. Spec:
~/aeoess_web/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md.

Tier scope this version: 'self-asserted' only. Verifiers MUST reject
'witnessed' and 'verified' envelopes per ENFORCEMENT-TRUST-ANCHOR
Component 4.
"""

from dataclasses import dataclass, field
from typing import List, Literal, Optional


AttestationTier = Literal["self-asserted", "witnessed", "verified"]
FilesystemMode = Literal["case-sensitive", "case-insensitive"]
InstructionRole = Literal[
    "system_prompt",
    "agent_md",
    "user_md",
    "memory",
    "rules",
    "other",
]


@dataclass
class InstructionFile:
    """One discovered instruction file."""

    path: str
    digest: str  # sha256 hex, 64 chars
    bytes: int
    role: InstructionRole
    is_symlink: Optional[bool] = None
    symlink_target: Optional[str] = None

    def to_canonical_dict(self) -> dict:
        out: dict = {
            "bytes": self.bytes,
            "digest": self.digest,
            "path": self.path,
            "role": self.role,
        }
        if self.is_symlink is not None:
            out["is_symlink"] = self.is_symlink
        if self.symlink_target is not None:
            out["symlink_target"] = self.symlink_target
        return out


@dataclass
class InstructionProvenanceReceiptBoundTo:
    type: Literal["session", "action", "window"]
    ref: str

    def to_canonical_dict(self) -> dict:
        return {"ref": self.ref, "type": self.type}


@dataclass
class InstructionProvenanceReceipt:
    """v0.2 envelope. Tier locked to 'self-asserted' until v0.3."""

    receipt_id: str
    delegation_chain_root: str
    agent_did: str
    discovery_patterns: List[str]
    working_root: str
    filesystem_mode: FilesystemMode
    instruction_files: List[InstructionFile]
    context_root: str
    attestation_tier: AttestationTier
    recompute_at_action: bool
    issued_at: str
    bound_to: InstructionProvenanceReceiptBoundTo
    signing_key_id: str
    signature: str
    expires_at: Optional[str] = None

    def to_canonical_dict(
        self,
        *,
        drop_signature: bool = False,
        drop_receipt_id: bool = False,
    ) -> dict:
        """Canonical dict for JCS canonicalization.

        canonicalize_envelope (per spec §5.2) strips both signature and
        receipt_id. Pass drop_signature=True and drop_receipt_id=True
        for that form. Other paths can include / exclude individually.
        """
        out: dict = {
            "agent_did": self.agent_did,
            "attestation_tier": self.attestation_tier,
            "bound_to": self.bound_to.to_canonical_dict(),
            "context_root": self.context_root,
            "delegation_chain_root": self.delegation_chain_root,
            "discovery_patterns": list(self.discovery_patterns),
            "filesystem_mode": self.filesystem_mode,
            "instruction_files": [f.to_canonical_dict() for f in self.instruction_files],
            "issued_at": self.issued_at,
            "recompute_at_action": self.recompute_at_action,
            "signing_key_id": self.signing_key_id,
            "working_root": self.working_root,
        }
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at
        if not drop_receipt_id:
            out["receipt_id"] = self.receipt_id
        if not drop_signature:
            out["signature"] = self.signature
        return out


@dataclass
class VerificationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    tier: Optional[AttestationTier] = None
    context_root: Optional[str] = None
