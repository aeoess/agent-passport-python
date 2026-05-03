# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — path canonicalization (§5.1) + envelope canonicalization (§5.2).

Mirrors src/v2/instruction-provenance/canonicalize.ts. Pure functions,
no I/O. Cross-language byte-parity contract: every canonicalize_path
result must match the TS port byte-for-byte against the same fixture
inputs.
"""

import re
import unicodedata
from hashlib import sha256
from typing import List

from ...canonical import canonicalize_jcs
from .types import FilesystemMode, InstructionFile, InstructionProvenanceReceipt


class IPRPathError(Exception):
    """Typed error for path-canonicalization rejections (spec §5.1)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def sha256_hex(data) -> str:
    """sha256 hex of a UTF-8 string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha256(data).hexdigest()


def _strip_trailing_slash(p: str) -> str:
    if len(p) > 1 and p.endswith("/"):
        return p[:-1]
    return p


def canonicalize_path(
    raw: str,
    *,
    working_root: str,
    filesystem_mode: FilesystemMode,
) -> str:
    """Canonicalize a raw path per spec §5.1. Returns a relative POSIX path.

    Steps (must match the spec algorithm exactly for cross-language
    parity):
      1. Reject empty path.
      2. Reject percent-encoded paths (paths are POSIX, not URIs).
      3. Compute absolute form (pure string math, no filesystem).
      4. Reject if absolute form is not under working_root.
      5. Strip working-root prefix to get relative form.
      6. Reject leading "./".
      7. Reject any ".." segment.
      8. Reject trailing slash.
      9. Normalize Unicode to NFC.
     10. Apply case mode (lowercase if case-insensitive).
     11. Replace OS separators with "/".
    """
    if len(raw) == 0:
        raise IPRPathError("EMPTY", "path is empty")
    if "%" in raw:
        raise IPRPathError(
            "PERCENT_ENCODING",
            "paths are POSIX, not URIs; percent-encoding rejected",
        )

    root = _strip_trailing_slash(working_root)
    if not root.startswith("/"):
        raise IPRPathError(
            "WORKING_ROOT_NOT_ABSOLUTE",
            f"working_root must be absolute POSIX: {root}",
        )

    # Compute absolute form. Treat raw as relative-to-root if not already absolute.
    if raw.startswith("/"):
        abs_path = raw
    else:
        cleaned = raw[2:] if raw.startswith("./") else raw
        abs_path = f"{root}/{cleaned}"

    # Reject ".." anywhere (segment-level check).
    for seg in abs_path.split("/"):
        if seg == "..":
            raise IPRPathError("TRAVERSAL", "parent traversal `..` not permitted")

    # Reject if absolute form is not under root.
    root_with_slash = f"{root}/"
    if abs_path != root and not abs_path.startswith(root_with_slash):
        raise IPRPathError("OUTSIDE_ROOT", f"path resolves outside working_root: {abs_path}")

    rel = "" if abs_path == root else abs_path[len(root_with_slash):]
    if len(rel) == 0:
        raise IPRPathError(
            "EMPTY",
            "path canonicalizes to empty (working_root itself, not a file)",
        )
    if rel.endswith("/"):
        raise IPRPathError("TRAILING_SLASH", f"trailing slash not permitted: {rel}")
    if rel.startswith("./"):
        raise IPRPathError(
            "LEADING_DOT_SLASH",
            f'leading "./" not permitted in canonical form: {rel}',
        )

    rel = unicodedata.normalize("NFC", rel)
    if filesystem_mode == "case-insensitive":
        rel = rel.lower()

    # Replace any backslashes (OS separators on non-POSIX). Spec mandates POSIX `/`.
    rel = rel.replace("\\", "/")

    return rel


def sort_instruction_files(files: List[InstructionFile]) -> List[InstructionFile]:
    """Canonical sort order: lexicographic by path. Spec §6.3 step 8."""
    return sorted(files, key=lambda f: f.path)


def compute_context_root(files: List[InstructionFile]) -> str:
    """Compute context_root per spec §4.1.

    sha256 of the JCS canonicalization of the instruction_files array
    (sorted). Must be byte-identical across languages.
    """
    sorted_files = sort_instruction_files(files)
    canon = canonicalize_jcs([f.to_canonical_dict() for f in sorted_files])
    return sha256_hex(canon)


def canonicalize_envelope(envelope: InstructionProvenanceReceipt) -> str:
    """Strip signature and receipt_id, JCS-canonicalize the rest.

    Mirrors TS canonicalizeEnvelope. Used for both receipt_id derivation
    and Ed25519 signing. Spec §5.2.
    """
    return canonicalize_jcs(
        envelope.to_canonical_dict(drop_signature=True, drop_receipt_id=True)
    )
