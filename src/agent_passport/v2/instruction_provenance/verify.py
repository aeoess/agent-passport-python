# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — verification end-to-end (§6).

Mirrors src/v2/instruction-provenance/verify.ts. Pipeline order matches
spec §6.1 → §6.5. Hard-rejects early; never silently downgrades.

Filesystem-side checks (§6.3 step 10/11 cross-walk vs disk) only run
when filesystem_check=True AND working_root exists on this host.
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ...crypto import verify as ed_verify_hex
from .canonicalize import (
    IPRPathError,
    canonicalize_envelope,
    canonicalize_path,
    compute_context_root,
    sha256_hex,
)
from .types import (
    InstructionProvenanceReceipt,
    VerificationResult,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_KID = re.compile(r"^ed25519:[0-9a-f]{16}$")
_VALID_TIERS = frozenset(["self-asserted", "witnessed", "verified"])
_V0_2_PERMITTED_TIER = "self-asserted"


def verify_instruction_provenance_receipt(
    envelope: InstructionProvenanceReceipt,
    *,
    public_key_hex: str,
    filesystem_check: bool = False,
    now: Optional[datetime] = None,
    clock_skew_ms: int = 5 * 60 * 1000,
) -> VerificationResult:
    """Verify an InstructionProvenanceReceipt envelope per spec §6."""
    errors: List[str] = []
    tier = envelope.attestation_tier

    # §6.1 — schema-level checks
    if envelope is None or not isinstance(envelope, InstructionProvenanceReceipt):
        errors.append("envelope is not an InstructionProvenanceReceipt")
        return VerificationResult(valid=False, errors=errors)

    if tier not in _VALID_TIERS:
        errors.append(
            f"attestation_tier must be one of self-asserted | witnessed | verified, got '{tier}'"
        )
    if tier != _V0_2_PERMITTED_TIER:
        errors.append(
            f"attestation_tier reserved for v0.3+, v0.2 only accepts self-asserted (got '{tier}')"
        )
    if not isinstance(envelope.signing_key_id, str) or not _KID.match(envelope.signing_key_id):
        errors.append(
            f"signing_key_id must match ^ed25519:[0-9a-f]{{16}}$ (got '{envelope.signing_key_id}')"
        )
    if not isinstance(envelope.signature, str) or not _HEX128.match(envelope.signature):
        errors.append("signature must be 128-char lowercase hex")
    if not isinstance(envelope.receipt_id, str) or not _HEX64.match(envelope.receipt_id):
        errors.append("receipt_id must be 64-char lowercase hex")
    if not isinstance(envelope.context_root, str) or not _HEX64.match(envelope.context_root):
        errors.append("context_root must be 64-char lowercase hex")
    if not isinstance(envelope.delegation_chain_root, str) or not _HEX64.match(envelope.delegation_chain_root):
        errors.append("delegation_chain_root must be 64-char lowercase hex")
    if not isinstance(envelope.discovery_patterns, list) or len(envelope.discovery_patterns) == 0:
        errors.append("discovery_patterns must be a non-empty array")
    if not isinstance(envelope.working_root, str) or not envelope.working_root.startswith("/"):
        errors.append("working_root must be absolute POSIX")

    if errors:
        return VerificationResult(valid=False, errors=errors, tier=tier)

    # §6.1 step 3 — recompute receipt_id from canonical bytes.
    canonical = canonicalize_envelope(envelope)
    expected_receipt_id = sha256_hex(canonical)
    if envelope.receipt_id != expected_receipt_id:
        errors.append(
            f"receipt_id mismatch (expected {expected_receipt_id}, got {envelope.receipt_id})"
        )
        return VerificationResult(valid=False, errors=errors, tier=tier)

    # §6.1 step 4 — Ed25519 signature.
    if not ed_verify_hex(canonical, envelope.signature, public_key_hex):
        errors.append("Ed25519 signature verification failed")
        return VerificationResult(valid=False, errors=errors, tier=tier)

    # §6.2 step 6 — signing_key_id must match the public key fingerprint.
    expected_kid = f"ed25519:{public_key_hex[:16]}"
    if envelope.signing_key_id != expected_kid:
        errors.append(
            f"signing_key_id {envelope.signing_key_id} does not match provided public_key_hex fingerprint {expected_kid}"
        )
        return VerificationResult(valid=False, errors=errors, tier=tier)

    # §6.3 steps 7-9 — path canonicalization + sort order + context_root.
    for f in envelope.instruction_files:
        try:
            canon = canonicalize_path(
                f.path,
                working_root=envelope.working_root,
                filesystem_mode=envelope.filesystem_mode,
            )
        except IPRPathError as e:
            errors.append(f"instruction_files[{f.path}] path canonicalization failed: {e}")
            continue
        except Exception as e:
            errors.append(f"instruction_files[{f.path}] path canonicalization failed: {e}")
            continue
        if canon != f.path:
            errors.append(
                f"instruction_files[{f.path}] path is not in canonical form (expected {canon})"
            )

    if not _is_sorted_by_path(envelope.instruction_files):
        errors.append("instruction_files is not sorted by path (canonical lexicographic)")

    expected_context_root = compute_context_root(envelope.instruction_files)
    if envelope.context_root != expected_context_root:
        errors.append(
            f"context_root mismatch (expected {expected_context_root}, got {envelope.context_root})"
        )

    # §6.3 step 10/11 — exhaustiveness + smuggling checks.
    declared_paths = set(f.path for f in envelope.instruction_files)
    for f in envelope.instruction_files:
        if not matches_any_pattern(f.path, envelope.discovery_patterns):
            errors.append(f"path smuggling: instruction_files[{f.path}] matches no discovery_pattern")

    if filesystem_check and Path(envelope.working_root).exists():
        discovered = _walk_patterns(
            envelope.working_root,
            envelope.discovery_patterns,
            envelope.filesystem_mode,
        )
        for p in discovered:
            if p not in declared_paths:
                errors.append(
                    f"omission detected: filesystem matches discovery_pattern but instruction_files omits '{p}'"
                )

    # §6.4 step 12 — issued_at not in the future.
    now_obj = now if now is not None else datetime.now(timezone.utc)
    issued_ms = _parse_iso_ms(envelope.issued_at)
    if issued_ms is None:
        errors.append("issued_at is not a parseable ISO-8601 timestamp")
    elif issued_ms > _to_ms(now_obj) + clock_skew_ms:
        errors.append(f"issued_at is in the future beyond clock skew ({envelope.issued_at})")

    # §6.4 step 13 — expires_at not in the past.
    if envelope.expires_at is not None:
        exp_ms = _parse_iso_ms(envelope.expires_at)
        if exp_ms is None:
            errors.append("expires_at is not a parseable ISO-8601 timestamp")
        elif exp_ms < _to_ms(now_obj):
            errors.append(f"IPR expired at {envelope.expires_at}")

    # §6.4 step 14 — bound_to.ref shape per type.
    if envelope.bound_to.type == "action" and not _HEX64.match(envelope.bound_to.ref):
        errors.append(
            f"bound_to.type='action' requires ref to be 64-char hex sha256, got '{envelope.bound_to.ref}'"
        )
    if envelope.bound_to.type == "window" and not re.match(r"^[^/]+/[^/]+$", envelope.bound_to.ref):
        errors.append("bound_to.type='window' requires ref of form '<iso8601>/<iso8601>'")

    return VerificationResult(
        valid=len(errors) == 0,
        errors=errors,
        tier=tier,
        context_root=expected_context_root,
    )


def verify_action_time_context_root(
    envelope: InstructionProvenanceReceipt,
    context_root_at_action_time: str,
) -> VerificationResult:
    """§6.5 — when an IPR carries recompute_at_action=True, every action
    receipt under its binding scope MUST include context_root_at_action_time
    computed by re-walking discovery_patterns. This helper compares.
    """
    errors: List[str] = []
    if not envelope.recompute_at_action:
        errors.append(
            "IPR did not declare recompute_at_action: True; action-time check not applicable"
        )
        return VerificationResult(valid=False, errors=errors)
    if not _HEX64.match(context_root_at_action_time):
        errors.append("context_root_at_action_time must be 64-char lowercase hex")
        return VerificationResult(valid=False, errors=errors)
    if context_root_at_action_time != envelope.context_root:
        errors.append(
            f"context_drift: action-time root {context_root_at_action_time} differs from IPR root {envelope.context_root}"
        )
        return VerificationResult(valid=False, errors=errors)
    return VerificationResult(valid=True, errors=[], context_root=envelope.context_root)


# ── Glob matching ──────────────────────────────────────────────────────


def matches_any_pattern(path: str, patterns: List[str]) -> bool:
    """Tiny POSIX-glob matcher mirroring TS matchesAnyPattern.

    Supports `*` (any non-`/`), `?` (one non-`/`), `**` (any number of
    segments). Patterns may start with `./` (stripped).
    """
    for raw in patterns:
        pat = raw[2:] if raw.startswith("./") else raw
        if _match_glob(path, pat):
            return True
    return False


def _match_glob(path: str, pattern: str) -> bool:
    return bool(_glob_to_regex(pattern).match(path))


def _glob_to_regex(pattern: str) -> "re.Pattern[str]":
    """Compile a POSIX glob to a Python regex.

    `**` matches any number of segments including zero (handles
    leading `**/` and trailing `/**`). `*` matches anything except `/`.
    `?` matches one non-`/`.
    """
    i = 0
    out = "^"
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                i += 2
                if i < len(pattern) and pattern[i] == "/":
                    out += "(?:.*/)?"
                    i += 1
                else:
                    out += ".*"
            else:
                out += "[^/]*"
                i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        elif c in ".+()|{}[]^$\\":
            out += f"\\{c}"
            i += 1
        else:
            out += c
            i += 1
    out += "$"
    return re.compile(out)


# ── Internal helpers ───────────────────────────────────────────────────


def _is_sorted_by_path(files) -> bool:
    for i in range(1, len(files)):
        if files[i - 1].path > files[i].path:
            return False
    return True


def _parse_iso_ms(s: str):
    if not isinstance(s, str):
        return None
    try:
        # Handle Z suffix; datetime.fromisoformat is stricter.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def _to_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _walk_patterns(working_root: str, patterns: List[str], filesystem_mode: str) -> List[str]:
    """Walk working_root and return canonical relative paths matching any
    discovery pattern. Symlinks returned as relative paths (no deref).
    """
    out: List[str] = []
    if not Path(working_root).exists() or not Path(working_root).is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(working_root, followlinks=False):
        for name in filenames:
            abs_p = os.path.join(dirpath, name)
            rel = os.path.relpath(abs_p, working_root)
            if rel.startswith("..") or len(rel) == 0:
                continue
            try:
                canon = canonicalize_path(
                    rel, working_root=working_root, filesystem_mode=filesystem_mode
                )
            except IPRPathError:
                continue
            if matches_any_pattern(canon, patterns):
                out.append(canon)
    return sorted(out)
