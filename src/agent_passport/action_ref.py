# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Native APS action_ref: the content-addressed request identity.

action_ref = SHA-256 over the RFC 8785 (JCS) canonicalization of exactly
{agentId, actionType, scopeRequired, timestamp}, per draft-pidlisnyi-aps-03
section 4.1. Before canonicalization, each scope string is normalized to
Unicode NFC and, when scopeRequired is a list, the list is sorted by Unicode
code point on a copy (Python's default str ordering IS code-point order).
No case folding: scopes differing only in case are distinct. The timestamp
is normalized to second precision UTC with the literal Z designator.

Byte parity with the TypeScript reference (computeActionRef,
agent-passport-system src/core/action-ref.ts) and the Go implementation
(ComputeActionRefScopes) is pinned by the shared cross-language vectors in
tests/cross_impl/actionref-canonical-vectors.json.

DISTINCT from compute_attribution_action_ref
(v2/attribution_primitive/construct.py line 17): that function derives the
ATTRIBUTION action reference over {agentId, actionType, nonce, params}, a
different preimage for a different primitive. It is untouched by this module
and the two values are never interchangeable.
"""

import hashlib
import unicodedata
from datetime import datetime, timezone

from .canonical import canonicalize_jcs


def _normalize_timestamp(ts: str) -> str:
    """Second-precision UTC with the literal Z, matching the TS SDK.

    The TS reference does new Date(ts).toISOString() then strips the
    fractional-seconds component, which truncates within the second.
    """
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"compute_action_ref: invalid timestamp {ts!r}") from exc
    if dt.tzinfo is None:
        # Reject naive timestamps. Spec 4.1 requires an explicit UTC designator
        # ('Z'), and the TS reference parses an offsetless string as LOCAL time,
        # so assuming UTC here would silently produce a different action_ref for
        # the same input across implementations. Fail closed on non-conforming
        # input instead of guessing a zone.
        raise ValueError(
            f"compute_action_ref: timestamp {ts!r} must carry an explicit UTC "
            "offset or 'Z' (spec 4.1); naive timestamps are non-conforming"
        )
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    # Explicit zero-padded formatting; strftime('%Y') zero-pads platform-
    # dependently for years < 1000. APS timestamps are always four-digit years.
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
        f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}Z"
    )


def _canonicalize_scope_required(scope_required):
    """NFC per scope string; code-point sort of a list, on a copy.

    A single string is NFC-normalized. A list (or tuple) of strings is
    NFC-normalized per element and sorted; the caller's list is never
    mutated. None and any non-conforming shape pass through unchanged so
    the strict-JCS null-preservation contract and legacy behavior for
    out-of-spec input both match the TS reference.
    """
    if isinstance(scope_required, str):
        return unicodedata.normalize("NFC", scope_required)
    if isinstance(scope_required, (list, tuple)) and all(
        isinstance(s, str) for s in scope_required
    ):
        return sorted(unicodedata.normalize("NFC", s) for s in scope_required)
    return scope_required


def compute_action_ref(agent_id, action_type, scope_required, timestamp) -> str:
    """Compute the native APS action_ref (lowercase hex SHA-256).

    Preimage keys are exactly the spec's camelCase names: agentId,
    actionType, scopeRequired, timestamp. scopeRequired may be a single
    scope string, a list of scope strings (the section 4.1 form), or None
    (preserved as null in the canonical bytes).

    Not the attribution reference: see compute_attribution_action_ref in
    v2/attribution_primitive/construct.py for the {agentId, actionType,
    nonce, params} preimage. The two are distinct primitives.
    """
    preimage = {
        "agentId": agent_id,
        "actionType": action_type,
        "scopeRequired": _canonicalize_scope_required(scope_required),
        "timestamp": _normalize_timestamp(timestamp),
    }
    canonical = canonicalize_jcs(preimage)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
