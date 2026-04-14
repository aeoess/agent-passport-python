# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS v2 HumanEscalationFlag — per-action-class owner confirmation.

Mirrors src/v2/human-escalation.ts. The owner (delegator) must sign a
confirmation before a flagged action class can execute. Three confirmation
scopes: per_action, per_session, time_window.

Default flagged action classes (documented, not enforced here):
  org_creation, third_party_attribution, spend_above_threshold,
  charter_amendment, delegation_scope_expansion
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import List, Optional, TypedDict

from ..crypto import sign, verify
from ..canonical import canonicalize


# ── Type aliases / TypedDicts ────────────────────────────────────────


class EscalationRequirement(TypedDict):
    action_class: str
    requires_owner_confirmation: bool
    confirmation_ttl_ms: int
    confirmation_scope: str  # "per_action" | "per_session" | "time_window"


class EscalationAction(TypedDict, total=False):
    action_class: str
    action_details: dict
    session_id: Optional[str]


class ConfirmationRequest(TypedDict):
    id: str
    delegation_id: str
    action_class: str
    action_details_hash: str
    confirmation_scope: str
    session_id: Optional[str]
    confirmation_ttl_ms: int
    created_at: str  # ISO-8601


class OwnerConfirmation(TypedDict):
    id: str
    request_id: str
    delegation_id: str
    action_class: str
    action_details_hash: str
    confirmation_scope: str
    session_id: Optional[str]
    confirmed_by: str
    confirmed_at: str
    expires_at: str
    signature: str


class EscalationCheck(TypedDict, total=False):
    required: bool
    reason: str
    requirement: EscalationRequirement


class ConfirmationVerdict(TypedDict, total=False):
    valid: bool
    reason: str


class VerifyForActionResult(TypedDict, total=False):
    valid: bool
    reason: str
    escalation_required: bool


DEFAULT_FLAGGED_ACTION_CLASSES = (
    "org_creation",
    "third_party_attribution",
    "spend_above_threshold",
    "charter_amendment",
    "delegation_scope_expansion",
)


# ── Helpers ──────────────────────────────────────────────────────────


def hash_action_details(details: dict) -> str:
    """sha256(JSON.stringify(details)) — mirrors the TS implementation
    (note: not canonicalize; uses standard JSON serialization). Both
    languages must serialize details identically for hashes to match.
    Use simple, stable detail dicts for cross-language compatibility."""
    serialized = json.dumps(details, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _find_requirement(delegation: dict, action_class: str) -> Optional[EscalationRequirement]:
    reqs = delegation.get("scope", {}).get("escalation_requirements")
    if not reqs:
        return None
    for r in reqs:
        if r["action_class"] == action_class and r.get("requires_owner_confirmation"):
            return r
    return None


def _now_iso(now_ms: Optional[int] = None) -> str:
    """ISO-8601 with millisecond precision and Z suffix — matches JS
    Date.toISOString() format."""
    from datetime import datetime, timezone
    ms = now_ms if now_ms is not None else int(time.time() * 1000)
    secs = ms / 1000
    dt = datetime.fromtimestamp(secs, tz=timezone.utc)
    # Force millisecond precision + Z suffix
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def _parse_iso(s: str) -> int:
    """Inverse of _now_iso — returns epoch ms."""
    from datetime import datetime
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return int(dt.timestamp() * 1000)


# ── checkEscalationRequired ─────────────────────────────────────────


def check_escalation_required(delegation: dict, action: EscalationAction) -> EscalationCheck:
    requirement = _find_requirement(delegation, action["action_class"])
    if not requirement:
        return {"required": False}
    return {
        "required": True,
        "requirement": requirement,
        "reason": f"action_requires_confirmation: {action['action_class']}",
    }


# ── requestOwnerConfirmation ────────────────────────────────────────


def request_owner_confirmation(delegation: dict, action: EscalationAction) -> ConfirmationRequest:
    requirement = _find_requirement(delegation, action["action_class"])
    if not requirement:
        raise ValueError(
            f'No escalation requirement for action_class="{action["action_class"]}" '
            f'on delegation {delegation["id"]}'
        )
    if requirement["confirmation_scope"] == "per_session" and not action.get("session_id"):
        raise ValueError("per_session confirmation requires action.session_id")
    return {
        "id": str(uuid.uuid4()),
        "delegation_id": delegation["id"],
        "action_class": action["action_class"],
        "action_details_hash": hash_action_details(action["action_details"]),
        "confirmation_scope": requirement["confirmation_scope"],
        "session_id": action.get("session_id"),
        "confirmation_ttl_ms": requirement["confirmation_ttl_ms"],
        "created_at": _now_iso(),
    }


# ── recordOwnerConfirmation (owner signs) ───────────────────────────


def record_owner_confirmation(
    *,
    request: ConfirmationRequest,
    delegation: dict,
    owner_private_key: str,
) -> OwnerConfirmation:
    if request["delegation_id"] != delegation["id"]:
        raise ValueError("ConfirmationRequest delegation_id does not match delegation.id")
    confirmed_at_ms = int(time.time() * 1000)
    expires_at_ms = confirmed_at_ms + request["confirmation_ttl_ms"]
    data: dict = {
        "id": str(uuid.uuid4()),
        "request_id": request["id"],
        "delegation_id": request["delegation_id"],
        "action_class": request["action_class"],
        "action_details_hash": request["action_details_hash"],
        "confirmation_scope": request["confirmation_scope"],
        "session_id": request.get("session_id"),
        "confirmed_by": delegation["delegator"],
        "confirmed_at": _now_iso(confirmed_at_ms),
        "expires_at": _now_iso(expires_at_ms),
    }
    signature = sign(canonicalize(data), owner_private_key)
    return {**data, "signature": signature}


# ── isConfirmationValid ─────────────────────────────────────────────


def is_confirmation_valid(confirmation: OwnerConfirmation, now_ms: Optional[int] = None) -> bool:
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    return now <= _parse_iso(confirmation["expires_at"])


# ── verifyOwnerConfirmation ─────────────────────────────────────────


def _matches_action(confirmation: OwnerConfirmation, action: EscalationAction, scope: str) -> ConfirmationVerdict:
    if confirmation["action_class"] != action["action_class"]:
        return {"valid": False, "reason": "action_class mismatch"}
    if scope == "per_action":
        expected = hash_action_details(action["action_details"])
        if confirmation["action_details_hash"] != expected:
            return {"valid": False, "reason": "per_action details hash mismatch"}
    elif scope == "per_session":
        sid = action.get("session_id")
        if not sid or confirmation.get("session_id") != sid:
            return {"valid": False, "reason": "per_session session_id mismatch"}
    return {"valid": True}


def verify_owner_confirmation(
    confirmation: OwnerConfirmation,
    action: EscalationAction,
    delegation: dict,
    now_ms: Optional[int] = None,
) -> ConfirmationVerdict:
    if confirmation["delegation_id"] != delegation["id"]:
        return {"valid": False, "reason": "delegation_id mismatch"}
    if confirmation["confirmed_by"] != delegation["delegator"]:
        return {"valid": False, "reason": "confirmed_by is not the delegator"}
    if not is_confirmation_valid(confirmation, now_ms):
        return {"valid": False, "reason": "confirmation expired"}
    requirement = _find_requirement(delegation, action["action_class"])
    if not requirement:
        return {"valid": False, "reason": "no matching escalation requirement on delegation"}
    if confirmation["confirmation_scope"] != requirement["confirmation_scope"]:
        return {"valid": False, "reason": "confirmation_scope mismatch"}
    match = _matches_action(confirmation, action, requirement["confirmation_scope"])
    if not match["valid"]:
        return match
    signable = {k: v for k, v in confirmation.items() if k != "signature"}
    try:
        ok = verify(canonicalize(signable), confirmation["signature"], delegation["delegator"])
    except Exception:
        ok = False
    if not ok:
        return {"valid": False, "reason": "signature verification failed"}
    return {"valid": True}


# ── verify chain (composite) ────────────────────────────────────────


def verify_v2_delegation_for_action(
    delegation: dict,
    action: EscalationAction,
    confirmations: Optional[List[OwnerConfirmation]] = None,
    now_ms: Optional[int] = None,
) -> VerifyForActionResult:
    """Composite check. This Python port does NOT validate the underlying
    delegation signature/expiry (no v2 delegation module ported yet); it
    only enforces the escalation gate. Callers that want full parity with
    TS verifyV2DelegationForAction should run their delegation validation
    first."""
    confirmations = confirmations or []
    esc = check_escalation_required(delegation, action)
    if not esc.get("required"):
        return {"valid": True}
    for conf in confirmations:
        v = verify_owner_confirmation(conf, action, delegation, now_ms)
        if v.get("valid"):
            return {"valid": True, "escalation_required": True}
    return {
        "valid": False,
        "escalation_required": True,
        "reason": "action_requires_confirmation",
    }
