# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""create_provisional, withdraw_provisional, isBinding, verify_author_signature.

Mirrors src/v2/provisional-statement/create.ts.
"""

import os
import time
from typing import Optional

from ...crypto import sign, verify
from ...canonical import canonicalize
from .types import ProvisionalStatement, Ed25519Signature
from ..attribution_consent.types import HybridTimestamp


# Module-level logical clock — mirrors the TS module-level counter in
# src/core/time.ts. Not gateway-shared; deterministic only within process.
_logical_counter = 0
_DEFAULT_NTP_DRIFT_MS = 1000


def _create_hybrid_timestamp(gateway_id: str, drift_ms: int = _DEFAULT_NTP_DRIFT_MS) -> HybridTimestamp:
    global _logical_counter
    _logical_counter += 1
    now_ms = int(time.time() * 1000)
    return {
        "logicalTime": _logical_counter,
        "wallClockEarliest": now_ms - drift_ms,
        "wallClockLatest": now_ms + drift_ms,
        "gatewayId": gateway_id,
    }


def statement_signing_payload(s: dict) -> str:
    """Canonical payload an author signs."""
    base = {
        "id": s["id"],
        "version": s["version"],
        "author": s["author"],
        "author_principal": s["author_principal"],
        "content": s["content"],
        "created_at": s["created_at"],
    }
    if s.get("dead_man_expires_at"):
        base["dead_man_expires_at"] = s["dead_man_expires_at"]
    return canonicalize(base)


def create_provisional(
    *,
    author: str,
    author_principal: str,
    content: str,
    author_private_key: str,
    gateway_id: str,
    dead_man_expires_at: Optional[HybridTimestamp] = None,
    id: Optional[str] = None,
) -> ProvisionalStatement:
    statement_id = id if id is not None else os.urandom(16).hex()
    created_at = _create_hybrid_timestamp(gateway_id)

    base = {
        "id": statement_id,
        "version": "1.0",
        "author": author,
        "author_principal": author_principal,
        "content": content,
        "created_at": created_at,
    }
    if dead_man_expires_at is not None:
        base["dead_man_expires_at"] = dict(dead_man_expires_at)

    author_signature = sign(statement_signing_payload(base), author_private_key)

    return {
        **base,
        "status": "provisional",
        "author_signature": author_signature,
    }


def is_binding(statement: ProvisionalStatement) -> bool:
    """True only for promoted statements with a promotion attached."""
    return statement.get("status") == "promoted" and bool(statement.get("promotion"))


def verify_author_signature(statement: ProvisionalStatement) -> bool:
    payload = statement_signing_payload(statement)
    try:
        return verify(payload, statement["author_signature"], statement["author"])
    except Exception:
        return False


def withdrawal_payload(statement_id: str) -> str:
    return canonicalize({"action": "withdraw", "statement_id": statement_id})


def withdraw_provisional(
    statement: ProvisionalStatement,
    author_sig: Ed25519Signature,
) -> ProvisionalStatement:
    if statement.get("status") == "promoted":
        raise ValueError("Cannot withdraw a promoted statement")
    if statement.get("status") == "withdrawn":
        return statement
    payload = withdrawal_payload(statement["id"])
    if not verify(payload, author_sig, statement["author"]):
        raise ValueError("Invalid withdrawal signature")
    return {**statement, "status": "withdrawn"}
