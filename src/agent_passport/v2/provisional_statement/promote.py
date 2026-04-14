# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""promote_statement, process_dead_man, promotion_signing_payload.

Mirrors src/v2/provisional-statement/promote.ts.
"""

import time
from typing import Optional

from ...canonical import canonicalize
from .types import ProvisionalStatement, PromotionEvent, PromotionPolicy
from .create import _create_hybrid_timestamp


def promotion_signing_payload(opts: dict) -> str:
    """Canonical payload a promoter signs."""
    return canonicalize({
        "statement_id": opts["statement_id"],
        "kind": opts["kind"],
        "promoted_at": opts["promoted_at"],
        "promoter": opts["promoter"],
        "policy_reference": opts["policy_reference"],
    })


def promote_statement(
    statement: ProvisionalStatement,
    promotion_event: PromotionEvent,
    policy: PromotionPolicy,
) -> ProvisionalStatement:
    """Promote a provisional statement into binding status. The provided
    PromotionEvent must satisfy the PromotionPolicy. dead_man_elapsed
    is rejected — use process_dead_man (auto-withdraw) for that path."""
    from .verify import verify_promotion  # local import — avoids cycle

    if statement.get("status") == "promoted":
        raise ValueError("Statement already promoted")
    if statement.get("status") == "withdrawn":
        raise ValueError("Cannot promote a withdrawn statement")
    if promotion_event.get("kind") == "dead_man_elapsed":
        raise ValueError("dead_man_elapsed does not promote — use process_dead_man (auto-withdraw)")

    candidate: ProvisionalStatement = {
        **statement,
        "status": "promoted",
        "promotion": promotion_event,
    }

    result = verify_promotion(candidate, policy)
    if not result["valid"]:
        raise ValueError(f"Promotion rejected: {'; '.join(result['errors'])}")
    return candidate


def process_dead_man(
    statement: ProvisionalStatement,
    *,
    now: Optional[int] = None,
    gateway_id: Optional[str] = None,
) -> ProvisionalStatement:
    """If the dead-man deadline has elapsed on a still-provisional
    statement, transition it to "withdrawn". Idempotent on terminal states."""
    if statement.get("status") != "provisional":
        return statement
    deadline = statement.get("dead_man_expires_at")
    if not deadline:
        return statement

    now_ms = now if now is not None else int(time.time() * 1000)
    if now_ms <= deadline["wallClockLatest"]:
        return statement

    gw = gateway_id or deadline["gatewayId"]
    event: PromotionEvent = {
        "kind": "dead_man_elapsed",
        "promoted_at": _create_hybrid_timestamp(gw),
        "promoter": "system:dead_man",
        "promoter_signature": "",
        "policy_reference": "dead_man_timer",
    }

    return {**statement, "status": "withdrawn", "promotion": event}
