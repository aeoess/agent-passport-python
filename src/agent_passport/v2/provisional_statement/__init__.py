# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Provisional Statement — agent-to-agent negotiation default.

Mirrors src/v2/provisional-statement in the TypeScript SDK. Default status
for agent-emitted statements is "provisional"; binding requires an explicit
PromotionEvent satisfying a PromotionPolicy. Dead-man elapses to
"withdrawn", never to "promoted" — absence of confirmation is not consent.
"""

from .types import (
    ProvisionalStatement,
    PromotionEvent,
    PromotionPolicy,
    PromotionVerifyResult,
)
from .create import (
    create_provisional,
    is_binding,
    verify_author_signature,
    withdraw_provisional,
    withdrawal_payload,
    statement_signing_payload,
)
from .promote import promote_statement, process_dead_man, promotion_signing_payload
from .verify import verify_promotion

__all__ = [
    "ProvisionalStatement",
    "PromotionEvent",
    "PromotionPolicy",
    "PromotionVerifyResult",
    "create_provisional",
    "is_binding",
    "verify_author_signature",
    "withdraw_provisional",
    "withdrawal_payload",
    "statement_signing_payload",
    "promote_statement",
    "process_dead_man",
    "promotion_signing_payload",
    "verify_promotion",
]
