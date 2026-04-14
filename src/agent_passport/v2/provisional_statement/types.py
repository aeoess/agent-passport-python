# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Type aliases mirroring the TS provisional-statement module."""

from typing import TypedDict, List, Optional

from ..attribution_consent.types import HybridTimestamp

AgentDID = str
PrincipalDID = str
Ed25519Signature = str
Duration = int  # milliseconds


class PromotionEvent(TypedDict, total=False):
    kind: str  # "principal_signature" | "counter_signature" | "dead_man_elapsed"
    promoted_at: HybridTimestamp
    promoter: str
    promoter_signature: Ed25519Signature
    policy_reference: str


class ProvisionalStatement(TypedDict, total=False):
    id: str
    version: str  # "1.0"
    author: AgentDID
    author_principal: PrincipalDID
    content: str
    status: str  # "provisional" | "promoted" | "withdrawn"
    created_at: HybridTimestamp
    dead_man_expires_at: HybridTimestamp  # optional
    author_signature: Ed25519Signature
    promotion: PromotionEvent  # optional


class PromotionPolicy(TypedDict):
    id: str
    required_signers: List[PrincipalDID]
    threshold: int
    max_time_to_promote: Duration


class PromotionVerifyResult(TypedDict):
    valid: bool
    errors: List[str]
