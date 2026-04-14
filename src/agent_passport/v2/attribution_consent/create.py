# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""create_attribution_receipt + receipt_core.

Mirrors src/v2/attribution-consent/create.ts exactly.
"""

import hashlib
from typing import Optional

from ...crypto import sign
from ...canonical import canonicalize
from .types import AttributionReceipt, HybridTimestamp


def receipt_core(receipt: dict) -> str:
    """Canonical unsigned core string. Both citer and cited principal sign
    exactly this payload, and the receipt id is sha256(core)."""
    return canonicalize({
        "version": receipt["version"],
        "citer": receipt["citer"],
        "citer_public_key": receipt["citer_public_key"],
        "cited_principal": receipt["cited_principal"],
        "cited_principal_public_key": receipt["cited_principal_public_key"],
        "citation_content": receipt["citation_content"],
        "binding_context": receipt["binding_context"],
        "created_at": receipt["created_at"],
        "expires_at": receipt["expires_at"],
    })


def create_attribution_receipt(
    *,
    citer: str,
    citer_public_key: str,
    citer_private_key: str,
    cited_principal: str,
    cited_principal_public_key: str,
    citation_content: str,
    binding_context: str,
    created_at: HybridTimestamp,
    expires_at: HybridTimestamp,
) -> AttributionReceipt:
    """Build an AttributionReceipt signed by the citer. The cited principal's
    consent signature is still absent — verify_attribution_consent() rejects
    it until sign_attribution_consent() runs."""
    if not citation_content or not isinstance(citation_content, str):
        raise ValueError("create_attribution_receipt: citation_content must be a non-empty string")
    if not binding_context:
        raise ValueError("create_attribution_receipt: binding_context is required")

    unsigned = {
        "version": "1.0",
        "citer": citer,
        "citer_public_key": citer_public_key,
        "cited_principal": cited_principal,
        "cited_principal_public_key": cited_principal_public_key,
        "citation_content": citation_content,
        "binding_context": binding_context,
        "created_at": dict(created_at),
        "expires_at": dict(expires_at),
    }

    core = receipt_core(unsigned)
    receipt_id = hashlib.sha256(core.encode("utf-8")).hexdigest()
    citer_signature = sign(core, citer_private_key)

    return {
        "id": receipt_id,
        **unsigned,
        "citer_signature": citer_signature,
    }
