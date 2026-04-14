# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""verify_attribution_consent + check_artifact_citations.

Mirrors src/v2/attribution-consent/verify.ts.
"""

import hashlib
import time
from typing import Optional, List

from ...crypto import verify
from .create import receipt_core
from .types import (
    AttributionReceipt,
    AttributionConsentResult,
    CitingArtifact,
    HybridTimestamp,
)


def _fail(reason: str) -> AttributionConsentResult:
    return {"valid": False, "reason": reason}


def _compare_timestamps(a: HybridTimestamp, b: HybridTimestamp) -> str:
    """Mirror compareTimestamps from src/core/time.ts (relevant cases)."""
    if a["wallClockLatest"] < b["wallClockEarliest"]:
        return "definitely_before"
    if a["wallClockEarliest"] > b["wallClockLatest"]:
        return "definitely_after"
    if a["gatewayId"] == b["gatewayId"]:
        if a["logicalTime"] < b["logicalTime"]:
            return "causally_before"
        if a["logicalTime"] > b["logicalTime"]:
            return "causally_after"
        return "concurrent"
    return "incomparable"


def _now_stamp(gateway_id: str = "attribution-verifier") -> HybridTimestamp:
    """A synthetic 'verifier' stamp. Logical time is irrelevant for expiry
    checks (which use only wall-clock bounds), so we hard-code it to 1."""
    now_ms = int(time.time() * 1000)
    drift = 1000  # match TS DEFAULT_NTP_DRIFT_MS conservative bound
    return {
        "logicalTime": 1,
        "wallClockEarliest": now_ms - drift,
        "wallClockLatest": now_ms + drift,
        "gatewayId": gateway_id,
    }


def verify_attribution_consent(
    receipt: AttributionReceipt,
    now: Optional[HybridTimestamp] = None,
) -> AttributionConsentResult:
    """End-to-end verification: id matches core hash, both signatures verify,
    not expired, not yet-valid, created_at <= expires_at."""
    core = receipt_core(receipt)
    expected_id = hashlib.sha256(core.encode("utf-8")).hexdigest()
    if expected_id != receipt.get("id"):
        return _fail("receipt id does not match canonical core — tampered")

    try:
        if not verify(core, receipt["citer_signature"], receipt["citer_public_key"]):
            return _fail("citer signature invalid")
    except Exception:
        return _fail("citer signature invalid")

    consent_sig = receipt.get("cited_principal_signature")
    if not consent_sig:
        return _fail("no consent signature")

    try:
        if not verify(core, consent_sig, receipt["cited_principal_public_key"]):
            return _fail("cited principal consent signature invalid")
    except Exception:
        return _fail("cited principal consent signature invalid")

    created_vs_expires = _compare_timestamps(receipt["created_at"], receipt["expires_at"])
    if created_vs_expires == "definitely_after":
        return _fail("expires_at precedes created_at")

    current = now if now is not None else _now_stamp()
    if current["wallClockEarliest"] > receipt["expires_at"]["wallClockLatest"]:
        return _fail("expired")
    if current["wallClockLatest"] < receipt["created_at"]["wallClockEarliest"]:
        return _fail("not yet valid")

    return {"valid": True}


def check_artifact_citations(
    artifact: CitingArtifact,
    receipts: List[AttributionReceipt],
    *,
    binding_context: Optional[str] = None,
    now: Optional[HybridTimestamp] = None,
) -> AttributionConsentResult:
    """Gate an artifact's citations: each must reference a receipt that
    matches content + principal, verifies end-to-end, and shares the
    binding context. Replay-protected per-artifact."""
    citations = artifact.get("citations") or []
    if len(citations) == 0:
        return {"valid": True}

    by_id = {r.get("id"): r for r in receipts}
    seen = set()
    for c in citations:
        rid = c["receipt_id"]
        if rid in seen:
            return _fail(f"replay: receipt {rid} cited more than once in this artifact")
        seen.add(rid)

        r = by_id.get(rid)
        if r is None:
            return _fail(f"no receipt provided for citation {rid}")
        if r["citation_content"] != c["citation_content"]:
            return _fail(f"citation content mismatch for receipt {rid}")
        if r["cited_principal"] != c["cited_principal"]:
            return _fail(f"cited principal mismatch for receipt {rid}")
        if binding_context and r["binding_context"] != binding_context:
            return _fail(f"receipt {rid} is scoped to a different binding context")

        v = verify_attribution_consent(r, now)
        if not v["valid"]:
            return _fail(f"receipt {rid} invalid: {v.get('reason')}")

    return {"valid": True}
