# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Data Settlement Protocol — Module 39.

Takes access receipts + DataTerms → generates settlement records.
Cryptographically signed, Merkle-committed, auditable.
Settlement is evidence, not payment.

Port of TypeScript SDK src/core/data-settlement.ts.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .crypto import sign, verify
from .canonical import canonicalize


def _merkle_root(items: list[str]) -> str:
    """Compute Merkle root from a list of hex hashes."""
    if not items:
        return hashlib.sha256(b"empty").hexdigest()
    hashes = [hashlib.sha256(i.encode()).hexdigest() for i in items]
    while len(hashes) > 1:
        nxt = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                nxt.append(hashlib.sha256((hashes[i] + hashes[i + 1]).encode()).hexdigest())
            else:
                nxt.append(hashes[i])
        hashes = nxt
    return hashes[0]


def generate_settlement(
    contributions: list[dict],
    period_start: str, period_end: str,
    generator_public_key: str, generator_private_key: str,
) -> dict:
    """Generate a signed, Merkle-committed settlement record.

    contributions: list of {sourceId, agentId, accessCount,
        compensationModel, amount, currency, receiptIds}
    """
    all_receipt_ids = []
    line_items = []
    for c in contributions:
        rids = c.get("receiptIds", [])
        all_receipt_ids.extend(rids)
        line_items.append({
            "sourceId": c.get("sourceId"),
            "agentId": c.get("agentId"),
            "accessCount": c.get("accessCount", 0),
            "compensationModel": c.get("compensationModel", "attribution_only"),
            "amount": c.get("amount", 0),
            "currency": c.get("currency", "usd"),
            "receiptIds": rids,
        })

    record = {
        "settlementId": f"stlr_{uuid.uuid4().hex[:16]}",
        "period": {"start": period_start, "end": period_end},
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "generatedBy": generator_public_key,
        "lineItems": line_items,
        "totalAmount": sum(li["amount"] for li in line_items),
        "totalAccesses": sum(li["accessCount"] for li in line_items),
        "uniqueSources": len(set(li["sourceId"] for li in line_items)),
        "currency": line_items[0]["currency"] if line_items else "usd",
        "receiptCount": len(all_receipt_ids),
        "merkleRoot": _merkle_root(all_receipt_ids),
    }
    record["signature"] = sign(canonicalize(record), generator_private_key)
    return record


def verify_settlement(record: dict) -> dict:
    """Verify a settlement record's signature and Merkle root."""
    sig = record.get("signature", "")
    pub = record.get("generatedBy", "")
    without_sig = {k: v for k, v in record.items() if k != "signature"}
    try:
        valid = verify(canonicalize(without_sig), sig, pub)
    except Exception:
        valid = False

    # Verify Merkle root
    all_receipt_ids = []
    for li in record.get("lineItems", []):
        all_receipt_ids.extend(li.get("receiptIds", []))
    expected_root = _merkle_root(all_receipt_ids)
    root_valid = expected_root == record.get("merkleRoot")

    return {
        "signatureValid": valid,
        "merkleRootValid": root_valid,
        "settlementId": record.get("settlementId"),
        "totalAmount": record.get("totalAmount"),
        "receiptCount": record.get("receiptCount"),
    }


def generate_compliance_report(
    contributions: list[dict],
    period_start: str, period_end: str,
    report_type: str = "gdpr_article_30",
    generator_private_key: str = "",
    agent_id: str | None = None,
) -> dict:
    """Generate a data compliance report (GDPR Art 30, EU AI Act Art 10, SOC 2)."""
    total_accesses = sum(c.get("accessCount", 0) for c in contributions)
    total_owed = sum(c.get("amount", 0) for c in contributions)
    sources = set(c.get("sourceId", "") for c in contributions)
    purposes: dict[str, int] = {}
    for c in contributions:
        for p in c.get("purposes", [c.get("purpose", "read")]):
            purposes[p] = purposes.get(p, 0) + c.get("accessCount", 0)

    report = {
        "reportId": f"dcpr_{uuid.uuid4().hex[:16]}",
        "reportType": report_type,
        "period": {"start": period_start, "end": period_end},
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "agentId": agent_id,
        "summary": {
            "totalDataAccesses": total_accesses,
            "uniqueDataSources": len(sources),
            "purposeBreakdown": purposes,
            "compensationSummary": {"total": total_owed, "currency": "usd"},
        },
    }
    return report
