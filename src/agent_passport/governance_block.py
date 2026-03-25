# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Governance Block — Cryptographic governance metadata for HTML embedding.

Embeds signed provenance, terms, and revocation primitives directly into
web pages so ANY crawler (not just MCP clients) ingests governance metadata
alongside content.

Two channels, same primitives:
  HTML: governance block embedded in page — evidence layer
  MCP:  full enforcement — terms must be accepted before content served
"""

import hashlib
import json
import re
import base64
from datetime import datetime, timezone
from typing import Optional, Literal

from .crypto import sign, verify
from .canonical import canonicalize

UsagePermission = Literal[
    "permitted", "prohibited", "compensation_required", "attribution_required"
]

DEFAULT_REVOCATION_POLICY = {
    "cached_copy": "delete",
    "rag_chunk": "delete",
    "embedding": "quarantine",
    "fine_tune": "no_future_use",
    "synthetic": "compensation_only",
}


def _create_did(public_key_hex: str) -> str:
    """Create a did:aps DID from a public key (simplified, no multibase)."""
    return f"did:aps:z{public_key_hex}"


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_governance_block(
    content: str,
    public_key: str,
    private_key: str,
    terms: dict,
    revocation_policy: Optional[dict] = None,
    published_at: Optional[str] = None,
) -> dict:
    """Generate a signed governance block for HTML embedding.

    Args:
        content: Article/page content to hash and govern.
        public_key: Publisher's Ed25519 public key (hex).
        private_key: Publisher's Ed25519 private key (hex).
        terms: Dict with keys like inference, training, redistribution, etc.
        revocation_policy: Dict with per-artifact obligations (defaults to strict).
        published_at: ISO timestamp (defaults to now).

    Returns:
        Signed governance block dict ready for HTML embedding.
    """
    content_hash = f"sha256:{_sha256(content)}"
    source_did = _create_did(public_key)
    now = _now_iso()

    block = {
        "@context": "https://aeoess.com/governance/v1",
        "@type": "GovernanceBlock",
        "source_did": source_did,
        "content_hash": content_hash,
        "published_at": published_at or now,
        "governance_generated_at": now,
        "terms": dict(terms),
        "revocation_policy": dict(revocation_policy or DEFAULT_REVOCATION_POLICY),
    }

    payload = canonicalize(block)
    signature = sign(payload, private_key)
    block["signature"] = signature
    return block


def verify_governance_block(block: dict, content: str, public_key: str) -> dict:
    """Verify a governance block's signature, content hash, and DID.

    Returns:
        Dict with signatureValid, contentHashValid, didConsistent, valid, errors.
    """
    errors = []

    # 1. Verify signature
    rest = {k: v for k, v in block.items() if k != "signature"}
    payload = canonicalize(rest)
    signature_valid = verify(payload, block.get("signature", ""), public_key)
    if not signature_valid:
        errors.append("Signature verification failed")

    # 2. Verify content hash
    expected_hash = f"sha256:{_sha256(content)}"
    content_hash_valid = block.get("content_hash") == expected_hash
    if not content_hash_valid:
        errors.append(f"Content hash mismatch: expected {expected_hash}")

    # 3. Verify DID consistency
    expected_did = _create_did(public_key)
    did_consistent = block.get("source_did") == expected_did
    if not did_consistent:
        errors.append(f"DID mismatch: expected {expected_did}")

    return {
        "signatureValid": signature_valid,
        "contentHashValid": content_hash_valid,
        "didConsistent": did_consistent,
        "valid": signature_valid and content_hash_valid and did_consistent,
        "errors": errors,
    }


def render_governance_html(block: dict) -> str:
    """Render governance block as an HTML script tag."""
    j = json.dumps(block, indent=2)
    return f'<script type="application/aps-governance+json">\n{j}\n</script>'


def render_governance_meta(block: dict) -> str:
    """Render governance block as a base64 meta tag (for strict CSP)."""
    b64 = base64.b64encode(json.dumps(block).encode()).decode()
    return f'<meta name="aps-governance" content="{b64}" />'


def parse_governance_block_from_html(html: str) -> Optional[dict]:
    """Extract a governance block from HTML content."""
    # Try script tag
    m = re.search(
        r'<script\s+type\s*=\s*"application/aps-governance\+json"\s*>(.*?)</script>',
        html, re.DOTALL | re.IGNORECASE,
    )
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            return None

    # Try meta tag
    m = re.search(
        r'<meta\s+name\s*=\s*"aps-governance"\s+content\s*=\s*"([^"]+)"\s*/?>',
        html, re.IGNORECASE,
    )
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8")
            return json.loads(decoded)
        except (json.JSONDecodeError, Exception):
            return None

    return None


def embed_governance(
    content: str,
    public_key: str,
    private_key: str,
    terms: dict,
    revocation_policy: Optional[dict] = None,
    published_at: Optional[str] = None,
) -> dict:
    """Generate + render in one call. Returns block, html, meta."""
    block = generate_governance_block(
        content, public_key, private_key, terms, revocation_policy, published_at,
    )
    return {
        "block": block,
        "html": render_governance_html(block),
        "meta": render_governance_meta(block),
    }


def is_usage_permitted(block: dict, usage: str) -> dict:
    """Check if a specific usage type is permitted under terms.

    Args:
        block: Governance block dict.
        usage: One of inference, training, redistribution, derivative, caching.

    Returns:
        Dict with permitted (bool) and condition (str).
    """
    permission = block.get("terms", {}).get(usage)
    if not permission:
        return {"permitted": True, "condition": "not_specified"}
    return {
        "permitted": permission in ("permitted", "attribution_required"),
        "condition": permission,
    }
