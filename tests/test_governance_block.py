# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tests for Governance Block — HTML-embedded governance metadata."""

import pytest
from agent_passport import (
    generate_key_pair,
    generate_governance_block,
    verify_governance_block,
    render_governance_html,
    render_governance_meta,
    parse_governance_block_from_html,
    embed_governance,
    is_usage_permitted,
)

ARTICLE = (
    "AI agents are transforming the economy. This article explores how "
    "governance infrastructure ensures accountability when agents act "
    "on behalf of humans and organizations."
)

TERMS = {
    "inference": "permitted",
    "training": "compensation_required",
    "redistribution": "prohibited",
    "derivative": "attribution_required",
    "caching": "permitted",
    "version": "1.0",
}


@pytest.fixture
def keys():
    return generate_key_pair()


class TestGenerateVerify:
    def test_generates_valid_block(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        assert block["@context"] == "https://aeoess.com/governance/v1"
        assert block["@type"] == "GovernanceBlock"
        assert block["source_did"].startswith("did:aps:z")
        assert block["content_hash"].startswith("sha256:")
        assert block["signature"]
        assert block["terms"]["training"] == "compensation_required"
        assert block["revocation_policy"]["cached_copy"] == "delete"

    def test_verifies_valid_block(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        result = verify_governance_block(block, ARTICLE, keys["publicKey"])
        assert result["valid"] is True
        assert result["signatureValid"] is True
        assert result["contentHashValid"] is True
        assert result["didConsistent"] is True
        assert len(result["errors"]) == 0

    def test_detects_tampered_content(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        result = verify_governance_block(block, ARTICLE + " INJECTED", keys["publicKey"])
        assert result["valid"] is False
        assert result["contentHashValid"] is False

    def test_detects_wrong_key(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        other = generate_key_pair()
        result = verify_governance_block(block, ARTICLE, other["publicKey"])
        assert result["valid"] is False
        assert result["signatureValid"] is False
        assert result["didConsistent"] is False

    def test_detects_tampered_terms(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        block["terms"]["training"] = "permitted"
        result = verify_governance_block(block, ARTICLE, keys["publicKey"])
        assert result["valid"] is False
        assert result["signatureValid"] is False


class TestHTMLEmbedding:
    def test_renders_script_tag(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        html = render_governance_html(block)
        assert html.startswith('<script type="application/aps-governance+json">')
        assert html.endswith("</script>")
        assert '"source_did"' in html

    def test_renders_meta_tag(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        meta = render_governance_meta(block)
        assert meta.startswith('<meta name="aps-governance"')
        assert 'content="' in meta

    def test_roundtrip_script_tag(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        html = render_governance_html(block)
        page = f"<html><head>{html}</head><body>{ARTICLE}</body></html>"
        parsed = parse_governance_block_from_html(page)
        assert parsed is not None
        result = verify_governance_block(parsed, ARTICLE, keys["publicKey"])
        assert result["valid"] is True

    def test_roundtrip_meta_tag(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        meta = render_governance_meta(block)
        page = f"<html><head>{meta}</head><body></body></html>"
        parsed = parse_governance_block_from_html(page)
        assert parsed is not None
        result = verify_governance_block(parsed, ARTICLE, keys["publicKey"])
        assert result["valid"] is True

    def test_no_block_returns_none(self):
        parsed = parse_governance_block_from_html("<html><body>No governance</body></html>")
        assert parsed is None

    def test_embed_governance_convenience(self, keys):
        result = embed_governance(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)
        assert result["block"]["signature"]
        assert "aps-governance+json" in result["html"]
        assert "aps-governance" in result["meta"]


class TestUsageChecks:
    @pytest.fixture(autouse=True)
    def setup(self, keys):
        self.block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], TERMS)

    def test_inference_permitted(self):
        r = is_usage_permitted(self.block, "inference")
        assert r["permitted"] is True
        assert r["condition"] == "permitted"

    def test_training_requires_compensation(self):
        r = is_usage_permitted(self.block, "training")
        assert r["permitted"] is False
        assert r["condition"] == "compensation_required"

    def test_redistribution_prohibited(self):
        r = is_usage_permitted(self.block, "redistribution")
        assert r["permitted"] is False
        assert r["condition"] == "prohibited"

    def test_derivative_requires_attribution(self):
        r = is_usage_permitted(self.block, "derivative")
        assert r["permitted"] is True
        assert r["condition"] == "attribution_required"

    def test_unspecified_defaults_permitted(self, keys):
        block = generate_governance_block(ARTICLE, keys["publicKey"], keys["privateKey"], {"inference": "permitted"})
        r = is_usage_permitted(block, "training")
        assert r["permitted"] is True
        assert r["condition"] == "not_specified"
