"""Tests for DID Interop (did:key, did:web, passport-to-DID-document)."""

from agent_passport.did_interop import (
    to_did_key,
    from_did_key,
    did_web_to_url,
    passport_to_did_document,
)
from agent_passport.crypto import generate_key_pair
import pytest


class TestDIDKey:
    def test_roundtrip(self):
        kp = generate_key_pair()
        did = to_did_key(kp["publicKey"])
        assert did.startswith("did:key:z")
        recovered = from_did_key(did)
        assert recovered == kp["publicKey"].lower()

    def test_deterministic(self):
        kp = generate_key_pair()
        assert to_did_key(kp["publicKey"]) == to_did_key(kp["publicKey"])

    def test_different_keys_different_dids(self):
        kp1 = generate_key_pair()
        kp2 = generate_key_pair()
        assert to_did_key(kp1["publicKey"]) != to_did_key(kp2["publicKey"])

    def test_rejects_invalid_key(self):
        with pytest.raises(ValueError, match="Invalid Ed25519"):
            to_did_key("not-a-key")

    def test_rejects_empty_key(self):
        with pytest.raises(ValueError, match="Invalid Ed25519"):
            to_did_key("")

    def test_rejects_invalid_did_key_format(self):
        with pytest.raises(ValueError, match="Invalid did:key"):
            from_did_key("not:a:valid:did:key")

    def test_rejects_non_z_prefix(self):
        with pytest.raises(ValueError, match="z-prefix"):
            from_did_key("did:key:m123abc")


class TestDIDWeb:
    def test_simple_domain(self):
        url = did_web_to_url("did:web:example.com")
        assert url == "https://example.com/.well-known/did.json"

    def test_domain_with_path(self):
        url = did_web_to_url("did:web:example.com:users:1")
        assert url == "https://example.com/users/1/did.json"

    def test_domain_with_port(self):
        url = did_web_to_url("did:web:example.com%3A8443")
        assert url == "https://example.com:8443/.well-known/did.json"

    def test_rejects_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid did:web"):
            did_web_to_url("did:key:z6Mk123")

    def test_rejects_non_string(self):
        with pytest.raises(ValueError, match="did:web must be a string"):
            did_web_to_url(123)


class TestPassportToDIDDocument:
    def test_produces_valid_document(self):
        kp = generate_key_pair()
        doc = passport_to_did_document("agent-001", kp["publicKey"])
        assert doc["id"].startswith("did:key:z")
        assert doc["controller"] == doc["id"]
        assert len(doc["verificationMethod"]) == 1
        assert doc["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"
        assert len(doc["authentication"]) == 1
        assert len(doc["assertionMethod"]) == 1
        assert len(doc["service"]) == 1
        assert doc["service"][0]["serviceEndpoint"]["agentId"] == "agent-001"

    def test_also_known_as_contains_did_aps(self):
        kp = generate_key_pair()
        doc = passport_to_did_document("agent-001", kp["publicKey"])
        assert any(aka.startswith("did:aps:z") for aka in doc["alsoKnownAs"])

    def test_custom_created_at(self):
        kp = generate_key_pair()
        doc = passport_to_did_document("agent-001", kp["publicKey"], created_at="2025-01-01T00:00:00Z")
        assert doc["created"] == "2025-01-01T00:00:00Z"

    def test_rejects_invalid_key(self):
        with pytest.raises(ValueError, match="public_key must be 64-char hex"):
            passport_to_did_document("agent-001", "short")

    def test_rejects_empty_agent_id(self):
        kp = generate_key_pair()
        with pytest.raises(ValueError, match="agent_id is required"):
            passport_to_did_document("", kp["publicKey"])
