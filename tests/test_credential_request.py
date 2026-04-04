"""Tests for Credential Request Protocol (Selective Disclosure)."""

from agent_passport.credential_request import (
    create_credential_request,
    fulfill_credential_request,
    verify_credential_response,
)
from agent_passport.crypto import generate_key_pair
import pytest


class TestCreateCredentialRequest:
    def test_creates_request(self):
        req = create_credential_request(
            ["grade", "capabilities"],
            "did:key:z6Mk123",
        )
        assert req["id"].startswith("creq_")
        assert req["requestedClaims"] == ["grade", "capabilities"]
        assert req["verifierDID"] == "did:key:z6Mk123"
        assert len(req["challenge"]) > 0

    def test_custom_challenge(self):
        req = create_credential_request(
            ["grade"],
            "did:key:z6Mk123",
            challenge="custom-nonce",
        )
        assert req["challenge"] == "custom-nonce"

    def test_rejects_empty_claims(self):
        with pytest.raises(ValueError, match="at least one claim"):
            create_credential_request([], "did:key:z6Mk123")

    def test_rejects_missing_verifier(self):
        with pytest.raises(ValueError, match="Verifier DID"):
            create_credential_request(["grade"], "")


class TestFulfillAndVerify:
    def _make_passport(self):
        kp = generate_key_pair()
        return {
            "agentId": "agent-test-001",
            "publicKey": kp["publicKey"],
            "agentName": "Test Agent",
            "mission": "Testing selective disclosure",
            "capabilities": ["code_exec", "web_search"],
            "grade": 3,
            "delegationScope": ["data_read", "commerce"],
        }, kp

    def test_full_roundtrip(self):
        passport, kp = self._make_passport()
        req = create_credential_request(
            ["grade", "capabilities"],
            "did:key:z6MkVerifier",
        )
        vp = fulfill_credential_request(req, passport, kp["privateKey"])

        result = verify_credential_response(vp, req["challenge"])
        assert result["valid"] is True
        assert result["claims"]["grade"] == 3
        assert result["claims"]["capabilities"] == ["code_exec", "web_search"]
        # mission was NOT requested, should not be in claims
        assert "mission" not in result["claims"]

    def test_selective_disclosure(self):
        passport, kp = self._make_passport()
        req = create_credential_request(["grade"], "did:key:z6MkV")
        vp = fulfill_credential_request(req, passport, kp["privateKey"])

        vc = vp["verifiableCredential"][0]
        subject = vc["credentialSubject"]
        assert "grade" in subject
        assert "capabilities" not in subject
        assert "mission" not in subject
        # id and agentId are always included
        assert "id" in subject
        assert "agentId" in subject

    def test_challenge_mismatch_fails(self):
        passport, kp = self._make_passport()
        req = create_credential_request(["grade"], "did:key:z6MkV")
        vp = fulfill_credential_request(req, passport, kp["privateKey"])

        result = verify_credential_response(vp, "wrong-challenge")
        assert result["valid"] is False
        assert any("challenge mismatch" in c for c in result["checks"])

    def test_no_challenge_check_passes(self):
        passport, kp = self._make_passport()
        req = create_credential_request(["grade"], "did:key:z6MkV")
        vp = fulfill_credential_request(req, passport, kp["privateKey"])

        result = verify_credential_response(vp)
        assert result["valid"] is True

    def test_tampered_vp_fails(self):
        passport, kp = self._make_passport()
        req = create_credential_request(["grade"], "did:key:z6MkV")
        vp = fulfill_credential_request(req, passport, kp["privateKey"])
        vp["holder"] = "did:key:z6MkTAMPERED"

        result = verify_credential_response(vp)
        assert result["valid"] is False

    def test_with_evidence(self):
        passport, kp = self._make_passport()
        passport["evidence"] = [{
            "provider": "cluster.local",
            "subjectClass": "workload",
            "verificationMethod": "x509",
            "issuedAt": "2025-01-01T00:00:00Z",
            "expiresAt": "2030-01-01T00:00:00Z",
        }]
        req = create_credential_request(["grade"], "did:key:z6MkV")
        vp = fulfill_credential_request(req, passport, kp["privateKey"])

        vc = vp["verifiableCredential"][0]
        assert len(vc["evidence"]) == 1

        result = verify_credential_response(vp)
        assert result["valid"] is True
