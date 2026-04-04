"""Tests for VC Wrapper (W3C Verifiable Credentials)."""

from agent_passport.vc_wrapper import (
    passport_to_verifiable_credential,
    verify_verifiable_credential,
    create_verifiable_presentation,
    verify_verifiable_presentation,
)
from agent_passport.crypto import generate_key_pair, public_key_from_private


class TestPassportToVC:
    def test_creates_valid_vc(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {
                "agentId": "agent-001",
                "publicKey": kp["publicKey"],
                "agentName": "Test Agent",
                "mission": "Testing",
                "capabilities": ["read"],
                "grade": 2,
            },
            kp["privateKey"],
        )
        assert "VerifiableCredential" in vc["type"]
        assert "AgentPassportCredential" in vc["type"]
        assert vc["issuer"].startswith("did:key:z")
        assert vc["credentialSubject"]["id"].startswith("did:key:z")
        assert vc["credentialSubject"]["agentId"] == "agent-001"
        assert vc["credentialSubject"]["grade"] == 2

    def test_verifies_own_vc(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {"agentId": "agent-001", "publicKey": kp["publicKey"]},
            kp["privateKey"],
        )
        result = verify_verifiable_credential(vc)
        assert result["valid"] is True
        assert any("signature valid" in c for c in result["checks"])

    def test_with_evidence(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {
                "agentId": "agent-001",
                "publicKey": kp["publicKey"],
                "evidence": [{
                    "provider": "cluster.local",
                    "subjectClass": "workload",
                    "verificationMethod": "x509",
                    "issuedAt": "2025-01-01T00:00:00Z",
                    "expiresAt": "2030-01-01T00:00:00Z",
                }],
            },
            kp["privateKey"],
        )
        assert len(vc["evidence"]) == 1
        result = verify_verifiable_credential(vc)
        assert result["valid"] is True
        assert any("evidence" in c for c in result["checks"])

    def test_tampered_vc_fails(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {"agentId": "agent-001", "publicKey": kp["publicKey"]},
            kp["privateKey"],
        )
        vc["credentialSubject"]["agentId"] = "tampered"
        result = verify_verifiable_credential(vc)
        assert result["valid"] is False

    def test_missing_fields_fails(self):
        result = verify_verifiable_credential({"type": ["VerifiableCredential"]})
        assert result["valid"] is False
        assert any("missing" in c for c in result["checks"])


class TestVerifiablePresentation:
    def test_creates_and_verifies_vp(self):
        issuer_kp = generate_key_pair()
        holder_kp = generate_key_pair()

        vc = passport_to_verifiable_credential(
            {"agentId": "agent-001", "publicKey": holder_kp["publicKey"]},
            issuer_kp["privateKey"],
        )

        vp = create_verifiable_presentation(
            [vc], holder_kp["privateKey"], challenge="test-challenge"
        )
        assert vp["holder"].startswith("did:key:z")
        assert len(vp["verifiableCredential"]) == 1

        result = verify_verifiable_presentation(vp)
        assert result["valid"] is True
        assert len(result["credentials"]) == 1

    def test_challenge_in_proof(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {"agentId": "agent-001", "publicKey": kp["publicKey"]},
            kp["privateKey"],
        )
        vp = create_verifiable_presentation(
            [vc], kp["privateKey"], challenge="nonce-123", domain="example.com"
        )
        assert vp["proof"]["challenge"] == "nonce-123"
        assert vp["proof"]["domain"] == "example.com"

    def test_missing_fields_fails(self):
        result = verify_verifiable_presentation({"type": ["VerifiablePresentation"]})
        assert result["valid"] is False

    def test_tampered_vp_fails(self):
        kp = generate_key_pair()
        vc = passport_to_verifiable_credential(
            {"agentId": "agent-001", "publicKey": kp["publicKey"]},
            kp["privateKey"],
        )
        vp = create_verifiable_presentation([vc], kp["privateKey"])
        vp["holder"] = "did:key:z6MkTAMPERED"
        result = verify_verifiable_presentation(vp)
        assert result["valid"] is False
