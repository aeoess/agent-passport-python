"""Tests for data source registration, access receipts, and terms compliance."""

import pytest
from agent_passport import generate_key_pair
from agent_passport.data_source import (
    register_self_attested_source,
    register_custodian_attested_source,
    register_gateway_observed_source,
    verify_source_receipt,
    revoke_source_receipt,
    record_data_access,
    verify_data_access_receipt,
    check_terms_compliance,
    compose_terms,
    build_data_access_merkle_root,
)


@pytest.fixture
def owner_keys():
    return generate_key_pair()

@pytest.fixture
def gateway_keys():
    return generate_key_pair()

@pytest.fixture
def terms():
    return {
        "allowed_purposes": ["read", "research"],
        "require_attribution": True,
        "compensation": {"model": "per_access", "rate": 0.001, "currency": "usd"},
        "retention_days": 30,
        "no_training": False,
    }


class TestSourceRegistration:
    def test_self_attested(self, owner_keys, terms):
        receipt = register_self_attested_source(
            "src-1", "Test Source", "https://example.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        assert receipt["sourceId"] == "src-1"
        assert receipt["attestationMode"] == "self_attested"
        assert receipt["signature"]
        v = verify_source_receipt(receipt)
        assert v["valid"]

    def test_custodian_attested(self, gateway_keys, terms):
        receipt = register_custodian_attested_source(
            "src-2", "Custodian Source", "https://example.com",
            terms, gateway_keys["publicKey"], gateway_keys["privateKey"],
        )
        assert receipt["attestationMode"] == "custodian_attested"
        assert verify_source_receipt(receipt)["valid"]

    def test_gateway_observed(self, gateway_keys, terms):
        receipt = register_gateway_observed_source(
            "src-3", "Gateway Source", "https://example.com",
            terms, gateway_keys["publicKey"], gateway_keys["privateKey"],
        )
        assert receipt["attestationMode"] == "gateway_observed"
        assert verify_source_receipt(receipt)["valid"]

    def test_tampered_receipt_fails(self, owner_keys, terms):
        receipt = register_self_attested_source(
            "src-4", "Test", "https://example.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        receipt["sourceName"] = "TAMPERED"
        assert not verify_source_receipt(receipt)["valid"]

    def test_revoke_source(self, owner_keys, terms):
        receipt = register_self_attested_source(
            "src-5", "Revokable", "https://example.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        revoked = revoke_source_receipt(receipt, owner_keys["privateKey"])
        assert revoked.get("revokedAt")

    def test_revoke_wrong_key_fails(self, owner_keys, gateway_keys, terms):
        receipt = register_self_attested_source(
            "src-6", "Test", "https://example.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        with pytest.raises(ValueError, match="does not match"):
            revoke_source_receipt(receipt, gateway_keys["privateKey"])


class TestDataAccess:
    def test_record_access(self, owner_keys, gateway_keys, terms):
        src = register_self_attested_source(
            "src-a", "Source A", "https://a.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        access = record_data_access(
            src, "agent-001", "data:read", "api_read", "read",
            "gw1", gateway_keys["publicKey"], gateway_keys["privateKey"],
        )
        assert access["agentId"] == "agent-001"
        assert access["sourceId"] == "src-a"
        assert access["termsAtAccessTime"] == terms
        v = verify_data_access_receipt(access)
        assert v["valid"]

    def test_revoked_source_blocks_access(self, owner_keys, gateway_keys, terms):
        src = register_self_attested_source(
            "src-b", "Source B", "https://b.com",
            terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        revoked = revoke_source_receipt(src, owner_keys["privateKey"])
        with pytest.raises(ValueError, match="revoked"):
            record_data_access(
                revoked, "agent-001", "data:read", "api_read", "read",
                "gw1", gateway_keys["publicKey"], gateway_keys["privateKey"],
            )

    def test_terms_snapshot_frozen(self, owner_keys, gateway_keys):
        mutable_terms = {"allowed_purposes": ["read"], "compensation": {"model": "per_access", "rate": 5}}
        src = register_self_attested_source(
            "src-c", "Source C", "https://c.com",
            mutable_terms, owner_keys["publicKey"], owner_keys["privateKey"],
        )
        access = record_data_access(
            src, "agent-001", "data:read", "api_read", "read",
            "gw1", gateway_keys["publicKey"], gateway_keys["privateKey"],
        )
        # Mutate original terms
        mutable_terms["compensation"]["rate"] = 999
        # Snapshot must be unaffected
        assert access["termsAtAccessTime"]["compensation"]["rate"] == 5


class TestTermsCompliance:
    def test_compliant_access(self, owner_keys, terms):
        src = register_self_attested_source(
            "src-d", "D", "https://d.com", terms,
            owner_keys["publicKey"], owner_keys["privateKey"],
        )
        result = check_terms_compliance(src, "agent-001", "read")
        assert result["compliant"]
        assert not result["hardViolations"]

    def test_training_blocked_when_no_training(self, owner_keys):
        no_train = {"no_training": True, "allowed_purposes": ["read"]}
        src = register_self_attested_source(
            "src-e", "E", "https://e.com", no_train,
            owner_keys["publicKey"], owner_keys["privateKey"],
        )
        result = check_terms_compliance(src, "agent-001", "model_training")
        assert not result["compliant"]
        assert any("Training" in e for e in result["hardViolations"])

    def test_purpose_advisory_warning(self, owner_keys, terms):
        src = register_self_attested_source(
            "src-f", "F", "https://f.com", terms,
            owner_keys["publicKey"], owner_keys["privateKey"],
        )
        result = check_terms_compliance(src, "agent-001", "commercial_use")
        assert result["compliant"]  # Advisory, not blocking
        assert result["advisoryWarnings"]

    def test_revoked_source_fails_compliance(self, owner_keys, terms):
        src = register_self_attested_source(
            "src-g", "G", "https://g.com", terms,
            owner_keys["publicKey"], owner_keys["privateKey"],
        )
        revoked = revoke_source_receipt(src, owner_keys["privateKey"])
        result = check_terms_compliance(revoked, "agent-001", "read")
        assert not result["compliant"]


class TestTermsComposition:
    def test_compose_narrows(self):
        t1 = {"allowed_purposes": ["read", "research", "training"], "no_training": False, "retention_days": 30}
        t2 = {"allowed_purposes": ["read", "research"], "no_training": False, "retention_days": 14}
        composed = compose_terms([t1, t2])
        assert set(composed["allowed_purposes"]) == {"read", "research"}
        assert composed["retention_days"] == 14

    def test_compose_no_training_wins(self):
        t1 = {"allowed_purposes": ["read"], "no_training": False}
        t2 = {"allowed_purposes": ["read"], "no_training": True}
        composed = compose_terms([t1, t2])
        assert composed["no_training"] is True


class TestMerkle:
    def test_merkle_root_for_receipts(self, owner_keys, gateway_keys, terms):
        src = register_self_attested_source(
            "src-m", "M", "https://m.com", terms,
            owner_keys["publicKey"], owner_keys["privateKey"],
        )
        receipts = []
        for i in range(5):
            r = record_data_access(
                src, f"agent-{i}", "data:read", "api_read", "read",
                "gw1", gateway_keys["publicKey"], gateway_keys["privateKey"],
            )
            receipts.append(r)
        root = build_data_access_merkle_root(receipts)
        assert len(root) == 64  # SHA-256 hex
