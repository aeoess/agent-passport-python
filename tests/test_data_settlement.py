"""Tests for data settlement protocol."""

import pytest
from agent_passport import generate_key_pair
from agent_passport.data_settlement import (
    generate_settlement,
    verify_settlement,
    generate_compliance_report,
)


@pytest.fixture
def gen_keys():
    return generate_key_pair()


@pytest.fixture
def sample_contributions():
    return [
        {"sourceId": "src-1", "agentId": "agent-a", "accessCount": 100,
         "compensationModel": "per_access", "amount": 0.10, "currency": "usd",
         "receiptIds": ["dar_1", "dar_2", "dar_3"]},
        {"sourceId": "src-2", "agentId": "agent-a", "accessCount": 50,
         "compensationModel": "per_access", "amount": 0.05, "currency": "usd",
         "receiptIds": ["dar_4", "dar_5"]},
        {"sourceId": "src-1", "agentId": "agent-b", "accessCount": 200,
         "compensationModel": "per_access", "amount": 0.20, "currency": "usd",
         "receiptIds": ["dar_6", "dar_7", "dar_8", "dar_9"]},
    ]


class TestSettlement:
    def test_generate_and_verify(self, gen_keys, sample_contributions):
        record = generate_settlement(
            sample_contributions,
            "2026-03-01", "2026-03-31",
            gen_keys["publicKey"], gen_keys["privateKey"],
        )
        assert record["totalAmount"] == pytest.approx(0.35)
        assert record["totalAccesses"] == 350
        assert record["uniqueSources"] == 2
        assert record["receiptCount"] == 9
        assert record["merkleRoot"]
        assert record["signature"]

        v = verify_settlement(record)
        assert v["signatureValid"]
        assert v["merkleRootValid"]

    def test_tampered_settlement_fails(self, gen_keys, sample_contributions):
        record = generate_settlement(
            sample_contributions,
            "2026-03-01", "2026-03-31",
            gen_keys["publicKey"], gen_keys["privateKey"],
        )
        record["totalAmount"] = 999.99
        v = verify_settlement(record)
        assert not v["signatureValid"]

    def test_empty_settlement(self, gen_keys):
        record = generate_settlement(
            [], "2026-03-01", "2026-03-31",
            gen_keys["publicKey"], gen_keys["privateKey"],
        )
        assert record["totalAmount"] == 0
        assert record["totalAccesses"] == 0
        v = verify_settlement(record)
        assert v["signatureValid"]


class TestComplianceReport:
    def test_generate_report(self, sample_contributions):
        report = generate_compliance_report(
            sample_contributions,
            "2026-03-01", "2026-03-31",
            report_type="gdpr_article_30",
        )
        assert report["reportType"] == "gdpr_article_30"
        assert report["summary"]["totalDataAccesses"] == 350
        assert report["summary"]["uniqueDataSources"] == 2
        assert report["summary"]["compensationSummary"]["total"] == pytest.approx(0.35)
