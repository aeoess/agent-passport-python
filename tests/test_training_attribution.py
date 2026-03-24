"""Tests for training attribution receipts."""

import pytest
from agent_passport import generate_key_pair
from agent_passport.training_attribution import (
    create_training_attribution,
    verify_training_attribution,
)


@pytest.fixture
def trainer_keys():
    return generate_key_pair()


class TestTrainingAttribution:
    def test_create_and_verify(self, trainer_keys):
        receipt = create_training_attribution(
            training_use_type="rag_index",
            model_id="my-model-v1",
            trainer_id="trainer-001",
            trainer_public_key=trainer_keys["publicKey"],
            trainer_private_key=trainer_keys["privateKey"],
            source_access_receipt_ids=["dar_abc", "dar_def", "dar_ghi"],
            output_content_hash="deadbeef",
        )
        assert receipt["trainingUseType"] == "rag_index"
        assert receipt["modelId"] == "my-model-v1"
        assert len(receipt["sourceAccessReceiptIds"]) == 3
        assert receipt["contentHash"]
        assert receipt["signature"]

        v = verify_training_attribution(receipt)
        assert v["valid"]
        assert v["sourceCount"] == 3

    def test_tampered_receipt_fails(self, trainer_keys):
        receipt = create_training_attribution(
            training_use_type="fine_tune",
            model_id="model-x",
            trainer_id="trainer-001",
            trainer_public_key=trainer_keys["publicKey"],
            trainer_private_key=trainer_keys["privateKey"],
            source_access_receipt_ids=["dar_123"],
        )
        receipt["modelId"] = "TAMPERED"
        assert not verify_training_attribution(receipt)["valid"]

    def test_all_training_types(self, trainer_keys):
        for use_type in ["fine_tune", "lora_adapter", "embedding", "rag_index",
                         "distillation", "evaluation", "synthetic_data"]:
            receipt = create_training_attribution(
                training_use_type=use_type,
                model_id=f"model-{use_type}",
                trainer_id="t1",
                trainer_public_key=trainer_keys["publicKey"],
                trainer_private_key=trainer_keys["privateKey"],
                source_access_receipt_ids=["dar_1"],
            )
            assert verify_training_attribution(receipt)["valid"]
