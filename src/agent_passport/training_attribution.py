"""Training Attribution — tracks when agent outputs are used for training.

Links Module 36A access receipts to downstream training events.
The chain: data source → access receipt → agent output → training event.

Port of TypeScript SDK src/core/training-attribution.ts.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .crypto import sign, verify
from .canonical import canonicalize

TRAINING_USE_TYPES = [
    "fine_tune", "lora_adapter", "embedding", "rag_index",
    "distillation", "evaluation", "synthetic_data",
]


def create_training_attribution(
    training_use_type: str, model_id: str,
    trainer_id: str, trainer_public_key: str, trainer_private_key: str,
    source_access_receipt_ids: list[str],
    execution_frame_id: str = "",
    output_content_hash: str = "",
    input_data_hashes: list[str] | None = None,
    contribution_weights: dict[str, float] | None = None,
    model_version: str = "",
    dataset_size: int | None = None,
    training_split: str = "train",
) -> dict:
    """Create a signed training attribution receipt."""
    receipt = {
        "trainingReceiptId": f"trar_{uuid.uuid4().hex[:16]}",
        "trainingUseType": training_use_type,
        "modelId": model_id,
        "modelVersion": model_version,
        "trainerId": trainer_id,
        "trainerPublicKey": trainer_public_key,
        "sourceAccessReceiptIds": source_access_receipt_ids,
        "executionFrameId": execution_frame_id,
        "outputContentHash": output_content_hash,
        "inputDataHashes": input_data_hashes or [],
        "contributionWeights": contribution_weights or {},
        "datasetSize": dataset_size,
        "trainingSplit": training_split,
        "recordedAt": datetime.now(timezone.utc).isoformat(),
    }
    receipt["contentHash"] = hashlib.sha256(
        canonicalize(receipt).encode()
    ).hexdigest()
    receipt["signature"] = sign(canonicalize(receipt), trainer_private_key)
    return receipt


def verify_training_attribution(receipt: dict) -> dict:
    """Verify a training attribution receipt's signature."""
    sig = receipt.get("signature", "")
    pub = receipt.get("trainerPublicKey", "")
    without = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        valid = verify(canonicalize(without), sig, pub)
    except Exception:
        valid = False
    return {
        "valid": valid,
        "trainingReceiptId": receipt.get("trainingReceiptId"),
        "modelId": receipt.get("modelId"),
        "sourceCount": len(receipt.get("sourceAccessReceiptIds", [])),
    }
