"""APS v1 receipt core.

New signed artifacts in this package use strict RFC 8785 bytes and explicit
domain separation.  Legacy formats are classified, never guessed by trying
multiple canonicalizers.
"""

from .decision_ref import (
    build_decision_ref_v1,
    compute_decision_component_ref_v1,
    compute_decision_ref_v1,
    normalize_core_decision_output_v1,
)
from .receipt import (
    compute_receipt_id_v1,
    create_receipt_v1,
    receipt_id_payload_v1,
    receipt_signature_payload_v1,
    validate_receipt_v1,
    verify_receipt_v1,
)
from .supporting_record import (
    build_evidence_bundle_body_v2,
    build_evidence_bundle_proof_v2,
    classify_supporting_record_format,
    compute_supporting_record_id_v1,
    create_supporting_record_v1,
    evidence_bundle_merkle_root_v2,
    supporting_record_id_payload_v1,
    supporting_record_signature_payload_v1,
    validate_supporting_record_v1,
    verify_evidence_bundle_body_v2,
    verify_evidence_bundle_proof_v2,
    verify_supporting_record_v1,
)

__all__ = [name for name in globals() if not name.startswith("_")]
