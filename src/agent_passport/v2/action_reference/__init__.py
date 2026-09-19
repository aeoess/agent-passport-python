# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS native action reference, profile ``aps-action-ref-v2``, public surface (Python port).

Draft-pidlisnyi-aps-03 section 4.1. Mirrors src/v2/action-reference/v2.ts in the
TypeScript SDK: the same domain-separation tags over the same strict-JCS preimage.
Digest agreement with the TypeScript SDK is checked by the vectors in
tests/cross_impl/action-ref-v2-vectors.json. Distinct from the pre-draft-03
compatibility digest in agent_passport.action_ref.
"""
from .v2 import (
    ACTION_REF_V2_DOMAIN,
    ACTION_REF_V2_PROFILE,
    PAYLOAD_REF_V1_DOMAIN,
    ActionReferenceError,
    compute_action_ref_v2,
    compute_action_ref_v2_from_json,
    compute_payload_ref_v1,
    create_action_reference_input_v2,
    parse_action_reference_input_v2,
    validate_action_reference_input_v2,
)

__all__ = [
    "ACTION_REF_V2_PROFILE",
    "ACTION_REF_V2_DOMAIN",
    "PAYLOAD_REF_V1_DOMAIN",
    "ActionReferenceError",
    "validate_action_reference_input_v2",
    "compute_action_ref_v2",
    "compute_payload_ref_v1",
    "create_action_reference_input_v2",
    "parse_action_reference_input_v2",
    "compute_action_ref_v2_from_json",
]
