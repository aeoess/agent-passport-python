# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Non-time bounds on a grant: purpose, use count and budget.

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Mirrors the TypeScript SDK's ``src/v2/bounds/``, name for name, with
snake_case adapted to Python convention. Concept source: aeoess/agent-authority-lifecycle,
invariant L10 and invariant candidates CAND-01 and CAND-02. See ``types.py``.
"""

from .canonical import (
    AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN,
    AUTHORITY_EXHAUSTION_ID_DOMAIN,
    AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN,
    authority_bound_fulfilment_signature_input,
    authority_bound_fulfilment_signature_input_for_write,
    authority_exhaustion_id_input,
    authority_exhaustion_signature_input,
    authority_exhaustion_signature_input_for_write,
    compute_authority_exhaustion_id,
    compute_authority_exhaustion_id_for_write,
    sign_authority_bound_fulfilment,
    sign_authority_exhaustion,
    verify_authority_bound_fulfilment_signature,
    verify_authority_exhaustion_signature,
)
from .evaluate import (
    assert_authority_bound,
    assess_fulfilment,
    evaluate_bound,
    is_attestor_role_answer,
    is_bound_kind,
)
from .purpose import is_purpose_permitted, purpose_category
from .record import (
    AUTHORITY_EXHAUSTION_FAILURE_CODES,
    AuthorityExhaustionVerification,
    issue_authority_bound_fulfilment,
    issue_authority_exhaustion,
    verify_authority_exhaustion,
)
from .types import (
    ATTESTOR_ROLE_ANSWERS,
    AUTHORITY_BOUND_FULFILMENT_TYPE,
    AUTHORITY_BOUND_TYPE,
    AUTHORITY_EXHAUSTION_TYPE,
    BOUND_KINDS,
    BOUND_REASON_CODES,
    BOUND_STATES,
    FULFILMENT_REASON_CODES,
    AttestorRoleResolver,
    AuthorityBound,
    AuthorityBoundError,
    BoundEvaluation,
    BoundVerificationKeyResolver,
    FulfilmentAssessment,
)

__all__ = [
    "ATTESTOR_ROLE_ANSWERS",
    "AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN",
    "AUTHORITY_BOUND_FULFILMENT_TYPE",
    "AUTHORITY_BOUND_TYPE",
    "AUTHORITY_EXHAUSTION_FAILURE_CODES",
    "AUTHORITY_EXHAUSTION_ID_DOMAIN",
    "AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN",
    "AUTHORITY_EXHAUSTION_TYPE",
    "BOUND_KINDS",
    "BOUND_REASON_CODES",
    "BOUND_STATES",
    "FULFILMENT_REASON_CODES",
    "AttestorRoleResolver",
    "AuthorityBound",
    "AuthorityBoundError",
    "AuthorityExhaustionVerification",
    "BoundEvaluation",
    "BoundVerificationKeyResolver",
    "FulfilmentAssessment",
    "assert_authority_bound",
    "assess_fulfilment",
    "authority_bound_fulfilment_signature_input",
    "authority_bound_fulfilment_signature_input_for_write",
    "authority_exhaustion_id_input",
    "authority_exhaustion_signature_input",
    "authority_exhaustion_signature_input_for_write",
    "compute_authority_exhaustion_id",
    "compute_authority_exhaustion_id_for_write",
    "evaluate_bound",
    "is_attestor_role_answer",
    "is_bound_kind",
    "is_purpose_permitted",
    "issue_authority_bound_fulfilment",
    "issue_authority_exhaustion",
    "purpose_category",
    "sign_authority_bound_fulfilment",
    "sign_authority_exhaustion",
    "verify_authority_bound_fulfilment_signature",
    "verify_authority_exhaustion",
    "verify_authority_exhaustion_signature",
]
