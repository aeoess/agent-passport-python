# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN activation conditions and condition attestation (Python port).

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Mirrors the TypeScript SDK's ``src/v2/activation/``, name for name, with
snake_case adapted to Python convention. Concept source: aeoess/agent-authority-lifecycle,
invariant candidates CAND-04, CAND-13 (activation half) and BROAD-L7, all proposed.
"""

from .canonical import (
    ACTIVATION_ATTESTATION_ID_DOMAIN,
    ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
    ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
    activation_attestation_body,
    activation_attestation_signature_input,
    activation_condition_signature_input,
    compute_activation_attestation_id,
)
from .types import (
    ACTIVATION_ASSERTIONS,
    ACTIVATION_ATTESTATION_TYPE,
    ACTIVATION_CONDITION_KINDS,
    ACTIVATION_CONDITION_TYPE,
    ACTIVATION_FINDINGS,
    ACTIVATION_GAPS_BY_REASON,
    ACTIVATION_INSTANT_BASES,
    ACTIVATION_REASON_CODES,
    ATTESTOR_ROLE_STANDINGS,
    ActivationError,
    ActivationFinding,
    ActivationRejection,
    ActivationResult,
    AttestorRoleResolver,
)
from .verify import compose_activation, validate_activation_condition, verify_activation

__all__ = [
    "ACTIVATION_CONDITION_TYPE",
    "ACTIVATION_ATTESTATION_TYPE",
    "ACTIVATION_CONDITION_KINDS",
    "ACTIVATION_INSTANT_BASES",
    "ACTIVATION_ASSERTIONS",
    "ATTESTOR_ROLE_STANDINGS",
    "ACTIVATION_FINDINGS",
    "ACTIVATION_REASON_CODES",
    "ACTIVATION_GAPS_BY_REASON",
    "ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN",
    "ACTIVATION_ATTESTATION_ID_DOMAIN",
    "ACTIVATION_CONDITION_SIGNATURE_DOMAIN",
    "ActivationFinding",
    "ActivationRejection",
    "ActivationResult",
    "AttestorRoleResolver",
    "ActivationError",
    "verify_activation",
    "compose_activation",
    "validate_activation_condition",
    "activation_attestation_body",
    "activation_attestation_signature_input",
    "compute_activation_attestation_id",
    "activation_condition_signature_input",
]
