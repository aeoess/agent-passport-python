# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN capability pins and identifier binding (Python port).

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Mirrors the TypeScript SDK's ``src/v2/capability-binding/``, name for
name, with snake_case adapted to Python convention. Concept source:
aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2. See ``types.py`` for the
specification position, stated once.
"""

from .binding import evaluate_capability_binding, observe_tool_attestation
from .digest import (
    CAPABILITY_METADATA_DOMAIN_CBD_V0,
    capability_implementation_digest,
    capability_metadata_digest,
)
from .identifier import (
    IDENTIFIER_BINDING_UNSIGNED_FIELDS,
    IDENTIFIER_RETENTION_UNSIGNED_FIELDS,
    evaluate_identifier_continuity,
    identifier_controller_pin_scope_grant,
    identifier_dependency_scope_grant,
    identifier_record_signed_bytes,
    parse_identifier_controller_pins,
)
from .pins import (
    capability_pin_is_empty,
    capability_pin_scope_grants,
    implementation_pin_prefix,
    metadata_pin_prefix,
    parse_capability_pin_from_scope_grants,
    tool_scope_grant,
)
from .types import (
    CAPABILITY_BINDING_REASON_CODES,
    IDENTIFIER_CONTINUITY_REASON_CODES,
    PIN_ENCODINGS,
    REFERENT_CONTINUITY,
    CapabilityBindingError,
    CapabilityPin,
    IdentifierContinuityResult,
    ReferentBindingResult,
    ToolAttestationObservation,
    identifier_continuity_result,
    project_boundary_outcome_to_candidate_v0,
    referent_binding_result,
)

__all__ = [
    "PIN_ENCODINGS",
    "REFERENT_CONTINUITY",
    "CAPABILITY_BINDING_REASON_CODES",
    "IDENTIFIER_CONTINUITY_REASON_CODES",
    "CAPABILITY_METADATA_DOMAIN_CBD_V0",
    "IDENTIFIER_BINDING_UNSIGNED_FIELDS",
    "IDENTIFIER_RETENTION_UNSIGNED_FIELDS",
    "CapabilityPin",
    "ReferentBindingResult",
    "IdentifierContinuityResult",
    "ToolAttestationObservation",
    "CapabilityBindingError",
    "referent_binding_result",
    "identifier_continuity_result",
    "project_boundary_outcome_to_candidate_v0",
    "capability_implementation_digest",
    "capability_metadata_digest",
    "tool_scope_grant",
    "implementation_pin_prefix",
    "metadata_pin_prefix",
    "parse_capability_pin_from_scope_grants",
    "capability_pin_scope_grants",
    "capability_pin_is_empty",
    "observe_tool_attestation",
    "evaluate_capability_binding",
    "identifier_record_signed_bytes",
    "identifier_dependency_scope_grant",
    "identifier_controller_pin_scope_grant",
    "parse_identifier_controller_pins",
    "evaluate_identifier_continuity",
]
