# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN lifecycle state vocabulary (Python port).

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Mirrors the TypeScript SDK's ``src/v2/lifecycle-state/``, name for
name, with snake_case adapted to Python convention. Concept source:
aeoess/agent-authority-lifecycle.
"""

from .map import map_authority_validation_to_lifecycle
from .state import (
    is_boundary_outcome,
    is_established_negative_shape,
    is_establishment_gap,
    is_lifecycle_verdict,
    lifecycle_state,
    not_established,
    resolve_established_negative,
)
from .types import (
    BOUNDARY_OUTCOMES,
    ESTABLISHED_NEGATIVE_SHAPES,
    ESTABLISHMENT_GAPS,
    LIFECYCLE_BASE_REASON_CODES,
    LIFECYCLE_VERDICTS,
    CompositeAuthorityResult,
    EstablishedNegativeResolution,
    LifecycleStateError,
    LifecycleStateResult,
    OutstandingCause,
)

__all__ = [
    "LIFECYCLE_VERDICTS",
    "BOUNDARY_OUTCOMES",
    "ESTABLISHMENT_GAPS",
    "ESTABLISHED_NEGATIVE_SHAPES",
    "LIFECYCLE_BASE_REASON_CODES",
    "LifecycleStateResult",
    "OutstandingCause",
    "EstablishedNegativeResolution",
    "CompositeAuthorityResult",
    "LifecycleStateError",
    "lifecycle_state",
    "not_established",
    "resolve_established_negative",
    "map_authority_validation_to_lifecycle",
    "is_lifecycle_verdict",
    "is_boundary_outcome",
    "is_establishment_gap",
    "is_established_negative_shape",
]
