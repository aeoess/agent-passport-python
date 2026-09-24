# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Suspension and restriction as a set of causes (Python port).

Each cause has its own release and releasing party. Nothing here is required by
draft-pidlisnyi-aps-03 and nothing here changes any existing exported behaviour. Mirrors
the TypeScript SDK's ``src/v2/suspension/``, name for name, with snake_case adapted to
Python convention. Concept source: aeoess/agent-authority-lifecycle, invariant L8 and
invariant candidate CAND-05, both proposed.
"""

from .evaluate import (
    SuspensionCauseError,
    compose_chain_and_pause,
    evaluate_pause_state,
    explain_pause_state,
    suspension_cause_from_mapping,
    suspension_record_preimage,
    suspension_release_from_mapping,
)
from .types import (
    PAUSE_KINDS,
    RELEASE_STANDINGS,
    SUSPENSION_CAUSE_TYPE,
    SUSPENSION_REASON_CODES,
    SUSPENSION_RELEASE_TYPE,
    CauseDisposition,
    PauseStateExplanation,
    ReleaseCauseDisposition,
    ReleaseDisposition,
    SuspensionCause,
    SuspensionRelease,
)

__all__ = [
    "SUSPENSION_CAUSE_TYPE",
    "SUSPENSION_RELEASE_TYPE",
    "PAUSE_KINDS",
    "RELEASE_STANDINGS",
    "SUSPENSION_REASON_CODES",
    "SuspensionCause",
    "SuspensionRelease",
    "CauseDisposition",
    "ReleaseCauseDisposition",
    "ReleaseDisposition",
    "PauseStateExplanation",
    "SuspensionCauseError",
    "suspension_record_preimage",
    "suspension_cause_from_mapping",
    "suspension_release_from_mapping",
    "evaluate_pause_state",
    "explain_pause_state",
    "compose_chain_and_pause",
]
