# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, EXPERIMENTAL, OPT-IN. Multi-source status observation with per-source freshness
bounds.

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Concept source: aeoess/agent-authority-lifecycle, invariant candidate
BROAD-L7 and invariant L7. See ``types.py`` for the full position.

Python port of the TypeScript SDK's ``src/v2/status-coverage/``.
"""

from .decide import decide_multi_source_status
from .types import (
    CONFLICT_POLICIES,
    COVERAGE_DENOMINATORS,
    DETERMINATE_STATUS_ANSWERS,
    SILENCE_POLICIES,
    STATUS_ANSWERS,
    STATUS_COVERAGE_REASON_CODES,
    STATUS_USE_BASES,
    VERIFIER_MODES,
    AdmittedSnapshot,
    DeclaredStatusSource,
    MultiSourceStatusBasis,
    MultiSourceStatusDecision,
    RequiredSourceSet,
    SnapshotSource,
    StaleAnswerPolicy,
    StatusAnswerInput,
    StatusConflict,
    StatusCoverage,
    StatusCoverageError,
    StatusSourceLine,
    StatusTrustPolicy,
)

__all__ = [
    "CONFLICT_POLICIES",
    "COVERAGE_DENOMINATORS",
    "DETERMINATE_STATUS_ANSWERS",
    "SILENCE_POLICIES",
    "STATUS_ANSWERS",
    "STATUS_COVERAGE_REASON_CODES",
    "STATUS_USE_BASES",
    "VERIFIER_MODES",
    "AdmittedSnapshot",
    "DeclaredStatusSource",
    "MultiSourceStatusBasis",
    "MultiSourceStatusDecision",
    "RequiredSourceSet",
    "SnapshotSource",
    "StaleAnswerPolicy",
    "StatusAnswerInput",
    "StatusConflict",
    "StatusCoverage",
    "StatusCoverageError",
    "StatusSourceLine",
    "StatusTrustPolicy",
    "decide_multi_source_status",
]
