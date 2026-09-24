# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN authority state markers, write fencing and revocation withdrawal
(Python port).

Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
exported behaviour. Mirrors the TypeScript SDK's ``src/v2/authority-state/``, name for name,
with snake_case adapted to Python convention. Concept source:
aeoess/agent-authority-lifecycle, invariant candidates CAND-08 and CAND-02. Proposed.
"""

from .fencing import FencedAuthorityStateLog
from .marker import (
    advance_high_water_mark,
    compare_state_marker,
    is_monotonicity_outcome,
    is_state_marker_scope,
    is_unplaceable_disposition,
    same_scope,
    state_marker,
)
from .report import authority_state_report, report_authority_state
from .retained import (
    MonotonicRevocationResolver,
    create_monotonic_revocation_resolver,
    resolve_under_retained_state,
)
from .types import (
    FENCED_WRITE_REFUSAL_CODES,
    MONOTONICITY_OUTCOMES,
    REVOCATION_WITHDRAWAL_RECORD_TYPE,
    REVOCATION_WITHDRAWAL_VERSION,
    STATE_MARKER_SCOPES,
    UNPLACEABLE_DISPOSITIONS,
    WITHDRAWAL_OUTCOME_CODES,
    WITHDRAWAL_STANDINGS,
    AuthorityStateError,
    AuthorityStateReport,
    CorrectedRevocationView,
    FencedWriteOutcome,
    RetainedAuthorityState,
    RevocationWithdrawalV0,
    StateMarker,
    WithdrawalEvaluation,
    WithdrawalStandingResolver,
)
from .withdrawal import (
    corrected_revocation_view,
    evaluate_revocation_withdrawal,
    is_withdrawal_standing,
    revocation_withdrawal,
    withdrawal_signer_is_revoker,
)

__all__ = [
    "STATE_MARKER_SCOPES",
    "MONOTONICITY_OUTCOMES",
    "UNPLACEABLE_DISPOSITIONS",
    "FENCED_WRITE_REFUSAL_CODES",
    "WITHDRAWAL_STANDINGS",
    "WITHDRAWAL_OUTCOME_CODES",
    "REVOCATION_WITHDRAWAL_RECORD_TYPE",
    "REVOCATION_WITHDRAWAL_VERSION",
    "AuthorityStateError",
    "StateMarker",
    "RetainedAuthorityState",
    "FencedWriteOutcome",
    "RevocationWithdrawalV0",
    "WithdrawalStandingResolver",
    "WithdrawalEvaluation",
    "CorrectedRevocationView",
    "AuthorityStateReport",
    "state_marker",
    "same_scope",
    "compare_state_marker",
    "advance_high_water_mark",
    "is_state_marker_scope",
    "is_monotonicity_outcome",
    "is_unplaceable_disposition",
    "resolve_under_retained_state",
    "MonotonicRevocationResolver",
    "create_monotonic_revocation_resolver",
    "FencedAuthorityStateLog",
    "revocation_withdrawal",
    "withdrawal_signer_is_revoker",
    "evaluate_revocation_withdrawal",
    "corrected_revocation_view",
    "is_withdrawal_standing",
    "authority_state_report",
    "report_authority_state",
]
