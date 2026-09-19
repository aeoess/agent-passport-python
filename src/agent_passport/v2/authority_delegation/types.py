# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Shared constants, result types and the module exception.

Python port of the TypeScript SDK's src/v2/authority-delegation/types.ts.
"""

from __future__ import annotations

from dataclasses import dataclass

AUTHORITY_DELEGATION_RECORD_TYPE = "aps:authority-delegation:v1"
AUTHORITY_DELEGATION_VERSION = "1.0"

SCOPE_PROFILE_V1 = "aps-hierarchical-v1"
REPUTATION_PROFILE_V1 = "aps-score-0-100-v1"
VALUES_PROFILE_V1 = "aps-values-identifiers-v1"
REVERSIBILITY_PROFILE_V1 = "aps-tci-v1"


@dataclass(frozen=True)
class AuthorityFailure:
    """One reason a delegation, chain or issuance request was rejected.

    ``index`` names the failing member of a chain (``None`` for a failure that
    is not about one particular member). ``facet`` names which of the seven
    authority facets an attenuation failure is about.
    """

    code: str
    message: str
    index: int | None = None
    facet: str | None = None


@dataclass(frozen=True)
class AuthorityValidationResult:
    """Outcome of verifying a delegation or a delegation chain."""

    state: str
    failures: tuple[AuthorityFailure, ...]

    @property
    def valid(self) -> bool:
        return self.state == "valid"


@dataclass(frozen=True)
class BudgetOperationResult:
    """Outcome of one operation against an :class:`InMemoryAuthorityBudgetLedger`."""

    ok: bool
    code: str
    state: str | None = None


class AuthorityDelegationError(ValueError):
    """Raised for every rejection this module produces (parsing and issuance).

    ``code`` is the single code callers should branch on; ``failures`` is the
    full, possibly empty, tuple of :class:`AuthorityFailure` behind it.
    """

    def __init__(self, code: str, failures: tuple[AuthorityFailure, ...] = ()) -> None:
        failures = tuple(failures)
        if failures:
            detail = "; ".join(f"{item.code}: {item.message}" for item in failures)
        else:
            detail = code
        super().__init__(detail)
        self.code = code
        self.failures = failures
