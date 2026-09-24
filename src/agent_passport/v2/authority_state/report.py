# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Reporting a chain result, a lifecycle verdict, the monotonicity finding
and any correction records TOGETHER, without any of them rewriting another.

See ``types.py`` for the specification position. Proposed.

Python port of the TypeScript SDK's src/v2/authority-state/report.ts.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..lifecycle_state.map import map_authority_validation_to_lifecycle
from .types import AuthorityStateReport, CorrectedRevocationView, StateMarker


def authority_state_report(
    chain: Any,
    *,
    lifecycle: Any = None,
    monotonicity: str | None = None,
    high_water_mark_after: StateMarker | None = None,
    corrections: Iterable[CorrectedRevocationView] | None = None,
) -> AuthorityStateReport:
    """Assemble the report.

    A pure structural constructor. It computes no verdict, consults no record and cannot
    change one: every field is what its own module already concluded. That is the shape of the
    doctrine it encodes. A later finding is a new record that references an earlier one and
    states its own effect, so the correction sits BESIDE the chain result rather than inside
    it, and a reader can present both and their relation.
    """
    return AuthorityStateReport(
        chain=chain,
        lifecycle=lifecycle,
        monotonicity=monotonicity,
        high_water_mark_after=high_water_mark_after,
        corrections=tuple(corrections or ()),
    )


def report_authority_state(
    chain: Any,
    *,
    monotonicity: str | None = None,
    high_water_mark_after: StateMarker | None = None,
    corrections: Iterable[CorrectedRevocationView] | None = None,
    not_yet_valid_as_not_yet_effective: bool = False,
) -> AuthorityStateReport:
    """The common case, in one call: take a chain result, express it in the lifecycle
    vocabulary and attach the state findings.

    Convenience over ``map_authority_validation_to_lifecycle`` plus
    :func:`authority_state_report`, with no behaviour of its own. Read-only: the chain result
    is not mutated and is carried through unchanged.

    The property worth stating: for a chain whose root is revoked, the lifecycle verdict is
    ``invalid`` with reason ``REVOKED`` whether or not ``corrections`` carries an accepted
    withdrawal. An accepted correction does not move the verdict one step toward valid. It is
    reported, and reporting it is the whole of its effect here.
    """
    return authority_state_report(
        chain,
        lifecycle=map_authority_validation_to_lifecycle(
            chain, not_yet_valid_as_not_yet_effective=not_yet_valid_as_not_yet_effective
        ),
        monotonicity=monotonicity,
        high_water_mark_after=high_water_mark_after,
        corrections=corrections,
    )
