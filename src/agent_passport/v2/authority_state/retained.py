# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Resolving revocation state under a retained high-water mark.

See ``types.py`` for the specification position. Concept source:
aeoess/agent-authority-lifecycle, invariant candidate CAND-08 and invariants L7 and L11.
Proposed.

WHAT THIS DOES NOT TOUCH. The chain verifier's options are unchanged. The existing
``create_authority_revocation_resolver`` is unchanged, and its one-argument shape is the
shape this module produces too: everything new closes over its own state and hands the chain
verifier back the same callable it already takes. That was the alternative to widening the
resolver signature, and widening it would have been a breaking change to an exported API for
the sake of a proposed feature.

Python port of the TypeScript SDK's src/v2/authority-state/retained.ts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..authority_revocation.verify import verify_authority_revocation
from .marker import advance_high_water_mark, compare_state_marker
from .types import RetainedAuthorityState, StateMarker


def resolve_under_retained_state(
    delegation: dict[str, Any],
    retained: RetainedAuthorityState,
    *,
    resolve_verification_key: Callable[..., Any],
) -> str:
    """What the records a verifier RETAINED say about one delegation.

    Two answers only.

    - ``revoked``, when one retained record verifies against this delegation under
      ``verify_authority_revocation``. The record is re-verified here rather than trusted: a
      record that reached the retained set by some other route cannot assert a revocation,
      which is the same discipline ``create_authority_revocation_resolver`` applies to a
      stored record.
    - ``unknown``, for everything else.

    NEVER ``active``. A retained record set is not a store: it says nothing about the
    delegations it does not mention, so its silence is ignorance and not a finding. That is
    L7 ("a revocation answer that is unavailable or stale is indeterminate. It does not
    become active"), and it is why the two-verifier split in
    :class:`~agent_passport.v2.authority_state.types.RetainedAuthorityState` has any content
    at all. A verifier that kept the records answers ``revoked``. A verifier that kept only
    the number answers ``unknown``, which the chain verifier turns into ``indeterminate``
    with ``REVOCATION_UNKNOWN``. Those are different verifiers and reporting the same thing
    for both would be the error.

    Never raises. A retained set that cannot be read is one that establishes nothing.
    """
    try:
        for record in retained.records or ():
            state = verify_authority_revocation(
                record, delegation, resolve_verification_key=resolve_verification_key
            ).state
            if state == "valid":
                return "revoked"
        return "unknown"
    except Exception:  # noqa: BLE001 - see the docstring: this never raises on purpose
        return "unknown"


@dataclass(frozen=True)
class MonotonicRevocationResolver:
    """What :func:`create_monotonic_revocation_resolver` returns."""

    #: The one-argument callable ``verify_authority_delegation_chain`` already takes. Pass it
    #: straight through as ``resolve_revocation``.
    resolve: Callable[[dict[str, Any]], str]
    #: How the presented view placed against the established mark. Reported so a caller can
    #: say WHY it answered as it did, rather than only what it answered.
    monotonicity: str
    #: The mark the verifier holds after this read. Only ever moves forward.
    high_water_mark_after: StateMarker | None


def create_monotonic_revocation_resolver(
    *,
    presented: Callable[[dict[str, Any]], str],
    presented_marker: StateMarker | None,
    retained: RetainedAuthorityState,
    resolve_verification_key: Callable[..., Any],
    on_unplaceable: str,
) -> MonotonicRevocationResolver:
    """Compose a presented state view, an established high-water mark and a retained record
    set into the resolver the chain verifier already takes.

    =============  ====================================================================
    monotonicity   what ``resolve`` consults
    =============  ====================================================================
    forward        the presented view, normally
    regressed      the retained records ONLY: revoked or unknown, never active
    unplaceable    the presented view, or nothing, per ``on_unplaceable``
    =============  ====================================================================

    The regressed row is CAND-08: a restore, a snapshot mount or a lagging replica presents
    state from before a revocation, and this refuses to read it as current rather than
    resolving the disagreement by recency of write. What it does NOT do is claim a revocation
    it cannot establish. A verifier that retained the record reports ``revoked``; one that
    retained only the mark reports ``unknown``, and unknown is not established, not false.

    ``on_unplaceable`` is REQUIRED with no default. ``read_presented`` reads the view as
    current, ``refuse`` answers ``unknown`` for every delegation, and both are defensible
    with different outcomes. Neither the proposed text nor draft-03 chooses between them, so
    this module does not choose either. The absence of a default is the point.

    Nothing here changes the chain verdict directly. The chain verifier decides that, from
    the answer this resolver gives it, exactly as it does today.

    Pure: no clock, no network, no randomness, no I/O.
    """
    monotonicity = compare_state_marker(retained.high_water_mark, presented_marker)
    high_water_mark_after = advance_high_water_mark(retained.high_water_mark, presented_marker)

    def resolve(delegation: dict[str, Any]) -> str:
        if monotonicity == "regressed":
            return resolve_under_retained_state(
                delegation, retained, resolve_verification_key=resolve_verification_key
            )
        if monotonicity == "unplaceable" and on_unplaceable == "refuse":
            return "unknown"
        try:
            return presented(delegation)
        except Exception:  # noqa: BLE001 - a resolver that raises is read as unknown
            return "unknown"

    return MonotonicRevocationResolver(
        resolve=resolve,
        monotonicity=monotonicity,
        high_water_mark_after=high_water_mark_after,
    )
