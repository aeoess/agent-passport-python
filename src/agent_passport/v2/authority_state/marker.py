# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The marker constructor and the comparison, and nothing else.

See ``types.py`` for the specification position. Concept source:
aeoess/agent-authority-lifecycle, invariant candidate CAND-08. Proposed.

Python port of the TypeScript SDK's src/v2/authority-state/marker.ts.
"""

from __future__ import annotations

import re

from .types import (
    MONOTONICITY_OUTCOMES,
    STATE_MARKER_SCOPES,
    UNPLACEABLE_DISPOSITIONS,
    AuthorityStateError,
    StateMarker,
)

#: Canonical unsigned decimal integer. Same pattern the authority vector's spend quantities
#: use: no sign, no leading zero, no separators.
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")


def is_state_marker_scope(value: object) -> bool:
    return isinstance(value, str) and value in STATE_MARKER_SCOPES


def is_monotonicity_outcome(value: object) -> bool:
    return isinstance(value, str) and value in MONOTONICITY_OUTCOMES


def is_unplaceable_disposition(value: object) -> bool:
    return isinstance(value, str) and value in UNPLACEABLE_DISPOSITIONS


def state_marker(value: str, scope: str, scope_ref: str | None = None) -> StateMarker:
    """Build a :class:`StateMarker`, enforcing its shape rules.

    1. ``value`` is a canonical unsigned decimal integer, as a string. An int would admit a
       negative and would not round-trip at any width through JSON; a float would lose
       exactness past 2**53 - 1.
    2. ``scope`` is one of the four. There is no fifth and there is no default: which thing a
       generation is counted within is the choice the proposed text does not make, so it has
       to be stated rather than assumed.
    3. ``scope_ref`` is present and non-empty exactly when ``scope`` is not ``global``. A
       per-delegation marker that does not say which delegation cannot be compared against
       anything.

    Proposed. Concept source: aeoess/agent-authority-lifecycle, ``Authority epoch``.
    """
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        raise AuthorityStateError(
            "MARKER_VALUE_NONCANONICAL",
            "value must be a canonical unsigned decimal integer string",
        )
    if not is_state_marker_scope(scope):
        raise AuthorityStateError(
            "MARKER_SCOPE_UNKNOWN", f"scope must be one of {', '.join(STATE_MARKER_SCOPES)}"
        )
    if scope == "global":
        if scope_ref is not None:
            raise AuthorityStateError(
                "MARKER_SCOPE_REF_NOT_ALLOWED", "a global marker names no scope_ref"
            )
        return StateMarker(value=value, scope=scope, scope_ref=None)
    if not isinstance(scope_ref, str) or scope_ref == "":
        raise AuthorityStateError(
            "MARKER_SCOPE_REF_REQUIRED",
            f"a {scope} marker must name the scope_ref it is counted within",
        )
    return StateMarker(value=value, scope=scope, scope_ref=scope_ref)


def _readable(marker: object) -> bool:
    return (
        isinstance(marker, StateMarker)
        and isinstance(marker.value, str)
        and _DECIMAL.fullmatch(marker.value) is not None
    )


def same_scope(a: StateMarker, b: StateMarker) -> bool:
    """Whether two markers are counted in the same thing and can therefore be ordered."""
    return a.scope == b.scope and a.scope_ref == b.scope_ref


def compare_state_marker(
    established: StateMarker | None, presented: StateMarker | None
) -> str:
    """Place a presented marker against what a verifier has established.

    =============  ==================  =============
    established    presented           outcome
    =============  ==================  =============
    ``None``       any                 unplaceable
    any            ``None``            unplaceable
    any            a different scope   unplaceable
    m              >= m                forward
    m              < m                 regressed
    =============  ==================  =============

    Equal is ``forward``, not a third thing: a view that has not moved has not gone backwards.

    ``unplaceable`` is where the honesty of the whole module sits. It is returned for a first
    read and for a cross-scope comparison, it is NOT a verdict, and nothing downstream turns
    it into one on its own. The proposed text gives a verifier with no prior observation
    nothing to compare against and does not say whether such a read is trusted or refused.

    Comparison is integer, never lexical: "10" is after "9", and Python ints are arbitrary
    precision so a value past 2**53 - 1 is exact.

    Never raises for a malformed marker. A marker this function cannot read is one it cannot
    place, which is ``unplaceable``, and raising on the read path of a state comparison would
    turn a data problem into a crash in a verifier.
    """
    if not _readable(established) or not _readable(presented):
        return "unplaceable"
    assert established is not None and presented is not None  # narrowed by _readable
    if not same_scope(established, presented):
        return "unplaceable"
    return "forward" if int(presented.value) >= int(established.value) else "regressed"


def advance_high_water_mark(
    established: StateMarker | None, presented: StateMarker | None
) -> StateMarker | None:
    """The high-water mark a verifier holds after reading a presented view.

    It only ever moves forward. A regressed view does not lower it, an unplaceable view does
    not replace it, and a verifier that had none adopts the presented one. This is the
    "monotonicity against what the verifier has established" limb of CAND-08, which is weaker
    than a rule against global truth and is the honest strength available: a verifier that
    has never seen the newer state cannot detect a regression and is not at fault.
    """
    if presented is None:
        return established
    if established is None:
        return presented
    return presented if compare_state_marker(established, presented) == "forward" else established
