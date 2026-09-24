# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Fencing on the authority-state WRITE path.

See ``types.py`` for the specification position. Proposed.

WHY THIS IS A SEPARATE AXIS FROM THE READ PATH. A read-side high-water mark protects one
verifier that has already seen the newer state. It does nothing for a verifier that has seen
nothing, reading a published view that a stale writer republished underneath it. A partition
that resolves the wrong way rolls authority back with no restore involved, and the read path
never sees a regression because the published state simply IS the old state. So the check has
to exist where the write lands.

The rule implemented here is the one Kleppmann's "How to do distributed locking" states: the
storage server takes an active role in checking tokens and rejects any write on which the
token has gone backwards. ``OPEN-QUESTIONS.md`` names authority rollback as open and names an
append-only revocation log a restore must replay as the other candidate mechanism in the same
sentence. That one is NOT modelled here. Neither is specified.

Python port of the TypeScript SDK's src/v2/authority-state/fencing.ts.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from .marker import compare_state_marker, same_scope
from .types import FencedWriteOutcome, StateMarker

T = TypeVar("T")


class FencedAuthorityStateLog(Generic[T]):
    """An authority-state publication log with a fencing gate on every write.

    Generic in the payload on purpose: this class orders writes and stores nothing about
    authority itself. The payload is whatever the deployment publishes as a state view, a
    store handle, a snapshot identifier or a record set. The SDK has no opinion about it.

    The gate, in one line each:

    - a token BELOW the highest already accepted is refused, ``stale_fencing_token``
    - a token EQUAL to it is accepted, because equal has not gone backwards: the same holder
      is retrying, and the retry is idempotent
    - a token ABOVE it is accepted, and so is a token the log has never seen before, as long
      as it does not go backwards. The gate fences state that is behind, not state that
      merely differs
    - a token counted in a DIFFERENT SCOPE from the log's is refused,
      ``fencing_scope_mismatch``, and an absent or malformed token is refused
      ``fencing_token_unreadable``. Two markers from different scopes order nothing, and a
      write path that cannot order a token is not fenced. Neither refusal is in any source;
      both are this module's choice, and they are kept apart because an unreadable token is a
      different finding from a backwards one

    A refused write changes nothing: not the published payload, not the highest token. That is
    the property the whole class exists for, and a caller reads ``accepted`` to learn which of
    the two happened rather than comparing payloads.

    NOT DURABLE, NOT CONCURRENT, NOT A LOCK SERVICE. This holds one token and one payload in
    this process's memory. It acquires no lock, contacts no lock service, and its
    check-then-set is not atomic across threads. The same warning the in-memory revocation
    store carries applies here for the same reason.
    """

    def __init__(self) -> None:
        self._highest: StateMarker | None = None
        self._payload: Any = None
        self._written = False

    def highest_token(self) -> StateMarker | None:
        """The highest token accepted so far, or ``None`` when nothing has been published."""
        return self._highest

    def published(self) -> Any:
        """What is published now. ``None`` when no write has landed, which a caller must tell
        apart from a write that landed carrying ``None``; :meth:`has_published` is how."""
        return self._payload

    def has_published(self) -> bool:
        return self._written

    def write(self, token: StateMarker | None, payload: T) -> FencedWriteOutcome:
        """Submit a write. See the class docstring for the four outcomes.

        Never raises for a malformed token: an unreadable token is one that cannot be shown to
        have moved forward, so it is refused.
        """
        # Read the token on its own first. An unreadable token is a different finding from a
        # stale one, and collapsing them would report a backwards move that never happened.
        if compare_state_marker(token, token) != "forward":
            return FencedWriteOutcome(
                accepted=False, code="fencing_token_unreadable", published=self._highest
            )
        assert token is not None  # narrowed by the readability check above
        if self._highest is not None:
            if not same_scope(self._highest, token):
                return FencedWriteOutcome(
                    accepted=False, code="fencing_scope_mismatch", published=self._highest
                )
            if compare_state_marker(self._highest, token) != "forward":
                return FencedWriteOutcome(
                    accepted=False, code="stale_fencing_token", published=self._highest
                )
        self._highest = token
        self._payload = payload
        self._written = True
        return FencedWriteOutcome(accepted=True, published=token, payload=payload)
