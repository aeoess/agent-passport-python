# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The in-memory reference revocation store.

Python port of the TypeScript SDK's src/v2/authority-revocation/store.ts.
"""

from __future__ import annotations

from .types import AuthorityRevocationInsertion


class InMemoryAuthorityRevocationStore:
    """Reference AuthorityRevocationStore holding every record in this process.

    For tests, fixtures and local reference use. It is not a persistence layer
    and does not become one: the records live in a dict and a set and are gone
    when the process exits, when the object is garbage collected, or when a
    second process asks the same question. Draft section 3.5.1 makes cascade
    completion depend on a descendant's revocation being PERSISTENT, and nothing
    here can establish that, which is why this module emits no completion
    record.

    Behavior this class fixes, none of it settled by draft text:

    - First verified revocation for a delegation wins. INV-5 makes revocation
      irreversible, and a store that let a second record displace the first
      would make the recorded revocation time, reason and revoker mutable after
      the fact.
    - insert_verified_revocation() for a delegation that already has a record
      reports ``inserted`` False and returns the record already held, and the
      caller's record is discarded. A repeated request is therefore idempotent
      in what the store reports, not in the bytes the caller minted: two calls
      with different nonces mint two different valid records, and the store
      keeps the first.
    - insert_verified_revocation() brings its target into the tracked view.
      Recording a revocation for a delegation is a statement that this store has
      an opinion about that delegation.

    insert_verified_revocation() is a persistence primitive and not an entry
    point. It does not verify, and a store cannot: verification needs the target
    delegation and a key resolver, neither of which is here.
    record_authority_revocation() in record.py is the one supported way in; it
    verifies against the target and calls this method only on a "valid" result.
    Nothing about that split relaxes the resolver, which still verifies on the
    way out, so a record that reached this store by some other route still
    cannot produce a "revoked" answer.
    """

    def __init__(self) -> None:
        self._tracked: set[str] = set()
        self._records: dict[str, dict] = {}

    def track(self, delegation_id: str) -> None:
        """Bring ``delegation_id`` into this store's view with no revocation
        recorded for it.

        Not part of the AuthorityRevocationStore protocol: how a store learns
        which delegations it covers is an implementation's own business, and a
        database-backed store would answer tracks() from its own rows rather
        than from a method like this one.
        """
        self._tracked.add(delegation_id)

    def tracks(self, delegation_id: str) -> bool:
        return delegation_id in self._tracked

    def get(self, delegation_id: str) -> dict | None:
        return self._records.get(delegation_id)

    def insert_verified_revocation(self, revocation: dict) -> AuthorityRevocationInsertion:
        """See AuthorityRevocationStore.insert_verified_revocation for the
        contract, including that ``revocation`` must already have been verified
        against its target delegation by record_authority_revocation().

        The read of the existing record and the write are one statement sequence
        with no await and no callback between them, and CPython evaluates them
        under the GIL without a bytecode boundary another thread can use to
        interleave a second insert for the same key, so no second caller can
        observe ``inserted`` True for a delegation whose slot is already taken.
        That is a property of this runtime and this container, not a pattern a
        durable store may copy; see the protocol docstring for what a durable
        implementation owes instead.
        """
        existing = self._records.get(revocation["delegation_id"])
        if existing is not None:
            return AuthorityRevocationInsertion(inserted=False, stored=existing)
        self._records[revocation["delegation_id"]] = revocation
        self._tracked.add(revocation["delegation_id"])
        return AuthorityRevocationInsertion(inserted=True, stored=revocation)
