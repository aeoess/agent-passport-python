# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The fail-closed store-to-chain-verifier adapter.

Python port of the TypeScript SDK's src/v2/authority-revocation/resolver.ts.
"""

from __future__ import annotations

from ..authority_delegation.canonical import (
    authority_delegation_body,
    compute_authority_delegation_id,
)
from .verify import verify_authority_revocation


def create_authority_revocation_resolver(store, *, resolve_verification_key):
    """Adapt a revocation store to the ``resolve_revocation`` callable that
    verify_authority_delegation_chain() and issue_sub_authority_delegation()
    already take.

    The three answers, and what each one costs to earn:

    - "revoked" only when the store holds a record for this delegation AND that
      record verifies against this delegation under
      verify_authority_revocation(). A stored record that does not verify yields
      "unknown", not "revoked" and not "active": the store has an opinion this
      resolver cannot confirm, which is exactly indeterminate.
    - "active" only when the store says it tracks this delegation and holds no
      revocation for it. Absence from a store is never "active" on its own. A
      store that has never heard of a delegation has not said the delegation is
      unrevoked.
    - "unknown" for everything else, including a store that raises and a
      delegation whose ``delegation_id`` does not recompute from its own body.

    The chain verifier treats "unknown" as indeterminate (REVOCATION_UNKNOWN)
    and issue_sub_authority_delegation() refuses to mint under anything but
    "active", so the fail-closed direction is already theirs; this resolver only
    has to avoid manufacturing an "active" it cannot support.

    Never raises. A resolver that raised would be caught by both callers and
    read as "unknown" anyway, so it returns "unknown" in the open rather than
    through an except clause in somebody else's code.
    """

    def resolve(delegation) -> str:
        try:
            # A claimed delegation_id sits outside the delegation's own
            # identifier preimage. Looking a revocation up by an unauthenticated
            # label would let a caller ask about one delegation while presenting
            # another.
            delegation_id = compute_authority_delegation_id(authority_delegation_body(delegation))
            if delegation_id != delegation["delegation_id"]:
                return "unknown"

            record = store.get(delegation_id)
            if record is not None:
                state = verify_authority_revocation(
                    record, delegation, resolve_verification_key=resolve_verification_key
                ).state
                return "revoked" if state == "valid" else "unknown"
            return "active" if store.tracks(delegation_id) else "unknown"
        except Exception:
            return "unknown"

    return resolve
