# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The verifying mutation path: the one supported way a revocation enters a store.

Python port of the TypeScript SDK's src/v2/authority-revocation/record.ts.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass

from .schema import validate_authority_revocation_shape
from .types import AuthorityRevocationVerificationResult
from .verify import verify_authority_revocation


@dataclass(frozen=True)
class AuthorityRevocationRecordResult:
    """What record_authority_revocation() answers.

    - ``recorded`` True — the candidate verified against its target. ``stored``
      is what the store holds for that delegation now, and ``inserted`` says
      whether this call is the one that wrote it. ``inserted`` False with
      ``recorded`` True is the ordinary first-wins case: a valid revocation
      arrived second and the earlier record stands.
    - ``recorded`` False — the candidate did not verify. ``stored`` is None,
      always, including when the store already holds a valid record for the same
      delegation. A rejected request is never handed somebody else's record as
      though it were its own result; ``verification`` carries the failures that
      rejected it, and ``inserted`` is False.

    ``verification`` is the candidate's own result in both cases, never a result
    borrowed from a record already held. The TypeScript SDK expresses the same
    contract as a union discriminated on ``recorded``; Python states it as one
    frozen record whose ``stored`` is None in the refused case.
    """

    recorded: bool
    inserted: bool
    stored: dict | None
    verification: AuthorityRevocationVerificationResult


def record_authority_revocation(
    store,
    delegation,
    candidate,
    *,
    resolve_verification_key,
) -> AuthorityRevocationRecordResult:
    """Verify one candidate revocation against the delegation it names and, only
    then, offer it to ``store`` for the delegation's first-wins slot.

    The defect this closes: a store's write primitive takes a record and a
    record alone, and a store can verify nothing, because verification needs the
    target delegation and a key resolver and a store holds neither. A write path
    reachable with an arbitrary object therefore lets any object take the
    first-wins slot for a delegation, and because that slot is irreversible
    (INV-5), the delegation can never afterwards record the valid revocation
    that would have revoked it. The resolver's own re-verification keeps such a
    record from ever reading as "revoked", so the damage is not a false
    revocation; it is a permanently blocked real one. Verification belongs
    before the write, which is here.

    Order of operations:

     1. judge the candidate's shape, which is what establishes that it is plain
        JSON data of exact types
     2. copy it, and verify the copy against ``delegation``
     3. on anything but "valid", return ``recorded`` False with that
        verification result and no record, having touched the store not at all
     4. on "valid", hand the COPY to store.insert_verified_revocation() and
        report what the store says it now holds

    Steps 2 and 4 use the same copy, so the bytes the store keeps are exactly
    the bytes that were verified. The copy is what closes the one window Python
    leaves open: ``resolve_verification_key`` is caller code that runs during
    verification, and a resolver holding a reference to the caller's dict could
    otherwise write to it between the verifier's reads and the store's write.
    The copy is taken only after the shape check has passed, because copying a
    value of unknown type can run that value's own code; a candidate that fails
    the shape check is verified as it came in, is refused, and never reaches the
    store. This is where the TypeScript SDK calls snapshotPlainData() instead,
    for the same reason and with the same effect. See schema.py for why nothing
    else in this port needs a snapshot.

    Does not raise on a bad candidate: an unusable candidate, an unusable target
    and an unusable resolver are all verification results, and
    verify_authority_revocation() does not raise. An exception raised by
    ``store`` itself is not caught. A store that cannot complete a write has not
    produced a verification outcome, and reporting its failure as one would be a
    lie about the record rather than about the store.
    """
    if validate_authority_revocation_shape(candidate):
        # Refused on shape alone. verify_authority_revocation() re-derives the
        # same failures and is called so the reported result is the verifier's,
        # not this function's reading of it.
        verification = verify_authority_revocation(
            candidate, delegation, resolve_verification_key=resolve_verification_key
        )
        return AuthorityRevocationRecordResult(
            recorded=False, inserted=False, stored=None, verification=verification
        )

    snapshot = copy.deepcopy(candidate)
    verification = verify_authority_revocation(
        snapshot, delegation, resolve_verification_key=resolve_verification_key
    )
    if not verification.valid:
        return AuthorityRevocationRecordResult(
            recorded=False, inserted=False, stored=None, verification=verification
        )
    insertion = store.insert_verified_revocation(snapshot)
    return AuthorityRevocationRecordResult(
        recorded=True,
        inserted=insertion.inserted,
        stored=insertion.stored,
        verification=verification,
    )
