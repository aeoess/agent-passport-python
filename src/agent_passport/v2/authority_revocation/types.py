# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Shared constants, result types, the store protocol and the module exception.

Python port of the TypeScript SDK's src/v2/authority-revocation/types.ts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

AUTHORITY_REVOCATION_RECORD_TYPE = "aps:authority-revocation:v1"
AUTHORITY_REVOCATION_VERSION = "1.0"

# Draft section 2.5 resolution outcomes, mapped to this module's failure codes.
# Identical in meaning to authority_delegation.types.KEY_RESOLUTION_OUTCOME_CODES
# and kept as its own table so the revocation vocabulary stays readable beside
# the codes below rather than being inherited from a neighbouring record type.
KEY_RESOLUTION_OUTCOME_CODES: dict[str, str] = {
    "unsupported_scheme": "KEY_SCHEME_UNSUPPORTED",
    "not_found": "KEY_NOT_FOUND",
    "ambiguous": "KEY_AMBIGUOUS",
    "unreachable": "KEY_UNREACHABLE",
    "malformed": "KEY_MATERIAL_MALFORMED",
}

# Every code verify.py and issue.py can report, the TypeScript SDK's
# AuthorityRevocationFailureCode union written as data. The strings are the wire
# vocabulary and are shared across both SDKs; a record that fails here must fail
# under the same name there.
AUTHORITY_REVOCATION_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "SCHEMA_INVALID",
        "UNSUPPORTED_RECORD_TYPE",
        "UNSUPPORTED_VERSION",
        "NONCANONICAL_VALUE",
        # revocation_id does not recompute from the record's own body.
        "ID_MISMATCH",
        # cascade_transaction_id does not recompute from the record's own body.
        "CASCADE_TRANSACTION_MISMATCH",
        # The delegation handed in is not the one this record names.
        "TARGET_MISMATCH",
        # The delegation handed in does not recompute its own delegation_id, so
        # its `issuer` is not an authenticated field and the revoker check
        # cannot be made against it.
        "TARGET_ID_MISMATCH",
        # `revoker` is not the target delegation's `issuer`.
        "REVOKER_NOT_ISSUER",
        "KEY_RESOLUTION_FAILED",
        "KEY_SCHEME_UNSUPPORTED",
        "KEY_NOT_FOUND",
        "KEY_AMBIGUOUS",
        "KEY_UNREACHABLE",
        "KEY_MATERIAL_MALFORMED",
        "SIGNATURE_INVALID",
    }
)


@dataclass(frozen=True)
class AuthorityRevocationFailure:
    """One reason a revocation was rejected.

    Deliberately not authority_delegation.AuthorityFailure: that type carries
    ``index`` and ``facet`` members, and neither has a meaning for a record that
    is judged alone against one target rather than as a member of a chain. The
    TypeScript SDK keeps the two failure types separate for the same reason.
    """

    code: str
    message: str


@dataclass(frozen=True)
class AuthorityRevocationVerificationResult:
    """Outcome of verifying one revocation against the delegation it names.

    ``state`` is one of "valid", "invalid", "indeterminate" or "unsupported",
    the same four the TypeScript SDK returns. ``valid`` is a property rather
    than a stored member so it can never disagree with ``state``.
    """

    state: str
    failures: tuple[AuthorityRevocationFailure, ...]

    @property
    def valid(self) -> bool:
        return self.state == "valid"


@dataclass(frozen=True)
class AuthorityRevocationInsertion:
    """What a store's first-write primitive reports.

    ``inserted`` is the only way a caller learns whether this call was the write
    that took the first-wins slot. ``stored`` is the record passed in when
    ``inserted`` is True and the record already held when it is False, so a
    caller that must tell them apart reads ``inserted`` rather than comparing
    bytes.
    """

    inserted: bool
    stored: dict


class AuthorityRevocationStore(Protocol):
    """The read and write boundary a revocation resolver needs.

    Nothing in this protocol promises durability. An implementation backed by
    process memory, a file, or a replicated database all satisfy it; only the
    implementation says which. Draft section 3.5.1 makes the cascade-completion
    record depend on the last descendant's revocation being PERSISTENT, and no
    method here establishes persistence, which is one reason no completion
    record is issued in this module.

    This protocol carries no method that takes an arbitrary, unverified record.
    ``insert_verified_revocation`` is a persistence primitive, not an entry
    point: the only supported way to move a candidate revocation into a store is
    :func:`~agent_passport.v2.authority_revocation.record.record_authority_revocation`,
    which verifies first and calls the primitive only on a "valid" result.
    """

    def tracks(self, delegation_id: str) -> bool:
        """Whether ``delegation_id`` is inside this store's view at all.

        This is what keeps absence from meaning "active". A store that has never
        heard of a delegation cannot say the delegation is unrevoked; it can
        only say it does not know. A store whose view covers the delegation and
        holds no revocation for it can.
        """

    def get(self, delegation_id: str) -> dict | None:
        """The revocation recorded for ``delegation_id``, or None when none is."""

    def insert_verified_revocation(self, revocation: dict) -> AuthorityRevocationInsertion:
        """Persistence primitive. Write ``revocation`` only when this store holds
        no record for ``revocation["delegation_id"]``, and report what it holds
        for that target now.

        ACCEPTS ONLY A RECORD ALREADY VERIFIED AGAINST ITS TARGET DELEGATION by
        record_authority_revocation(). It performs no verification, and none is
        possible here: verification needs the target delegation and a key
        resolver, neither of which a store has. An implementation is a write
        path, not a trust boundary, and a caller that reaches past
        record_authority_revocation() to this method is the one asserting the
        record was verified.

        First verified revocation for a delegation wins. Revocation is
        irreversible (INV-5), so a later call naming a delegation that already
        has a record does not replace it: ``inserted`` is False and ``stored``
        is the record already held, unchanged. The check for an existing record
        and the write MUST be one indivisible operation, so that two callers
        racing on the same delegation cannot both observe ``inserted`` True.

        For a DURABLE implementation that means the first write MUST be an
        atomic conditional insert keyed by ``delegation_id`` — an insert the
        storage engine itself makes succeed for exactly one of two concurrent
        callers, such as a unique-constrained primary key, a compare-and-set, or
        an insert-if-absent. Reading the existing record and then writing does
        NOT satisfy this contract: under concurrency two callers can both read
        an empty slot before either writes, both report ``inserted`` True, and
        the second write displaces the first, which makes the recorded
        revocation time, reason and revoker mutable after the fact and breaks
        first-wins and INV-5.

        Brings its target into the tracked view: recording a revocation for a
        delegation is a statement that this store has an opinion about that
        delegation.
        """


class AuthorityRevocationError(ValueError):
    """Raised for every rejection issuance produces.

    ``code`` is the single code callers should branch on; ``failures`` is the
    full, possibly empty, tuple of :class:`AuthorityRevocationFailure` behind
    it. The TypeScript SDK throws a plain Error whose message names the code in
    parentheses; a coded exception is the Python port's equivalent and follows
    authority_delegation.AuthorityDelegationError. The code is kept inside the
    message too, so a caller that only reads ``str(error)`` sees the same text
    the TypeScript SDK writes.
    """

    def __init__(self, code: str, failures: tuple[AuthorityRevocationFailure, ...] = ()) -> None:
        failures = tuple(failures)
        if failures:
            detail = "; ".join(f"{item.code}: {item.message}" for item in failures)
        else:
            detail = code
        super().__init__(f"{detail} ({code})")
        self.code = code
        self.failures = failures
