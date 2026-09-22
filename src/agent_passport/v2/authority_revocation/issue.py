# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Minting one draft-03 section 3.5.1 direct revocation.

Python port of the TypeScript SDK's src/v2/authority-revocation/issue.ts.
"""

from __future__ import annotations

import copy

from ..authority_delegation.canonical import (
    authority_delegation_body,
    compute_authority_delegation_id,
)
from ..authority_delegation.schema import (
    is_canonical_timestamp,
    validate_authority_delegation_shape,
)
from .canonical import (
    compute_authority_revocation_cascade_transaction_id_for_write,
    compute_authority_revocation_id_for_write,
    sign_authority_revocation,
)
from .schema import validate_authority_revocation_shape
from .types import (
    AUTHORITY_REVOCATION_RECORD_TYPE,
    AUTHORITY_REVOCATION_VERSION,
    AuthorityRevocationError,
    AuthorityRevocationFailure,
)

_UNSET = object()


def issue_authority_revocation(
    delegation: dict,
    *,
    now: str,
    revoker: str,
    verification_method: str,
    reason_code: str,
    nonce: str,
    detail=_UNSET,
    private_key: str,
) -> dict:
    """Mint a draft-03 section 3.5.1 direct revocation for one AuthorityDelegationV1.

    Draft section 3.5 line 634 states the only authorization rule this function
    applies: "Any delegation MAY be revoked by its issuer." The exact comparison
    is ``revoker == delegation["issuer"]``, where ``delegation`` is the target
    record passed in by the caller and ``issuer`` is its own member. The record
    being minted is never consulted for its own authorization: a field a
    would-be revoker writes inside its own record cannot make that revoker the
    issuer of somebody else's delegation.

    The target's ``delegation_id`` is recomputed from its body before that
    comparison. A ``delegation_id`` sits outside the delegation's own identifier
    preimage, so a record whose claimed identifier does not match its body has
    an unauthenticated ``issuer`` too, and refusing there is what keeps the
    revoker check meaningful.

    What this function does NOT establish: that the holder of ``private_key`` is
    in fact ``revoker``, or that ``verification_method`` is one of that party's
    keys. An identifier-to-key binding is a resolver's answer, not a local one,
    and no string shape imposed on ``verification_method`` here could stand in
    for it. verify_authority_revocation() makes that check, resolving the method
    under the TARGET delegation's ``issuer`` at ``revoked_at``. Issuance can only
    refuse to mint a record that is already unverifiable; it cannot promise the
    record will verify.

    Nothing about a cascade over descendants is emitted here. This function
    produces one record about one delegation. Enforcement against descendants
    comes from chain verification, which rejects any chain containing a revoked
    ancestor.

    ``now`` is the canonical UTC-millisecond revocation time, supplied by the
    caller: issuance never reads a clock, which is what makes the identifier and
    the signature reproducible in a test and in a conformance vector. It lands
    in the record's signed ``revoked_at``. ``detail`` is OPTIONAL and is omitted
    from the record entirely when not supplied; it is never written as null,
    because JCS has no canonical form for an absent value.

    Every input is a keyword argument, where the TypeScript SDK takes one
    options object. The TypeScript function reads each member of that object
    exactly once so a getter cannot answer the check and the hash differently;
    Python binds its arguments once at the call, which is the same guarantee by
    construction.

    Raises :class:`AuthorityRevocationError` on refusal.
    """
    if not is_canonical_timestamp(now):
        raise AuthorityRevocationError(
            "NONCANONICAL_VALUE",
            (
                AuthorityRevocationFailure(
                    code="NONCANONICAL_VALUE",
                    message="authority revocation now must be a canonical UTC-millisecond timestamp",
                ),
            ),
        )

    target_failures = validate_authority_delegation_shape(delegation)
    if target_failures:
        raise AuthorityRevocationError(
            target_failures[0].code,
            (
                AuthorityRevocationFailure(
                    code=target_failures[0].code,
                    message=f"authority revocation target delegation invalid: {target_failures[0].message}",
                ),
            ),
        )

    # The target has passed the shape check, so it is plain JSON data of exact
    # types and copying it runs no caller code. Everything below reads this
    # copy, so a caller writing to its own dict after this point cannot change
    # which delegation_id and issuer the record is built against.
    target = copy.deepcopy(delegation)

    if compute_authority_delegation_id(authority_delegation_body(target)) != target["delegation_id"]:
        raise AuthorityRevocationError(
            "TARGET_ID_MISMATCH",
            (
                AuthorityRevocationFailure(
                    code="TARGET_ID_MISMATCH",
                    message="authority revocation target content address does not match its body",
                ),
            ),
        )

    # Draft section 3.5: a delegation may be revoked by its issuer. The compared
    # fields are the caller's claimed revoker and the TARGET delegation's own
    # `issuer` member.
    if type(revoker) is not str or revoker != target["issuer"]:
        raise AuthorityRevocationError(
            "REVOKER_NOT_ISSUER",
            (
                AuthorityRevocationFailure(
                    code="REVOKER_NOT_ISSUER",
                    message="authority revocation revoker is not the target delegation issuer",
                ),
            ),
        )

    origin: dict = {
        "record_type": AUTHORITY_REVOCATION_RECORD_TYPE,
        "version": AUTHORITY_REVOCATION_VERSION,
        "delegation_id": target["delegation_id"],
        "revoker": revoker,
        "verification_method": verification_method,
        "revoked_at": now,
        "reason_code": reason_code,
    }
    if detail is not _UNSET:
        origin["detail"] = detail
    origin["nonce"] = nonce

    body = dict(origin)
    body["cascade_transaction_id"] = compute_authority_revocation_cascade_transaction_id_for_write(origin)

    # Shape is judged on the finished record, so the probe carries placeholder
    # values in exactly the two members that are not derivable yet. Both are
    # replaced below.
    probe = dict(body)
    probe["revocation_id"] = "sha256:" + "0" * 64
    probe["signature"] = "0" * 128
    failures = validate_authority_revocation_shape(probe)
    if failures:
        raise AuthorityRevocationError(
            failures[0].code,
            (
                AuthorityRevocationFailure(
                    code=failures[0].code,
                    message=f"authority revocation invalid: {failures[0].message}",
                ),
            ),
        )

    unsigned = dict(body)
    unsigned["revocation_id"] = compute_authority_revocation_id_for_write(body)
    signed = dict(unsigned)
    signed["signature"] = sign_authority_revocation(unsigned, private_key)
    return signed
