# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Issuance of a root delegation and of a child under an immediate parent.

Python port of the TypeScript SDK's src/v2/authority-delegation/issue.ts, with
one deliberate difference from it: nonce generation (see _with_nonce below).
Both SDKs' child issuers verify the parent before signing (see
issue_sub_authority_delegation).

issue_authority_delegation issues roots only (draft section 3.1 line 428:
parent_delegation_id is null only for a root selected by verifier trust
policy). A child is minted only through issue_sub_authority_delegation,
which performs the section 3.6 (lines 695-704) parent checks before signing
it; issue_authority_delegation refuses a body whose parent_delegation_id is
not null with PARENT_MISMATCH.

_assert_bare_body below rejects a body that is not a dict, before either
issuing function does anything else with it; that check is a property of
this Python implementation, not a claim about what the TypeScript SDK does
for a non-object body. It also rejects a body that already carries an own
"delegation_id" or "signature" member, of any value. Draft section 3.1
(lines 484-490) computes delegation_id and signature from a body without
those two members, so such a body would yield a record whose delegation_id
does not recompute from itself; section 3.6 (lines 695-704) enforces
signature integrity at issuance and says an issuer does not leave an
invalidity for a later verifier to discover.
Both this Python port and the TypeScript SDK's issueAuthorityDelegation and
issueSubAuthorityDelegation refuse such a body with SCHEMA_INVALID before
issuing anything.
"""

from __future__ import annotations

import secrets

from .canonical import (
    authority_delegation_body,
    compute_authority_delegation_id,
    compute_authority_delegation_id_for_write,
    sign_authority_delegation,
    verify_authority_delegation_signature,
)
from .compare import compare_authority
from .schema import is_canonical_timestamp, validate_authority_delegation_shape
from .types import AuthorityDelegationError, AuthorityFailure


def _assert_bare_body(body) -> None:
    """Reject a body that is not a dict, or that already carries an id or a signature.

    See the module docstring: the not-a-dict check is a property of this
    Python implementation only. The delegation_id/signature check matches
    the TypeScript SDK's issueAuthorityDelegation and
    issueSubAuthorityDelegation, which perform the same check (draft section
    3.1 lines 484-490; section 3.6 lines 695-704).
    """
    if type(body) is not dict:
        raise AuthorityDelegationError(
            "SCHEMA_INVALID",
            (AuthorityFailure(code="SCHEMA_INVALID", message="delegation body must be an object"),),
        )
    if "delegation_id" in body or "signature" in body:
        raise AuthorityDelegationError(
            "SCHEMA_INVALID",
            (AuthorityFailure(
                code="SCHEMA_INVALID",
                message="delegation body must carry neither delegation_id nor signature",
            ),),
        )


def _with_nonce(body: dict) -> dict:
    """Copy body and fill in a nonce if it does not already carry one.

    Draft section 3.1 asks only for 16 random bytes; it does not forbid the
    caller supplying its own. This is a deliberate difference from the
    TypeScript SDK, whose issueAuthorityDelegation and
    issueSubAuthorityDelegation both require a complete body, nonce included.
    Here a body without "nonce" gets one generated as 32 lowercase hex
    characters (secrets.token_hex(16)); a body that already carries "nonce"
    keeps it unchanged, which lets test vectors pin an exact byte value. The
    caller's dict is never mutated: this always returns a new copy.
    """
    copied = dict(body)
    if "nonce" not in copied:
        copied["nonce"] = secrets.token_hex(16)
    return copied


def _assert_body(body: dict) -> None:
    probe = {**body, "delegation_id": "sha256:" + "0" * 64, "signature": "0" * 128}
    failures = validate_authority_delegation_shape(probe)
    if failures:
        raise AuthorityDelegationError(failures[0].code, tuple(failures))


def _finish_issuance(body: dict, private_key: str) -> dict:
    """Compute the delegation_id and sign, for a body both issuers have already checked.

    Module-private helper shared by issue_authority_delegation and
    issue_sub_authority_delegation, so the id computation and signing happen
    in exactly one place. Neither issuer's own checks live here; each calls
    this only after it has completed them.
    """
    delegation_id = compute_authority_delegation_id_for_write(body)
    unsigned = {**body, "delegation_id": delegation_id}
    signature = sign_authority_delegation(unsigned, private_key)
    return {**unsigned, "signature": signature}


def issue_authority_delegation(body: dict, private_key: str) -> dict:
    """Create a deterministic v1 root record from explicit body fields and an Ed25519 key.

    Issues roots only. After the bare-body check and the body-shape check,
    and before computing anything, this refuses a body whose
    parent_delegation_id is not null with PARENT_MISMATCH: draft section 3.1
    line 428 says parent_delegation_id is null only for a root selected by
    verifier trust policy. A body with a malformed parent_delegation_id
    still fails the shape check first, with its existing SCHEMA_INVALID
    code. A child is minted only through issue_sub_authority_delegation,
    which performs the section 3.6 (lines 695-704) parent checks before
    signing it.
    """
    _assert_bare_body(body)
    body = _with_nonce(body)
    _assert_body(body)
    if body["parent_delegation_id"] is not None:
        raise AuthorityDelegationError(
            "PARENT_MISMATCH",
            (AuthorityFailure(
                code="PARENT_MISMATCH",
                message="root delegation body must have a null parent_delegation_id",
            ),),
        )
    return _finish_issuance(body, private_key)


def issue_sub_authority_delegation(
    parent: dict,
    body: dict,
    private_key: str,
    *,
    now: str,
    resolve_verification_key,
    resolve_revocation,
) -> dict:
    """Issue a child after verifying the parent and the immediate-parent attenuation checks.

    Draft section 3.6 says an issuer minting a child MUST verify the parent
    delegation's signature and temporal validity before signing the child,
    and MUST refuse to issue under an expired, not-yet-valid or revoked
    parent. This function does so, in the same order as the TypeScript SDK's
    issueSubAuthorityDelegation, which takes the same now, key resolver and
    revocation resolver.

    Two different timestamps are checked against the parent's validity
    window, for two different things. `now` is when the issuer is acting: it
    must fall inside the parent's own [not_before, not_after) window, or
    issuance is refused with NOT_YET_VALID or EXPIRED, exactly the same
    check verify_authority_delegation_chain makes for a verifier's clock.
    body["issued_at"] is the timestamp being stamped into the child being
    minted: it is checked against that same parent window independently
    (ISSUED_AT_OUTSIDE_PARENT below), so a caller cannot mint a child whose
    stated issuance time falls outside the parent's window even by acting at
    a `now` when the parent is still valid. There is still no wall clock
    here: `now` is a required keyword-only argument supplied by the caller.

    Checks run in this order, raising AuthorityDelegationError at the first
    one that fails: `now` is a canonical UTC-millisecond timestamp; the
    parent's shape; the parent's delegation_id against its own body; the
    parent's signing key resolves and its signature verifies; the parent is
    valid at `now`; the parent's revocation resolves to exactly "active";
    the child body is a bare object carrying neither delegation_id nor
    signature (see _assert_bare_body); the child body's shape (after nonce
    generation); the child's parent_delegation_id; the child's issuer
    against the parent's subject; the child's issued_at against the
    parent's validity window; and the seven-facet attenuation of the child
    under the parent.
    """
    if not is_canonical_timestamp(now):
        raise AuthorityDelegationError(
            "NONCANONICAL_VALUE",
            (AuthorityFailure(
                code="NONCANONICAL_VALUE", message="now must be a canonical UTC-millisecond timestamp",
            ),),
        )

    parent_failures = validate_authority_delegation_shape(parent)
    if parent_failures:
        raise AuthorityDelegationError(parent_failures[0].code, tuple(parent_failures))

    expected_parent_id = compute_authority_delegation_id(authority_delegation_body(parent))
    if expected_parent_id != parent["delegation_id"]:
        raise AuthorityDelegationError(
            "ID_MISMATCH",
            (AuthorityFailure(code="ID_MISMATCH", message="parent delegation content address does not match its body"),),
        )

    try:
        parent_key = resolve_verification_key(parent["issuer"], parent["verification_method"], parent["issued_at"])
    except Exception:
        parent_key = None
    if parent_key is None:
        raise AuthorityDelegationError(
            "KEY_RESOLUTION_FAILED",
            (AuthorityFailure(
                code="KEY_RESOLUTION_FAILED", message="parent issuer verification key could not be resolved",
            ),),
        )
    if not verify_authority_delegation_signature(parent, parent_key):
        raise AuthorityDelegationError(
            "SIGNATURE_INVALID",
            (AuthorityFailure(code="SIGNATURE_INVALID", message="parent Ed25519 signature is invalid"),),
        )

    parent_time = parent["authority"]["time"]
    if now < parent_time["not_before"]:
        raise AuthorityDelegationError(
            "NOT_YET_VALID",
            (AuthorityFailure(code="NOT_YET_VALID", message="parent delegation is not yet valid at now"),),
        )
    if now >= parent_time["not_after"]:
        raise AuthorityDelegationError(
            "EXPIRED",
            (AuthorityFailure(code="EXPIRED", message="parent delegation has expired at now"),),
        )

    try:
        parent_revocation = resolve_revocation(parent)
    except Exception:
        parent_revocation = None
    # Exact type, not just equality: a str subclass instance that merely
    # compares equal to "active" (or "revoked") must not count as one, since
    # an unresolved or unrecognized result must never be treated as active.
    if type(parent_revocation) is str and parent_revocation == "revoked":
        raise AuthorityDelegationError(
            "REVOKED", (AuthorityFailure(code="REVOKED", message="parent delegation is revoked"),)
        )
    if not (type(parent_revocation) is str and parent_revocation == "active"):
        raise AuthorityDelegationError(
            "REVOCATION_UNKNOWN",
            (AuthorityFailure(code="REVOCATION_UNKNOWN", message="parent revocation status is unknown"),),
        )

    _assert_bare_body(body)
    body = _with_nonce(body)
    _assert_body(body)

    if body["parent_delegation_id"] != parent["delegation_id"]:
        raise AuthorityDelegationError(
            "PARENT_MISMATCH",
            (AuthorityFailure(code="PARENT_MISMATCH", message="child does not name immediate parent content address"),),
        )
    if body["issuer"] != parent["subject"]:
        raise AuthorityDelegationError(
            "CHAIN_CONTINUITY",
            (AuthorityFailure(code="CHAIN_CONTINUITY", message="child issuer is not parent subject"),),
        )

    issued_at = body["issued_at"]
    if issued_at < parent_time["not_before"] or issued_at >= parent_time["not_after"]:
        raise AuthorityDelegationError(
            "ISSUED_AT_OUTSIDE_PARENT",
            (AuthorityFailure(
                code="ISSUED_AT_OUTSIDE_PARENT", message="child was issued outside parent validity window",
            ),),
        )

    attenuation_failures = compare_authority(parent["authority"], body["authority"])
    if attenuation_failures:
        raise AuthorityDelegationError(attenuation_failures[0].code, tuple(attenuation_failures))

    return _finish_issuance(body, private_key)
