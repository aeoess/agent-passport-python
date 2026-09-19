# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Issuance of a root delegation and of a child under an immediate parent.

Python port of the TypeScript SDK's src/v2/authority-delegation/issue.ts, with
three deliberate differences from it: nonce generation (see _with_nonce
below), a bare-body check (see _assert_bare_body below), and a stricter
issue_sub_authority_delegation (see its docstring).

Deliberate addition over the TypeScript SDK: _assert_bare_body below rejects
a body that is not an object, or that already carries "delegation_id" or
"signature", before either issuing function does anything else with it. The
TypeScript SDK's AuthorityDelegationBodyV1 type excludes those two members at
compile time, but nothing checks for them at runtime: a caller that passes an
object carrying a stray "delegation_id" or "signature" has it hashed and
signed together with the rest of the body, so the id that comes out never
recomputes from that same body and the record is invalid from the moment it
is issued, an outcome draft section 3.6 asks an issuer to avoid rather than
leave for a later verifier to discover. This Python port refuses to issue
from such a body instead of producing a self-contradicting record.
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
from .schema import validate_authority_delegation_shape
from .types import AuthorityDelegationError, AuthorityFailure


def _assert_bare_body(body) -> None:
    """Reject a body that is not an object, or that already carries an id or a signature.

    See the module docstring: this check has no TypeScript SDK counterpart at
    runtime.
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


def issue_authority_delegation(body: dict, private_key: str) -> dict:
    """Create a deterministic v1 record from explicit body fields and an Ed25519 key."""
    _assert_bare_body(body)
    body = _with_nonce(body)
    _assert_body(body)
    delegation_id = compute_authority_delegation_id_for_write(body)
    unsigned = {**body, "delegation_id": delegation_id}
    signature = sign_authority_delegation(unsigned, private_key)
    return {**unsigned, "signature": signature}


def issue_sub_authority_delegation(
    parent: dict,
    body: dict,
    private_key: str,
    *,
    resolve_verification_key,
    resolve_revocation,
) -> dict:
    """Issue a child after verifying the parent and the immediate-parent attenuation checks.

    Deliberate difference from the TypeScript SDK: draft section 3.6 says an
    issuer minting a child MUST verify the parent delegation's signature and
    temporal validity before signing the child, and MUST refuse to issue
    under an expired, not-yet-valid or revoked parent. The TypeScript SDK's
    issueSubAuthorityDelegation checks neither the parent's signature nor its
    revocation (only the shape, id-derived continuity fields and attenuation
    below, which this function also checks); this Python port adds the
    parent signature and revocation checks the draft requires. Parent
    temporal validity is enforced indirectly: this function requires the
    child's issued_at to fall inside the parent's validity window (the
    ISSUED_AT_OUTSIDE_PARENT check below), which is only satisfiable when the
    parent is currently valid at that instant.

    Checks run in this order, raising AuthorityDelegationError at the first
    one that fails: the parent's shape; the parent's delegation_id against
    its own body; the parent's signing key resolves and its signature
    verifies; the parent's revocation resolves to exactly "active"; the
    child body is a bare object carrying neither delegation_id nor signature
    (see _assert_bare_body); the child body's shape (after nonce generation);
    the child's parent_delegation_id; the child's issuer against the parent's
    subject; the child's issued_at against the parent's validity window; and
    the seven-facet attenuation of the child under the parent.
    """
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
    parent_time = parent["authority"]["time"]
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

    return issue_authority_delegation(body, private_key)
