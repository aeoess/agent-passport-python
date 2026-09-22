# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""aps:authority-revocation:v1 semantics: the behaviour the wire vector does not pin.

The committed vector (tests/cross_impl/authority-revocation-v1-vectors.json and
its test) pins the wire format: the preimages, the identifiers, the signature
and the nine negative outcomes. It deliberately does not pin store behaviour,
the resolver built over a store, or chain-level enforcement of a revoked
ancestor. Those are what this file covers, mirroring the TypeScript SDK's
tests/v2/authority-revocation.test.ts case for case:

  - a wrong signer is rejected;
  - the first valid revocation wins;
  - an invalid record arriving first cannot take the slot from the valid one
    behind it;
  - a second valid revocation returns the stored first, unchanged;
  - a refused request is never handed the record already stored;
  - the resolver answers revoked / active / unknown, and nothing else;
  - a revoked root makes a valid child fail chain verification;
  - an untracked root is indeterminate, never valid.

Every record here is minted by the module under test. No digest, identifier or
signature is written down by hand.
"""

from __future__ import annotations

import pytest

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_delegation import (
    AUTHORITY_DELEGATION_RECORD_TYPE,
    AUTHORITY_DELEGATION_VERSION,
    REPUTATION_PROFILE_V1,
    REVERSIBILITY_PROFILE_V1,
    SCOPE_PROFILE_V1,
    VALUES_PROFILE_V1,
    AuthorityDelegationError,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    verify_authority_delegation_chain,
)
from agent_passport.v2.authority_revocation import (
    AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
    AUTHORITY_REVOCATION_ID_DOMAIN,
    AUTHORITY_REVOCATION_RECORD_TYPE,
    AUTHORITY_REVOCATION_VERSION,
    AuthorityRevocationError,
    InMemoryAuthorityRevocationStore,
    authority_revocation_body,
    authority_revocation_cascade_origin,
    authority_revocation_cascade_transaction_input,
    authority_revocation_id_input,
    compute_authority_revocation_cascade_transaction_id,
    compute_authority_revocation_id,
    create_authority_revocation_resolver,
    issue_authority_revocation,
    record_authority_revocation,
    sign_authority_revocation,
    verify_authority_revocation,
)

ROOT_KEY = "11" * 32
CHILD_KEY = "22" * 32
IMPOSTOR_KEY = "33" * 32

ROOT_ISSUER = "did:example:root"
ROOT_SUBJECT = "did:example:agent-a"
CHILD_SUBJECT = "did:example:agent-b"
IMPOSTOR = "did:example:impostor"

ROOT_VM = f"{ROOT_ISSUER}#key-1"
CHILD_VM = f"{ROOT_SUBJECT}#key-1"
IMPOSTOR_VM = f"{IMPOSTOR}#key-1"

_PUBLIC_KEYS = {
    ROOT_VM: public_key_from_private(ROOT_KEY),
    CHILD_VM: public_key_from_private(CHILD_KEY),
    IMPOSTOR_VM: public_key_from_private(IMPOSTOR_KEY),
}

NOW = "2026-07-18T22:10:00.000Z"
REVOKED_AT = "2026-07-18T22:20:00.000Z"
NONCE = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"


def resolve_verification_key(_controller, method, _at):
    return _PUBLIC_KEYS.get(method)


def _root_body() -> dict:
    return {
        "record_type": AUTHORITY_DELEGATION_RECORD_TYPE,
        "version": AUTHORITY_DELEGATION_VERSION,
        "parent_delegation_id": None,
        "issuer": ROOT_ISSUER,
        "subject": ROOT_SUBJECT,
        "verification_method": ROOT_VM,
        "issued_at": "2026-07-18T22:00:00.000Z",
        "nonce": "00112233445566778899aabbccddeeff",
        "authority": {
            "scope": {"profile": SCOPE_PROFILE_V1, "grants": ["commerce:*"]},
            "spend": {
                "mode": "bounded",
                "unit": "iso4217:USD:minor",
                "per_action": "100",
                "cumulative": "100",
            },
            "depth": {"remaining": 3},
            "time": {
                "not_before": "2026-07-18T22:00:00.000Z",
                "not_after": "2026-07-18T23:00:00.000Z",
            },
            "reputation": {"profile": REPUTATION_PROFILE_V1, "ceiling": 80},
            "values": {"profile": VALUES_PROFILE_V1, "required": ["F-001", "F-003"]},
            "reversibility": {"profile": REVERSIBILITY_PROFILE_V1, "ceiling": "compensable"},
        },
    }


def _child_body(parent: dict) -> dict:
    return {
        "record_type": AUTHORITY_DELEGATION_RECORD_TYPE,
        "version": AUTHORITY_DELEGATION_VERSION,
        "parent_delegation_id": parent["delegation_id"],
        "issuer": ROOT_SUBJECT,
        "subject": CHILD_SUBJECT,
        "verification_method": CHILD_VM,
        "issued_at": "2026-07-18T22:05:00.000Z",
        "nonce": "ffeeddccbbaa99887766554433221100",
        "authority": {
            "scope": {"profile": SCOPE_PROFILE_V1, "grants": ["commerce:checkout"]},
            "spend": {
                "mode": "bounded",
                "unit": "iso4217:USD:minor",
                "per_action": "80",
                "cumulative": "80",
            },
            "depth": {"remaining": 2},
            "time": {
                "not_before": "2026-07-18T22:05:00.000Z",
                "not_after": "2026-07-18T22:55:00.000Z",
            },
            "reputation": {"profile": REPUTATION_PROFILE_V1, "ceiling": 70},
            "values": {"profile": VALUES_PROFILE_V1, "required": ["F-001", "F-003", "F-004"]},
            "reversibility": {"profile": REVERSIBILITY_PROFILE_V1, "ceiling": "tentative"},
        },
    }


def _root() -> dict:
    return issue_authority_delegation(_root_body(), ROOT_KEY)


def _child(parent: dict) -> dict:
    return issue_sub_authority_delegation(
        parent,
        _child_body(parent),
        CHILD_KEY,
        now=NOW,
        resolve_verification_key=resolve_verification_key,
        resolve_revocation=lambda _delegation: "active",
    )


def _revoke_by_issuer(delegation: dict, *, revoked_at: str = REVOKED_AT, nonce: str = NONCE, **detail) -> dict:
    """A direct revocation of ``delegation`` signed by its own issuer."""
    return issue_authority_revocation(
        delegation,
        now=revoked_at,
        revoker=ROOT_ISSUER,
        verification_method=ROOT_VM,
        reason_code="key_compromise",
        nonce=nonce,
        private_key=ROOT_KEY,
        **detail,
    )


def _revoke_by_non_issuer(delegation: dict) -> dict:
    """A self-consistent revocation naming a non-issuer as its revoker, signed by
    that non-issuer.

    issue_authority_revocation() refuses to mint one, so it is assembled from
    the module's own published helpers; every digest and the signature still
    come from the module under test. verify_authority_revocation() rejects it
    with REVOKER_NOT_ISSUER.
    """
    origin = {
        "record_type": AUTHORITY_REVOCATION_RECORD_TYPE,
        "version": AUTHORITY_REVOCATION_VERSION,
        "delegation_id": delegation["delegation_id"],
        "revoker": IMPOSTOR,
        "verification_method": IMPOSTOR_VM,
        "revoked_at": REVOKED_AT,
        "reason_code": "key_compromise",
        "nonce": NONCE,
    }
    body = dict(origin)
    body["cascade_transaction_id"] = compute_authority_revocation_cascade_transaction_id(origin)
    unsigned = dict(body)
    unsigned["revocation_id"] = compute_authority_revocation_id(body)
    signed = dict(unsigned)
    signed["signature"] = sign_authority_revocation(unsigned, IMPOSTOR_KEY)
    return signed


def _verify(candidate, delegation):
    return verify_authority_revocation(
        candidate, delegation, resolve_verification_key=resolve_verification_key
    )


def _record(store, delegation, candidate):
    """Move ``candidate`` into ``store`` through the verifying mutation path, the
    only supported way a revocation enters a store."""
    return record_authority_revocation(
        store, delegation, candidate, resolve_verification_key=resolve_verification_key
    )


def _resolver(store):
    return create_authority_revocation_resolver(
        store, resolve_verification_key=resolve_verification_key
    )


# ── issuance and the record's own content ────────────────────────────────────


def test_issues_and_verifies_a_direct_revocation_of_the_delegation_its_issuer_signed():
    delegation = _root()
    revocation = _revoke_by_issuer(delegation)

    assert revocation["record_type"] == "aps:authority-revocation:v1"
    assert revocation["delegation_id"] == delegation["delegation_id"]
    assert revocation["revoker"] == delegation["issuer"]
    assert revocation["revoked_at"] == REVOKED_AT
    assert revocation["reason_code"] == "key_compromise"
    # An absent OPTIONAL member is absent, never written as null: JCS has no
    # canonical form for an absent value.
    assert "detail" not in revocation

    result = _verify(revocation, delegation)
    assert result.state == "valid"
    assert result.valid is True
    assert result.failures == ()


def test_optional_detail_rides_inside_the_signed_content_when_supplied():
    delegation = _root()
    revocation = _revoke_by_issuer(delegation, detail="reported by the operator")
    assert revocation["detail"] == "reported by the operator"
    assert _verify(revocation, delegation).state == "valid"

    # Removing it changes the cascade origin, so the first recomputation fails.
    without_detail = {key: value for key, value in revocation.items() if key != "detail"}
    assert _verify(without_detail, delegation).failures[0].code == "CASCADE_TRANSACTION_MISMATCH"


def test_revocation_id_recomputes_independently_from_the_domain_tag_and_jcs():
    import hashlib

    delegation = _root()
    revocation = _revoke_by_issuer(delegation)
    body = authority_revocation_body(revocation)

    # Rebuilt here from the published tag and the canonicalizer, not by calling
    # the module's own compute helper, so the construction is checked rather
    # than echoed.
    digest = hashlib.sha256(
        AUTHORITY_REVOCATION_ID_DOMAIN + canonicalize_jcs(body).encode("utf-8")
    ).hexdigest()
    assert revocation["revocation_id"] == f"sha256:{digest}"
    assert compute_authority_revocation_id(body) == revocation["revocation_id"]
    assert authority_revocation_id_input(body).endswith(canonicalize_jcs(body).encode("utf-8"))


def test_cascade_transaction_id_recomputes_independently_from_its_own_domain_tag():
    import hashlib

    delegation = _root()
    revocation = _revoke_by_issuer(delegation)
    origin = authority_revocation_cascade_origin(authority_revocation_body(revocation))

    digest = hashlib.sha256(
        AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalize_jcs(origin).encode("utf-8")
    ).hexdigest()
    assert revocation["cascade_transaction_id"] == f"sha256:{digest}"
    assert (
        compute_authority_revocation_cascade_transaction_id(origin)
        == revocation["cascade_transaction_id"]
    )
    assert revocation["cascade_transaction_id"] != revocation["revocation_id"]
    assert authority_revocation_cascade_transaction_input(origin).startswith(
        AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN
    )


def test_issuance_with_the_same_inputs_is_byte_deterministic():
    delegation = _root()
    first = _revoke_by_issuer(delegation)
    second = _revoke_by_issuer(delegation)
    assert canonicalize_jcs(first) == canonicalize_jcs(second)
    assert first["signature"] == second["signature"]
    assert first["revocation_id"] == second["revocation_id"]

    # A different nonce is a different record and a different cascade.
    third = _revoke_by_issuer(delegation, nonce="b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
    assert third["revocation_id"] != first["revocation_id"]
    assert third["cascade_transaction_id"] != first["cascade_transaction_id"]


def test_issuance_never_reads_a_clock():
    """`now` is a required keyword argument; there is no default and no wall clock."""
    delegation = _root()
    with pytest.raises(TypeError):
        issue_authority_revocation(
            delegation,
            revoker=ROOT_ISSUER,
            verification_method=ROOT_VM,
            reason_code="key_compromise",
            nonce=NONCE,
            private_key=ROOT_KEY,
        )
    with pytest.raises(AuthorityRevocationError) as exc_info:
        _revoke_by_issuer(delegation, revoked_at="2026-07-18T22:20:00Z")
    assert exc_info.value.code == "NONCANONICAL_VALUE"


# ── authorization ────────────────────────────────────────────────────────────


def test_a_revoker_who_is_not_the_target_delegation_issuer_is_refused_at_issuance():
    delegation = _root()
    with pytest.raises(AuthorityRevocationError) as exc_info:
        issue_authority_revocation(
            delegation,
            now=REVOKED_AT,
            revoker=IMPOSTOR,
            verification_method=IMPOSTOR_VM,
            reason_code="key_compromise",
            nonce=NONCE,
            private_key=IMPOSTOR_KEY,
        )
    assert exc_info.value.code == "REVOKER_NOT_ISSUER"
    assert "REVOKER_NOT_ISSUER" in str(exc_info.value)


def test_a_record_naming_the_issuer_but_signed_by_another_key_does_not_verify():
    delegation = _root()
    # The claimed revoker and verification_method are the issuer's; only the
    # signing key is somebody else's. The resolver answers under the TARGET
    # delegation's issuer, so the impostor's signature is checked against the
    # issuer's public key and fails.
    forged = issue_authority_revocation(
        delegation,
        now=REVOKED_AT,
        revoker=ROOT_ISSUER,
        verification_method=ROOT_VM,
        reason_code="key_compromise",
        nonce=NONCE,
        private_key=IMPOSTOR_KEY,
    )
    result = _verify(forged, delegation)
    assert result.state == "invalid"
    assert result.failures[0].code == "SIGNATURE_INVALID"


def test_a_self_consistent_record_signed_by_a_non_issuer_is_rejected_by_the_verifier():
    delegation = _root()
    forged = _revoke_by_non_issuer(delegation)

    result = _verify(forged, delegation)
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKER_NOT_ISSUER"

    # The mutation path refuses to record it at all, so it never reaches the store.
    store = InMemoryAuthorityRevocationStore()
    refused = _record(store, delegation, forged)
    assert refused.recorded is False
    assert store.get(delegation["delegation_id"]) is None

    # And forced past that gate, straight onto the persistence primitive, it
    # still can never become a "revoked" answer: the resolver verifies again on
    # the way out.
    store.insert_verified_revocation(forged)
    assert _resolver(store)(delegation) == "unknown"


def test_a_valid_revocation_of_one_delegation_does_not_verify_against_another():
    parent = _root()
    descendant = _child(parent)
    revocation = _revoke_by_issuer(parent)
    result = _verify(revocation, descendant)
    assert result.state == "invalid"
    assert result.failures[0].code == "TARGET_MISMATCH"


def test_a_tampered_field_breaks_the_identifier_or_the_signature():
    delegation = _root()
    revocation = _revoke_by_issuer(delegation)
    other = _revoke_by_issuer(delegation, nonce="c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")

    # reason_code is inside the cascade origin, the identifier body and the
    # signature, so the first recomputation already fails.
    assert (
        _verify({**revocation, "reason_code": "operator_request"}, delegation).failures[0].code
        == "CASCADE_TRANSACTION_MISMATCH"
    )
    # revoked_at, likewise.
    assert (
        _verify({**revocation, "revoked_at": "2026-07-18T22:30:00.000Z"}, delegation)
        .failures[0]
        .code
        == "CASCADE_TRANSACTION_MISMATCH"
    )
    # cascade_transaction_id alone: it is not part of its own preimage, so the
    # mismatch is reported against the value the record carries.
    assert (
        _verify(
            {**revocation, "cascade_transaction_id": other["cascade_transaction_id"]}, delegation
        )
        .failures[0]
        .code
        == "CASCADE_TRANSACTION_MISMATCH"
    )
    # revocation_id alone: outside its own preimage, inside the signature's.
    assert (
        _verify({**revocation, "revocation_id": other["revocation_id"]}, delegation)
        .failures[0]
        .code
        == "ID_MISMATCH"
    )
    # The signature is the only member inside neither preimage.
    assert (
        _verify({**revocation, "signature": other["signature"]}, delegation).failures[0].code
        == "SIGNATURE_INVALID"
    )


def test_an_opaque_verification_method_issues_and_verifies():
    delegation = _root()
    # Nothing in this module requires a method identifier to be a fragment of
    # the identifier that controls it. Whether it belongs to the issuer is
    # settled by the resolver, which is handed target["issuer"].
    opaque_vm = "urn:example:hsm/slot-3"
    revocation = issue_authority_revocation(
        delegation,
        now=REVOKED_AT,
        revoker=ROOT_ISSUER,
        verification_method=opaque_vm,
        reason_code="key_compromise",
        nonce=NONCE,
        private_key=ROOT_KEY,
    )
    assert revocation["verification_method"] == opaque_vm
    assert not opaque_vm.startswith(f"{ROOT_ISSUER}#")

    seen = {}

    def resolve(controller, method, _at):
        seen["controller"] = controller
        if controller == ROOT_ISSUER and method == opaque_vm:
            return public_key_from_private(ROOT_KEY)
        return None

    result = verify_authority_revocation(revocation, delegation, resolve_verification_key=resolve)
    assert result.state == "valid"
    assert seen["controller"] == delegation["issuer"]

    # The same record under a resolver that does not bind the method to this
    # issuer is indeterminate, never valid.
    assert (
        verify_authority_revocation(
            revocation, delegation, resolve_verification_key=lambda *_a: None
        ).state
        == "indeterminate"
    )


def test_a_reason_code_outside_the_old_lowercase_grammar_issues_and_verifies():
    delegation = _root()
    reason = "Key Compromise"
    revocation = issue_authority_revocation(
        delegation,
        now=REVOKED_AT,
        revoker=ROOT_ISSUER,
        verification_method=ROOT_VM,
        reason_code=reason,
        nonce=NONCE,
        private_key=ROOT_KEY,
    )
    assert revocation["reason_code"] == reason
    assert _verify(revocation, delegation).state == "valid"

    # An empty reason_code is still refused: the member carries a value or the
    # record is not valid.
    with pytest.raises(AuthorityRevocationError) as exc_info:
        issue_authority_revocation(
            delegation,
            now=REVOKED_AT,
            revoker=ROOT_ISSUER,
            verification_method=ROOT_VM,
            reason_code="",
            nonce=NONCE,
            private_key=ROOT_KEY,
        )
    assert "reason_code" in str(exc_info.value)


def test_verification_fails_closed_on_an_unusable_resolver():
    delegation = _root()
    revocation = _revoke_by_issuer(delegation)

    def raising(*_args):
        raise RuntimeError("offline")

    assert (
        verify_authority_revocation(
            revocation, delegation, resolve_verification_key=lambda *_a: None
        ).state
        == "indeterminate"
    )
    assert (
        verify_authority_revocation(
            revocation, delegation, resolve_verification_key=raising
        ).state
        == "indeterminate"
    )
    assert (
        verify_authority_revocation(
            revocation, delegation, resolve_verification_key=lambda *_a: {"outcome": "unreachable"}
        )
        .failures[0]
        .code
        == "KEY_UNREACHABLE"
    )
    assert (
        verify_authority_revocation(
            revocation, delegation, resolve_verification_key=None
        ).failures[0].code
        == "KEY_RESOLUTION_FAILED"
    )
    assert _verify({"record_type": "nope"}, delegation).state == "unsupported"
    assert _verify(None, delegation).state == "invalid"


# ── the store and the mutation path ──────────────────────────────────────────


def test_store_keeps_the_first_revocation_and_returns_it_for_a_repeated_request():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    first = _revoke_by_issuer(delegation)
    second = _revoke_by_issuer(
        delegation, revoked_at="2026-07-18T22:40:00.000Z", nonce="d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    )
    assert second["revocation_id"] != first["revocation_id"]

    accepted = _record(store, delegation, first)
    assert accepted.inserted is True
    assert accepted.stored is not None
    assert accepted.stored["revocation_id"] == first["revocation_id"]

    returned = _record(store, delegation, second)
    assert returned.inserted is False
    assert returned.stored is not None
    assert returned.stored["revocation_id"] == first["revocation_id"]
    assert returned.stored["revoked_at"] == REVOKED_AT
    assert store.get(delegation["delegation_id"])["revocation_id"] == first["revocation_id"]
    assert store.tracks(delegation["delegation_id"]) is True


def test_an_invalid_record_cannot_take_the_first_wins_slot_from_the_valid_one_behind_it():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    store.track(delegation["delegation_id"])
    resolve = _resolver(store)

    # An arbitrary object naming the delegation: refused, and the store is not
    # touched.
    garbage = _record(store, delegation, {"delegation_id": delegation["delegation_id"]})
    assert garbage.recorded is False
    assert garbage.inserted is False
    assert garbage.stored is None
    assert garbage.verification.valid is False
    assert store.get(delegation["delegation_id"]) is None

    # A self-consistent record signed by a party who is not the issuer: refused
    # on its own authorization failure, not on a schema complaint.
    unauthorized = _record(store, delegation, _revoke_by_non_issuer(delegation))
    assert unauthorized.recorded is False
    assert unauthorized.stored is None
    assert unauthorized.verification.failures[0].code == "REVOKER_NOT_ISSUER"
    assert store.get(delegation["delegation_id"]) is None

    # The slot is therefore still open. Under the defect this closes, either
    # refused record held it, the write below was discarded, and this delegation
    # could never be revoked.
    assert resolve(delegation) == "active"
    valid = _revoke_by_issuer(delegation)
    accepted = _record(store, delegation, valid)
    assert accepted.recorded is True
    assert accepted.inserted is True
    assert accepted.stored is not None
    assert accepted.stored["revocation_id"] == valid["revocation_id"]
    assert resolve(delegation) == "revoked"


def test_a_second_valid_revocation_returns_the_stored_first_record_byte_identical():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    first = _revoke_by_issuer(delegation)
    second = _revoke_by_issuer(
        delegation, revoked_at="2026-07-18T22:45:00.000Z", nonce="e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    )
    assert second["revocation_id"] != first["revocation_id"]
    # Both are genuinely valid, so what separates them is arrival order and
    # nothing else.
    assert _verify(first, delegation).state == "valid"
    assert _verify(second, delegation).state == "valid"

    assert _record(store, delegation, first).inserted is True

    later = _record(store, delegation, second)
    assert later.recorded is True
    assert later.inserted is False
    assert later.verification.state == "valid"
    assert later.stored is not None
    assert canonicalize_jcs(later.stored) == canonicalize_jcs(first)
    assert canonicalize_jcs(store.get(delegation["delegation_id"])) == canonicalize_jcs(first)
    assert later.stored["revoked_at"] == REVOKED_AT


def test_a_refused_request_is_never_handed_the_record_already_stored():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    first = _revoke_by_issuer(delegation)
    assert _record(store, delegation, first).inserted is True

    # Unauthorized, arriving after a valid record exists.
    unauthorized = _record(store, delegation, _revoke_by_non_issuer(delegation))
    assert unauthorized.recorded is False
    assert unauthorized.inserted is False
    # Not the stored record, and not the candidate either.
    assert unauthorized.stored is None
    assert unauthorized.verification.state == "invalid"
    assert unauthorized.verification.failures[0].code == "REVOKER_NOT_ISSUER"

    # Structurally invalid, same answer.
    broken = _record(store, delegation, {**first, "signature": "0" * 128})
    assert broken.recorded is False
    assert broken.stored is None
    assert broken.verification.failures[0].code == "SIGNATURE_INVALID"

    # Neither refusal disturbed what the store holds.
    assert canonicalize_jcs(store.get(delegation["delegation_id"])) == canonicalize_jcs(first)
    assert _resolver(store)(delegation) == "revoked"


def test_the_stored_record_is_this_module_s_copy_not_the_caller_s_dict():
    """The bytes the store keeps are the bytes that were verified, and a caller
    writing to its own dict afterwards cannot change them."""
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    candidate = _revoke_by_issuer(delegation)
    accepted = _record(store, delegation, candidate)
    assert accepted.inserted is True

    candidate["reason_code"] = "operator_request"
    assert store.get(delegation["delegation_id"])["reason_code"] == "key_compromise"
    assert _resolver(store)(delegation) == "revoked"


# ── the resolver ─────────────────────────────────────────────────────────────


def test_resolver_revoked_tracked_active_untracked_unknown():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    resolve = _resolver(store)

    assert resolve(delegation) == "unknown"
    store.track(delegation["delegation_id"])
    assert resolve(delegation) == "active"
    _record(store, delegation, _revoke_by_issuer(delegation))
    assert resolve(delegation) == "revoked"


def test_a_stored_record_that_does_not_verify_resolves_unknown_never_revoked_or_active():
    delegation = _root()
    store = InMemoryAuthorityRevocationStore()
    store.track(delegation["delegation_id"])
    revocation = _revoke_by_issuer(delegation)
    broken = {**revocation, "signature": "0" * 128}

    # The mutation path refuses it, so reaching this state at all means going
    # around it, straight onto the persistence primitive.
    assert _record(store, delegation, broken).recorded is False
    store.insert_verified_revocation(broken)

    assert _resolver(store)(delegation) == "unknown"


def test_resolver_never_raises():
    """A store that raises, and a delegation whose id does not recompute, are
    both "unknown" in the open rather than through an except clause in somebody
    else's code."""
    delegation = _root()

    class Raising:
        def get(self, _delegation_id):
            raise RuntimeError("store offline")

        def tracks(self, _delegation_id):
            raise RuntimeError("store offline")

    assert _resolver(Raising())(delegation) == "unknown"

    store = InMemoryAuthorityRevocationStore()
    store.track(delegation["delegation_id"])
    relabelled = {**delegation, "delegation_id": "sha256:" + "0" * 64}
    assert _resolver(store)(relabelled) == "unknown"


# ── chain-level enforcement ──────────────────────────────────────────────────


def _chain_options(store, parent):
    return {
        "now": NOW,
        "resolve_verification_key": resolve_verification_key,
        "trust_root": lambda candidate: candidate["delegation_id"] == parent["delegation_id"],
        "resolve_revocation": _resolver(store),
    }


def test_a_revoked_root_makes_a_valid_child_chain_fail_with_the_existing_revoked_outcome():
    parent = _root()
    descendant = _child(parent)
    store = InMemoryAuthorityRevocationStore()
    store.track(parent["delegation_id"])
    store.track(descendant["delegation_id"])

    before = verify_authority_delegation_chain(
        [parent, descendant], **_chain_options(store, parent)
    )
    assert before.state == "valid"

    _record(store, parent, _revoke_by_issuer(parent))

    after = verify_authority_delegation_chain([parent, descendant], **_chain_options(store, parent))
    assert after.state == "invalid"
    assert after.failures[0].code == "REVOKED"
    assert after.failures[0].index == 0

    # The descendant carries no revocation record of its own. Enforcement
    # against it comes from the ancestor in its chain, not from a
    # cascade-derived record.
    assert store.get(descendant["delegation_id"]) is None


def test_a_revoked_parent_cannot_mint_a_further_child():
    parent = _root()
    store = InMemoryAuthorityRevocationStore()
    store.track(parent["delegation_id"])
    _record(store, parent, _revoke_by_issuer(parent))

    with pytest.raises(AuthorityDelegationError) as exc_info:
        issue_sub_authority_delegation(
            parent,
            _child_body(parent),
            CHILD_KEY,
            now=NOW,
            resolve_verification_key=resolve_verification_key,
            resolve_revocation=_resolver(store),
        )
    assert exc_info.value.code == "REVOKED"


def test_an_untracked_root_yields_indeterminate_never_valid():
    parent = _root()
    descendant = _child(parent)
    store = InMemoryAuthorityRevocationStore()
    store.track(descendant["delegation_id"])

    outcome = verify_authority_delegation_chain(
        [parent, descendant], **_chain_options(store, parent)
    )
    assert outcome.state == "indeterminate"
    assert outcome.valid is False
    assert outcome.failures[0].code == "REVOCATION_UNKNOWN"
    assert outcome.failures[0].index == 0
