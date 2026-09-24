# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED authority-state surface: markers,
the monotonicity comparison, the fencing gate on a write, and withdrawal of a recorded
revocation.

Every expectation in the vector-driven sections comes from
conformance/authority-state/v0/vectors.json, which is the SHARED fixture: the TypeScript SDK
authors it and this repository vendors a byte-identical copy, so the same cases run through
both ports. Expectations are hand specified in the vectors, never computed by the code under
test. The file's SHA-256 is pinned in both repositories, so the two copies can be shown
identical without either repository importing the other.

The sections after the vectors are the parts that need real Ed25519 records, so they cannot
live in a language-neutral vector file. Every record in them is minted by the modules under
test. No digest, identifier or signature is written down by hand. They mirror
tests/v2/authority-state.test.ts in the TypeScript SDK case for case.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import pytest

from agent_passport import (
    FENCED_WRITE_REFUSAL_CODES,
    MONOTONICITY_OUTCOMES,
    REVOCATION_WITHDRAWAL_RECORD_TYPE,
    REVOCATION_WITHDRAWAL_VERSION,
    STATE_MARKER_SCOPES,
    UNPLACEABLE_DISPOSITIONS,
    WITHDRAWAL_OUTCOME_CODES,
    WITHDRAWAL_STANDINGS,
    AuthorityStateError,
    FencedAuthorityStateLog,
    RetainedAuthorityState,
    StateMarker,
    advance_high_water_mark,
    authority_state_report,
    compare_state_marker,
    corrected_revocation_view,
    create_monotonic_revocation_resolver,
    evaluate_revocation_withdrawal,
    report_authority_state,
    resolve_under_retained_state,
    revocation_withdrawal,
    state_marker,
    withdrawal_signer_is_revoker,
)
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_delegation import (
    AUTHORITY_DELEGATION_RECORD_TYPE,
    AUTHORITY_DELEGATION_VERSION,
    REPUTATION_PROFILE_V1,
    REVERSIBILITY_PROFILE_V1,
    SCOPE_PROFILE_V1,
    VALUES_PROFILE_V1,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    verify_authority_delegation_chain,
)
from agent_passport.v2.authority_revocation import (
    InMemoryAuthorityRevocationStore,
    create_authority_revocation_resolver,
    issue_authority_revocation,
    record_authority_revocation,
    verify_authority_revocation,
)

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "authority-state", "v0", "vectors.json"
)
with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()
_VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))

# Pinned so the TypeScript SDK's authoring copy can be shown byte identical. If this moves,
# the TypeScript repo's copy and its own pin move with it, in the same change.
_VECTORS_SHA256 = "4c2292d56f4e26fee62e7d70518d1d4a2fc5d7b2762ebfe4d3e8bc804cd15f45"


def _as_marker(literal):
    """A marker literal from the vectors, as the dataclass the API takes. The vectors carry
    shapes the constructor is meant to reject, so the negative cases deliberately bypass it
    and build the dataclass directly."""
    if literal is None:
        return None
    return StateMarker(
        value=literal["value"], scope=literal["scope"], scope_ref=literal.get("scope_ref")
    )


def _as_literal(marker):
    """A marker back as the plain object the vectors express, absent scope_ref dropped."""
    if marker is None:
        return None
    out = {"value": marker.value, "scope": marker.scope}
    if marker.scope_ref is not None:
        out["scope_ref"] = marker.scope_ref
    return out


_STANDING_RESOLVERS = {
    "signer_is_revoker": withdrawal_signer_is_revoker,
    "always_unknown": lambda _w, _r: "unknown",
    "always_has_standing": lambda _w, _r: "has_standing",
}


# ── The shared fixture ────────────────────────────────────────────────────────────────


def test_vectors_file_is_the_pinned_bytes():
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == _VECTORS_SHA256


def test_vocabulary_in_the_vectors_is_the_vocabulary_the_module_exports():
    vocabulary = _VECTORS["vocabulary"]
    assert list(STATE_MARKER_SCOPES) == vocabulary["state_marker_scopes"]
    assert list(MONOTONICITY_OUTCOMES) == vocabulary["monotonicity_outcomes"]
    assert list(UNPLACEABLE_DISPOSITIONS) == vocabulary["unplaceable_dispositions"]
    assert list(FENCED_WRITE_REFUSAL_CODES) == vocabulary["fenced_write_refusal_codes"]
    assert list(WITHDRAWAL_STANDINGS) == vocabulary["withdrawal_standings"]
    assert list(WITHDRAWAL_OUTCOME_CODES) == vocabulary["withdrawal_outcome_codes"]
    assert REVOCATION_WITHDRAWAL_RECORD_TYPE == vocabulary["revocation_withdrawal_record_type"]
    assert REVOCATION_WITHDRAWAL_VERSION == vocabulary["revocation_withdrawal_version"]


# ── Vector-driven cases ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("vec", _VECTORS["marker_cases"], ids=lambda v: v["id"])
def test_marker_constructor(vec):
    spec = vec["input"]
    if vec["expected"]["ok"]:
        marker = state_marker(spec["value"], spec["scope"], spec.get("scope_ref"))
        assert _as_literal(marker) == vec["expected"]["marker"]
    else:
        with pytest.raises(AuthorityStateError) as caught:
            state_marker(spec["value"], spec["scope"], spec.get("scope_ref"))
        assert caught.value.code == vec["expected"]["error_code"]


@pytest.mark.parametrize("vec", _VECTORS["comparison_cases"], ids=lambda v: v["id"])
def test_monotonicity_comparison(vec):
    established = _as_marker(vec["established"])
    presented = _as_marker(vec["presented"])
    assert compare_state_marker(established, presented) == vec["expected"]["outcome"]
    after = advance_high_water_mark(established, presented)
    assert _as_literal(after) == vec["expected"]["high_water_mark_after"]


@pytest.mark.parametrize("vec", _VECTORS["routing_cases"], ids=lambda v: v["id"])
def test_resolver_routing(vec):
    resolver = create_monotonic_revocation_resolver(
        presented=lambda _delegation: vec["presented_answer"],
        presented_marker=_as_marker(vec["presented_marker"]),
        retained=RetainedAuthorityState(
            records=(), high_water_mark=_as_marker(vec["established"])
        ),
        resolve_verification_key=lambda *_args: None,
        on_unplaceable=vec["on_unplaceable"],
    )
    assert resolver.monotonicity == vec["expected"]["monotonicity"]
    assert resolver.resolve({}) == vec["expected"]["resolution"]
    assert _as_literal(resolver.high_water_mark_after) == vec["expected"]["high_water_mark_after"]


@pytest.mark.parametrize("vec", _VECTORS["fencing_cases"], ids=lambda v: v["id"])
def test_fencing_gate(vec):
    log: FencedAuthorityStateLog = FencedAuthorityStateLog()
    for write in vec["writes"]:
        outcome = log.write(_as_marker(write["token"]), write["payload"])
        assert outcome.accepted == write["expected"]["accepted"]
        if not outcome.accepted:
            assert outcome.code == write["expected"]["code"]
    assert log.published() == vec["expected"]["published_payload"]
    assert _as_literal(log.highest_token()) == vec["expected"]["highest_token"]


@pytest.mark.parametrize("vec", _VECTORS["withdrawal_cases"], ids=lambda v: v["id"])
def test_withdrawal_evaluation(vec):
    evaluation = evaluate_revocation_withdrawal(
        vec["withdrawal"], vec["held"], _STANDING_RESOLVERS[vec["standing_resolver"]]
    )
    assert evaluation.accepted == vec["expected"]["accepted"]
    assert evaluation.reason_code == vec["expected"]["reason_code"]
    assert evaluation.standing == vec["expected"]["standing"]


@pytest.mark.parametrize("vec", _VECTORS["corrected_view_cases"], ids=lambda v: v["id"])
def test_corrected_revocation_view(vec):
    view = corrected_revocation_view(
        vec["revocation"], vec["withdrawals"], _STANDING_RESOLVERS[vec["standing_resolver"]]
    )
    assert (view.revocation is not None) == vec["expected"]["revocation_present"]
    assert view.revocation == vec["revocation"]
    assert len(view.accepted) == vec["expected"]["accepted_count"]
    assert len(view.refused) == vec["expected"]["refused_count"]
    assert [e.reason_code for e in view.accepted] == vec["expected"]["accepted_reason_codes"]
    assert [e.reason_code for e in view.refused] == vec["expected"]["refused_reason_codes"]


# ── Against real records ──────────────────────────────────────────────────────────────
# Everything below mints its own delegations and revocations through the SDK's own issuance
# path, so a `revoked` answer here is earned by verification rather than asserted.

ROOT_KEY = "11" * 32
CHILD_KEY = "22" * 32
ROOT_ISSUER = "did:example:aer-principal"
ROOT_SUBJECT = "did:example:aer-agent-a"
CHILD_SUBJECT = "did:example:aer-agent-b"
ROOT_VM = f"{ROOT_ISSUER}#key-1"
CHILD_VM = f"{ROOT_SUBJECT}#key-1"

_PUBLIC_KEYS = {
    ROOT_VM: public_key_from_private(ROOT_KEY),
    CHILD_VM: public_key_from_private(CHILD_KEY),
}

NOW = "2026-09-20T13:00:00.000Z"
REVOKED_AT = "2026-09-20T11:30:00.000Z"


def resolve_verification_key(_controller, method, _at=None):
    return _PUBLIC_KEYS.get(method)


def _no_key(_controller, _method, _at=None):
    return None


def _root_body() -> dict:
    return {
        "record_type": AUTHORITY_DELEGATION_RECORD_TYPE,
        "version": AUTHORITY_DELEGATION_VERSION,
        "parent_delegation_id": None,
        "issuer": ROOT_ISSUER,
        "subject": ROOT_SUBJECT,
        "verification_method": ROOT_VM,
        "issued_at": "2026-09-20T10:00:00.000Z",
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
                "not_before": "2026-09-20T10:00:00.000Z",
                "not_after": "2026-09-20T23:00:00.000Z",
            },
            "reputation": {"profile": REPUTATION_PROFILE_V1, "ceiling": 80},
            "values": {"profile": VALUES_PROFILE_V1, "required": ["F-001"]},
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
        "issued_at": "2026-09-20T10:05:00.000Z",
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
                "not_before": "2026-09-20T10:05:00.000Z",
                "not_after": "2026-09-20T22:55:00.000Z",
            },
            "reputation": {"profile": REPUTATION_PROFILE_V1, "ceiling": 70},
            "values": {"profile": VALUES_PROFILE_V1, "required": ["F-001"]},
            "reversibility": {"profile": REVERSIBILITY_PROFILE_V1, "ceiling": "tentative"},
        },
    }


@dataclasses.dataclass
class _Scenario:
    root: dict
    child: dict
    revocation: dict
    #: epoch 6: both delegations tracked, no revocation held.
    before: InMemoryAuthorityRevocationStore
    #: epoch 7: the root revocation held.
    after: InMemoryAuthorityRevocationStore


def _scenario() -> _Scenario:
    root = issue_authority_delegation(_root_body(), ROOT_KEY)
    child = issue_sub_authority_delegation(
        root,
        _child_body(root),
        CHILD_KEY,
        now="2026-09-20T10:05:00.000Z",
        resolve_verification_key=resolve_verification_key,
        resolve_revocation=lambda _delegation: "active",
    )
    revocation = issue_authority_revocation(
        root,
        now=REVOKED_AT,
        revoker=ROOT_ISSUER,
        verification_method=ROOT_VM,
        reason_code="recorded_in_error",
        nonce="a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        private_key=ROOT_KEY,
    )

    before = InMemoryAuthorityRevocationStore()
    before.track(root["delegation_id"])
    before.track(child["delegation_id"])

    after = InMemoryAuthorityRevocationStore()
    after.track(root["delegation_id"])
    after.track(child["delegation_id"])
    recorded = record_authority_revocation(
        after, root, revocation, resolve_verification_key=resolve_verification_key
    )
    assert recorded.recorded is True

    return _Scenario(root=root, child=child, revocation=revocation, before=before, after=after)


EPOCH_6 = state_marker("6", "global")
EPOCH_7 = state_marker("7", "global")
EPOCH_8 = state_marker("8", "global")


def _chain_result(scenario: _Scenario, resolve_revocation):
    return verify_authority_delegation_chain(
        [scenario.root, scenario.child],
        now=NOW,
        resolve_verification_key=resolve_verification_key,
        trust_root=lambda candidate: candidate["delegation_id"] == scenario.root["delegation_id"],
        resolve_revocation=resolve_revocation,
    )


# ── A retained record set is not a store ──────────────────────────────────────────────


def test_retained_record_that_verifies_answers_revoked():
    s = _scenario()
    assert (
        resolve_under_retained_state(
            s.root,
            RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
            resolve_verification_key=resolve_verification_key,
        )
        == "revoked"
    )


def test_retained_set_that_does_not_mention_this_delegation_is_unknown_never_active():
    s = _scenario()
    assert (
        resolve_under_retained_state(
            s.child,
            RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
            resolve_verification_key=resolve_verification_key,
        )
        == "unknown"
    )


def test_empty_retained_set_answers_unknown():
    s = _scenario()
    assert (
        resolve_under_retained_state(
            s.root,
            RetainedAuthorityState(records=(), high_water_mark=EPOCH_7),
            resolve_verification_key=resolve_verification_key,
        )
        == "unknown"
    )


def test_retained_record_whose_key_does_not_resolve_is_unknown_not_revoked():
    s = _scenario()
    assert (
        resolve_under_retained_state(
            s.root,
            RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
            resolve_verification_key=_no_key,
        )
        == "unknown"
    )


# ── Rollback against a real chain ─────────────────────────────────────────────────────


def test_epoch_7_presented_to_a_verifier_at_epoch_7_is_invalid_at_the_root_index():
    s = _scenario()
    resolver = create_monotonic_revocation_resolver(
        presented=create_authority_revocation_resolver(
            s.after, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_7,
        retained=RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
        resolve_verification_key=resolve_verification_key,
        on_unplaceable="read_presented",
    )
    result = _chain_result(s, resolver.resolve)
    assert resolver.monotonicity == "forward"
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"
    assert result.failures[0].index == 0


def test_epoch_6_presented_to_a_verifier_that_has_seen_nothing_later_is_valid():
    s = _scenario()
    resolver = create_monotonic_revocation_resolver(
        presented=create_authority_revocation_resolver(
            s.before, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_6,
        retained=RetainedAuthorityState(records=(), high_water_mark=EPOCH_6),
        resolve_verification_key=resolve_verification_key,
        on_unplaceable="read_presented",
    )
    result = _chain_result(s, resolver.resolve)
    assert resolver.monotonicity == "forward"
    assert result.state == "valid"


def test_restored_snapshot_against_a_verifier_that_retained_the_record_is_invalid_not_valid():
    s = _scenario()
    # The same epoch-6 store as the case above. Only the verifier differs.
    assert (
        create_authority_revocation_resolver(
            s.before, resolve_verification_key=resolve_verification_key
        )(s.root)
        == "active"
    )

    resolver = create_monotonic_revocation_resolver(
        presented=create_authority_revocation_resolver(
            s.before, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_6,
        retained=RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
        resolve_verification_key=resolve_verification_key,
        on_unplaceable="read_presented",
    )
    result = _chain_result(s, resolver.resolve)
    assert resolver.monotonicity == "regressed"
    assert resolver.resolve(s.root) == "revoked"
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"
    assert result.failures[0].index == 0
    assert resolver.high_water_mark_after == EPOCH_7


def test_lagging_replica_against_a_verifier_that_retained_only_the_mark_is_indeterminate():
    s = _scenario()
    resolver = create_monotonic_revocation_resolver(
        presented=create_authority_revocation_resolver(
            s.before, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_6,
        retained=RetainedAuthorityState(records=(), high_water_mark=EPOCH_7),
        resolve_verification_key=resolve_verification_key,
        on_unplaceable="read_presented",
    )
    result = _chain_result(s, resolver.resolve)
    assert resolver.monotonicity == "regressed"
    assert resolver.resolve(s.root) == "unknown"
    assert result.state == "indeterminate"
    assert result.failures[0].code == "REVOCATION_UNKNOWN"
    assert result.failures[0].index == 0


def test_forward_move_is_read_normally_and_the_mark_advances():
    s = _scenario()
    resolver = create_monotonic_revocation_resolver(
        presented=create_authority_revocation_resolver(
            s.after, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_8,
        retained=RetainedAuthorityState(records=(s.revocation,), high_water_mark=EPOCH_7),
        resolve_verification_key=resolve_verification_key,
        on_unplaceable="read_presented",
    )
    result = _chain_result(s, resolver.resolve)
    assert resolver.monotonicity == "forward"
    assert resolver.high_water_mark_after == EPOCH_8
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"


def test_first_contact_takes_the_caller_disposition_and_the_two_dispositions_differ():
    s = _scenario()
    shared = dict(
        presented=create_authority_revocation_resolver(
            s.before, resolve_verification_key=resolve_verification_key
        ),
        presented_marker=EPOCH_6,
        retained=RetainedAuthorityState(records=(), high_water_mark=None),
        resolve_verification_key=resolve_verification_key,
    )
    read = create_monotonic_revocation_resolver(**shared, on_unplaceable="read_presented")
    refuse = create_monotonic_revocation_resolver(**shared, on_unplaceable="refuse")
    assert read.monotonicity == "unplaceable"
    assert refuse.monotonicity == "unplaceable"
    assert _chain_result(s, read.resolve).state == "valid"
    assert _chain_result(s, refuse.resolve).state == "indeterminate"


# ── Fencing on the write path, with real stores ───────────────────────────────────────


def test_a_stale_token_cannot_republish_pre_revocation_state():
    s = _scenario()
    log: FencedAuthorityStateLog = FencedAuthorityStateLog()
    current = log.write(state_marker("42", "global"), s.after)
    assert current.accepted is True

    stale = log.write(state_marker("41", "global"), s.before)
    assert stale.accepted is False
    assert stale.code == "stale_fencing_token"

    published = log.published()
    result = _chain_result(
        s,
        create_authority_revocation_resolver(
            published, resolve_verification_key=resolve_verification_key
        ),
    )
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"


def test_an_unfenced_publisher_republishes_it_and_the_same_chain_then_verifies_valid():
    """The defect the gate exists to catch, shown rather than asserted: with no token check
    the pre-revocation store becomes what is read, and every signature still checks out."""
    s = _scenario()
    unfenced = create_authority_revocation_resolver(
        s.before, resolve_verification_key=resolve_verification_key
    )
    result = _chain_result(s, unfenced)
    assert result.state == "valid"


# ── A withdrawal is a record, not a resurrection ──────────────────────────────────────


def _withdrawal(s: _Scenario, by: str):
    return revocation_withdrawal(
        revocation_id=s.revocation["revocation_id"],
        delegation_id=s.revocation["delegation_id"],
        withdrawn_by=by,
        withdrawn_at="2026-09-20T12:30:00.000Z",
        reason_code="recorded-in-error",
    )


def test_an_accepted_withdrawal_leaves_the_revocation_held_verifying_and_effective():
    s = _scenario()
    view = corrected_revocation_view(
        s.revocation, [_withdrawal(s, ROOT_ISSUER)], withdrawal_signer_is_revoker
    )
    assert len(view.accepted) == 1
    assert len(view.refused) == 0

    # Still in the store, and still verifies byte for byte.
    assert s.after.get(s.root["delegation_id"]) == s.revocation
    assert (
        verify_authority_revocation(
            s.revocation, s.root, resolve_verification_key=resolve_verification_key
        ).state
        == "valid"
    )

    # And the chain verdict has not moved one step toward valid.
    result = _chain_result(
        s,
        create_authority_revocation_resolver(
            s.after, resolve_verification_key=resolve_verification_key
        ),
    )
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"

    report = report_authority_state(result, corrections=[view])
    assert report.chain is result
    assert report.lifecycle.verdict == "invalid"
    assert report.lifecycle.reason_code == "REVOKED"
    assert len(report.corrections[0].accepted) == 1
    assert report.corrections[0].revocation == s.revocation


def test_a_withdrawal_from_a_party_without_standing_is_refused_with_a_named_reason():
    s = _scenario()
    view = corrected_revocation_view(
        s.revocation, [_withdrawal(s, ROOT_SUBJECT)], withdrawal_signer_is_revoker
    )
    assert len(view.accepted) == 0
    assert len(view.refused) == 1
    assert view.refused[0].reason_code == "WITHDRAWAL_SIGNER_WITHOUT_STANDING"
    assert view.refused[0].standing == "no_standing"


def test_no_path_in_this_module_removes_a_revocation_from_a_store():
    s = _scenario()
    corrected_revocation_view(
        s.revocation, [_withdrawal(s, ROOT_ISSUER)], withdrawal_signer_is_revoker
    )
    evaluate_revocation_withdrawal(
        _withdrawal(s, ROOT_ISSUER), [s.revocation], withdrawal_signer_is_revoker
    )
    assert s.after.get(s.root["delegation_id"]) == s.revocation
    assert s.after.tracks(s.root["delegation_id"]) is True
    # The store surface is unchanged: no removal method was added anywhere.
    assert not hasattr(s.after, "remove")
    assert not hasattr(s.after, "delete")


def test_a_standing_resolver_that_raises_is_read_as_unknown_not_as_standing():
    s = _scenario()

    def _explodes(_withdrawal_record, _revocation):
        raise RuntimeError("resolver exploded")

    evaluation = evaluate_revocation_withdrawal(
        _withdrawal(s, ROOT_ISSUER), [s.revocation], _explodes
    )
    assert evaluation.accepted is False
    assert evaluation.reason_code == "WITHDRAWAL_STANDING_NOT_ESTABLISHED"
    assert evaluation.standing == "unknown"


# ── Nothing existing changed ──────────────────────────────────────────────────────────


def test_the_chain_verifier_still_takes_the_one_argument_resolver_it_always_took():
    s = _scenario()
    result = _chain_result(
        s,
        create_authority_revocation_resolver(
            s.after, resolve_verification_key=resolve_verification_key
        ),
    )
    assert result.state == "invalid"
    assert result.failures[0].code == "REVOKED"


def test_the_report_carries_the_chain_result_through_untouched():
    s = _scenario()
    result = _chain_result(
        s,
        create_authority_revocation_resolver(
            s.after, resolve_verification_key=resolve_verification_key
        ),
    )
    snapshot = dataclasses.asdict(result)
    report = authority_state_report(result, monotonicity="forward")
    assert dataclasses.asdict(report.chain) == snapshot
    assert report.lifecycle is None
    assert report.monotonicity == "forward"
