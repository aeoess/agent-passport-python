# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""AuthorityDelegationV1 unit tests for behaviour the cross-impl vectors do not cover.

The vector file tests/cross_impl/authority-delegation-v1-vectors.json (run through
the separate oracle runner) already exercises the schema, scope, compare, canonical,
verify and budget rules. Its expected states come from the draft; its failure codes
are the TypeScript SDK's vocabulary, not protocol vocabulary. This file only covers
the Python-specific and cross-cutting behaviours the vectors do not: nonce
generation, float/bool rejection, the phase order of chain verification, resolver
edge cases, budget ledger thread-safety, the no-wall-clock rule, the parse-level
size and number-token rules, canonical-pattern anchoring, non-string dict keys,
fixed-width hex checks, the bare-body refusal, revocation type-exactness, scope
grant redundancy performance, and the child issuer's `now` checks.
"""

from __future__ import annotations

import copy
import json
import random
import re
import secrets
import threading
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from agent_passport.v2.authority_delegation import (
    AuthorityDelegationError,
    InMemoryAuthorityBudgetLedger,
    grants_are_canonical,
    is_valid_scope_grant,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    parse_authority_delegation_json,
    scope_grant_covers,
    validate_authority_delegation_shape,
    verify_authority_delegation_chain,
)

_PACKAGE_DIR = Path(__file__).parent.parent.parent / "src" / "agent_passport" / "v2" / "authority_delegation"
_VECTORS_PATH = (
    Path(__file__).parent.parent / "cross_impl" / "authority-delegation-v1-vectors.json"
)


def _keypair() -> tuple[str, str]:
    seed = secrets.token_bytes(32)
    signing_key = SigningKey(seed)
    return seed.hex(), signing_key.verify_key.encode().hex()


def _authority(**overrides) -> dict:
    authority = {
        "scope": {"profile": "aps-hierarchical-v1", "grants": ["*"]},
        "spend": {"mode": "unbounded"},
        "depth": {"remaining": 2},
        "time": {"not_before": "2026-01-01T00:00:00.000Z", "not_after": "2026-01-02T00:00:00.000Z"},
        "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
        "values": {"profile": "aps-values-identifiers-v1", "required": []},
        "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
    }
    authority.update(overrides)
    return authority


def _root_body(**overrides) -> dict:
    body = {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "parent_delegation_id": None,
        "issuer": "did:example:principal",
        "subject": "did:example:agent-a",
        "verification_method": "did:example:principal#key-1",
        "issued_at": "2026-01-01T00:00:00.000Z",
        "authority": _authority(),
    }
    body.update(overrides)
    return body


def _rich_authority(**overrides) -> dict:
    """An authority vector with a concrete (non-wildcard) grant, bounded spend
    and a non-empty required-values list, so every field the trailing-newline
    tests below corrupt is actually present with a corruptible non-empty
    value."""
    return _authority(
        scope={"profile": "aps-hierarchical-v1", "grants": ["commerce:checkout"]},
        spend={"mode": "bounded", "unit": "iso4217:USD:minor", "per_action": "500", "cumulative": "1000"},
        values={"profile": "aps-values-identifiers-v1", "required": ["F-001"]},
        **overrides,
    )


def _verify_one(record: dict, public_key: str):
    return verify_authority_delegation_chain(
        [record],
        now="2026-01-01T00:05:00.000Z",
        resolve_verification_key=lambda *args: public_key,
        trust_root=lambda root: True,
        resolve_revocation=lambda delegation: "active",
    )


class TestNonceGeneration:
    def test_two_root_issuances_get_different_nonces_and_body_is_not_mutated(self):
        seed, _ = _keypair()
        body = _root_body()
        assert "nonce" not in body

        first = issue_authority_delegation(body, seed)
        second = issue_authority_delegation(body, seed)

        assert "nonce" not in body  # the caller's dict was never mutated
        assert re.match(r"^[0-9a-f]{32}$", first["nonce"])
        assert re.match(r"^[0-9a-f]{32}$", second["nonce"])
        assert first["nonce"] != second["nonce"]


class TestFloatAndBoolRejection:
    def _valid_record(self) -> dict:
        seed, _ = _keypair()
        return issue_authority_delegation(_root_body(nonce="00" * 16), seed)

    def test_depth_remaining_as_float_is_rejected(self):
        record = self._valid_record()
        record["authority"] = dict(record["authority"])
        record["authority"]["depth"] = {"remaining": 2.0}
        failures = validate_authority_delegation_shape(record)
        assert any(item.code == "SCHEMA_INVALID" for item in failures)

    def test_reputation_ceiling_as_float_is_rejected(self):
        record = self._valid_record()
        record["authority"] = dict(record["authority"])
        record["authority"]["reputation"] = {"profile": "aps-score-0-100-v1", "ceiling": 80.0}
        failures = validate_authority_delegation_shape(record)
        assert any(item.code == "SCHEMA_INVALID" for item in failures)

    def test_depth_remaining_as_bool_is_rejected(self):
        record = self._valid_record()
        record["authority"] = dict(record["authority"])
        record["authority"]["depth"] = {"remaining": True}
        failures = validate_authority_delegation_shape(record)
        assert any(item.code == "SCHEMA_INVALID" for item in failures)


class _Chain:
    """Builds a signed root and a signed child under it, for the phase-order and
    resolver tests below. Two independent identities (principal, agent-a) so the
    child's issuer/verification_method differ from the root's."""

    def __init__(self):
        self.principal_seed, self.principal_pub = _keypair()
        self.agent_a_seed, self.agent_a_pub = _keypair()

        root_body = _root_body(
            issued_at="2026-01-01T00:00:00.000Z",
            authority=_authority(
                time={"not_before": "2026-01-01T00:00:00.000Z", "not_after": "2026-01-02T00:00:00.000Z"},
            ),
        )
        self.root = issue_authority_delegation(root_body, self.principal_seed)

        child_body = {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": self.root["delegation_id"],
            "issuer": "did:example:agent-a",
            "subject": "did:example:agent-b",
            "verification_method": "did:example:agent-a#key-1",
            "issued_at": "2026-01-01T00:05:00.000Z",
            "authority": _authority(
                depth={"remaining": 1},
                time={"not_before": "2026-01-01T00:10:00.000Z", "not_after": "2026-01-01T00:20:00.000Z"},
            ),
        }

        def resolve_key_for_issuance(issuer, verification_method, issued_at):
            return self._key_table().get((issuer, verification_method))

        self.child = issue_sub_authority_delegation(
            self.root,
            child_body,
            self.agent_a_seed,
            now=child_body["issued_at"],
            resolve_verification_key=resolve_key_for_issuance,
            resolve_revocation=lambda delegation: "active",
        )

    def _key_table(self) -> dict:
        return {
            ("did:example:principal", "did:example:principal#key-1"): self.principal_pub,
            ("did:example:agent-a", "did:example:agent-a#key-1"): self.agent_a_pub,
        }

    def resolve_verification_key(self, issuer, verification_method, issued_at):
        return self._key_table().get((issuer, verification_method))

    def trust_root(self, root_record) -> bool:
        return root_record.get("delegation_id") == self.root["delegation_id"]


class TestPhaseOrder:
    def test_validity_runs_before_revocation_for_all_members(self):
        chain = _Chain()

        def resolve_revocation(delegation):
            return "unknown"

        # now is after the child's not_after (00:20) but still inside the root's
        # window (00:00 day1 through 00:00 day2): only the child is expired.
        result = verify_authority_delegation_chain(
            [chain.root, chain.child],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=chain.resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=resolve_revocation,
        )

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["EXPIRED"]
        assert result.failures[0].index == 1


class TestVerifyInputValidation:
    def test_now_not_canonical_is_invalid_with_no_index(self):
        chain = _Chain()
        result = verify_authority_delegation_chain(
            [chain.root],
            now="not-a-timestamp",
            resolve_verification_key=chain.resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: "active",
        )
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["NONCANONICAL_VALUE"]
        assert result.failures[0].index is None

    @pytest.mark.parametrize("bad_chain", [{"not": "a list"}, "just a string"])
    def test_chain_as_dict_or_string_is_invalid_schema(self, bad_chain):
        result = verify_authority_delegation_chain(
            bad_chain,
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=lambda *a: None,
            trust_root=lambda root: True,
            resolve_revocation=lambda delegation: "active",
        )
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID"]


class TestResolverEdgeCases:
    def test_key_resolver_raising_gives_indeterminate_key_resolution_failed(self):
        chain = _Chain()

        def resolve_verification_key(issuer, verification_method, issued_at):
            raise RuntimeError("boom")

        result = verify_authority_delegation_chain(
            [chain.root],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: "active",
        )
        assert result.state == "indeterminate"
        assert [item.code for item in result.failures] == ["KEY_RESOLUTION_FAILED"]
        assert result.failures[0].index == 0

    def test_key_resolver_returning_64_non_hex_chars_gives_invalid_signature_invalid(self):
        chain = _Chain()

        def resolve_verification_key(issuer, verification_method, issued_at):
            return "g" * 64

        result = verify_authority_delegation_chain(
            [chain.root],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: "active",
        )
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SIGNATURE_INVALID"]
        assert result.failures[0].index == 0

    def test_trust_policy_returning_non_bool_gives_indeterminate_root_untrusted(self):
        chain = _Chain()

        result = verify_authority_delegation_chain(
            [chain.root],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=chain.resolve_verification_key,
            trust_root=lambda root: 1,
            resolve_revocation=lambda delegation: "active",
        )
        assert result.state == "indeterminate"
        assert [item.code for item in result.failures] == ["ROOT_UNTRUSTED"]
        assert result.failures[0].index == 0


class TestBudgetLedgerConcurrency:
    """A smoke test: it exercises the ledger under concurrent reservations
    and checks the final counts are exact, but on its own it does not prove
    the lock is necessary. It would very likely still pass, at least most of
    the time, with a lock that did nothing, because CPython's GIL already
    serializes the individual dict and attribute operations inside each
    critical section; this test does not control for that."""

    def test_eight_threads_reserving_against_a_cumulative_of_100(self):
        seed, _ = _keypair()
        leaf = issue_authority_delegation(
            _root_body(
                authority=_authority(
                    spend={"mode": "bounded", "unit": "iso4217:USD:minor", "per_action": "1", "cumulative": "100"},
                ),
            ),
            seed,
        )
        ledger = InMemoryAuthorityBudgetLedger()
        results: list = []
        results_lock = threading.Lock()

        def worker(thread_index: int) -> None:
            for call_index in range(50):
                action_ref = f"{thread_index:02x}{call_index:062x}"
                result = ledger.reserve([leaf], action_ref, "iso4217:USD:minor", "1")
                with results_lock:
                    results.append(result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        succeeded = [item for item in results if item.ok and item.code == "RESERVED"]
        assert len(succeeded) == 100
        assert len(results) == 400
        assert ledger.counter(leaf["delegation_id"]) == {"reserved": "100", "committed": "0"}


class TestNoWallClock:
    def test_source_contains_no_wall_clock_calls(self):
        banned = ("datetime.now", "utcnow", "date.today", "time.time(", "time.monotonic(")
        for path in sorted(_PACKAGE_DIR.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for token in banned:
                assert token not in text, f"{path.name} contains {token!r}"


class TestParseWireLimits:
    def test_oversized_input_is_rejected(self):
        oversized = "x" * 1_048_577
        with pytest.raises(AuthorityDelegationError):
            parse_authority_delegation_json(oversized)

    def test_depth_remaining_written_as_2_point_0_is_rejected(self):
        seed, _ = _keypair()
        record = issue_authority_delegation(_root_body(nonce="00" * 16), seed)
        source = json.dumps(record)
        assert '"remaining": 2' in source
        source = source.replace('"remaining": 2', '"remaining": 2.0')
        with pytest.raises(AuthorityDelegationError):
            parse_authority_delegation_json(source)


def _append_newline_to_nonce(record: dict) -> dict:
    record["nonce"] = record["nonce"] + "\n"
    return record


def _append_newline_to_delegation_id(record: dict) -> dict:
    record["delegation_id"] = record["delegation_id"] + "\n"
    return record


def _append_newline_to_signature(record: dict) -> dict:
    record["signature"] = record["signature"] + "\n"
    return record


def _append_newline_to_issued_at(record: dict) -> dict:
    record["issued_at"] = record["issued_at"] + "\n"
    return record


def _append_newline_to_time_not_before(record: dict) -> dict:
    record["authority"]["time"]["not_before"] = record["authority"]["time"]["not_before"] + "\n"
    return record


def _append_newline_to_spend_per_action(record: dict) -> dict:
    record["authority"]["spend"]["per_action"] = record["authority"]["spend"]["per_action"] + "\n"
    return record


def _append_newline_to_spend_unit(record: dict) -> dict:
    record["authority"]["spend"]["unit"] = record["authority"]["spend"]["unit"] + "\n"
    return record


def _append_newline_to_values_entry(record: dict) -> dict:
    required = record["authority"]["values"]["required"]
    required[0] = required[0] + "\n"
    return record


def _append_newline_to_scope_grant(record: dict) -> dict:
    grants = record["authority"]["scope"]["grants"]
    grants[0] = grants[0] + "\n"
    return record


_TRAILING_NEWLINE_MUTATIONS = [
    ("nonce", _append_newline_to_nonce),
    ("delegation_id", _append_newline_to_delegation_id),
    ("signature", _append_newline_to_signature),
    ("issued_at", _append_newline_to_issued_at),
    ("time.not_before", _append_newline_to_time_not_before),
    ("spend.per_action", _append_newline_to_spend_per_action),
    ("spend.unit", _append_newline_to_spend_unit),
    ("values.required entry", _append_newline_to_values_entry),
    ("scope grant", _append_newline_to_scope_grant),
]


class TestTrailingNewlineRejected:
    """Python's `$` also matches just before a trailing "\\n", unlike
    JavaScript's, so every anchored pattern in the package must use
    fullmatch. Each case here appends "\\n" to one canonical-looking field of
    an otherwise valid, properly signed root record and checks that
    verification now reports it invalid, rather than silently accepting a
    value that only looks canonical up to its last real character."""

    def _valid_root(self) -> tuple[dict, str]:
        seed, public_key = _keypair()
        record = issue_authority_delegation(_root_body(authority=_rich_authority()), seed)
        return record, public_key

    @pytest.mark.parametrize("name, mutate", _TRAILING_NEWLINE_MUTATIONS, ids=[item[0] for item in _TRAILING_NEWLINE_MUTATIONS])
    def test_field_with_trailing_newline_is_invalid(self, name, mutate):
        record, public_key = self._valid_root()
        # Sanity: the unmutated record verifies clean before we corrupt it.
        assert _verify_one(copy.deepcopy(record), public_key).state == "valid"

        corrupted = mutate(copy.deepcopy(record))
        result = _verify_one(corrupted, public_key)
        assert result.state == "invalid", f"{name}: expected invalid, got {result.state} {result.failures}"

    def test_reserve_action_ref_with_trailing_newline_is_conflict_and_counters_unchanged(self):
        leaf, _ = self._valid_root()
        ledger = InMemoryAuthorityBudgetLedger()
        action_ref = "a" * 64 + "\n"

        result = ledger.reserve([leaf], action_ref, "iso4217:USD:minor", "1")

        assert result.ok is False
        assert result.code == "CONFLICT"
        assert ledger.counter(leaf["delegation_id"]) == {"reserved": "0", "committed": "0"}


class TestNonStringDictKey:
    """A dict with a non-string key must yield a defined SCHEMA_INVALID
    result rather than raising."""

    def test_depth_with_a_non_string_key_is_invalid_schema_invalid_no_exception(self):
        seed, public_key = _keypair()
        record = issue_authority_delegation(_root_body(authority=_rich_authority()), seed)
        record = copy.deepcopy(record)
        record["authority"]["depth"] = {"remaining": 2, 1: 3}

        result = _verify_one(record, public_key)  # must not raise

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID"]


class TestSpacedHexKeyRejected:
    """bytes.fromhex tolerates whitespace between byte pairs, so a resolved
    key written with a space after every two hex digits must not verify even
    though it decodes to the right bytes."""

    def test_key_resolver_returning_spaced_hex_gives_invalid_signature_invalid(self):
        chain = _Chain()
        spaced_principal_pub = " ".join(
            chain.principal_pub[i : i + 2] for i in range(0, len(chain.principal_pub), 2)
        )
        assert len(spaced_principal_pub) != 64  # sanity: this is not a bare 64-hex string

        def resolve_verification_key(issuer, verification_method, issued_at):
            return spaced_principal_pub

        result = verify_authority_delegation_chain(
            [chain.root],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: "active",
        )

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SIGNATURE_INVALID"]


class TestIssueBareBodyRequired:
    """An issuer must refuse a body that already carries delegation_id or
    signature, or that is not an object at all, rather than silently hashing
    the stray member into a record whose id can never recompute."""

    def test_body_with_delegation_id_raises_schema_invalid(self):
        seed, _ = _keypair()
        body = _root_body(delegation_id="sha256:" + "0" * 64)
        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation(body, seed)
        assert exc_info.value.code == "SCHEMA_INVALID"

    def test_body_with_signature_raises_schema_invalid(self):
        seed, _ = _keypair()
        body = _root_body(signature="0" * 128)
        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation(body, seed)
        assert exc_info.value.code == "SCHEMA_INVALID"

    def test_issuing_from_a_list_raises_schema_invalid(self):
        seed, _ = _keypair()
        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation([1, 2, 3], seed)
        assert exc_info.value.code == "SCHEMA_INVALID"


class _ActiveLookalike(str):
    """A str subclass equal to "active" by value but not by exact type."""


class TestRevocationStrSubclassIsUnknown:
    """A str subclass instance that merely compares equal to "active" must
    not be treated as active, in either verify.py or issue.py."""

    def test_verify_treats_str_subclass_as_revocation_unknown(self):
        chain = _Chain()

        result = verify_authority_delegation_chain(
            [chain.root],
            now="2026-01-01T00:25:00.000Z",
            resolve_verification_key=chain.resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: _ActiveLookalike("active"),
        )

        assert result.state == "indeterminate"
        assert [item.code for item in result.failures] == ["REVOCATION_UNKNOWN"]

    def test_issue_sub_treats_str_subclass_as_revocation_unknown(self):
        chain = _Chain()
        child_body = {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": chain.root["delegation_id"],
            "issuer": "did:example:agent-a",
            "subject": "did:example:agent-b",
            "verification_method": "did:example:agent-a#key-1",
            "issued_at": "2026-01-01T00:05:00.000Z",
            "authority": _authority(
                depth={"remaining": 1},
                time={"not_before": "2026-01-01T00:10:00.000Z", "not_after": "2026-01-01T00:20:00.000Z"},
            ),
        }

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_sub_authority_delegation(
                chain.root,
                child_body,
                chain.agent_a_seed,
                now=child_body["issued_at"],
                resolve_verification_key=chain.resolve_verification_key,
                resolve_revocation=lambda delegation: _ActiveLookalike("active"),
            )
        assert exc_info.value.code == "REVOCATION_UNKNOWN"


class TestReserveChainTypeChecked:
    """A verified_chain that is not a list or tuple must return CONFLICT
    rather than raising out of len()/indexing."""

    def test_reserve_with_none_chain_returns_conflict(self):
        ledger = InMemoryAuthorityBudgetLedger()

        result = ledger.reserve(None, "a" * 64, "iso4217:USD:minor", "1")

        assert result.ok is False
        assert result.code == "CONFLICT"


class TestLedgerNonStringKeysReturnDefined:
    """mark_dispatched, commit and cancel with an action_ref that is not a
    str must return NOT_FOUND rather than raising out of an unhashable dict
    key; counter with a non-str id must return zeroed counters the same way
    it does for an id it has never seen."""

    def test_mark_dispatched_with_list_action_ref_returns_not_found(self):
        ledger = InMemoryAuthorityBudgetLedger()
        result = ledger.mark_dispatched(["not", "a", "string"])
        assert result.ok is False
        assert result.code == "NOT_FOUND"

    def test_commit_with_list_action_ref_returns_not_found(self):
        ledger = InMemoryAuthorityBudgetLedger()
        result = ledger.commit(["not", "a", "string"])
        assert result.ok is False
        assert result.code == "NOT_FOUND"

    def test_cancel_with_list_action_ref_returns_not_found(self):
        ledger = InMemoryAuthorityBudgetLedger()
        result = ledger.cancel(["not", "a", "string"])
        assert result.ok is False
        assert result.code == "NOT_FOUND"

    def test_counter_with_list_id_returns_zeroed_counters(self):
        ledger = InMemoryAuthorityBudgetLedger()
        assert ledger.counter(["not", "a", "string"]) == {"reserved": "0", "committed": "0"}


def _pairwise_reference_grants_are_canonical(grants) -> bool:
    """The straightforward O(n^2) pairwise definition, kept only in this
    test as the oracle grants_are_canonical is checked against: every grant
    must be valid and strictly sorted, and no grant may be covered by any
    other grant in the list."""
    if type(grants) is not list:
        return False
    for i, grant in enumerate(grants):
        if not is_valid_scope_grant(grant):
            return False
        if i > 0 and grants[i - 1] >= grant:
            return False
        for j in range(len(grants)):
            if i != j and scope_grant_covers(grants[j], grant):
                return False
    return True


_GRANT_SEGMENT_POOL = (
    "a", "b", "c", "commerce", "travel", "checkout", "book", "x1", "y-2", "AA", "z_9",
)
_INVALID_GRANT_POOL = (
    "", "a" * 300, ":", "a::b", "a:*:b", "*:a", "-bad", "*" + "*", "a:" + "!" * 3,
)


def _random_valid_grant(rng: random.Random) -> str:
    if rng.random() < 0.08:
        return "*"
    depth = rng.randint(1, 4)
    segments = [rng.choice(_GRANT_SEGMENT_POOL) for _ in range(depth)]
    if rng.random() < 0.4:
        segments.append("*")
    return ":".join(segments)


def _generate_grant_list(rng: random.Random) -> list:
    size = rng.randint(0, 14)
    grants = []
    for _ in range(size):
        if rng.random() < 0.12:
            grants.append(rng.choice(_INVALID_GRANT_POOL))
        else:
            grants.append(_random_valid_grant(rng))
    if grants and rng.random() < 0.25:
        grants.append(rng.choice(grants))  # inject a duplicate
    if rng.random() < 0.5:
        rng.shuffle(grants)
    return grants


class TestGrantsAreCanonicalMatchesPairwiseReference:
    """grants_are_canonical was rewritten to check redundancy in
    O(n * segments) instead of the O(n^2) pairwise scan the definition
    suggests (8000 grants used to take about 31 seconds). This checks the
    rewrite against a straightforward pairwise reference implementation
    over many deterministically generated lists mixing exact grants,
    wildcards, the bare "*", unsorted order, duplicates and invalid
    entries."""

    def test_matches_reference_over_2000_generated_lists(self):
        rng = random.Random(20260919)
        for case_index in range(2000):
            grants = _generate_grant_list(rng)
            fast = grants_are_canonical(list(grants))
            reference = _pairwise_reference_grants_are_canonical(list(grants))
            assert fast == reference, f"case {case_index}: {grants!r} -> fast={fast} reference={reference}"


class TestGrantsAreCanonicalPerformance:
    def test_20000_sorted_exact_grants_checked_under_one_second(self):
        grants = [f"seg{i:06d}" for i in range(20000)]
        assert grants == sorted(grants)  # already strictly sorted, no wildcards to redund against

        start = time.perf_counter()
        result = grants_are_canonical(grants)
        elapsed = time.perf_counter() - start

        assert result is True
        assert elapsed < 1.0, f"took {elapsed:.3f}s"


class TestIssueSubAuthorityDelegationNow:
    """issue_sub_authority_delegation requires the parent to be currently
    valid at the issuer-supplied `now`, independently of the child's own
    issued_at."""

    def test_parent_valid_at_issued_at_but_expired_at_now_raises_expired(self):
        chain = _Chain()
        child_body = {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": chain.root["delegation_id"],
            "issuer": "did:example:agent-a",
            "subject": "did:example:agent-b",
            "verification_method": "did:example:agent-a#key-1",
            "issued_at": "2026-01-01T00:05:00.000Z",  # inside the parent's window
            "authority": _authority(
                depth={"remaining": 1},
                time={"not_before": "2026-01-01T00:10:00.000Z", "not_after": "2026-01-01T00:20:00.000Z"},
            ),
        }

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_sub_authority_delegation(
                chain.root,
                child_body,
                chain.agent_a_seed,
                now="2026-01-02T00:00:00.000Z",  # exactly the parent's not_after: expired
                resolve_verification_key=chain.resolve_verification_key,
                resolve_revocation=lambda delegation: "active",
            )
        assert exc_info.value.code == "EXPIRED"

    def test_now_before_the_parents_not_before_raises_not_yet_valid(self):
        chain = _Chain()
        child_body = {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": chain.root["delegation_id"],
            "issuer": "did:example:agent-a",
            "subject": "did:example:agent-b",
            "verification_method": "did:example:agent-a#key-1",
            "issued_at": "2026-01-01T00:05:00.000Z",
            "authority": _authority(
                depth={"remaining": 1},
                time={"not_before": "2026-01-01T00:10:00.000Z", "not_after": "2026-01-01T00:20:00.000Z"},
            ),
        }

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_sub_authority_delegation(
                chain.root,
                child_body,
                chain.agent_a_seed,
                now="2025-12-31T23:59:59.999Z",  # before the parent's not_before
                resolve_verification_key=chain.resolve_verification_key,
                resolve_revocation=lambda delegation: "active",
            )
        assert exc_info.value.code == "NOT_YET_VALID"

    def test_malformed_now_raises_noncanonical_value(self):
        chain = _Chain()
        child_body = {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": chain.root["delegation_id"],
            "issuer": "did:example:agent-a",
            "subject": "did:example:agent-b",
            "verification_method": "did:example:agent-a#key-1",
            "issued_at": "2026-01-01T00:05:00.000Z",
            "authority": _authority(
                depth={"remaining": 1},
                time={"not_before": "2026-01-01T00:10:00.000Z", "not_after": "2026-01-01T00:20:00.000Z"},
            ),
        }

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_sub_authority_delegation(
                chain.root,
                child_body,
                chain.agent_a_seed,
                now="not-a-timestamp",
                resolve_verification_key=chain.resolve_verification_key,
                resolve_revocation=lambda delegation: "active",
            )
        assert exc_info.value.code == "NONCANONICAL_VALUE"


def _load_vectors() -> dict:
    return json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))


def _vector_key_resolver(entries):
    table = {(entry["issuer"], entry["verification_method"]): entry["public_key_hex"] for entry in entries}

    def resolve(issuer, verification_method, issued_at):
        return table.get((issuer, verification_method))

    return resolve


_ISSUE_CHILD_REFUSE_EXPECTED_CODES = {
    "AD-I04": "SCOPE_WIDENING",
    "AD-I05": "ISSUED_AT_OUTSIDE_PARENT",
    "AD-I06": "ISSUED_AT_OUTSIDE_PARENT",
    "AD-I07": "REVOKED",
    "AD-I08": "SIGNATURE_INVALID",
    "AD-I09": "REVOCATION_UNKNOWN",
    "AD-I10": "KEY_RESOLUTION_FAILED",
    "AD-I11": "DEPTH_EXHAUSTED",
    "AD-I12": "PARENT_MISMATCH",
    "AD-I13": "CHAIN_CONTINUITY",
    "AD-I14": "NONCANONICAL_VALUE",
}


def _issue_child_refuse_cases() -> list:
    vectors = _load_vectors()
    seeds = {entry["label"]: entry["seed_hex"] for entry in vectors["keys"]}
    cases = []
    for case in vectors["cases"]:
        if case["kind"] != "issue_child" or case["expected"]["result"] != "refuse":
            continue
        if case["id"] not in _ISSUE_CHILD_REFUSE_EXPECTED_CODES:
            continue
        cases.append((case, seeds[case["signing_key"]]))
    return cases


_ISSUE_CHILD_REFUSE_CASES = _issue_child_refuse_cases()


class TestIssueChildRefuseVectorsRaiseExpectedCode:
    """For every issue_child vector whose expected result is "refuse", check
    that issue_sub_authority_delegation raises AuthorityDelegationError with
    the specific code the case is about, not just that it raises. Only the
    ids in _ISSUE_CHILD_REFUSE_EXPECTED_CODES are checked, since new cases
    may be added to the vector file later without a code assigned here yet."""

    @pytest.mark.parametrize(
        "case, seed", _ISSUE_CHILD_REFUSE_CASES, ids=[c["id"] for c, _ in _ISSUE_CHILD_REFUSE_CASES],
    )
    def test_refuse_case_raises_expected_code(self, case, seed):
        expected_code = _ISSUE_CHILD_REFUSE_EXPECTED_CODES[case["id"]]
        status = case["context"]["revocation"]["parent"]

        def resolve_revocation(delegation):
            if status == "unavailable":
                raise RuntimeError("revocation source unavailable")
            return status

        now = case["context"]["now"]

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_sub_authority_delegation(
                case["parent"],
                case["body"],
                seed,
                now=now,
                resolve_verification_key=_vector_key_resolver(case["context"]["keys"]),
                resolve_revocation=resolve_revocation,
            )
        assert exc_info.value.code == expected_code, (
            f"{case['id']}: expected {expected_code}, got {exc_info.value.code}"
        )
