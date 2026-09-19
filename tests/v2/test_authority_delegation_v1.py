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
grant redundancy and narrowing performance, the child issuer's `now` checks,
and I-JSON well-formedness for in-memory Python values other than the exact
str/dict/list json.loads produces.
"""

from __future__ import annotations

import copy
import json
import random
import re
import secrets
import threading
import time
from collections import OrderedDict
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from agent_passport.v2.authority_delegation import (
    AuthorityDelegationError,
    InMemoryAuthorityBudgetLedger,
    authority_delegation_body,
    compute_authority_delegation_id_for_write,
    grants_are_canonical,
    is_canonical_timestamp,
    is_valid_scope_grant,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    parse_authority_delegation_json,
    scope_grant_covers,
    scope_narrows,
    sign_authority_delegation,
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
        # The whole-record I-JSON walk and the depth facet's own exact-keys
        # check both independently reject the non-str key 1, so two SCHEMA_INVALID
        # failures are expected here, not exactly one.
        assert result.failures
        assert all(item.code == "SCHEMA_INVALID" for item in result.failures)


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


class TestRootIssuerIssuesRootsOnly:
    """issue_authority_delegation issues roots only (draft section 3.1 line
    428; section 3.6 lines 695-704). It refuses a body whose
    parent_delegation_id is not null with PARENT_MISMATCH, whether or not a
    real, sound parent exists for that body; a sound root body is unaffected;
    and the child issuer, which no longer calls the root issuer internally,
    still produces exactly the bytes the root issuer used to produce for the
    same body."""

    def test_valid_child_body_under_a_real_sound_parent_is_refused(self):
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
        # Sanity: this is exactly the body the child issuer accepts under
        # chain.root, so the refusal below is not a symptom of an otherwise
        # malformed or orphaned body.
        issued = issue_sub_authority_delegation(
            chain.root,
            dict(child_body),
            chain.agent_a_seed,
            now=child_body["issued_at"],
            resolve_verification_key=chain.resolve_verification_key,
            resolve_revocation=lambda delegation: "active",
        )
        assert issued["parent_delegation_id"] == chain.root["delegation_id"]

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation(dict(child_body), chain.agent_a_seed)
        assert exc_info.value.code == "PARENT_MISMATCH"

    def test_orphan_child_body_is_refused(self):
        seed, _ = _keypair()
        body = _root_body(
            parent_delegation_id="sha256:" + "a" * 64,
            authority=_authority(
                scope={"profile": "aps-hierarchical-v1", "grants": ["*"]},
                spend={"mode": "unbounded"},
                depth={"remaining": 255},
            ),
        )

        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation(body, seed)
        assert exc_info.value.code == "PARENT_MISMATCH"

    def test_sound_root_body_still_issues_and_id_recomputes(self):
        seed, _ = _keypair()
        body = _root_body()

        record = issue_authority_delegation(body, seed)

        assert record["parent_delegation_id"] is None
        assert (
            compute_authority_delegation_id_for_write(authority_delegation_body(record))
            == record["delegation_id"]
        )

    def test_child_issuer_output_is_byte_identical_to_the_raw_helpers(self):
        chain = _Chain()

        unsigned = authority_delegation_body(chain.child)
        recomputed_id = compute_authority_delegation_id_for_write(unsigned)
        assert recomputed_id == chain.child["delegation_id"]

        recomputed_signature = sign_authority_delegation(
            {**unsigned, "delegation_id": recomputed_id}, chain.agent_a_seed
        )
        assert recomputed_signature == chain.child["signature"]


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


class TestReserveUnitTypeChecked:
    """A unit that is not an exact str must return CONFLICT before any
    counter or reservation state changes, on a chain with no bounded member
    (so the value of the unit would otherwise never be checked at all)."""

    @pytest.mark.parametrize("bad_unit", [["x"], {"u": 1}, True, 1])
    def test_non_string_unit_on_unbounded_chain_returns_conflict(self, bad_unit):
        seed, _ = _keypair()
        leaf = issue_authority_delegation(_root_body(), seed)
        ledger = InMemoryAuthorityBudgetLedger()
        action_ref = "b" * 64

        refused = ledger.reserve([leaf], action_ref, bad_unit, "1")
        assert refused.ok is False
        assert refused.code == "CONFLICT"

        retry = ledger.reserve([leaf], action_ref, "iso4217:USD:minor", "1")
        assert retry.ok is True
        assert retry.code == "RESERVED"

    def test_string_unit_on_unbounded_chain_reserves_as_before(self):
        seed, _ = _keypair()
        leaf = issue_authority_delegation(_root_body(), seed)
        ledger = InMemoryAuthorityBudgetLedger()
        action_ref = "c" * 64

        result = ledger.reserve([leaf], action_ref, "iso4217:USD:minor", "1")

        assert result.ok is True
        assert result.code == "RESERVED"


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


def _pairwise_reference_scope_narrows(parent, child) -> bool:
    """The straightforward O(len(parent) * len(child)) pairwise definition,
    kept only in this test as the oracle scope_narrows is checked against."""
    return all(any(scope_grant_covers(parent_grant, grant) for parent_grant in parent) for grant in child)


_SCOPE_NARROWS_POOL = ("a", "ab", "b", "commerce", "travel", "checkout", "x1", "y-2", "AA", "z9")


def _make_canonical_grant_list(rng: random.Random) -> list:
    """A random valid, sorted, irredundant grant list.

    Built by generating a candidate set from a vocabulary that deliberately
    includes both "a" and "ab" (so some generated pairs pit "a:*" against
    the unrelated exact grant "ab:x", a shared-character-not-shared-segment
    case), then dropping anything a remaining candidate already covers.
    This uses the library's own scope_grant_covers and is_valid_scope_grant
    as ground truth for constructing the fixture; those are not the
    function under test here.
    """
    candidates = set()
    for _ in range(rng.randint(0, 8)):
        if rng.random() < 0.12:
            candidates.add("*")
            continue
        depth = rng.randint(1, 3)
        segments = [rng.choice(_SCOPE_NARROWS_POOL) for _ in range(depth)]
        if rng.random() < 0.5:
            segments.append("*")
        candidates.add(":".join(segments))
    valid = [grant for grant in candidates if is_valid_scope_grant(grant)]
    kept = [
        grant for grant in valid
        if not any(scope_grant_covers(other, grant) for other in valid if other != grant)
    ]
    return sorted(kept)


class TestScopeNarrowsMatchesPairwiseReference:
    """scope_narrows was rewritten from the pairwise O(len(parent) *
    len(child)) scan to a linear one (a trusted root and two children with
    50,000 grants each used to take 59 seconds to verify). This checks the
    rewrite against a straightforward pairwise reference implementation
    over many deterministically generated pairs of already-canonical grant
    lists, including the bare "*", nested wildcards, and grants whose
    strings share a character but not a segment."""

    def test_matches_reference_over_2000_generated_canonical_pairs(self):
        rng = random.Random(20260920)
        for case_index in range(2000):
            parent = _make_canonical_grant_list(rng)
            child = _make_canonical_grant_list(rng)
            assert grants_are_canonical(parent)
            assert grants_are_canonical(child)
            fast = scope_narrows(parent, child)
            reference = _pairwise_reference_scope_narrows(parent, child)
            assert fast == reference, (
                f"case {case_index}: parent={parent!r} child={child!r} -> fast={fast} reference={reference}"
            )

    def test_shared_character_not_shared_segment_is_not_covered(self):
        # "ab" shares its leading character with "a" but is a different,
        # unrelated single segment: "a:*" must not cover "ab:x".
        assert scope_narrows(["a:*"], ["ab:x"]) is False
        assert _pairwise_reference_scope_narrows(["a:*"], ["ab:x"]) is False

    def test_bare_wildcard_parent_covers_everything(self):
        assert scope_narrows(["*"], ["anything:at:all", "commerce:*"]) is True

    def test_bare_wildcard_child_requires_bare_wildcard_parent(self):
        assert scope_narrows(["commerce:*"], ["*"]) is False


class TestScopeNarrowsPerformance:
    def test_50000_exact_grants_each_side_compare_under_one_second(self):
        parent = [f"seg{i:06d}" for i in range(50000)]
        child = [f"seg{i:06d}" for i in range(50000)]

        start = time.perf_counter()
        result = scope_narrows(parent, child)
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


class _NoncharacterStr(str):
    """A str subclass, used to check that the I-JSON walk still examines a
    string built as a subclass instance rather than a plain str."""


class _RecordTypeAlias(str):
    """A str subclass equal by content to the v1 record_type, used to check
    that validate_authority_delegation_shape's recognised-type branch tests
    record_type by exact type, not merely by ==."""


class _SubjectAliasKey(str):
    """A str subclass whose own character data is "subjectX" but that
    compares and hashes exactly as the plain string "subject", so a Python
    dict lookup or a set-equality check (as _exact_keys performs) treats it
    as interchangeable with "subject" while an encoder that reads a key's
    character data directly, as RFC 8785 JCS does, would use "subjectX" for
    the member name instead."""

    def __new__(cls):
        return str.__new__(cls, "subjectX")

    def __eq__(self, other):
        return str.__eq__("subject", other)

    def __hash__(self):
        return str.__hash__("subject")


def _bare_valid_record(authority: dict) -> dict:
    """A record with correctly formatted (but not cryptographically real)
    delegation_id, signature and nonce fields, for exercising the shape and
    chain-verification checks directly without going through issuance
    (which would itself refuse a body whose scope facet is already
    invalid, before this test ever got to see the walk's behaviour)."""
    return {
        "record_type": "aps:authority-delegation:v1",
        "version": "1.0",
        "delegation_id": "sha256:" + "0" * 64,
        "parent_delegation_id": None,
        "issuer": "did:example:principal",
        "subject": "did:example:agent-a",
        "verification_method": "did:example:principal#key-1",
        "issued_at": "2026-01-01T00:00:00.000Z",
        "nonce": "00" * 16,
        "authority": authority,
        "signature": "0" * 128,
    }


class TestNonIJsonValuesAnywhereInRecord:
    """The record-wide I-JSON walk must catch a surrogate, a noncharacter,
    or a value that is not JSON at all, wherever it is nested in the
    record, including inside a facet whose own profile this package does
    not support and so never examines further itself, and must recognize a
    dict, list or str subclass the same way it recognizes the exact builtin
    type."""

    def _record_with_scope_grants(self, grants_value) -> dict:
        authority = _authority(scope={"profile": "custom-unsupported-v9", "grants": grants_value})
        return _bare_valid_record(authority)

    def test_tuple_containing_a_noncharacter_is_invalid(self):
        record = self._record_with_scope_grants(("x", "y" + "\ufdd0"))
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_ordereddict_key_containing_a_noncharacter_is_invalid(self):
        record = self._record_with_scope_grants(OrderedDict([("segment" + "\ufdd0", "value")]))
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_str_subclass_containing_a_noncharacter_is_invalid(self):
        record = self._record_with_scope_grants(_NoncharacterStr("bad" + "\ufdd0"))
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_set_value_is_invalid(self):
        record = self._record_with_scope_grants({"a", "b"})
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_bytes_value_is_invalid(self):
        record = self._record_with_scope_grants(b"bytes")
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_nan_float_value_is_invalid(self):
        record = self._record_with_scope_grants(float("nan"))
        result = _verify_one(record, "unused")
        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    def test_a_valid_root_is_unaffected(self):
        seed, public_key = _keypair()
        record = issue_authority_delegation(_root_body(nonce="00" * 16), seed)
        result = _verify_one(record, public_key)
        assert result.state == "valid"


class TestDictKeyTypeMustBeExactStr:
    """Round 2 of the requirement text: a dict key is examined as a field
    name only when type(key) is str, never merely when it compares and
    hashes as one. Without that, a key built to compare and hash as
    "subject" while holding different character data would pass both
    _exact_keys's set comparison and a plain top["subject"] lookup, making
    the record look like an ordinary valid v1 body with every field
    present, and a canonicalizer that reads the key's own character data
    (as RFC 8785 JCS does) would sign a member name the schema check never
    saw."""

    def test_key_that_compares_as_subject_but_reads_as_subjectx_is_schema_invalid(self):
        record = _bare_valid_record(_authority())
        alias = _SubjectAliasKey()
        assert alias == "subject" and hash(alias) == hash("subject")
        record[alias] = record.pop("subject")

        result = _verify_one(record, "unused")

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID"]


class TestContainerTypeItselfMustBeExact:
    """Round 2 of the requirement text applied completely: a tuple, an
    OrderedDict or a str subclass is not plain JSON data because of its own
    runtime type, not only because of what it might hold. Each value below
    is otherwise an unremarkable scope grants value (one valid-looking
    grant), which isolates the container-type check itself from the
    noncharacter-content case TestNonIJsonValuesAnywhereInRecord already
    covers above. Each is placed (a) inside a v1 facet, (b) inside a facet
    with an unsupported profile, and (c) inside a record whose version is
    "2.0", reproducing the same combined-failure-list shape a noncharacter
    already produces in those same three places."""

    _BAD_VALUES = [
        pytest.param(("commerce:checkout",), id="tuple"),
        pytest.param(OrderedDict([("commerce:checkout", True)]), id="ordereddict"),
        pytest.param(_NoncharacterStr("commerce:checkout"), id="str-subclass"),
    ]

    @pytest.mark.parametrize("bad_value", _BAD_VALUES)
    def test_inside_a_v1_facet_is_schema_invalid_from_two_sources(self, bad_value):
        authority = _authority(scope={"profile": "aps-hierarchical-v1", "grants": bad_value})
        record = _bare_valid_record(authority)

        result = _verify_one(record, "unused")

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "SCHEMA_INVALID"]

    @pytest.mark.parametrize("bad_value", _BAD_VALUES)
    def test_inside_an_unsupported_profile_facet_combines_with_unsupported_profile(self, bad_value):
        authority = _authority(scope={"profile": "custom-unsupported-v9", "grants": bad_value})
        record = _bare_valid_record(authority)

        result = _verify_one(record, "unused")

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]

    @pytest.mark.parametrize("bad_value", _BAD_VALUES)
    def test_inside_a_record_with_unknown_version_combines_with_unsupported_version(self, bad_value):
        authority = _authority(scope={"profile": "aps-hierarchical-v1", "grants": bad_value})
        record = _bare_valid_record(authority)
        record["version"] = "2.0"

        result = _verify_one(record, "unused")

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_VERSION"]


class TestCyclicContainerIsNotPlainJsonData:
    """A container that contains itself at any depth is not plain JSON
    data, and the walk must terminate rather than loop forever. Placed
    inside a facet with an unsupported profile, so the result also shows
    the cycle combines with UNSUPPORTED_PROFILE the same way a noncharacter
    does there, and the overall state stays "invalid" (a SCHEMA_INVALID
    code is present, so it is never "unsupported")."""

    def test_cycle_inside_an_unsupported_profile_facet_is_schema_invalid(self):
        grants: list = []
        grants.append(grants)
        authority = _authority(scope={"profile": "custom-unsupported-v9", "grants": grants})
        record = _bare_valid_record(authority)

        result = _verify_one(record, "unused")

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID", "UNSUPPORTED_PROFILE"]


class TestIntegerMagnitudeMustFitADouble:
    """An integer this package will canonicalize as a JSON number must
    itself survive conversion to an IEEE 754 double: float(v) raising
    OverflowError is round 2's test for that. Placed inside a record whose
    version is unrecognised, so it is reached only by the record-wide walk,
    never by any version="1.0" facet-specific integer check, and the wire
    form is exercised through parse_authority_delegation_json directly,
    since json.loads decodes an arbitrarily large integer literal exactly
    (unlike JSON.parse, which would already have turned it into Infinity)."""

    def _probe_with_depth_remaining(self, value) -> dict:
        body = _root_body(version="2.0", authority=_authority(depth={"remaining": value}))
        return {**body, "nonce": "0" * 32, "delegation_id": "sha256:" + "0" * 64, "signature": "0" * 128}

    def test_a_400_digit_integer_is_schema_invalid_and_unsupported_version(self):
        probe = self._probe_with_depth_remaining(10**400)

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["SCHEMA_INVALID", "UNSUPPORTED_VERSION"]

    def test_a_300_digit_integer_stays_unsupported_version_only(self):
        probe = self._probe_with_depth_remaining(10**300)

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["UNSUPPORTED_VERSION"]

    def test_parse_authority_delegation_json_reports_the_verifiers_first_code(self):
        probe = self._probe_with_depth_remaining(10**400)
        direct_failures = validate_authority_delegation_shape(probe)
        wire_text = json.dumps(probe)

        with pytest.raises(AuthorityDelegationError) as exc_info:
            parse_authority_delegation_json(wire_text)

        assert exc_info.value.code == direct_failures[0].code


class TestSecond60OnlyAtLastMomentOfMonth:
    """A canonical timestamp's second field of 60 is valid only when the
    hour is 23, the minute is 59, and the day is the last day of its month
    in the proleptic Gregorian calendar (RFC 3339 section 5.7; Appendix D's
    "YYYY-MM-DDT23:59:60Z"). Every other second-60 timestamp is invalid.
    Exercises the section 3 public entry point, is_canonical_timestamp,
    directly."""

    @pytest.mark.parametrize(
        "timestamp",
        [
            "2016-12-31T23:59:60.000Z",
            "2026-06-30T23:59:60.000Z",
            "2028-02-29T23:59:60.999Z",
            "2027-02-28T23:59:60.000Z",
            "0000-02-29T23:59:60.000Z",
        ],
    )
    def test_second_60_at_2359_on_the_last_day_of_the_month_is_valid(self, timestamp):
        assert is_canonical_timestamp(timestamp) is True

    @pytest.mark.parametrize(
        "timestamp",
        [
            "2026-04-08T12:00:60.000Z",  # the former accepted example
            "2026-06-29T23:59:60.000Z",  # not the last day of the month
            "2016-12-31T23:58:60.000Z",  # minute 58, not 59
            "2016-12-31T22:59:60.000Z",  # hour 22, not 23
            "2028-02-28T23:59:60.000Z",  # not the last day of February in a leap year
            "2027-02-29T23:59:60.000Z",  # no such day
        ],
    )
    def test_second_60_outside_2359_on_the_last_day_of_the_month_is_invalid(self, timestamp):
        assert is_canonical_timestamp(timestamp) is False

    @pytest.mark.parametrize(
        "timestamp",
        [
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:59.000Z",
            "2016-12-31T23:59:59.000Z",
        ],
    )
    def test_seconds_00_to_59_are_unchanged(self, timestamp):
        assert is_canonical_timestamp(timestamp) is True


class TestRootNotBeforeMayPredateIssuedAt:
    """The check that time.not_before cannot predate issued_at binds a
    delegated child only (draft section 3.2 lines 536-537, "A child's
    not_before MUST NOT predate its issued_at"). A record whose
    parent_delegation_id is null is a root and is exempt from that check;
    the window must still be non-empty, and a child must still be issued
    inside its parent's window."""

    def test_backdated_root_verifies_valid(self):
        seed, public_key = _keypair()
        body = _root_body(
            authority=_authority(
                time={"not_before": "2025-12-31T00:00:00.000Z", "not_after": "2026-01-02T00:00:00.000Z"},
            ),
        )
        record = issue_authority_delegation(body, seed)

        result = _verify_one(record, public_key)

        assert result.state == "valid"
        assert result.failures == ()

    def test_issue_authority_delegation_accepts_a_backdated_root(self):
        seed, _ = _keypair()
        body = _root_body(
            authority=_authority(
                time={"not_before": "2025-12-31T00:00:00.000Z", "not_after": "2026-01-02T00:00:00.000Z"},
            ),
        )

        record = issue_authority_delegation(body, seed)  # must not raise

        assert record["authority"]["time"]["not_before"] == "2025-12-31T00:00:00.000Z"

    def test_child_with_not_before_before_its_issued_at_stays_invalid_at_index_1(self):
        chain = _Chain()
        bad_child = copy.deepcopy(chain.child)
        # The child's own issued_at is 2026-01-01T00:05:00.000Z; back its
        # not_before up before that, keeping the window non-empty.
        bad_child["authority"]["time"]["not_before"] = "2026-01-01T00:00:00.000Z"

        result = verify_authority_delegation_chain(
            [chain.root, bad_child],
            now="2026-01-01T00:15:00.000Z",
            resolve_verification_key=chain.resolve_verification_key,
            trust_root=chain.trust_root,
            resolve_revocation=lambda delegation: "active",
        )

        assert result.state == "invalid"
        assert [item.code for item in result.failures] == ["SCHEMA_INVALID"]
        assert result.failures[0].index == 1

    def test_root_with_an_empty_time_window_stays_schema_invalid(self):
        body = _root_body(
            authority=_authority(
                time={"not_before": "2026-01-02T00:00:00.000Z", "not_after": "2026-01-02T00:00:00.000Z"},
            ),
        )
        probe = {**body, "nonce": "0" * 32, "delegation_id": "sha256:" + "0" * 64, "signature": "0" * 128}

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["SCHEMA_INVALID"]
        assert failures[0].message == "time window must be non-empty"


class TestRecordTypeVersionAndFacetProfiles:
    """A record_type or version that is not a string is malformed input; a
    recognised record_type with an unknown string version is unsupported and
    skips the rest of the v1 body schema entirely; an unrecognised record_type
    string is still judged by that schema; and a facet's own profile handling
    (missing/non-string profile, unsupported profile string) is unchanged."""

    def _probe(self, **overrides) -> dict:
        body = _root_body(**overrides)
        return {**body, "nonce": "0" * 32, "delegation_id": "sha256:" + "0" * 64, "signature": "0" * 128}

    def test_version_as_a_number_is_schema_invalid(self):
        failures = validate_authority_delegation_shape(self._probe(version=1))
        assert [item.code for item in failures] == ["SCHEMA_INVALID"]
        assert failures[0].message == "record_type and version must be strings"

    def test_version_as_a_list_is_schema_invalid(self):
        failures = validate_authority_delegation_shape(self._probe(version=["1.0"]))
        assert [item.code for item in failures] == ["SCHEMA_INVALID"]
        assert failures[0].message == "record_type and version must be strings"

    def test_record_type_as_a_number_is_schema_invalid(self):
        failures = validate_authority_delegation_shape(self._probe(record_type=7))
        assert [item.code for item in failures] == ["SCHEMA_INVALID"]
        assert failures[0].message == "record_type and version must be strings"

    @pytest.mark.parametrize("version", ["2.0", "1.0"])
    def test_record_type_str_subclass_is_schema_invalid_regardless_of_version(self, version):
        # A str subclass equal by content to the v1 record_type must not
        # take the recognised-type-with-unknown-version fast path (which
        # would otherwise skip this record straight to UNSUPPORTED_VERSION
        # alone): the branch tests record_type by exact type, so this record
        # falls through to the ordinary body checks, where the record-wide
        # walk and the record_type/version type check each report
        # SCHEMA_INVALID, regardless of which version string is present.
        probe = self._probe(record_type=_RecordTypeAlias("aps:authority-delegation:v1"), version=version)

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["SCHEMA_INVALID", "SCHEMA_INVALID"]

    def test_recognised_type_with_unknown_version_skips_exact_keys_and_facet_checks(self):
        probe = self._probe(version="2.0")
        probe["extensions"] = {}
        probe["authority"] = dict(probe["authority"])
        probe["authority"]["risk"] = {"profile": "x", "ceiling": 1}

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["UNSUPPORTED_VERSION"]

    def test_recognised_type_with_unknown_version_skips_the_missing_nonce_member(self):
        body = _root_body(version="1.1")
        probe = {**body, "delegation_id": "sha256:" + "0" * 64, "signature": "0" * 128}
        assert "nonce" not in probe

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["UNSUPPORTED_VERSION"]

    def test_recognised_type_with_unknown_version_and_a_noncharacter_reports_both_codes(self):
        probe = self._probe(version="2.0", subject="did:example:agent-a\ufdd0")

        failures = validate_authority_delegation_shape(probe)

        assert [item.code for item in failures] == ["SCHEMA_INVALID", "UNSUPPORTED_VERSION"]

    def test_recognised_type_with_unknown_version_and_an_otherwise_valid_v1_body_is_unsupported(self):
        failures = validate_authority_delegation_shape(self._probe(version="2.0"))
        assert [item.code for item in failures] == ["UNSUPPORTED_VERSION"]
        assert failures[0].message == "unsupported authority-delegation record_type or version"

    def test_unrecognised_record_type_with_an_otherwise_valid_v1_body_is_unsupported_version(self):
        failures = validate_authority_delegation_shape(
            self._probe(record_type="aps:authority-delegation:v2"),
        )
        assert [item.code for item in failures] == ["UNSUPPORTED_VERSION"]

    def test_unrecognised_record_type_with_an_extra_top_level_member_is_schema_invalid(self):
        # Discriminates this from the recognised-type/unknown-version branch
        # above, which skips the exact-keys check entirely: an unrecognised
        # record_type string is still judged by the v1 schema's structural
        # checks, so an extra top-level member is caught as SCHEMA_INVALID
        # before UNSUPPORTED_VERSION is ever considered. This is current
        # behaviour for a case the draft leaves open: no rule states whether
        # an unknown record_type string should be judged by the v1 schema.
        failures = validate_authority_delegation_shape(
            self._probe(record_type="aps:authority-delegation:v2", extensions={}),
        )
        assert [item.code for item in failures] == ["SCHEMA_INVALID"]

    def test_reputation_profile_as_a_number_is_schema_invalid(self):
        probe = self._probe(authority=_authority(reputation={"profile": 5, "ceiling": 80}))
        failures = validate_authority_delegation_shape(probe)
        assert [item.code for item in failures] == ["SCHEMA_INVALID"]

    def test_unsupported_scope_profile_is_unsupported_profile(self):
        probe = self._probe(
            authority=_authority(scope={"profile": "aps-hierarchical-v2", "grants": ["commerce/checkout"]}),
        )
        failures = validate_authority_delegation_shape(probe)
        assert [item.code for item in failures] == ["UNSUPPORTED_PROFILE"]
