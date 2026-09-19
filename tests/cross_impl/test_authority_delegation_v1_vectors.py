# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Check the Python AuthorityDelegationV1 port against tests/cross_impl/authority-delegation-v1-vectors.json.

Chain cases must return the expected state, failure codes and failure index. Wire cases must be
accepted (and parse to the expected record) or rejected. Issuance cases must produce the expected
record byte for byte, or refuse. Budget cases replay their operations on a fresh ledger and must
return the expected result and counters after every step.

The vector file records where each expected value comes from (expected_provenance). The failure codes
are the TypeScript SDK's vocabulary, which the Python port shares; they are not protocol vocabulary.
Agreement here shows the Python port matches those values, not more.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_passport.v2.authority_delegation import (
    AuthorityDelegationError,
    InMemoryAuthorityBudgetLedger,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    parse_authority_delegation_json,
    verify_authority_delegation_chain,
)

_PATH = pathlib.Path(__file__).parent / "authority-delegation-v1-vectors.json"
_VECTORS = json.loads(_PATH.read_text(encoding="utf-8"))
_CASES = _VECTORS["cases"]
_SEEDS = {entry["label"]: entry["seed_hex"] for entry in _VECTORS["keys"]}


def _by_kind(kind):
    return [case for case in _CASES if case["kind"] == kind]


def _key_resolver(entries):
    table = {(entry["issuer"], entry["verification_method"]): entry["public_key_hex"] for entry in entries}

    def resolve(issuer, verification_method, issued_at):
        return table.get((issuer, verification_method))

    return resolve


def _trust(spec):
    if spec["mode"] == "unavailable":
        def unavailable(root):
            raise RuntimeError("trust policy unavailable")
        return unavailable
    trusted = set(spec["trusted_root_ids"])
    return lambda root: root.get("delegation_id") in trusted


def _revocation(spec, chain):
    by_id = {}
    for index, status in spec.get("by_index", {}).items():
        delegation_id = chain[int(index)]["delegation_id"]
        assert by_id.get(delegation_id, status) == status, "vector names two statuses for one delegation_id"
        by_id[delegation_id] = status
    default = spec["default"]

    def resolve(delegation):
        status = by_id.get(delegation.get("delegation_id"), default)
        if status == "unavailable":
            raise RuntimeError("revocation source unavailable")
        return status

    return resolve


def test_vector_file_shape():
    counts = _VECTORS["counts"]
    assert len(_CASES) == counts["total"]
    assert {case["expected_provenance"] for case in _CASES} <= {"draft-derived", "ts-conformant-regression"}
    for kind, number in counts["by_kind"].items():
        assert len(_by_kind(kind)) == number, kind
    assert len({case["id"] for case in _CASES}) == len(_CASES)


@pytest.mark.parametrize("case", _by_kind("chain"), ids=[c["id"] for c in _by_kind("chain")])
def test_chain(case):
    context = case["context"]
    result = verify_authority_delegation_chain(
        case["chain"],
        now=context["now"],
        resolve_verification_key=_key_resolver(context["keys"]),
        trust_root=_trust(context["trust"]),
        resolve_revocation=_revocation(context["revocation"], case["chain"]),
    )
    expected = case["expected"]
    assert result.state == expected["state"]
    assert result.valid is (expected["state"] == "valid")
    assert [failure.code for failure in result.failures] == expected["sdk_codes"]
    assert all(failure.index == expected["index"] for failure in result.failures)


@pytest.mark.parametrize("case", _by_kind("wire"), ids=[c["id"] for c in _by_kind("wire")])
def test_wire(case):
    if case["expected"]["result"] == "accept":
        assert parse_authority_delegation_json(case["input_json"]) == case["expected"]["value"]
    else:
        with pytest.raises(AuthorityDelegationError):
            parse_authority_delegation_json(case["input_json"])


@pytest.mark.parametrize("case", _by_kind("issue_root"), ids=[c["id"] for c in _by_kind("issue_root")])
def test_issue_root(case):
    seed = _SEEDS[case["signing_key"]]
    if case["expected"]["result"] == "issue":
        assert issue_authority_delegation(case["body"], seed) == case["expected"]["delegation"]
    else:
        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue_authority_delegation(case["body"], seed)
        if "sdk_code" in case["expected"]:
            assert exc_info.value.code == case["expected"]["sdk_code"]


@pytest.mark.parametrize("case", _by_kind("issue_child"), ids=[c["id"] for c in _by_kind("issue_child")])
def test_issue_child(case):
    status = case["context"]["revocation"]["parent"]

    def revocation(delegation):
        if status == "unavailable":
            raise RuntimeError("revocation source unavailable")
        return status

    def issue():
        return issue_sub_authority_delegation(
            case["parent"],
            case["body"],
            _SEEDS[case["signing_key"]],
            now=case["context"]["now"],
            resolve_verification_key=_key_resolver(case["context"]["keys"]),
            resolve_revocation=revocation,
        )

    if case["expected"]["result"] == "issue":
        assert issue() == case["expected"]["delegation"]
    else:
        with pytest.raises(AuthorityDelegationError) as exc_info:
            issue()
        if "sdk_code" in case["expected"]:
            assert exc_info.value.code == case["expected"]["sdk_code"]


@pytest.mark.parametrize("case", _by_kind("budget"), ids=[c["id"] for c in _by_kind("budget")])
def test_budget(case):
    ledger = InMemoryAuthorityBudgetLedger()
    labels = case["record_labels"]
    for number, step in enumerate(case["steps"]):
        op = step["op"]
        if op == "reserve":
            result = ledger.reserve(case["chains"][step["chain"]], step["action_ref"], step["unit"], step["amount"])
        elif op == "mark_dispatched":
            result = ledger.mark_dispatched(step["action_ref"])
        elif op == "commit":
            result = ledger.commit(step["action_ref"])
        elif op == "cancel":
            result = ledger.cancel(step["action_ref"])
        else:
            raise AssertionError(f"unknown op {op!r}")
        expected = step["expected"]
        assert (result.ok, result.code, result.state) == (expected["ok"], expected["sdk_code"], expected.get("state")), f"step {number}"
        for label, counter in step["counters_after"].items():
            assert ledger.counter(labels[label]) == counter, f"step {number} {label}"
