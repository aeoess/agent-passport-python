# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED suspension-cause module.

Every expectation comes from conformance/suspension-causes/v0/vectors.json, which is the
SHARED fixture: the TypeScript SDK authors it and this repository vendors a byte-identical
copy, so the same cases run through both ports. Expectations are hand specified in the
vectors, never computed by the code under test, so the test is not circular. The file's
SHA-256 is pinned in both repositories, so the two copies can be shown identical without
either repository importing the other.

The case list here is the TypeScript suite's case list, name for name: the same 29
evaluation vectors, 6 composition vectors and 6 caller-error vectors, plus the same eight
properties the vectors cannot state.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from typing import Any, Mapping

import pytest

from agent_passport import (
    PAUSE_KINDS,
    RELEASE_STANDINGS,
    SUSPENSION_CAUSE_TYPE,
    SUSPENSION_REASON_CODES,
    SUSPENSION_RELEASE_TYPE,
    LifecycleStateResult,
    SuspensionCause,
    SuspensionCauseError,
    SuspensionRelease,
    compose_chain_and_pause,
    evaluate_pause_state,
    explain_pause_state,
    lifecycle_state,
    not_established,
    suspension_cause_from_mapping,
    suspension_record_preimage,
    suspension_release_from_mapping,
)

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "suspension-causes", "v0", "vectors.json"
)
with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()
_VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))

# Pinned so the TypeScript SDK's authoring copy can be shown byte identical. If this moves,
# the TypeScript repo's copy and its own pin move with it, in the same change.
_VECTORS_SHA256 = "fc4c04b53299d35cb7bc810565f5bf8b7a1fea1d5b2e53478778a3642728df97"


def _cause(name: str) -> SuspensionCause:
    return suspension_cause_from_mapping(_VECTORS["causes"][name])


def _release(name: str) -> SuspensionRelease:
    return suspension_release_from_mapping(_VECTORS["releases"][name])


def _fixture_standing(release: SuspensionRelease, cause: SuspensionCause) -> str:
    """The fixture's standing resolver, implemented exactly as the vectors state it.

    It is a fixture object, not a mechanism this work proposes: nothing in the concept
    document says what establishes that a party holds standing over a cause.
    """
    for entry in _VECTORS["standing_resolver"]["standing_unknown"]:
        if entry["release_id"] == release.release_id and entry["cause_id"] == cause.cause_id:
            return "unknown"
    holders = _VECTORS["standing_resolver"]["standing_registry"].get(cause.cause_id, [])
    return "has_standing" if release.issuer in holders else "no_standing"


def _fixture_key(_signer: str, verification_method: str) -> str | None:
    """Resolves by ``verification_method`` alone, deliberately ignoring ``signer``.

    A record whose method belongs to somebody other than the party it names still gets a key
    and is caught by the binding check rather than by a missing key.
    """
    key = _VECTORS["verification_keys"].get(verification_method)
    return key if isinstance(key, str) else None


def _input_for(vector: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "delegation_id": _VECTORS["delegation_id"],
        "causes": [_cause(name) for name in vector["causes"]],
        "releases": [_release(name) for name in vector["releases"]],
        "at_instant": _VECTORS["clock"][vector["at"]],
        "resolve_release_standing": _fixture_standing,
        "resolve_verification_key": _fixture_key,
    }


def _build_state(spec: Mapping[str, Any]) -> LifecycleStateResult:
    if spec["verdict"] == "not_established":
        return not_established(spec["missing"], spec["reason_code"])
    kwargs: dict[str, Any] = {
        "verdict": spec["verdict"],
        "reason_code": spec["reason_code"],
    }
    if "outstanding" in spec:
        kwargs["outstanding"] = spec["outstanding"]
    return lifecycle_state(**kwargs)


# --- the shared fixture ---------------------------------------------------------------


def test_the_vectors_file_is_the_pinned_bytes() -> None:
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == _VECTORS_SHA256


def test_the_profile_and_status_are_what_both_sdks_expect() -> None:
    assert _VECTORS["profile"] == "aps-suspension-causes-v0"
    assert _VECTORS["status"] == "proposed"


def test_the_record_types_carry_the_proposed_namespace() -> None:
    assert SUSPENSION_CAUSE_TYPE == "proposed:aps:suspension-cause:v0"
    assert SUSPENSION_RELEASE_TYPE == "proposed:aps:cause-release:v0"


def test_the_vocabularies_are_the_two_and_three_values_the_module_documents() -> None:
    assert list(PAUSE_KINDS) == ["suspension", "restriction"]
    assert list(RELEASE_STANDINGS) == ["has_standing", "no_standing", "unknown"]


def test_every_reason_code_is_screaming_snake_case_and_unique() -> None:
    import re

    seen: set[str] = set()
    for code in SUSPENSION_REASON_CODES:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", code), f"{code} is not SCREAMING_SNAKE_CASE"
        assert code not in seen, f"{code} appears twice"
        seen.add(code)


# --- cause evaluation vectors ---------------------------------------------------------


@pytest.mark.parametrize("vector", _VECTORS["cases"], ids=[c["id"] for c in _VECTORS["cases"]])
def test_cause_evaluation_vector(vector: Mapping[str, Any]) -> None:
    explanation = explain_pause_state(**_input_for(vector))
    state = explanation.state
    expected = vector["expected"]

    assert state.verdict == expected["verdict"], "verdict"
    assert state.reason_code == expected["reason_code"], "reason_code"

    if "missing" in expected:
        assert list(state.missing or ()) == expected["missing"], "missing"
    else:
        assert state.missing is None, "missing must be absent"

    # The whole of CAND-05 in one field: a SET, never a count and never a boolean.
    if "outstanding" in expected:
        assert [dataclasses.asdict(c) for c in (state.outstanding or ())] == expected[
            "outstanding"
        ], "outstanding set"
        assert [
            dataclasses.asdict(c) for c in explanation.outstanding
        ] == expected["outstanding"], "explanation outstanding"
    else:
        assert state.outstanding is None, "outstanding must be absent"
        assert list(explanation.outstanding) == [], "explanation outstanding"

    by_cause = {d.cause_id: d for d in explanation.causes}
    for cause_id, disposition in expected.get("cause_dispositions", {}).items():
        assert by_cause[cause_id].disposition == disposition, f"cause {cause_id}"
    for cause_id, release_id in expected.get("released_by", {}).items():
        assert by_cause[cause_id].released_by == release_id, f"released_by {cause_id}"

    by_release = {d.release_id: d for d in explanation.releases}
    for release_id, disposition in expected.get("release_dispositions", {}).items():
        assert by_release[release_id].disposition == disposition, f"release {release_id}"
    for key, disposition in expected.get("release_cause_dispositions", {}).items():
        release_id, cause_id = key.split("|")
        entry = next(
            (c for c in by_release[release_id].causes if c.cause_id == cause_id), None
        )
        assert entry is not None and entry.disposition == disposition, (
            f"release {release_id} cause {cause_id}"
        )
    for release_id, count in expected.get("release_cause_count", {}).items():
        assert len(by_release[release_id].causes) == count, f"release {release_id} arity"

    # One entry per input record, in input order, with nothing dropped.
    assert len(explanation.causes) == len(vector["causes"])
    assert len(explanation.releases) == len(vector["releases"])

    # evaluate_pause_state is the same computation returning only the state.
    assert evaluate_pause_state(**_input_for(vector)) == state


# --- composition with a chain result ---------------------------------------------------


@pytest.mark.parametrize(
    "vector", _VECTORS["compose_cases"], ids=[c["id"] for c in _VECTORS["compose_cases"]]
)
def test_composition_vector(vector: Mapping[str, Any]) -> None:
    composed = compose_chain_and_pause(
        _build_state(vector["chain"]), _build_state(vector["pause"])
    )
    assert composed == _build_state(vector["expected"])


def test_a_release_never_clears_a_revocation_for_every_pause_verdict_reachable() -> None:
    revoked = lifecycle_state(verdict="invalid", reason_code="REVOKED")
    pause_states = [
        lifecycle_state(verdict="valid", reason_code="NO_CAUSE_PRESENTED"),
        lifecycle_state(verdict="valid", reason_code="NO_CAUSE_IN_EVIDENCE"),
        lifecycle_state(verdict="valid", reason_code="ALL_CAUSES_RELEASED"),
        lifecycle_state(
            verdict="suspended",
            reason_code="CAUSES_OUTSTANDING",
            outstanding=[{"id": "c", "kind": "suspension", "reason_code": "R"}],
        ),
        lifecycle_state(
            verdict="restricted",
            reason_code="CAUSES_OUTSTANDING",
            outstanding=[{"id": "c", "kind": "restriction", "reason_code": "R"}],
        ),
        not_established(["source"], "RELEASE_STANDING_NOT_ESTABLISHED"),
    ]
    for pause in pause_states:
        assert compose_chain_and_pause(revoked, pause) == revoked, pause.reason_code


def test_a_non_lifecycle_state_result_argument_is_a_caller_error() -> None:
    ok = lifecycle_state(verdict="valid", reason_code="CHAIN_VALID")
    with pytest.raises(SuspensionCauseError) as first:
        compose_chain_and_pause(None, ok)  # type: ignore[arg-type]
    assert first.value.code == "INPUT_MALFORMED"
    with pytest.raises(SuspensionCauseError) as second:
        compose_chain_and_pause(ok, None)  # type: ignore[arg-type]
    assert second.value.code == "INPUT_MALFORMED"


# --- malformed input is a caller error, never a verdict --------------------------------


@pytest.mark.parametrize(
    "vector", _VECTORS["error_cases"], ids=[c["id"] for c in _VECTORS["error_cases"]]
)
def test_error_vector(vector: Mapping[str, Any]) -> None:
    kwargs = _input_for(vector)
    mutation = vector["mutation"]
    if mutation in ("duplicate_cause_id", "duplicate_release_id"):
        pass
    elif mutation == "cause_kind_unknown":
        kwargs["causes"] = [dataclasses.replace(kwargs["causes"][0], kind="quarantine")]
    elif mutation == "cause_drop_reason_code":
        kwargs["causes"] = [dataclasses.replace(kwargs["causes"][0], reason_code="")]
    elif mutation == "standing_resolver_returns_maybe":
        kwargs["resolve_release_standing"] = lambda _release, _cause: "maybe"
    elif mutation == "release_cause_ids_string":
        kwargs["releases"] = [
            dataclasses.replace(kwargs["releases"][0], cause_ids="sc-cause-reg")
        ]
    else:  # pragma: no cover - the vectors file grew a mutation this port does not know
        raise AssertionError(f"unknown mutation {mutation}")

    with pytest.raises(SuspensionCauseError) as caught:
        evaluate_pause_state(**kwargs)
    assert caught.value.code == vector["expected_error_code"]


# --- properties the vectors cannot state ------------------------------------------------


def test_the_single_flag_representation_is_not_reachable() -> None:
    # The LC-B-024 mistake, stated as a property. With three causes and one effective
    # release, an implementation holding a boolean would report everything cleared.
    state = evaluate_pause_state(
        **_input_for(
            {
                "causes": ["REG", "FIRM", "DECREE"],
                "releases": ["REL_REG_BY_REGULATOR"],
                "at": "T_EVAL",
            }
        )
    )
    assert state.verdict == "suspended"
    assert state.outstanding is not None and len(state.outstanding) == 2
    assert not hasattr(state, "valid")


def test_release_authority_on_the_cause_is_never_read_by_the_evaluator() -> None:
    # Standing is resolved outside the record, always. Rewrite the answer so the stranger
    # DOES hold standing and the same release now works, which shows the resolver is the
    # only thing deciding.
    cause = _cause("REG_SELF_NOMINATING")
    release = _release("REL_REG_SELF_BY_STRANGER")
    assert cause.release_authority == release.issuer, "fixture precondition"

    without_standing = evaluate_pause_state(
        delegation_id=_VECTORS["delegation_id"],
        causes=[cause],
        releases=[release],
        at_instant=_VECTORS["clock"]["T_EVAL"],
        resolve_release_standing=lambda _r, _c: "no_standing",
        resolve_verification_key=_fixture_key,
    )
    assert without_standing.verdict == "suspended"

    with_standing = evaluate_pause_state(
        delegation_id=_VECTORS["delegation_id"],
        causes=[cause],
        releases=[release],
        at_instant=_VECTORS["clock"]["T_EVAL"],
        resolve_release_standing=lambda _r, _c: "has_standing",
        resolve_verification_key=_fixture_key,
    )
    assert with_standing.verdict == "valid"
    assert with_standing.reason_code == "ALL_CAUSES_RELEASED"


def test_no_precedence_order_among_causes() -> None:
    # CAND-05 defines no precedence order and says so. The outstanding set is sorted by
    # cause_id, which is a presentation choice with no claim behind it.
    forward = evaluate_pause_state(
        **_input_for({"causes": ["REG", "FIRM", "DECREE"], "releases": [], "at": "T_EVAL"})
    )
    reversed_ = evaluate_pause_state(
        **_input_for({"causes": ["DECREE", "FIRM", "REG"], "releases": [], "at": "T_EVAL"})
    )
    assert forward == reversed_


def test_release_order_does_not_change_the_answer() -> None:
    forward = evaluate_pause_state(
        **_input_for(
            {
                "causes": ["REG", "FIRM", "DECREE"],
                "releases": ["REL_REG_BY_REGULATOR", "REL_FIRM_BY_FIRM"],
                "at": "T_EVAL",
            }
        )
    )
    reversed_ = evaluate_pause_state(
        **_input_for(
            {
                "causes": ["REG", "FIRM", "DECREE"],
                "releases": ["REL_FIRM_BY_FIRM", "REL_REG_BY_REGULATOR"],
                "at": "T_EVAL",
            }
        )
    )
    assert forward == reversed_


def test_the_preimage_excludes_signature_and_record_id_and_nothing_else() -> None:
    preimage = suspension_record_preimage(
        {"b": 2, "a": 1, "signature": "deadbeef", "record_id": "cafe"}
    )
    assert preimage == '{"a":1,"b":2}'


def test_a_resolver_that_raises_fails_the_record_closed() -> None:
    def _broken(_signer: str, _method: str) -> str | None:
        raise RuntimeError("resolver down")

    state = evaluate_pause_state(
        delegation_id=_VECTORS["delegation_id"],
        causes=[_cause("REG")],
        releases=[_release("REL_REG_BY_REGULATOR")],
        at_instant=_VECTORS["clock"]["T_EVAL"],
        resolve_release_standing=_fixture_standing,
        resolve_verification_key=_broken,
    )
    # The cause record cannot be verified either, so nothing is in evidence and nothing is
    # claimed against the artifact.
    assert state.verdict == "valid"
    assert state.reason_code == "NO_CAUSE_IN_EVIDENCE"


def test_the_result_and_its_outstanding_set_are_immutable() -> None:
    state = evaluate_pause_state(
        **_input_for({"causes": ["REG", "FIRM"], "releases": [], "at": "T_EVAL"})
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        state.verdict = "valid"  # type: ignore[misc]
    assert isinstance(state.outstanding, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        state.outstanding[0].id = "other"  # type: ignore[misc]


def test_nothing_in_this_module_is_reachable_from_an_existing_chain_result() -> None:
    # The opt-in guarantee, checked rather than asserted in prose: the chain verifier does
    # not import the suspension module.
    verify_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "src",
        "agent_passport",
        "v2",
        "authority_delegation",
        "verify.py",
    )
    with open(verify_path, "r", encoding="utf-8") as handle:
        assert "suspension" not in handle.read()
