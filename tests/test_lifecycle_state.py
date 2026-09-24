# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED lifecycle state vocabulary.

Every expectation comes from conformance/lifecycle-state/v0/vectors.json, which is the
SHARED fixture: the TypeScript SDK authors it and this repository vendors a byte-identical
copy, so the same cases run through both ports. Expectations are hand specified in the
vectors, never computed by the code under test, so the test is not circular. The file's
SHA-256 is pinned in both repositories, so the two copies can be shown identical without
either repository importing the other.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import pytest

from agent_passport import (
    BOUNDARY_OUTCOMES,
    ESTABLISHED_NEGATIVE_SHAPES,
    ESTABLISHMENT_GAPS,
    LIFECYCLE_VERDICTS,
    AuthorityFailure,
    AuthorityValidationResult,
    LifecycleStateError,
    LifecycleStateResult,
    is_boundary_outcome,
    is_establishment_gap,
    is_lifecycle_verdict,
    lifecycle_state,
    map_authority_validation_to_lifecycle,
    not_established,
    resolve_established_negative,
    verify_authority_delegation_chain,
)

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "lifecycle-state", "v0", "vectors.json"
)
with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()
_VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))

# Pinned so the TypeScript SDK's authoring copy can be shown byte identical. If this
# moves, the TypeScript repo's copy and its own pin move with it, in the same change.
_VECTORS_SHA256 = "e2efab4001ee7593cdd38a3f6bfb9d35e9946e865f93ae62c71c8587d1cccf6f"


def _as_plain(result: LifecycleStateResult) -> dict:
    """The result as a mapping with absent members dropped, for comparison with the
    fixture's expected objects."""
    out: dict = {"verdict": result.verdict, "reason_code": result.reason_code}
    if result.missing is not None:
        out["missing"] = list(result.missing)
    if result.applied_default is not None:
        out["applied_default"] = result.applied_default
    if result.outstanding is not None:
        out["outstanding"] = [dataclasses.asdict(c) for c in result.outstanding]
    return out


def test_vectors_file_is_the_pinned_bytes():
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == _VECTORS_SHA256


def test_module_vocabulary_matches_the_fixture_vocabulary_exactly():
    vocab = _VECTORS["vocabulary"]
    assert list(LIFECYCLE_VERDICTS) == vocab["verdicts"]
    assert list(BOUNDARY_OUTCOMES) == vocab["boundary_outcomes"]
    assert list(ESTABLISHMENT_GAPS) == vocab["establishment_gaps"]
    assert list(ESTABLISHED_NEGATIVE_SHAPES) == vocab["established_negative_shapes"]


def test_there_are_exactly_six_artifact_verdicts():
    assert len(LIFECYCLE_VERDICTS) == 6


@pytest.mark.parametrize(
    "vec", _VECTORS["constructor_cases"], ids=[v["id"] for v in _VECTORS["constructor_cases"]]
)
def test_constructor_case(vec):
    kwargs = dict(vec["input"])
    if vec["expected"]["ok"]:
        result = lifecycle_state(**kwargs)
        assert _as_plain(result) == vec["expected"]["result"]
        # No truthiness shortcut: not_established is not a boolean's false branch.
        assert not hasattr(result, "valid")
    else:
        with pytest.raises(LifecycleStateError) as excinfo:
            lifecycle_state(**kwargs)
        assert excinfo.value.code == vec["expected"]["error_code"]


@pytest.mark.parametrize(
    "vec",
    _VECTORS["established_negative_cases"],
    ids=[v["id"] for v in _VECTORS["established_negative_cases"]],
)
def test_established_negative_case(vec):
    expected = vec["expected"]
    if "error_code" in expected:
        with pytest.raises(LifecycleStateError) as excinfo:
            resolve_established_negative(vec["shape"])
        assert excinfo.value.code == expected["error_code"]
        return
    resolution = resolve_established_negative(vec["shape"])
    assert resolution.subject == expected["subject"]
    assert resolution.reason_code == expected["reason_code"]
    assert resolution.verdict == expected.get("verdict")
    assert resolution.outcome == expected.get("outcome")
    # None of the three is ever the evidential not established.
    assert (resolution.verdict or resolution.outcome) != "not_established"


def _chain_result(spec: dict) -> AuthorityValidationResult:
    return AuthorityValidationResult(
        state=spec["state"],
        failures=tuple(
            AuthorityFailure(code=f["code"], message=f.get("message", "")) for f in spec["failures"]
        ),
    )


@pytest.mark.parametrize(
    "vec", _VECTORS["mapping_cases"], ids=[v["id"] for v in _VECTORS["mapping_cases"]]
)
def test_mapping_case(vec):
    options = vec.get("options") or {}
    result = map_authority_validation_to_lifecycle(
        _chain_result(vec["chain_result"]),
        not_yet_valid_as_not_yet_effective=options.get(
            "not_yet_valid_as_not_yet_effective", True
        ),
    )
    expected = vec["expected"]
    assert result.verdict == expected["verdict"]
    assert result.reason_code == expected["reason_code"]
    if "missing" in expected:
        assert list(result.missing or ()) == expected["missing"]
    else:
        assert result.missing is None
    for forbidden in expected.get("not_verdict", []):
        assert result.verdict != forbidden
    for forbidden in expected.get("missing_excludes", []):
        assert forbidden not in (result.missing or ())


def test_mapping_never_mutates_the_result_it_was_given():
    given = _chain_result({"state": "invalid", "failures": [{"code": "REVOKED"}]})
    before = dataclasses.asdict(given)
    map_authority_validation_to_lifecycle(given)
    assert dataclasses.asdict(given) == before


def test_unrecognised_chain_state_is_not_established_not_invalid():
    result = map_authority_validation_to_lifecycle(
        AuthorityValidationResult(state="perhaps", failures=())
    )
    assert result.verdict == "not_established"
    assert result.reason_code == "CHAIN_STATE_UNRECOGNISED"
    assert list(result.missing or ()) == ["source"]


def test_existing_chain_verification_behaviour_is_unchanged():
    """The module is a second vocabulary reported alongside the draft-03 one, never in
    place of it. This runs the real chain verifier and asserts its four-value answer is
    what it always was, then maps it without touching it."""
    chain_result = verify_authority_delegation_chain(
        [],
        now="2026-09-23T00:00:00Z",
        resolve_verification_key=lambda _i, _m, _a: None,
        trust_root=lambda _r: True,
        resolve_revocation=lambda _d: "active",
    )
    assert chain_result.state in ("valid", "invalid", "indeterminate", "unsupported")
    assert isinstance(chain_result.valid, bool)
    lifecycle = map_authority_validation_to_lifecycle(chain_result)
    assert is_lifecycle_verdict(lifecycle.verdict)


def test_predicates_accept_only_their_own_vocabulary():
    assert is_lifecycle_verdict("restricted") is True
    assert is_lifecycle_verdict("exercisable") is False
    assert is_lifecycle_verdict("authorized") is False
    assert is_boundary_outcome("denied") is True
    assert is_boundary_outcome("invalid") is False
    assert is_establishment_gap("coverage") is True
    assert is_establishment_gap("standing") is False


def test_not_established_helper_carries_its_limbs_through_the_same_rules():
    result = not_established(["freshness"], "STATUS_STALE_BEYOND_BOUND")
    assert result.verdict == "not_established"
    assert list(result.missing or ()) == ["freshness"]
    with pytest.raises(LifecycleStateError):
        not_established([], "STATUS_STALE_BEYOND_BOUND")


def test_a_built_result_is_frozen():
    result = lifecycle_state(verdict="valid", reason_code="CHAIN_VALID")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.verdict = "invalid"  # type: ignore[misc]
