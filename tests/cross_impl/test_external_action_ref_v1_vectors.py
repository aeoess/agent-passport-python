# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Check the Python section 4.2 port against tests/cross_impl/external-action-ref-v1-vectors.json.

Every case must produce its expected digest, or be rejected with its expected
failure code. The vector file records where each expected value comes from
(expected_provenance) and, for reject cases, what the TypeScript reference
implementation actually does (ts_behaviour, which is informational only:
this file never asserts the Python port must match TS on a case the spec
itself says to reject).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_passport import ExternalActionRefError, compute_external_action_ref_v1

_VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "external-action-ref-v1-vectors.json").read_text(
        encoding="utf-8"
    )
)
_CASES = _VECTORS["cases"]


def _run(case):
    inp = case["input"]
    return compute_external_action_ref_v1(
        action_type=inp["action_type"],
        agent_id=inp["agent_id"],
        scope=inp["scope"],
        timestamp=inp["timestamp"],
    )


def test_vector_file_shape():
    assert len(_CASES) == _VECTORS["counts"]["total"]
    assert {c["expected_provenance"] for c in _CASES} <= {
        "draft-derived",
        "ts-conformant-regression",
    }
    codes = {row["code"] for row in _VECTORS["failure_codes"]}
    for case in _CASES:
        if case["expected"]["result"] == "reject":
            assert case["expected"]["failure"] in codes, case["id"]
            assert "ts_behaviour" in case, case["id"]


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_vector(case):
    expected = case["expected"]
    if expected["result"] == "accept":
        digest = _run(case)
        assert digest == expected["external_action_ref"]
    else:
        with pytest.raises(ExternalActionRefError) as exc_info:
            _run(case)
        assert exc_info.value.code == expected["failure"]
