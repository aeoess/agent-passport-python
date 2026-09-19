# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The seven-facet parent/child attenuation comparison.

Python port of the TypeScript SDK's src/v2/authority-delegation/compare.ts.
"""

from __future__ import annotations

from .scope import scope_narrows
from .types import AuthorityFailure

_REVERSIBILITY_RANK = {"tentative": 0, "compensable": 1, "irreversible": 2}


def _fail(failures: list[AuthorityFailure], code: str, facet: str, message: str) -> None:
    failures.append(AuthorityFailure(code=code, message=message, facet=facet))


def compare_authority(parent: dict, child: dict) -> list[AuthorityFailure]:
    """Compare a child against its immediate parent in the seven-facet partial order."""
    failures: list[AuthorityFailure] = []

    if child["scope"]["profile"] != parent["scope"]["profile"]:
        _fail(failures, "UNSUPPORTED_PROFILE", "scope", "scope profile changes are incomparable")
    elif not scope_narrows(parent["scope"]["grants"], child["scope"]["grants"]):
        _fail(failures, "SCOPE_WIDENING", "scope", "child scope is not covered by parent scope")

    parent_spend = parent["spend"]
    child_spend = child["spend"]
    if parent_spend["mode"] == "bounded":
        if child_spend["mode"] == "unbounded":
            _fail(failures, "SPEND_WIDENING", "spend", "bounded parent cannot produce unbounded child")
        elif child_spend["unit"] != parent_spend["unit"]:
            _fail(failures, "SPEND_UNIT_CHANGE", "spend", "bounded spend unit must remain exact")
        elif (
            int(child_spend["per_action"]) > int(parent_spend["per_action"])
            or int(child_spend["cumulative"]) > int(parent_spend["cumulative"])
        ):
            _fail(failures, "SPEND_WIDENING", "spend", "child spend limits exceed parent limits")

    parent_remaining = parent["depth"]["remaining"]
    child_remaining = child["depth"]["remaining"]
    if parent_remaining == 0:
        _fail(failures, "DEPTH_EXHAUSTED", "depth", "parent has no remaining delegation hop")
    elif child_remaining > parent_remaining - 1:
        _fail(failures, "DEPTH_WIDENING", "depth", "child remaining depth must consume at least one hop")

    if (
        child["time"]["not_before"] < parent["time"]["not_before"]
        or child["time"]["not_after"] > parent["time"]["not_after"]
    ):
        _fail(failures, "TIME_WIDENING", "time", "child validity window is not contained in parent window")

    if child["reputation"]["profile"] != parent["reputation"]["profile"]:
        _fail(failures, "UNSUPPORTED_PROFILE", "reputation", "reputation profile changes are incomparable")
    elif child["reputation"]["ceiling"] > parent["reputation"]["ceiling"]:
        _fail(failures, "REPUTATION_WIDENING", "reputation", "child reputation ceiling exceeds parent")

    if child["values"]["profile"] != parent["values"]["profile"]:
        _fail(failures, "UNSUPPORTED_PROFILE", "values", "values profile changes are incomparable")
    else:
        child_required = set(child["values"]["required"])
        if any(identifier not in child_required for identifier in parent["values"]["required"]):
            _fail(failures, "VALUES_WEAKENING", "values", "child removed an ancestor-required value identifier")

    if child["reversibility"]["profile"] != parent["reversibility"]["profile"]:
        _fail(failures, "UNSUPPORTED_PROFILE", "reversibility", "reversibility profile changes are incomparable")
    elif _REVERSIBILITY_RANK[child["reversibility"]["ceiling"]] > _REVERSIBILITY_RANK[parent["reversibility"]["ceiling"]]:
        _fail(failures, "REVERSIBILITY_WIDENING", "reversibility", "child reversibility ceiling exceeds parent")

    return failures
