# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Scope grant grammar and the parent/child covers relation.

Python port of the TypeScript SDK's src/v2/authority-delegation/scope.ts.
"""

from __future__ import annotations

import re

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def is_valid_scope_grant(grant: str) -> bool:
    if grant == "*":
        return True
    if type(grant) is not str or len(grant) == 0 or len(grant) > 255:
        return False
    parts = grant.split(":")
    if len(parts) > 16:
        return False
    wildcard = parts[-1] == "*"
    if wildcard:
        parts = parts[:-1]
    if len(parts) == 0 or any(not _SEGMENT.fullmatch(part) for part in parts):
        return False
    return "*" not in parts


def scope_grant_covers(parent: str, child: str) -> bool:
    """Exact grants cover only themselves. A terminal :* grant covers its prefix and descendants."""
    if parent == "*":
        return True
    if parent.endswith(":*"):
        prefix = parent[:-2]
        child_prefix = child[:-2] if child.endswith(":*") else child
        return child_prefix == prefix or child_prefix.startswith(prefix + ":")
    return parent == child


def grants_are_canonical(grants) -> bool:
    """True when grants is a valid, strictly sorted, irredundant scope grant list.

    Validity and strict order are checked exactly as before, in one O(n)
    pass. Redundancy (no grant is covered by any other grant in the list) is
    checked without the pairwise O(n^2) scan the definition above suggests.

    Once every grant is known valid and the list strictly sorted (so every
    grant is distinct), whether some OTHER grant in the list covers a given
    grant g reduces to two cheap tests: is the bare wildcard "*" present (it
    covers everything), or is "Q:*" present for a Q that is a whole-segment
    prefix of g's own prefix? g's own prefix is g with a trailing ":*"
    removed if it has one, else g itself. scope_grant_covers's own
    definition is: an exact grant covers only itself, and a grant ending in
    ":*" with prefix P covers a grant with prefix C exactly when C equals P
    or C starts with P + ":". Because a colon only ever falls on a segment
    boundary in a valid grant, "C starts with P + ':'" for a valid P is
    exactly "P equals the join of some whole number of C's leading segments"
    (and "C equals P" is that same statement for all of C's segments), so
    together, some other grant covers g exactly when the string formed by
    joining the first m segments of g's own prefix, followed by ":*", is a
    grant in the list (other than g itself) for some m from 1 up to the
    number of segments in g's prefix. Building those at-most-16 candidate
    strings and doing a set lookup for each replaces comparing g against
    every other grant, so this is O(n * segments) instead of O(n^2).
    """
    if type(grants) is not list:
        return False
    for i, grant in enumerate(grants):
        if not is_valid_scope_grant(grant):
            return False
        if i > 0 and grants[i - 1] >= grant:
            return False

    grant_set = set(grants)
    for grant in grants:
        if grant == "*":
            continue
        if "*" in grant_set:
            return False
        prefix = grant[:-2] if grant.endswith(":*") else grant
        segments = prefix.split(":")
        for m in range(1, len(segments) + 1):
            candidate = ":".join(segments[:m]) + ":*"
            if candidate != grant and candidate in grant_set:
                return False
    return True


def scope_narrows(parent, child) -> bool:
    return all(any(scope_grant_covers(parent_grant, grant) for parent_grant in parent) for grant in child)
