# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Scope grant grammar and the parent/child covers relation.

Python port of the TypeScript SDK's src/v2/authority-delegation/scope.ts.
"""

from __future__ import annotations

import re

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def is_valid_scope_grant(grant: str) -> bool:
    """True when grant is "*" or a well-formed aps-hierarchical-v1 grant.

    Provisional, pending a protocol ruling: the aps-hierarchical-v1 segment
    grammar checked by _SEGMENT (letters, digits, ".", "_", "-", up to 64
    characters, starting with a letter or digit) is narrower than draft line
    516's own requirement that scope grants use ASCII colon-separated
    segments, and the limits below of at most 16 segments and 255 characters
    for the whole grant are not stated by the draft at all. All three are
    kept identical to the TypeScript SDK.
    """
    # The type test comes first: ``grant == "*"`` on a caller-supplied object runs
    # that object's own __eq__, which can raise out of this function and out of
    # grants_are_canonical below, both of which this package exports. The TypeScript
    # twin compares with === and never coerces. Chain verification and the issuers are
    # unaffected either way, since the closed schema types every grant before calling
    # here.
    if type(grant) is not str or len(grant) == 0 or len(grant) > 255:
        return False
    if grant == "*":
        return True
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
    """True when every grant in child is covered by some grant in parent.

    Linear in len(parent) + len(child) * segments, instead of the pairwise
    O(len(parent) * len(child)) scan the definition above suggests: parent is
    put in a set once. A child grant g is then covered exactly when "*" is
    in the set (it covers everything), or g itself is in the set (an exact
    grant covers only itself, and an identical wildcard covers itself too),
    or the string formed by joining the first m segments of g's own prefix,
    followed by ":*", is in the set for some m from 1 up to the number of
    segments in g's prefix (g's prefix is g with a trailing ":*" removed, if
    it has one). This is the same reasoning grants_are_canonical's
    redundancy check uses for one list against itself, applied here to two
    different lists instead.

    This equals the pairwise scope_grant_covers definition above only for a
    parent and a child grant list that have each already passed
    grants_are_canonical (valid, strictly sorted, irredundant grants).
    compare_authority, the only caller that reaches this function from the
    chain verifier, is never invoked before both authority vectors' scope
    facets have passed schema validation, so that precondition always holds
    on that path. Called directly with an unvalidated or malformed grant
    list, this function is not specified to agree with the pairwise
    definition.
    """
    parent_set = set(parent)
    if "*" in parent_set:
        return True
    for grant in child:
        if grant in parent_set:
            continue
        prefix = grant[:-2] if grant.endswith(":*") else grant
        segments = prefix.split(":")
        covered = False
        for m in range(1, len(segments) + 1):
            candidate = ":".join(segments[:m]) + ":*"
            if candidate in parent_set:
                covered = True
                break
        if not covered:
            return False
    return True
