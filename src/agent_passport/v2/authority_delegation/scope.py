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
    if type(grants) is not list:
        return False
    for i, grant in enumerate(grants):
        if not is_valid_scope_grant(grant):
            return False
        if i > 0 and grants[i - 1] >= grant:
            return False
        # A canonical set is an antichain: no entry is redundant under another entry.
        for j in range(len(grants)):
            if i != j and scope_grant_covers(grants[j], grant):
                return False
    return True


def scope_narrows(parent, child) -> bool:
    return all(any(scope_grant_covers(parent_grant, grant) for parent_grant in parent) for grant in child)
