# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Hierarchical purpose membership. PROPOSED module, NOT a proposed primitive.

These two functions are a port of ``isPurposePermitted`` and ``purposeCategory``, which
have shipped in the TypeScript SDK's ``src/core/data-lifecycle.ts`` since before this
module existed. This Python SDK had no port of either, which was a cross-language parity
gap and not a design position.

WHY THEY LIVE HERE. Adding them under a ``data_lifecycle`` module, to hold two functions,
would have put the same primitive at two unrelated paths in the two languages, which
becomes a cross-language test annoyance the first time a vector references it. Both SDKs
now expose them from the bounds module, and the TypeScript original stays exported from its
old path too, so nothing that imports it today changes.

PURPOSE MEMBERSHIP IS NOT PURPOSE EXHAUSTION, and the distinction is the reason this file
carries a docstring at all. :func:`is_purpose_permitted` answers whether a requested purpose
falls inside a set of allowed purposes. It answers ``True`` for the second compressor
purchase exactly as it does for the first. Membership can therefore never decide
exhaustion, and a boundary that checks only membership is the defective implementation the
purpose-bound case corpus exists to catch. :func:`evaluate_bound` is the exhaustion
question.
"""

from __future__ import annotations

from collections.abc import Sequence


def is_purpose_permitted(requested: str, allowed: Sequence[str]) -> bool:
    """Check if a requested purpose is permitted under allowed purposes.

    Supports wildcard matching: ``'research:*'`` permits ``'research:academic'``.
    Supports exact matching: ``'research:academic'`` only permits that exact purpose.
    A bare parent covers its children: ``'research'`` permits ``'research:academic'``.
    """
    for a in allowed:
        if a == requested:
            return True
        # Wildcard: 'research:*' matches 'research:academic', 'research:commercial'
        if a.endswith(":*"):
            prefix = a[:-1]  # 'research:'
            if requested.startswith(prefix):
                return True
        # Parent covers child: 'research' matches 'research:academic'
        if ":" not in a and requested.startswith(a + ":"):
            return True
    return False


def purpose_category(purpose: str) -> str:
    """Extract the purpose category from a hierarchical purpose string.

    e.g. ``'research:academic'`` -> ``'research'``
    """
    idx = purpose.find(":")
    return purpose if idx == -1 else purpose[:idx]
