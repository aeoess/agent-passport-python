# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""UTC timestamp parsing that is correct on Python 3.9+ (matches the TS SDK).

``datetime.fromisoformat`` did not accept a trailing ``Z`` until Python 3.11.
The SDK writes ``Z``-suffixed timestamps and the TS reference issues them, so a
bare ``fromisoformat(ts)`` silently raised ``ValueError`` on the standard form
under the declared minimum interpreter (3.10). Where that error was swallowed,
expiry checks became no-ops (fail open). This helper normalizes ``Z`` to
``+00:00`` first, so a valid timestamp parses on every supported version, and
raises on genuinely malformed input so the caller can fail closed.
"""

from datetime import datetime, timezone


def parse_iso_utc(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp to a timezone-aware UTC datetime.

    Accepts a trailing ``Z`` (UTC designator) on Python 3.9+. A naive
    (offsetless) timestamp is read as UTC, matching how the SDK writes them.
    Raises ``ValueError``/``TypeError`` on malformed input; callers treating an
    unparseable expiry as expired keep the check fail-closed.
    """
    if not isinstance(ts, str):
        raise TypeError(f"timestamp must be str, got {type(ts).__name__}")
    normalized = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
