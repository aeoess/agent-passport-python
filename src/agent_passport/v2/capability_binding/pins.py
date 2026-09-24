# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The ``scope_grant_v0`` pin encoding: reading a pin out of a grant's
scope, and writing one into it.

WHY THIS ENCODING. draft-03 section 3.2 already defines a segmented scope grammar,
verbatim: 'Scope grants use ASCII colon-separated segments. "*" covers all grants; a
wildcard is otherwise permitted only as the terminal segment ":*".' Expressing a pin as
further segments under the tool grant keeps it inside a grammar that exists, rather than
requiring an eighth authority facet, which draft-03 section 3.2 forbids by closing the
vector at seven and making a missing facet invalid.

THE SIDE EFFECT, STATED. Under this encoding a pin is subject to draft-03's ordinary
parent-covers-child rule, so a child delegation carrying a DIFFERENT pin fails as scope
widening rather than as a binding failure, and a child that drops the pin narrows
legitimately into an unpinned grant. That is a consequence of the encoding, not a decision
the concept document asked for. Concept source: aeoess/agent-authority-lifecycle, invariant
candidate CAND-07 v2.
"""

from __future__ import annotations

from collections.abc import Sequence

from .types import CapabilityBindingError, CapabilityPin


def _assert_segment(label: str, value: str) -> None:
    if not isinstance(value, str) or value == "":
        raise CapabilityBindingError("SEGMENT_INVALID", f"{label} must be a non-empty string")


def tool_scope_grant(tool_name: str) -> str:
    """The tool grant itself, ``tool:<name>``."""
    _assert_segment("tool_name", tool_name)
    return f"tool:{tool_name}"


def implementation_pin_prefix(tool_name: str) -> str:
    """The implementation-pin prefix, ``tool:<name>:impl:``."""
    return f"{tool_scope_grant(tool_name)}:impl:"


def metadata_pin_prefix(tool_name: str) -> str:
    """The declared-metadata-pin prefix, ``tool:<name>:meta:``."""
    return f"{tool_scope_grant(tool_name)}:meta:"


def _pins_under(grants: Sequence[str], prefix: str) -> tuple[str, ...]:
    seen: list[str] = []
    for grant in grants:
        if not isinstance(grant, str) or not grant.startswith(prefix):
            continue
        value = grant[len(prefix) :]
        if value and value not in seen:
            seen.append(value)
    return tuple(seen)


def parse_capability_pin_from_scope_grants(
    grants: Sequence[str], tool_name: str
) -> CapabilityPin | None:
    """Read the pin a grant's scope carries for one tool.

    Returns ``None`` when the grant does not name the tool at all, which is a DIFFERENT
    ANSWER from a grant that names it and pins nothing. The second comes back as a
    :class:`CapabilityPin` with both digest tuples empty.
    :func:`evaluate_capability_binding` gives the two different reason codes,
    ``TOOL_NOT_IN_GRANT_SCOPE`` and ``NO_CAPABILITY_PIN_IN_GRANT``, and collapsing them
    loses the distinction CAND-07 v2's unpinned limb is about.

    Pins are returned in the order the grants appear, de-duplicated, and are NOT validated
    as digests: an unparseable pin value is a pin that will not match, which is a verdict,
    not an error.
    """
    if isinstance(grants, (str, bytes)) or not isinstance(grants, Sequence):
        raise CapabilityBindingError("GRANTS_INVALID", "grants must be a sequence of strings")
    grant = tool_scope_grant(tool_name)
    if grant not in grants:
        return None
    return CapabilityPin(
        tool_name=tool_name,
        implementation_digests=_pins_under(grants, f"{grant}:impl:"),
        metadata_digests=_pins_under(grants, f"{grant}:meta:"),
        encoding="scope_grant_v0",
    )


def capability_pin_scope_grants(pin: CapabilityPin) -> tuple[str, ...]:
    """Write a pin as scope grants, the inverse of
    :func:`parse_capability_pin_from_scope_grants`.

    Returns the tool grant followed by one grant per pinned digest, sorted by UTF-8 bytes
    so a caller appending them to an existing grant array can keep the array canonical,
    which draft-03 section 3.2 requires of scope arrays. Refuses a pin whose ``encoding``
    is not ``scope_grant_v0``, because writing a ``bound_record_v0`` pin into a scope would
    be a silently different artifact.
    """
    if not isinstance(pin, CapabilityPin):
        raise CapabilityBindingError("PIN_INVALID", "pin must be a CapabilityPin")
    if pin.encoding != "scope_grant_v0":
        raise CapabilityBindingError(
            "PIN_ENCODING_UNSUPPORTED",
            f"capability_pin_scope_grants writes scope_grant_v0 only, not {pin.encoding}",
        )
    grant = tool_scope_grant(pin.tool_name)
    out = [grant]
    for digest in pin.implementation_digests:
        _assert_segment("implementation digest", digest)
        out.append(f"{grant}:impl:{digest}")
    for digest in pin.metadata_digests:
        _assert_segment("metadata digest", digest)
        out.append(f"{grant}:meta:{digest}")
    return tuple(sorted(set(out), key=lambda s: s.encode("utf-8")))


def capability_pin_is_empty(pin: CapabilityPin) -> bool:
    """Whether a pin pins nothing. CAND-07 v2's unpinned limb turns on exactly this."""
    return len(pin.implementation_digests) == 0 and len(pin.metadata_digests) == 0
