# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The identity limb of CAND-07: whether an authority path that depends
on an identifier nobody in the delegation graph controls still depends on the same party.

SPECIFICATION POSITION. Not required by draft-pidlisnyi-aps-03, which states no rule about
an off-chain identifier a grant depends on. Concept source:
aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2 ("A verifier must not
treat an unchanged name as evidence of an unchanged controller, an unchanged implementation
or an unchanged schema") and the AUTHORITY-LIFECYCLE.md concepts "Target binding",
"Authority path and dependency", "Issuer standing" and "Coverage and completeness". All
PROPOSED.

THE THING THIS CATCHES. A mail domain, a package namespace or a phone number that an
account-recovery path depends on. The string in the grant never changes. The party holding
it does, by lapse and re-registration, by a vacated name being claimed, or by routine
reassignment. A boundary whose whole check is that the string still matches admits every
one of those.

WHAT RUNS WHERE. Chain verification stays with the caller and is unchanged. An identifier
changing hands is not a revocation, so the two checks are separate: run
``verify_authority_delegation_chain`` first, and if it does not return valid there is no
identifier question to ask. This module reads no clock and no network. It does verify
Ed25519 signatures over custodian records, which is why it is not pure in the way
:func:`evaluate_capability_binding` is; standing is still resolved entirely outside the
records, through two caller-supplied resolvers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from ...canonical import canonicalize_jcs
from ...crypto import verify as verify_ed25519
from .types import CapabilityBindingError, IdentifierContinuityResult, identifier_continuity_result

#: Members dropped from a binding record before canonicalizing its signed body. The record
#: id is a digest OF the body and the signature is OVER the body, so neither can be inside
#: it.
IDENTIFIER_BINDING_UNSIGNED_FIELDS: tuple[str, ...] = ("binding_id", "signature")

#: Members dropped from a retention record before canonicalizing its signed body.
IDENTIFIER_RETENTION_UNSIGNED_FIELDS: tuple[str, ...] = ("retention_id", "signature")


def identifier_record_signed_bytes(
    record: Mapping[str, object], unsigned_fields: Sequence[str]
) -> str:
    """The exact bytes a custodian signature is taken over: RFC 8785 JCS over the record
    with ``unsigned_fields`` removed.

    JCS, not the SDK's legacy ``canonicalize``. The two are NOT interchangeable here,
    because a binding record's ``bound_until`` is meaningfully ``None`` for an open-ended
    interval and the legacy form strips null members, which would make an open-ended
    binding and a binding with no end field sign to the same bytes.
    """
    if not isinstance(record, Mapping):
        raise CapabilityBindingError("RECORD_INVALID", "record must be a mapping")
    body = {k: v for k, v in record.items() if k not in unsigned_fields}
    return canonicalize_jcs(body)


def _assert_segment(label: str, value: str) -> None:
    if not isinstance(value, str) or value == "":
        raise CapabilityBindingError("SEGMENT_INVALID", f"{label} must be a non-empty string")


def identifier_dependency_scope_grant(kind: str, identifier: str) -> str:
    """The dependency scope grant, ``extid:<kind>:<identifier>``. Says the grant's recovery
    or verification path depends on this identifier at all."""
    _assert_segment("kind", kind)
    _assert_segment("identifier", identifier)
    return f"extid:{kind}:{identifier}"


def identifier_controller_pin_scope_grant(kind: str, identifier: str, controller: str) -> str:
    """The controller-pin scope grant,
    ``extid:<kind>:<identifier>:controller:<did>``. Says which party the grant was written
    against."""
    _assert_segment("controller", controller)
    return f"{identifier_dependency_scope_grant(kind, identifier)}:controller:{controller}"


def parse_identifier_controller_pins(
    grants: Sequence[str], kind: str, identifier: str
) -> tuple[str, ...]:
    """Read the controller pins a grant's scope carries for one identifier. Empty means the
    grant names the identifier and says nothing about who holds it."""
    if isinstance(grants, (str, bytes)) or not isinstance(grants, Sequence):
        raise CapabilityBindingError("GRANTS_INVALID", "grants must be a sequence of strings")
    prefix = f"{identifier_dependency_scope_grant(kind, identifier)}:controller:"
    seen: list[str] = []
    for grant in grants:
        if not isinstance(grant, str) or not grant.startswith(prefix):
            continue
        value = grant[len(prefix) :]
        if value and value not in seen:
            seen.append(value)
    return tuple(seen)


@dataclass(frozen=True)
class _Interval:
    """Half-open ``[start, end)``. ``end`` of ``None`` is open-ended."""

    start: str
    end: str | None


def _covers(start: str, end: str | None, instant: str) -> bool:
    if instant < start:
        return False
    if end is None:
        return True
    return instant < end


def _subtract(gaps: Sequence[_Interval], start: str, end: str) -> list[_Interval]:
    """Subtract a covered interval from a list of gaps, half-open throughout."""
    out: list[_Interval] = []
    for gap in gaps:
        if gap.end is not None and start >= gap.end:
            out.append(gap)
            continue
        if end <= gap.start:
            out.append(gap)
            continue
        if start > gap.start:
            out.append(_Interval(gap.start, start))
        if gap.end is None or end < gap.end:
            out.append(_Interval(end, gap.end))
    return out


def _format_gaps(gaps: Sequence[_Interval]) -> str:
    return ",".join(f"{g.start}..{g.end if g.end is not None else 'open'}" for g in gaps)


def evaluate_identifier_continuity(
    *,
    identifier_kind: str,
    identifier: str,
    granted_scopes: Sequence[str],
    grant_issued_at: str,
    at: str,
    bindings: Sequence[Mapping[str, object]],
    retentions: Sequence[Mapping[str, object]],
    resolve_custodian_standing: Callable[[str], str | None],
    resolve_custodian_key: Callable[[str], str | None],
) -> IdentifierContinuityResult:
    """Decide whether the identifier this authority path depends on is still held by the
    party the grant pinned, and whether it has been continuously so since issuance.

    ``identifier_kind`` is what kind of identifier this is, for example ``mail-domain``.
    Standing is resolved per kind, because the party with standing to say who holds a mail
    domain is not the party with standing to say who holds a phone number.
    ``grant_issued_at`` is the presented delegation's ``issued_at``: continuity is measured
    from there, not from an arbitrary earlier point, because what matters is whether the
    identifier was continuously the pinned party's since the grant was written. ``at`` is
    the instant asked about, supplied and never read from a clock.

    ``resolve_custodian_standing`` is resolved by KIND and never from the ``custodian``
    member the record asserts about itself: a valid signature establishes who signed, not
    that they had standing. Returning ``None`` means the caller resolves no custodian for
    that kind, and then no record of that kind is acceptable.

    Four ordered steps:

    1. Is the dependency declared in the grant at all. A verifier that never modelled the
       identifier has no record to invalidate when control of it moves, so an undeclared
       dependency is ``not_established`` on the coverage limb rather than a silent admit.
    2. Does the grant pin who controls it. An unpinned dependency is CAND-07 v2's unpinned
       limb again: the grant names a string and says nothing about who holds it.
    3. Who holds it at ``at``, according to records from a custodian this caller resolves
       for that kind. No accepted record covering the instant is a lapse. Two accepted
       records naming different holders is an unresolved conflict between accepted sources,
       and the holder is reported as ``None`` rather than guessed.
    4. Continuity since issuance. Every interval from ``grant_issued_at`` to ``at`` must be
       either bound to the established holder or covered by an accepted retention record. A
       retention record that exists but comes from a party without standing is named
       separately from there being no retention record at all, because the two call for
       different fixes.

    Never returns an artifact verdict and never makes any delegation invalid. PROPOSED.
    """
    _assert_segment("identifier_kind", identifier_kind)
    _assert_segment("identifier", identifier)
    _assert_segment("at", at)
    _assert_segment("grant_issued_at", grant_issued_at)
    for label, seq in (
        ("granted_scopes", granted_scopes),
        ("bindings", bindings),
        ("retentions", retentions),
    ):
        if isinstance(seq, (str, bytes)) or not isinstance(seq, Sequence):
            raise CapabilityBindingError("RECORDS_INVALID", f"{label} must be a sequence")
    if not callable(resolve_custodian_standing) or not callable(resolve_custodian_key):
        raise CapabilityBindingError(
            "RESOLVER_INVALID",
            "resolve_custodian_standing and resolve_custodian_key must be callables",
        )

    dependency = identifier_dependency_scope_grant(identifier_kind, identifier)

    # Step 1.
    if dependency not in granted_scopes:
        return identifier_continuity_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="IDENTIFIER_DEPENDENCY_NOT_DECLARED",
            missing=("coverage",),
            detail=dependency,
            controller_at_instant=None,
        )

    # Step 2.
    pins = parse_identifier_controller_pins(granted_scopes, identifier_kind, identifier)
    if not pins:
        return identifier_continuity_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="IDENTIFIER_CONTROLLER_NOT_PINNED",
            missing=("coverage",),
            detail=dependency,
            controller_at_instant=None,
        )

    def acceptable(
        records: Sequence[Mapping[str, object]], unsigned_fields: Sequence[str]
    ) -> list[Mapping[str, object]]:
        out: list[Mapping[str, object]] = []
        for record in records:
            custodian = record.get("custodian")
            if not isinstance(custodian, str):
                continue
            key = resolve_custodian_key(custodian)
            if not key:
                continue
            signature = record.get("signature")
            if not isinstance(signature, str):
                continue
            if not verify_ed25519(
                identifier_record_signed_bytes(record, unsigned_fields), signature, key
            ):
                continue
            kind = record.get("identifier_kind")
            if not isinstance(kind, str):
                continue
            standing = resolve_custodian_standing(kind)
            if standing is None or standing != custodian:
                continue
            out.append(record)
        return out

    relevant = [
        b
        for b in acceptable(bindings, IDENTIFIER_BINDING_UNSIGNED_FIELDS)
        if b.get("identifier_kind") == identifier_kind and b.get("identifier") == identifier
    ]

    # Step 3.
    at_instant = [
        b
        for b in relevant
        if _covers(str(b.get("bound_from")), b.get("bound_until"), at)  # type: ignore[arg-type]
    ]
    holders = sorted({str(b.get("controller")) for b in at_instant})
    if not holders:
        return identifier_continuity_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="IDENTIFIER_BINDING_LAPSED",
            missing=("coverage",),
            detail=f"no_binding_covers={at}",
            controller_at_instant=None,
        )
    if len(holders) > 1:
        return identifier_continuity_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="IDENTIFIER_BINDING_CONFLICT",
            missing=("source",),
            detail=f"holders={'|'.join(holders)}",
            controller_at_instant=None,
        )
    holder = holders[0]
    if holder not in pins:
        # ESTABLISHED NEGATIVE. The string is the same. The party behind it is not, and the
        # verifier established that from accepted records. CAND-07 v2: a denial with a
        # mismatch reason, not ignorance. controller_at_instant names who holds it now.
        return identifier_continuity_result(
            outcome="denied",
            continuity="mismatch",
            reason_code="IDENTIFIER_CONTROLLER_CHANGED",
            detail=f"pinned={'|'.join(pins)} holder={holder}",
            controller_at_instant=holder,
        )

    # Step 4.
    gaps: list[_Interval] = [_Interval(grant_issued_at, at)]
    for binding in relevant:
        if str(binding.get("controller")) != holder:
            continue
        bound_until = binding.get("bound_until")
        gaps = _subtract(gaps, str(binding.get("bound_from")), str(bound_until) if bound_until is not None else at)
    if not gaps:
        return identifier_continuity_result(
            outcome="authorized",
            continuity="established",
            reason_code="IDENTIFIER_CONTINUITY_ESTABLISHED",
            detail="continuously_bound",
            controller_at_instant=holder,
        )

    acceptable_retentions = [
        r
        for r in acceptable(retentions, IDENTIFIER_RETENTION_UNSIGNED_FIELDS)
        if r.get("identifier_kind") == identifier_kind and r.get("identifier") == identifier
    ]
    uncovered: list[_Interval] = list(gaps)
    for retention in acceptable_retentions:
        uncovered = _subtract(
            uncovered, str(retention.get("retained_from")), str(retention.get("retained_until"))
        )
    if not uncovered:
        return identifier_continuity_result(
            outcome="authorized",
            continuity="established",
            reason_code="IDENTIFIER_CONTINUITY_ESTABLISHED",
            detail=f"retained_gap={_format_gaps(gaps)}",
            controller_at_instant=holder,
        )

    # A retention record that exists but does not count is worth naming apart from there
    # being no retention record at all: the first is a standing problem and the second is a
    # missing record, and they call for different fixes.
    present_but_unacceptable = [
        r
        for r in retentions
        if r.get("identifier_kind") == identifier_kind
        and r.get("identifier") == identifier
        and not any(r is a for a in acceptable_retentions)
    ]
    would_be_covered: list[_Interval] = list(uncovered)
    for retention in present_but_unacceptable:
        would_be_covered = _subtract(
            would_be_covered,
            str(retention.get("retained_from")),
            str(retention.get("retained_until")),
        )
    if not would_be_covered:
        custodians = sorted({str(r.get("custodian")) for r in present_but_unacceptable})
        return identifier_continuity_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="RETENTION_CUSTODIAN_WITHOUT_STANDING",
            missing=("source",),
            detail="|".join(custodians),
            controller_at_instant=holder,
        )
    return identifier_continuity_result(
        outcome="not_established",
        continuity="not_established",
        reason_code="IDENTIFIER_CONTINUITY_GAP_UNCOVERED",
        missing=("coverage",),
        detail=_format_gaps(uncovered),
        controller_at_instant=holder,
    )
