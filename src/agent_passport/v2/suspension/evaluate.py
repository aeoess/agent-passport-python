# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Evaluating a set of lifecycle causes at one instant.

See ``types.py`` for the specification position: nothing here is required by
draft-pidlisnyi-aps-03, and nothing here changes any existing exported behaviour.

Python port of the TypeScript SDK's src/v2/suspension/evaluate.ts. Same names, same
semantics, snake_case per Python convention. The one shape difference is the loader pair
:func:`suspension_cause_from_mapping` and :func:`suspension_release_from_mapping`: the
TypeScript records are plain objects with an index signature and the Python ones are frozen
dataclasses carrying an ``extra`` mapping, so Python needs an explicit step from a parsed
record to a typed one. The signed preimage is identical either way.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ...canonical import canonicalize_jcs
from ...crypto import verify as verify_ed25519
from ..lifecycle_state.state import lifecycle_state, not_established
from ..lifecycle_state.types import LifecycleStateResult, OutstandingCause
from .types import (
    PAUSE_KINDS,
    RELEASE_STANDINGS,
    SUSPENSION_CAUSE_TYPE,
    SUSPENSION_RELEASE_TYPE,
    CauseDisposition,
    PauseStateExplanation,
    ReleaseCauseDisposition,
    ReleaseDisposition,
    ReleaseStandingResolver,
    SuspensionCause,
    SuspensionRelease,
    SuspensionVerificationKeyResolver,
)

_CAUSE_NAMED_FIELDS = (
    "record_type",
    "cause_id",
    "delegation_id",
    "kind",
    "imposed_by",
    "issued_at",
    "reason_code",
    "verification_method",
    "signature",
    "release_authority",
)

_RELEASE_NAMED_FIELDS = (
    "record_type",
    "release_id",
    "delegation_id",
    "cause_ids",
    "issuer",
    "issued_at",
    "verification_method",
    "signature",
)


class SuspensionCauseError(ValueError):
    """Raised when the INPUT is malformed, never as a verdict.

    The line this module draws: a record that is well formed but fails a check is a
    disposition and feeds the verdict. A caller who passes a cause with no ``cause_id``,
    two causes sharing one ``cause_id`` or a resolver that answers off the vocabulary has
    made a programming error, and a programming error is not a finding about anybody's
    authority. Same split, and same shape, as ``LifecycleStateError``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def suspension_record_preimage(record: Mapping[str, Any]) -> str:
    """The signed preimage of a cause or release record.

    Every member except ``signature`` and ``record_id``, canonicalized under RFC 8785 by
    this SDK's own canonicalizer. ``record_id`` is excluded because where a record carries
    one it is a content address over these very bytes and cannot be inside its own
    preimage, which is the convention ``v2/instruction_provenance`` already follows for its
    ``receipt_id``. Every other member signs, including members this module does not read,
    so an extension cannot be added to a record after signing.
    """
    body = {k: v for k, v in record.items() if k not in ("signature", "record_id")}
    return canonicalize_jcs(body)


def suspension_cause_from_mapping(record: Mapping[str, Any]) -> SuspensionCause:
    """Build a :class:`SuspensionCause` from a parsed record, keeping unknown members.

    Nothing is dropped: members this class does not name land in ``extra`` and still sign.
    """
    if not isinstance(record, Mapping):
        raise SuspensionCauseError("CAUSE_MALFORMED", "cause record is not a mapping")
    extra = {k: v for k, v in record.items() if k not in _CAUSE_NAMED_FIELDS}
    return SuspensionCause(
        record_type=record.get("record_type"),  # type: ignore[arg-type]
        cause_id=record.get("cause_id"),  # type: ignore[arg-type]
        delegation_id=record.get("delegation_id"),  # type: ignore[arg-type]
        kind=record.get("kind"),  # type: ignore[arg-type]
        imposed_by=record.get("imposed_by"),  # type: ignore[arg-type]
        issued_at=record.get("issued_at"),  # type: ignore[arg-type]
        reason_code=record.get("reason_code"),  # type: ignore[arg-type]
        verification_method=record.get("verification_method"),  # type: ignore[arg-type]
        signature=record.get("signature"),  # type: ignore[arg-type]
        release_authority=record.get("release_authority"),
        extra=extra,
    )


def suspension_release_from_mapping(record: Mapping[str, Any]) -> SuspensionRelease:
    """Build a :class:`SuspensionRelease` from a parsed record, keeping unknown members."""
    if not isinstance(record, Mapping):
        raise SuspensionCauseError("RELEASE_MALFORMED", "release record is not a mapping")
    extra = {k: v for k, v in record.items() if k not in _RELEASE_NAMED_FIELDS}
    cause_ids = record.get("cause_ids")
    return SuspensionRelease(
        record_type=record.get("record_type"),  # type: ignore[arg-type]
        release_id=record.get("release_id"),  # type: ignore[arg-type]
        delegation_id=record.get("delegation_id"),  # type: ignore[arg-type]
        cause_ids=tuple(cause_ids) if isinstance(cause_ids, (list, tuple)) else cause_ids,  # type: ignore[arg-type]
        issuer=record.get("issuer"),  # type: ignore[arg-type]
        issued_at=record.get("issued_at"),  # type: ignore[arg-type]
        verification_method=record.get("verification_method"),  # type: ignore[arg-type]
        signature=record.get("signature"),  # type: ignore[arg-type]
        extra=extra,
    )


def _cause_body(cause: SuspensionCause) -> dict[str, Any]:
    body: dict[str, Any] = {
        "record_type": cause.record_type,
        "cause_id": cause.cause_id,
        "delegation_id": cause.delegation_id,
        "kind": cause.kind,
        "imposed_by": cause.imposed_by,
        "issued_at": cause.issued_at,
        "reason_code": cause.reason_code,
        "verification_method": cause.verification_method,
        "signature": cause.signature,
    }
    if cause.release_authority is not None:
        body["release_authority"] = cause.release_authority
    body.update(dict(cause.extra))
    return body


def _release_body(release: SuspensionRelease) -> dict[str, Any]:
    body: dict[str, Any] = {
        "record_type": release.record_type,
        "release_id": release.release_id,
        "delegation_id": release.delegation_id,
        "cause_ids": list(release.cause_ids),
        "issuer": release.issuer,
        "issued_at": release.issued_at,
        "verification_method": release.verification_method,
        "signature": release.signature,
    }
    body.update(dict(release.extra))
    return body


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def _assert_cause_shape(cause: SuspensionCause, index: int) -> None:
    if not isinstance(cause, SuspensionCause):
        raise SuspensionCauseError(
            "CAUSE_MALFORMED", f"causes[{index}] is not a SuspensionCause"
        )
    for name in (
        "record_type",
        "cause_id",
        "delegation_id",
        "imposed_by",
        "issued_at",
        "reason_code",
        "verification_method",
        "signature",
    ):
        if not _is_non_empty_string(getattr(cause, name)):
            raise SuspensionCauseError(
                "CAUSE_MALFORMED", f"causes[{index}].{name} must be a non-empty string"
            )
    if cause.kind not in PAUSE_KINDS:
        raise SuspensionCauseError(
            "CAUSE_KIND_UNKNOWN",
            f"causes[{index}].kind must be one of {', '.join(PAUSE_KINDS)}",
        )


def _assert_release_shape(release: SuspensionRelease, index: int) -> None:
    if not isinstance(release, SuspensionRelease):
        raise SuspensionCauseError(
            "RELEASE_MALFORMED", f"releases[{index}] is not a SuspensionRelease"
        )
    for name in (
        "record_type",
        "release_id",
        "delegation_id",
        "issuer",
        "issued_at",
        "verification_method",
        "signature",
    ):
        if not _is_non_empty_string(getattr(release, name)):
            raise SuspensionCauseError(
                "RELEASE_MALFORMED", f"releases[{index}].{name} must be a non-empty string"
            )
    if isinstance(release.cause_ids, str) or not isinstance(release.cause_ids, (list, tuple)):
        raise SuspensionCauseError(
            "RELEASE_MALFORMED", f"releases[{index}].cause_ids must be a sequence"
        )
    for i, cause_id in enumerate(release.cause_ids):
        if not _is_non_empty_string(cause_id):
            raise SuspensionCauseError(
                "RELEASE_MALFORMED",
                f"releases[{index}].cause_ids[{i}] must be a non-empty string",
            )


def _signature_verifies(
    body: Mapping[str, Any],
    signer: str,
    resolve_verification_key: SuspensionVerificationKeyResolver,
) -> bool:
    method = body.get("verification_method")
    if not isinstance(method, str):
        return False
    try:
        public_key = resolve_verification_key(signer, method)
    except Exception:  # noqa: BLE001 - a broken resolver fails the record closed
        return False
    signature = body.get("signature")
    if not isinstance(public_key, str) or not public_key:
        return False
    if not isinstance(signature, str) or not signature:
        return False
    try:
        return verify_ed25519(suspension_record_preimage(body), signature, public_key)
    except Exception:  # noqa: BLE001
        return False


def _dispose_cause(
    cause: SuspensionCause,
    delegation_id: str,
    at_instant: str,
    resolve_verification_key: SuspensionVerificationKeyResolver,
) -> CauseDisposition:
    """Which disposition a cause gets, or ``CAUSE_IN_EVIDENCE`` when it survives.

    The order matters and is the order below: a record that is not this artifact's cause is
    not judged on its signature, and a record not yet in evidence at this instant is not
    judged on anything else.
    """
    if cause.delegation_id != delegation_id:
        return CauseDisposition(cause.cause_id, "CAUSE_NOT_ON_DELEGATION")
    if cause.record_type != SUSPENSION_CAUSE_TYPE:
        return CauseDisposition(cause.cause_id, "CAUSE_RECORD_TYPE_UNRECOGNISED")
    if cause.issued_at > at_instant:
        return CauseDisposition(cause.cause_id, "CAUSE_NOT_YET_IN_EVIDENCE")
    # An unverified claim must not become a lifecycle state. A cause record whose signature
    # does not verify holds nothing: reporting ``suspended`` on it would convert an
    # unauthenticated assertion into a pause the artifact never carried.
    if not _signature_verifies(_cause_body(cause), cause.imposed_by, resolve_verification_key):
        return CauseDisposition(cause.cause_id, "CAUSE_SIGNATURE_UNVERIFIED")
    if not cause.verification_method.startswith(f"{cause.imposed_by}#"):
        return CauseDisposition(cause.cause_id, "CAUSE_IMPOSER_BINDING_MISMATCH")
    return CauseDisposition(cause.cause_id, "CAUSE_IN_EVIDENCE")


def _dispose_release(
    release: SuspensionRelease,
    in_evidence: Mapping[str, SuspensionCause],
    delegation_id: str,
    at_instant: str,
    resolve_release_standing: ReleaseStandingResolver,
    resolve_verification_key: SuspensionVerificationKeyResolver,
) -> ReleaseDisposition:
    """Apply one release record.

    A record-level rejection releases nothing and reports no per-cause entries, because the
    record was never applied to any cause.
    """
    if release.delegation_id != delegation_id:
        return ReleaseDisposition(release.release_id, "RELEASE_NOT_ON_DELEGATION")
    if release.record_type != SUSPENSION_RELEASE_TYPE:
        return ReleaseDisposition(release.release_id, "RELEASE_RECORD_TYPE_UNRECOGNISED")
    if not _signature_verifies(_release_body(release), release.issuer, resolve_verification_key):
        return ReleaseDisposition(release.release_id, "RELEASE_SIGNATURE_UNVERIFIED")
    if not release.verification_method.startswith(f"{release.issuer}#"):
        return ReleaseDisposition(release.release_id, "RELEASE_ISSUER_BINDING_MISMATCH")
    # A release recorded after the instant being evaluated is not in evidence there. It is
    # in evidence at a later one, and nothing about the record changes in between. The
    # proposed text says nothing about when a release takes effect, so this is a reading.
    if release.issued_at > at_instant:
        return ReleaseDisposition(release.release_id, "RELEASE_AFTER_EVALUATION_INSTANT")

    # Per named cause, independently. A record naming three causes from a party holding
    # standing over two of them clears exactly those two. Naming a cause in a release is not
    # the same as being able to release it.
    causes: list[ReleaseCauseDisposition] = []
    for cause_id in release.cause_ids:
        cause = in_evidence.get(cause_id)
        if cause is None:
            causes.append(ReleaseCauseDisposition(cause_id, "CAUSE_NOT_PRESENTED"))
            continue
        if release.issued_at < cause.issued_at:
            causes.append(ReleaseCauseDisposition(cause_id, "RELEASE_PRECEDES_IMPOSITION"))
            continue
        standing = resolve_release_standing(release, cause)
        if standing not in RELEASE_STANDINGS:
            raise SuspensionCauseError(
                "STANDING_ANSWER_UNKNOWN",
                f"resolve_release_standing must answer one of {', '.join(RELEASE_STANDINGS)}",
            )
        if standing == "has_standing":
            causes.append(ReleaseCauseDisposition(cause_id, "CAUSE_RELEASED"))
        elif standing == "no_standing":
            causes.append(ReleaseCauseDisposition(cause_id, "RELEASER_WITHOUT_STANDING"))
        else:
            causes.append(
                ReleaseCauseDisposition(cause_id, "RELEASE_STANDING_NOT_ESTABLISHED")
            )
    return ReleaseDisposition(release.release_id, "RELEASE_IN_EVIDENCE", tuple(causes))


def explain_pause_state(
    *,
    delegation_id: str,
    causes: Sequence[SuspensionCause],
    releases: Sequence[SuspensionRelease],
    at_instant: str,
    resolve_release_standing: ReleaseStandingResolver,
    resolve_verification_key: SuspensionVerificationKeyResolver,
) -> PauseStateExplanation:
    """Evaluate a set of lifecycle causes at one instant, with the audit trail.

    :func:`evaluate_pause_state` is the same computation returning only ``state``. Use this
    one when you have to record why each record did or did not move the answer.

    WHAT THE VERDICT MEANS, AND WHAT IT DOES NOT. This module looked at causes and releases.
    It did not verify a chain, did not resolve a revocation and did not read a time facet.
    So a ``valid`` verdict here means exactly "no cause holds this artifact paused at this
    instant" and NOTHING MORE. It is not a statement that the artifact confers authority.
    Compose it with a chain result through :func:`compose_chain_and_pause` before anything
    treats the artifact as exercisable.

    No clock, no network and no ambient state: the instant is a parameter and both resolvers
    are caller supplied.

    Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L8 and invariant
    candidate CAND-05.
    """
    if not _is_non_empty_string(delegation_id):
        raise SuspensionCauseError("INPUT_MALFORMED", "delegation_id must be a non-empty string")
    if not _is_non_empty_string(at_instant):
        raise SuspensionCauseError("INPUT_MALFORMED", "at_instant must be a non-empty string")
    if isinstance(causes, (str, bytes)) or not isinstance(causes, (list, tuple)):
        raise SuspensionCauseError("INPUT_MALFORMED", "causes must be a sequence")
    if isinstance(releases, (str, bytes)) or not isinstance(releases, (list, tuple)):
        raise SuspensionCauseError("INPUT_MALFORMED", "releases must be a sequence")
    if not callable(resolve_release_standing):
        raise SuspensionCauseError("INPUT_MALFORMED", "resolve_release_standing must be callable")
    if not callable(resolve_verification_key):
        raise SuspensionCauseError("INPUT_MALFORMED", "resolve_verification_key must be callable")

    for index, cause in enumerate(causes):
        _assert_cause_shape(cause, index)
    for index, release in enumerate(releases):
        _assert_release_shape(release, index)

    seen_cause_ids: set[str] = set()
    for cause in causes:
        if cause.cause_id in seen_cause_ids:
            raise SuspensionCauseError(
                "DUPLICATE_CAUSE_ID", f"cause_id {cause.cause_id} appears more than once"
            )
        seen_cause_ids.add(cause.cause_id)
    seen_release_ids: set[str] = set()
    for release in releases:
        if release.release_id in seen_release_ids:
            raise SuspensionCauseError(
                "DUPLICATE_RELEASE_ID",
                f"release_id {release.release_id} appears more than once",
            )
        seen_release_ids.add(release.release_id)

    cause_dispositions = [
        _dispose_cause(cause, delegation_id, at_instant, resolve_verification_key)
        for cause in causes
    ]
    in_evidence: dict[str, SuspensionCause] = {}
    for cause, disposition in zip(causes, cause_dispositions):
        if disposition.disposition == "CAUSE_IN_EVIDENCE":
            in_evidence[cause.cause_id] = cause

    release_dispositions = [
        _dispose_release(
            release,
            in_evidence,
            delegation_id,
            at_instant,
            resolve_release_standing,
            resolve_verification_key,
        )
        for release in releases
    ]

    # A cause released by ANY accepted record is released. A cause for which some record got
    # ``unknown`` standing and no record released it is unresolved: this verifier did not
    # establish whether it still holds.
    released_by: dict[str, str] = {}
    unresolved: set[str] = set()
    for release_disposition in release_dispositions:
        for entry in release_disposition.causes:
            if entry.disposition == "CAUSE_RELEASED" and entry.cause_id not in released_by:
                released_by[entry.cause_id] = release_disposition.release_id
            elif entry.disposition == "RELEASE_STANDING_NOT_ESTABLISHED":
                unresolved.add(entry.cause_id)
    unresolved -= set(released_by)

    final_causes: list[CauseDisposition] = []
    for disposition in cause_dispositions:
        release_id = released_by.get(disposition.cause_id)
        if disposition.disposition == "CAUSE_IN_EVIDENCE" and release_id is not None:
            final_causes.append(
                CauseDisposition(disposition.cause_id, "CAUSE_RELEASED", release_id)
            )
        else:
            final_causes.append(disposition)

    # Sorted by cause_id, which is a presentation choice with no claim behind it. CAND-05
    # defines no precedence order among causes and says so, and nothing here depends on one
    # cause outranking another.
    remaining = sorted(
        (c for c in in_evidence.values() if c.cause_id not in released_by),
        key=lambda c: c.cause_id,
    )
    outstanding = tuple(
        OutstandingCause(id=c.cause_id, kind=c.kind, reason_code=c.reason_code)
        for c in remaining
    )

    def _explain(state: LifecycleStateResult) -> PauseStateExplanation:
        # ``outstanding`` mirrors ``state.outstanding`` exactly, and is empty where the state
        # carries none. On a ``not_established`` verdict that means empty: a verifier that
        # could not establish the pause state has no set to vouch for, and publishing the
        # causes it would have named alongside an admission of ignorance is the collapse this
        # vocabulary prevents.
        return PauseStateExplanation(
            state=state,
            causes=tuple(final_causes),
            releases=tuple(release_dispositions),
            outstanding=tuple(state.outstanding or ()),
        )

    # An unresolved cause is reported as unresolved. Reporting ``suspended`` would claim a
    # finding this verifier did not reach, which is the exact collapse the lifecycle
    # vocabulary's two uses of "not established" exist to prevent: failing to establish that
    # a cause was released is not establishing that it still holds. The other reading, that
    # an unreleased cause holds until a release is established, is available and defensible.
    # The proposed text settles neither, and this one is recorded as an open question.
    if unresolved:
        return _explain(not_established(["source"], "RELEASE_STANDING_NOT_ESTABLISHED"))

    if not remaining:
        if len(causes) == 0:
            reason_code = "NO_CAUSE_PRESENTED"
        elif not in_evidence:
            reason_code = "NO_CAUSE_IN_EVIDENCE"
        else:
            reason_code = "ALL_CAUSES_RELEASED"
        return _explain(lifecycle_state(verdict="valid", reason_code=reason_code))

    # Any remaining cause of kind ``suspension`` holds the artifact suspended. With only
    # restrictions left it is restricted, which is the distinction invariant L8 draws:
    # suspension stops the use of authority, a restriction is different again and does not
    # have to pause descendants.
    any_suspension = any(c.kind == "suspension" for c in remaining)
    return _explain(
        lifecycle_state(
            verdict="suspended" if any_suspension else "restricted",
            reason_code="CAUSES_OUTSTANDING",
            outstanding=outstanding,
        )
    )


def evaluate_pause_state(
    *,
    delegation_id: str,
    causes: Sequence[SuspensionCause],
    releases: Sequence[SuspensionRelease],
    at_instant: str,
    resolve_release_standing: ReleaseStandingResolver,
    resolve_verification_key: SuspensionVerificationKeyResolver,
) -> LifecycleStateResult:
    """Evaluate a set of lifecycle causes against one authority artifact at one instant.

    The result's ``outstanding`` member is the remaining cause set. NEVER A COUNT AND NEVER
    A BOOLEAN: that member being a list is the whole of CAND-05 in one field. An
    implementation holding a single suspended flag conforms to every word of invariant L8,
    which says nothing about arity, and still gets a regulatory suspension lapsing while an
    unrelated internal restriction stands exactly backwards, because the first effective
    release looks to it like a full restoration.

    See :func:`explain_pause_state` for the same computation with the per-record audit
    trail, and :func:`compose_chain_and_pause` for what a ``valid`` verdict here does and
    does not entitle a caller to conclude.

    Proposed. Concept source: aeoess/agent-authority-lifecycle, invariant L8 and invariant
    candidate CAND-05.
    """
    return explain_pause_state(
        delegation_id=delegation_id,
        causes=causes,
        releases=releases,
        at_instant=at_instant,
        resolve_release_standing=resolve_release_standing,
        resolve_verification_key=resolve_verification_key,
    ).state


def compose_chain_and_pause(
    chain: LifecycleStateResult, pause: LifecycleStateResult
) -> LifecycleStateResult:
    """Compose a chain result and a pause state into one lifecycle answer, chain first.

    A RELEASE NEVER CLEARS A REVOCATION THAT HAPPENED MEANWHILE. That is the rule this
    function exists to make unavoidable, and ``OPEN-QUESTIONS.md`` states it directly:
    lifting one suspension should not clear another, "bypass a revocation that happened
    while the agent was suspended, or recreate rights that changed in the meantime". A grant
    revoked during its suspension is invalid once every cause has been lifted, because
    draft-03 section 3.5 says verbatim "Revocation is irreversible" and a release record is
    a later record about the causes, not about the chain. It never reaches the chain result.

    So: when ``chain`` is anything other than ``valid``, ``chain`` is returned UNCHANGED and
    the pause state is not reported. When ``chain`` is ``valid``, the pause state is the
    answer.

    Both arguments come from the six-value lifecycle vocabulary. Get ``chain`` from
    ``map_authority_validation_to_lifecycle`` over a real ``AuthorityValidationResult``,
    which leaves the draft-03 four-value result untouched, and ``pause`` from
    :func:`evaluate_pause_state`. A caller wanting both raw results side by side has
    ``CompositeAuthorityResult``.

    WHAT THIS DOES NOT DECIDE. The reverse ordering: a revoked or indeterminate chain with
    causes still outstanding. This function reports the chain, which is a choice of what to
    report first and not a claim that the causes stopped mattering. No published text and no
    proposed text settles it. Recorded as an open question rather than papered over.

    Proposed.
    """
    if not isinstance(chain, LifecycleStateResult):
        raise SuspensionCauseError("INPUT_MALFORMED", "chain must be a LifecycleStateResult")
    if not isinstance(pause, LifecycleStateResult):
        raise SuspensionCauseError("INPUT_MALFORMED", "pause must be a LifecycleStateResult")
    return pause if chain.verdict == "valid" else chain
