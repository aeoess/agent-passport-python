# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The multi-source status decision.

See ``types.py`` for the specification position: nothing here is required by
draft-pidlisnyi-aps-03, everything here is experimental against the
aeoess/agent-authority-lifecycle invariant candidate BROAD-L7, and nothing here changes any
existing exported behaviour.

Pure. No clock, no network, no crypto, no policy grammar and no evaluator. Every instant
arrives as a string and is parsed with the SDK's own strict RFC 3339 parser, so this port
and the TypeScript one agree on what an instant is rather than each reaching for a language
date library.

Python port of the TypeScript SDK's src/v2/status-coverage/decide.ts.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..._time import parse_rfc3339
from ..lifecycle_state.state import lifecycle_state, not_established
from ..lifecycle_state.types import LifecycleStateResult
from .types import (
    CONFLICT_POLICIES,
    SILENCE_POLICIES,
    STATUS_ANSWERS,
    VERIFIER_MODES,
    AdmittedSnapshot,
    MultiSourceStatusBasis,
    MultiSourceStatusDecision,
    StaleAnswerPolicy,
    StatusConflict,
    StatusCoverage,
    StatusCoverageError,
    StatusSourceLine,
    StatusTrustPolicy,
)


def _require_instant(value: object, field: str) -> int:
    parsed = parse_rfc3339(value)
    if parsed.ms is None:
        raise StatusCoverageError(
            "INSTANT_INVALID",
            f"{field} must be an RFC 3339 instant, got {parsed.reason}",
        )
    return parsed.ms


def _require_whole_second_bound(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatusCoverageError(
            "BOUND_INVALID",
            f"{field} must be a non-negative whole number of seconds",
        )
    return value


def _require_non_empty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or value == "":
        raise StatusCoverageError("FIELD_INVALID", f"{field} must be a non-empty string")
    return value


def _answer_of(candidate: Any) -> str:
    answer = getattr(candidate, "answer", None)
    if answer is None and isinstance(candidate, dict):
        answer = candidate.get("answer")
    if not isinstance(answer, str) or answer not in STATUS_ANSWERS:
        raise StatusCoverageError(
            "ANSWER_UNKNOWN",
            f"answers[].answer must be one of {', '.join(STATUS_ANSWERS)}",
        )
    return answer


def _field_of(candidate: Any, name: str) -> Any:
    if isinstance(candidate, dict):
        return candidate.get(name)
    return getattr(candidate, name, None)


def decide_multi_source_status(
    *,
    authority_ref: str,
    trust_policy: StatusTrustPolicy,
    answers: Sequence[Any],
    conflict_policy: str,
    stale_policy: StaleAnswerPolicy,
    now: str,
) -> MultiSourceStatusDecision:
    """Decide what an authorization boundary can establish about one ``authority_ref`` from a
    SET of status answers, each measured against the freshness bound declared for its own
    source.

    BROAD-L7 in one function, for the source and freshness limbs, plus a declared-set
    coverage report that is explicitly not a completeness claim. The procedure, in order, and
    every step is a consequence of the candidate rather than a design preference:

    1. Age every answer against ``now``. An answer is within bound when its age is at most
       the bound declared for its source, inclusive. An answer dated after the boundary is
       refused as skew rather than read as fresh.
    2. Decide which answers are USED. ``unavailable`` is never used. Within bound is used.
       Past bound is used only where ``stale_policy`` says that class of answer still counts,
       and the line records which of the two it was.
    3. If the used answers carry more than one determinate state, that is a conflict. Per
       ``conflict_policy`` the boundary denies or returns not established. The artifact state
       is NOT ESTABLISHED either way, with the source limb missing, never invalid: a conflict
       is the verifier failing to reach a conclusion, not a finding that the authority ended.
       A conflict never admits, whatever coverage says.
    4. If every used answer is ``revoked``, the boundary denies and the artifact state is
       invalid. Checked BEFORE coverage, because an observed revocation from an accepted
       source does not need a complete source set to count, and before the offline branch,
       because being offline does not soften an observed revocation.
    5. Offline mode resolves on the declared snapshot: inside its declared bound and active,
       the boundary admits and the basis names the snapshot and the age it admitted at. Past
       the bound, the freshness limb is missing. No snapshot answer at all, the source limb is
       missing.
    6. Online mode admits only when coverage is complete under the declared reading and every
       used answer is active. Short of that the reason distinguishes no usable answer at all,
       a silent required source, and a required source whose answer was past its bound.

    Nothing in the result is the negation of a claim. ``not_established`` is ignorance about
    the authority and never a statement that the authority is inactive, active, or anything
    about the world.

    Concept source: aeoess/agent-authority-lifecycle, invariant candidate BROAD-L7 and
    invariant L7. Proposed, and the two policy parameters mark the two places the proposed
    text does not choose.
    """
    authority = _require_non_empty_string(authority_ref, "authority_ref")
    now_ms = _require_instant(now, "now")

    if trust_policy is None:
        raise StatusCoverageError("INPUT_INVALID", "trust_policy is required")
    mode = _field_of(trust_policy, "mode")
    if mode not in VERIFIER_MODES:
        raise StatusCoverageError(
            "MODE_UNKNOWN", "trust_policy.mode must be online or offline"
        )
    source_set = _field_of(trust_policy, "sources")
    required_declared = _field_of(source_set, "required") if source_set is not None else None
    if not isinstance(required_declared, (list, tuple)):
        raise StatusCoverageError(
            "INPUT_INVALID", "trust_policy.sources.required must be a sequence"
        )
    silence_is = _field_of(source_set, "silence_is")
    if silence_is not in SILENCE_POLICIES:
        raise StatusCoverageError(
            "SILENCE_POLICY_REQUIRED",
            "trust_policy.sources.silence_is is required and has no default: it decides "
            "whether a silent required source is a coverage gap or an unavailable answer",
        )
    if len(required_declared) == 0:
        raise StatusCoverageError(
            "REQUIRED_SET_EMPTY",
            "trust_policy.sources.required must name at least one source: a verifier that "
            "accepts no source for a claim cannot establish it",
        )

    if conflict_policy not in CONFLICT_POLICIES:
        raise StatusCoverageError(
            "CONFLICT_POLICY_REQUIRED",
            "conflict_policy is required and has no default: the proposed text does not "
            "choose between denying on a conflict and returning not established",
        )
    if (
        stale_policy is None
        or not isinstance(_field_of(stale_policy, "stale_revoked_still_counts"), bool)
        or not isinstance(_field_of(stale_policy, "stale_active_still_counts"), bool)
    ):
        raise StatusCoverageError(
            "STALE_POLICY_REQUIRED",
            "stale_policy is required with both members set and has no default: whether an "
            "answer past its own bound still counts decides the deployment-relevant case and "
            "the proposed text does not choose",
        )
    stale_revoked_counts = bool(_field_of(stale_policy, "stale_revoked_still_counts"))
    stale_active_counts = bool(_field_of(stale_policy, "stale_active_still_counts"))

    bounds: dict[str, int] = {}
    required_ids: list[str] = []
    for declared in required_declared:
        source_id = _require_non_empty_string(
            _field_of(declared, "source_id"), "required[].source_id"
        )
        if source_id in bounds:
            raise StatusCoverageError(
                "SOURCE_DECLARED_TWICE",
                f"source {source_id} is declared more than once, so its bound is ambiguous",
            )
        bounds[source_id] = _require_whole_second_bound(
            _field_of(declared, "freshness_bound_s"), f"{source_id}.freshness_bound_s"
        )
        required_ids.append(source_id)

    snapshot_id: str | None = None
    snapshot_bound_s = 0
    snapshot_source = _field_of(trust_policy, "snapshot_source")
    if mode == "offline":
        if snapshot_source is None:
            raise StatusCoverageError(
                "SNAPSHOT_SOURCE_REQUIRED",
                "offline mode requires trust_policy.snapshot_source with a declared bound: "
                "BROAD-L7 forbids admitting on a snapshot with no declared bound",
            )
        snapshot_id = _require_non_empty_string(
            _field_of(snapshot_source, "source_id"), "snapshot_source.source_id"
        )
        snapshot_bound_s = _require_whole_second_bound(
            _field_of(snapshot_source, "declared_bound_s"),
            "snapshot_source.declared_bound_s",
        )
        if snapshot_id in bounds:
            raise StatusCoverageError(
                "SNAPSHOT_SOURCE_ALSO_REQUIRED",
                f"{snapshot_id} is both the snapshot source and a required source, so which "
                "bound applies is ambiguous",
            )
    elif snapshot_source is not None:
        raise StatusCoverageError(
            "SNAPSHOT_SOURCE_NOT_ALLOWED",
            "trust_policy.snapshot_source is only meaningful in offline mode",
        )

    if not isinstance(answers, (list, tuple)):
        raise StatusCoverageError("INPUT_INVALID", "answers must be a sequence")

    # -- step 1 and 2: age every answer, decide which are used ----------------
    lines: list[StatusSourceLine] = []
    seen: set[str] = set()
    for supplied in answers:
        source_id = _require_non_empty_string(
            _field_of(supplied, "source_id"), "answers[].source_id"
        )
        if source_id in seen:
            raise StatusCoverageError(
                "SOURCE_ANSWERED_TWICE",
                f"source {source_id} supplied more than one answer, which is a conflict "
                "inside one source rather than between two and is not what this module decides",
            )
        seen.add(source_id)
        answer = _answer_of(supplied)
        as_of = _field_of(supplied, "as_of")
        accepted = source_id in bounds or source_id == snapshot_id
        bound_s = snapshot_bound_s if source_id == snapshot_id else bounds.get(source_id)

        if not accepted:
            lines.append(
                StatusSourceLine(
                    source_id=source_id,
                    answer=answer,
                    as_of=as_of if isinstance(as_of, str) else None,
                    age_s=None,
                    freshness_bound_s=None,
                    within_bound=False,
                    used=False,
                    use_basis="source_not_accepted",
                )
            )
            continue

        if answer == "unavailable":
            if as_of is not None:
                raise StatusCoverageError(
                    "UNAVAILABLE_CARRIES_AS_OF",
                    f"source {source_id} answered unavailable and also supplied as_of: an "
                    "unavailable answer dates nothing",
                )
            lines.append(
                StatusSourceLine(
                    source_id=source_id,
                    answer=answer,
                    as_of=None,
                    age_s=None,
                    freshness_bound_s=bound_s,
                    within_bound=False,
                    used=False,
                    use_basis="source_gave_no_answer",
                )
            )
            continue

        as_of_ms = _require_instant(as_of, f"answers[{source_id}].as_of")
        age_s = (now_ms - as_of_ms) // 1000
        if age_s < 0:
            lines.append(
                StatusSourceLine(
                    source_id=source_id,
                    answer=answer,
                    as_of=as_of,
                    age_s=age_s,
                    freshness_bound_s=bound_s,
                    within_bound=False,
                    used=False,
                    use_basis="answer_dated_after_boundary",
                )
            )
            continue

        within_bound = bound_s is not None and age_s <= bound_s
        used = within_bound
        basis = "within_freshness_bound"
        if not within_bound:
            if answer == "revoked" and stale_revoked_counts:
                used = True
                basis = "revocation_observed_outside_bound_still_used"
            elif answer == "active" and stale_active_counts:
                used = True
                basis = "stale_active_admitted_by_policy"
            else:
                used = False
                basis = "stale_beyond_bound"
        lines.append(
            StatusSourceLine(
                source_id=source_id,
                answer=answer,
                as_of=as_of,
                age_s=age_s,
                freshness_bound_s=bound_s,
                within_bound=within_bound,
                used=used,
                use_basis=basis,
            )
        )

    by_id = {line.source_id: line for line in lines}
    silent = sorted(sid for sid in required_ids if sid not in by_id)
    answered_required = [sid for sid in required_ids if sid in by_id]
    usable_required = [
        sid
        for sid in required_ids
        if sid in by_id and by_id[sid].used and by_id[sid].answer != "unavailable"
    ]

    measured_over = (
        "declared_required_set" if silence_is == "coverage_gap" else "sources_that_answered"
    )
    denominator = (
        len(required_ids) if measured_over == "declared_required_set" else len(answered_required)
    )
    coverage = StatusCoverage(
        required=len(required_ids),
        answered=len(answered_required),
        usable_determinate=len(usable_required),
        silent=tuple(silent),
        measured_over=measured_over,
        complete=denominator > 0 and len(usable_required) == denominator,
    )

    used_determinate = [l for l in lines if l.used and l.answer != "unavailable"]
    used_states = sorted({l.answer for l in used_determinate})
    any_stale = any(
        l.use_basis in ("stale_beyond_bound", "answer_dated_after_boundary") for l in lines
    )

    def missing_limbs(conflicted: bool) -> list[str]:
        """Which of BROAD-L7's three limbs were missing, computed MECHANICALLY from what the
        boundary actually had, in the canonical order source, freshness, coverage.

        More than one can be missing at once and all of them are reported. A denial that
        names one limb when two were missing understates what the verifier did not have, and
        the reason code, not the limb list, is what says which gap the module treated as the
        headline.

        - ``source``    no accepted source produced a usable determinate answer, or two
                        accepted sources are in unresolved conflict. Both are BROAD-L7's
                        source limb as the lifecycle-state vocabulary states it.
        - ``freshness`` at least one answer was past the bound declared for its source, or
                        was dated after the boundary so no age against the bound was
                        measurable.
        - ``coverage``  the answers the boundary had do not cover what the verdict needed,
                        which is ``coverage.complete`` being false. Which denominator that
                        was measured against is ``coverage.measured_over``, set by the
                        silence reading, and it is in the basis so a reader does not have to
                        infer it. This limb is NOT a completeness claim. See the module
                        docstring and invariant L12.
        """
        limbs: list[str] = []
        if conflicted or len(used_determinate) == 0:
            limbs.append("source")
        if any_stale:
            limbs.append("freshness")
        if not coverage.complete:
            limbs.append("coverage")
        return limbs

    def make_basis(
        conflict: StatusConflict | None, snapshot: AdmittedSnapshot | None
    ) -> MultiSourceStatusBasis:
        return MultiSourceStatusBasis(
            authority_ref=authority,
            evaluated_at=now,
            verifier_mode=mode,
            required_sources=tuple(required_ids),
            sources_consulted=tuple(lines),
            sources_silent=tuple(silent),
            coverage=coverage,
            conflict=conflict,
            snapshot=snapshot,
            conflict_policy=conflict_policy,
            stale_policy=StaleAnswerPolicy(
                stale_revoked_still_counts=stale_revoked_counts,
                stale_active_still_counts=stale_active_counts,
            ),
            silence_is=silence_is,
        )

    def decide(
        outcome: str,
        lifecycle: LifecycleStateResult,
        reason_code: str,
        basis: MultiSourceStatusBasis,
    ) -> MultiSourceStatusDecision:
        return MultiSourceStatusDecision(
            outcome=outcome, lifecycle=lifecycle, reason_code=reason_code, basis=basis
        )

    # -- step 3: conflict. Never admits, whatever coverage says ---------------
    if len(used_states) > 1:
        conflict = StatusConflict(
            states=tuple(used_states),
            sources=tuple(sorted(l.source_id for l in used_determinate)),
        )
        # The ARTIFACT state is not established under either conflict policy, never invalid:
        # a conflict is the verifier failing to reach a conclusion about the authority, not a
        # finding that the authority ended. What the policy changes is only the BOUNDARY
        # outcome, which is the whole content of the unresolved question.
        lifecycle = not_established(missing_limbs(True), "STATUS_SOURCES_CONFLICT")
        outcome = "denied" if conflict_policy == "deny_with_conflict" else "not_established"
        return decide(
            outcome, lifecycle, "STATUS_SOURCES_CONFLICT", make_basis(conflict, None)
        )

    # -- step 4: revoked, before coverage and before the offline branch -------
    if len(used_states) == 1 and used_states[0] == "revoked":
        return decide(
            "denied",
            lifecycle_state(verdict="invalid", reason_code="STATUS_REVOKED"),
            "STATUS_REVOKED",
            make_basis(None, None),
        )

    # -- step 5: offline resolves on the declared snapshot -------------------
    if mode == "offline":
        snap_line = by_id.get(snapshot_id) if snapshot_id is not None else None
        if snap_line is not None and snap_line.used and snap_line.answer == "active":
            assert snap_line.as_of is not None and snap_line.age_s is not None
            snapshot = AdmittedSnapshot(
                source_id=snap_line.source_id,
                as_of=snap_line.as_of,
                age_s=snap_line.age_s,
                declared_bound_s=snapshot_bound_s,
            )
            return decide(
                "authorized",
                lifecycle_state(
                    verdict="valid",
                    reason_code="ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND",
                ),
                "ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND",
                make_basis(None, snapshot),
            )
        if snap_line is not None and snap_line.use_basis in (
            "stale_beyond_bound",
            "answer_dated_after_boundary",
        ):
            return decide(
                "not_established",
                not_established(missing_limbs(False), "STATUS_STALE_BEYOND_BOUND"),
                "STATUS_STALE_BEYOND_BOUND",
                make_basis(None, None),
            )
        return decide(
            "not_established",
            not_established(missing_limbs(False), "STATUS_NO_USABLE_OBSERVATION"),
            "STATUS_NO_USABLE_OBSERVATION",
            make_basis(None, None),
        )

    # -- step 6: online -----------------------------------------------------
    if coverage.complete and len(used_states) == 1 and used_states[0] == "active":
        return decide(
            "authorized",
            lifecycle_state(
                verdict="valid", reason_code="STATUS_ACTIVE_ALL_SOURCES_AGREE"
            ),
            "STATUS_ACTIVE_ALL_SOURCES_AGREE",
            make_basis(None, None),
        )

    # Not complete, or nothing usable. The reason code says which gap the module treats as
    # the headline, and it distinguishes an empty answer set from a silent required source
    # from a required source whose answer was past its bound. The limb list is computed
    # separately and can carry more than one limb.
    blocking_stale = any(
        sid in by_id
        and by_id[sid].use_basis in ("stale_beyond_bound", "answer_dated_after_boundary")
        for sid in required_ids
    )
    if len(used_determinate) == 0:
        reason_code = "STATUS_NO_USABLE_OBSERVATION"
    elif len(silent) > 0 and measured_over == "declared_required_set":
        reason_code = "STATUS_COVERAGE_INCOMPLETE"
    elif blocking_stale:
        reason_code = "STATUS_STALE_BEYOND_BOUND"
    else:
        # A required source answered `unavailable`, so the declared set is not covered and no
        # bound was exceeded to blame it on.
        reason_code = "STATUS_COVERAGE_INCOMPLETE"
    return decide(
        "not_established",
        not_established(missing_limbs(False), reason_code),
        reason_code,
        make_basis(None, None),
    )
