# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Capability pins and identifier binding.

NOT REQUIRED BY draft-pidlisnyi-aps-03. That document defines no pin syntax and states no
rule pinning a tool to an implementation digest or a schema. Its nearest text is the
section 4.1 action reference, verbatim:

    "target is the exact resource, tool, or endpoint against which the action will be
    dispatched; a profile MUST define its target string construction."

A target names a resource, tool or endpoint. It carries no implementation digest and no
metadata digest, so it cannot tell two revisions of one tool behind one endpoint apart.
Nothing in draft-03 supplies the missing distinction, and proposed -04 excludes capability
binding by name.

Concept source: the aeoess/agent-authority-lifecycle concept document, invariant candidate
CAND-07 as rewritten ("a stable name does not establish stable semantics"), and the
AUTHORITY-LIFECYCLE.md concepts "Action or capability binding" and "Target binding". All
PROPOSED. Nothing here claims otherwise.

WHAT THIS MODULE DOES NOT TOUCH. ``AuthorityValidationResult`` stays the four draft-03
values, ``verify_authority_delegation_chain`` returns exactly what it returned, and the
authority vector gains no eighth facet (draft-03 section 3.2 closes it at seven and makes
a missing facet invalid). A pin rides in the existing scope grammar or in a separate
record. A caller that never imports this module sees exactly today's behaviour.

Python port of the TypeScript SDK's ``src/v2/capability-binding/``. Same names, same
semantics, snake_case per Python convention.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Where a pin lives.
#:
#: - ``scope_grant_v0``  further colon-separated segments under the tool grant, which keeps
#:                       the pin inside the scope grammar draft-03 section 3.2 already
#:                       defines. It has a side effect worth stating: a pin then narrows
#:                       across a chain by the ordinary covering rule, so a child carrying
#:                       a different pin fails as scope widening rather than as a binding
#:                       failure. This module's parser and writer implement this encoding.
#: - ``bound_record_v0`` a separate signed record referencing a delegation id. Reserved as
#:                       a name so a caller can state which encoding it chose. This module
#:                       does not define its wire format.
#:
#: draft-03 defines neither. PROPOSED.
PIN_ENCODINGS: tuple[str, ...] = ("scope_grant_v0", "bound_record_v0")

#: What the verifier could establish about continuity of the thing named.
#:
#: Three values, not two, and the third is the point of this module:
#:
#: - ``established``     the referent the grant pinned is the referent now observed.
#: - ``not_established`` the verifier could not reach a conclusion either way. Nothing was
#:                       pinned, or no accepted attestation covered what the answer needed.
#:                       Ignorance, never a finding about the world.
#: - ``mismatch``        the verifier DID reach a conclusion and the conclusion is that the
#:                       referent changed. An established negative, not ignorance.
#:
#: Concept source: aeoess/agent-authority-lifecycle, CAND-07 v2 and the invariant
#: candidates' section on the two uses of "not established". PROPOSED.
REFERENT_CONTINUITY: tuple[str, ...] = ("established", "not_established", "mismatch")

#: Every reason code :func:`evaluate_capability_binding` can emit.
CAPABILITY_BINDING_REASON_CODES: tuple[str, ...] = (
    # authorized: every pinned axis matched what was observed.
    "CAPABILITY_CONTINUITY_ESTABLISHED",
    # denied: the grant does not name this tool at all. An established negative, not
    # ignorance: the grant is in front of the verifier and it does not say this.
    "TOOL_NOT_IN_GRANT_SCOPE",
    # denied: the grant names the tool but does not carry a scope the action requires.
    "SCOPE_NOT_GRANTED",
    # not_established (source): no trusted attestor key resolved for this tool.
    "TOOL_ATTESTOR_KEY_UNRESOLVED",
    # not_established (source): the entry's signature does not verify against the key the
    # caller resolved for this tool, so no accepted attestation exists.
    "TOOL_ATTESTATION_SIGNATURE_INVALID",
    # not_established (coverage): no attestation was presented at all.
    "TOOL_ATTESTATION_ABSENT",
    # not_established (coverage): the entry is about a different tool, so the claim does
    # not cover what the verdict needed.
    "REGISTRY_ENTRY_TOOL_NAME_MISMATCH",
    # not_established (freshness): the signed entry no longer describes the implementation
    # observed now. The entry is a claim, and the claim is stale.
    "REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH",
    # not_established (coverage): the grant names the tool and pins neither axis. CAND-07
    # v2's unpinned limb: recorded, not admitted, and not resolved either way.
    "NO_CAPABILITY_PIN_IN_GRANT",
    # not_established (coverage): the grant pins the declared metadata and says nothing
    # about the implementation. A metadata pin does not cover an implementation.
    "IMPLEMENTATION_NOT_PINNED_IN_GRANT",
    # not_established (coverage): the grant pins the implementation and says nothing about
    # the declared metadata. An implementation pin does not cover a schema.
    "METADATA_NOT_PINNED_IN_GRANT",
    # not_established (coverage): the caller observed nothing on an axis the evaluation
    # needed. ``detail`` names the axis. The SDK cannot reach a running tool and must not
    # pretend that an unobserved axis matched.
    "OBSERVATION_ABSENT",
    # denied: the implementation pin is established not to match.
    "PINNED_IMPLEMENTATION_DIGEST_MISMATCH",
    # denied: the declared-metadata pin is established not to match.
    "PINNED_METADATA_DIGEST_MISMATCH",
)

#: Every reason code :func:`evaluate_identifier_continuity` can emit.
IDENTIFIER_CONTINUITY_REASON_CODES: tuple[str, ...] = (
    # authorized: a single accepted holder at the instant, equal to a pinned controller,
    # with every interval since issuance either bound to that holder or covered by an
    # accepted retention record.
    "IDENTIFIER_CONTINUITY_ESTABLISHED",
    # not_established (coverage): the grant does not declare the identifier the action in
    # fact relies on. A verifier that never modelled the identifier has no record to
    # invalidate when control of it moves.
    "IDENTIFIER_DEPENDENCY_NOT_DECLARED",
    # not_established (coverage): the grant names the identifier and pins no controller.
    "IDENTIFIER_CONTROLLER_NOT_PINNED",
    # not_established (coverage): no accepted binding record covers the instant asked
    # about.
    "IDENTIFIER_BINDING_LAPSED",
    # not_established (source): two or more accepted custodian records name different
    # holders at the instant, an unresolved conflict between accepted sources.
    "IDENTIFIER_BINDING_CONFLICT",
    # denied: a single accepted holder is established, and it is not a pinned controller.
    # The string is the same. The party behind it is not.
    "IDENTIFIER_CONTROLLER_CHANGED",
    # not_established (coverage): an interval between issuance and the instant is neither
    # bound to the holder nor covered by an accepted retention record. An interval the
    # identifier was held by nobody is an interval anyone could have taken it.
    "IDENTIFIER_CONTINUITY_GAP_UNCOVERED",
    # not_established (source): a retention record covering the gap exists but its issuer
    # is not the custodian this caller resolves for that identifier kind. Worth naming
    # apart from there being no retention record at all.
    "RETENTION_CUSTODIAN_WITHOUT_STANDING",
)


class CapabilityBindingError(ValueError):
    """Raised when a caller asks this module for something the vocabulary does not allow,
    or passes a malformed record.

    A shape rule broken at a call boundary is a programming error, not a verdict. ``code``
    is the single stable code callers branch on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CapabilityPin:
    """What a grant pins about one named tool.

    Each axis is a SET, not a single value, because a grant may legitimately pin more than
    one acceptable revision, and because an empty tuple is the unambiguous way to say "this
    axis is not pinned". An EMPTY tuple on both axes is the unpinned grant, and CAND-07's
    rewritten statement is explicit about what happens there: the verdict records that
    referent continuity was not established rather than admitting silently.

    A ``CapabilityPin`` of ``None`` at an evaluator's input is a different thing again: the
    grant does not name the tool at all. See :func:`evaluate_capability_binding`. PROPOSED.
    """

    tool_name: str
    #: Digests of acceptable implementations, ``sha256:<64 lowercase hex>``. Empty means
    #: this axis is not pinned.
    implementation_digests: tuple[str, ...]
    #: Digests of acceptable declared metadata blocks. Empty means this axis is not pinned.
    #: DISTINCT from ``implementation_digests`` on purpose: a tool can keep its name and
    #: its implementation bytes while its declared schema, description or permissions
    #: change, which is a different evidence problem from an implementation that drifted.
    metadata_digests: tuple[str, ...]
    encoding: str


@dataclass(frozen=True)
class ReferentBindingResult:
    """What this module decides about ONE action at ONE authorization boundary.

    ``outcome`` is the boundary-outcome subject from the lifecycle state vocabulary, not an
    artifact verdict: nothing here makes any delegation invalid. The grant is a fine grant
    and the chain result is untouched. What is decided is whether the action now attempted
    is within it.

    THE MAPPING FROM ``continuity`` TO ``outcome`` IS THE CONTESTED PART AND IT IS STATED
    HERE RATHER THAN BURIED. CAND-07 v2 reads, verbatim: "Where something pins it and the
    pin does not match, the action is denied with a mismatch reason rather than reported as
    not established." So ``mismatch`` maps to ``denied``, and ``not_established`` maps to
    ``not_established`` with its limbs named. The ``aps-capability-binding-drift-v0`` and
    ``aps-lifecycle-identifier-reuse-and-rename-v0`` candidate fixture families label an
    established mismatch ``not_established`` instead, in a three-value vocabulary that has
    no denial member. This module follows CAND-07 v2. See
    :func:`project_boundary_outcome_to_candidate_v0` for reproducing the fixture labelling
    explicitly.

    There is deliberately NO ``valid`` property here, on the same reasoning as
    ``LifecycleStateResult``: ``not_established`` is not a boolean's false branch.
    """

    outcome: str
    continuity: str
    #: Stable, module-local, SCREAMING_SNAKE_CASE, matching the lifecycle state
    #: vocabulary's convention.
    reason_code: str
    #: Present with at least one member exactly when ``outcome`` is ``not_established``,
    #: and ``None`` otherwise. BROAD-L7 requires a denial on an unestablished state to
    #: record which of source, freshness or coverage was missing.
    missing: tuple[str, ...] | None = None
    #: Free-form, for a human reading a receipt. Never parsed.
    detail: str | None = None


@dataclass(frozen=True)
class IdentifierContinuityResult(ReferentBindingResult):
    """A :class:`ReferentBindingResult` for the identifier limb, plus who the accepted
    custodian records say holds the identifier at the instant asked about.

    ``controller_at_instant`` is ``None`` whenever the boundary could not establish a
    single holder, which includes the conflict case where two accepted records disagree. A
    non-``None`` value on a ``denied`` result is the load-bearing one: it names the party
    that holds the identifier now, which is precisely the fact that is NOT the pinned
    party.
    """

    controller_at_instant: str | None = None


@dataclass(frozen=True)
class ToolAttestationObservation:
    """What a caller observed about one tool attestation, with the crypto already done.

    Built by :func:`observe_tool_attestation`, which runs the SDK's own
    ``verify_tool_integrity``. Kept as a separate value so
    :func:`evaluate_capability_binding` stays pure: no clock, no network, no crypto, on the
    same rule the chain verifier follows. PROPOSED.
    """

    #: The tool name the presented entry is about, as the entry itself states it.
    attested_tool_name: str
    #: The implementation digest the entry attests, ``sha256:<64 lowercase hex>``.
    attested_implementation_digest: str
    #: Whether a trusted attestor key was resolvable FOR THE TOOL. Resolution is by tool,
    #: never from the ``attestorId`` the presented entry asserts about itself: a valid
    #: signature establishes who signed, not that they had standing to attest this tool.
    attestor_key_resolved: bool
    #: ``verify_tool_integrity().attestor_signature_valid`` against that resolved key.
    #: ``False`` whenever no key resolved.
    attestor_signature_valid: bool


def referent_binding_result(
    *,
    outcome: str,
    continuity: str,
    reason_code: str,
    missing: tuple[str, ...] | None = None,
    detail: str | None = None,
) -> ReferentBindingResult:
    """Internal constructor enforcing the one shape rule this module has: ``missing`` is
    present with at least one member exactly when ``outcome`` is ``not_established``."""
    wants_missing = outcome == "not_established"
    if wants_missing and not missing:
        raise CapabilityBindingError(
            "MISSING_REQUIRED",
            "a not_established outcome must name at least one missing establishment limb",
        )
    if not wants_missing and missing is not None:
        raise CapabilityBindingError(
            "MISSING_NOT_ALLOWED",
            f"missing is only meaningful on not_established, not on {outcome}",
        )
    return ReferentBindingResult(
        outcome=outcome,
        continuity=continuity,
        reason_code=reason_code,
        missing=tuple(missing) if missing is not None else None,
        detail=detail,
    )


def identifier_continuity_result(
    *,
    outcome: str,
    continuity: str,
    reason_code: str,
    controller_at_instant: str | None,
    missing: tuple[str, ...] | None = None,
    detail: str | None = None,
) -> IdentifierContinuityResult:
    """The identifier limb's constructor. Enforces the same shape rule and carries the
    established holder alongside it."""
    base = referent_binding_result(
        outcome=outcome,
        continuity=continuity,
        reason_code=reason_code,
        missing=missing,
        detail=detail,
    )
    return IdentifierContinuityResult(
        outcome=base.outcome,
        continuity=base.continuity,
        reason_code=base.reason_code,
        missing=base.missing,
        detail=base.detail,
        controller_at_instant=controller_at_instant,
    )


def project_boundary_outcome_to_candidate_v0(outcome: str, positive_label: str) -> str:
    """PROPOSED. Project a boundary outcome into the three-value verdict vocabulary the
    ``aps-capability-binding-drift-v0`` and ``aps-lifecycle-identifier-reuse-and-rename-v0``
    candidate fixture families declare, so a caller reproducing one of those families does
    not have to write the collapse out by hand and get it silently wrong.

    THIS FUNCTION COLLAPSES ``denied`` INTO ``not_established`` AND THAT IS A KNOWN
    DIVERGENCE, NOT THIS MODULE'S READING. Those families were authored against the concept
    document before CAND-07 was rewritten, and their vocabulary has no denial member, so an
    established pinned-referent mismatch had nowhere else to land. CAND-07 v2 now says such
    a mismatch is a denial with a mismatch reason. Reach for this only to reproduce a v0
    family's labelling, never to decide anything.

    ``positive_label`` is ``"admitted"`` for the capability-binding-drift family and
    ``"valid"`` for the identifier-reuse family, which spell the positive differently.
    """
    if positive_label not in ("admitted", "valid"):
        raise CapabilityBindingError(
            "POSITIVE_LABEL_UNKNOWN",
            'positive_label must be "admitted" or "valid"',
        )
    return positive_label if outcome == "authorized" else "not_established"
