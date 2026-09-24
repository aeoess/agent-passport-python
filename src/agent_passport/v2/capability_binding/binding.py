# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Whether an action through a named tool is established under a grant
that pins that tool.

SPECIFICATION POSITION. Not required by draft-pidlisnyi-aps-03. See ``types.py``. Concept
source: aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2, whose statement
is a verdict rule: "Where nothing pins it, the verdict records that referent continuity was
not established rather than admitting silently. Where something pins it and the pin does
not match, the action is denied with a mismatch reason rather than reported as not
established."

WHAT RUNS WHERE. This function decides the pin question and nothing else. Chain
verification stays with the caller and is unchanged: run
``verify_authority_delegation_chain`` first, and if it does not return valid there is no
capability question to ask. This module never sees a delegation, never reads a clock, never
touches the network, and holds no policy.

OPEN DESIGN QUESTIONS THIS CODE TAKES A POSITION ON, each recorded because a different
position gives different outcomes for the same records:

1. Where a pin lives. This module implements ``scope_grant_v0``; ``pins.py`` states why and
   states the narrowing side effect that follows.
2. What an established mismatch is. CAND-07 v2 says a denial with a mismatch reason, and
   that is what this returns. The ``aps-capability-binding-drift-v0`` candidate fixture
   family says ``not_established`` in a three-value vocabulary with no denial member. See
   :func:`project_boundary_outcome_to_candidate_v0`.
3. What an unpinned grant gets. ``not_established`` with the coverage limb named, never a
   silent admit. CAND-07 v2's unpinned limb, and the single highest-value thing in this
   cluster to settle in the text, because it decides whether capability binding is opt-in
   or the default.
4. Whether implementation and declared metadata are one pin or two. Two, pinned separately,
   and an implementation pin does not cover a metadata change. A partial pin is recorded as
   a partial pin.

NOT DECIDED HERE. Whether a capability change should invalidate the grant (it does not, and
nothing in this module makes any artifact invalid), what happens when a referent change
NARROWS what a tool can do (CAND-07 v2 scopes that out, and this module gives an
established mismatch in that direction too, which is a known false denial), and semantic
drift generally, which the concept document's OPEN-QUESTIONS.md keeps open.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ...tool_integrity import ToolRegistryEntry, verify_tool_integrity
from .pins import capability_pin_is_empty
from .types import (
    CapabilityBindingError,
    CapabilityPin,
    ReferentBindingResult,
    ToolAttestationObservation,
    referent_binding_result,
)


def observe_tool_attestation(
    *,
    registry_entry: ToolRegistryEntry,
    requested_tool_name: str,
    observed_implementation: str | bytes,
    resolve_trusted_attestor_key: Callable[[str], str | None],
) -> ToolAttestationObservation:
    """Run the SDK's existing ``verify_tool_integrity`` and record what it found, in the
    shape :func:`evaluate_capability_binding` consumes.

    ``resolve_trusted_attestor_key`` is keyed BY TOOL NAME, never by the ``attestorId`` the
    presented entry asserts about itself. That is the whole reason this is a callback: a
    valid signature establishes who signed, and standing to attest a particular tool is
    resolved outside the record asserting it. An entry signed by a perfectly real attestor
    who is not the attestor for this tool comes back with
    ``attestor_signature_valid=False``.

    Returns ``attestor_key_resolved=False`` and ``attestor_signature_valid=False`` when no
    key resolves, and does not run the signature check in that case. PROPOSED.
    """
    if not isinstance(registry_entry, ToolRegistryEntry):
        raise CapabilityBindingError(
            "REGISTRY_ENTRY_INVALID", "registry_entry must be a ToolRegistryEntry"
        )
    if not callable(resolve_trusted_attestor_key):
        raise CapabilityBindingError(
            "RESOLVER_INVALID",
            "resolve_trusted_attestor_key must be a callable of the tool name",
        )
    attestor_key = resolve_trusted_attestor_key(requested_tool_name)
    if not attestor_key:
        return ToolAttestationObservation(
            attested_tool_name=registry_entry.toolName,
            attested_implementation_digest=registry_entry.implementationHash,
            attestor_key_resolved=False,
            attestor_signature_valid=False,
        )
    integrity = verify_tool_integrity(
        registry_entry=registry_entry,
        current_implementation=observed_implementation,
        attestor_public_key=attestor_key,
    )
    return ToolAttestationObservation(
        attested_tool_name=registry_entry.toolName,
        attested_implementation_digest=registry_entry.implementationHash,
        attestor_key_resolved=True,
        attestor_signature_valid=integrity.attestor_signature_valid,
    )


def evaluate_capability_binding(
    *,
    requested_tool_name: str,
    granted_scopes: Sequence[str],
    pin: CapabilityPin | None,
    attestation: ToolAttestationObservation | None,
    observed_implementation_digest: str | None,
    observed_metadata_digest: str | None,
    required_scopes: Sequence[str] = (),
) -> ReferentBindingResult:
    """Decide whether an action through ``requested_tool_name`` is established under the
    grant that carries ``pin``.

    ``pin`` of ``None`` means THE GRANT DOES NOT NAME THE TOOL AT ALL, which is a different
    answer from a grant that names it and pins nothing (a pin with both digest tuples
    empty). The caller passes it explicitly; there is no default, because a default here
    would be the design decision. Build it with
    :func:`parse_capability_pin_from_scope_grants`.

    ``observed_implementation_digest`` and ``observed_metadata_digest`` of ``None`` mean
    the caller observed nothing on that axis, which this module reports rather than
    assuming a match. The SDK cannot reach a running tool and must not pretend to.

    Five ordered steps, each one the reason a vector in the ``capability-binding-drift``
    candidate family exists:

    1. Does the grant name the tool, and does it carry the scopes the action declares.
    2. Is there an accepted attestation for this tool, from an attestor resolved for the
       tool, and does that signed claim still describe the implementation observed NOW. A
       registry entry is a claim; this step is what says the claim is not stale.
    3. The implementation pin. Compared against the ATTESTED digest, which step 2 has
       already established equals the observed digest, so the comparison is against a
       digest an attestor vouched for rather than against an unattested observation.
    4. The declared-metadata pin, pinned and checked separately from the implementation.
    5. Nothing left outstanding.

    Never returns an artifact verdict and never makes any delegation invalid. PROPOSED.
    """
    if not isinstance(requested_tool_name, str) or requested_tool_name == "":
        raise CapabilityBindingError(
            "TOOL_NAME_INVALID", "requested_tool_name must be a non-empty string"
        )
    if isinstance(granted_scopes, (str, bytes)) or not isinstance(granted_scopes, Sequence):
        raise CapabilityBindingError(
            "GRANTS_INVALID", "granted_scopes must be a sequence of strings"
        )
    if pin is not None and pin.tool_name != requested_tool_name:
        raise CapabilityBindingError(
            "PIN_TOOL_MISMATCH",
            f"pin is for {pin.tool_name}, the action is for {requested_tool_name}",
        )

    # Step 1a. The grant has to name the tool. An established negative: the grant is in
    # front of the verifier and it does not say this.
    if pin is None:
        return referent_binding_result(
            outcome="denied",
            continuity="not_established",
            reason_code="TOOL_NOT_IN_GRANT_SCOPE",
            detail=f"tool:{requested_tool_name}",
        )

    # Step 1b. Scopes the action declares it needs.
    missing_scopes = [s for s in required_scopes if s not in granted_scopes]
    if missing_scopes:
        return referent_binding_result(
            outcome="denied",
            continuity="not_established",
            reason_code="SCOPE_NOT_GRANTED",
            detail=",".join(missing_scopes),
        )

    # Step 2. The attestation.
    if attestation is None:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="TOOL_ATTESTATION_ABSENT",
            missing=("coverage",),
            detail=requested_tool_name,
        )
    if not attestation.attestor_key_resolved:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="TOOL_ATTESTOR_KEY_UNRESOLVED",
            missing=("source",),
            detail=requested_tool_name,
        )
    if not attestation.attestor_signature_valid:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="TOOL_ATTESTATION_SIGNATURE_INVALID",
            missing=("source",),
        )
    if attestation.attested_tool_name != requested_tool_name:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="REGISTRY_ENTRY_TOOL_NAME_MISMATCH",
            missing=("coverage",),
            detail=f"{attestation.attested_tool_name}!={requested_tool_name}",
        )
    if observed_implementation_digest is None:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="OBSERVATION_ABSENT",
            missing=("coverage",),
            detail="implementation",
        )
    if attestation.attested_implementation_digest != observed_implementation_digest:
        # The signed entry no longer describes what is reachable now. Freshness, not
        # source: the claim is authentic and from the right party, and it is out of date.
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH",
            missing=("freshness",),
            detail=(
                f"attested={attestation.attested_implementation_digest} "
                f"observed={observed_implementation_digest}"
            ),
        )

    # Step 3. The implementation pin.
    if len(pin.implementation_digests) == 0:
        if capability_pin_is_empty(pin):
            # CAND-07 v2's unpinned limb. The grant gives the verifier no basis to
            # establish that the implementation behind this name is the one the principal
            # granted against, and that is recorded rather than resolved either way. Note
            # this holds whether or not the tool in fact changed: the absence of a change
            # is not something an unpinned grant establishes.
            return referent_binding_result(
                outcome="not_established",
                continuity="not_established",
                reason_code="NO_CAPABILITY_PIN_IN_GRANT",
                missing=("coverage",),
                detail=f"tool:{requested_tool_name}",
            )
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="IMPLEMENTATION_NOT_PINNED_IN_GRANT",
            missing=("coverage",),
            detail=f"tool:{requested_tool_name}",
        )
    if attestation.attested_implementation_digest not in pin.implementation_digests:
        # ESTABLISHED NEGATIVE. The verifier reached a conclusion and the conclusion is
        # that the pinned referent changed. CAND-07 v2: a denial with a mismatch reason,
        # not ignorance.
        return referent_binding_result(
            outcome="denied",
            continuity="mismatch",
            reason_code="PINNED_IMPLEMENTATION_DIGEST_MISMATCH",
            detail=(
                f"pinned={'|'.join(pin.implementation_digests)} "
                f"attested={attestation.attested_implementation_digest}"
            ),
        )

    # Step 4. The declared-metadata pin. A tool can keep both its name and its
    # implementation digest while its declared schema and permissions change and gain a
    # destructive permission, so this axis is pinned and checked on its own.
    if len(pin.metadata_digests) == 0:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="METADATA_NOT_PINNED_IN_GRANT",
            missing=("coverage",),
            detail=f"tool:{requested_tool_name}",
        )
    if observed_metadata_digest is None:
        return referent_binding_result(
            outcome="not_established",
            continuity="not_established",
            reason_code="OBSERVATION_ABSENT",
            missing=("coverage",),
            detail="metadata",
        )
    if observed_metadata_digest not in pin.metadata_digests:
        return referent_binding_result(
            outcome="denied",
            continuity="mismatch",
            reason_code="PINNED_METADATA_DIGEST_MISMATCH",
            detail=(
                f"pinned={'|'.join(pin.metadata_digests)} observed={observed_metadata_digest}"
            ),
        )

    # Step 5.
    return referent_binding_result(
        outcome="authorized",
        continuity="established",
        reason_code="CAPABILITY_CONTINUITY_ESTABLISHED",
    )
