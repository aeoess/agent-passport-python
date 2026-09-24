# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Agent Passport System — Python SDK.

Cryptographic identity, delegation, governance, and attribution for AI agents.
Cross-language compatible with the TypeScript SDK (npm: agent-passport-system).

8 protocol layers. Full parity with the TypeScript SDK.

Quick start:
    from agent_passport import create_passport, verify_passport

    result = create_passport(
        agent_id="my-agent-001",
        agent_name="My Agent",
        owner_alias="developer",
        mission="Assist with development tasks",
        capabilities=["code_execution", "web_search"],
        runtime={"platform": "python", "models": ["gpt-4"], "toolsCount": 5, "memoryType": "session"},
    )
    passport = result["signedPassport"]
    key_pair = result["keyPair"]

    # Verify
    check = verify_passport(passport)
    assert check["valid"]

Remote MCP: https://mcp.aeoess.com/sse
Docs: https://agent-passport.org/llms-full.txt
"""

__version__ = "4.1.0"

# Crypto
from .crypto import generate_key_pair, sign, verify, public_key_from_private

# Canonical serialization
from .canonical import canonicalize
from .action_ref import compute_action_ref

# Passport (Layer 1 — Identity)
from .passport import (
    create_passport,
    sign_passport,
    verify_passport,
    update_passport,
    is_expired,
)

# Delegation (Layer 1 — Delegation)
from .delegation import (
    create_delegation,
    verify_delegation,
    sub_delegate,
    revoke_delegation,
    create_action_receipt,
    verify_action_receipt,
    scope_covers,
    scope_authorizes,
)

# Values Floor (Layer 2 — Human Values Floor)
from .values import (
    load_floor,
    load_floor_from_file,
    resolve_enforcement_mode,
    effective_enforcement_mode,
    attest_floor,
    verify_attestation,
    evaluate_compliance,
    negotiate_common_ground,
)

# Attribution (Layer 3 - Merkle proofs + beneficiary trace)
from .attribution import (
    build_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
    verify_merkle_proof_against_root,
    trace_beneficiary,
)

# Composition Check Receipt v0 (carrier + stateless anchor verifier; detection stays
# in the private gateway). Cross-language signature compatible with the TS SDK.
from .v2.composition_check import (
    COMPOSITION_CHECK_PROFILE,
    COMPOSITION_CHECK_TAG,
    COMPOSITION_CHECK_RESULTS,
    ATTESTOR_INDEPENDENCE_CLASSES,
    composition_check_signing_payload,
    verify_composition_check,
)

# Native action reference (draft-pidlisnyi-aps-03 section 4.1, profile
# aps-action-ref-v2). DISTINCT from compute_action_ref above, which is a
# pre-draft-03 compatibility digest over a different preimage (see its own
# docstring for what it is and is not).
from .v2.action_reference import (
    ACTION_REF_V2_PROFILE,
    ACTION_REF_V2_DOMAIN,
    PAYLOAD_REF_V1_DOMAIN,
    ActionReferenceError,
    validate_action_reference_input_v2,
    compute_action_ref_v2,
    compute_payload_ref_v1,
    create_action_reference_input_v2,
    parse_action_reference_input_v2,
    compute_action_ref_v2_from_json,
)

# External correlation key (draft-pidlisnyi-aps-03 section 4.2, label
# action-ref-v1-jcs-sha256). Legacy cross-ecosystem correlation form,
# DISTINCT from both compute_action_ref above (pre-draft-03 compatibility
# digest) and compute_action_ref_v2 above (section 4.1 native action_ref).
# See the module docstring for what a matching value is and is not evidence
# of.
from .external_action_ref import (
    EXTERNAL_ACTION_REF_V1_LABEL,
    ExternalActionRefError,
    compute_external_action_ref_v1,
)

# AuthorityDelegationV1, the draft-pidlisnyi-aps-03 delegated authority record
# (sections 3.1 to 3.4 and 3.6). DISTINCT from the legacy delegation functions
# above (create_delegation, sub_delegate, verify_delegation), which are a
# pre-draft compatibility surface and are not the draft-03 record.
from .v2.authority_delegation import (
    AUTHORITY_DELEGATION_RECORD_TYPE,
    AUTHORITY_DELEGATION_VERSION,
    SCOPE_PROFILE_V1,
    REPUTATION_PROFILE_V1,
    VALUES_PROFILE_V1,
    REVERSIBILITY_PROFILE_V1,
    AuthorityDelegationError,
    AuthorityFailure,
    AuthorityValidationResult,
    BudgetOperationResult,
    InMemoryAuthorityBudgetLedger,
    authority_delegation_body,
    compute_authority_delegation_id,
    validate_authority_delegation_shape,
    compare_authority,
    issue_authority_delegation,
    issue_sub_authority_delegation,
    parse_authority_delegation_json,
    verify_authority_delegation,
    verify_authority_delegation_chain,
    verify_authority_delegation_signature,
)

# aps:authority-revocation:v1, the draft-pidlisnyi-aps-03 section 3.5.1 direct
# revocation of an AuthorityDelegationV1. DISTINCT from the pre-draft revocation
# surface above, which carries a raw public key and a free-text reason and is
# not the draft-03 record. One direct revocation of one delegation: no
# cascade-derived record for a descendant and no cascade-completion record.
from .v2.authority_revocation import (
    AUTHORITY_REVOCATION_RECORD_TYPE,
    AUTHORITY_REVOCATION_VERSION,
    AUTHORITY_REVOCATION_ID_DOMAIN,
    AUTHORITY_REVOCATION_SIGNATURE_DOMAIN,
    AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
    AuthorityRevocationError,
    AuthorityRevocationFailure,
    AuthorityRevocationInsertion,
    AuthorityRevocationRecordResult,
    AuthorityRevocationStore,
    AuthorityRevocationVerificationResult,
    InMemoryAuthorityRevocationStore,
    authority_revocation_body,
    authority_revocation_cascade_origin,
    compute_authority_revocation_cascade_transaction_id,
    compute_authority_revocation_id,
    create_authority_revocation_resolver,
    is_authority_revocation_v1,
    issue_authority_revocation,
    record_authority_revocation,
    sign_authority_revocation,
    validate_authority_revocation_shape,
    verify_authority_revocation,
    verify_authority_revocation_signature,
)

# Agora (Layer 4 — Communication)
from .agora import (
    create_agora_message,
    verify_agora_message,
    create_feed,
    append_to_feed,
    get_thread,
    get_by_topic,
    get_by_author,
    get_topics,
    create_registry,
    register_agent,
    verify_feed,
)

# Intent Architecture (Layer 5a — Roles, Deliberation, Consensus)
from .intent import (
    assign_role,
    create_tradeoff_rule,
    evaluate_tradeoff,
    create_intent_document,
    create_deliberation,
    submit_consensus_round,
    evaluate_consensus,
    resolve_deliberation,
    get_precedents_by_topic,
    cite_precedent,
    create_intent_passport_extension,
)

# Policy Engine (Layer 5b — 3-signature chain)
from .policy import (
    create_action_intent,
    verify_action_intent,
    evaluate_intent,
    verify_policy_decision,
    create_policy_receipt,
    PolicyReceiptChainInputs,
    verify_policy_receipt,
    verify_policy_receipt_envelope,
    FloorValidatorV1,
    request_action,
)

# Coordination (Layer 6 — Task lifecycle)
from .coordination import (
    create_task_brief,
    verify_task_brief,
    assign_task,
    accept_task,
    submit_evidence,
    verify_evidence,
    review_evidence,
    verify_review,
    handoff_evidence,
    verify_handoff,
    submit_deliverable,
    verify_deliverable,
    complete_task,
    verify_completion,
    create_task_unit,
    get_task_status,
    validate_task_unit,
)

# Integration Wiring (Layer 7 — Cross-layer bridges)
from .integration import (
    commerce_with_intent,
    commerce_receipt_to_action_receipt,
    validate_commerce_delegation,
    coordination_to_agora,
    post_task_created,
    post_review_completed,
    post_task_completed,
)

# Agentic Commerce (Layer 8 — ACP)
from .commerce import (
    commerce_preflight,
    request_human_approval,
    create_commerce_delegation,
    record_spend,
    get_spend_summary,
    sign_commerce_receipt,
    verify_commerce_receipt,
)

# Principal Identity
from .principal import (
    create_principal_identity,
    endorse_agent as endorse_agent_as_principal,
    verify_endorsement,
    revoke_endorsement,
    create_disclosure,
    verify_disclosure,
    create_fleet,
    add_to_fleet,
    get_fleet_status,
    revoke_from_fleet,
)


# Data Source Registration (Module 36A)
from .data_source import (
    register_self_attested_source,
    register_custodian_attested_source,
    register_gateway_observed_source,
    verify_source_receipt,
    revoke_source_receipt,
    record_data_access,
    verify_data_access_receipt,
    check_terms_compliance,
    compose_terms,
    build_data_access_merkle_root,
)

# Training Attribution
from .training_attribution import (
    create_training_attribution,
    verify_training_attribution,
)

# Data Settlement (Module 39)
from .data_settlement import (
    generate_settlement,
    verify_settlement,
    generate_compliance_report,
)

# Governance Block (HTML-embedded governance)
from .governance_block import (
    generate_governance_block,
    verify_governance_block,
    render_governance_html,
    render_governance_meta,
    parse_governance_block_from_html,
    embed_governance,
    is_usage_permitted,
    DEFAULT_REVOCATION_POLICY,
)

# DID Interop (did:key, did:web, passport-to-DID-document)
from .did_interop import (
    to_did_key,
    from_did_key,
    did_web_to_url,
    passport_to_did_document,
)

# Identity Bridge (SPIFFE, OAuth)
from .identity_bridge import (
    parse_spiffe_id,
    import_spiffe_svid,
    map_oauth_scopes,
    import_oauth_token,
)

# VC Wrapper (W3C Verifiable Credentials)
from .vc_wrapper import (
    passport_to_verifiable_credential,
    verify_verifiable_credential,
    create_verifiable_presentation,
    verify_verifiable_presentation,
)

# Credential Request Protocol (Selective Disclosure)
from .credential_request import (
    create_credential_request,
    fulfill_credential_request,
    verify_credential_response,
)


# Mutual Authentication v1 (SDK v2.2.0)
# Closes the asymmetry where agents authenticate to systems but systems do
# not authenticate to agents. Standalone primitive. No federation.
from .v2.mutual_auth import (
    # types
    MutualAuthRole,
    MutualAuthCertificate,
    TrustAnchor,
    TrustAnchorBundle,
    MutualAuthHello,
    MutualAuthAttest,
    MutualAuthSession,
    MutualAuthResult,
    MutualAuthPolicy,
    MutualAuthFailureReason,
    # certificate
    build_certificate,
    sign_certificate,
    certificate_id,
    verify_certificate_signature,
    is_certificate_temporally_valid,
    check_anchor,
    # trust bundle
    build_bundle,
    sign_bundle,
    verify_bundle,
    # handshake
    new_nonce,
    build_hello,
    choose_version,
    build_attest,
    verify_attest,
    derive_session,
    is_session_active,
)

# Canonical JCS (RFC 8785 strict) for modules requiring cross-language signature interop
from .canonical import canonicalize_jcs


# Evidentiary Type Safety primitives (SDK v2.4.0a1 alpha pre-release)
# Ports of TypeScript SDK 2.6.0-alpha.0:
#   2.4.0a0: claim-evidence-types, claim-verifier, downstream-taint
#   2.4.0a1: full Wave 1 accountability surface, cognitive-attestation,
#            instruction-provenance.
from .v2 import (
    # claim_evidence_types
    ClaimType,
    RecordType,
    EvidenceProfile,
    EvidenceProfiles,
    required_evidence_for,
    # claim_verifier
    ClaimVerificationInput,
    ClaimVerificationResult,
    ClaimVerificationStatus,
    EvidenceEntry,
    OpenContestationLookup,
    OpenContestationResolver,
    verify_evidence_claim,
    # downstream_taint
    TaintCandidate,
    TaintedRecord,
    TaintedSet,
    compute_downstream_taint,
    is_contestation_tainting,
)

# Wave 1 accountability — full surface (v2.4.0a1)
# create_action_receipt / verify_action_receipt collide with legacy
# delegation-flavored functions of the same names; the Wave 1 versions
# are re-exported under accountability_* prefixes here. The unaliased
# forms remain available via `from agent_passport.v2.accountability
# import ...`.
from .v2.accountability import (
    # base
    CaptureMode,
    Completeness,
    ScopeOfClaim,
    # action
    ActionPayload,
    ActionReceipt as AccountabilityActionReceipt,
    SideEffectClass,
    TransparencyLogInclusion,
    # authority-boundary
    AuthorityBoundaryReceipt,
    BoundaryResult,
    # custody
    CustodyEventType,
    CustodyPurpose,
    CustodyReceipt,
    SubjectReceiptBatch,
    # contestability
    ContestabilityContestant,
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    ContestStatus,
    GroundsClass,
    GroundsClassValue,
    RequestedRemedy,
    StandingBasis,
    # bundle
    APSBundle,
    BundledReceiptRef,
    # construct (aliased to avoid legacy delegation collision)
    attach_controller_response,
    create_action_receipt as create_accountability_action_receipt,
    create_aps_bundle,
    create_authority_boundary_receipt,
    create_contestability_receipt,
    create_custody_receipt,
    # bundle helpers
    compute_merkle_root,
    # verify (aliased)
    verify_action_receipt as verify_accountability_action_receipt,
    verify_aps_bundle,
    verify_authority_boundary_receipt,
    verify_contestability_receipt,
    verify_custody_receipt,
)

# Cognitive Attestation (Paper 4)
from .v2.cognitive_attestation import (
    ActivationStatistic,
    AggregationPolicy,
    AttachmentPoint,
    CognitiveAttestation,
    CompletenessClaim,
    DictionaryRef,
    ExecutionEnvironment,
    FeatureActivation,
    ModelRef,
    Precision,
    SAEType,
    Signature as CognitiveSignature,
    SignerRole as CognitiveSignerRole,
    TiebreakerRule,
    TokenRange,
    BuildAttestationInput,
    build_attestation,
    canonicalize_attestation,
    cognitive_attestation_digest,
    sign_attestation as sign_cognitive_attestation,
    sort_feature_activations,
    validate_attestation_shape,
    RegistryResolver,
    RegistryVerificationResult,
    ReplayBackend,
    ReplayVerificationResult,
    RequiredRoleCoverage,
    verify_against_registry,
    verify_by_replay,
    verify_required_signer_roles,
    verify_signature as verify_cognitive_signature,
    ComputationalDispute,
    DecompositionAdequacyDispute,
    Dispute,
    ExclusionDispute,
    FacetedReinterpretationDispute,
    InterpretiveDispute,
    ThresholdDispute,
)

# Instruction Provenance Receipt (Paper 8 candidate, v0.2)
from .v2.instruction_provenance import (
    AttestationTier,
    FilesystemMode,
    InstructionFile,
    InstructionProvenanceReceipt,
    InstructionProvenanceReceiptBoundTo,
    InstructionRole,
    IPRConstructionError,
    IPRPathError,
    canonicalize_envelope as canonicalize_instruction_envelope,
    canonicalize_path,
    compute_context_root,
    create_instruction_provenance_receipt,
    matches_any_pattern,
    sign_ed25519 as sign_ed25519_ipr,
    sort_instruction_files,
    verify_action_time_context_root,
    verify_instruction_provenance_receipt,
)

# Word digest handles (word_handles, v2)
from .v2.word_handles import (
    LEXICON_ID as WORD_HANDLE_LEXICON_ID,
    LEXICON_NAME as WORD_HANDLE_LEXICON_NAME,
    LEXICON_PROFILE as WORD_HANDLE_LEXICON_PROFILE,
    PROFILES as WORD_HANDLE_PROFILES,
    WORDS as WORD_HANDLE_WORDS,
    canonical_wordlist_text,
    decode as decode_word_handle,
    decode_profile as decode_word_handle_profile,
    encode as encode_word_handle,
    encode_profile as encode_word_handle_profile,
    min_unique_prefix_bits,
)

# Read fidelity receipt (read_fidelity_receipt, v2)
from .v2.read_fidelity_receipt import (
    ReadFidelityChallenge,
    ReadFidelityReceipt,
    ReadFidelityVerifyResult,
    SampledSpan,
    VerifyAgainstSourceResult,
    VerifyResponsesResult,
    canonical_no_sig,
    commit_spans,
    create_read_fidelity_receipt,
    derive_seed,
    sample_spans,
    score_responses,
    verify_against_source,
    verify_read_fidelity_receipt,
    verify_responses,
)

# Lifecycle state vocabulary (v2): PROPOSED, OPT-IN.
#
# A SECOND verdict vocabulary, reported alongside chain verification and never merged
# into it. NOT REQUIRED BY draft-pidlisnyi-aps-03, whose section 3.3 closes chain
# verification at "valid, invalid, indeterminate, or unsupported with a stable failure
# code". That enumeration, AuthorityValidationResult and everything
# verify_authority_delegation_chain returns are unchanged, and a caller that does not
# import this module sees exactly today's behaviour.
#
# What it adds: the six artifact verdicts (valid, invalid, not_established,
# not_yet_effective, suspended, restricted), the separate boundary-outcome subject, the
# three establishment limbs a not_established verdict must name, and the split between
# the two uses of "not established" - the evidential sense, which keeps the name, and the
# established negative, which resolves to not_yet_effective or to a denial at a boundary.
# map_authority_validation_to_lifecycle is the opt-in read-only view of an existing
# result in the new vocabulary.
#
# Concept source: the aeoess/agent-authority-lifecycle concept document, invariant L8 and
# invariant candidates BROAD-L7, CAND-04 and CAND-05. Every one of those is PROPOSED,
# with no published specification text behind it. Nothing downstream should treat these
# names as specified.
from .v2.lifecycle_state import (
    BOUNDARY_OUTCOMES,
    ESTABLISHED_NEGATIVE_SHAPES,
    ESTABLISHMENT_GAPS,
    LIFECYCLE_BASE_REASON_CODES,
    LIFECYCLE_VERDICTS,
    CompositeAuthorityResult,
    EstablishedNegativeResolution,
    LifecycleStateError,
    LifecycleStateResult,
    OutstandingCause,
    is_boundary_outcome,
    is_established_negative_shape,
    is_establishment_gap,
    is_lifecycle_verdict,
    lifecycle_state,
    map_authority_validation_to_lifecycle,
    not_established,
    resolve_established_negative,
)

# Non-time bounds on a grant (v2/bounds): PROPOSED, OPT-IN.
#
# Purpose, use-count and budget bounds, and the state "this bound has been reached".
#
# NOT REQUIRED BY draft-pidlisnyi-aps-03. Two of its sentences constrain the whole module.
# Section 3.2: "authority contains exactly seven required facets: scope, spend, depth,
# time, reputation, values, and reversibility." That set is closed, so a purpose or
# use-count bound cannot live inside a signed authority delegation at all, and this module
# declares a SEPARATE artifact referencing a delegation by content address. Section 3.3:
# "Verification returns one of valid, invalid, indeterminate, or unsupported with a stable
# failure code." That set is closed too, and nothing here touches it. A bound evaluation is
# reported ALONGSIDE a chain result, and a caller that does not import this module sees
# exactly today's behaviour.
#
# draft-03 has zero occurrences of "exhaust" and of "use_count", and uses "single-use" only
# of an approval in section 4.3, never of a grant.
#
# What it adds: a bound declaration, a signed fulfilment attestation, evaluate_bound() which
# answers not_reached, exhausted or not_established at an instant, and an optional signed
# exhaustion record shaped like the section 3.5.1 revocation record. The exhaustion record
# attests the enforcement boundary's own finding and not the state of the world, on the same
# model draft-03 section 5.3.3 uses for an action result. is_purpose_permitted and
# purpose_category are the Python port of the TypeScript SDK's long-standing functions of
# the same name, so both reference SDKs expose purpose membership from the same place;
# membership is not exhaustion.
#
# Concept source: the aeoess/agent-authority-lifecycle concept document, invariant L10
# (expiry is not revocation) and invariant candidates CAND-01 (an external event is
# authority-changing only when established) and CAND-02 (later evidence does not rewrite
# earlier evidence). All PROPOSED, with no published specification text behind them.
from .v2.bounds import (
    ATTESTOR_ROLE_ANSWERS,
    AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN,
    AUTHORITY_BOUND_FULFILMENT_TYPE,
    AUTHORITY_BOUND_TYPE,
    AUTHORITY_EXHAUSTION_FAILURE_CODES,
    AUTHORITY_EXHAUSTION_ID_DOMAIN,
    AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN,
    AUTHORITY_EXHAUSTION_TYPE,
    BOUND_KINDS,
    BOUND_REASON_CODES,
    BOUND_STATES,
    FULFILMENT_REASON_CODES,
    AttestorRoleResolver,
    AuthorityBound,
    AuthorityBoundError,
    AuthorityExhaustionVerification,
    BoundEvaluation,
    BoundVerificationKeyResolver,
    FulfilmentAssessment,
    assert_authority_bound,
    assess_fulfilment,
    authority_bound_fulfilment_signature_input,
    authority_bound_fulfilment_signature_input_for_write,
    authority_exhaustion_id_input,
    authority_exhaustion_signature_input,
    authority_exhaustion_signature_input_for_write,
    compute_authority_exhaustion_id,
    compute_authority_exhaustion_id_for_write,
    evaluate_bound,
    is_attestor_role_answer,
    is_bound_kind,
    is_purpose_permitted,
    issue_authority_bound_fulfilment,
    issue_authority_exhaustion,
    purpose_category,
    sign_authority_bound_fulfilment,
    sign_authority_exhaustion,
    verify_authority_bound_fulfilment_signature,
    verify_authority_exhaustion,
    verify_authority_exhaustion_signature,
)
