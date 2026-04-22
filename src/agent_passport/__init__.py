# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
Docs: https://aeoess.com/llms-full.txt
"""

__version__ = "2.0.0"

# Crypto
from .crypto import generate_key_pair, sign, verify, public_key_from_private

# Canonical serialization
from .canonical import canonicalize

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

# Attribution (Layer 3 — Merkle proofs)
from .attribution import (
    build_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
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
    verify_policy_receipt,
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
