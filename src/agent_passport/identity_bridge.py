# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Identity Bridge: import external identity credentials into APS.

Import SPIFFE SVIDs and OAuth tokens into APS attestations and
delegation parameters. Cross-language compatible with the TypeScript
SDK's identity-bridge module.
"""

import hashlib
from datetime import datetime, timezone


# Default OAuth -> APS scope mapping
_DEFAULT_SCOPE_MAP = {
    "read:*": "data_read",
    "write:*": "data_write",
    "admin:*": "governance",
    "pay:*": "commerce",
}


def parse_spiffe_id(spiffe_id: str) -> dict:
    """Parse a SPIFFE ID into trust domain and workload path.

    Format: spiffe://trust-domain/workload/path/segments

    Args:
        spiffe_id: A SPIFFE ID string.

    Returns:
        dict with 'trust_domain' and 'workload_path'.
    """
    if not spiffe_id or not spiffe_id.startswith("spiffe://"):
        raise ValueError(f"Invalid SPIFFE ID: must start with spiffe:// - got: {spiffe_id}")
    without_scheme = spiffe_id[len("spiffe://"):]
    slash_index = without_scheme.find("/")
    if slash_index == -1 or slash_index == 0:
        raise ValueError(f"Invalid SPIFFE ID: missing trust domain or workload path - got: {spiffe_id}")
    trust_domain = without_scheme[:slash_index]
    workload_path = without_scheme[slash_index:]
    if not workload_path or workload_path == "/":
        raise ValueError(f"Invalid SPIFFE ID: workload path must not be empty - got: {spiffe_id}")
    return {"trust_domain": trust_domain, "workload_path": workload_path}


def import_spiffe_svid(svid: dict) -> dict:
    """Import a SPIFFE SVID into an APS ProviderAttestation.

    SPIFFE SVIDs are infrastructure-level identity (Tier 1 in APS attestation model).

    Args:
        svid: dict with 'spiffe_id', optional 'x509_cert', and 'expires_at' (ISO 8601).

    Returns:
        ProviderAttestation dict.
    """
    spiffe_id = svid.get("spiffe_id", "")
    parsed = parse_spiffe_id(spiffe_id)

    expires_at = svid.get("expires_at")
    if not expires_at:
        raise ValueError("SVID expires_at is required")

    subject_id_hash = hashlib.sha256(spiffe_id.encode("utf-8")).hexdigest()

    return {
        "provider": parsed["trust_domain"],
        "subjectClass": "workload",
        "subjectIdHash": subject_id_hash,
        "verificationMethod": "x509" if svid.get("x509_cert") else "spiffe_bundle",
        "issuedAt": datetime.now(timezone.utc).isoformat(),
        "expiresAt": expires_at,
    }


def map_oauth_scopes(oauth_scopes: list, scope_mapping: dict = None) -> list:
    """Convert OAuth scopes to APS delegation scopes.

    Matching rules:
    1. Exact match checked first
    2. Wildcard match: "read:users" matches "read:*" pattern
    3. Unmatched scopes are passed through as-is

    Args:
        oauth_scopes: List of OAuth scope strings.
        scope_mapping: Optional custom mapping (overrides defaults for overlapping keys).

    Returns:
        List of APS delegation scope strings (deduplicated, order preserved).
    """
    mapping = {**_DEFAULT_SCOPE_MAP, **(scope_mapping or {})}
    result = []
    seen = set()

    for scope in oauth_scopes:
        mapped = None

        # Exact match first
        if scope in mapping:
            mapped = mapping[scope]
        else:
            # Wildcard match
            prefix = scope.split(":")[0]
            wildcard_key = f"{prefix}:*"
            if wildcard_key in mapping:
                mapped = mapping[wildcard_key]

        value = mapped or scope
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def import_oauth_token(token: dict, scope_mapping: dict = None) -> dict:
    """Convert an OAuth token's claims into APS delegation parameters.

    The OAuth scope becomes the delegation ceiling. Agent ID is deterministic:
    sha256(iss + sub) truncated, so the same OAuth subject always maps to
    the same APS agent.

    Args:
        token: dict with 'sub', 'scope' (space-separated), 'iss', 'exp' (unix seconds).
        scope_mapping: Optional custom scope mapping.

    Returns:
        dict with 'agent_id', 'delegation_scope', and 'expires_at'.
    """
    if not token.get("sub"):
        raise ValueError("OAuth token must have a sub claim")
    if not token.get("iss"):
        raise ValueError("OAuth token must have an iss claim")
    if not token.get("exp") or token["exp"] <= 0:
        raise ValueError("OAuth token must have a valid exp claim")

    scope_str = token.get("scope", "")
    scopes = [s for s in scope_str.split(" ") if s]
    delegation_scope = map_oauth_scopes(scopes, scope_mapping)

    id_hash = hashlib.sha256(
        f"{token['iss']}:{token['sub']}".encode("utf-8")
    ).hexdigest()[:16]

    agent_id = f"agent-oauth-{id_hash}"
    expires_at = datetime.fromtimestamp(token["exp"], tz=timezone.utc).isoformat()

    return {
        "agent_id": agent_id,
        "delegation_scope": delegation_scope,
        "expires_at": expires_at,
    }
