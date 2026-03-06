"""Principal Identity — cryptographic chain from human to agent.

The principal (human or org) gets their own Ed25519 keypair and endorses agents,
creating a two-layer trust chain: principal proves identity + agent proves
who authorized it.
"""

import uuid
import hashlib
from datetime import datetime, timedelta
from .crypto import generate_key_pair, sign, verify
from .canonical import canonicalize


def create_principal_identity(
    display_name,
    domain=None,
    jurisdiction=None,
    contact_channel=None,
    disclosure_level="public",
    metadata=None,
):
    """Create a new principal identity with its own Ed25519 keypair."""
    key_pair = generate_key_pair()
    principal = {
        "principalId": f"principal-{str(uuid.uuid4())[:8]}",
        "displayName": display_name,
        "publicKey": key_pair["publicKey"],
        "domain": domain,
        "jurisdiction": jurisdiction,
        "contactChannel": contact_channel,
        "disclosureLevel": disclosure_level,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "metadata": metadata or {},
    }
    return {"principal": principal, "keyPair": key_pair}


def endorse_agent(
    principal, principal_private_key, agent_id, agent_public_key,
    scope, relationship, expires_in_days=365,
):
    """Endorse an agent. Principal signs: 'This agent acts under my authority.'"""
    now = datetime.utcnow()
    expiry = now + timedelta(days=expires_in_days)
    endorsement_id = f"endorsement-{str(uuid.uuid4())[:8]}"

    payload = {
        "endorsementId": endorsement_id,
        "principalId": principal["principalId"],
        "principalPublicKey": principal["publicKey"],
        "agentId": agent_id,
        "agentPublicKey": agent_public_key,
        "scope": scope,
        "relationship": relationship,
        "endorsedAt": now.isoformat() + "Z",
        "expiresAt": expiry.isoformat() + "Z",
    }
    canonical = canonicalize(payload)
    signature = sign(canonical, principal_private_key)
    return {**payload, "revoked": False, "signature": signature}


def verify_endorsement(endorsement):
    """Verify an endorsement's cryptographic signature."""
    errors = []
    exp_str = endorsement["expiresAt"].replace("Z", "")
    if "+" in exp_str:
        exp_str = exp_str.split("+")[0]
    expired = datetime.fromisoformat(exp_str) < datetime.utcnow()
    if expired:
        errors.append("Endorsement has expired")
    if endorsement.get("revoked"):
        errors.append("Endorsement has been revoked")

    payload = {
        "endorsementId": endorsement["endorsementId"],
        "principalId": endorsement["principalId"],
        "principalPublicKey": endorsement["principalPublicKey"],
        "agentId": endorsement["agentId"],
        "agentPublicKey": endorsement["agentPublicKey"],
        "scope": endorsement["scope"],
        "relationship": endorsement["relationship"],
        "endorsedAt": endorsement["endorsedAt"],
        "expiresAt": endorsement["expiresAt"],
    }
    canonical = canonicalize(payload)
    sig_valid = verify(canonical, endorsement["signature"], endorsement["principalPublicKey"])
    if not sig_valid:
        errors.append("Invalid signature")

    return {
        "valid": sig_valid and not expired and not endorsement.get("revoked"),
        "expired": expired,
        "revoked": endorsement.get("revoked", False),
        "principalId": endorsement["principalId"],
        "agentId": endorsement["agentId"],
        "errors": errors,
    }


def revoke_endorsement(endorsement, reason):
    """Revoke a principal's endorsement of an agent."""
    return {
        **endorsement,
        "revoked": True,
        "revokedAt": datetime.utcnow().isoformat() + "Z",
        "revokedReason": reason,
    }


def create_disclosure(principal, principal_private_key, level=None):
    """Create a selective disclosure of principal identity.
    
    Levels:
    - minimal: just idHash + DID (verifiable but anonymous)
    - verified-only: principalId + publicKey + domain
    - public: everything
    """
    effective_level = level or principal.get("disclosureLevel", "public")
    did = f"did:aps:{principal['publicKey']}"

    if effective_level == "minimal":
        id_hash = hashlib.sha256(principal["principalId"].encode()).hexdigest()[:16]
        revealed = {"idHash": id_hash, "did": did}
    elif effective_level == "verified-only":
        revealed = {
            "principalId": principal["principalId"],
            "publicKey": principal["publicKey"],
            "did": did,
            "domain": principal.get("domain"),
        }
    else:
        revealed = {
            "principalId": principal["principalId"],
            "displayName": principal["displayName"],
            "publicKey": principal["publicKey"],
            "did": did,
            "domain": principal.get("domain"),
            "jurisdiction": principal.get("jurisdiction"),
            "contactChannel": principal.get("contactChannel"),
        }

    canonical = canonicalize(revealed)
    proof = sign(canonical, principal_private_key)

    return {
        "disclosureId": f"disclosure-{str(uuid.uuid4())[:8]}",
        "principalId": principal["principalId"],
        "level": effective_level,
        "revealedFields": revealed,
        "proof": proof,
        "createdAt": datetime.utcnow().isoformat() + "Z",
    }


def verify_disclosure(disclosure):
    """Verify a selective disclosure's proof."""
    try:
        did = disclosure["revealedFields"].get("did", "")
        if not did:
            return {"valid": False, "level": disclosure["level"], "error": "No DID"}
        parts = did.split(":")
        if len(parts) != 3:
            return {"valid": False, "level": disclosure["level"], "error": "Invalid DID"}
        public_key = parts[2]
        canonical = canonicalize(disclosure["revealedFields"])
        sig_valid = verify(canonical, disclosure["proof"], public_key)
        return {
            "valid": sig_valid,
            "level": disclosure["level"],
            "error": None if sig_valid else "Invalid proof",
        }
    except Exception as e:
        return {"valid": False, "level": disclosure["level"], "error": str(e)}


def create_fleet(principal):
    """Create a fleet record for a principal."""
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "principalId": principal["principalId"],
        "principalPublicKey": principal["publicKey"],
        "agents": [],
        "createdAt": now,
        "updatedAt": now,
    }


def add_to_fleet(fleet, endorsement):
    """Add an endorsed agent to the fleet."""
    now = datetime.utcnow()
    exp_str = endorsement["expiresAt"].replace("Z", "")
    if "+" in exp_str:
        exp_str = exp_str.split("+")[0]
    expired = datetime.fromisoformat(exp_str) < now

    status = "revoked" if endorsement.get("revoked") else ("expired" if expired else "active")
    agent = {
        "agentId": endorsement["agentId"],
        "agentPublicKey": endorsement["agentPublicKey"],
        "endorsementId": endorsement["endorsementId"],
        "relationship": endorsement["relationship"],
        "status": status,
        "endorsedAt": endorsement["endorsedAt"],
    }
    return {
        **fleet,
        "agents": fleet["agents"] + [agent],
        "updatedAt": now.isoformat() + "Z",
    }


def get_fleet_status(fleet):
    """Get fleet status summary."""
    agents = fleet["agents"]
    active = [a for a in agents if a["status"] == "active"]
    revoked = [a for a in agents if a["status"] == "revoked"]
    expired = [a for a in agents if a["status"] == "expired"]
    return {
        "principalId": fleet["principalId"],
        "totalAgents": len(agents),
        "activeAgents": len(active),
        "revokedAgents": len(revoked),
        "expiredAgents": len(expired),
        "agents": agents,
    }


def revoke_from_fleet(fleet, agent_id):
    """Revoke an agent from the fleet."""
    return {
        **fleet,
        "agents": [
            {**a, "status": "revoked"} if a["agentId"] == agent_id else a
            for a in fleet["agents"]
        ],
        "updatedAt": datetime.utcnow().isoformat() + "Z",
    }
