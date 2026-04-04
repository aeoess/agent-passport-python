# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Credential Request Protocol.

Selective disclosure: verifier requests specific claims,
agent presents a VC containing only those claims.
Cross-language compatible with the TypeScript SDK.
"""

import time
import uuid
import random
import string
from datetime import datetime, timezone

from .canonical import canonicalize
from .crypto import sign, verify, public_key_from_private
from .did_interop import to_did_key, from_did_key, _hex_to_multibase
from .vc_wrapper import _create_proof, _base64url_to_hex, _VC_CONTEXT


_APS_CONTEXT = "https://aeoess.com/ns/agent-passport/v1"


def create_credential_request(
    claims: list,
    verifier_did: str,
    challenge: str = None,
) -> dict:
    """Create a credential request specifying which claims the verifier needs.

    Args:
        claims: List of claim names (e.g., ["grade", "capabilities"]).
        verifier_did: DID of the verifier making the request.
        challenge: Optional challenge nonce. Auto-generated if not provided.

    Returns:
        CredentialRequest dict.
    """
    if not claims or len(claims) == 0:
        raise ValueError("Credential request must specify at least one claim")
    if not verifier_did:
        raise ValueError("Verifier DID is required")

    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return {
        "id": f"creq_{int(time.time() * 1000)}_{suffix}",
        "requestedClaims": claims,
        "verifierDID": verifier_did,
        "challenge": challenge or str(uuid.uuid4()),
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }


def fulfill_credential_request(
    request: dict,
    passport: dict,
    private_key: str,
) -> dict:
    """Fulfill a credential request with selective disclosure.

    Creates a VP containing a VC with only the requested claims.
    The VC's credentialSubject always includes id and agentId,
    plus only the fields listed in request.requestedClaims.

    Args:
        request: CredentialRequest dict from create_credential_request.
        passport: dict with agentId, publicKey, and optional fields.
        private_key: Hex-encoded Ed25519 private key.

    Returns:
        Verifiable Presentation dict.
    """
    public_key = public_key_from_private(private_key)
    subject_did = to_did_key(passport["publicKey"])
    issuer_did = to_did_key(public_key)
    now = datetime.now(timezone.utc).isoformat()

    # Full subject with all possible claims
    full_subject = {
        "id": subject_did,
        "agentId": passport["agentId"],
        "publicKey": subject_did,
        "publicKeyMultibase": _hex_to_multibase(passport["publicKey"]),
        "agentName": passport.get("agentName"),
        "mission": passport.get("mission"),
        "capabilities": passport.get("capabilities"),
        "grade": passport.get("grade"),
        "delegationScope": passport.get("delegationScope"),
    }

    # Filter to only requested claims + mandatory fields
    selective = {
        "id": full_subject["id"],
        "agentId": full_subject["agentId"],
    }
    for claim in request["requestedClaims"]:
        if claim in full_subject and full_subject[claim] is not None:
            selective[claim] = full_subject[claim]

    credential = {
        "@context": [*_VC_CONTEXT, _APS_CONTEXT],
        "id": f"urn:aps:credential:selective:{passport['agentId']}:{request['id']}",
        "type": ["VerifiableCredential", "AgentPassportCredential"],
        "issuer": issuer_did,
        "issuanceDate": passport.get("createdAt") or now,
        "credentialSubject": selective,
    }

    if passport.get("expiresAt"):
        credential["expirationDate"] = passport["expiresAt"]

    evidence = passport.get("evidence")
    if evidence and len(evidence) > 0:
        credential["evidence"] = [
            {
                "type": "InfrastructureAttestation",
                "provider": att["provider"],
                "subjectClass": att["subjectClass"],
                "verificationMethod": att["verificationMethod"],
                "issuedAt": att["issuedAt"],
                "expiresAt": att["expiresAt"],
            }
            for att in evidence
        ]

    vc_proof = _create_proof(credential, private_key, issuer_did, "assertionMethod")
    vc = {**credential, "proof": vc_proof}

    # Wrap in VP with the request's challenge
    holder_did = to_did_key(passport["publicKey"])

    presentation = {
        "@context": _VC_CONTEXT,
        "id": f"urn:aps:presentation:{request['id']}",
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": [vc],
    }

    vp_proof = _create_proof(
        presentation,
        private_key,
        holder_did,
        "authentication",
        {"challenge": request["challenge"], "domain": request["verifierDID"]},
    )
    return {**presentation, "proof": vp_proof}


def verify_credential_response(
    vp: dict,
    expected_challenge: str = None,
) -> dict:
    """Verify a credential response VP and extract requested claims.

    Checks:
    1. VP proof is valid
    2. Challenge matches (replay protection)
    3. Each contained VC proof is valid
    4. Credential is not expired
    5. Extracts claims from credentialSubject

    Args:
        vp: Verifiable Presentation dict.
        expected_challenge: Optional expected challenge for replay protection.

    Returns:
        dict with 'valid' (bool), 'claims' (dict), and 'checks' (list).
    """
    checks = []
    valid = True

    if not all(k in vp for k in ("holder", "proof", "verifiableCredential")):
        checks.append("FAIL: missing required VP fields")
        return {"valid": False, "claims": {}, "checks": checks}
    checks.append("PASS: required VP fields present")

    # Verify challenge
    proof = vp["proof"]
    if expected_challenge:
        if proof.get("challenge") == expected_challenge:
            checks.append("PASS: challenge matches")
        else:
            checks.append(
                f'FAIL: challenge mismatch - expected "{expected_challenge}", '
                f'got "{proof.get("challenge")}"'
            )
            valid = False

    # Verify VP proof
    try:
        vm_did = proof["verificationMethod"].split("#")[0]
        public_key = from_did_key(vm_did) if vm_did.startswith("did:key:") else vm_did.split(":")[-1]
        vp_without_proof = {k: v for k, v in vp.items() if k != "proof"}
        canonical = canonicalize(vp_without_proof)
        sig_hex = _base64url_to_hex(proof["proofValue"])
        sig_valid = verify(canonical, sig_hex, public_key)

        if sig_valid:
            checks.append("PASS: presentation signature valid")
        else:
            checks.append("FAIL: presentation signature invalid")
            valid = False
    except Exception as e:
        checks.append(f"FAIL: presentation signature error - {e}")
        valid = False

    # Verify each credential and extract claims
    claims = {}

    for i, vc in enumerate(vp["verifiableCredential"]):
        try:
            vm_did = vc["proof"]["verificationMethod"].split("#")[0]
            public_key = from_did_key(vm_did) if vm_did.startswith("did:key:") else vm_did.split(":")[-1]
            vc_without_proof = {k: v for k, v in vc.items() if k != "proof"}
            canonical = canonicalize(vc_without_proof)
            sig_hex = _base64url_to_hex(vc["proof"]["proofValue"])
            sig_valid = verify(canonical, sig_hex, public_key)

            if sig_valid:
                checks.append(f"PASS: credential[{i}] signature valid")
            else:
                checks.append(f"FAIL: credential[{i}] signature invalid")
                valid = False
                continue
        except Exception as e:
            checks.append(f"FAIL: credential[{i}] signature error - {e}")
            valid = False
            continue

        # Check expiration
        if vc.get("expirationDate"):
            exp = datetime.fromisoformat(vc["expirationDate"].replace("Z", "+00:00"))
            if exp < datetime.now(timezone.utc):
                checks.append(f"FAIL: credential[{i}] expired")
                valid = False
            else:
                checks.append(f"PASS: credential[{i}] not expired")

        # Extract claims
        subject = vc.get("credentialSubject", {})
        for key, value in subject.items():
            if key != "id" and value is not None:
                claims[key] = value

    return {"valid": valid, "claims": claims, "checks": checks}
