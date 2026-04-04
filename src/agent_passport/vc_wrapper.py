# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""VC Wrapper (Interop Bridge).

Thin layer that uses did:key identifiers, includes passport grade +
delegation scope in credentialSubject, and connects SPIFFE attestations
as VC evidence. Cross-language compatible with the TypeScript SDK.
"""

import base64
from datetime import datetime, timezone

from .canonical import canonicalize
from .crypto import sign, verify, public_key_from_private
from .did_interop import to_did_key, from_did_key, _hex_to_multibase


_VC_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]
_APS_CONTEXT = "https://aeoess.com/ns/agent-passport/v1"


def passport_to_verifiable_credential(
    passport: dict,
    issuer_private_key: str,
) -> dict:
    """Wrap an APS passport as a W3C Verifiable Credential using did:key.

    Args:
        passport: dict with agentId, publicKey, and optional agentName, mission,
            capabilities, grade, delegationScope, createdAt, expiresAt, evidence.
        issuer_private_key: Hex-encoded Ed25519 private key.

    Returns:
        Verifiable Credential dict with Ed25519 proof.
    """
    issuer_public_key = public_key_from_private(issuer_private_key)
    subject_did = to_did_key(passport["publicKey"])
    issuer_did = to_did_key(issuer_public_key)

    now = datetime.now(timezone.utc).isoformat()

    credential_subject = {
        "id": subject_did,
        "agentId": passport["agentId"],
        "publicKey": subject_did,
        "publicKeyMultibase": _hex_to_multibase(passport["publicKey"]),
    }
    for field in ("agentName", "mission", "capabilities", "grade", "delegationScope"):
        if passport.get(field) is not None:
            credential_subject[field] = passport[field]

    credential = {
        "@context": [*_VC_CONTEXT, _APS_CONTEXT],
        "id": f"urn:aps:credential:passport:{passport['agentId']}",
        "type": ["VerifiableCredential", "AgentPassportCredential"],
        "issuer": issuer_did,
        "issuanceDate": passport.get("createdAt") or now,
        "credentialSubject": credential_subject,
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

    proof = _create_proof(credential, issuer_private_key, issuer_did, "assertionMethod")
    return {**credential, "proof": proof}


def verify_verifiable_credential(vc: dict) -> dict:
    """Verify a Verifiable Credential's Ed25519 proof.

    Args:
        vc: Verifiable Credential dict.

    Returns:
        dict with 'valid' (bool) and 'checks' (list of strings).
    """
    checks = []
    valid = True

    if not all(k in vc for k in ("@context", "type", "issuer", "credentialSubject", "proof")):
        checks.append("FAIL: missing required VC fields")
        return {"valid": False, "checks": checks}
    checks.append("PASS: required fields present")

    if "VerifiableCredential" not in vc["type"]:
        checks.append("FAIL: type array must include VerifiableCredential")
        return {"valid": False, "checks": checks}
    checks.append("PASS: type includes VerifiableCredential")

    if vc.get("expirationDate"):
        exp = datetime.fromisoformat(vc["expirationDate"].replace("Z", "+00:00"))
        if exp < datetime.now(timezone.utc):
            checks.append("FAIL: credential expired")
            valid = False
        else:
            checks.append("PASS: credential not expired")
    else:
        checks.append("SKIP: no expirationDate set")

    try:
        vm_did = vc["proof"]["verificationMethod"].split("#")[0]
        if vm_did.startswith("did:key:"):
            public_key = from_did_key(vm_did)
        else:
            public_key = vm_did.split(":")[-1]

        cred_without_proof = {k: v for k, v in vc.items() if k != "proof"}
        canonical = canonicalize(cred_without_proof)
        sig_hex = _base64url_to_hex(vc["proof"]["proofValue"])
        sig_valid = verify(canonical, sig_hex, public_key)

        if sig_valid:
            checks.append("PASS: Ed25519 signature valid")
        else:
            checks.append("FAIL: Ed25519 signature invalid")
            valid = False
    except Exception as e:
        checks.append(f"FAIL: signature verification error - {e}")
        valid = False

    evidence = vc.get("evidence")
    if isinstance(evidence, list) and len(evidence) > 0:
        checks.append(f"PASS: {len(evidence)} evidence attachment(s) present")

    return {"valid": valid, "checks": checks}


def create_verifiable_presentation(
    credentials: list,
    holder_private_key: str,
    challenge: str = None,
    domain: str = None,
) -> dict:
    """Wrap one or more VCs into a Verifiable Presentation.

    Args:
        credentials: List of Verifiable Credential dicts.
        holder_private_key: Hex-encoded Ed25519 private key.
        challenge: Optional challenge nonce for replay protection.
        domain: Optional domain for replay protection.

    Returns:
        Verifiable Presentation dict with Ed25519 proof.
    """
    import time
    holder_public_key = public_key_from_private(holder_private_key)
    holder_did = to_did_key(holder_public_key)

    presentation = {
        "@context": _VC_CONTEXT,
        "id": f"urn:aps:presentation:{int(time.time() * 1000)}",
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": credentials,
    }

    options = {}
    if challenge:
        options["challenge"] = challenge
    if domain:
        options["domain"] = domain

    proof = _create_proof(
        presentation, holder_private_key, holder_did, "authentication", options or None
    )
    return {**presentation, "proof": proof}


def verify_verifiable_presentation(vp: dict) -> dict:
    """Verify a Verifiable Presentation and each contained credential.

    Args:
        vp: Verifiable Presentation dict.

    Returns:
        dict with 'valid' (bool), 'credentials' (list), and 'checks' (list).
    """
    checks = []
    valid = True

    if not all(k in vp for k in ("holder", "proof", "verifiableCredential")):
        checks.append("FAIL: missing required VP fields")
        return {"valid": False, "credentials": [], "checks": checks}
    checks.append("PASS: required VP fields present")

    try:
        vm_did = vp["proof"]["verificationMethod"].split("#")[0]
        if vm_did.startswith("did:key:"):
            public_key = from_did_key(vm_did)
        else:
            public_key = vm_did.split(":")[-1]

        vp_without_proof = {k: v for k, v in vp.items() if k != "proof"}
        canonical = canonicalize(vp_without_proof)
        sig_hex = _base64url_to_hex(vp["proof"]["proofValue"])
        sig_valid = verify(canonical, sig_hex, public_key)

        if sig_valid:
            checks.append("PASS: presentation signature valid")
        else:
            checks.append("FAIL: presentation signature invalid")
            valid = False
    except Exception as e:
        checks.append(f"FAIL: presentation signature error - {e}")
        valid = False

    for i, vc in enumerate(vp["verifiableCredential"]):
        vc_result = verify_verifiable_credential(vc)
        if vc_result["valid"]:
            checks.append(f"PASS: credential[{i}] ({vc.get('id', '?')}) verified")
        else:
            fails = "; ".join(c for c in vc_result["checks"] if c.startswith("FAIL"))
            checks.append(f"FAIL: credential[{i}] ({vc.get('id', '?')}) - {fails}")
            valid = False

    return {"valid": valid, "credentials": vp["verifiableCredential"], "checks": checks}


# ── Proof helpers ──

def _create_proof(data: dict, private_key: str, did: str, purpose: str, options: dict = None) -> dict:
    canonical = canonicalize(data)
    sig = sign(canonical, private_key)
    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"{did}#key-1",
        "proofPurpose": purpose,
        "proofValue": _hex_to_base64url(sig),
    }
    if options and options.get("challenge"):
        proof["challenge"] = options["challenge"]
    if options and options.get("domain"):
        proof["domain"] = options["domain"]
    return proof


# ── Encoding helpers ──

def _hex_to_base64url(hex_str: str) -> str:
    raw = bytes.fromhex(hex_str)
    b64 = base64.b64encode(raw).decode("ascii")
    return b64.replace("+", "-").replace("/", "_").rstrip("=")


def _base64url_to_hex(b64url: str) -> str:
    b64 = b64url.replace("-", "+").replace("_", "/")
    padding = 4 - len(b64) % 4
    if padding != 4:
        b64 += "=" * padding
    return base64.b64decode(b64).hex()
