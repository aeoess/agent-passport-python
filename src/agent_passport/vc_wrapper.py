# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""VC Wrapper (Interop Bridge).

Thin layer that uses did:key identifiers, includes passport grade +
delegation scope in credentialSubject, and connects SPIFFE attestations
as VC evidence. Cross-language compatible with the TypeScript SDK.
"""

import base64
from datetime import datetime, timezone
from typing import Any, Optional

from ._time import now_ms, now_rfc3339, parse_rfc3339
from ._vc_proof import (
    assert_presentation_proof_options,
    bind_verification_method,
    proof_signing_input,
)
from .canonical import canonicalize, canonicalize_for_write
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
        parsed = parse_rfc3339(vc["expirationDate"])
        if parsed.ms is None:
            # Previously this parse was unguarded and outside the try below, so
            # an expirationDate an issuer chose could raise out of a verifier
            # whose contract is a result dict.
            checks.append(f"FAIL: credential expirationDate unreadable ({parsed.reason})")
            valid = False
        elif parsed.ms < now_ms():
            checks.append("FAIL: credential expired")
            valid = False
        else:
            checks.append("PASS: credential not expired")
    else:
        checks.append("SKIP: no expirationDate set")

    proof = vc["proof"] if isinstance(vc.get("proof"), dict) else {}
    if proof.get("type") != "Ed25519Signature2020":
        checks.append(f"FAIL: unsupported proof type {proof.get('type')!r}")
        valid = False
    if proof.get("proofPurpose") != "assertionMethod":
        checks.append(
            f"FAIL: proof was made for {proof.get('proofPurpose')!r}, "
            "not assertionMethod"
        )
        valid = False

    # Whose key. The proof names its own verificationMethod, so deriving a key
    # from it and verifying under that key establishes only that the document's
    # author held a private key. The question is whether that key belongs to
    # the issuer the credential names.
    binding = bind_verification_method(vc.get("issuer"), proof.get("verificationMethod"))
    issuer_did = ""
    proof_of_possession = False
    if binding.public_key is None:
        checks.append(f"FAIL: issuer binding {binding.key_authority} - {binding.reason}")
        valid = False
    else:
        issuer_did = vc["issuer"]
        try:
            sig_hex = _base64url_to_hex(proof["proofValue"])
            proof_of_possession = verify(
                proof_signing_input(vc, proof, canonicalize), sig_hex, binding.public_key
            )
        except Exception as e:
            checks.append(f"FAIL: signature verification error - {e}")
            valid = False
        else:
            if proof_of_possession:
                checks.append("PASS: Ed25519 signature valid")
            else:
                checks.append("FAIL: Ed25519 signature invalid")
                valid = False

    evidence = vc.get("evidence")
    if isinstance(evidence, list) and len(evidence) > 0:
        checks.append(f"PASS: {len(evidence)} evidence attachment(s) present")

    return {
        "valid": valid,
        "key_authority": binding.key_authority,
        # The DID the proof key was bound to, empty unless that succeeded. A
        # rejected verification must not hand back the issuer the document
        # named: returning a trusted DID from a failed check is how a caller
        # ends up allowlisting whoever wrote the document.
        "issuer_did": issuer_did,
        # The binding held and the bytes verified. Separate from valid so a
        # caller can tell a forgery from a tampered document, and separate
        # from key_authority so a signature failure is never reported as an
        # identity rejection.
        "proof_of_possession": proof_of_possession,
        "checks": checks,
    }


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
        challenge: The verifier's nonce. Required: a presentation that answers
            no challenge answers any, and verify_verifiable_presentation
            refuses one carrying none.
        domain: Optional. When present it must be a non-empty string.

    Returns:
        Verifiable Presentation dict with Ed25519 proof.

    Raises:
        TypeError: when challenge is absent or unusable, or domain is present
            and unusable. A creator raises where a verifier would return,
            because its caller can still fix the input.
    """
    import time
    assert_presentation_proof_options(challenge, domain, "create_verifiable_presentation")
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


def verify_verifiable_presentation(
    vp: dict[str, Any],
    expected_challenge: Optional[str] = None,
    expected_domain: Optional[str] = None,
) -> dict[str, Any]:
    """Verify a Verifiable Presentation and each contained credential.

    Args:
        vp: Verifiable Presentation dict.
        expected_challenge: The nonce this verifier issued. Required. A
            presentation verified against no challenge is a response to
            nothing in particular, replayable by anyone who has seen it, so
            omitting it is refused rather than treated as "no replay check".
        expected_domain: When given, the proof's domain must equal it.

    Returns:
        dict with 'valid', 'key_authority', 'holder_did', 'proof_of_possession',
        'challenge', 'domain', 'credentials' and 'checks'.

        'valid' means the presentation's bytes are intact, the proof key
        belongs to the holder the presentation names, and the proof answers
        this verifier's challenge. It does NOT mean the holder is trusted;
        'holder_did' is returned so the caller can apply its own allowlist.
        Nor does it mean the challenge has not been used before: one-time use
        is relying-party state, which is why the verified challenge is
        returned for the caller to consume.
    """
    checks = []
    valid = True

    if not all(k in vp for k in ("holder", "proof", "verifiableCredential")):
        checks.append("FAIL: missing required VP fields")
        return {
            "valid": False, "key_authority": "rejected", "holder_did": "",
            "proof_of_possession": False, "challenge": None, "domain": None,
            "credentials": [], "checks": checks,
        }
    checks.append("PASS: required VP fields present")

    proof = vp["proof"] if isinstance(vp.get("proof"), dict) else {}
    if proof.get("type") != "Ed25519Signature2020":
        checks.append(f"FAIL: unsupported proof type {proof.get('type')!r}")
        valid = False
    if proof.get("proofPurpose") != "authentication":
        checks.append(
            f"FAIL: proof was made for {proof.get('proofPurpose')!r}, "
            "not authentication"
        )
        valid = False

    # The challenge and domain compared here are inside the signed bytes, so
    # matching one means the holder answered THIS verifier. Before, they were
    # attached after signing and could be rewritten by whoever held the
    # presentation, which made comparing them establish nothing.
    if not isinstance(expected_challenge, str) or not expected_challenge:
        checks.append(
            "FAIL: no expected challenge supplied; a presentation verified "
            "against no challenge answers any challenge"
        )
        valid = False
    elif proof.get("challenge") != expected_challenge:
        checks.append(
            f"FAIL: proof answers challenge {proof.get('challenge')!r}, "
            f"not {expected_challenge!r}"
        )
        valid = False

    if expected_domain is not None and proof.get("domain") != expected_domain:
        checks.append(
            f"FAIL: proof is addressed to domain {proof.get('domain')!r}, "
            f"not {expected_domain!r}"
        )
        valid = False

    binding = bind_verification_method(vp.get("holder"), proof.get("verificationMethod"))
    holder_did = ""
    proof_of_possession = False
    if binding.public_key is None:
        checks.append(f"FAIL: holder binding {binding.key_authority} - {binding.reason}")
        valid = False
    else:
        holder_did = vp["holder"]
        try:
            sig_hex = _base64url_to_hex(proof["proofValue"])
            proof_of_possession = verify(
                proof_signing_input(vp, proof, canonicalize), sig_hex, binding.public_key
            )
        except Exception as e:
            checks.append(f"FAIL: presentation signature error - {e}")
            valid = False
        else:
            if proof_of_possession:
                checks.append("PASS: presentation signature valid")
            else:
                checks.append("FAIL: presentation signature invalid")
                valid = False

    for i, vc in enumerate(vp["verifiableCredential"]):
        vc_result = verify_verifiable_credential(vc)
        if vc_result["valid"]:
            checks.append(f"PASS: credential[{i}] ({vc.get('id', '?')}) verified")
        else:
            fails = "; ".join(c for c in vc_result["checks"] if c.startswith("FAIL"))
            checks.append(f"FAIL: credential[{i}] ({vc.get('id', '?')}) - {fails}")
            valid = False

    return {
        "valid": valid,
        "key_authority": binding.key_authority,
        "holder_did": holder_did,
        "proof_of_possession": proof_of_possession,
        # Returned only when they were actually verified, so a caller cannot
        # read a challenge out of a presentation that failed.
        "challenge": proof.get("challenge") if valid else None,
        "domain": proof.get("domain") if valid else None,
        "credentials": vp["verifiableCredential"],
        "checks": checks,
    }


# ── Proof helpers ──

def _create_proof(data: dict, private_key: str, did: str, purpose: str, options: dict = None) -> dict:
    """Sign the document together with the proof configuration.

    The configuration is assembled first and the signature is made over the
    document with that configuration in place, so created, verificationMethod,
    proofPurpose, challenge and domain are all inside the signed bytes.
    Previously the signature covered the body alone and the proof was attached
    afterwards, which left every one of those fields rewritable.

    created is emitted through format_rfc3339 rather than datetime.isoformat.
    isoformat writes a +00:00 offset and six fractional digits where the
    TypeScript SDK's toISOString writes .mmmZ; now that created is inside the
    preimage those are different bytes for the same instant, and a proof made
    by one SDK would not verify in the other.
    """
    proof_config: dict[str, object] = {
        "type": "Ed25519Signature2020",
        "created": now_rfc3339(),
        "verificationMethod": f"{did}#key-1",
        "proofPurpose": purpose,
    }
    if options and options.get("challenge"):
        proof_config["challenge"] = options["challenge"]
    if options and options.get("domain"):
        proof_config["domain"] = options["domain"]
    sig = sign(proof_signing_input(data, proof_config, canonicalize_for_write), private_key)
    return {**proof_config, "proofValue": _hex_to_base64url(sig)}


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
