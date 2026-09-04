# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Proof binding and proof-signing input for the credential surfaces.

Two rules that vc_wrapper and credential_request both need and each got wrong
in the same way.

WHOSE KEY. A proof carries ``verificationMethod``, and both modules derived
the verification key from it and verified under that key. But the proof is
part of the document its author wrote. Deriving the key from it establishes
only that whoever assembled the document held one private key, which is true
of every document anyone can make. The relying party's question is whether
that key belongs to the identity the document CLAIMS to speak for: ``issuer``
on a credential, ``holder`` on a presentation. :func:`bind_verification_method`
answers that, and returns a state rather than a boolean, because "this key is
not the issuer's" and "this DID method cannot be resolved offline" are
different answers and only one of them is an accusation.

WHAT IS SIGNED. Both signed the document body and then attached a proof block
the signature did not cover, so ``created``, ``proofPurpose``, ``challenge``
and ``domain`` could be rewritten without invalidating ``proofValue``. A
presentation minted for one verifier could be readdressed to another.
:func:`proof_signing_input` puts the proof configuration, which is the proof
minus ``proofValue``, inside the signed bytes. This is not W3C Data Integrity
and does not implement RDF canonicalization; it reuses this package's own
canonicalization.

Byte-for-byte the contract of vc-proof.ts in the TypeScript SDK
(agent-passport-system src/core/vc-proof.ts), including the three-valued
``key_authority`` vocabulary, so a credential that binds in one SDK binds in
the other and one that does not is refused for the same stated cause.

A note on what ``verified`` claims. It says the proof key belongs to the DID
the document names. It does NOT say that DID is trusted. Whether to accept an
issuer or a holder is the relying party's allowlist, which is why the
verifiers return the bound DID instead of consulting a list of their own.
"""

from typing import Callable, NamedTuple, Optional

from .did_interop import _hex_to_multibase, _multibase_to_hex


class ProofBinding(NamedTuple):
    """Whether the signing key was shown to belong to the claimed identity.

    ``key_authority`` is one of:
      - ``"verified"``   the DID commits to this key; ``public_key`` is set.
      - ``"rejected"``   the DID commits to a different key, or names a
                         different identity than the document claims.
      - ``"unresolved"`` the DID method is not self-certifying, so the binding
                         cannot be established without fetching a DID
                         document. NOT an acceptance.

    ``public_key`` is set exactly when ``key_authority`` is ``"verified"``, so
    ``public_key is None`` is the failure test and it is the one a type checker
    narrows on. Branching on it rather than on the string means a verifier
    cannot reach the signature check without a key the binding actually
    produced.
    """

    key_authority: str
    public_key: Optional[str] = None
    reason: Optional[str] = None


def _public_key_from_self_certifying(did: str, prefix: str) -> str:
    """Decode and then re-encode, and require the result to be the input.

    ``from_did_key`` in did_interop decodes without checking that the
    identifier is the canonical spelling of the key it decodes to. Two
    different strings that decode to one key would then be two identities for
    one signer, and a payload longer than 32 bytes would produce a "key" that
    is not an Ed25519 key at all. Re-encoding and comparing closes both:
    exactly one string survives per key.
    """
    body = did[len(prefix):]
    if not body.startswith("z"):
        raise ValueError(f"{did}: identifier must use z-prefix (base58btc) multibase")
    public_key = _multibase_to_hex(body)
    if len(public_key) != 64:
        raise ValueError(f"{did}: does not encode a 32-byte Ed25519 key")
    if prefix + _hex_to_multibase(public_key) != did:
        raise ValueError(f"{did}: non-canonical identifier")
    return public_key


def self_certifying_public_key(did: str) -> Optional[str]:
    """The Ed25519 key a self-certifying DID commits to, or None.

    ``None`` means the method is not self-certifying, which is a different
    answer from a raise: a raise means the method claims to encode its own key
    and does not.

    Two methods qualify. ``did:key`` is what every credential this package
    issues uses. ``did:aps`` in the multibase spelling is the legacy form,
    carried so identifiers already emitted stay verifiable; it is the same
    spelling passport_to_did_document writes into ``alsoKnownAs`` and the same
    one the TypeScript SDK binds.

    Two other ``did:aps`` spellings exist elsewhere in this package, one with
    a raw hex body and one with a "z" glued in front of raw hex. Neither is
    multibase, so neither round-trips, and both are refused here. That is not
    a change of mind about them: nothing ever established that such a string
    was a key, and reading one as key material is the defect this function
    replaces.
    """
    if did.startswith("did:key:"):
        return _public_key_from_self_certifying(did, "did:key:")
    if did.startswith("did:aps:"):
        return _public_key_from_self_certifying(did, "did:aps:")
    return None


def bind_verification_method(claimed_did: object, verification_method: object) -> ProofBinding:
    """Bind a proof's ``verificationMethod`` to the identity the document claims.

    Both halves are checked, because either alone is insufficient. The DID
    before the fragment must be the claimed DID, or the proof is a proof by
    somebody else. And the key must derive from that DID, or the DID string
    and the key material are unrelated assertions sitting next to each other.

    Only self-certifying methods can be bound offline. Every other method
    needs a resolved DID document and this package has no resolver on these
    surfaces, so it reports ``unresolved`` and the caller refuses. That is a
    compatibility break for any did:web credential that used to verify here,
    and it is the intended one: it never established anything.

    The fragment is deliberately not constrained. A self-certifying DID
    commits to exactly one key, so the fragment selects nothing and cannot be
    used to substitute key material. A fragment the controller does not list
    is a document-conformance defect, not an authority one, and catching it
    needs the DID document this function does not fetch.
    """
    if not isinstance(claimed_did, str) or not claimed_did:
        return ProofBinding("rejected", None, "document claims no issuer or holder DID")
    if not isinstance(verification_method, str) or not verification_method:
        return ProofBinding("rejected", None, "proof carries no verificationMethod")

    method_did = verification_method.split("#")[0]
    if method_did != claimed_did:
        return ProofBinding(
            "rejected", None,
            f"proof verificationMethod names {method_did}, "
            f"which is not the claimed {claimed_did}",
        )

    try:
        derived = self_certifying_public_key(method_did)
    except (ValueError, TypeError) as exc:
        # A malformed or non-canonical self-certifying identifier. The method
        # claims to encode its own key and does not, which is a rejection
        # rather than an unresolved binding.
        return ProofBinding(
            "rejected", None, f"not a canonical self-certifying identifier: {exc}"
        )

    if derived is None:
        method = ":".join(method_did.split(":")[:2])
        return ProofBinding(
            "unresolved", None,
            f"{method} is not self-certifying and this verifier resolves no DID documents",
        )

    return ProofBinding("verified", derived, None)


def assert_presentation_proof_options(
    challenge: object, domain: object, fn: str
) -> None:
    """Refuse presentation proof options a verifier could never accept.

    A presentation minted without a challenge is permanently unverifiable:
    both presentation verifiers require an expected challenge, and a proof
    carrying none is refused. Minting an artifact this package's own verifier
    will always reject is worth stopping at the one moment the caller can
    still fix it.

    ``domain`` stays optional. What it may not be is present and unusable: an
    empty string or a non-string reads as a domain the presentation is
    addressed to, and it addresses nothing.

    Creators raise; verifiers do not. A verifier that raises is not a verifier
    that rejects, and a relying party branches on the verdict. A creator has a
    caller who can still supply a real challenge.

    Raises:
        TypeError: when ``challenge`` is absent, not a string, or empty, or
            when ``domain`` is present and is not a non-empty string.
    """
    if not isinstance(challenge, str) or not challenge:
        raise TypeError(
            f"{fn}: challenge is required and must be a non-empty string. "
            "A presentation minted without one answers no challenge, so it "
            "answers any, and both presentation verifiers refuse it. "
            f"Got {challenge!r}."
        )
    if domain is not None and (not isinstance(domain, str) or not domain):
        raise TypeError(
            f"{fn}: domain is optional, but when present it must be a "
            f"non-empty string. Got {domain!r}."
        )


def proof_signing_input(
    document: dict[str, object],
    proof: dict[str, object],
    canon: Callable[[object], str],
) -> str:
    """The bytes a proof is made over.

    The document with its ``proof`` member replaced by the proof
    configuration, which is the proof minus ``proofValue``.

    Signing and verification MUST both go through this, or every credential in
    existence stops verifying against half a change. The canonicalizer is the
    caller's, so this package's write-boundary rule survives:
    ``canonicalize_for_write`` when signing, ``canonicalize`` when rebuilding
    the preimage of an artifact that already exists.
    """
    body = {k: v for k, v in document.items() if k != "proof"}
    proof_config = {k: v for k, v in proof.items() if k != "proofValue"}
    return canon({**body, "proof": proof_config})
