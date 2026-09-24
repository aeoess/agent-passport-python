# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Canonical bytes for the two records this module owns.

See ``types.py`` for the specification position: draft-pidlisnyi-aps-03 states no
activation-condition rule, and nothing here changes any existing exported behaviour.

Python port of the TypeScript SDK's src/v2/activation/canonical.ts. The preimages are the
domain tag followed by the UTF-8 bytes of RFC 8785 JCS, byte for byte what the TypeScript
module produces, which is what makes the cross-language parity vectors meaningful.
"""

from __future__ import annotations

import hashlib

from ...canonical import canonicalize_jcs

#: Domain tag for an activation attestation's signature preimage. Distinct APS tag followed
#: by one zero byte, the same discipline ``AuthorityDelegationV1`` and
#: ``AuthorityRevocationV1`` follow, so bytes minted for one construction can never be read
#: as bytes minted for another. ``PROPOSED`` is inside the tag on purpose: if this record is
#: ever ruled into APS under a settled name, its bytes will differ from these, and nothing
#: signed under a proposed tag can be replayed as a specified record.
ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN = "APS-PROPOSED-ACTIVATION-ATTESTATION-SIGNATURE-V0\x00"

#: Domain tag for an activation attestation's identifier preimage.
ACTIVATION_ATTESTATION_ID_DOMAIN = "APS-PROPOSED-ACTIVATION-ATTESTATION-ID-V0\x00"

#: Domain tag for an activation condition's signature preimage.
#:
#: Whether a condition record MUST be signed, and by whom, is not settled. The grant's issuer
#: is the obvious answer and is not the only defensible one: a condition that narrows an
#: already issued grant could come from any party with lifecycle standing over it, and where
#: lifecycle standing comes from is itself unsettled. :func:`verify_activation` therefore does
#: NOT require a signature on the condition, and this tag exists so a deployment that does
#: sign its conditions has one preimage to sign rather than inventing one.
ACTIVATION_CONDITION_SIGNATURE_DOMAIN = "APS-PROPOSED-ACTIVATION-CONDITION-SIGNATURE-V0\x00"


def activation_attestation_body(attestation: dict) -> dict:
    """The signed body of an attestation: every member except the two derived from it.

    ``attestation_id`` and ``signature`` are both excluded because both are derived from the
    body: the identifier is a digest over these bytes and the signature covers the same
    bytes. Every other member, including ones this module never interprets, is inside the
    preimage, so nothing on the record is unauthenticated.
    """
    return {
        key: value
        for key, value in attestation.items()
        if key not in ("attestation_id", "signature")
    }


def activation_attestation_signature_input(attestation: dict) -> str:
    """Exact Ed25519 input for an attestation this module owns.

    This is the DEFAULT preimage, used when the caller supplies no ``attestation_preimage``.
    Which bytes a signature covers is a property of a record type, and this module owns
    exactly one record type, so a model that accepts condition evidence in another shape
    supplies its own preimage callable. See ``verify.py``.
    """
    return ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN + canonicalize_jcs(
        activation_attestation_body(attestation)
    )


def compute_activation_attestation_id(attestation: dict) -> str:
    """Content-bound identifier for an attestation this module owns.

    Recomputable by a verifier rather than accepted as whatever the attestor wrote there.
    """
    material = ACTIVATION_ATTESTATION_ID_DOMAIN + canonicalize_jcs(
        activation_attestation_body(attestation)
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def activation_condition_signature_input(condition: dict) -> str:
    """Exact Ed25519 input for a condition record, for a deployment that chooses to sign one."""
    return ACTIVATION_CONDITION_SIGNATURE_DOMAIN + canonicalize_jcs(condition)
