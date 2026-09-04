# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The bytes a credential proof is signed over, pinned against TypeScript.

A credential crosses between the two SDKs. If they build different preimages
from the same document, a proof made by one does not verify in the other, and
the failure looks like a bad signature rather than like the disagreement it is.

The vectors carry a document with a stale ``proof`` member that must be
dropped, a ``proofValue`` that must be excluded from the configuration, nested
objects, arrays, null, booleans, and non-ASCII text, because those are where
two canonicalizers diverge if they are going to.
"""

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport._vc_proof import proof_signing_input
from agent_passport.canonical import canonicalize, canonicalize_for_write

VECTORS = json.loads(
    (Path(__file__).parent / "cross_impl" / "vc-proof-preimage-vectors.json").read_text(
        encoding="utf-8"
    )
)

CANONICALIZERS = {"canonicalize": canonicalize, "canonicalizeForWrite": canonicalize_for_write}


@pytest.mark.parametrize("which", sorted(CANONICALIZERS))
def test_the_preimage_is_byte_identical_to_typescript(which):
    produced = proof_signing_input(VECTORS["document"], VECTORS["proof"], CANONICALIZERS[which])
    expected = VECTORS["expected"][which]
    assert produced == expected["preimage"]
    assert hashlib.sha256(produced.encode("utf-8")).hexdigest() == expected["sha256"]


@pytest.mark.parametrize("which", sorted(CANONICALIZERS))
def test_the_proof_value_is_not_in_the_bytes_it_signs(which):
    """A signature cannot cover itself. The configuration is the proof minus
    proofValue, and the document's own stale proof member is replaced, not
    merged."""
    produced = proof_signing_input(VECTORS["document"], VECTORS["proof"], CANONICALIZERS[which])
    assert VECTORS["proof"]["proofValue"] not in produced
    assert "IGNORED" not in produced


@pytest.mark.parametrize("which", sorted(CANONICALIZERS))
def test_every_rewritable_proof_field_is_inside_the_bytes(which):
    """The fields that used to sit outside the signature. Each must change the
    preimage, or it can still be rewritten on a signed artifact."""
    base = proof_signing_input(VECTORS["document"], VECTORS["proof"], CANONICALIZERS[which])
    for field, other in [
        ("created", "2020-01-01T00:00:00.000Z"),
        ("verificationMethod", "did:key:z6MkOther#key-1"),
        ("proofPurpose", "assertionMethod"),
        ("challenge", "nonce-parity-2"),
        ("domain", "verifier-b.example"),
        ("type", "JsonWebSignature2020"),
    ]:
        altered = {**VECTORS["proof"], field: other}
        assert proof_signing_input(
            VECTORS["document"], altered, CANONICALIZERS[which]
        ) != base, f"{field} is not covered by the signature"
