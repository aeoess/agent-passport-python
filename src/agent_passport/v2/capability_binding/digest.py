# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The two digests a capability pin is taken over.

See ``types.py`` for the specification position: draft-pidlisnyi-aps-03 defines neither of
these digests and states no pin rule. Concept source: aeoess/agent-authority-lifecycle,
invariant candidate CAND-07 v2.
"""

from __future__ import annotations

import hashlib

from ...canonical import canonicalize_jcs
from .types import CapabilityBindingError

#: The metadata-digest domain the ``aps-capability-binding-drift-v0`` candidate fixture
#: family declares. Offered so a caller reproducing that family passes the same label, not
#: as a protocol constant and not as a default. PROPOSED.
CAPABILITY_METADATA_DOMAIN_CBD_V0 = "APS-CBD-TOOL-METADATA-V0"


def capability_implementation_digest(implementation: str | bytes) -> str:
    """``sha256:`` over the raw implementation bytes.

    Byte-identical to what ``create_tool_registry_entry`` and ``verify_tool_integrity``
    already compute for ``implementationHash``, and exported here so a caller can obtain
    the observed digest without minting a registry entry. The content may be source, a
    binary, or an endpoint descriptor: this function hashes exactly the bytes it is given
    and interprets nothing.
    """
    raw = implementation.encode("utf-8") if isinstance(implementation, str) else implementation
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def capability_metadata_digest(metadata: object, domain: str) -> str:
    """``sha256:`` over ``domain || 0x00 || JCS(metadata)``.

    DISTINCT FROM THE IMPLEMENTATION DIGEST, WHICH IS THE WHOLE POINT. A tool can keep its
    name and its implementation bytes while its declared description, schema or permissions
    change, gaining a destructive permission without any change to the grant. An
    implementation digest cannot see that; this one can.

    The domain-separated preimage follows the style draft-03 section 4.1 uses for its own
    digests, verbatim::

        payload_ref = lowercase-hex(SHA-256("APS-ACTION-PAYLOAD-V1" || 0x00 || JCS(payload)))

    draft-03 does not define a tool-metadata digest, so ``domain`` is REQUIRED and has no
    default: a default here would mint protocol vocabulary this module has no standing to
    mint. :data:`CAPABILITY_METADATA_DOMAIN_CBD_V0` is the one label already in use by a
    published candidate fixture family, offered as a value to pass rather than as a
    default.

    The canonical bytes are RFC 8785 JCS, which preserves ``None`` members. The SDK's
    legacy ``canonicalize`` strips them, so the two are NOT interchangeable for this
    preimage.
    """
    if not isinstance(domain, str) or domain == "":
        raise CapabilityBindingError(
            "METADATA_DIGEST_DOMAIN_REQUIRED",
            "domain must be a non-empty string: this module mints no default metadata "
            "digest domain",
        )
    preimage = domain.encode("utf-8") + b"\x00" + canonicalize_jcs(metadata).encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()
