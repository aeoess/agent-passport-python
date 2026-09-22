# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Verifying one direct revocation against the delegation it names.

Python port of the TypeScript SDK's src/v2/authority-revocation/verify.ts.
"""

from __future__ import annotations

import re

from ..authority_delegation.canonical import (
    authority_delegation_body,
    compute_authority_delegation_id,
)
from ..authority_delegation.schema import validate_authority_delegation_shape
from .canonical import (
    authority_revocation_body,
    authority_revocation_cascade_origin,
    compute_authority_revocation_cascade_transaction_id,
    compute_authority_revocation_id,
    verify_authority_revocation_signature,
)
from .schema import validate_authority_revocation_shape
from .types import (
    KEY_RESOLUTION_OUTCOME_CODES,
    AuthorityRevocationFailure,
    AuthorityRevocationVerificationResult,
)

# Well-formed Ed25519 public key material: 32 bytes as hexadecimal. A resolver
# that hands back anything else has produced structurally malformed material,
# and the signature check must not run on it: reporting SIGNATURE_INVALID there
# would say the bytes were checked and failed when nothing was checked at all.
_KEY_MATERIAL = re.compile(r"^[0-9a-fA-F]{64}$")

_UNSUPPORTED_CODES = frozenset({"UNSUPPORTED_RECORD_TYPE", "UNSUPPORTED_VERSION"})

_KEY_OUTCOME_MESSAGES: dict[str, str] = {
    "KEY_SCHEME_UNSUPPORTED": "identifier scheme is not supported by the resolver",
    "KEY_NOT_FOUND": "revoker or key was not found",
    "KEY_AMBIGUOUS": "key resolution was ambiguous",
    "KEY_UNREACHABLE": "key material was unreachable",
    "KEY_MATERIAL_MALFORMED": "resolved key material is structurally malformed",
}


def _result(state: str, failures) -> AuthorityRevocationVerificationResult:
    return AuthorityRevocationVerificationResult(state=state, failures=tuple(failures))


def _invalid(code: str, message: str) -> AuthorityRevocationVerificationResult:
    return _result("invalid", (AuthorityRevocationFailure(code=code, message=message),))


def _indeterminate(code: str, message: str) -> AuthorityRevocationVerificationResult:
    return _result("indeterminate", (AuthorityRevocationFailure(code=code, message=message),))


def _key_resolution_failure(resolved):
    """Map a resolver's answer onto the draft's section 2.5 outcomes, or None
    when it resolved usable key material.

    An unsupported identifier scheme is unsupported; everything else that is not
    a usable key is indeterminate, never SIGNATURE_INVALID, because in those
    branches no signature was checked at all.
    """
    if type(resolved) is str:
        if _KEY_MATERIAL.fullmatch(resolved):
            return None
        return _indeterminate(
            "KEY_MATERIAL_MALFORMED",
            "resolved key material is not a 32-byte Ed25519 public key",
        )
    if type(resolved) is dict:
        outcome = resolved.get("outcome")
        code = KEY_RESOLUTION_OUTCOME_CODES.get(outcome) if type(outcome) is str else None
        if code is not None:
            state = "unsupported" if outcome == "unsupported_scheme" else "indeterminate"
            return _result(
                state, (AuthorityRevocationFailure(code=code, message=_KEY_OUTCOME_MESSAGES[code]),)
            )
    return _indeterminate(
        "KEY_RESOLUTION_FAILED", "revoker verification key could not be resolved"
    )


def verify_authority_revocation(
    candidate,
    delegation,
    *,
    resolve_verification_key,
) -> AuthorityRevocationVerificationResult:
    """Verify one draft-03 section 3.5.1 direct revocation against the delegation it names.

    A revocation is never judged alone. Whether a record is a revocation of THIS
    delegation and whether its signer was allowed to revoke are both questions
    about the target, so the target is a required argument and every
    authorization fact is read from it.

    Checks, in order, returning at the first that fails:

     1. closed schema and canonical values on the revocation
     2. ``cascade_transaction_id`` recomputes from the record's own origin content
     3. ``revocation_id`` recomputes from the record's own body
     4. closed schema and canonical values on the target delegation
     5. the target's ``delegation_id`` recomputes from the target's own body
     6. the revocation's ``delegation_id`` equals the target's
     7. the revocation's ``revoker`` equals the TARGET's ``issuer`` (section 3.5)
     8. the revoker's key resolves, at the revocation's ``revoked_at``
     9. the Ed25519 signature verifies over the domain-tagged preimage

    Step 8 hands the resolver ``delegation["issuer"]``, read from the target
    delegation, not the ``revoker`` the record carries. The two are equal by
    step 7, and reading the target's member is what makes the authorization
    external to the record: no field inside a revocation selects the key that
    authorizes it. ``resolve_verification_key`` is called with
    (issuer, verification_method, revoked_at), the same three-argument shape the
    delegation chain verifier's resolver takes; draft section 2.4 is why the
    third argument is the record's own ``revoked_at`` and not a verification
    clock.

    Fails closed. Anything unrecognized, any resolver that raises, any shape
    this schema does not claim, produces "invalid", "indeterminate" or
    "unsupported", never "valid". This function does not raise.
    """
    shape_failures = validate_authority_revocation_shape(candidate)
    if shape_failures:
        unsupported = all(item.code in _UNSUPPORTED_CODES for item in shape_failures)
        return _result("unsupported" if unsupported else "invalid", shape_failures)
    revocation = candidate

    body = authority_revocation_body(revocation)
    origin = authority_revocation_cascade_origin(body)
    if compute_authority_revocation_cascade_transaction_id(origin) != revocation["cascade_transaction_id"]:
        return _invalid(
            "CASCADE_TRANSACTION_MISMATCH", "cascade_transaction_id does not recompute from the record"
        )
    if compute_authority_revocation_id(body) != revocation["revocation_id"]:
        return _invalid("ID_MISMATCH", "revocation content address does not match its body")

    target_failures = validate_authority_delegation_shape(delegation)
    if target_failures:
        return _invalid("SCHEMA_INVALID", f"target delegation invalid ({target_failures[0].code})")
    target = delegation
    if compute_authority_delegation_id(authority_delegation_body(target)) != target["delegation_id"]:
        return _invalid(
            "TARGET_ID_MISMATCH", "target delegation content address does not match its body"
        )
    if revocation["delegation_id"] != target["delegation_id"]:
        return _invalid("TARGET_MISMATCH", "revocation does not name this delegation")
    # Draft section 3.5: a delegation may be revoked by its issuer, and by
    # nobody else this document names.
    if revocation["revoker"] != target["issuer"]:
        return _invalid("REVOKER_NOT_ISSUER", "revoker is not the target delegation issuer")

    if not callable(resolve_verification_key):
        return _indeterminate("KEY_RESOLUTION_FAILED", "no verification key resolver was supplied")
    try:
        # target["issuer"], not revocation["revoker"]: the authorizing identity
        # comes from the record being revoked.
        resolved = resolve_verification_key(
            target["issuer"], revocation["verification_method"], revocation["revoked_at"]
        )
    except Exception:
        resolved = None
    key_failure = _key_resolution_failure(resolved)
    if key_failure is not None:
        return key_failure

    if not verify_authority_revocation_signature(revocation, resolved):
        return _invalid("SIGNATURE_INVALID", "Ed25519 signature is invalid")
    return _result("valid", ())
