# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""aps:authority-revocation:v1, the draft-pidlisnyi-aps-03 section 3.5.1 direct
revocation of an AuthorityDelegationV1.

Port of the TypeScript SDK's src/v2/authority-revocation package, following it
file by file: the closed schema, the three domain-separated preimages, issuance
under a caller-supplied ``now`` and nonce, verification with issuer-bound
historical key resolution at ``revoked_at``, the first-wins store, the verifying
mutation path, and the fail-closed resolver the authority delegation chain
verifier takes.

Distinct from the pre-draft revocation surface in agent_passport.passport, which
carries a raw public key, a free-text reason, no cascade transaction identity,
no nonce, no record_type and no domain-separated preimage. That record cannot
represent section 3.5.1 evidence and is not reused here.

What this package does NOT do, matching the TypeScript module it ports:

- No derived revocation records for descendants of the revoked delegation. This
  is one direct revocation of one delegation. Enforcement against descendants
  comes from chain verification, which rejects any chain with a revoked
  ancestor, not from a cascade-derived record.
- No cascade-completion record. Section 3.5.1 makes completion depend on the
  last descendant's revocation being persistent, and no store interface here
  establishes persistence.
- No suspension.

Points where the Python port's surface differs from the TypeScript SDK's, each
documented at the place it applies:

- Issuance takes keyword arguments where TypeScript takes one options object,
  and verification, the mutation path and the resolver take
  ``resolve_verification_key`` as a keyword argument rather than an options
  object with one member (issue.py, verify.py).
- Issuance raises AuthorityRevocationError, which carries ``code``, where the
  TypeScript SDK throws an Error whose message names the code in parentheses.
  The code stays inside the message too (types.py).
- Nothing is snapshotted before it is judged. TypeScript's snapshotPlainData()
  defends against a getter or a Proxy trap answering two reads differently;
  Python dict access runs no code, and this schema's exact-type checks are what
  establish plain JSON data (schema.py). record.py copies for a different
  reason, stated there.
- The schema reports a non-str member name as SCHEMA_INVALID before it reads
  record_type or version, since a dict lookup would otherwise compare against
  that key and run its code. A JavaScript object key is always a string, so the
  TypeScript schema has no such case (schema.py).
"""

from __future__ import annotations

from .canonical import (
    AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
    AUTHORITY_REVOCATION_ID_DOMAIN,
    AUTHORITY_REVOCATION_SIGNATURE_DOMAIN,
    authority_revocation_body,
    authority_revocation_cascade_origin,
    authority_revocation_cascade_transaction_input,
    authority_revocation_id_input,
    authority_revocation_signature_input,
    compute_authority_revocation_cascade_transaction_id,
    compute_authority_revocation_cascade_transaction_id_for_write,
    compute_authority_revocation_id,
    compute_authority_revocation_id_for_write,
    sign_authority_revocation,
    verify_authority_revocation_signature,
)
from .issue import issue_authority_revocation
from .record import AuthorityRevocationRecordResult, record_authority_revocation
from .resolver import create_authority_revocation_resolver
from .schema import (
    is_authority_revocation_v1,
    validate_authority_revocation_shape,
)
from .store import InMemoryAuthorityRevocationStore
from .types import (
    AUTHORITY_REVOCATION_FAILURE_CODES,
    AUTHORITY_REVOCATION_RECORD_TYPE,
    AUTHORITY_REVOCATION_VERSION,
    AuthorityRevocationError,
    AuthorityRevocationFailure,
    AuthorityRevocationInsertion,
    AuthorityRevocationStore,
    AuthorityRevocationVerificationResult,
)
from .verify import verify_authority_revocation

__all__ = [
    "AUTHORITY_REVOCATION_RECORD_TYPE",
    "AUTHORITY_REVOCATION_VERSION",
    "AUTHORITY_REVOCATION_FAILURE_CODES",
    "AuthorityRevocationError",
    "AuthorityRevocationFailure",
    "AuthorityRevocationVerificationResult",
    "AuthorityRevocationInsertion",
    "AuthorityRevocationStore",
    "AuthorityRevocationRecordResult",
    "validate_authority_revocation_shape",
    "is_authority_revocation_v1",
    "AUTHORITY_REVOCATION_ID_DOMAIN",
    "AUTHORITY_REVOCATION_SIGNATURE_DOMAIN",
    "AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN",
    "authority_revocation_cascade_transaction_input",
    "authority_revocation_id_input",
    "authority_revocation_signature_input",
    "compute_authority_revocation_cascade_transaction_id",
    "compute_authority_revocation_cascade_transaction_id_for_write",
    "compute_authority_revocation_id",
    "compute_authority_revocation_id_for_write",
    "sign_authority_revocation",
    "verify_authority_revocation_signature",
    "authority_revocation_body",
    "authority_revocation_cascade_origin",
    "issue_authority_revocation",
    "verify_authority_revocation",
    "InMemoryAuthorityRevocationStore",
    "record_authority_revocation",
    "create_authority_revocation_resolver",
]
