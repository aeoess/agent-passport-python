# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""AuthorityDelegationV1, the draft-pidlisnyi-aps-03 delegated authority record (sections 3.1 to 3.4 and 3.6).

This is a port of the TypeScript SDK's src/v2/authority-delegation package,
following it file by file: the scope grant grammar, the seven-facet
parent/child attenuation comparison, content addressing and Ed25519 signing,
chain verification, strict wire parsing, and the in-memory budget ledger.

It is distinct from the legacy agent_passport.delegation module, which is a
pre-draft compatibility surface and is not the draft-03 record described here.

Both SDKs' child issuers verify the parent before signing: its shape and
delegation_id, its signature through the caller's key resolver, its validity
at the caller's `now`, and a revocation status of exactly "active" (draft
section 3.6).

Both SDKs also refuse to issue from a body that already carries its own
delegation_id or signature member, of any value, before doing anything else
with that body. Draft section 3.1 (lines 484-490) computes delegation_id and
signature from a body without those two members, so such a body would yield
a record whose delegation_id does not recompute from itself; section 3.6
(lines 695-704) enforces signature integrity at issuance and says an issuer
does not leave an invalidity for a later verifier to discover (issue.py).

Points that are deliberately different in behaviour from the TypeScript SDK,
each documented at the function it affects:
- the order chain verification decides between several simultaneous faults
  (verify.py);
- a missing nonce on an issuing body is filled in with 16 random bytes
  rather than required (issue.py);
- every integer in the record is a Python int and nothing else: a float or a
  bool value where the schema calls for an integer is rejected; the
  TypeScript SDK also rejects a bool there, but cannot tell an
  integer-valued float such as 80.0 apart from an integer (schema.py);
- every object, array and string in the record is required to be exactly a
  Python dict, list or str: a Mapping or Sequence subclass such as
  collections.OrderedDict, which the TypeScript SDK's structural typing
  cannot distinguish from a plain object, is rejected here (schema.py).

Separately, a number of choices are kept identical to the TypeScript SDK in
places where the draft states no rule of its own, each marked provisional at
the point it applies, pending a protocol ruling: the grammar required of a
bounded spend's unit; rejecting a wire number token with a fraction or
exponent even where it denotes an integer; the aps-hierarchical-v1 scope
segment grammar, which is narrower than draft line 516's own requirement
that scope grants use ASCII colon-separated segments; the
aps-values-identifiers-v1 identifier grammar, which is narrower than draft
line 547's own description of a profile-defined identifier; and the limits
of 256 records per chain, 1024 UTF-8 bytes per identifier, and 1 MiB of wire
input, none of which the draft states. record_type, version and facet
profiles are settled, not provisional: a record_type or version that is not
a string is invalid; a record whose record_type names the v1 type and whose
version names some other string is unsupported and is not judged by the v1
body schema at all; a record_type naming some other string is still judged
by the v1 body schema, which is left open; a facet's profile that is missing
or not a string is invalid; and a facet's profile naming an unsupported
string is unsupported without its content being judged by the section 3.2
value rules.
"""

from __future__ import annotations

from .budget import InMemoryAuthorityBudgetLedger
from .canonical import (
    AUTHORITY_DELEGATION_ID_DOMAIN,
    AUTHORITY_DELEGATION_SIGNATURE_DOMAIN,
    authority_delegation_body,
    authority_delegation_id_input,
    authority_delegation_id_input_for_write,
    authority_delegation_signature_input,
    compute_authority_delegation_id,
    compute_authority_delegation_id_for_write,
    sign_authority_delegation,
    verify_authority_delegation_signature,
)
from .compare import compare_authority
from .issue import issue_authority_delegation, issue_sub_authority_delegation
from .parse import parse_authority_delegation_json
from .schema import (
    compare_canonical_timestamps,
    is_authority_delegation_v1,
    is_canonical_quantity,
    is_canonical_timestamp,
    validate_authority_delegation_shape,
)
from .scope import grants_are_canonical, is_valid_scope_grant, scope_grant_covers, scope_narrows
from .types import (
    AUTHORITY_DELEGATION_RECORD_TYPE,
    AUTHORITY_DELEGATION_VERSION,
    REPUTATION_PROFILE_V1,
    REVERSIBILITY_PROFILE_V1,
    SCOPE_PROFILE_V1,
    VALUES_PROFILE_V1,
    AuthorityDelegationError,
    AuthorityFailure,
    AuthorityValidationResult,
    BudgetOperationResult,
)
from .verify import verify_authority_delegation, verify_authority_delegation_chain

__all__ = [
    "AUTHORITY_DELEGATION_RECORD_TYPE",
    "AUTHORITY_DELEGATION_VERSION",
    "SCOPE_PROFILE_V1",
    "REPUTATION_PROFILE_V1",
    "VALUES_PROFILE_V1",
    "REVERSIBILITY_PROFILE_V1",
    "AuthorityFailure",
    "AuthorityValidationResult",
    "BudgetOperationResult",
    "AuthorityDelegationError",
    "is_canonical_timestamp",
    "compare_canonical_timestamps",
    "is_canonical_quantity",
    "validate_authority_delegation_shape",
    "is_authority_delegation_v1",
    "is_valid_scope_grant",
    "scope_grant_covers",
    "grants_are_canonical",
    "scope_narrows",
    "AUTHORITY_DELEGATION_ID_DOMAIN",
    "AUTHORITY_DELEGATION_SIGNATURE_DOMAIN",
    "authority_delegation_id_input",
    "authority_delegation_id_input_for_write",
    "compute_authority_delegation_id",
    "compute_authority_delegation_id_for_write",
    "authority_delegation_signature_input",
    "sign_authority_delegation",
    "verify_authority_delegation_signature",
    "authority_delegation_body",
    "compare_authority",
    "issue_authority_delegation",
    "issue_sub_authority_delegation",
    "parse_authority_delegation_json",
    "verify_authority_delegation_chain",
    "verify_authority_delegation",
    "InMemoryAuthorityBudgetLedger",
]
