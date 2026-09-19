# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""AuthorityDelegationV1, the draft-pidlisnyi-aps-03 delegated authority record (sections 3.1 to 3.4 and 3.6).

This is a port of the TypeScript SDK's src/v2/authority-delegation package: the
same closed wire schema, the same scope grant grammar, the same seven-facet
parent/child attenuation comparison, the same content addressing and Ed25519
signing, the same chain verification checks, and the same in-memory budget
ledger, expressed in Python.

It is distinct from the legacy agent_passport.delegation module, which is a
pre-draft compatibility surface and is not the draft-03 record described here.

A few points are deliberately different from the TypeScript SDK, each
documented at the function it affects: the order chain verification decides
between several simultaneous faults (verify.py), what a child issuer checks
about its parent before signing (issue.py), how a missing nonce is filled in
(issue.py), and a small number of schema edge cases kept identical to the
TypeScript SDK and marked provisional where the draft itself does not settle
them (schema.py).
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
