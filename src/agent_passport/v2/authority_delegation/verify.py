# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Full root-to-leaf chain verification.

Python port of the TypeScript SDK's src/v2/authority-delegation/verify.ts,
restructured into the phase order below (a deliberate difference from the
TypeScript source's control flow; see the docstring of
verify_authority_delegation_chain).

There is no wall clock anywhere in this module: ``now`` is a required
keyword-only argument supplied by the caller.
"""

from __future__ import annotations

import dataclasses

from .canonical import authority_delegation_body, compute_authority_delegation_id, verify_authority_delegation_signature
from .compare import compare_authority
from .schema import is_canonical_timestamp, validate_authority_delegation_shape
from .types import AuthorityFailure, AuthorityValidationResult


def _result(state: str, failures: tuple[AuthorityFailure, ...]) -> AuthorityValidationResult:
    return AuthorityValidationResult(state=state, failures=tuple(failures))


def _indexed(failure: AuthorityFailure, index: int) -> AuthorityFailure:
    return dataclasses.replace(failure, index=index)


def verify_authority_delegation_chain(
    chain,
    *,
    now: str,
    resolve_verification_key,
    trust_root,
    resolve_revocation,
) -> AuthorityValidationResult:
    """Full root-to-leaf structural, cryptographic, temporal and revocation validation.

    Deliberate difference from the TypeScript SDK: draft section 3.3 gives an
    order of checks: closed schema and canonical values; delegation_id;
    historical signing-key resolution and signature; duplicate identifiers;
    root trust; parent_delegation_id (the root's null-parent check belongs
    here, after root trust); issuer-to-subject continuity; child issuance
    time; the seven facet comparisons; current validity; and revocation state
    for every member. This function runs that order phase by phase over the
    whole chain: every record is checked against phase K before any record is
    checked against phase K+1, and the first failing phase, at its lowest
    failing record index, decides the result. Phase 1 (shape): the first
    record with shape failures returns all of them, indexed; the state is
    "unsupported" if every one of its codes is UNSUPPORTED_VERSION or
    UNSUPPORTED_PROFILE, else "invalid". Phase 9 (facets) returns every
    attenuation failure of the first failing child; "unsupported" if every
    one of those codes is UNSUPPORTED_PROFILE, else "invalid".

    The TypeScript SDK instead interleaves several of these checks within a
    single per-record loop (in particular: duplicate-identifier detection
    runs together with delegation_id and signature checking, before this
    phase order's root-trust and parent-linkage phases). For a chain with a
    single fault, both orders reach the same result, but only when the
    resolvers themselves answer consistently and that fault is the only one
    in the chain: a trust or revocation resolver that is unavailable (not
    callable, raising, or returning something other than the bool or the
    "active"/"revoked" string it is asked for) is a fault of its own, in the
    same sense a malformed record is, and can combine with an unrelated
    fault elsewhere in the chain the same way two record faults can. The
    draft does not say which failure decides when a chain carries several
    faults at once, so this phase order is a provisional reading of section
    3.3, not a conclusion the draft itself states; a chain with more than
    one fault can therefore get a different failure code from this function
    than from the TypeScript SDK.
    """
    # Provisional: the draft does not state a maximum chain length. This
    # 256-record limit is kept identical to the TypeScript SDK, pending a
    # protocol ruling.
    # Two identity tests rather than ``type(chain) not in (list, tuple)``: a
    # tuple membership test compares with ==, which runs a hostile metaclass's
    # own __eq__, while ``is`` never runs caller code.
    if (type(chain) is not list and type(chain) is not tuple) or not (1 <= len(chain) <= 256):
        return _result(
            "invalid", (AuthorityFailure(code="SCHEMA_INVALID", message="chain must contain 1 through 256 records"),)
        )
    if not is_canonical_timestamp(now):
        return _result(
            "invalid",
            (AuthorityFailure(
                code="NONCANONICAL_VALUE", message="verification clock must be canonical UTC milliseconds",
            ),),
        )

    n = len(chain)

    # Phase 1: closed schema and canonical values, for every record.
    for i in range(n):
        failures = tuple(_indexed(item, i) for item in validate_authority_delegation_shape(chain[i]))
        if failures:
            unsupported = all(item.code in ("UNSUPPORTED_VERSION", "UNSUPPORTED_PROFILE") for item in failures)
            return _result("unsupported" if unsupported else "invalid", failures)

    # Phase 2: delegation_id, for every record.
    for i in range(n):
        delegation = chain[i]
        expected_id = compute_authority_delegation_id(authority_delegation_body(delegation))
        if expected_id != delegation["delegation_id"]:
            return _result(
                "invalid",
                (AuthorityFailure(
                    code="ID_MISMATCH", message="delegation content address does not match body", index=i,
                ),),
            )

    # Phase 3: historical signing-key resolution and signature, for every record.
    for i in range(n):
        delegation = chain[i]
        try:
            public_key = resolve_verification_key(
                delegation["issuer"], delegation["verification_method"], delegation["issued_at"]
            )
        except Exception:
            public_key = None
        if public_key is None:
            return _result(
                "indeterminate",
                (AuthorityFailure(
                    code="KEY_RESOLUTION_FAILED", message="issuer verification key could not be resolved", index=i,
                ),),
            )
        if not verify_authority_delegation_signature(delegation, public_key):
            return _result(
                "invalid",
                (AuthorityFailure(code="SIGNATURE_INVALID", message="Ed25519 signature is invalid", index=i),),
            )

    # Phase 4: duplicate identifiers.
    seen: set[str] = set()
    for i in range(n):
        delegation_id = chain[i]["delegation_id"]
        if delegation_id in seen:
            return _result(
                "invalid",
                (AuthorityFailure(code="CHAIN_DUPLICATE_ID", message="delegation ID repeats in chain", index=i),),
            )
        seen.add(delegation_id)

    # Phase 5: root trust.
    root = chain[0]
    if not callable(trust_root):
        return _result(
            "indeterminate",
            (AuthorityFailure(code="ROOT_UNTRUSTED", message="root trust policy is unavailable", index=0),),
        )
    try:
        trust_decision = trust_root(root)
    except Exception:
        return _result(
            "indeterminate",
            (AuthorityFailure(code="ROOT_UNTRUSTED", message="root trust policy could not decide", index=0),),
        )
    if type(trust_decision) is not bool:
        return _result(
            "indeterminate",
            (AuthorityFailure(
                code="ROOT_UNTRUSTED", message="root trust policy returned no boolean decision", index=0,
            ),),
        )
    if not trust_decision:
        return _result(
            "invalid",
            (AuthorityFailure(
                code="ROOT_UNTRUSTED", message="root is not accepted by verifier trust policy", index=0,
            ),),
        )

    # Phase 6: parent_delegation_id (the root's null-parent check, then child linkage).
    if root["parent_delegation_id"] is not None:
        return _result(
            "invalid",
            (AuthorityFailure(
                code="PARENT_MISMATCH", message="full chain root must carry null parent_delegation_id", index=0,
            ),),
        )
    for i in range(1, n):
        if chain[i]["parent_delegation_id"] != chain[i - 1]["delegation_id"]:
            return _result(
                "invalid",
                (AuthorityFailure(
                    code="PARENT_MISMATCH", message="child does not name immediate parent content address", index=i,
                ),),
            )

    # Phase 7: issuer-to-subject continuity.
    for i in range(1, n):
        if chain[i]["issuer"] != chain[i - 1]["subject"]:
            return _result(
                "invalid",
                (AuthorityFailure(code="CHAIN_CONTINUITY", message="child issuer is not parent subject", index=i),),
            )

    # Phase 8: child issuance time (parent must be valid at the child's issuance instant).
    for i in range(1, n):
        parent_time = chain[i - 1]["authority"]["time"]
        issued_at = chain[i]["issued_at"]
        if issued_at < parent_time["not_before"] or issued_at >= parent_time["not_after"]:
            return _result(
                "invalid",
                (AuthorityFailure(
                    code="ISSUED_AT_OUTSIDE_PARENT", message="child was issued outside parent validity window", index=i,
                ),),
            )

    # Phase 9: the seven facet comparisons.
    for i in range(1, n):
        attenuation_failures = compare_authority(chain[i - 1]["authority"], chain[i]["authority"])
        if attenuation_failures:
            indexed_failures = tuple(_indexed(item, i) for item in attenuation_failures)
            unsupported = all(item.code == "UNSUPPORTED_PROFILE" for item in indexed_failures)
            return _result("unsupported" if unsupported else "invalid", indexed_failures)

    # Phase 10: current validity, for every member.
    for i in range(n):
        time_facet = chain[i]["authority"]["time"]
        if now < time_facet["not_before"]:
            return _result(
                "invalid", (AuthorityFailure(code="NOT_YET_VALID", message="delegation is not yet valid", index=i),)
            )
        if now >= time_facet["not_after"]:
            return _result(
                "invalid", (AuthorityFailure(code="EXPIRED", message="delegation has expired", index=i),)
            )

    # Phase 11: revocation state, for every member.
    for i in range(n):
        delegation = chain[i]
        try:
            resolved = resolve_revocation(delegation)
            # Exact type, not just equality: a str subclass instance that
            # merely compares equal to "active" or "revoked" must not count
            # as one of those two outcomes.
            revocation = resolved if (type(resolved) is str and resolved in ("active", "revoked")) else "unknown"
        except Exception:
            revocation = "unknown"
        if revocation == "revoked":
            return _result(
                "invalid", (AuthorityFailure(code="REVOKED", message="delegation is revoked", index=i),)
            )
        if revocation == "unknown":
            return _result(
                "indeterminate",
                (AuthorityFailure(code="REVOCATION_UNKNOWN", message="revocation status is unknown", index=i),),
            )

    return _result("valid", ())


def verify_authority_delegation(
    delegation,
    *,
    now: str,
    resolve_verification_key,
    trust_root,
    resolve_revocation,
) -> AuthorityValidationResult:
    return verify_authority_delegation_chain(
        [delegation],
        now=now,
        resolve_verification_key=resolve_verification_key,
        trust_root=trust_root,
        resolve_revocation=resolve_revocation,
    )
