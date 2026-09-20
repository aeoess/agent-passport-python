# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Full root-to-leaf chain verification.

Python port of the TypeScript SDK's src/v2/authority-delegation/verify.ts. Both SDKs
run the phase order below; see the docstring of
verify_authority_delegation_chain.

There is no wall clock anywhere in this module: ``now`` is a required
keyword-only argument supplied by the caller.
"""

from __future__ import annotations

import copy

import dataclasses
import re

from .canonical import authority_delegation_body, compute_authority_delegation_id, verify_authority_delegation_signature
from .compare import compare_authority
from .schema import is_canonical_timestamp, validate_authority_delegation_shape
from .types import AuthorityFailure, AuthorityValidationResult, KEY_RESOLUTION_OUTCOME_CODES


def _result(state: str, failures: tuple[AuthorityFailure, ...]) -> AuthorityValidationResult:
    return AuthorityValidationResult(state=state, failures=tuple(failures))


def _indexed(failure: AuthorityFailure, index: int) -> AuthorityFailure:
    return dataclasses.replace(failure, index=index)


# A conformance failure (any code that is neither an unsupported code nor
# RESOURCE_LIMIT) dominates: it is a statement about the record, where the other two
# are statements about what could be evaluated. Between the remaining two, an
# unsupported code dominates RESOURCE_LIMIT, because a record this schema does not
# claim was never going to be judged by it whatever ceiling it also crossed. The draft
# orders none of this: it is fail-closed precedence inside one phase.
_UNSUPPORTED_CODES = frozenset({"UNSUPPORTED_VERSION", "UNSUPPORTED_RECORD_TYPE", "UNSUPPORTED_PROFILE"})


def _shape_state(failures) -> str:
    """The state a set of shape failures on one member produces.

    RESOURCE_LIMIT (the byte cap on issuer, subject and verification_method) means
    this implementation declined to judge the record, not that the record is bad, so
    it is mapped to "indeterminate" rather than "invalid" unless some other failure on
    the same member is a genuine conformance failure.
    """
    if any(item.code not in _UNSUPPORTED_CODES and item.code != "RESOURCE_LIMIT" for item in failures):
        return "invalid"
    if any(item.code in _UNSUPPORTED_CODES for item in failures):
        return "unsupported"
    return "indeterminate"


# Well-formed Ed25519 public key material: 32 bytes as hexadecimal. A resolver that
# hands back anything else has produced structurally malformed material, and the
# signature check must not run on it: reporting SIGNATURE_INVALID there would say the
# bytes were checked and failed when nothing was checked at all. Case is not narrowed
# here, because the verifier accepted either case before this rule and the change is
# about which outcome is reported, not about which keys resolve.
_KEY_MATERIAL = re.compile(r"^[0-9a-fA-F]{64}$")

_KEY_OUTCOME_MESSAGES: dict[str, str] = {
    "KEY_SCHEME_UNSUPPORTED": "identifier scheme is not supported by the resolver",
    "KEY_NOT_FOUND": "subject or key was not found",
    "KEY_AMBIGUOUS": "key resolution was ambiguous",
    "KEY_UNREACHABLE": "key material was unreachable",
    "KEY_MATERIAL_MALFORMED": "resolved key material is structurally malformed",
}


def _key_resolution_failure(resolved):
    """Map a resolver's answer to the draft's section 2.5 outcomes, or None when it
    resolved to usable key material. Returns (state, code, message).

    An unsupported identifier scheme is unsupported; everything else that is not a
    usable key is indeterminate, each under its own code. A resolved string that does
    not match _KEY_MATERIAL is structurally malformed and must not reach the signature
    check (see _KEY_MATERIAL above); a well-formed key that did not sign the record is
    still reported by the caller as SIGNATURE_INVALID, since that check did run.
    """
    if type(resolved) is str:
        if _KEY_MATERIAL.fullmatch(resolved):
            return None
        return (
            "indeterminate", "KEY_MATERIAL_MALFORMED",
            "resolved key material is not a 32-byte Ed25519 public key",
        )
    if type(resolved) is dict:
        outcome = resolved.get("outcome")
        code = KEY_RESOLUTION_OUTCOME_CODES.get(outcome) if type(outcome) is str else None
        if code is not None:
            state = "unsupported" if outcome == "unsupported_scheme" else "indeterminate"
            return (state, code, _KEY_OUTCOME_MESSAGES[code])
    return ("indeterminate", "KEY_RESOLUTION_FAILED", "issuer verification key could not be resolved")


def _read_chain_container(chain, min_length: int, max_length: int):
    """Read chain as a container, telling "not a usable chain at all" apart from
    "longer than this implementation's own ceiling" without a second, separate read
    of chain's raw type or length outside this function, since chain may be hostile.

    Returns (container, reason): reason is None when container is chain itself (a
    list or tuple of length between min_length and max_length inclusive); otherwise
    container is None and reason is "not-a-container" or "over-ceiling", mirroring the
    TypeScript SDK's readPlainDataChainContainer() rejection reason.
    """
    # Two identity tests rather than ``type(chain) not in (list, tuple)``: a tuple
    # membership test compares with ==, which runs a hostile metaclass's own __eq__,
    # while ``is`` never runs caller code.
    if type(chain) is not list and type(chain) is not tuple:
        return None, "not-a-container"
    length = len(chain)
    if length > max_length:
        return None, "over-ceiling"
    if length < min_length:
        return None, "not-a-container"
    return chain, None


def verify_authority_delegation_chain(
    chain,
    *,
    now: str,
    resolve_verification_key,
    trust_root,
    resolve_revocation,
) -> AuthorityValidationResult:
    """Full root-to-leaf structural, cryptographic, temporal and revocation validation.

    Draft section 3.3 gives an order of checks: closed schema and canonical values;
    delegation_id; historical signing-key resolution and signature; duplicate
    identifiers; root trust; parent_delegation_id (the root's null-parent check
    belongs here, after root trust); issuer-to-subject continuity; child issuance
    time; the seven facet comparisons; current validity; and revocation state for
    every member. This order is the ruled behaviour, not one reading among others: this
    function runs it phase by phase over the whole chain, every record checked against
    phase K before any record is checked against phase K+1, and the first failing
    phase, at its lowest failing record index, decides the result. Phase 1 (shape): the
    first record with shape failures returns all of them, indexed; the state follows
    _shape_state (a conformance code makes it "invalid"; otherwise an unsupported code
    makes it "unsupported"; otherwise, if the only codes present are RESOURCE_LIMIT,
    it is "indeterminate"). Phase 9 (facets) returns every attenuation failure of the
    first failing child; "unsupported" if every one of those codes is
    UNSUPPORTED_PROFILE, else "invalid".

    The TypeScript SDK previously interleaved several of these checks within a single
    per-record loop instead (in particular: duplicate-identifier detection ran together
    with delegation_id and signature checking, before this phase order's root-trust and
    parent-linkage phases); it has since been changed to run the same phase-by-phase
    order this function does, so both SDKs now agree on which failure decides a chain
    that carries several faults at once, not only one with a single fault. A trust or
    revocation resolver that is unavailable (not callable, raising, or returning
    something other than the bool or the "active"/"revoked" string it is asked for) is
    a fault of its own, in the same sense a malformed record is, and can combine with
    an unrelated fault elsewhere in the chain the same way two record faults can.

    ``trust_root`` and ``resolve_revocation`` are each handed a deep copy of
    the record, made after phase 1 has validated it, and every phase from
    there on reads this function's own copy of the chain rather than the
    caller's dicts. ``trust_root`` is given a copy because the phases after
    it read that record again: a callback that wrote to what it was given
    would otherwise change what the linkage, continuity, issuance-time,
    attenuation, validity and revocation checks see, and a chain that widens
    its parent's authority would verify valid. ``resolve_revocation`` is
    given a copy for the same reason rather than from the same need: it runs
    in the last phase, after every other check of that member, so a write
    there changes nothing this function still reads. The child issuer is
    where a revocation callback's write does reach later checks, and it
    copies too (see issue.py). What a callback does to its
    own copy changes nothing here, and neither does a caller writing to its
    own dicts once this function has copied them. The TypeScript SDK gives
    its callbacks a copy for the same reason. A callback that compares its
    argument by identity against a record the caller already holds therefore
    fails in both SDKs; the draft says nothing about what a verifier hands a
    caller-supplied callback.
    """
    # The draft states no maximum chain length. This 256-record limit is this
    # implementation's own ceiling, not a protocol rule: a chain that crosses it is one
    # this implementation declines to judge, reported as RESOURCE_LIMIT and
    # indeterminate, never as a protocol failure. A chain that is not a usable
    # container at all is a different answer: invalid, with SCHEMA_INVALID, since
    # there is nothing to verify. _read_chain_container tells the two apart without
    # this function inspecting chain's own type or length again outside it.
    container, reason = _read_chain_container(chain, 1, 256)
    if container is None:
        if reason == "over-ceiling":
            return _result(
                "indeterminate",
                (AuthorityFailure(
                    code="RESOURCE_LIMIT", message="chain exceeds this implementation's 256-record ceiling",
                ),),
            )
        return _result(
            "invalid", (AuthorityFailure(code="SCHEMA_INVALID", message="chain must contain 1 through 256 records"),)
        )
    chain = container
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
            return _result(_shape_state(failures), failures)

    # Every record has now passed the shape check, so each one is a plain JSON
    # value of exact types and bounded depth: copying it runs no caller code.
    # Every phase below reads this copy, so nothing a callback or the caller
    # does to a dict of its own changes what the remaining phases see.
    chain = [copy.deepcopy(chain[i]) for i in range(n)]

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

    # Phase 3: historical signing-key resolution, then the signature it resolves. The
    # resolver is called with the record's own issued_at, which is what selects the
    # key version: a key current at verification time is not the one that signed this
    # record (draft lines 313-315 and 353-357).
    for i in range(n):
        delegation = chain[i]
        try:
            resolved = resolve_verification_key(
                delegation["issuer"], delegation["verification_method"], delegation["issued_at"]
            )
        except Exception:
            resolved = None
        failure = _key_resolution_failure(resolved)
        if failure is not None:
            state, code, message = failure
            return _result(state, (AuthorityFailure(code=code, message=message, index=i),))
        if not verify_authority_delegation_signature(delegation, resolved):
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
        trust_decision = trust_root(copy.deepcopy(root))
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
            resolved = resolve_revocation(copy.deepcopy(delegation))
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
