# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Closed-schema and canonical-value validation for a decoded revocation.

Python port of the TypeScript SDK's src/v2/authority-revocation/schema.ts.

Every JSON type test below is exact (``type(v) is str``, ``type(v) is dict``)
rather than ``isinstance``, the same rule the authority_delegation port applies:
a ``str`` subclass, an ``OrderedDict`` or any other object that merely resembles
plain JSON data is not the value RFC 8785 JCS canonicalizes and Ed25519 signs,
so it is rejected wherever it appears.

That exactness is also what stands in for the TypeScript SDK's
``snapshotPlainData()``. There, a getter or a Proxy trap in the caller's
argument could answer the schema's read one way and the hashing read another,
so the record is snapshotted to plain data before it is judged. A Python
``dict`` runs no code on member access, and every member of this record is a
plain ``str``, so once ``type(top) is dict`` holds and each member is exactly a
``str``, a second read cannot differ from the first. Nothing is snapshotted
here; see record.py for the one place the port does copy, and why.
"""

from __future__ import annotations

import re

from ..authority_delegation.schema import is_canonical_timestamp
from .types import (
    AUTHORITY_REVOCATION_RECORD_TYPE,
    AUTHORITY_REVOCATION_VERSION,
    AuthorityRevocationFailure,
)

_CONTENT_ADDRESS = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_128 = re.compile(r"^[0-9a-f]{128}$")

# Every member a valid record may carry. A member outside this list is
# SCHEMA_INVALID: the schema is closed, so an unknown field cannot ride inside a
# signed preimage unnoticed. `detail` is the only OPTIONAL one.
REQUIRED_KEYS: tuple[str, ...] = (
    "record_type",
    "version",
    "revocation_id",
    "delegation_id",
    "revoker",
    "verification_method",
    "revoked_at",
    "reason_code",
    "cascade_transaction_id",
    "nonce",
    "signature",
)
OPTIONAL_KEYS: tuple[str, ...] = ("detail",)

_ALLOWED_KEYS = frozenset(REQUIRED_KEYS + OPTIONAL_KEYS)


def _failure(code: str, message: str) -> AuthorityRevocationFailure:
    return AuthorityRevocationFailure(code=code, message=message)


def _is_content_address(value) -> bool:
    return type(value) is str and bool(_CONTENT_ADDRESS.fullmatch(value))


def _is_non_empty_str(value) -> bool:
    return type(value) is str and len(value) > 0


def validate_authority_revocation_shape(value) -> tuple[AuthorityRevocationFailure, ...]:
    """Closed-schema and canonical-value validation for a decoded revocation.

    Returns every failure it finds rather than the first, matching
    validate_authority_delegation_shape(). The caller decides which one it
    reports.
    """
    if type(value) is not dict:
        return (_failure("SCHEMA_INVALID", "revocation must be a JSON object"),)
    top = value

    # Key-type pre-walk, before any member is looked up. A dict built directly
    # in Python, as opposed to one decoded from JSON, can carry a key that is
    # not a str, and a dict lookup compares the stored key with ==, which would
    # run that object's own __eq__ during the record_type and version reads
    # below. Iterating the keys and testing their type runs no caller code.
    # Reported alone, with no UNSUPPORTED_RECORD_TYPE or UNSUPPORTED_VERSION
    # after it, the same precedence validate_authority_delegation_shape applies.
    # The TypeScript SDK reaches the same place by a different route: a
    # JavaScript object key is always a string, and its snapshotPlainData() is
    # what stops a getter from answering two reads differently.
    for key in top:
        if type(key) is not str:
            return (_failure("SCHEMA_INVALID", "every member name must be a string"),)

    # record_type and version stop the walk before the body is judged at all: a
    # record this schema does not claim was never going to be judged by it.
    if top.get("record_type") != AUTHORITY_REVOCATION_RECORD_TYPE:
        return (
            _failure(
                "UNSUPPORTED_RECORD_TYPE",
                f"record_type must be {AUTHORITY_REVOCATION_RECORD_TYPE}",
            ),
        )
    if top.get("version") != AUTHORITY_REVOCATION_VERSION:
        return (
            _failure("UNSUPPORTED_VERSION", f"version must be {AUTHORITY_REVOCATION_VERSION}"),
        )

    failures: list[AuthorityRevocationFailure] = []

    for key in REQUIRED_KEYS:
        if key not in top:
            failures.append(_failure("SCHEMA_INVALID", f"{key} is required"))
    for key in top:
        if key not in _ALLOWED_KEYS:
            failures.append(_failure("SCHEMA_INVALID", f"unknown member {key!s}"))

    if not _is_content_address(top.get("revocation_id")):
        failures.append(_failure("SCHEMA_INVALID", "revocation_id must be sha256:<64 lowercase hex>"))
    if not _is_content_address(top.get("delegation_id")):
        failures.append(_failure("SCHEMA_INVALID", "delegation_id must be sha256:<64 lowercase hex>"))
    if not _is_content_address(top.get("cascade_transaction_id")):
        failures.append(
            _failure("SCHEMA_INVALID", "cascade_transaction_id must be sha256:<64 lowercase hex>")
        )
    if not _is_non_empty_str(top.get("revoker")):
        failures.append(_failure("SCHEMA_INVALID", "revoker must be a non-empty string"))
    # Nothing here judges whether the method belongs to the revoker. That is
    # decided only by key resolution against the target delegation's `issuer` at
    # `revoked_at`, which verify_authority_revocation() performs; a local string
    # shape cannot establish it, and a method identifier need not be a fragment
    # of the identifier that controls it.
    if not _is_non_empty_str(top.get("verification_method")):
        failures.append(_failure("SCHEMA_INVALID", "verification_method must be a non-empty string"))
    if not is_canonical_timestamp(top.get("revoked_at")):
        failures.append(
            _failure("NONCANONICAL_VALUE", "revoked_at must be a canonical UTC-millisecond timestamp")
        )
    # The draft names a machine-readable reason code and fixes no grammar for
    # one, so no grammar is invented here.
    if not _is_non_empty_str(top.get("reason_code")):
        failures.append(_failure("SCHEMA_INVALID", "reason_code must be a non-empty string"))
    if "detail" in top and type(top["detail"]) is not str:
        failures.append(_failure("SCHEMA_INVALID", "detail, when present, must be a string"))
    nonce = top.get("nonce")
    if not (type(nonce) is str and _HEX_32.fullmatch(nonce)):
        failures.append(_failure("NONCANONICAL_VALUE", "nonce must be 32 lowercase hex characters"))
    signature = top.get("signature")
    if not (type(signature) is str and _HEX_128.fullmatch(signature)):
        failures.append(_failure("SCHEMA_INVALID", "signature must be 128 lowercase hex characters"))
    return tuple(failures)


def is_authority_revocation_v1(value) -> bool:
    return len(validate_authority_revocation_shape(value)) == 0
