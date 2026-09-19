# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Native action reference v2 (draft-pidlisnyi-aps-03 section 4.1, profile
``aps-action-ref-v2``).

Mirrors the behaviours in tests/action-reference-v2.test.ts in the TypeScript
SDK: determinism, field binding, NFC/sort canonicalization on the create
path, strict duplicate-member rejection on the serialized-JSON path, and the
section-4.1 type-coercion rejection (a non-string payload_ref/issued_at/nonce
is refused before the format check, never coerced with something like
JavaScript's ``String()``). Also one test per ActionReferenceError.code.
"""

import json
import re

import pytest

from agent_passport import (
    ACTION_REF_V2_PROFILE,
    ActionReferenceError,
    compute_action_ref_v2,
    compute_action_ref_v2_from_json,
    compute_payload_ref_v1,
    create_action_reference_input_v2,
    parse_action_reference_input_v2,
    validate_action_reference_input_v2,
)


def _base() -> dict:
    return {
        "profile": ACTION_REF_V2_PROFILE,
        "agent_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "action_type": "commerce_preflight",
        "target": "https://api.example/payments",
        "payload_ref": compute_payload_ref_v1(
            {"amount": "5000", "currency": "USD", "merchant": "example"}
        ),
        "scope_required": ["commerce:read", "commerce:write"],
        "issued_at": "2026-04-08T12:00:00.000Z",
        "nonce": "00112233445566778899aabbccddeeff",
    }


def _expect_code(candidate, code: str) -> None:
    with pytest.raises(ActionReferenceError) as exc_info:
        validate_action_reference_input_v2(candidate)
    assert exc_info.value.code == code


# ── Determinism and field binding ──────────────────────────────────────────


def test_is_deterministic_and_domain_shaped():
    ref = compute_action_ref_v2(_base())
    assert re.fullmatch(r"[0-9a-f]{64}", ref)
    assert compute_action_ref_v2(_base()) == ref


def test_target_changes_the_digest():
    other = _base()
    other["target"] = "https://api.example/refunds"
    assert compute_action_ref_v2(_base()) != compute_action_ref_v2(other)


def test_payload_ref_changes_the_digest():
    other = _base()
    other["payload_ref"] = compute_payload_ref_v1({"cart": ["sku-1"]})
    assert compute_action_ref_v2(_base()) != compute_action_ref_v2(other)


def test_nonce_changes_the_digest():
    other = _base()
    other["nonce"] = "ffeeddccbbaa99887766554433221100"
    assert compute_action_ref_v2(_base()) != compute_action_ref_v2(other)


# ── create_action_reference_input_v2: NFC-normalize and sort ───────────────


def test_create_normalizes_and_sorts_scopes_so_two_spellings_agree():
    base = _base()
    common = dict(
        agent_id=base["agent_id"],
        action_type=base["action_type"],
        target=base["target"],
        payload_ref=base["payload_ref"],
        issued_at=base["issued_at"],
        nonce=base["nonce"],
    )
    decomposed_first = create_action_reference_input_v2(
        **common, scope_required=["repo:write", "café:read"]
    )
    precomposed_first = create_action_reference_input_v2(
        **common, scope_required=["café:read", "repo:write"]
    )
    assert decomposed_first["scope_required"] == ["café:read", "repo:write"]
    assert compute_action_ref_v2(decomposed_first) == compute_action_ref_v2(
        precomposed_first
    )


def test_create_rejects_a_duplicate_surviving_nfc_normalization():
    base = _base()
    with pytest.raises(ActionReferenceError) as exc_info:
        create_action_reference_input_v2(
            agent_id=base["agent_id"],
            action_type=base["action_type"],
            target=base["target"],
            payload_ref=base["payload_ref"],
            issued_at=base["issued_at"],
            nonce=base["nonce"],
            scope_required=["café:read", "café:read"],
        )
    assert exc_info.value.code == "scope_not_canonical"


# ── Serialized-JSON path: strict duplicate-member parsing ──────────────────


def test_json_path_rejects_a_duplicated_member_name():
    doc = _base()
    clean = json.dumps(doc)
    marker = f'"agent_id": "{doc["agent_id"]}"'
    assert marker in clean
    with_duplicate = clean.replace(
        marker, marker + ', "agent_id": "did:example:attacker"'
    )
    assert with_duplicate != clean
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(with_duplicate)
    assert exc_info.value.code == "duplicate_member"


def test_json_path_rejects_an_escape_aliased_duplicate():
    doc = _base()
    clean = json.dumps(doc)
    marker = f'"agent_id": "{doc["agent_id"]}"'
    # The second occurrence reaches the same name "agent_id" through a a
    # escape rather than a literal repeat, so this is rejected only if names
    # are compared AFTER decoding.
    with_escaped_duplicate = clean.replace(
        marker, marker + ', "\\u0061gent_id": "did:example:attacker"'
    )
    assert with_escaped_duplicate != clean
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(with_escaped_duplicate)
    assert exc_info.value.code == "duplicate_member"


def test_json_path_accepts_the_same_document_without_the_duplicate():
    doc = _base()
    clean = json.dumps(doc)
    parsed = parse_action_reference_input_v2(clean)
    assert parsed["agent_id"] == doc["agent_id"]
    assert compute_action_ref_v2_from_json(clean) == compute_action_ref_v2(parsed)


def test_json_path_rejects_wrong_profile():
    doc = _base()
    clean = json.dumps(doc)
    wrong_profile = clean.replace('"aps-action-ref-v2"', '"aps-action-ref-v1"')
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(wrong_profile)
    assert exc_info.value.code == "wrong_profile"


def test_json_path_rejects_a_bad_nonce():
    doc = _base()
    clean = json.dumps(doc)
    bad_nonce = clean.replace(doc["nonce"], "zz" * 16)
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(bad_nonce)
    assert exc_info.value.code == "bad_hex"


def test_json_path_rejects_an_extra_key():
    doc = _base()
    clean = json.dumps(doc)
    extra_key = clean.replace('"profile":', '"unexpected": 1, "profile":', 1)
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(extra_key)
    assert exc_info.value.code == "unknown_member"


# ── Section 4.1 type-coercion rejection: no String() coercion ──────────────


def test_rejects_array_wrapped_payload_ref_as_not_string():
    doc = _base()
    doc["payload_ref"] = [doc["payload_ref"]]
    _expect_code(doc, "not_string")


def test_rejects_array_wrapped_issued_at_as_not_string():
    doc = _base()
    doc["issued_at"] = [doc["issued_at"]]
    _expect_code(doc, "not_string")


def test_rejects_array_wrapped_nonce_as_not_string():
    doc = _base()
    doc["nonce"] = [doc["nonce"]]
    _expect_code(doc, "not_string")


def test_rejects_nested_array_wrapped_payload_ref_as_not_string():
    doc = _base()
    doc["payload_ref"] = [[doc["payload_ref"]]]
    _expect_code(doc, "not_string")


# ── One test per ActionReferenceError.code ──────────────────────────────────


def test_not_object():
    _expect_code([_base()], "not_object")
    _expect_code(None, "not_object")


def test_missing_member():
    doc = _base()
    del doc["nonce"]
    _expect_code(doc, "missing_member")


def test_unknown_member():
    doc = _base()
    doc["extra"] = "x"
    _expect_code(doc, "unknown_member")


def test_duplicate_member():
    # duplicate_member can only be observed on the serialized-JSON path: by
    # the time raw JSON has become a dict, a duplicate member has already
    # overwritten the first occurrence and the evidence is gone.
    doc = _base()
    clean = json.dumps(doc)
    marker = f'"nonce": "{doc["nonce"]}"'
    with_duplicate = clean.replace(marker, marker + ', "nonce": "' + "1" * 32 + '"')
    with pytest.raises(ActionReferenceError) as exc_info:
        parse_action_reference_input_v2(with_duplicate)
    assert exc_info.value.code == "duplicate_member"


def test_wrong_profile():
    doc = _base()
    doc["profile"] = "aps-action-ref-v1"
    _expect_code(doc, "wrong_profile")


def test_not_string():
    doc = _base()
    doc["agent_id"] = 123
    _expect_code(doc, "not_string")


def test_empty_string():
    doc = _base()
    doc["target"] = ""
    _expect_code(doc, "empty_string")


def test_bad_hex():
    doc = _base()
    doc["payload_ref"] = doc["payload_ref"].upper()
    _expect_code(doc, "bad_hex")
    doc2 = _base()
    doc2["nonce"] = "0" * 31
    _expect_code(doc2, "bad_hex")


def test_bad_timestamp():
    doc = _base()
    doc["issued_at"] = "2026-04-08T12:00:00Z"
    _expect_code(doc, "bad_timestamp")


def test_scope_not_array():
    doc = _base()
    doc["scope_required"] = "commerce:write"
    _expect_code(doc, "scope_not_array")


def test_scope_not_canonical_out_of_order():
    doc = _base()
    doc["scope_required"] = ["commerce:write", "commerce:read"]
    _expect_code(doc, "scope_not_canonical")


def test_scope_not_canonical_duplicate():
    doc = _base()
    doc["scope_required"] = ["commerce:read", "commerce:read"]
    _expect_code(doc, "scope_not_canonical")


def test_scope_not_canonical_not_nfc():
    doc = _base()
    doc["scope_required"] = ["café:read"]
    _expect_code(doc, "scope_not_canonical")


def test_lone_surrogate():
    doc = _base()
    doc["agent_id"] = "did:example:\ud800"
    _expect_code(doc, "lone_surrogate")


def test_non_i_json():
    doc = _base()
    doc["agent_id"] = 2**60  # exceeds the interoperable IEEE 754 range
    _expect_code(doc, "non_i_json")


def test_empty_scope_required():
    doc = _base()
    doc["scope_required"] = []
    _expect_code(doc, "empty_scope_required")


# ── Cross-language pinned digest ────────────────────────────────────────────


def test_pinned_digest_matches_the_ts_reference():
    # Mirrors "the pinned valid-input digest is unchanged" in
    # tests/action-reference-v2.test.ts (agent-passport-system), produced by
    # the unmodified TypeScript computeActionRefV2 on 2026-09-18. Byte
    # identity here is cross-implementation parity evidence, not proof of
    # protocol correctness on its own.
    value = {
        "profile": ACTION_REF_V2_PROFILE,
        "agent_id": "did:key:z6MkA",
        "action_type": "commerce_preflight",
        "target": "https://api.example/payments",
        "payload_ref": "a" * 64,
        "scope_required": ["commerce:read"],
        "issued_at": "2026-04-08T12:00:00.000Z",
        "nonce": "b" * 32,
    }
    assert (
        compute_action_ref_v2(value)
        == "bf73633f76d1fd2aa81564dbd69d04f6f815d5bb3f27495a480f5984e256a822"
    )


# ── Calendar edge cases: proleptic Gregorian, arithmetic (not datetime) ─────


def test_year_0000_02_29_is_accepted_leap_year():
    doc = _base()
    doc["issued_at"] = "0000-02-29T00:00:00.000Z"
    validate_action_reference_input_v2(doc)  # does not raise


def test_2027_02_29_is_rejected_not_a_leap_year():
    doc = _base()
    doc["issued_at"] = "2027-02-29T00:00:00.000Z"
    _expect_code(doc, "bad_timestamp")


def test_2028_02_29_is_accepted_leap_year():
    doc = _base()
    doc["issued_at"] = "2028-02-29T00:00:00.000Z"
    validate_action_reference_input_v2(doc)  # does not raise


def test_2000_02_29_is_accepted_leap_year_divisible_by_400():
    doc = _base()
    doc["issued_at"] = "2000-02-29T00:00:00.000Z"
    validate_action_reference_input_v2(doc)  # does not raise


# Create-path input shape (orchestrator review, job 2 batch 2)


def _create_kwargs() -> dict:
    doc = _base()
    return {key: doc[key] for key in ("agent_id", "action_type", "target", "payload_ref", "issued_at", "nonce")}


def test_create_rejects_a_string_scope_required_instead_of_reading_its_characters():
    # "ab" is iterable in Python; it must not become the two scopes ["a", "b"].
    with pytest.raises(ActionReferenceError) as exc_info:
        create_action_reference_input_v2(scope_required="ab", **_create_kwargs())
    assert exc_info.value.code == "scope_not_array"


def test_create_rejects_a_lone_surrogate_scope_with_the_module_error():
    with pytest.raises(ActionReferenceError) as exc_info:
        create_action_reference_input_v2(scope_required=["\ud800:x"], **_create_kwargs())
    assert exc_info.value.code == "lone_surrogate"


def test_create_accepts_a_tuple_of_scopes():
    value = create_action_reference_input_v2(scope_required=("repo:write", "commerce:read"), **_create_kwargs())
    assert value["scope_required"] == ["commerce:read", "repo:write"]
