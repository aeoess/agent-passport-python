# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""RFC 8785: canonicalize_jcs must reject lone/unpaired UTF-16 surrogates.

A lone surrogate is not a valid Unicode scalar and has no UTF-8 encoding, so the
input is invalid and must be rejected, not escaped or replaced. A valid surrogate
pair (a non-BMP character) must still canonicalize to its raw UTF-8 bytes.
"""

import pytest

from agent_passport.canonical import JCSCanonicalizationError, canonicalize_jcs

HIGH = chr(0xD800)  # lone high surrogate
LOW = chr(0xDFFF)  # lone low surrogate
EMOJI = chr(0x1F600)  # valid non-BMP scalar (U+1F600)


def test_reject_lone_high_surrogate():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"v": HIGH})


def test_reject_lone_low_surrogate():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"v": LOW})


def test_reject_lone_surrogate_after_valid_pair():
    # A valid non-BMP scalar followed by a lone surrogate: detection must not be
    # fooled by the earlier valid character.
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"v": EMOJI + HIGH})


def test_reject_lone_surrogate_in_key():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({HIGH: "x"})


def test_reject_bare_lone_surrogate_string():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs(HIGH)


def test_valid_non_bmp_unchanged():
    # A valid non-BMP character canonicalizes to raw UTF-8, unchanged by this fix.
    assert canonicalize_jcs(EMOJI) == '"' + EMOJI + '"'
    assert canonicalize_jcs({"v": EMOJI}) == '{"v":"' + EMOJI + '"}'
    # The canonical bytes are the raw 4-byte UTF-8 of U+1F600.
    assert canonicalize_jcs({"v": EMOJI}).encode("utf-8") == b'{"v":"\xf0\x9f\x98\x80"}'


def test_error_is_valueerror_subclass():
    # Existing fail-closed handlers that catch ValueError keep working.
    assert issubclass(JCSCanonicalizationError, ValueError)


# --- property-name and structural coverage ---


def test_reject_lone_surrogate_nested_value():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"a": {"b": HIGH}})


def test_reject_lone_surrogate_array_element():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"a": [HIGH]})


def test_reject_lone_surrogate_nested_key():
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"a": {LOW: "x"}})


def test_reject_valid_pair_followed_by_lone_low():
    # Off-by-one guard: a valid non-BMP scalar then a lone low surrogate rejects.
    with pytest.raises(JCSCanonicalizationError):
        canonicalize_jcs({"v": EMOJI + LOW})


# --- error contract ---


def test_error_contract_category_reason_and_no_leak():
    # Caught by the documented type (ValueError), carries the stable category and
    # reason, and does not leak the offending string into the message.
    with pytest.raises(ValueError) as exc:
        canonicalize_jcs({"v": HIGH})
    err = exc.value
    assert isinstance(err, JCSCanonicalizationError)
    assert err.category == "invalid_unicode"
    assert err.reason == "lone_surrogate"
    assert HIGH not in str(err)


# --- signing boundary ---


def test_sign_preimage_api_fails_closed_on_lone_surrogate():
    # A real content-id API (compute_action_ref) routes through canonicalize_jcs;
    # a lone surrogate in the signed preimage must fail closed with the typed
    # error and produce no output, with no fallback to the legacy canonicalizer.
    from agent_passport.action_ref import compute_action_ref

    with pytest.raises(JCSCanonicalizationError):
        compute_action_ref("agent-1", "read", [HIGH], "2026-07-13T00:00:00Z")
