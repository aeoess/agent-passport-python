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
