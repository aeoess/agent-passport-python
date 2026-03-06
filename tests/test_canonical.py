"""Tests for canonical JSON serialization — cross-language compatibility."""

from agent_passport.canonical import canonicalize


def test_sorts_keys():
    assert canonicalize({"z": 1, "a": "hello"}) == '{"a":"hello","z":1}'


def test_omits_null():
    assert canonicalize({"a": "hello", "m": None, "z": 1}) == '{"a":"hello","z":1}'


def test_nested():
    result = canonicalize({"name": "test", "nested": {"z": True, "a": False}})
    assert result == '{"name":"test","nested":{"a":false,"z":true}}'


def test_null_in_arrays_preserved():
    """F-PX2-001: null in arrays must produce valid JSON."""
    assert canonicalize([1, None, 3]) == "[1,null,3]"
    assert canonicalize([None]) == "[null]"


def test_top_level_null():
    assert canonicalize(None) == "null"


def test_empty_array():
    assert canonicalize({"empty": [], "num": 0}) == '{"empty":[],"num":0}'


def test_quotes_in_strings():
    assert canonicalize({"a": 'quotes "inside"'}) == '{"a":"quotes \\"inside\\""}'
