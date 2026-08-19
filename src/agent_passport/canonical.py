# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Canonical JSON serialization for cross-language signature interoperability.

Produces identical output to the TypeScript SDK's canonicalize() function.
Rules:
  - Object keys sorted alphabetically
  - null/None values omitted from objects (NOT from arrays)
  - No whitespace
"""

import json
import math
import re

from .write_policy import MAX_SAFE_INTEGER, UnsafeIntegerError


class JCSCanonicalizationError(ValueError):
    """A value cannot be canonicalized under RFC 8785.

    Subclasses ValueError so existing fail-closed handlers that catch ValueError
    around canonicalization keep working (they fail closed rather than crash).

    Carries a stable machine-readable ``category`` and ``reason`` matching the
    TypeScript and Go SDKs, so cross-language callers can branch on the failure
    without parsing the message.
    """

    #: Stable machine-readable category, shared across the APS SDKs.
    category = "invalid_unicode"

    def __init__(self, message: str, reason: str = "lone_surrogate") -> None:
        super().__init__(message)
        #: Specific failure within the category, e.g. "lone_surrogate".
        self.reason = reason


def _assert_no_lone_surrogate(s: str) -> None:
    """Reject a string containing an unpaired UTF-16 surrogate.

    A lone surrogate (U+D800..U+DFFF) is not a valid Unicode scalar and has no
    UTF-8 encoding, so RFC 8785 requires rejecting the input rather than escaping
    it or replacing it with U+FFFD. Python's JSON parser resolves valid surrogate
    PAIRS to their single non-BMP code point, so any character that remains in the
    surrogate range is unpaired.
    """
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JCSCanonicalizationError(
                "canonicalize_jcs: string contains an unpaired UTF-16 surrogate "
                f"(U+{o:04X}); a lone surrogate has no valid UTF-8 encoding and "
                "RFC 8785 requires rejection"
            )


def has_non_finite(obj) -> bool:
    """Return True if obj contains a NaN or Infinity float anywhere within it.

    canonicalize() raises ValueError on non-finite floats (they are not valid
    JSON per RFC 8259), but Python's json.loads accepts them by default, so a
    poisoned input reaches the canonicalizing verifiers and crashes them.
    Verifier entry paths call this first to fail closed (valid=False) instead
    of raising. Pure predicate: it never changes canonical output.
    """
    if isinstance(obj, bool):
        return False
    if isinstance(obj, float):
        return math.isnan(obj) or math.isinf(obj)
    if isinstance(obj, list):
        return any(has_non_finite(item) for item in obj)
    if isinstance(obj, dict):
        return any(has_non_finite(v) for v in obj.values())
    return False


def _es_number(value: float) -> str:
    """Serialize a finite float exactly like ECMAScript Number::toString.

    RFC 8785 section 3.2.2.3 mandates the ECMAScript number-to-string algorithm.
    Python's repr() yields the same shortest round-trip DIGITS as ECMAScript (the
    shortest decimal that round-trips a double is unique), but Python and
    json.dumps format the decimal point / exponent differently (e.g. 1e21 ->
    '1000000000000000000000', 1e-7 -> '1e-07', 1e-6 -> '1e-06'), so we reformat
    the digits into ECMAScript notation ('1e+21', '1e-7', '0.000001'). Validated
    by differential test against Node's JSON.stringify (tests/test_es_number.py).
    """
    if value == 0:
        return "0"  # ECMAScript renders -0 as "0"
    sign = ""
    if value < 0:
        sign, value = "-", -value
    r = repr(value)
    if "e" in r or "E" in r:
        mant, exp_s = re.split("[eE]", r)
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    if "." in mant:
        int_part, frac_part = mant.split(".")
    else:
        int_part, frac_part = mant, ""
    digits = (int_part + frac_part).lstrip("0")
    lsd_pow = exp - len(frac_part)  # power of ten of the least-significant digit
    trail = len(digits) - len(digits.rstrip("0"))
    s = digits.rstrip("0")
    k = len(s)
    n = lsd_pow + trail + k  # value = s * 10^(n-k); 10^(n-1) <= value < 10^n
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e_out = n - 1
    e_str = ("e+" if e_out >= 0 else "e-") + str(abs(e_out))
    return sign + (s if k == 1 else s[0] + "." + s[1:]) + e_str


def _canonical_keys(keys):
    """Sort object keys by UTF-16 code units, matching RFC 8785 section 3.2.3
    and the TS SDK (Array.prototype.sort compares UTF-16 code units). Python's
    default str sort is by code point, which orders astral-plane (>= U+10000)
    keys differently from surrogate-pair UTF-16 order."""
    return sorted(keys, key=lambda k: k.encode("utf-16-be"))


def canonicalize(obj) -> str:
    """Canonical JSON serialization matching the TypeScript SDK.

    Args:
        obj: Any JSON-serializable Python object.

    Returns:
        Deterministic JSON string with sorted keys and no null object values.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return json.dumps(obj)
    if isinstance(obj, float):
        import math
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"Cannot canonicalize {obj} — NaN/Infinity are not valid JSON per RFC 8259")
        return _es_number(obj)
    if isinstance(obj, str):
        # ensure_ascii=False to match the TypeScript SDK's JSON.stringify,
        # which emits raw UTF-8 and does not \u-escape non-ASCII. Without
        # this, a non-ASCII string canonicalizes differently in Python than
        # in TypeScript, breaking cross-language signatures and content hashes.
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        pairs = []
        for key in _canonical_keys(obj.keys()):
            val = obj[key]
            if val is None:
                continue
            pairs.append(json.dumps(key, ensure_ascii=False) + ":" + canonicalize(val))
        return "{" + ",".join(pairs) + "}"
    # Fallback for other types
    return json.dumps(obj, ensure_ascii=False)


def canonicalize_for_write(obj, path: str = "$") -> str:
    """Legacy canonicalization for a NEW WRITE, with the APS unsafe-integer rule applied.

    Byte-identical to :func:`canonicalize` for every value it accepts: same key order,
    same null stripping, same number and string formatting. The only difference is that
    an integer-valued number outside the interoperable IEEE 754 range is refused rather
    than emitted. See :mod:`agent_passport.write_policy` for the rule.

    Use at signing and new-write boundaries ONLY. Verification, recompute, and any path
    rebuilding the preimage of an existing artifact must keep calling
    :func:`canonicalize`, which stays unrestricted so historical bytes keep verifying.

    READS EACH KEY EXACTLY ONCE. A separate validating pre-pass followed by
    :func:`canonicalize` would walk the mapping twice, and a Mapping subclass or an
    object overriding ``__getitem__`` can answer differently on the second read, so the
    value checked would not be the value signed. Here the value is captured once into
    ``val``, checked, and emitted from that same capture.

    Note this deliberately does NOT fix the legacy int-verbatim divergence from the other
    SDKs: refusing the unsafe range makes that divergence unreachable on write without
    altering a single historical byte.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return json.dumps(obj)
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"Cannot canonicalize {obj}: NaN and Infinity are not valid JSON per RFC 8259")
        if obj.is_integer() and abs(obj) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return _es_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(
            canonicalize_for_write(item, f"{path}[{index}]") for index, item in enumerate(obj)
        ) + "]"
    if isinstance(obj, dict):
        pairs = []
        for key in _canonical_keys(obj.keys()):
            val = obj[key]  # the single read; everything below uses this capture
            if val is None:
                continue
            pairs.append(
                json.dumps(key, ensure_ascii=False)
                + ":"
                + canonicalize_for_write(val, f"{path}.{key}")
            )
        return "{" + ",".join(pairs) + "}"
    return json.dumps(obj, ensure_ascii=False)


def canonicalize_jcs(obj) -> str:
    """RFC 8785 JSON Canonicalization Scheme (strict).

    Unlike canonicalize() above, this preserves null values inside objects.
    Used by Mutual Authentication v1 and other modules that need strict
    RFC 8785 compatibility with the TypeScript SDK's canonicalizeJCS().

    Args:
        obj: Any JSON-serializable Python object.

    Returns:
        RFC 8785 canonical JSON string.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        # Must stay ahead of the int branch: bool is a subclass of int in Python,
        # and reordering would serialize True as 1.
        return "true" if obj else "false"
    if isinstance(obj, int):
        # RFC 8785 section 3.2.2.3 defines the JCS number domain as IEEE-754
        # binary64 serialized under ECMAScript Number::toString. Python's int is
        # arbitrary precision, so emitting it verbatim preserves a decimal
        # spelling the double does not have: 2**60 would serialize as
        # 1152921504606846976 where the double is 1152921504606847000. Widen to
        # binary64 first, then take exactly the same path a float takes.
        try:
            as_double = float(obj)
        except OverflowError:
            as_double = math.inf
        if math.isinf(as_double):
            raise JCSCanonicalizationError(
                f"canonicalize_jcs: integer {obj} exceeds the IEEE-754 binary64 "
                "range and has no representation in the RFC 8785 number domain",
                reason="number_out_of_double_range",
            )
        return _es_number(as_double)
    if isinstance(obj, float):
        # math is imported at module scope. A local "import math" here would make
        # the name function-local for the whole of canonicalize_jcs and shadow it
        # from the int branch above.
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"Cannot canonicalize {obj}")
        return _es_number(obj)
    if isinstance(obj, str):
        _assert_no_lone_surrogate(obj)
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize_jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        # Preserve null values in objects (unlike legacy canonicalize)
        # Validate keys before sorting: _canonical_keys encodes each key as
        # utf-16-be, which itself raises on a lone surrogate. Check first so the
        # failure is the clean typed error, not a raw UnicodeEncodeError.
        for key in obj.keys():
            _assert_no_lone_surrogate(key)
        pairs = []
        for key in _canonical_keys(obj.keys()):
            pairs.append(
                json.dumps(key, ensure_ascii=False) + ":" + canonicalize_jcs(obj[key])
            )
        return "{" + ",".join(pairs) + "}"
    return json.dumps(obj, ensure_ascii=False)


def canonicalize_jcs_for_write(obj, path: str = "$") -> str:
    """RFC 8785 canonicalization for a NEW WRITE, with the unsafe-integer rule applied.

    Byte-identical to :func:`canonicalize_jcs` for every value it accepts. The only
    difference is that an integer-valued number outside the interoperable IEEE 754 range
    is refused rather than emitted.

    Use at signing and new-write boundaries ONLY. Verification and recompute keep calling
    :func:`canonicalize_jcs`, which stays unrestricted so historical bytes keep verifying.

    READS EACH KEY EXACTLY ONCE, so a Mapping subclass or an object overriding
    ``__getitem__`` cannot answer safe on a validating pre-pass and unsafe on the
    emitting pass. The value is captured once, checked, and emitted from that capture.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return _es_number(float(obj))
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"Cannot canonicalize {obj}")
        if obj.is_integer() and abs(obj) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return _es_number(obj)
    if isinstance(obj, str):
        _assert_no_lone_surrogate(obj)
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(
            canonicalize_jcs_for_write(item, f"{path}[{index}]") for index, item in enumerate(obj)
        ) + "]"
    if isinstance(obj, dict):
        for key in obj.keys():
            _assert_no_lone_surrogate(key)
        pairs = []
        for key in _canonical_keys(obj.keys()):
            val = obj[key]  # the single read; everything below uses this capture
            pairs.append(
                json.dumps(key, ensure_ascii=False)
                + ":"
                + canonicalize_jcs_for_write(val, f"{path}.{key}")
            )
        return "{" + ",".join(pairs) + "}"
    return json.dumps(obj, ensure_ascii=False)
