# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Canonical JSON serialization for cross-language signature interoperability.

Produces identical output to the TypeScript SDK's canonicalize() function.
Rules:
  - Object keys sorted alphabetically
  - null/None values omitted from objects (NOT from arrays)
  - No whitespace
  - Dates serialized as ISO strings
"""

import json


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
        # Match TypeScript: JSON.stringify(1.0) produces "1", not "1.0"
        if obj == int(obj):
            return str(int(obj))
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        pairs = []
        for key in sorted(obj.keys()):
            val = obj[key]
            if val is None:
                continue
            pairs.append(json.dumps(key) + ":" + canonicalize(val))
        return "{" + ",".join(pairs) + "}"
    # Fallback for other types
    return json.dumps(obj)


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
        return "true" if obj else "false"
    if isinstance(obj, int):
        return json.dumps(obj)
    if isinstance(obj, float):
        import math
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(f"Cannot canonicalize {obj}")
        if obj == int(obj):
            return str(int(obj))
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize_jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        # Preserve null values in objects (unlike legacy canonicalize)
        pairs = []
        for key in sorted(obj.keys()):
            pairs.append(
                json.dumps(key, ensure_ascii=False) + ":" + canonicalize_jcs(obj[key])
            )
        return "{" + ",".join(pairs) + "}"
    return json.dumps(obj)
