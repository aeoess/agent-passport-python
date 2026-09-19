# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Independent rfc8785-based cross-check for external-action-ref-v1-vectors.json.

This script does NOT import agent_passport and does NOT depend on the
TypeScript SDK. It only re-derives, from the raw formula in
draft-pidlisnyi-aps-03 section 4.2 (published text lines 852-857), the
digest that tests/cross_impl/gen_external_action_ref_v1_vectors.mts recorded
after calling the TS reference implementation, using the rfc8785 package (an
RFC 8785 JSON Canonicalization Scheme implementation external to this
project) as the canonicalizer:

    external_action_ref = sha256(rfc8785.dumps(input_object))

No domain-separation tag: the section 4.2 formula hashes the canonicalized
bytes directly. Lowercase hex. Only ACCEPTED cases carry a digest to check;
reject cases are reported as skipped, since a rejected input has no digest
in this file to compare against, and this script does not reimplement the
section 4.2 validation rules (that would just be a second copy of the same
logic, not an independent check).

Exit code is 1 if any case mismatches or errors, 0 otherwise.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import rfc8785

_VECTORS_PATH = pathlib.Path(__file__).parent / "external-action-ref-v1-vectors.json"


def _digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def main() -> int:
    document = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    cases = document["cases"]

    mismatches: list[str] = []
    checked = 0
    skipped = 0

    for case in cases:
        case_id = case["id"]
        expected = case["expected"]

        if expected.get("result") != "accept":
            print(f"{case_id}: skip (reject case, nothing to cross-check)")
            skipped += 1
            continue

        try:
            actual = _digest(case["input"])
            recorded = expected["external_action_ref"]
        except Exception as exc:  # noqa: BLE001 - report, don't hide, any recompute failure
            mismatches.append(f"{case_id}: recompute raised {exc!r}")
            print(f"{case_id}: ERROR recompute raised {exc!r}")
            continue

        checked += 1
        if actual == recorded:
            print(f"{case_id}: external_action_ref OK ({actual})")
        else:
            mismatches.append(
                f"{case_id}: external_action_ref mismatch, file has {recorded}, rfc8785 recompute gives {actual}"
            )
            print(f"{case_id}: external_action_ref MISMATCH file={recorded} recomputed={actual}")

    total = len(cases)
    print(f"---\n{total} cases total, {checked} recomputed, {skipped} skipped, {len(mismatches)} mismatches")

    if mismatches:
        print("MISMATCHES:")
        for line in mismatches:
            print(f"  - {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
