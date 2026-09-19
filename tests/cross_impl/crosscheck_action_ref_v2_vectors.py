"""Independent rfc8785-based cross-check for action-ref-v2-vectors.json.

This script does NOT import agent_passport and does NOT depend on the
TypeScript SDK. It only re-derives, from the raw formulas in
draft-pidlisnyi-aps-03 section 4.1, the two digests that
tests/cross_impl/gen_action_ref_v2_vectors.mts recorded after calling the TS
reference implementation, using the rfc8785 package (an RFC 8785 JSON
Canonicalization Scheme implementation external to this project) as the
canonicalizer:

    payload_ref  = sha256(b"APS-ACTION-PAYLOAD-V1\\x00" + rfc8785.dumps(payload))
    action_ref   = sha256(b"APS-ACTION-REF-V2\\x00"     + rfc8785.dumps(canonical_input))

Both lowercase hex. Only ACCEPTED cases carry a digest to check; reject cases
are reported as skipped. A mismatch means the recorded value, the rfc8785
package or the script disagree and must be investigated; agreement shows
that two canonicalizers agree on these inputs.

Exit code is 1 if any case mismatches or errors, 0 otherwise.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import rfc8785

_VECTORS_PATH = pathlib.Path(__file__).parent / "action-ref-v2-vectors.json"

_PAYLOAD_DOMAIN = b"APS-ACTION-PAYLOAD-V1\x00"
_ACTION_REF_DOMAIN = b"APS-ACTION-REF-V2\x00"


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + rfc8785.dumps(value)).hexdigest()


def main() -> int:
    document = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    cases = document["cases"]

    mismatches: list[str] = []
    checked = 0
    skipped = 0

    for case in cases:
        case_id = case["id"]
        entry = case["entry"]
        expected = case["expected"]

        if expected.get("result") != "accept":
            print(f"{case_id}: skip (reject case, nothing to cross-check)")
            skipped += 1
            continue

        try:
            if entry == "payload":
                actual = _digest(_PAYLOAD_DOMAIN, case["input"])
                recorded = expected["payload_ref"]
                label = "payload_ref"
            elif entry == "object":
                actual = _digest(_ACTION_REF_DOMAIN, case["input"])
                recorded = expected["action_ref"]
                label = "action_ref"
            elif entry == "json":
                parsed = json.loads(case["input_json"])
                actual = _digest(_ACTION_REF_DOMAIN, parsed)
                recorded = expected["action_ref"]
                label = "action_ref"
            elif entry == "create":
                actual = _digest(_ACTION_REF_DOMAIN, expected["canonical_input"])
                recorded = expected["action_ref"]
                label = "action_ref"
            else:
                mismatches.append(f"{case_id}: unknown entry type {entry!r}")
                print(f"{case_id}: ERROR unknown entry type {entry!r}")
                continue
        except Exception as exc:  # noqa: BLE001 - report, don't hide, any recompute failure
            mismatches.append(f"{case_id}: recompute raised {exc!r}")
            print(f"{case_id}: ERROR recompute raised {exc!r}")
            continue

        checked += 1
        if actual == recorded:
            print(f"{case_id}: {label} OK ({actual})")
        else:
            mismatches.append(
                f"{case_id}: {label} mismatch — file has {recorded}, rfc8785 recompute gives {actual}"
            )
            print(f"{case_id}: {label} MISMATCH file={recorded} recomputed={actual}")

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
