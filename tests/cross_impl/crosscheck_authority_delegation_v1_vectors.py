"""Independent rfc8785/PyNaCl-based cross-check for authority-delegation-v1-vectors.json.

This script does NOT import agent_passport and does NOT depend on the
TypeScript SDK. For every full AuthorityDelegationV1 record anywhere in the
vector file (a JSON object carrying record_type, delegation_id, signature,
verification_method, issuer, subject and authority), other than the one
all-zero placeholder record (AD-N-S13, which cannot be canonicalized at all;
see its case entry), it independently recomputes:

    delegation_id = "sha256:" + sha256(
        b"APS-AUTHORITY-DELEGATION-ID-V1\\x00" + rfc8785.dumps(body)
    ).hexdigest()

where body is the record without delegation_id and signature, and checks the
Ed25519 signature with PyNaCl over

    b"APS-AUTHORITY-DELEGATION-SIGNATURE-V1\\x00" + rfc8785.dumps(record_without_signature)

under the public key of the file's `keys` entry whose verification_method
the record names. It also independently re-derives each `keys` entry's own
seed (SHA-256 of the ASCII string "aps-authority-delegation-v1-vectors:"
plus the label) and public key (PyNaCl SigningKey(seed).verify_key).

A handful of records are deliberately corrupted by the case that builds them
(AD-N-C01 to AD-N-C04, AD-N-S08, AD-N-S09, AD-N-S55, AD-I08): for those, a
mismatch on the specific corrupted aspect (delegation_id or signature) is
the correct, expected outcome and is reported as such, not as an error.
AD-N-S22 (signature hex uppercased) is included in the same list in the
vector specification but needs no inversion here: hex-decoding is
case-insensitive, so its signature verifies as bytes regardless of letter
case, and the uppercase-only fault it demonstrates is a schema-format rule
this script does not model.

Exit code is 1 if any record other than a deliberately corrupted aspect
fails to recompute or verify, or if any `keys` entry fails to re-derive;
0 otherwise.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import nacl.exceptions
import nacl.signing
import rfc8785

_VECTORS_PATH = pathlib.Path(__file__).parent / "authority-delegation-v1-vectors.json"

_ID_DOMAIN = b"APS-AUTHORITY-DELEGATION-ID-V1\x00"
_SIGNATURE_DOMAIN = b"APS-AUTHORITY-DELEGATION-SIGNATURE-V1\x00"
_SEED_PREFIX = "aps-authority-delegation-v1-vectors:"
_PLACEHOLDER_ID = "sha256:" + ("0" * 64)

_RECORD_KEYS = {"record_type", "delegation_id", "signature", "verification_method", "issuer", "subject", "authority"}

# (case_id, field, index) -> (id_expected_to_match, signature_expected_to_verify).
# Every record not listed here is expected to match and verify normally.
# field is "chain" (index into case["chain"]) or "parent" (index is None).
_SPECIAL: dict[tuple[str, str, int | None], tuple[bool, bool]] = {
    ("AD-N-C01", "chain", 0): (False, True),
    ("AD-N-C02", "chain", 1): (False, True),
    ("AD-N-C03", "chain", 0): (True, False),
    ("AD-N-C04", "chain", 0): (True, False),
    ("AD-N-S08", "chain", 0): (False, True),
    ("AD-N-S09", "chain", 0): (False, True),
    ("AD-N-S22", "chain", 0): (True, True),
    ("AD-N-S55", "chain", 0): (False, True),
    ("AD-I08", "parent", None): (True, False),
}


def _is_record(value: object) -> bool:
    return isinstance(value, dict) and _RECORD_KEYS.issubset(value.keys())


def _recompute_id(record: dict) -> str:
    body = {k: v for k, v in record.items() if k not in ("delegation_id", "signature")}
    digest = hashlib.sha256(_ID_DOMAIN + rfc8785.dumps(body)).hexdigest()
    return f"sha256:{digest}"


def _find_public_key_hex(document: dict, verification_method: str) -> str | None:
    for entry in document["keys"]:
        if entry["verification_method"] == verification_method:
            return entry["public_key_hex"]
    return None


def _verify_signature(record: dict, public_key_hex: str) -> bool:
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    message = _SIGNATURE_DOMAIN + rfc8785.dumps(unsigned)
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(message, bytes.fromhex(record["signature"]))
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, KeyError):
        return False


def _iter_case_records(case: dict) -> list[tuple[str, int | None, dict]]:
    """Return [(field, index, record), ...] for every full record directly
    reachable from this case's own fields (not from a nested case)."""
    kind = case["kind"]
    out: list[tuple[str, int | None, dict]] = []
    if kind == "chain":
        for i, rec in enumerate(case.get("chain", [])):
            if _is_record(rec):
                out.append(("chain", i, rec))
    elif kind == "wire":
        value = case.get("expected", {}).get("value")
        if _is_record(value):
            out.append(("value", None, value))
    elif kind == "issue_root":
        delegation = case.get("expected", {}).get("delegation")
        if _is_record(delegation):
            out.append(("delegation", None, delegation))
    elif kind == "issue_child":
        parent = case.get("parent")
        if _is_record(parent):
            out.append(("parent", None, parent))
        delegation = case.get("expected", {}).get("delegation")
        if _is_record(delegation):
            out.append(("delegation", None, delegation))
    elif kind == "budget":
        for chain_name, chain in case.get("chains", {}).items():
            for i, rec in enumerate(chain):
                if _is_record(rec):
                    out.append((f"chains.{chain_name}", i, rec))
    return out


def _check_records(document: dict) -> tuple[int, int, int, list[str]]:
    checked = 0
    skipped_placeholder = 0
    confirmed_corruptions = 0
    mismatches: list[str] = []

    for case in document["cases"]:
        case_id = case["id"]
        for field, index, record in _iter_case_records(case):
            location = f"{case_id}.{field}" + (f"[{index}]" if index is not None else "")

            if record.get("delegation_id") == _PLACEHOLDER_ID:
                skipped_placeholder += 1
                print(f"{location}: skip (all-zero placeholder, cannot be canonicalized)")
                continue

            id_expected_match, sig_expected_verify = _SPECIAL.get((case_id, field, index), (True, True))

            try:
                recomputed_id = _recompute_id(record)
            except Exception as exc:  # noqa: BLE001 - report, don't hide, any recompute failure
                mismatches.append(f"{location}: delegation_id recompute raised {exc!r}")
                print(f"{location}: ERROR delegation_id recompute raised {exc!r}")
                continue
            id_matches = recomputed_id == record.get("delegation_id")

            public_key_hex = _find_public_key_hex(document, record.get("verification_method", ""))
            if public_key_hex is None:
                mismatches.append(f"{location}: no keys entry for verification_method {record.get('verification_method')!r}")
                print(f"{location}: ERROR no keys entry for verification_method {record.get('verification_method')!r}")
                continue
            sig_verifies = _verify_signature(record, public_key_hex)

            checked += 1
            id_ok = id_matches == id_expected_match
            sig_ok = sig_verifies == sig_expected_verify
            if id_ok and sig_ok:
                if id_expected_match and sig_expected_verify:
                    print(f"{location}: OK (id matches, signature verifies)")
                else:
                    confirmed_corruptions += 1
                    print(
                        f"{location}: OK, confirmed deliberate corruption "
                        f"(id_matches={id_matches}, signature_verifies={sig_verifies}, as the case states)"
                    )
            else:
                mismatches.append(
                    f"{location}: id_matches={id_matches} (expected {id_expected_match}), "
                    f"signature_verifies={sig_verifies} (expected {sig_expected_verify})"
                )
                print(
                    f"{location}: MISMATCH id_matches={id_matches} (expected {id_expected_match}), "
                    f"signature_verifies={sig_verifies} (expected {sig_expected_verify})"
                )

    return checked, skipped_placeholder, confirmed_corruptions, mismatches


def _check_keys(document: dict) -> list[str]:
    mismatches: list[str] = []
    for entry in document["keys"]:
        seed = hashlib.sha256((_SEED_PREFIX + entry["label"]).encode("ascii")).digest()
        if seed.hex() != entry["seed_hex"]:
            mismatches.append(f"keys[{entry['label']}]: seed_hex mismatch: file has {entry['seed_hex']}, recomputed {seed.hex()}")
            print(f"keys[{entry['label']}]: MISMATCH seed_hex file={entry['seed_hex']} recomputed={seed.hex()}")
            continue
        signing_key = nacl.signing.SigningKey(seed)
        public_key_hex = signing_key.verify_key.encode().hex()
        if public_key_hex != entry["public_key_hex"]:
            mismatches.append(
                f"keys[{entry['label']}]: public_key_hex mismatch: file has {entry['public_key_hex']}, recomputed {public_key_hex}"
            )
            print(f"keys[{entry['label']}]: MISMATCH public_key_hex file={entry['public_key_hex']} recomputed={public_key_hex}")
        else:
            print(f"keys[{entry['label']}]: OK (seed and public key both re-derive)")
    return mismatches


def main() -> int:
    document = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))

    key_mismatches = _check_keys(document)
    checked, skipped, confirmed_corruptions, record_mismatches = _check_records(document)
    mismatches = key_mismatches + record_mismatches

    print("---")
    print(f"{len(document['keys'])} keys entries checked, {len(key_mismatches)} mismatches")
    print(
        f"{checked} records recomputed ({confirmed_corruptions} confirmed as deliberately corrupted), "
        f"{skipped} skipped (all-zero placeholder), {len(record_mismatches)} mismatches"
    )
    print(f"{len(mismatches)} total mismatches")

    if mismatches:
        print("MISMATCHES:")
        for line in mismatches:
            print(f"  - {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
