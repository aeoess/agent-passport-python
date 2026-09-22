# `authority-revocation-v1-vectors.json` — provenance

Vendored byte for byte from the TypeScript SDK. Nothing in this repository
generates or edits it; a change to its bytes is a change to the wire format and
belongs upstream, in the repository named below, not here.

| field | value |
|---|---|
| source repository | `aeoess/agent-passport-system` (TypeScript SDK) |
| source path | `fixtures/authority-revocation/authority-revocation-vectors-v1.json` |
| SDK merge commit | `2afe124` — "Merge pull request #183 from aeoess/fixtures/authority-revocation-vector", the commit that carries the vector file |
| generator reference commit | `f6792af732f2102b239cca6b18840f6fa7d8fe87` — the `src/` tree whose implementation produced every recorded outcome, also written inside the JSON at `sdk_reference.commit` |
| SHA-256 of the file as vendored | `43dbe7fed137269405be38bf829681bc18525a1eccb8e8236e37f03720147ee2` |

`tests/cross_impl/test_authority_revocation_v1_vectors.py` asserts that SHA-256
against the file on disk, so the vendored copy cannot drift from the bytes this
port was checked against without a test saying so.

The two commits are different on purpose. `f6792af` pins the **implementation**
the outcomes came from; the vector files were added on top of it, so the SDK
commit that carries the file is the later `2afe124`.

To re-fetch the exact bytes:

```
git -C <agent-passport-system> show 2afe124:fixtures/authority-revocation/authority-revocation-vectors-v1.json
```

## Renamed on vendoring

The file is `authority-revocation-vectors-v1.json` upstream and
`authority-revocation-v1-vectors.json` here, matching the
`authority-delegation-v1-vectors.json` naming its siblings in this directory
already use. Only the filename differs; the bytes do not.

## What the vector covers, and what it does not

One valid direct revocation and nine named negative cases, each carrying the
state and first failure code the TypeScript reference returned. Not covered, in
the vector's own words: derived revocation records for descendants (0B), the
cascade-completion record (0C), store and resolver behaviour (exercised by
`tests/v2/test_authority_revocation_v1.py` instead), and JCS escaping of
non-ASCII and control characters (pinned by `jcs-test-vectors.json`).
