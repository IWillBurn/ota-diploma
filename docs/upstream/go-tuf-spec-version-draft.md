# Draft issue for theupdateframework/go-tuf

> **Status: draft, not posted.** Post only after the author has reviewed it. Checked on
> 2026-11-01: go-tuf v2.4.2 (latest release, 2026-05-19) and `master` set `spec_version`
> when they create metadata (`metadata/metadata.go`) and serialise it (`metadata/marshal.go`),
> but no code path compares the `spec_version` of loaded metadata with the supported one.
> Existing issues #206 and PR #512 are about the *format* of the value go-tuf writes
> ("1.0" vs SemVer), not about verifying incoming metadata.

---

**Title:** Client does not verify `spec_version` of loaded metadata

**Body:**

The specification (v1.0.37, "File formats: general principles", `SPEC_VERSION`) says:
"Metadata is written according to version "spec_version" of the specification, and clients
MUST verify that "spec_version" matches the expected version number. Adopters are free to
determine what is considered a match (e.g., the version number exactly, or perhaps only the
major version number)."

go-tuf v2.4.2 accepts metadata with any `spec_version`. Reproduction with the
tuf-conformance client CLI (`clients/go-tuf`, go-tuf v2.4.2) and the conformance
`RepositorySimulator`:

1. `init` with root v1, `refresh` (timestamp v1 trusted).
2. Repository publishes timestamp v2 with `"spec_version": "2.0.0"`, correctly signed by the
   timestamp key.
3. `refresh` exits 0 and `timestamp.json` v2 (spec_version 2.0.0) is stored as trusted.

python-tuf 7.0.1 rejects the same metadata (`Unsupported spec_version 2.0.0`, the major
version is compared in `tuf/api/_payload.py`), and tuf-js 6.0.1 rejects it as well.

Impact is low: the metadata still has to be signed by the role's keys. The check matters
for forward compatibility (metadata of an incompatible future major version should not be
interpreted with 1.x semantics) and for conformance.

Suggested fix: when loading metadata (`trustedmetadata`), reject a `spec_version` whose
major version differs from `SPECIFICATION_VERSION`, as python-tuf does. A conformance test
for this is proposed separately in tuf-conformance.

---

**Second, separate issue (draft): ask for a release with the nil checks of #743 and the key-length check of #739.**

go-tuf v2.4.2, the latest release on 2026-11-01, panics (nil pointer dereference in
`trustedmetadata.(*TrustedMetadata).UpdateTimestamp`, `trustedmetadata.go:144`) when a
correctly signed timestamp has no `meta["snapshot.json"]` entry or has it set to `null`
(also `meta` empty or `null`). The signature checks pass first, so this needs the timestamp
key or a broken repository, but a long-running updater process dies instead of reporting an
error. The nil checks added in #743 (merged 2026-09-22, `923b304`) fix it: the tuf-conformance
go client built against `923b304` returns `meta is missing required "snapshot.json" entry`.


A second panic fixed on master is not released either: an ed25519 key whose public value is
not 32 bytes (e.g. empty) in a root's or a delegator's `keys` makes `VerifyDelegate` call
`crypto/ed25519.Verify`, which panics (`ed25519: bad public key length: 0`) — for every
`keyid` of the role, even when no signature with that `keyid` exists. Fixed by #739
(2026-08-07). With v2.4.2, a holder of the targets key can crash every client that verifies
a delegated role, and a damaged trusted root on disk crashes the client at start
(`trustedmetadata.New`) instead of returning an error.

Suggested action: cut a release; no new code needed.

---

## Notes for the author (not part of the issue)

* Result: `bench/results/d1-new-scenarios/` (scenario `unsupported-spec-version`, otabench).
* Source checked: `~/go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/`
  and `master` on GitHub (2026-11-01).
* No @-handles in the issue.
* Second panic (#739): found by coverage-guided fuzzing (`bench/fuzz/go-tuf`, target
  `FuzzParse`, 26 s; `bench/results/d5-covfuzz-2026-11-02/`).
* Panic: found by the otabench scenario `fuzz-metadata` (`bench/results/d5-fuzz-metadata/`,
  4 of 120 inputs, exit code 2); master checked by building the conformance client against
  `923b304` (2026-11-01). Not a new vulnerability report: the fix exists upstream.
