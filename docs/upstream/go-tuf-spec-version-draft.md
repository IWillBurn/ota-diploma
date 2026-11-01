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

## Notes for the author (not part of the issue)

* Result: `bench/results/d1-new-scenarios/` (scenario `unsupported-spec-version`, otabench).
* Source checked: `~/go/pkg/mod/github.com/theupdateframework/go-tuf/v2@v2.4.2/metadata/`
  and `master` on GitHub (2026-11-01).
* No @-handles in the issue.
