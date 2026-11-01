# Conformance/test suites and implementations of OTA / software-update systems (TUF, Uptane, IETF SUIT, Linux A/B updaters, MCUboot): what exists and what it does not cover

Research date: 2026-10-31. Repo status (archived flag, last push, latest release) was pulled from the GitHub REST API and the GitHub release Atom feeds on that date. OSS-Fuzz presence was checked by requesting `google/oss-fuzz/master/projects/<name>/project.yaml`.

## Q1. tuf-conformance: CLI protocol, simulator, clients tested in CI, test categories, xfails, bugs found, talks, what it does NOT test

### Takeaway
tuf-conformance is a pytest suite with an in-memory, HTTP-served TUF repository simulator. It drives any TUF client as a black box through a 3-command CLI (`init`, `refresh`, `download`). It judges the client only by exit code, the trusted metadata it stores in `--metadata-dir`, the files it writes to `--target-dir`, and the HTTP requests it makes. As of 2026-10-31 the nightly report lists 6 clients and 119 test cases. It covers only TUF *client metadata-workflow* conformance. It does not cover network-level attacks (slow retrieval, endless data), crash or power-loss safety, installation or boot, Uptane, or SUIT. That gap is what the thesis can claim.

### Cited Findings

**Repo, release, maintenance**
- Repo `theupdateframework/tuf-conformance` (Python). Latest release v2.5.0 (2026-09-02). Earlier releases: v2.4.0 (2025-11-03), v2.3.0 (2025-02-17), v2.2.0 (2024-11-29), v2.1.0 (2024-10-18) — [releases](https://github.com/theupdateframework/tuf-conformance/releases)
- Versioning rule: the major version is bumped "if the client CLI changes or workflows are likely to break", the minor version when tests are added — [README](https://github.com/theupdateframework/tuf-conformance/blob/main/README.md)
- Stated goals: help client developers measure conformance with the spec, improve practical compatibility between implementations, and collaborate on tests — [README](https://github.com/theupdateframework/tuf-conformance/blob/main/README.md)
- Ships as a composite GitHub Action. Inputs are `entrypoint` (required) and `artifact-name`. It installs `faketime` and runs `pytest -v --json-report ... --entrypoint "$ENTRYPOINT" --repository-dump-dir ./test-repositories`, then uploads the repository dumps and a `tuf-conformance-report.json` artifact — [action.yml](https://github.com/theupdateframework/tuf-conformance/blob/main/action.yml)
- The suite depends on the `faketime` tool. The client is wrapped as `faketime <time> <client> ...` for expiry tests, so a client must honour libfaketime (there is even a `test_faketime` test). An issue reports faketime problems on macOS — [README](https://github.com/theupdateframework/tuf-conformance/blob/main/README.md), [client_runner.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/client_runner.py), [issue #305](https://github.com/theupdateframework/tuf-conformance/issues/305)

**Exact client-under-test CLI protocol** ([CLIENT-CLI.md](https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md))
- `<client> --metadata-dir <METADATA_DIR> init <TRUSTED_ROOT>`
  - Initializes from the given root file; "may simply mean copying it into METADATA_DIR".
  - Must make no network requests and is expected to do no checks.
  - Exit 0 on success, 1 otherwise. Called once per test.
- `<client> --metadata-dir <METADATA_DIR> --metadata-url <METADATA_URL> refresh`
  - Runs the TUF top-level metadata update workflow.
  - Exit 0 only if the refresh fully succeeded, 1 if any part failed.
  - Metadata must be stored under non-versioned names (`root.json`, not `1.root.json`). May be called several times.
- `<client> --metadata-dir <DIR> --metadata-url <URL> --target-name <TARGET_PATH> --target-base-url <TARGET_URL> --target-dir <TARGET_DIR> download`
  - `--target-name` can be repeated. Targets are processed in order with the same client instance, and the client must stop with exit 1 on the first failing target.
  - Metadata must be up to date before downloading.
  - Already-downloaded artifacts with matching hashes must not be downloaded again (caching).
  - Filenames inside TARGET_DIR are free, but an artifact re-downloaded after its content changed must keep the same filename.
- What the suite measures: exit codes, the trusted metadata in METADATA_DIR, the artifacts in TARGET_DIR, and the HTTP requests made. Clients that keep data in a database must still copy it to these directories. Some tests expect a specific sequence of metadata requests, for example for delegations.
- `ClientRunner` launches the client with `subprocess.Popen(cmd)`. The command string is split on spaces, so the entrypoint can carry extra arguments. — [client_runner.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/client_runner.py)

**How the simulator works** ([DEVELOPMENT.md](https://github.com/theupdateframework/tuf-conformance/blob/main/DEVELOPMENT.md), [repository_simulator.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/repository_simulator.py), [simulator_server.py](https://github.com/theupdateframework/tuf-conformance/blob/main/tuf_conformance/_internal/simulator_server.py))
- `RepositorySimulator` is "an in-memory TUF repository implementation designed for this test suite". It makes common repository actions easy and "still allows tests to meddle with the repository in ways that are not spec-compliant".
  - Helpers: `add_key()`, `add_delegation()`, `add_artifact()`, `rotate_keys()`, `add_succinct_roles()`.
  - Changes reach clients only after an explicit `repo.publish([...])`, which bumps the version, re-signs, and stores the bytes in `repo.signed_mds`.
  - Publishing a targets role updates `snapshot.meta`; publishing snapshot updates the timestamp's `snapshot_meta`.
  - Tests can tamper with the signed bytes directly. `publish(..., verify_version=False)` serves inconsistent versions.
- `SimulatorServer` is a Python `ThreadingHTTPServer` on localhost.
  - Each test gets its own URL prefix: `http://host:port/<test>/metadata/` and `/<test>/targets/`.
  - Responses send the full body with a correct `Content-length`.
  - The request log (`repo.metadata_statistics`, `repo.artifact_statistics`) is used to assert on client behaviour.
- `StaticServer` serves frozen real-world repositories (`static_data/sigstore-root-signing`, `static_data/tuf-on-ci-0.11`) for interop tests — [repo tree](https://github.com/theupdateframework/tuf-conformance/tree/main/tuf_conformance/static_data)
- Debug dumps go to `/tmp/tuf-conformance-dump`, one repository snapshot per client refresh or download — [DEVELOPMENT.md](https://github.com/theupdateframework/tuf-conformance/blob/main/DEVELOPMENT.md)

**Expected failures**
- Clients mark tests in a `<entrypoint>.xfails` file. Entries can be test names, groups, or parametrized cases like `test-group[parameter]`, and comment lines are allowed. This is meant for features that are not strict spec requirements, such as key types or hash algorithms — [README](https://github.com/theupdateframework/tuf-conformance/blob/main/README.md)
- sigstore-rust's xfails header says "xfail is strict, so a listed test that passes fails the run" — [sigstore-rust conformance.xfails](https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-tuf/conformance.xfails)

**Test categories** (counted from the source files in [tuf_conformance/](https://github.com/theupdateframework/tuf-conformance/tree/main/tuf_conformance), main branch, 2026-10-31: 56 test functions and 15 `parametrize` decorators, which expand to 119 cases)

| File | Functions | Test names |
|---|---|---|
| test_basic.py | 19 | basic_refresh_requests, basic_refresh_trusted_data, implicit_refresh, invalid_initial_root, unsigned_initial_root, unsigned_metadata, url_and_metadata_version_mismatch, timestamp_content_changes, basic_metadata_hash_support, targets_hash_mismatch, snapshot_hash_mismatch, metadata_bytes_match, custom_fields, deprecated_keyid_hash_algorithms, snapshot_404, targets_404, timestamp_404, incorrect_metadata_type, faketime |
| test_expiration.py | 6 | root/timestamp/snapshot/targets_expired, expired_local_root, expired_local_timestamp |
| test_file_download.py | 7 | downloads_expected_file (+ in subdir), repository_substitutes_target_file, multiple_changes_to_target, download_with_hash_algorithms, unknown_hash_algorithm, artifact_cache |
| test_keys.py | 9 | snapshot_does_not_meet_threshold, snapshot_has_too_few_keys, duplicate_keys, duplicate_sig_keyids, keytype_and_scheme, rsa_/ecdsa_/mldsa_keytype_and_scheme, invalid_sig_in_valid_metadata |
| test_rollback.py | 7 | new_timestamp_version_rollback, snapshot_rollback, targets_rollback, targets_role_removal, targets/snapshot/timestamp fast_forward_recovery |
| test_updater_delegation_graphs.py | 4 | graph_traversal (≈12 parametrized graphs including cyclic and terminating), targetfile_search, cached_role_is_verified_against_current_delegator, delegation_not_in_snapshot |
| test_updater_key_rotations.py | 2 | root_rotation, non_root_rotations |
| test_quoting_issues.py | 1 | unusual_role_name (`?`, `#`, `/delegatedrole`, `../delegatedrole`) |
| test_static_repositories.py | 1 | static_repository (sigstore-root-signing, tuf-on-ci-0.11) |

The parametrization names come from the sigstore-java xfails list — [sigstore-java tuf-cli-server.xfails](https://github.com/sigstore/sigstore-java/blob/main/tuf-cli/tuf-cli-server.xfails)

**Clients tested and results**
- In-repo example clients: python-tuf (`clients/python-tuf/python_tuf.py`) and go-tuf (`clients/go-tuf`, Go/cobra). CI runs both on every PR. The clients README calls them examples for developing the suite itself — [ci.yml](https://github.com/theupdateframework/tuf-conformance/blob/main/.github/workflows/ci.yml), [clients/README.md](https://github.com/theupdateframework/tuf-conformance/blob/main/clients/README.md). An open issue asks to "Get go-tuf client upstreamed or remove it" — [issue #290](https://github.com/theupdateframework/tuf-conformance/issues/290)
- The nightly "Client Conformance Report" (cron 02:00) pulls each project's `tuf-conformance-results` artifact from its own CI — [publish-report.yml](https://github.com/theupdateframework/tuf-conformance/blob/main/.github/workflows/publish-report.yml). Projects pulled:
  - python-tuf: `develop`, conformance.yml
  - tuf-js: `main`, conformance.yml
  - sigstore-java: `main`, tuf-conformance.yml
  - sigstore-ruby: `main`, ci.yml
  - sigstore-rust: `main`, tuf-conformance.yml
  - go-tuf: `master`, conformance.yml
- Report as of 2026-10-31T02:00Z — [Client Conformance Report](https://theupdateframework.github.io/tuf-conformance/):

  | Client | Pass rate | Passed | Failed | Xfailed |
  |---|---|---|---|---|
  | python-tuf | 100% | 119 | 0 | 0 |
  | sigstore-rust | 100% | 119 | 0 | 0 |
  | go-tuf | 97% | 116 | 0 | 3 |
  | tuf-js | 97% | 116 | 0 | 3 |
  | sigstore-java | 80% | 86 | 0 | 22 |
  | sigstore-ruby | no data | | | |

- Suite version pinned by each project:
  - python-tuf, go-tuf, tuf-js, sigstore-rust: v2.5.0 — [python-tuf](https://github.com/theupdateframework/python-tuf/blob/develop/.github/workflows/conformance.yml), [go-tuf](https://github.com/theupdateframework/go-tuf/blob/master/.github/workflows/conformance.yml), [tuf-js](https://github.com/theupdateframework/tuf-js/blob/main/.github/workflows/conformance.yml), [sigstore-rust](https://github.com/sigstore/sigstore-rust/blob/main/.github/workflows/tuf-conformance.yml)
  - sigstore-java: v2.4.0 — [sigstore-java](https://github.com/sigstore/sigstore-java/blob/main/.github/workflows/tuf-conformance.yml)
  - sigstore-ruby: v2.3.0 — [sigstore-ruby ci.yml](https://github.com/sigstore/sigstore-ruby/blob/main/.github/workflows/ci.yml)
  - The older suite versions explain sigstore-java's smaller total (108) and sigstore-ruby's missing data (inference from the pins).
- go-tuf was added to the report in [tuf-conformance PR #427](https://github.com/theupdateframework/tuf-conformance/pull/427) after go-tuf added its own conformance workflow — [go-tuf PR #789](https://github.com/theupdateframework/go-tuf/pull/789)

**Known xfails per client**
- go-tuf (upstream file):
  - `test_rsa_keytype_and_scheme[rsa/rsassa-pss-sha384]` and `[...sha512]` ("go-tuf does not support these optional RSA schemes").
  - `test_cached_role_is_verified_against_current_delegator`, linked to [go-tuf issue #759](https://github.com/theupdateframework/go-tuf/issues/759).
  - Source: [tuf-conformance-client.xfails](https://github.com/theupdateframework/go-tuf/blob/master/.github/scripts/tuf-conformance-client.xfails)
  - The in-suite copy also lists `test_mldsa_keytype_and_scheme`, citing [go-tuf PR #758](https://github.com/theupdateframework/go-tuf/pull/758) — [clients/go-tuf/go-tuf.xfails](https://github.com/theupdateframework/tuf-conformance/blob/main/clients/go-tuf/go-tuf.xfails)
- tuf-js: `test_mldsa_keytype_and_scheme` ("ML-DSA key schemes are not supported by tuf-js") — [tuf-conformance.xfails](https://github.com/theupdateframework/tuf-js/blob/main/.github/scripts/tuf-conformance.xfails)
- sigstore-java: 22 entries — [tuf-cli-server.xfails](https://github.com/sigstore/sigstore-java/blob/main/tuf-cli/tuf-cli-server.xfails)
  - `test_metadata_bytes_match`
  - 4× `test_unusual_role_name`
  - `test_static_repository[tuf-on-ci-0.11]`
  - all 12 `test_graph_traversal[...]` cases, so delegation graphs are not supported
  - 4× `test_targetfile_search[...]`
- sigstore-rust: none — [conformance.xfails](https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-tuf/conformance.xfails)

**Bugs and CVEs found**
- CVE-2024-47534 / GHSA-4f8r-qqr9-fq8j (High), go-tuf ≤ v2.0.0.
  - Flaw: `GetRolesForTarget` returned a Go map, so delegations were traced in nondeterministic order and the client "could result in downloading the wrong artifact".
  - Found while developing `test_graph_traversal` in [tuf-conformance PR #115](https://github.com/theupdateframework/tuf-conformance/pull/115): CI failures were flaky. Reporter: AdamKorcz (Ada Logics). Published 2024-10-01.
  - Source: [advisory](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-4f8r-qqr9-fq8j)
- go-tuf issue #759 (cached delegated role not re-verified against the current delegator) is still tracked as an xfail in go-tuf — [go-tuf xfails](https://github.com/theupdateframework/go-tuf/blob/master/.github/scripts/tuf-conformance-client.xfails)
- Clients disagree on duplicate keyids and on keyids without a matching key, both still-open issues — [#143](https://github.com/theupdateframework/tuf-conformance/issues/143), [#144](https://github.com/theupdateframework/tuf-conformance/issues/144)

**Talks and blogs**
- SigstoreCon 2024: "Sigstore & TUF Conformance Testing: Are Clients Playing by the Rules?" by Adam Korczynski (Ada Logics) and Jussi Kukkonen (Google). They "shared how conformance testing suites help identify security vulnerabilities and maintain ecosystem compatibility". Only the general [SigstoreCon playlist](https://www.youtube.com/playlist?list=PLM6mY5TOhY1E02_fQWqfQk_gMRHHtX0q6) is linked — [OpenSSF blog](https://openssf.org/blog/2024/12/16/sigstorecon-2024-advancing-software-supply-chain-security/)
- The README links no talk, paper, or blog — [README](https://github.com/theupdateframework/tuf-conformance/blob/main/README.md)

**Coverage gaps the project itself acknowledges (open issues and PRs on 2026-10-31)** — [issues list](https://github.com/theupdateframework/tuf-conformance/issues)
- Expired delegated role: [#184](https://github.com/theupdateframework/tuf-conformance/issues/184), and [PR #429](https://github.com/theupdateframework/tuf-conformance/pull/429) "Test expiry of delegated targets metadata", still open.
- Succinct delegations, TAP 15: [#127](https://github.com/theupdateframework/tuf-conformance/issues/127).
- Optional features: [#33](https://github.com/theupdateframework/tuf-conformance/issues/33).
- Key types and schemes: [#159](https://github.com/theupdateframework/tuf-conformance/issues/159), [#65](https://github.com/theupdateframework/tuf-conformance/issues/65).
- Multiple hash algorithms: [#174](https://github.com/theupdateframework/tuf-conformance/issues/174).
- "Add option to persist temp local cache": [#231](https://github.com/theupdateframework/tuf-conformance/issues/231).
- A 2024 issue "investigate performance" is closed — [#44](https://github.com/theupdateframework/tuf-conformance/issues/44).

**Clients NOT in tuf-conformance**
- rust-tuf: issue "Integrating tuf-conformance" is open — [rust-tuf #410](https://github.com/theupdateframework/rust-tuf/issues/410)
- php-tuf: "consider using tuf-conformance for testing" is open — [php-tuf #384](https://github.com/php-tuf/php-tuf/issues/384)
- awslabs/tough: an issue search for "conformance" found only an unrelated TAP 12 PR — [tough PR #944](https://github.com/awslabs/tough/pull/944)

**Prior calls for exactly this kind of cross-implementation testing**
- The X41 D-Sec audit of go-tuf for OSTIF (2023-02-27 to 2023-03-10, report 2023-05-31) describes differential fuzzing: "Run implementation A and B individually on the input generated… Compare the results". It says "Due to the time available, a differential fuzzing approach could not be implemented. Such an implementation would need to involve a program that is executing the two implementations individually on the same TUF repository and staging data and perform a comparison afterwards." Findings were GOTUF-CR-23-01 (key reuse allows a cut-and-paste attack) and GOTUF-CR-23-02 (symbolic link attacks during commit) — [X41 report §4.2.3](https://x41-dsec.de/static/reports/X41-go-tuf-Audit-2023-Final-Report-PUBLIC.pdf)
- The OSTIF PHP-TUF assessment (Oct–Nov 2023) found two cross-implementation issues — [OSTIF report](https://ostif.org/wp-content/uploads/2024/01/OSTIF-2023-Q3-PHP-TUF-Multi-Final-Report-Updated-v2.pdf):
  - M1 "Path Traversal in Delegated Role Metadata". The same bug class was earlier CVE-2021-41131 in python-tuf.
  - L2 "Canonical JSON Encoding Differential" vs python-tuf. Impact: "different TUF implementations could produce mutually incompatible metadata files".

### Inferences
- **Not covered at the network level.** The server always returns complete bodies with correct `Content-length`, and no test is named for slow retrieval, endless data, or freeze at the transport level. `ClientRunner` sets no per-command timeout (grep found none in `client_runner.py`). So TUF's endless-data and slow-retrieval attacks are not exercised. Freeze attacks are covered only through metadata expiry plus faketime. Mix-and-match is covered only indirectly, through the snapshot/targets hash and version mismatch tests.
- **Not covered for persistence or crash safety.** The client is never killed mid-write. No test checks atomic metadata writes or recovery from a torn local `root.json`. Issue #231 is about persisting the cache for debugging, not crash safety.
- **Not covered beyond TUF.** There is no installation, A/B switch, boot, or rollback-on-boot testing. Uptane concepts (Director, multiple repositories, ECU manifests, TAP-4 map file) are absent, and so is SUIT.
- **Not covered in delegation depth and scale.** Graphs are small, three levels at most. There is no stress test on delegation depth or count, no succinct-delegation test, and no performance or resource metric.
- **Limited to localhost HTTP.** There is no TLS, no mirrors, and no proxies.
- **Pass/fail only.** Results are per test. There is no scoring, no severity weighting, and no cross-client differential comparison beyond side-by-side pass rates.
- **The adapter idea transfers directly.** The CLI contract plus observable state (exit code, metadata-dir, target-dir, request log) is exactly the pattern to generalize to Uptane, SUIT, and A/B updaters.

### Gaps
- No slide deck or transcript was found for the SigstoreCon 2024 talk, and no PackagingCon or KubeCon talk dedicated to tuf-conformance was found.
- The names of tuf-js's 3 xfailed parametrizations were not visible on the report page. The xfails file lists only `test_mldsa_keytype_and_scheme`, which presumably has 3 parameters (inference).
- A search snippet claimed a no_std Rust client ("kaituf") runs tuf-conformance — [dane1599d/kernel-ai PR #242](https://github.com/dane1599d/kernel-ai/pull/242). UNVERIFIED. The same snippet said python-tuf xfails a test, which contradicts the report's 0 xfails for python-tuf.
- A search summary attributed a diamond-delegation cached-metadata bug to tuf-js. UNVERIFIED. The primary source found (the xfails file) ties it to go-tuf #759.

## Q2. TUF implementations: list and status (late 2026)

### Takeaway
Four TUF clients are actively maintained and conformance-tested: python-tuf, go-tuf v2, tuf-js, and the sigstore-* language clients. awslabs/tough (Rust, used by Bottlerocket) is active but not in tuf-conformance, which makes it the clearest "new adapter" contribution. rust-tuf stays beta, php-tuf is stagnant, and Notary v1 is archived.

### Cited Findings

| Implementation | Language | Latest release | Status / notes | Source |
|---|---|---|---|---|
| python-tuf (ngclient) | Python | v7.0.1 (2026-09-01) | Active (last push 2026-10-19); reference client; 100% conformance | [releases](https://github.com/theupdateframework/python-tuf/releases) |
| go-tuf v2 | Go | v2.4.2 (2026-05-19) | Active (push 2026-10-28) | [releases](https://github.com/theupdateframework/go-tuf/releases) |
| tuf-js | TypeScript | tuf-js@6.0.1 (2026-10-29) | Active; bumped to suite v2.5.0 in [PR #1018](https://github.com/theupdateframework/tuf-js/pull/1018) | [releases](https://github.com/theupdateframework/tuf-js/releases) |
| tough | Rust | tough-v0.24.0 / tuftool-v0.17.0 (2026-07-10) | Active (push 2026-09-25); crates.io `tough` 0.24.0. Its README says integration tests need `noxious`, a network-fault proxy | [releases](https://github.com/awslabs/tough/releases), [README](https://github.com/awslabs/tough), [crates.io](https://crates.io/crates/tough) |
| rust-tuf | Rust | no GitHub releases; crates.io `tuf` 0.3.0-beta9 (updated 2025-10-20) | README: "Warning: Beta Software… may not suitable for production use"; last push 2026-08-24 | [repo](https://github.com/theupdateframework/rust-tuf), [crates.io](https://crates.io/crates/tuf) |
| php-tuf | PHP | 0.1.6 (2024-07-09) | Low activity (last push 2026-04-23); audited by OSTIF in 2023 | [releases](https://github.com/php-tuf/php-tuf/releases) |
| sigstore-java (TUF client, `tuf-cli`) | Java | v2.4.0 (2026-10-21) | Active; 22 xfails (no delegation graphs) | [releases](https://github.com/sigstore/sigstore-java/releases) |
| sigstore-rust (`sigstore-tuf` crate) | Rust | sigstore-verify-v0.15.1 (2026-10-23) | Active; 100% conformance, 0 xfails | [repo](https://github.com/sigstore/sigstore-rust) |
| sigstore-rs (older crate) | Rust | v0.14.0 (2026-05-22) | Active, but not in the conformance report | [releases](https://github.com/sigstore/sigstore-rs/releases) |
| sigstore-ruby | Ruby | v0.2.3 (2026-03-10) | Runs tuf-conformance v2.3.0 in CI; no data in report | [ci.yml](https://github.com/sigstore/sigstore-ruby/blob/main/.github/workflows/ci.yml) |
| Repository Service for TUF (RSTUF), server side | Python | v1.0.1 (2025-08-29) | Active (push 2026-10-23) | [releases](https://github.com/repository-service-tuf/repository-service-tuf/releases) |
| Notary v1 | Go | v0.6.1 (2018-04-10) | ARCHIVED (GitHub `archived=true`) | [repo](https://github.com/notaryproject/notary) |
| uptane/ota-tuf (TUF server in Scala) | Scala | v6.1.0 (2026-04-27) | Active (push 2026-10-31); server side | [releases](https://github.com/uptane/ota-tuf/releases) |

### Inferences
- tough is the best non-tested TUF client to add: Rust, production use, and no adapter exists. rust-tuf and php-tuf are also untested (open issues #410 and #384) but are weaker candidates because of their beta and stagnant status.
- A thesis can call "first tuf-conformance run against tough" a concrete contribution. Check tough's issue tracker once more before claiming it, because absence of evidence comes from a single issue search.

### Gaps
- No maintained "tuf-c / libtuf" for embedded Linux or MCUs was found. The closest artifact is `uptane/uptiny` (C, last push 2022-04-22, no README at the default path) — [uptane org](https://github.com/orgs/uptane/repositories). UNVERIFIED as to its functionality.
- The Bottlerocket dependency on tough was not re-verified in this session. UNVERIFIED, but widely known.

## Q3. Uptane: implementations and conformance efforts

### Takeaway
Two open-source Uptane clients exist: aktualizr (`uptane/aktualizr`, C++) and Foundries' aktualizr-lite, both built on libaktualizr. The server side is the Scala stack (ota-tuf, director, OTA Community Edition). No executable official Uptane conformance suite exists today. The official test plan repo is archived, the old `tuf-test-vectors` server was last pushed in 2022, and the commercial route is SwRI compliance testing.

### Cited Findings
- **aktualizr** (`uptane/aktualizr`): "C++ implementation of Uptane OTA update client".
  - Last GitHub release 2020.10 (2020-10-27), but the repo is still pushed (2026-06-28) and not archived.
  - Usually built through the Yocto `meta-updater` layer. The README points at HERE OTA Connect as a server.
  - Sources: [README](https://github.com/uptane/aktualizr), [releases](https://github.com/uptane/aktualizr/releases), [meta-updater](https://github.com/uptane/meta-updater)
- **aktualizr's own test infrastructure** — [tests/](https://github.com/uptane/aktualizr/tree/master/tests):
  - Fake Uptane/HTTP servers in Python: `fake_http_server/fake_uptane_server.py`, `fake_test_server.py`.
  - A `tuf-test-vectors` submodule run by `run_vector_tests.sh`. The script generates vectors with `generator.py`, starts the vector server, and runs `aktualizr_uptane_vector_tests` (optionally under valgrind) — [run_vector_tests.sh](https://github.com/uptane/aktualizr/blob/master/tests/run_vector_tests.sh)
  - Failure tests: `test_director_failure.py`, `test_imagerepo_failure.py`, `test_treehub_failure.py`, `test_customrepo_failure.py`.
  - `test_aktualizr_kill.py` sends SIGKILL to the daemon — [test_aktualizr_kill.py](https://github.com/uptane/aktualizr/blob/master/tests/test_aktualizr_kill.py)
  - `test_io_failure.py` runs "provisioning and update cycles with random IO failures, then retry… and make sure the second attempt succeeds". It uses syscall-failure probability 0.00025 (about 1 fault per run of ~4000 IO syscalls) and the coupon-collector bound of ~50000 runs. The tree also contains `fiuinfo_test.cc`, which suggests libfiu — [test_io_failure.py](https://github.com/uptane/aktualizr/blob/master/tests/test_io_failure.py)
- **aktualizr-lite** (Foundries.io), C++, "The Foundries.io update agent based on libaktualizr". Latest v98 (2026-10-22), active — [releases](https://github.com/foundriesio/aktualizr-lite/releases)
- **Server side:**
  - `uptane/ota-tuf` (Scala) v6.1.0 (2026-04-27) — [releases](https://github.com/uptane/ota-tuf/releases)
  - `uptane/director` (Scala), pushed 2026-10-29 — [repo](https://github.com/uptane/director)
  - `uptane/ota-community-edition`, "Configuration and charts for deploying Uptane services", pushed 2026-01-08, no releases — [repo](https://github.com/uptane/ota-community-edition)
  - `ota-device-registry` is ARCHIVED — [uptane org](https://github.com/orgs/uptane/repositories)
- **Reference implementation:** `uptane/obsolete-reference-implementation` (Python) is ARCHIVED and labelled "⚠️ Obsolete". Last tag "sept_deliverable" (2017-09-21) — [repo](https://github.com/uptane/obsolete-reference-implementation)
- **Official test plan:** `uptane/uptane-test` is ARCHIVED (archived 2024-02-09 per search result; last push 2019-11-21).
  - Goal: "a framework for verifying that an implementation meets all of the MUSTs and SHALLs".
  - Non-goals: it confers no certification, and it excludes SHOULDs and MAYs.
  - It is a document, not an executable suite.
  - Sources: [repo](https://github.com/uptane/uptane-test), [search result on archive date](https://github.yxlr123.workers.dev/uptane/uptane-test)
- **tuf-test-vectors** (`uptane/tuf-test-vectors`, Python, HERE Europe 2017–2020, last push 2022-05-25). An HTTP server (`server.py`) with a step protocol — [README](https://github.com/uptane/tuf-test-vectors):
  - `GET /` lists vectors.
  - `POST /<vector>/step` returns the expected `update.is_success` and per-target `is_success` / `err` / `err_msg`.
  - The client updates and compares, then steps again until HTTP 204. `POST /<vector>/reset` resets a vector.
  - It is "a collection of test vectors that can be used to verify if a TUF or Uptane client conforms". This is the direct predecessor of tuf-conformance's approach, with the client driving the server instead of the reverse.
- **POUFs:** `uptane/POUFs` holds interoperability profiles. A POUF "precisely specifies the wireline format and operations", because "the framework does not specify data binding formats… Uptane can not guarantee interoperability" — [POUFs README](https://github.com/uptane/POUFs)
- **Standard:** Uptane Standard 2.1.0 (2023-06-23) is the latest release — [releases](https://github.com/uptane/uptane-standard/releases). Version 2.1.0 uses SHALL for conformance requirements — [Uptane 2.1.0 standard](https://uptane.org/docs/2.1.0/standard/uptane-standard)
- **Commercial compliance testing:** Southwest Research Institute offers tiered Uptane compliance testing. Deliverables include a compliance report, code analysis, TARA, and a pentest — [SwRI](https://www.swri.org/node/13402576) (from a search snippet; page not fetched)
- **Academic security testing of Uptane:**
  - "A formal framework for security testing of automotive over-the-air update systems" (JLAMP): CSP models of Uptane plus an attack model generate test cases that run on an Uptane testbed — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2352220822000657), [Coventry pure portal](https://pureportal.coventry.ac.uk/en/publications/a-formal-framework-for-security-testing-of-automotive-over-the-ai/)
  - "Systematic threat assessment and security testing of automotive over-the-air (OTA) updates": attack-tree based test generation — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2214209622000158). The page returned 403; content comes from the search snippet.

### Inferences
- An Uptane harness can reuse aktualizr's own fixtures (fake_uptane_server, uptane-generator for repo creation) to build an adapter. Black-box drive: point the config at a local simulated Director plus Image repo, run one update cycle (`aktualizr once` or the test binary `aktualizr-cycle-simple`), and observe the exit code, the SQL storage, and the installed target.
- aktualizr-lite shares libaktualizr, so adding it adds little implementation diversity. It is useful only as "same core, different policy" (Foundries uses only the TUF image repo, no Director).
- The academic Uptane testing papers target a single implementation and model-based generation, not cross-ecosystem comparison.

### Gaps
- The CSCS 2025 (Bucharest) paper reportedly pentesting OTA Community Edition was mentioned in a search summary without a clear URL. UNVERIFIED.
- The status of HERE OTA Connect, Airbiquity OTAmatic, and other commercial Uptane products was not researched (UNVERIFIED). They are closed source and not candidates for a black-box OSS benchmark anyway.
- `uptane/libuptiny` does not exist (API 404). The embedded C code is at `uptane/uptiny` (last push 2022). UNVERIFIED as to completeness.

## Q4. IETF SUIT: implementations, test vectors, interop, conformance suite

### Takeaway
The SUIT manifest draft (draft-ietf-suit-manifest-37) is in the RFC Editor queue, not yet an RFC. Open implementations are few: libcsuit (C), RIOT's SUIT module (based on an old draft, v9), Nordic's suit-generator and suit-processor, and Arm's stale suit-manifest-generator. Nordic removed SUIT from nRF54H20 in NCS v3.1.0. No SUIT conformance suite was found. The draft's Appendix B examples and libcsuit's test files serve as de facto test vectors.

### Cited Findings
- draft-ietf-suit-manifest-37 (18 June 2026). IESG state "RFC Ed Queue", RFC Editor "Awaiting Reference Checker, formatting", intended Proposed Standard, no RFC number yet.
  - Appendix B has six examples (secure boot, simultaneous download and install, A/B images, external storage, two images).
  - "Additional resources" lists libcsuit and two Python manifest generators.
  - Source: [datatracker](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/)
- draft-ietf-suit-trust-domains-12 was approved as Proposed Standard. The announcement lists libcsuit as an implementation — [IETF-announce](https://www.mail-archive.com/ietf-announce@ietf.org/msg25822.html)
- **libcsuit** (`kentakayama/libcsuit`, C): latest v1.0.2 (2026-02-06), with v1.0.0 on 2025-12-23 — [releases](https://github.com/kentakayama/libcsuit/releases)
  - Parses, executes, and reports. Also signs or MACs, encrypts and decrypts payloads, and encodes.
  - Implements suit-manifest-34, trust-domains-12, update-management-10, firmware-encryption-26, and report-18.
  - Uses QCBOR, a forked t_cose, and OpenSSL or Mbed TLS.
  - "Tested SUIT Manifests are found in testfiles/README.md". The companion encoder is [kentakayama/suit-manifest-generator](https://github.com/kentakayama/suit-manifest-generator).
  - Source: [README](https://github.com/kentakayama/libcsuit)
- **RIOT OS SUIT** (`sys/suit`): "The current implementation of this specification is based on the IETF-SUIT-v9 draft" — [RIOT API docs](https://api.riot-os.org/group__sys__suit.html)
  - The Berlin 2020 hackathon report covers the full workflow (manifest generation → CoAP transfer → verification → install on nRF52840dk) — [slides](https://datatracker.ietf.org/meeting/interim-2020-suit-01/materials/slides-interim-2020-suit-01-sessa-riot-hackaton-report-00)
  - The RIOT wiki documents an IETF 104 hackathon harness — [wiki](https://github.com/RIOT-OS/RIOT/wiki/SUIT-compliant-RIOT-firmware-support)
  - RIOT latest is 2026.10-RC3 (2026-10-29) — [releases](https://github.com/RIOT-OS/RIOT/releases)
- **Nordic:** "SUIT support is removed in the nRF Connect SDK v3.1.0". The nRF54H20 Secure Domain now runs IronSide SE, and DFU goes through MCUboot in the local domain. Devices provisioned with SUIT in LCS RoT cannot go back — [NCS migration guide 3.0→3.1](https://nrfconnectdocs.nordicsemi.com/ncs/latest/nrf/releases_and_maturity/migration/migration_3.1_54h_suit_ironside.html), [NCS 3.2 migration](https://nrfconnectdocs.nordicsemi.com/ncs/latest/nrf/releases_and_maturity/migration/migration_guide_3.2.html)
  - The Nordic repos still exist: [nrfconnect/suit-generator](https://github.com/nrfconnect/suit-generator) (Python) and [nrfconnect/suit-processor](https://github.com/nrfconnect/suit-processor) (C), both last pushed 2026-04-24.
- **Arm** `ARMmbed/suit-manifest-generator`: last push 2022-11-05, effectively stale — [repo](https://github.com/ARMmbed/suit-manifest-generator)
- **SUIT WG GitHub:**
  - Active: manifest-spec, suit-report, suit-update-management, firmware-encryption, multiple-trust-domains, suit-mti.
  - Old interop artifacts: `Hackathon-Interim-Berlin` (2019), `SUIT-repository-manager` (Python, 2018), `mbed-libcose` (2018).
  - No conformance or test-suite repo.
  - Sources: [suit-wg org](https://github.com/orgs/suit-wg/repositories), [Hackathon-Interim-Berlin](https://github.com/suit-wg/Hackathon-Interim-Berlin)
- **Interop at IETF hackathons:** the TEEP hackathon 115 found an interop issue on SUIT_Envelope vs SUIT_Envelope_Tagged — [teep-protocol #273](https://github.com/ietf-teep/teep-protocol/issues/273)
- **Academic baseline:** Zandberg, Schleiser, Acosta, Tschofenig, Baccelli, "Secure Firmware Updates for Constrained IoT Devices Using Open Standards: A Reality Check", IEEE Access 7 (2019), 71907–71920, DOI 10.1109/ACCESS.2019.2919760. It gives first SUIT experiments on RIOT and shows feasibility in under 32 kB RAM and 128 kB flash — [IEEE Xplore](https://ieeexplore.ieee.org/abstract/document/8725488), [HAL](https://hal-univ-tlse3.archives-ouvertes.fr/INRIA/hal-02351794)
- **OSS-Fuzz:** no project named `libcsuit`, `suit`, `riot`, or `zephyr` (404 on `projects/<name>/project.yaml`) — [oss-fuzz projects](https://github.com/google/oss-fuzz/tree/master/projects)

### Inferences
- A SUIT adapter on Linux is most feasible with libcsuit's `examples/process`: feed it an envelope plus payloads and observe the exit code, the generated SUIT report, and the written payload.
- RIOT `native` (a Linux process) is a second, independent SUIT processor. It is from an older draft, which is itself a finding for interop and differential testing.
- Appendix B examples, plus attack variants (bad signature, sequence-number rollback, digest mismatch, wrong vendor/class ID), are a natural SUIT test corpus.

### Gaps
- No formal SUIT interop report document (IETF hackathon wiki results) for 2024–2026 was found.
- TF-M SUIT support was not found or verified. TF-M implements the PSA Firmware Update API rather than SUIT (UNVERIFIED).
- Whether RIOT's SUIT has been updated beyond draft v9 in 2026 is unclear. The docs string may be stale.

## Q5. Linux updaters (RAUC, SWUpdate, Mender, OSTree, swupd, hawkBit, balena, Memfault): status, own test suites, fuzzing

### Takeaway
RAUC, SWUpdate, Mender, and OSTree are all actively maintained C/C++ projects. Each tests itself in isolation:
- RAUC: GLib and pytest tests inside a QEMU runner.
- SWUpdate: cmocka unit tests.
- Mender: a large Docker/QEMU integration suite with network-fault tests.
- OSTree: shell-based tests.

Only RAUC, OSTree, fwupd, and casync are in OSS-Fuzz. None of these projects runs a shared security or robustness benchmark, and none runs attack scenarios equivalent to TUF's.

### Cited Findings

| Project | Lang | Latest release | Status | Source |
|---|---|---|---|---|
| RAUC | C | v1.15.2 (2026-03-27) | Active (push 2026-10-29) | [releases](https://github.com/rauc/rauc/releases) |
| SWUpdate | C | 2026.05.1 (2026-06-22) | Active (push 2026-10-30) | [releases](https://github.com/sbabic/swupdate/releases) |
| Mender client | C++ | 5.2.0 (2026-10-23) | Active | [releases](https://github.com/mendersoftware/mender/releases) |
| Mender server | Go | v4.1.5 (2026-10-23) | Active | [releases](https://github.com/mendersoftware/mender-server/releases) |
| mender-artifact | Go | v4.4.2 (2026-09-07) | Active | [releases](https://github.com/mendersoftware/mender-artifact/releases) |
| OSTree | C | v2026.6 (2026-10-30) | Active | [releases](https://github.com/ostreedev/ostree/releases) |
| Eclipse hawkBit (server) | Java | 1.1.0 (2026-07-03) | Active | [releases](https://github.com/eclipse-hawkbit/hawkbit/releases) |
| balena supervisor / meta-balena | TS / BitBake | v20.0.3 / v9.0.4 (Oct 2026) | Active | [supervisor](https://github.com/balena-os/balena-supervisor/releases), [meta-balena](https://github.com/balena-os/meta-balena/releases) |
| Memfault Linux SDK | C/Rust | 1.30.1 (2026-10-22) | Active | [releases](https://github.com/memfault/memfault-linux-sdk/releases) |
| swupd-client (Clear Linux) | C/Shell | v7.0.0 (2025-04-24) | ARCHIVED (GitHub `archived=true`, last push 2025-08-07) | [repo](https://github.com/clearlinux/swupd-client) |

- **RAUC test suite** — [docs/contributing.rst](https://github.com/rauc/rauc/blob/master/docs/contributing.rst), [qemu-test](https://github.com/rauc/rauc/blob/master/qemu-test):
  - GLib "gtest" unit tests in `test/*.c` (26 C files, named after the module, for example `test/bundle.c`).
  - pytest tests: `test_install.py`, `test_http.py`, `test_mark.py`, `test_verify.py`, `test_encrypt.py`, and others (24 Python files).
  - `qemu-test` runs the whole suite in QEMU "with simulated root privileges to emulate and test virtual devices such as block devices, NAND, etc.". It uses a pinned kernel and passes the host VFS through virtfs with tmpfs overlays.
  - Modes: `shell`, `system` ("dummy system that behaves like a target (without reboot!)"), `asan`, `ssh`, `test=<name>`.
  - Fuzzers live in `fuzz/` (`bundle.c`, `manifest.c` with corpora) — [fuzz/](https://github.com/rauc/rauc/tree/master/fuzz). RAUC is in OSS-Fuzz (`projects/rauc`, main_repo rauc/rauc) — [oss-fuzz rauc](https://github.com/google/oss-fuzz/tree/master/projects/rauc)
- **SWUpdate test suite** — [test/](https://github.com/sbabic/swupdate/tree/master/test), [CI workflow](https://github.com/sbabic/swupdate/blob/master/.github/workflows/ci_tests.yml):
  - Unit tests in `test/`: `test_cpio_utils.c`, `test_crypt.c`, `test_crypt_pkcs11.c` (SoftHSM token), `test_verify.c`, `test_parser.c`, `test_installer.c`, `test_handlers.c`, `test_flash_handler.c`, `test_mender_artifact.c`, `test_server_hawkbit.c`, `test_stream_interface.c`, and others.
  - CI scripts: `ci/test-configs.sh`, `ci/coverity.sh`.
  - No `fuzz` directory in the tree, and no OSS-Fuzz project named `swupdate` (404).
- **Mender integration tests** (`mendersoftware/integration`, pytest, 33 files under `tests/tests/`) — [tests dir](https://github.com/mendersoftware/integration/tree/master/tests/tests), [test_fault_tolerance.py](https://github.com/mendersoftware/integration/blob/master/tests/tests/test_fault_tolerance.py):
  - `test_fault_tolerance.py`: `test_update_image_breaks_networking`, `test_deployed_during_network_outage`, `test_image_download_retry_timeout`, `test_image_download_retry_download_count`, `test_image_download_retry_hosts_broken`, `test_rootfs_conf_missing_from_new_update`.
  - `test_signed_image_update.py`: `test_signed_artifact_success`, `test_unsigned_artifact_fails_deployment`.
  - `test_image_update_failures.py`: `test_update_image_id_already_installed`, `test_large_update_image`.
  - Others: `test_state_scripts.py`, `test_update_modules.py`, `test_security.py` (token expiration), `test_mtls.py`.
  - These are full-stack (server plus client in Docker or QEMU), not black-box adapters.
- **OSS-Fuzz presence** (HTTP 200 vs 404 on `projects/<name>/project.yaml`, checked 2026-10-31) — [oss-fuzz projects](https://github.com/google/oss-fuzz/tree/master/projects):
  - PRESENT: rauc, ostree, fwupd, casync, u-boot, libarchive, notary (main_repo notaryproject/notary, which is archived), sigstore and sigstore-go (main_repo github.com/sigstore/sigstore).
  - ABSENT under these names: tuf, python-tuf, go-tuf, tuf-js, tough, rust-tuf, swupdate, mender, mender-client, mcuboot, libcsuit, suit, zephyr, riot, hawkbit, aktualizr, uptane, swupd, zchunk.
- **Prior comparisons are qualitative, not executable:**
  - Yocto wiki "System Update" comparison table — [Yocto wiki](https://wiki.yoctoproject.org/wiki/System_Update)
  - Leon Anavi, FOSDEM 2025, "Exploring Open Source Dual A/B Update Solutions for Embedded Linux" — [slides](https://archive.fosdem.org/2025/events/attachments/fosdem-2025-6299-exploring-open-source-dual-a-b-update-solutions-for-embedded-linux/slides/237879/leon-anav_pyytRpX.pdf)
  - embedded.com comparison — [article](https://www.embedded.com/ota-updates-for-embedded-linux-part-2-a-comparison-of-off-the-shelf-update-systems/)

### Inferences
- **Black-box drive.** RAUC (`rauc install <bundle>` + `rauc status`), SWUpdate (`swupdate -i <file.swu> -k <pubkey>`), and Mender (standalone `mender-update install <artifact>`) can all be driven from a CLI inside a QEMU guest. Observe the exit code, the slot or bootloader state (grubenv / U-Boot env), and which slot boots after a reboot or power cut. These CLI names come from general knowledge and were not re-verified this session — UNVERIFIED.
- **Malicious inputs.** These updaters verify a signed bundle or artifact, not a TUF/Uptane metadata graph. A cross-ecosystem benchmark therefore needs per-ecosystem malicious inputs: tampered payload, bad or absent signature, downgrade (version/compatible field), truncated or oversized image, wrong hardware compatibility.
- **Power loss.** It is not systematically tested in any of these suites. RAUC `qemu-test system` explicitly runs "without reboot!". Mender's fault tests are about networking, not power.

### Gaps
- Mender's power-loss and rollback acceptance tests (expected in `meta-mender/tests/acceptance`) could not be located at the guessed path. UNVERIFIED.
- No source was fetched for the Clear Linux OS end-of-life (2025) beyond the archived swupd repo. UNVERIFIED.
- The hawkBit device-simulator and test tooling were not researched.

## Q6. MCUboot / Zephyr test infrastructure (power-fail injection prior art)

### Takeaway
The MCUboot simulator (`sim/`, Rust) is the strongest existing prior art for exhaustive power-loss testing. It compiles the real MCUboot C code against a simulated flash. It first counts the flash operations of a clean upgrade, then interrupts the upgrade at every operation index 1..N (or at random indices), reboots, and checks the image and trailer invariants. It is limited to one bootloader and to the swap/upgrade logic. It has no network, no metadata attacks, and no cross-project scope.

### Cited Findings
- "This is a small simulator designed to exercise the mcuboot upgrade code, specifically testing untimely reset scenarios to make sure the code is robust." It is written in Rust, run with `cargo test`, and features select variants such as `--features sig-rsa` — [sim/README.rst](https://github.com/mcu-tools/mcuboot/blob/main/sim/README.rst)
- **Mechanism** — [sim/src/image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs):
  - Image setup runs `run_basic_upgrade` first ("upgrades without fails, counts number of flash operations") and stores `total_count`.
  - `try_upgrade(stop: Option<i32>, …)` clones the flash and calls the C `boot_go(&mut flash, …, Some(&mut counter))`. If the call returns `interrupted()`, it calls `boot_go` again ("Shouldn't stop again").
  - `run_perm_with_fails` loops `for i in 1 .. total_flash_ops { try_upgrade(Some(i), true) … verify_images … verify_trailers(BOOT_MAGIC_GOOD…) }` and reports "FAIL at step i of N" with a percentage.
  - Other scenarios: `run_perm_with_random_fails(total_fails)`, `run_revert_with_fails`, `try_revert_with_fail_at`, `run_with_status_fails_complete`, `run_with_status_fails_with_reset`.
- **Simulated flash** — [sim/simflash/src/lib.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/simflash/src/lib.rs):
  - Sector-granular erase and `write`. `verify_writes` panics on "Write to unerased location".
  - `add_bad_region(offset, len, rate)` means "writes to this area fail with a chance", which models flaky flash.
- **Test catalogue** — [sim/tests/core.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/tests/core.rs):
  - bad_secondary_slot (bad signature), secondary_trailer_leftover, bootstrap, oversized_bootstrap
  - norevert_newimage, basic_revert, revert_with_fails, perm_with_fails, perm_with_random_fails(5), norevert
  - oversized_secondary_slot, wrong_load_addr, status_write_fails_complete, status_write_fails_with_reset
  - downgrade_prevention, direct_xip_first, ram_load_*, hw_prot_missing_security_cnt, hw_prot_failed_security_cnt_check, and others
- On-hardware Zephyr testing is a semi-manual test plan (`samples/zephyr`, `run-tests.sh` with "y or n" prompts, FRDM-K64F) — [docs/testplan-zephyr.md](https://github.com/mcu-tools/mcuboot/blob/main/docs/testplan-zephyr.md)
- MCUboot latest release is v2.5.0 (2026-10-22). Repo: C, 2177 stars, active — [releases](https://github.com/mcu-tools/mcuboot/releases)
- Zephyr: 4.5.0 (2026-10-28) and 4.3.2 (2026-10-30) — [releases](https://github.com/zephyrproject-rtos/zephyr/releases)
- No OSS-Fuzz project named `mcuboot` or `zephyr` (404) — [oss-fuzz projects](https://github.com/google/oss-fuzz/tree/master/projects)

### Inferences
- The "count operations, then interrupt at every k" pattern can be generalized to Linux updaters. Count block writes (QEMU block trace, NBD, or a dm-flakey / dm-log-writes target), cut power at write k by killing QEMU or dropping the overlay, reboot, and check that the system boots either the old or the new version, never neither. This turns MCUboot's in-process technique into a black-box technique and is a clear methodological contribution.
- aktualizr's `test_io_failure.py` (random syscall failure with a probability) is a second, coarser prior art for client-side crash or IO faults.

### Gaps
- MCUboot's sim CI matrix (how many feature combinations run in GitHub Actions) was not inspected.

## Q7. Does ANY cross-ecosystem OTA test bench or benchmark exist?

### Takeaway
None was found. Every existing suite is single-ecosystem (tuf-conformance, sigstore-conformance, tuf-test-vectors, the Uptane test plan) or single-project (MCUboot sim, RAUC qemu-test, Mender integration, aktualizr fault tests). Academic work is either model-based testing of Uptane alone or feasibility studies (SUIT on RIOT). The closest 2026 items are an engrXiv method preprint (hardware-in-the-loop, no tool, no named implementations) and a single-updater QEMU teaching lab (RAUC). An executable, adapter-based, cross-ecosystem benchmark (TUF + Uptane + SUIT + A/B updaters) with network and power-loss fault injection appears to be a genuine gap.

### Cited Findings
- **Auditors call for differential testing:**
  - The X41 go-tuf audit (2023) recommends differential testing between TUF implementations "on the same TUF repository and staging data", but did not implement it — [X41](https://x41-dsec.de/static/reports/X41-go-tuf-Audit-2023-Final-Report-PUBLIC.pdf)
  - OSTIF's PHP-TUF assessment (2023) documents cross-implementation canonical-JSON differentials — [OSTIF](https://ostif.org/wp-content/uploads/2024/01/OSTIF-2023-Q3-PHP-TUF-Multi-Final-Report-Updated-v2.pdf)
- **engrXiv preprint (2026-10-29)** — [engrXiv 8657](https://engrxiv.org/preprint/view/8657):
  - Manvith Dharavath, "Testing the Interrupted Update: A Fault-Injection Method for Verifying Recovery in Automotive Over-the-Air Software Updates", DOI 10.31224/8657.
  - Proposes a method combining "controlled interruption points, fault types, vehicle-state conditions, and evidence requirements into repeatable test cases" with a HIL arrangement.
  - Names no specific OTA client or standard and releases no tool.
- **`chubuchnyi/qemu-ota-recovery-lab`** (Python, created 2026-09-15, 4 stars) — [repo](https://github.com/chubuchnyi/qemu-ota-recovery-lab):
  - "Hands-on QEMU lab for signed A/B OTA, rollback, power-cut testing, and RAM-only recovery".
  - Setup: x86_64 QEMU, OVMF Secure Boot, GRUB, dm-verity, RAUC.
  - `make test-e2e` runs 16 scenarios "from signed OTA and power loss to one-bit tampering".
  - It covers a single updater (RAUC) and is a learning lab.
- **Automotive Uptane security testing** is model-based and single-implementation — [JLAMP formal framework](https://www.sciencedirect.com/science/article/pii/S2352220822000657), [threat assessment paper](https://www.sciencedirect.com/science/article/pii/S2214209622000158)
- **SUIT feasibility work** is on RIOT only — [Zandberg et al. 2019](https://ieeexplore.ieee.org/abstract/document/8725488)
- **ASSURED** (Asokan et al., 2018) is an architecture for secure update of embedded devices, not a benchmark — [arXiv 1807.05002](https://arxiv.org/pdf/1807.05002)
- **Comparisons of Linux A/B updaters** are feature tables and talks, not executable — [Yocto wiki](https://wiki.yoctoproject.org/wiki/System_Update), [FOSDEM 2025 Anavi](https://archive.fosdem.org/2025/events/attachments/fosdem-2025-6299-exploring-open-source-dual-a-b-update-solutions-for-embedded-linux/slides/237879/leon-anav_pyytRpX.pdf)
- **Uptane interoperability** depends on POUFs because "the framework does not specify data binding formats" — [POUFs](https://github.com/uptane/POUFs)

### Inferences
- The thesis can position itself as follows. It generalizes the tuf-conformance black-box CLI adapter idea, which today covers only TUF clients and only metadata logic, into a cross-ecosystem harness. The harness adds:
  - (a) Uptane (aktualizr), SUIT (libcsuit / RIOT native), and A/B updaters (RAUC, SWUpdate, Mender);
  - (b) network-level attacks absent from tuf-conformance (slow retrieval, endless data, freeze via stale but valid metadata, MITM-style substitution);
  - (c) MCUboot-sim-style exhaustive power-cut injection, applied black-box through QEMU;
  - (d) a common, normalized outcome model (accept / reject / brick / rollback) and differential comparison.
- Expect novelty pushback on "power-loss testing" (MCUboot sim, the QEMU lab) and "TUF conformance" (tuf-conformance). The defensible novelty is the cross-ecosystem combination and the unified threat-to-test mapping, not any single technique.

### Gaps
- Searches of ACM DL, USENIX, and NDSS for "OTA benchmark" turned up no direct hit, but coverage of non-English (for example Chinese or Russian) academic literature was not attempted.
- No industry cross-vendor test bench (for example from SwRI, Auto-ISAC, or the Linux Foundation) was found publicly. Absence is not proof.

## Q8. Recommended shortlist of 9–10 implementations for the experiments

### Takeaway
Pick 10 implementations covering 4 specification families and 6 languages, all runnable on Linux or QEMU:
- TUF: python-tuf, go-tuf, tuf-js, tough
- Uptane: aktualizr
- SUIT: libcsuit, RIOT SUIT on `native`
- A/B updaters: RAUC, SWUpdate, Mender

MCUboot (via its sim, or Zephyr/QEMU) is an optional 11th, used as the power-loss methodology baseline. Three TUF clients already have adapters, which validates the harness against tuf-conformance results. tough and everything outside TUF need new adapters, which is the contribution.

### Cited Findings (supporting each pick)
1. **python-tuf ngclient** (Python): reference implementation, 119/119 passes, adapter exists. Status: [python-tuf releases](https://github.com/theupdateframework/python-tuf/releases), [report](https://theupdateframework.github.io/tuf-conformance/), [adapter](https://github.com/theupdateframework/tuf-conformance/blob/main/clients/python-tuf/python_tuf.py)
2. **go-tuf v2** (Go): adapter exists, known xfails, and CVE-2024-47534 history. Status: [go-tuf releases](https://github.com/theupdateframework/go-tuf/releases), [advisory](https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-4f8r-qqr9-fq8j)
3. **tuf-js** (TypeScript/Node): adapter exists at `.github/scripts/tuf-conformance`. Status: [tuf-js workflow](https://github.com/theupdateframework/tuf-js/blob/main/.github/workflows/conformance.yml)
4. **tough** (Rust, awslabs): active (0.24.0, 2026-07-10) and not covered by tuf-conformance, so a new adapter is needed. Status: [tough](https://github.com/awslabs/tough)
5. **aktualizr** (C++, Uptane): the only maintained open Uptane client codebase. It has fake servers and repo generators to reuse. Status: [aktualizr tests](https://github.com/uptane/aktualizr/tree/master/tests)
6. **libcsuit** (C, SUIT): implements the most recent drafts and has test files and examples (process/parser). Status: [libcsuit](https://github.com/kentakayama/libcsuit)
7. **RIOT SUIT** (C, runs as a Linux process on `native`): an independent SUIT processor (draft v9), which makes it a differential-testing target. Status: [RIOT SUIT docs](https://api.riot-os.org/group__sys__suit.html). Alternative: [nrfconnect/suit-processor](https://github.com/nrfconnect/suit-processor), now orphaned by NCS 3.1 ([migration](https://nrfconnectdocs.nordicsemi.com/ncs/latest/nrf/releases_and_maturity/migration/migration_3.1_54h_suit_ironside.html)).
8. **RAUC** (C): bundle-signature-based A/B. It has a QEMU test runner, fuzzers, and is in OSS-Fuzz. Status: [RAUC contributing](https://github.com/rauc/rauc/blob/master/docs/contributing.rst)
9. **SWUpdate** (C): different design (single `.swu` CPIO + sw-description, handlers), no fuzzing in OSS-Fuzz. Status: [SWUpdate](https://github.com/sbabic/swupdate)
10. **Mender client 5.x** (C++): artifact-signature-based, with client/server and rollback via the bootloader. Status: [Mender releases](https://github.com/mendersoftware/mender/releases), [integration tests](https://github.com/mendersoftware/integration/tree/master/tests/tests)
- Optional 11th, **MCUboot** (C): baseline for power-loss methodology via its simulator. Status: [MCUboot sim](https://github.com/mcu-tools/mcuboot/blob/main/sim/README.rst)
- Alternates if one pick fails:
  - sigstore-java or sigstore-rust TUF clients: Java/Rust diversity; adapters exist upstream ([sigstore-java workflow](https://github.com/sigstore/sigstore-java/blob/main/.github/workflows/tuf-conformance.yml)).
  - OSTree: content-addressed, used by aktualizr and Foundries ([OSTree](https://github.com/ostreedev/ostree)).
  - aktualizr-lite ([releases](https://github.com/foundriesio/aktualizr-lite/releases)).

### Inferences
- **Diversity.**
  - Languages: Python, Go, TypeScript, Rust, C++, C.
  - Specifications: TUF metadata, Uptane (Director + Image repo), SUIT (CBOR/COSE manifest), plus signed-bundle A/B models in three styles: RAUC (verity/CMS bundles), SWUpdate (CPIO + sw-description), Mender (artifact v3).
- **Adapter feasibility, from easy to hard:**
  1. TUF clients: the CLI is already defined; tough needs a ~100-line Rust wrapper.
  2. libcsuit: a CLI wrapper around `examples/process`.
  3. aktualizr: config + local simulated Director/Image repo + one update cycle.
  4. RIOT native: needs a tap interface and a CoAP server.
  5. RAUC, SWUpdate, Mender: each needs a QEMU image with A/B partitions and a bootloader (GRUB or U-Boot). They can share one Yocto/QEMU base or Docker images. Power-cut injection kills QEMU at the k-th block write, following MCUboot's count-then-interrupt method.
- **Common outcome model.** Results would be normalized to {accepted-correct, rejected-correct, accepted-malicious (vulnerability), bricked, stale-but-safe}. That enables cross-ecosystem metrics that no existing suite provides.
- **Validation.** Re-running the existing tuf-conformance tests on picks 1–3 through the new harness, and reproducing the published pass rates, validates the harness. CVE-2024-47534 (go-tuf ≤ 2.0.0) can serve as a known-bug regression oracle.

### Gaps
- Exact CLI flags of current Mender (`mender-update`), SWUpdate, RAUC, and aktualizr were not re-verified this session. Check them against each project's docs before writing adapters (UNVERIFIED).
- RIOT `native` SUIT feasibility (tap networking in CI) and libcsuit's `examples/process` exit-code semantics need hands-on checking.
