# Draft issue for theupdateframework/tuf-conformance

> **Status: draft, not posted.** Post only after the author has reviewed it. Checked on
> 2026-11-01: no existing tuf-conformance issue covers endless data or truncated transfers
> (search "slow OR endless OR timeout"). Related python-tuf discussion: #932 (closed
> 2025-02-20), where maintainers decided that a generic library cannot protect against slow
> retrieval, so this draft deliberately does **not** propose a pass/fail slow-retrieval test.

---

**Title:** Proposal: transport-level tests for endless data and interrupted transfers

**Body:**

tuf-conformance currently attacks clients at the metadata level: every response from the
simulator is a complete HTTP response with a correct `Content-Length`. The specification
also bounds what a client reads from the network:

* §1.5.2 lists *Endless data attacks* among the goals;
* the client workflow bounds every download: 5.3.3 (root, W bytes), 5.4.1 (timestamp,
  X bytes), 5.5.1 / 5.6.1 (snapshot/targets: length from the referring metadata, or Y/Z
  bytes), 5.7.3 (artifact: "up to the number of bytes specified in the targets metadata").

None of the current tests serves a body that is longer than allowed or that has no length at
all, so a client that buffers the whole response before checking it would still pass.

We prototyped these tests in an external harness (same client-under-test CLI, a small HTTP
server wrapper around `RepositorySimulator`) and ran them against python-tuf 7.0.1,
go-tuf v2.4.2 and tuf-js 6.0.1. All three pass. A deliberately naive control client fails the
endless-data tests, and mutants of it (no hash check, keeps a bad file) fail the
interrupted-transfer test. That suggests the tests discriminate and are cheap to keep green:

| Proposed test | Server behaviour | Expectation |
|---|---|---|
| `test_endless_timestamp` | `timestamp.json` streamed without `Content-Length`, never ends | client gives up by itself after at most the configured bound (no unbounded buffering); refresh fails; trusted metadata unchanged |
| `test_endless_unhashed_snapshot` | same for `snapshot.json` when timestamp carries no length | same |
| `test_endless_artifact` | artifact keeps streaming past the length in targets metadata | download fails, nothing longer than the signed length is stored |
| `test_truncated_artifact_then_retry` | connection closed half-way through the artifact once | first download fails, no partial file is reported as success, the next download succeeds with the correct content |

Measured in two runs: clients closed the connection after 0.07–0.64 s, having received
320–960 KiB, mostly socket buffering. The naive control accepted 64 MiB, which was our cap.

Implementation sketch: the simulator server would need an option to stream a body
(chunked or close-delimited) and to close the socket after N bytes. The assertion
"client gave up by itself" can be made on the server side (the client closed the connection
before the cap was reached) rather than with timing, which keeps the tests stable on slow CI
runners.

One more test that does not fit the transport theme but is equally cheap: none of the
current tests serves metadata with an unsupported `spec_version`, although the specification
says clients MUST verify it. In our run go-tuf v2.4.2 accepted a correctly signed timestamp
with `"spec_version": "2.0.0"`, python-tuf and tuf-js rejected it
(`test_unsupported_spec_version_major`: publish timestamp with spec_version "2.0.0", expect
the refresh to fail and the trusted timestamp to stay unchanged).

Out of scope on purpose: slow retrieval. As discussed in python-tuf#932, TUF since v1.0.7
no longer lists it as a goal, and distinguishing an attack from a slow network is
deployment-specific. A purely informational measurement (time until the client gives up when
fed 2 bytes/s) might still be useful for implementers, but not as pass/fail.

Happy to send a PR if this direction is acceptable.

---

## Notes for the author (not part of the issue)

* Numbers come from `bench/results/full-2026-10-31-v2/` (otabench MVP, Windows 11).
  Re-run on Linux before posting.
* The harness code is `bench/otabench/server.py` (`endless`, `truncate` actions). A PR to
  tuf-conformance would reimplement the same in `_internal/simulator_server.py`.
* Do not mention @-handles in the issue; refer to "python-tuf#932".
