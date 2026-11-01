# Draft issue for awslabs/tough

> **Status: draft, not posted.** Post only after the author has reviewed it. Found with the
> otabench client suite on tough 0.24.0 (`bench/clients/tough/`, Linux container,
> `bench/results/tough-linux-2026-11-01/`). Both checks are in the tuf-conformance suite or
> follow from the specification; tough is not among tuf-conformance's tested clients.

---

**Title:** Timestamp with an equal version but different content replaces the trusted one; `spec_version` is not checked

**Body:**

We run tough 0.24.0 (library defaults, `RepositoryLoader` with a datastore) through a
tuf-conformance-style client CLI and see two deviations from TUF 1.0.37.

**1. Equal timestamp version.** The repository re-signs `timestamp.json` with the *same* version
but different content (`meta["snapshot.json"].version` changed). TUF 1.0.37 §5.4.3.1 expects
the client to keep its trusted timestamp and stop the update cycle without an error when the
versions are equal; tuf-conformance checks this in `test_timestamp_content_changes`
("client should not persist new timestamp"). tough accepts the new timestamp and writes it to
the datastore: `load_timestamp()` only requires `old_timestamp.signed.version <=
timestamp.signed.version` (`src/lib.rs`, the comment cites TUF v1.0.16). python-tuf 7.0.1,
go-tuf v2.4.2 and tuf-js 6.0.1 keep the trusted timestamp in the same scenario.

Impact is low: the new timestamp must still be signed by the timestamp key.

**2. `spec_version`.** Correctly signed metadata declaring `spec_version` 2.0.0 is accepted and
stored as trusted. The specification requires clients to reject metadata of an unsupported
major version; python-tuf and tuf-js reject it (go-tuf accepts it as well, reported
separately).

Reproduction: otabench scenarios `timestamp-same-version` and `unsupported-spec-version`
(repository simulator from tuf-conformance; link to the repository once public).

---

## Notes for the author (not part of the issue)
* Other results of tough in the same run: all authenticity, freshness and online-key attacks
  rejected, endless data aborted within 0.25–0.58 s, slow retrieval aborted after ~30 s
  (HTTP transport timeout), 15/15 event-based kill points and 10/10 kills during download
  survived; the one-key-under-two-keyids threshold attack is rejected.
* Before posting, check tough's issue tracker for "spec_version" and "equal version".
