# otabench: threat × implementation matrix

Run: 2026-11-01T17:26:34+00:00 · host: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.36 · trials: 10

| Scenario | Threats | python-tuf | tough | naive |
|---|---|---|---|---|
| baseline |  | ✅ | ✅ | ✅ |
| arb-target-substitution | OTA-AUTH-01 | ✅ | ✅ | ✅ |
| arb-metadata-tamper | OTA-AUTH-02 | ✅ | ✅ | ✅ |
| arb-keyid-spoofing | OTA-AUTH-03 | ✅ | ✅ | ✅ |
| freeze-expired-timestamp | OTA-FRESH-01 | ✅ | ✅ | ❌ |
| rollback-timestamp | OTA-FRESH-02 | ✅ | ✅ | ❌ |
| mix-and-match | OTA-FRESH-03 | ✅ | ✅ | ❌ |
| online-keys-downgrade | OTA-KEY-01, OTA-FRESH-02 | ✅ | ✅ | ❌ |
| online-keys-arbitrary | OTA-KEY-02, OTA-AUTH-01 | ✅ | ✅ | ✅ |
| endless-metadata | OTA-DOS-01 | ✅ abort 0.31s, 3.7 MiB | ✅ abort 0.25s, 4.7 MiB | ❌ abort 0.72s, 64.0 MiB |
| endless-artifact | OTA-DOS-02 | ✅ abort 0.42s, 3.1 MiB | ✅ abort 0.58s, 1.7 MiB | ❌ abort 0.64s, 64.0 MiB |
| **slow-metadata** ⚡ | OTA-DOS-03 | ❌ abort 135.01s, 240 B | ✅ abort 30.35s, 60 B | ❌ abort 120.32s, 240 B |
| **slow-artifact** ⚡ | OTA-DOS-04 | ❌ abort 135.01s, 7563 B | ✅ abort 30.56s, 1891 B | ❌ abort 120.25s, 7545 B |
| dropped-connection | OTA-NET-01 | ✅ | ✅ | ✅ |
| powercut-refresh | OTA-PWR-01 | ✅ survived 15/15 kill points (census), recovery 0.305s | ✅ survived 15/15 kill points (census), recovery 0.471s | ✅ survived 15/15 kill points (census), recovery 0.271s |
| powercut-download | OTA-PWR-02 | ✅ survival 100% [72%–100%] (n=10), recovery 0.267s | ✅ survival 100% [72%–100%] (n=10), recovery 0.566s | ❌ survival 0% [0%–28%] (n=10), torn file 10× |
| online-keys-freeze | OTA-KEY-04, OTA-FRESH-01 | ✅ | ✅ | ❌ |
| mirror-errors | OTA-DOS-05 | ✅ | ✅ | ✅ |
| drop-requests | OTA-DOS-06 | ✅ | ✅ | ✅ |
| extra-data-artifact | OTA-AUTH-04 | ✅ | ✅ | ✅ |
| **unsupported-spec-version** ⚡ | OTA-PARSE-02 | ✅ | ❌ | ✅ |
| **timestamp-same-version** ⚡ | OTA-FRESH-02 | ✅ | ❌ | ❌ |
| **threshold-key-twice** ⚡ | OTA-AUTH-03, OTA-KEY-02 | ❌ | ✅ | ❌ |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 16.0/19 | 84% | 3.0/3 | 100% |
| tough | tuf | 17.0/19 | 90% | 3.0/3 | 100% |
| naive (control) | tuf | 8.0/19 | 42% | 2.0/3 | 67% |

## Mutation analysis (which controls each scenario kills)

| Scenario | killed controls |
|---|---|
| arb-target-substitution | **none** |
| arb-metadata-tamper | **none** |
| arb-keyid-spoofing | **none** |
| freeze-expired-timestamp | naive |
| rollback-timestamp | naive |
| mix-and-match | naive |
| online-keys-downgrade | naive |
| online-keys-arbitrary | **none** |
| endless-metadata | naive |
| endless-artifact | naive |
| slow-metadata | naive |
| slow-artifact | naive |
| dropped-connection | **none** |
| powercut-refresh | **none** |
| powercut-download | naive |
| online-keys-freeze | naive |
| mirror-errors | **none** |
| drop-requests | **none** |
| extra-data-artifact | **none** |
| unsupported-spec-version | **none** |
| timestamp-same-version | naive |
| threshold-key-twice | naive |

## Details

- `arb-target-substitution` / python-tuf: PASS — rejected
- `arb-target-substitution` / tough: PASS — rejected
- `arb-target-substitution` / naive: PASS — rejected
- `arb-metadata-tamper` / python-tuf: PASS — rejected
- `arb-metadata-tamper` / tough: PASS — rejected
- `arb-metadata-tamper` / naive: PASS — rejected
- `arb-keyid-spoofing` / python-tuf: PASS — rejected
- `arb-keyid-spoofing` / tough: PASS — rejected
- `arb-keyid-spoofing` / naive: PASS — rejected
- `freeze-expired-timestamp` / python-tuf: PASS — expired metadata rejected
- `freeze-expired-timestamp` / tough: PASS — expired metadata rejected
- `freeze-expired-timestamp` / naive: FAIL — expired timestamp accepted
- `rollback-timestamp` / python-tuf: PASS — rejected
- `rollback-timestamp` / tough: PASS — rejected
- `rollback-timestamp` / naive: FAIL — trusted timestamp rolled back to v2
- `mix-and-match` / python-tuf: PASS — rejected
- `mix-and-match` / tough: PASS — rejected
- `mix-and-match` / naive: FAIL — inconsistent targets trusted
- `online-keys-downgrade` / python-tuf: PASS — rejected
- `online-keys-downgrade` / tough: PASS — rejected
- `online-keys-downgrade` / naive: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-arbitrary` / python-tuf: PASS — rejected
- `online-keys-arbitrary` / tough: PASS — rejected
- `online-keys-arbitrary` / naive: PASS — rejected
- `endless-metadata` / python-tuf: PASS — client aborted the transfer itself
- `endless-metadata` / tough: PASS — client aborted the transfer itself
- `endless-metadata` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / python-tuf: PASS — client aborted the transfer itself
- `endless-artifact` / tough: PASS — client aborted the transfer itself
- `endless-artifact` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `slow-metadata` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 135s)
- `slow-metadata` / tough: PASS — client aborted the transfer itself
- `slow-metadata` / naive: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 135s)
- `slow-artifact` / tough: PASS — client aborted the transfer itself
- `slow-artifact` / naive: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `dropped-connection` / python-tuf: PASS — recovered
- `dropped-connection` / tough: PASS — recovered
- `dropped-connection` / naive: PASS — recovered
- `powercut-refresh` / python-tuf: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / tough: PASS — 15/15 survived (12 killed mid-run)
- `powercut-refresh` / naive: PASS — 15/15 survived (13 killed mid-run)
- `powercut-download` / python-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / tough: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / naive: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 671744B] -> after retry exit=0 [fw.bin:BAD 671744B]; 1x after crash [fw.bin:BAD 1933312B] -> after retry exit=0 [fw.bin:BAD 1933312B]; 1x after crash [fw.bin:BAD 1310720B] -> after retry exit=0 [fw.bin:BAD 1310720B]
- `online-keys-freeze` / python-tuf: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / tough: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / naive: FAIL — expired targets accepted under fresh online signatures
- `mirror-errors` / python-tuf: PASS — failure reported after 0.22s, trust store intact
- `mirror-errors` / tough: PASS — failure reported after 0.96s, trust store intact
- `mirror-errors` / naive: PASS — failure reported after 0.20s, trust store intact
- `drop-requests` / python-tuf: PASS — failure reported after 0.25s, trust store intact
- `drop-requests` / tough: PASS — failure reported after 0.97s, trust store intact
- `drop-requests` / naive: PASS — failure reported after 0.22s, trust store intact
- `extra-data-artifact` / python-tuf: PASS — rejected
- `extra-data-artifact` / tough: PASS — rejected
- `extra-data-artifact` / naive: PASS — rejected
- `unsupported-spec-version` / python-tuf: PASS — rejected
- `unsupported-spec-version` / tough: FAIL — metadata of an unsupported major spec version became trusted
- `unsupported-spec-version` / naive: PASS — rejected
- `timestamp-same-version` / python-tuf: PASS — kept the trusted timestamp (exit 0, as TUF requires)
- `timestamp-same-version` / tough: FAIL — a timestamp with an equal version but new content replaced the trusted one
- `timestamp-same-version` / naive: FAIL — a timestamp with an equal version but new content replaced the trusted one
- `threshold-key-twice` / python-tuf: FAIL — one key counted twice towards threshold 2 (two keyids)
- `threshold-key-twice` / tough: PASS — rejected
- `threshold-key-twice` / naive: FAIL — one key counted twice towards threshold 2 (two keyids)

## Catalog coverage

| Threat | Class | Existing suites | otabench |
|---|---|---|---|
| OTA-AUTH-01 Arbitrary software installation (artifact substitution) | authenticity | mcuboot-sim, mender-integration, tuf-conformance | arb-target-substitution, online-keys-arbitrary, ab:attacker, suit-payload-substitution |
| OTA-AUTH-02 Metadata tampering without keys | authenticity | tuf-conformance | arb-metadata-tamper, suit-manifest-tamper, suit-signature-tamper, rauc-sigcover |
| OTA-AUTH-03 Signature / keyid confusion | authenticity | tuf-conformance | arb-keyid-spoofing, threshold-key-twice |
| OTA-FRESH-01 Indefinite freeze (replay of expired metadata) | freshness | tuf-conformance | freeze-expired-timestamp, online-keys-freeze |
| OTA-FRESH-02 Rollback (replay of older validly signed metadata / firmware) | freshness | mcuboot-sim, tuf-conformance | rollback-timestamp, timestamp-same-version, online-keys-downgrade, ab:downgrade |
| OTA-FRESH-03 Mix-and-match | freshness | tuf-conformance | mix-and-match |
| OTA-FRESH-04 Fast-forward (attacker-inflated version locks out recovery) | freshness | tuf-conformance | — |
| OTA-KEY-01 Online-key compromise -> downgrade to older firmware | key-compromise | tuf-conformance | online-keys-downgrade |
| OTA-KEY-02 Online-key compromise -> arbitrary software | key-compromise | — | online-keys-arbitrary, threshold-key-twice |
| OTA-KEY-03 Compromised key not revoked after root rotation | key-compromise | tuf-conformance | — |
| OTA-KEY-04 Online-key compromise -> indefinite freeze with fresh signatures | key-compromise | — | online-keys-freeze |
| OTA-DOS-01 Endless data (metadata) | availability | — | endless-metadata |
| OTA-DOS-02 Endless data (artifact beyond signed length) | availability | — | endless-artifact |
| OTA-DOS-03 Slow retrieval (metadata) | availability | — | slow-metadata |
| OTA-DOS-04 Slow retrieval (artifact) | availability | — | slow-artifact |
| OTA-DOS-05 Malicious mirror prevents updates (no fallback) | availability | — | mirror-errors |
| OTA-NET-01 Interrupted transfer, recovery on retry | fault-tolerance | aktualizr-tests, mender-integration | dropped-connection |
| OTA-PWR-01 Power loss during metadata update (trust state must not brick) | fault-tolerance | — | powercut-refresh |
| OTA-PWR-02 Power loss during artifact download/storage | fault-tolerance | — | powercut-download |
| OTA-PWR-03 Power loss while writing the inactive A/B slot | fault-tolerance | mcuboot-sim | ab:crash-replay, ab:window:*, ab:reorder:* |
| OTA-PWR-04 Power loss during boot-slot switch / first boot (fallback via boot counter) | fault-tolerance | mcuboot-sim | ab:cut-firstboot, ab:crash-replay |
| OTA-PWR-05 Power loss leaves the update state unusable (device boots but can no longer be updated) | fault-tolerance | — | ab:reorder:*, ab:replay-state-liveness |
| OTA-PWR-06 Power loss corrupts the RUNNING slot (writable rootfs) during an update | fault-tolerance | — | ab:reorder:* --torn |
| OTA-INST-01 Wrong software installation (wrong device/hardware class) | installation | tuf-conformance | — |
| OTA-INST-02 Partial bundle installation (multi-ECU / multi-image) | installation | — | — |
| OTA-PARSE-01 Malformed metadata / manifest triggers parser fault | parsing | oss-fuzz | suit-malformed |
| OTA-INST-03 Extraneous dependencies | installation | — | — |
| OTA-INST-04 TOCTOU between verification and use | installation | — | ab:toctou |
| OTA-INST-05 Wrong delta precursor | installation | — | — |
| OTA-AUTH-04 Extra data after a valid image | authenticity | — | extra-data-artifact, suit-extra-data |
| OTA-AUTH-05 Debug / pre-production build accepted | authenticity | — | — |
| OTA-AUTHZ-01 Unapproved firmware / override of critical manifest elements | authenticity | tuf-conformance | — |
| OTA-CONF-01 Eavesdropping on update content (image disclosure) | confidentiality | — | — |
| OTA-CONF-02 Confidential manifest element exposure | confidentiality | — | — |
| OTA-DOS-06 Drop-request (update traffic blocked) | availability | — | drop-requests |
| OTA-FRESH-05 Cross-device replay of image-less Director metadata | freshness | — | — |
| OTA-TIME-01 Absent or invalid time attestation | freshness | — | — |
| OTA-REP-01 Version-report replay / attacker-authored version report | authenticity | — | — |
| OTA-NET-02 Missing transport / update-server authentication | authenticity | — | — |
| OTA-PARSE-02 Unsupported spec / encoding version accepted | parsing | — | unsupported-spec-version |
