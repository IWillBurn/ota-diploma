# otabench: threat × implementation matrix

Run: 2026-11-01T15:35:51+00:00 · host: Windows-11-10.0.26200-SP0 · trials: 10

| Scenario | Threats | python-tuf | go-tuf | tuf-js | naive | naive-nosig | naive-anykey | naive-nohash | naive-keeptorn | naive-lazyroot |
|---|---|---|---|---|---|---|---|---|---|---|
| online-keys-freeze | OTA-KEY-04, OTA-FRESH-01 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| mirror-errors | OTA-DOS-05 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| drop-requests | OTA-DOS-06 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| extra-data-artifact | OTA-AUTH-04 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **unsupported-spec-version** ⚡ | OTA-PARSE-02 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 5.0/5 | 100% | 0/0 | 0% |
| go-tuf | tuf | 4.0/5 | 80% | 0/0 | 0% |
| tuf-js | tuf | 5.0/5 | 100% | 0/0 | 0% |
| naive (control) | tuf | 4.0/5 | 80% | 0/0 | 0% |
| naive-nosig (control) | tuf | 4.0/5 | 80% | 0/0 | 0% |
| naive-anykey (control) | tuf | 4.0/5 | 80% | 0/0 | 0% |
| naive-nohash (control) | tuf | 3.0/5 | 60% | 0/0 | 0% |
| naive-keeptorn (control) | tuf | 3.0/5 | 60% | 0/0 | 0% |
| naive-lazyroot (control) | tuf | 4.0/5 | 80% | 0/0 | 0% |

## Mutation analysis (which controls each scenario kills)

| Scenario | killed controls |
|---|---|
| online-keys-freeze | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| mirror-errors | **none** |
| drop-requests | **none** |
| extra-data-artifact | naive-nohash, naive-keeptorn |
| unsupported-spec-version | **none** |

## Details

- `online-keys-freeze` / python-tuf: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / go-tuf: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / tuf-js: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / naive: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-nosig: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-anykey: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-nohash: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-keeptorn: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-lazyroot: FAIL — expired targets accepted under fresh online signatures
- `mirror-errors` / python-tuf: PASS — failure reported after 0.40s, trust store intact
- `mirror-errors` / go-tuf: PASS — failure reported after 0.06s, trust store intact
- `mirror-errors` / tuf-js: PASS — failure reported after 3.26s, trust store intact
- `mirror-errors` / naive: PASS — failure reported after 0.32s, trust store intact
- `mirror-errors` / naive-nosig: PASS — failure reported after 0.37s, trust store intact
- `mirror-errors` / naive-anykey: PASS — failure reported after 0.36s, trust store intact
- `mirror-errors` / naive-nohash: PASS — failure reported after 0.33s, trust store intact
- `mirror-errors` / naive-keeptorn: PASS — failure reported after 0.34s, trust store intact
- `mirror-errors` / naive-lazyroot: PASS — failure reported after 0.37s, trust store intact
- `drop-requests` / python-tuf: PASS — failure reported after 0.64s, trust store intact
- `drop-requests` / go-tuf: PASS — failure reported after 0.20s, trust store intact
- `drop-requests` / tuf-js: PASS — failure reported after 3.20s, trust store intact
- `drop-requests` / naive: PASS — failure reported after 0.33s, trust store intact
- `drop-requests` / naive-nosig: PASS — failure reported after 0.35s, trust store intact
- `drop-requests` / naive-anykey: PASS — failure reported after 0.37s, trust store intact
- `drop-requests` / naive-nohash: PASS — failure reported after 0.37s, trust store intact
- `drop-requests` / naive-keeptorn: PASS — failure reported after 0.38s, trust store intact
- `drop-requests` / naive-lazyroot: PASS — failure reported after 0.39s, trust store intact
- `extra-data-artifact` / python-tuf: PASS — rejected
- `extra-data-artifact` / go-tuf: PASS — rejected
- `extra-data-artifact` / tuf-js: PASS — rejected
- `extra-data-artifact` / naive: PASS — rejected
- `extra-data-artifact` / naive-nosig: PASS — rejected
- `extra-data-artifact` / naive-anykey: PASS — rejected
- `extra-data-artifact` / naive-nohash: FAIL — bytes after the signed image were stored
- `extra-data-artifact` / naive-keeptorn: FAIL — bytes after the signed image were stored
- `extra-data-artifact` / naive-lazyroot: PASS — rejected
- `unsupported-spec-version` / python-tuf: PASS — rejected
- `unsupported-spec-version` / go-tuf: FAIL — metadata of an unsupported major spec version became trusted
- `unsupported-spec-version` / tuf-js: PASS — rejected
- `unsupported-spec-version` / naive: PASS — rejected
- `unsupported-spec-version` / naive-nosig: PASS — rejected
- `unsupported-spec-version` / naive-anykey: PASS — rejected
- `unsupported-spec-version` / naive-nohash: PASS — rejected
- `unsupported-spec-version` / naive-keeptorn: PASS — rejected
- `unsupported-spec-version` / naive-lazyroot: PASS — rejected

## Catalog coverage

| Threat | Class | Existing suites | otabench |
|---|---|---|---|
| OTA-AUTH-01 Arbitrary software installation (artifact substitution) | authenticity | mcuboot-sim, mender-integration, tuf-conformance | arb-target-substitution, online-keys-arbitrary, ab:attacker |
| OTA-AUTH-02 Metadata tampering without keys | authenticity | tuf-conformance | arb-metadata-tamper |
| OTA-AUTH-03 Signature / keyid confusion | authenticity | tuf-conformance | arb-keyid-spoofing |
| OTA-FRESH-01 Indefinite freeze (replay of expired metadata) | freshness | tuf-conformance | freeze-expired-timestamp, online-keys-freeze |
| OTA-FRESH-02 Rollback (replay of older validly signed metadata / firmware) | freshness | mcuboot-sim, tuf-conformance | rollback-timestamp, online-keys-downgrade, ab:downgrade |
| OTA-FRESH-03 Mix-and-match | freshness | tuf-conformance | mix-and-match |
| OTA-FRESH-04 Fast-forward (attacker-inflated version locks out recovery) | freshness | tuf-conformance | — |
| OTA-KEY-01 Online-key compromise -> downgrade to older firmware | key-compromise | tuf-conformance | online-keys-downgrade |
| OTA-KEY-02 Online-key compromise -> arbitrary software | key-compromise | — | online-keys-arbitrary |
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
| OTA-PARSE-01 Malformed metadata / manifest triggers parser fault | parsing | oss-fuzz | — |
| OTA-INST-03 Extraneous dependencies | installation | — | — |
| OTA-INST-04 TOCTOU between verification and use | installation | — | — |
| OTA-INST-05 Wrong delta precursor | installation | — | — |
| OTA-AUTH-04 Extra data after a valid image | authenticity | — | extra-data-artifact |
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
