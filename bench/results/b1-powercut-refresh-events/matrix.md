# otabench: threat × implementation matrix

Run: 2026-11-01T14:46:08+00:00 · host: Windows-11-10.0.26200-SP0 · trials: 10

| Scenario | Threats | python-tuf | go-tuf | tuf-js | naive | naive-nosig | naive-anykey | naive-nohash | naive-keeptorn | naive-lazyroot |
|---|---|---|---|---|---|---|---|---|---|---|
| powercut-refresh | OTA-PWR-01 | ✅ survival 100% [80%–100%] (n=15), recovery 0.516s | ✅ survival 100% [80%–100%] (n=15), recovery 0.088s | ✅ survival 100% [80%–100%] (n=15), recovery 0.272s | ✅ survival 100% [80%–100%] (n=15), recovery 0.386s | ✅ survival 100% [80%–100%] (n=15), recovery 0.367s | ✅ survival 100% [80%–100%] (n=15), recovery 0.377s | ✅ survival 100% [80%–100%] (n=15), recovery 0.368s | ✅ survival 100% [80%–100%] (n=15), recovery 0.359s | 🟡 survival 87% [62%–96%] (n=15), recovery 0.354s |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 0/0 | 0% | 1.0/1 | 100% |
| go-tuf | tuf | 0/0 | 0% | 1.0/1 | 100% |
| tuf-js | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive (control) | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive-nosig (control) | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive-anykey (control) | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive-nohash (control) | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive-keeptorn (control) | tuf | 0/0 | 0% | 1.0/1 | 100% |
| naive-lazyroot (control) | tuf | 0/0 | 0% | 0.5/1 | 50% |

## Mutation analysis (which controls each scenario kills)

| Scenario | killed controls |
|---|---|
| powercut-refresh | naive-lazyroot |

## Details

- `powercut-refresh` / python-tuf: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / go-tuf: PASS — 15/15 survived (12 killed mid-run)
- `powercut-refresh` / tuf-js: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nosig: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-anykey: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nohash: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-keeptorn: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-lazyroot: PARTIAL — 13/15 survived (13 killed mid-run) | 1x recovery refresh failed: naive client: Can't open C:\Users\eugen\AppData\Local\Temp\otabench-naive-lazyroot-us931jw4\metadata; 1x recovery refresh failed: naive client: Can't open C:\Users\eugen\AppData\Local\Temp\otabench-naive-lazyroot-7vkdxjf0\metadata

## Catalog coverage

| Threat | Class | Existing suites | otabench |
|---|---|---|---|
| OTA-AUTH-01 Arbitrary software installation (artifact substitution) | authenticity | mcuboot-sim, mender-integration, tuf-conformance | arb-target-substitution, online-keys-arbitrary, ab:attacker |
| OTA-AUTH-02 Metadata tampering without keys | authenticity | tuf-conformance | arb-metadata-tamper |
| OTA-AUTH-03 Signature / keyid confusion | authenticity | tuf-conformance | arb-keyid-spoofing |
| OTA-FRESH-01 Indefinite freeze (replay of expired metadata) | freshness | tuf-conformance | freeze-expired-timestamp |
| OTA-FRESH-02 Rollback (replay of older validly signed metadata / firmware) | freshness | mcuboot-sim, tuf-conformance | rollback-timestamp, online-keys-downgrade, ab:downgrade |
| OTA-FRESH-03 Mix-and-match | freshness | tuf-conformance | mix-and-match |
| OTA-FRESH-04 Fast-forward (attacker-inflated version locks out recovery) | freshness | tuf-conformance | — |
| OTA-KEY-01 Online-key compromise -> downgrade to older firmware | key-compromise | tuf-conformance | online-keys-downgrade |
| OTA-KEY-02 Online-key compromise -> arbitrary software | key-compromise | — | online-keys-arbitrary |
| OTA-KEY-03 Compromised key not revoked after root rotation | key-compromise | tuf-conformance | — |
| OTA-KEY-04 Online-key compromise -> indefinite freeze with fresh signatures | key-compromise | — | — |
| OTA-DOS-01 Endless data (metadata) | availability | — | endless-metadata |
| OTA-DOS-02 Endless data (artifact beyond signed length) | availability | — | endless-artifact |
| OTA-DOS-03 Slow retrieval (metadata) | availability | — | slow-metadata |
| OTA-DOS-04 Slow retrieval (artifact) | availability | — | slow-artifact |
| OTA-DOS-05 Malicious mirror prevents updates (no fallback) | availability | — | — |
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
| OTA-AUTH-04 Extra data after a valid image | authenticity | — | — |
| OTA-AUTH-05 Debug / pre-production build accepted | authenticity | — | — |
| OTA-AUTHZ-01 Unapproved firmware / override of critical manifest elements | authenticity | tuf-conformance | — |
| OTA-CONF-01 Eavesdropping on update content (image disclosure) | confidentiality | — | — |
| OTA-CONF-02 Confidential manifest element exposure | confidentiality | — | — |
| OTA-DOS-06 Drop-request (update traffic blocked) | availability | — | — |
| OTA-FRESH-05 Cross-device replay of image-less Director metadata | freshness | — | — |
| OTA-TIME-01 Absent or invalid time attestation | freshness | — | — |
| OTA-REP-01 Version-report replay / attacker-authored version report | authenticity | — | — |
| OTA-NET-02 Missing transport / update-server authentication | authenticity | — | — |
| OTA-PARSE-02 Unsupported spec / encoding version accepted | parsing | — | — |
