# otabench: threat × implementation matrix

Run: 2026-11-01T18:20:28+00:00 · host: Windows-11-10.0.26200-SP0 · trials: 10

| Scenario | Threats | tuf-js |
|---|---|---|
| baseline |  | ✅ |
| dropped-connection | OTA-NET-01 | ✅ |
| endless-artifact | OTA-DOS-02 | ✅ abort 0.25s, 896 KiB |
| powercut-download | OTA-PWR-02 | ✅ survival 100% [72%–100%] (n=10), recovery 0.261s |
| fuzz-metadata | OTA-PARSE-01 | ✅ |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| tuf-js | tuf | 2.0/2 | 100% | 2.0/2 | 100% |

## Details

- `dropped-connection` / tuf-js: PASS — recovered
- `endless-artifact` / tuf-js: PASS — client aborted the transfer itself
- `powercut-download` / tuf-js: PASS — 10/10 survived (10 killed mid-run)
- `fuzz-metadata` / tuf-js: PASS — no crash or hang on 120 inputs; 3 mutated timestamps became trusted (compared across clients)

## Catalog coverage

| Threat | Class | Existing suites | otabench |
|---|---|---|---|
| OTA-AUTH-01 Arbitrary software installation (artifact substitution) | authenticity | mcuboot-sim, mender-integration, tuf-conformance | arb-target-substitution, online-keys-arbitrary, ab:attacker, ab:net-tamper, suit-payload-substitution |
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
| OTA-DOS-02 Endless data (artifact beyond signed length) | availability | — | endless-artifact, ab:net-endless |
| OTA-DOS-03 Slow retrieval (metadata) | availability | — | slow-metadata |
| OTA-DOS-04 Slow retrieval (artifact) | availability | — | slow-artifact, ab:net-slow |
| OTA-DOS-05 Malicious mirror prevents updates (no fallback) | availability | — | mirror-errors |
| OTA-NET-01 Interrupted transfer, recovery on retry | fault-tolerance | aktualizr-tests, mender-integration | dropped-connection, ab:net-drop |
| OTA-PWR-01 Power loss during metadata update (trust state must not brick) | fault-tolerance | — | powercut-refresh |
| OTA-PWR-02 Power loss during artifact download/storage | fault-tolerance | — | powercut-download |
| OTA-PWR-03 Power loss while writing the inactive A/B slot | fault-tolerance | mcuboot-sim | ab:crash-replay, ab:window:*, ab:reorder:* |
| OTA-PWR-04 Power loss during boot-slot switch / first boot (fallback via boot counter) | fault-tolerance | mcuboot-sim | ab:cut-firstboot, ab:crash-replay |
| OTA-PWR-05 Power loss leaves the update state unusable (device boots but can no longer be updated) | fault-tolerance | — | ab:reorder:*, ab:replay-state-liveness |
| OTA-PWR-06 Power loss corrupts the RUNNING slot (writable rootfs) during an update | fault-tolerance | — | ab:reorder:* --torn |
| OTA-INST-01 Wrong software installation (wrong device/hardware class) | installation | tuf-conformance | — |
| OTA-INST-02 Partial bundle installation (multi-ECU / multi-image) | installation | — | — |
| OTA-PARSE-01 Malformed metadata / manifest triggers parser fault | parsing | oss-fuzz | suit-malformed, fuzz-metadata |
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
