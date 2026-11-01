# otabench: threat × implementation matrix

Run: 2026-10-31T17:00:18+00:00 · host: Windows-11-10.0.26200-SP0 · trials: 10

| Scenario | Threats | python-tuf | go-tuf | tuf-js | naive | naive-nosig | naive-anykey | naive-nohash | naive-keeptorn |
|---|---|---|---|---|---|---|---|---|---|
| baseline |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| arb-target-substitution | OTA-AUTH-01 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| arb-metadata-tamper | OTA-AUTH-02 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| arb-keyid-spoofing | OTA-AUTH-03 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| freeze-expired-timestamp | OTA-FRESH-01 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| rollback-timestamp | OTA-FRESH-02 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| mix-and-match | OTA-FRESH-03 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| online-keys-downgrade | OTA-KEY-01, OTA-FRESH-02 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| online-keys-arbitrary | OTA-KEY-02, OTA-AUTH-01 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| endless-metadata | OTA-DOS-01 | ✅ abort 0.64s, 960 KiB | ✅ abort 0.1s, 320 KiB | ✅ abort 0.32s, 768 KiB | ❌ abort 0.89s, 64.0 MiB | ❌ abort 0.97s, 64.0 MiB | ❌ abort 0.9s, 64.0 MiB | ❌ abort 0.82s, 64.0 MiB | ❌ abort 0.91s, 64.0 MiB |
| endless-artifact | OTA-DOS-02 | ✅ abort 0.64s, 832 KiB | ✅ abort 0.12s, 448 KiB | ✅ abort 0.4s, 448 KiB | ❌ abort 0.69s, 64.0 MiB | ❌ abort 0.73s, 64.0 MiB | ❌ abort 0.68s, 64.0 MiB | ❌ abort 0.62s, 64.0 MiB | ❌ abort 0.61s, 64.0 MiB |
| **slow-metadata** ⚡ | OTA-DOS-03 | ❌ abort 120.64s, 240 B | ❌ abort 120.22s, 240 B | ✅ abort 100.28s, 200 B | ❌ abort 120.52s, 240 B | ❌ abort 120.45s, 240 B | ❌ abort 120.45s, 240 B | ❌ abort 120.45s, 240 B | ❌ abort 120.4s, 240 B |
| **slow-artifact** ⚡ | OTA-DOS-04 | ❌ abort 120.39s, 7445 B | ❌ abort 120.08s, 7446 B | ✅ abort 100.17s, 6205 B | ❌ abort 120.28s, 7456 B | ❌ abort 120.35s, 7458 B | ❌ abort 120.38s, 7458 B | ❌ abort 120.36s, 7460 B | ❌ abort 120.35s, 7458 B |
| dropped-connection | OTA-NET-01 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ torn file after drop | ❌ torn file after drop |
| powercut-refresh | OTA-PWR-01 | ✅ survival 100% [72%–100%] (n=10), recovery 0.423s | ✅ survival 100% [72%–100%] (n=10), recovery 0.067s | ✅ survival 100% [72%–100%] (n=10), recovery 0.196s | ✅ survival 100% [72%–100%] (n=10), recovery 0.328s | ✅ survival 100% [72%–100%] (n=10), recovery 0.31s | ✅ survival 100% [72%–100%] (n=10), recovery 0.314s | ✅ survival 100% [72%–100%] (n=10), recovery 0.306s | ✅ survival 100% [72%–100%] (n=10), recovery 0.307s |
| powercut-download | OTA-PWR-02 | ✅ survival 100% [72%–100%] (n=10), recovery 0.417s | ✅ survival 100% [72%–100%] (n=10), recovery 0.076s | ⚠️ | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 20% [6%–51%] (n=10), recovery 0.27s, torn file 8× | ❌ survival 0% [0%–28%] (n=10), torn file 10× | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.259s, torn file 9× |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 10.0/12 | 83% | 2.0/2 | 100% |
| go-tuf | tuf | 10.0/12 | 83% | 2.0/2 | 100% |
| tuf-js | tuf | 12.0/12 | 100% | 2.0/2 | 100% |
| naive (control) | tuf | 4.0/12 | 33% | 2.0/2 | 100% |
| naive-nosig (control) | tuf | 1.0/12 | 8% | 2.0/2 | 100% |
| naive-anykey (control) | tuf | 3.0/12 | 25% | 2.0/2 | 100% |
| naive-nohash (control) | tuf | 3.0/12 | 25% | 1.0/2 | 50% |
| naive-keeptorn (control) | tuf | 3.0/12 | 25% | 1.0/2 | 50% |

Excluded from the rate because some client returned ERROR: powercut-download

## Mutation analysis (which controls each scenario kills)

| Scenario | killed controls |
|---|---|
| arb-target-substitution | naive-nohash, naive-keeptorn |
| arb-metadata-tamper | naive-nosig |
| arb-keyid-spoofing | naive-nosig |
| freeze-expired-timestamp | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| rollback-timestamp | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| mix-and-match | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| online-keys-downgrade | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| online-keys-arbitrary | naive-nosig, naive-anykey |
| endless-metadata | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| endless-artifact | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| slow-metadata | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| slow-artifact | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |
| dropped-connection | naive-nohash, naive-keeptorn |
| powercut-refresh | **none** |
| powercut-download | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn |

## Details

- `arb-target-substitution` / python-tuf: PASS — rejected
- `arb-target-substitution` / go-tuf: PASS — rejected
- `arb-target-substitution` / tuf-js: PASS — rejected
- `arb-target-substitution` / naive: PASS — rejected
- `arb-target-substitution` / naive-nosig: PASS — rejected
- `arb-target-substitution` / naive-anykey: PASS — rejected
- `arb-target-substitution` / naive-nohash: FAIL — malicious artifact stored in target dir
- `arb-target-substitution` / naive-keeptorn: FAIL — malicious artifact stored in target dir
- `arb-metadata-tamper` / naive-nosig: FAIL — tampered metadata accepted, payload stored
- `arb-keyid-spoofing` / naive-nosig: FAIL — forged signature accepted
- `freeze-expired-timestamp` / python-tuf: PASS — expired metadata rejected
- `freeze-expired-timestamp` / go-tuf: PASS — expired metadata rejected
- `freeze-expired-timestamp` / tuf-js: PASS — expired metadata rejected
- `freeze-expired-timestamp` / naive: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-nosig: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-anykey: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-nohash: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-keeptorn: FAIL — expired timestamp accepted
- `rollback-timestamp` / python-tuf: PASS — rejected
- `rollback-timestamp` / go-tuf: PASS — rejected
- `rollback-timestamp` / tuf-js: PASS — rejected
- `rollback-timestamp` / naive: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-nosig: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-anykey: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-nohash: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-keeptorn: FAIL — trusted timestamp rolled back to v2
- `mix-and-match` / naive: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-nosig: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-anykey: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-nohash: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-keeptorn: FAIL — inconsistent targets trusted
- `online-keys-downgrade` / python-tuf: PASS — rejected
- `online-keys-downgrade` / go-tuf: PASS — rejected
- `online-keys-downgrade` / tuf-js: PASS — rejected
- `online-keys-downgrade` / naive: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-nosig: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-anykey: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-nohash: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-keeptorn: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-arbitrary` / naive-nosig: FAIL — targets signed by wrong role accepted
- `online-keys-arbitrary` / naive-anykey: FAIL — targets signed by wrong role accepted
- `endless-metadata` / python-tuf: PASS — client aborted the transfer itself
- `endless-metadata` / go-tuf: PASS — client aborted the transfer itself
- `endless-metadata` / tuf-js: PASS — client aborted the transfer itself
- `endless-metadata` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-nosig: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-anykey: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-nohash: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-keeptorn: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / python-tuf: PASS — client aborted the transfer itself
- `endless-artifact` / go-tuf: PASS — client aborted the transfer itself
- `endless-artifact` / tuf-js: PASS — client aborted the transfer itself
- `endless-artifact` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-nosig: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-anykey: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-nohash: FAIL — over-long artifact stored
- `endless-artifact` / naive-keeptorn: FAIL — over-long artifact stored
- `slow-metadata` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / go-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / tuf-js: PASS — client aborted the transfer itself
- `slow-metadata` / naive: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-nosig: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-anykey: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-nohash: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-keeptorn: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / go-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / tuf-js: PASS — client aborted the transfer itself
- `slow-artifact` / naive: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-nosig: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-anykey: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-nohash: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-keeptorn: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `dropped-connection` / python-tuf: PASS — recovered
- `dropped-connection` / go-tuf: PASS — recovered
- `dropped-connection` / tuf-js: PASS — recovered
- `dropped-connection` / naive: PASS — recovered
- `dropped-connection` / naive-nosig: PASS — recovered
- `dropped-connection` / naive-anykey: PASS — recovered
- `dropped-connection` / naive-nohash: FAIL — truncated artifact reported as success
- `dropped-connection` / naive-keeptorn: FAIL — did not recover: stale torn file trusted
- `powercut-refresh` / python-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-refresh` / go-tuf: PASS — 10/10 survived (2 killed mid-run)
- `powercut-refresh` / tuf-js: PASS — 10/10 survived (10 killed mid-run)
- `powercut-refresh` / naive: PASS — 10/10 survived (3 killed mid-run)
- `powercut-refresh` / naive-nosig: PASS — 10/10 survived (6 killed mid-run)
- `powercut-refresh` / naive-anykey: PASS — 10/10 survived (6 killed mid-run)
- `powercut-refresh` / naive-nohash: PASS — 10/10 survived (5 killed mid-run)
- `powercut-refresh` / naive-keeptorn: PASS — 10/10 survived (4 killed mid-run)
- `powercut-download` / python-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / go-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / tuf-js: ERROR — precondition: honest 2 MiB download fails without any fault: Node.js v24.19.0 | Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 94
- `powercut-download` / naive: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 688128B] -> after retry exit=0 [fw.bin:BAD 688128B]; 1x after crash [fw.bin:BAD 1900544B] -> after retry exit=0 [fw.bin:BAD 1900544B]; 1x after crash [fw.bin:BAD 1310720B] -> after retry exit=0 [fw.bin:BAD 1310720B]
- `powercut-download` / naive-nosig: PARTIAL — 2/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1425408B] -> after retry exit=0 [fw.bin:BAD 1425408B]; 1x after crash [fw.bin:BAD 327680B] -> after retry exit=0 [fw.bin:BAD 327680B]; 1x after crash [fw.bin:BAD 1736704B] -> after retry exit=0 [fw.bin:BAD 1736704B]
- `powercut-download` / naive-anykey: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 147456B] -> after retry exit=0 [fw.bin:BAD 147456B]; 1x after crash [fw.bin:BAD 1507328B] -> after retry exit=0 [fw.bin:BAD 1507328B]; 1x after crash [fw.bin:BAD 376832B] -> after retry exit=0 [fw.bin:BAD 376832B]
- `powercut-download` / naive-nohash: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 1818624B] -> after retry exit=0 [fw.bin:BAD 1818624B]; 1x after crash [fw.bin:BAD 262144B] -> after retry exit=0 [fw.bin:BAD 262144B]; 1x after crash [fw.bin:BAD 999424B] -> after retry exit=0 [fw.bin:BAD 999424B]
- `powercut-download` / naive-keeptorn: PARTIAL — 1/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1490944B] -> after retry exit=0 [fw.bin:BAD 1490944B]; 1x after crash [fw.bin:BAD 606208B] -> after retry exit=0 [fw.bin:BAD 606208B]; 1x after crash [fw.bin:BAD 1769472B] -> after retry exit=0 [fw.bin:BAD 1769472B]

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
| OTA-PWR-03 Power loss while writing the inactive A/B slot | fault-tolerance | mcuboot-sim | ab:crash-replay, ab:window, ab:reorder |
| OTA-PWR-04 Power loss during boot-slot switch / first boot (fallback via boot counter) | fault-tolerance | mcuboot-sim | ab:cut-firstboot, ab:broken, ab:crash-replay |
| OTA-PWR-05 Power loss leaves the update state unusable (device boots but can no longer be updated) | fault-tolerance | — | ab:reorder, ab:replay-state-liveness |
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
