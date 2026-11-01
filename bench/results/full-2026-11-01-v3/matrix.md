# otabench: threat × implementation matrix

Run: 2026-11-01T15:00:06+00:00 · host: Windows-11-10.0.26200-SP0 · trials: 10

| Scenario | Threats | python-tuf | go-tuf | tuf-js | naive | naive-nosig | naive-anykey | naive-nohash | naive-keeptorn | naive-lazyroot |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline |  | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| arb-target-substitution | OTA-AUTH-01 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| arb-metadata-tamper | OTA-AUTH-02 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| arb-keyid-spoofing | OTA-AUTH-03 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| freeze-expired-timestamp | OTA-FRESH-01 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| rollback-timestamp | OTA-FRESH-02 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| mix-and-match | OTA-FRESH-03 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| online-keys-downgrade | OTA-KEY-01, OTA-FRESH-02 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| online-keys-arbitrary | OTA-KEY-02, OTA-AUTH-01 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| endless-metadata | OTA-DOS-01 | ✅ abort 0.72s, 960 KiB | ✅ abort 0.12s, 896 KiB | ✅ abort 0.33s, 576 KiB | ❌ abort 0.88s, 64.0 MiB | ❌ abort 0.98s, 64.0 MiB | ❌ abort 0.89s, 64.0 MiB | ❌ abort 1.08s, 64.0 MiB | ❌ abort 0.95s, 64.0 MiB | ❌ abort 1.12s, 64.0 MiB |
| endless-artifact | OTA-DOS-02 | ✅ abort 0.69s, 768 KiB | ✅ abort 0.15s, 512 KiB | ✅ abort 0.48s, 768 KiB | ❌ abort 0.89s, 64.0 MiB | ❌ abort 0.8s, 64.0 MiB | ❌ abort 0.82s, 64.0 MiB | ❌ abort 0.83s, 64.0 MiB | ❌ abort 0.91s, 64.0 MiB | ❌ abort 0.79s, 64.0 MiB |
| **slow-metadata** ⚡ | OTA-DOS-03 | ❌ abort 120.75s, 240 B | ❌ abort 120.22s, 240 B | ✅ abort 100.31s, 200 B | ❌ abort 120.54s, 240 B | ❌ abort 120.53s, 240 B | ❌ abort 120.54s, 240 B | ❌ abort 120.52s, 240 B | ❌ abort 120.51s, 240 B | ❌ abort 120.5s, 240 B |
| **slow-artifact** ⚡ | OTA-DOS-04 | ❌ abort 120.44s, 7462 B | ❌ abort 120.07s, 7431 B | ✅ abort 100.22s, 6188 B | ❌ abort 120.45s, 7418 B | ❌ abort 120.48s, 7414 B | ❌ abort 120.48s, 7416 B | ❌ abort 120.46s, 7411 B | ❌ abort 120.45s, 7414 B | ❌ abort 120.45s, 7414 B |
| dropped-connection | OTA-NET-01 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ torn file after drop | ❌ torn file after drop | ✅ |
| powercut-refresh | OTA-PWR-01 | ✅ survived 15/15 kill points (census), recovery 0.467s | ✅ survived 15/15 kill points (census), recovery 0.078s | ✅ survived 15/15 kill points (census), recovery 0.227s | ✅ survived 15/15 kill points (census), recovery 0.34s | ❌ survived 14/15 kill points (census), recovery 0.328s | ✅ survived 15/15 kill points (census), recovery 0.345s | ✅ survived 15/15 kill points (census), recovery 0.342s | ✅ survived 15/15 kill points (census), recovery 0.354s | ❌ survived 14/15 kill points (census), recovery 0.341s |
| powercut-download | OTA-PWR-02 | ✅ survival 100% [72%–100%] (n=10), recovery 0.444s | ✅ survival 100% [72%–100%] (n=10), recovery 0.072s | ⚠️ | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 20% [6%–51%] (n=10), recovery 0.352s, torn file 8× | ❌ survival 0% [0%–28%] (n=10), torn file 10× | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.32s, torn file 9× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.325s, torn file 9× |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 10.0/12 | 83% | 2.0/2 | 100% |
| go-tuf | tuf | 10.0/12 | 83% | 2.0/2 | 100% |
| tuf-js | tuf | 12.0/12 | 100% | 2.0/2 | 100% |
| naive (control) | tuf | 4.0/12 | 33% | 2.0/2 | 100% |
| naive-nosig (control) | tuf | 1.0/12 | 8% | 1.0/2 | 50% |
| naive-anykey (control) | tuf | 3.0/12 | 25% | 2.0/2 | 100% |
| naive-nohash (control) | tuf | 3.0/12 | 25% | 1.0/2 | 50% |
| naive-keeptorn (control) | tuf | 3.0/12 | 25% | 1.0/2 | 50% |
| naive-lazyroot (control) | tuf | 4.0/12 | 33% | 1.0/2 | 50% |

Excluded from the rate because some client returned ERROR: powercut-download

## Mutation analysis (which controls each scenario kills)

| Scenario | killed controls |
|---|---|
| arb-target-substitution | naive-nohash, naive-keeptorn |
| arb-metadata-tamper | naive-nosig |
| arb-keyid-spoofing | naive-nosig |
| freeze-expired-timestamp | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| rollback-timestamp | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| mix-and-match | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| online-keys-downgrade | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| online-keys-arbitrary | naive-nosig, naive-anykey |
| endless-metadata | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| endless-artifact | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| slow-metadata | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| slow-artifact | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| dropped-connection | naive-nohash, naive-keeptorn |
| powercut-refresh | naive-nosig, naive-lazyroot |
| powercut-download | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |

## Details

- `arb-target-substitution` / python-tuf: PASS — rejected
- `arb-target-substitution` / go-tuf: PASS — rejected
- `arb-target-substitution` / tuf-js: PASS — rejected
- `arb-target-substitution` / naive: PASS — rejected
- `arb-target-substitution` / naive-nosig: PASS — rejected
- `arb-target-substitution` / naive-anykey: PASS — rejected
- `arb-target-substitution` / naive-nohash: FAIL — malicious artifact stored in target dir
- `arb-target-substitution` / naive-keeptorn: FAIL — malicious artifact stored in target dir
- `arb-target-substitution` / naive-lazyroot: PASS — rejected
- `arb-metadata-tamper` / python-tuf: PASS — rejected
- `arb-metadata-tamper` / go-tuf: PASS — rejected
- `arb-metadata-tamper` / tuf-js: PASS — rejected
- `arb-metadata-tamper` / naive: PASS — rejected
- `arb-metadata-tamper` / naive-nosig: FAIL — tampered metadata accepted, payload stored
- `arb-metadata-tamper` / naive-anykey: PASS — rejected
- `arb-metadata-tamper` / naive-nohash: PASS — rejected
- `arb-metadata-tamper` / naive-keeptorn: PASS — rejected
- `arb-metadata-tamper` / naive-lazyroot: PASS — rejected
- `arb-keyid-spoofing` / python-tuf: PASS — rejected
- `arb-keyid-spoofing` / go-tuf: PASS — rejected
- `arb-keyid-spoofing` / tuf-js: PASS — rejected
- `arb-keyid-spoofing` / naive: PASS — rejected
- `arb-keyid-spoofing` / naive-nosig: FAIL — forged signature accepted
- `arb-keyid-spoofing` / naive-anykey: PASS — rejected
- `arb-keyid-spoofing` / naive-nohash: PASS — rejected
- `arb-keyid-spoofing` / naive-keeptorn: PASS — rejected
- `arb-keyid-spoofing` / naive-lazyroot: PASS — rejected
- `freeze-expired-timestamp` / python-tuf: PASS — expired metadata rejected
- `freeze-expired-timestamp` / go-tuf: PASS — expired metadata rejected
- `freeze-expired-timestamp` / tuf-js: PASS — expired metadata rejected
- `freeze-expired-timestamp` / naive: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-nosig: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-anykey: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-nohash: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-keeptorn: FAIL — expired timestamp accepted
- `freeze-expired-timestamp` / naive-lazyroot: FAIL — expired timestamp accepted
- `rollback-timestamp` / python-tuf: PASS — rejected
- `rollback-timestamp` / go-tuf: PASS — rejected
- `rollback-timestamp` / tuf-js: PASS — rejected
- `rollback-timestamp` / naive: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-nosig: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-anykey: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-nohash: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-keeptorn: FAIL — trusted timestamp rolled back to v2
- `rollback-timestamp` / naive-lazyroot: FAIL — trusted timestamp rolled back to v2
- `mix-and-match` / python-tuf: PASS — rejected
- `mix-and-match` / go-tuf: PASS — rejected
- `mix-and-match` / tuf-js: PASS — rejected
- `mix-and-match` / naive: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-nosig: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-anykey: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-nohash: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-keeptorn: FAIL — inconsistent targets trusted
- `mix-and-match` / naive-lazyroot: FAIL — inconsistent targets trusted
- `online-keys-downgrade` / python-tuf: PASS — rejected
- `online-keys-downgrade` / go-tuf: PASS — rejected
- `online-keys-downgrade` / tuf-js: PASS — rejected
- `online-keys-downgrade` / naive: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-nosig: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-anykey: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-nohash: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-keeptorn: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-downgrade` / naive-lazyroot: FAIL — downgrade to vulnerable firmware accepted
- `online-keys-arbitrary` / python-tuf: PASS — rejected
- `online-keys-arbitrary` / go-tuf: PASS — rejected
- `online-keys-arbitrary` / tuf-js: PASS — rejected
- `online-keys-arbitrary` / naive: PASS — rejected
- `online-keys-arbitrary` / naive-nosig: FAIL — targets signed by wrong role accepted
- `online-keys-arbitrary` / naive-anykey: FAIL — targets signed by wrong role accepted
- `online-keys-arbitrary` / naive-nohash: PASS — rejected
- `online-keys-arbitrary` / naive-keeptorn: PASS — rejected
- `online-keys-arbitrary` / naive-lazyroot: PASS — rejected
- `endless-metadata` / python-tuf: PASS — client aborted the transfer itself
- `endless-metadata` / go-tuf: PASS — client aborted the transfer itself
- `endless-metadata` / tuf-js: PASS — client aborted the transfer itself
- `endless-metadata` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-nosig: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-anykey: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-nohash: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-keeptorn: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-metadata` / naive-lazyroot: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / python-tuf: PASS — client aborted the transfer itself
- `endless-artifact` / go-tuf: PASS — client aborted the transfer itself
- `endless-artifact` / tuf-js: PASS — client aborted the transfer itself
- `endless-artifact` / naive: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-nosig: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-anykey: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `endless-artifact` / naive-nohash: FAIL — over-long artifact stored
- `endless-artifact` / naive-keeptorn: FAIL — over-long artifact stored
- `endless-artifact` / naive-lazyroot: FAIL — client never gave up, harness cap hit (64 MiB accepted)
- `slow-metadata` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / go-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / tuf-js: PASS — client aborted the transfer itself
- `slow-metadata` / naive: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-nosig: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-anykey: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-nohash: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-keeptorn: FAIL — client never gave up, harness cap hit (still waiting after 121s)
- `slow-metadata` / naive-lazyroot: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / python-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / go-tuf: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / tuf-js: PASS — client aborted the transfer itself
- `slow-artifact` / naive: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-nosig: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-anykey: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-nohash: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-keeptorn: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-artifact` / naive-lazyroot: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `dropped-connection` / python-tuf: PASS — recovered
- `dropped-connection` / go-tuf: PASS — recovered
- `dropped-connection` / tuf-js: PASS — recovered
- `dropped-connection` / naive: PASS — recovered
- `dropped-connection` / naive-nosig: PASS — recovered
- `dropped-connection` / naive-anykey: PASS — recovered
- `dropped-connection` / naive-nohash: FAIL — truncated artifact reported as success
- `dropped-connection` / naive-keeptorn: FAIL — did not recover: stale torn file trusted
- `dropped-connection` / naive-lazyroot: PASS — recovered
- `powercut-refresh` / python-tuf: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / go-tuf: PASS — 15/15 survived (12 killed mid-run)
- `powercut-refresh` / tuf-js: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nosig: FAIL — 14/15 survived (13 killed mid-run) | 1x recovery refresh failed: naive client: Failed to deserialize JSON
- `powercut-refresh` / naive-anykey: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nohash: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-keeptorn: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-lazyroot: FAIL — 14/15 survived (13 killed mid-run) | 1x recovery refresh failed: naive client: Can't open C:\Users\eugen\AppData\Local\Temp\otabench-naive-lazyroot-gxj9zt8o\metadata
- `powercut-download` / python-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / go-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / tuf-js: ERROR — precondition: honest 2 MiB download fails without any fault (control 1/3, exit 3221226505): Node.js v24.19.0 | Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 94
- `powercut-download` / naive: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 704512B] -> after retry exit=0 [fw.bin:BAD 704512B]; 1x after crash [fw.bin:BAD 1900544B] -> after retry exit=0 [fw.bin:BAD 1900544B]; 1x after crash [fw.bin:BAD 1277952B] -> after retry exit=0 [fw.bin:BAD 1277952B]
- `powercut-download` / naive-nosig: PARTIAL — 2/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 1441792B] -> after retry exit=0 [fw.bin:BAD 1441792B]; 1x after crash [fw.bin:BAD 294912B] -> after retry exit=0 [fw.bin:BAD 294912B]; 1x after crash [fw.bin:BAD 1720320B] -> after retry exit=0 [fw.bin:BAD 1720320B]
- `powercut-download` / naive-anykey: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 147456B] -> after retry exit=0 [fw.bin:BAD 147456B]; 1x after crash [fw.bin:BAD 1523712B] -> after retry exit=0 [fw.bin:BAD 1523712B]; 1x after crash [fw.bin:BAD 393216B] -> after retry exit=0 [fw.bin:BAD 393216B]
- `powercut-download` / naive-nohash: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 1802240B] -> after retry exit=0 [fw.bin:BAD 1802240B]; 1x after crash [fw.bin:BAD 262144B] -> after retry exit=0 [fw.bin:BAD 262144B]; 1x after crash [fw.bin:BAD 999424B] -> after retry exit=0 [fw.bin:BAD 999424B]
- `powercut-download` / naive-keeptorn: PARTIAL — 1/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1523712B] -> after retry exit=0 [fw.bin:BAD 1523712B]; 1x after crash [fw.bin:BAD 606208B] -> after retry exit=0 [fw.bin:BAD 606208B]; 1x after crash [fw.bin:BAD 1753088B] -> after retry exit=0 [fw.bin:BAD 1753088B]
- `powercut-download` / naive-lazyroot: PARTIAL — 1/10 survived (9 killed mid-run) | 2x after crash [fw.bin:BAD 1261568B] -> after retry exit=0 [fw.bin:BAD 1261568B]; 1x after crash [fw.bin:BAD 1130496B] -> after retry exit=0 [fw.bin:BAD 1130496B]; 1x after crash [fw.bin:BAD 245760B] -> after retry exit=0 [fw.bin:BAD 245760B]

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
