# otabench: threat × implementation matrix

Run: 2026-11-01T15:52:04+00:00 · host: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.36 · trials: 10

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
| endless-metadata | OTA-DOS-01 | ✅ abort 0.6s, 3.1 MiB | ✅ abort 0.04s, 320 KiB | ✅ abort 0.5s, 2.8 MiB | ❌ abort 1.38s, 64.0 MiB | ❌ abort 1.24s, 64.0 MiB | ❌ abort 1.21s, 64.0 MiB | ❌ abort 1.52s, 64.0 MiB | ❌ abort 1.28s, 64.0 MiB | ❌ abort 1.5s, 64.0 MiB |
| endless-artifact | OTA-DOS-02 | ✅ abort 0.58s, 3.0 MiB | ✅ abort 0.06s, 320 KiB | ✅ abort 0.54s, 2.5 MiB | ❌ abort 0.78s, 64.0 MiB | ❌ abort 0.78s, 64.0 MiB | ❌ abort 0.78s, 64.0 MiB | ❌ abort 0.63s, 64.0 MiB | ❌ abort 0.77s, 64.0 MiB | ❌ abort 0.72s, 64.0 MiB |
| **slow-metadata** ⚡ | OTA-DOS-03 | ❌ abort 120.63s, 240 B | ❌ abort 120.12s, 240 B | ✅ abort 100.38s, 200 B | ❌ abort 120.46s, 240 B | ❌ abort 120.45s, 240 B | ❌ abort 120.43s, 240 B | ❌ abort 120.4s, 240 B | ❌ abort 120.39s, 240 B | ❌ abort 120.41s, 240 B |
| **slow-artifact** ⚡ | OTA-DOS-04 | ❌ abort 120.33s, 7558 B | ❌ abort 120.03s, 7501 B | ✅ abort 100.19s, 6238 B | ❌ abort 120.28s, 7476 B | ❌ abort 120.28s, 7483 B | ❌ abort 120.28s, 7482 B | ❌ abort 120.31s, 7483 B | ❌ abort 120.36s, 7485 B | ❌ abort 120.36s, 7475 B |
| dropped-connection | OTA-NET-01 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ torn file after drop | ❌ torn file after drop | ✅ |
| **powercut-refresh** ⚡ | OTA-PWR-01 | ✅ survived 15/15 kill points (census), recovery 0.276s | ❌ survived 12/15 kill points (census), recovery 0.02s | ✅ survived 15/15 kill points (census), recovery 0.239s | ✅ survived 15/15 kill points (census), recovery 0.288s | ✅ survived 15/15 kill points (census), recovery 0.298s | ✅ survived 15/15 kill points (census), recovery 0.29s | ✅ survived 15/15 kill points (census), recovery 0.283s | ✅ survived 15/15 kill points (census), recovery 0.32s | ❌ survived 14/15 kill points (census), recovery 0.319s |
| powercut-download | OTA-PWR-02 | ✅ survival 100% [72%–100%] (n=10), recovery 0.289s | ✅ survival 100% [72%–100%] (n=10), recovery 0.035s | ⚠️ | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.24s, torn file 9× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.291s, torn file 9× | ❌ survival 0% [0%–28%] (n=10), torn file 10× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.266s, torn file 9× | 🟡 survival 10% [2%–40%] (n=10), recovery 0.3s, torn file 9× |
| online-keys-freeze | OTA-KEY-04, OTA-FRESH-01 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| mirror-errors | OTA-DOS-05 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| drop-requests | OTA-DOS-06 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| extra-data-artifact | OTA-AUTH-04 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **unsupported-spec-version** ⚡ | OTA-PARSE-02 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

⚡ = differential finding: real implementations of the same spec disagree.

## Rates over the common scenario set (PARTIAL counts 0.5)

| Client | spec | attacks blocked | rate | faults survived | rate |
|---|---|---|---|---|---|
| python-tuf | tuf | 15.0/17 | 88% | 2.0/2 | 100% |
| go-tuf | tuf | 14.0/17 | 82% | 1.0/2 | 50% |
| tuf-js | tuf | 17.0/17 | 100% | 2.0/2 | 100% |
| naive (control) | tuf | 8.0/17 | 47% | 2.0/2 | 100% |
| naive-nosig (control) | tuf | 5.0/17 | 29% | 2.0/2 | 100% |
| naive-anykey (control) | tuf | 7.0/17 | 41% | 2.0/2 | 100% |
| naive-nohash (control) | tuf | 6.0/17 | 35% | 1.0/2 | 50% |
| naive-keeptorn (control) | tuf | 6.0/17 | 35% | 1.0/2 | 50% |
| naive-lazyroot (control) | tuf | 8.0/17 | 47% | 1.0/2 | 50% |

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
| powercut-refresh | naive-lazyroot |
| powercut-download | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| online-keys-freeze | naive, naive-nosig, naive-anykey, naive-nohash, naive-keeptorn, naive-lazyroot |
| mirror-errors | **none** |
| drop-requests | **none** |
| extra-data-artifact | naive-nohash, naive-keeptorn |
| unsupported-spec-version | **none** |

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
- `slow-metadata` / naive: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-nosig: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-anykey: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-nohash: FAIL — client never gave up, harness cap hit (still waiting after 120s)
- `slow-metadata` / naive-keeptorn: FAIL — client never gave up, harness cap hit (still waiting after 120s)
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
- `powercut-refresh` / go-tuf: FAIL — 12/15 survived (10 killed mid-run) | 2x recovery refresh failed: ; 1x recovery refresh failed: 6 [/work/bench/clients/bin/go-tuf --metadata-url http://127.0.0.1:42891/powercut-refresh--go-tuf--16
- `powercut-refresh` / tuf-js: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nosig: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-anykey: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-nohash: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-keeptorn: PASS — 15/15 survived (13 killed mid-run)
- `powercut-refresh` / naive-lazyroot: FAIL — 14/15 survived (13 killed mid-run) | 1x recovery refresh failed: naive client: Can't open /tmp/otabench-naive-lazyroot-pja3878q/metadata/root.json
- `powercut-download` / python-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / go-tuf: PASS — 10/10 survived (10 killed mid-run)
- `powercut-download` / tuf-js: ERROR — precondition: honest 2 MiB download fails without any fault (control 1/3, exit 1): } | Node.js v24.22.2
- `powercut-download` / naive: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 688128B] -> after retry exit=0 [fw.bin:BAD 688128B]; 1x after crash [fw.bin:BAD 1933312B] -> after retry exit=0 [fw.bin:BAD 1933312B]; 1x after crash [fw.bin:BAD 1310720B] -> after retry exit=0 [fw.bin:BAD 1310720B]
- `powercut-download` / naive-nosig: PARTIAL — 1/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1425408B] -> after retry exit=0 [fw.bin:BAD 1425408B]; 1x after crash [fw.bin:BAD 294912B] -> after retry exit=0 [fw.bin:BAD 294912B]; 1x after crash [fw.bin:BAD 1753088B] -> after retry exit=0 [fw.bin:BAD 1753088B]
- `powercut-download` / naive-anykey: PARTIAL — 1/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 147456B] -> after retry exit=0 [fw.bin:BAD 147456B]; 1x after crash [fw.bin:BAD 1523712B] -> after retry exit=0 [fw.bin:BAD 1523712B]; 1x after crash [fw.bin:BAD 360448B] -> after retry exit=0 [fw.bin:BAD 360448B]
- `powercut-download` / naive-nohash: FAIL — 0/10 survived (10 killed mid-run) | 1x after crash [fw.bin:BAD 1835008B] -> after retry exit=0 [fw.bin:BAD 1835008B]; 1x after crash [fw.bin:BAD 262144B] -> after retry exit=0 [fw.bin:BAD 262144B]; 1x after crash [fw.bin:BAD 1032192B] -> after retry exit=0 [fw.bin:BAD 1032192B]
- `powercut-download` / naive-keeptorn: PARTIAL — 1/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1507328B] -> after retry exit=0 [fw.bin:BAD 1507328B]; 1x after crash [fw.bin:BAD 606208B] -> after retry exit=0 [fw.bin:BAD 606208B]; 1x after crash [fw.bin:BAD 1753088B] -> after retry exit=0 [fw.bin:BAD 1753088B]
- `powercut-download` / naive-lazyroot: PARTIAL — 1/10 survived (9 killed mid-run) | 1x after crash [fw.bin:BAD 1114112B] -> after retry exit=0 [fw.bin:BAD 1114112B]; 1x after crash [fw.bin:BAD 229376B] -> after retry exit=0 [fw.bin:BAD 229376B]; 1x after crash [fw.bin:BAD 114688B] -> after retry exit=0 [fw.bin:BAD 114688B]
- `online-keys-freeze` / python-tuf: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / go-tuf: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / tuf-js: PASS — freeze detected: expired targets rejected
- `online-keys-freeze` / naive: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-nosig: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-anykey: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-nohash: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-keeptorn: FAIL — expired targets accepted under fresh online signatures
- `online-keys-freeze` / naive-lazyroot: FAIL — expired targets accepted under fresh online signatures
- `mirror-errors` / python-tuf: PASS — failure reported after 0.27s, trust store intact
- `mirror-errors` / go-tuf: PASS — failure reported after 0.01s, trust store intact
- `mirror-errors` / tuf-js: PASS — failure reported after 3.26s, trust store intact
- `mirror-errors` / naive: PASS — failure reported after 0.22s, trust store intact
- `mirror-errors` / naive-nosig: PASS — failure reported after 0.21s, trust store intact
- `mirror-errors` / naive-anykey: PASS — failure reported after 0.20s, trust store intact
- `mirror-errors` / naive-nohash: PASS — failure reported after 0.33s, trust store intact
- `mirror-errors` / naive-keeptorn: PASS — failure reported after 0.31s, trust store intact
- `mirror-errors` / naive-lazyroot: PASS — failure reported after 0.32s, trust store intact
- `drop-requests` / python-tuf: PASS — failure reported after 0.37s, trust store intact
- `drop-requests` / go-tuf: PASS — failure reported after 0.01s, trust store intact
- `drop-requests` / tuf-js: PASS — failure reported after 3.21s, trust store intact
- `drop-requests` / naive: PASS — failure reported after 0.35s, trust store intact
- `drop-requests` / naive-nosig: PASS — failure reported after 0.37s, trust store intact
- `drop-requests` / naive-anykey: PASS — failure reported after 0.38s, trust store intact
- `drop-requests` / naive-nohash: PASS — failure reported after 0.44s, trust store intact
- `drop-requests` / naive-keeptorn: PASS — failure reported after 0.44s, trust store intact
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
