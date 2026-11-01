# otabench: threat × implementation matrix (both levels)

40 threats, 19 exercised by at least one implementation. Cell = worst verdict over the threat's scenarios (FAIL > PARTIAL > ERROR > PASS); — = not exercised, n/a = threat does not apply to this ecosystem.

| Threat | Title | Existing suites | python-tuf | go-tuf | tuf-js | rauc-grub: ext4 /boot (default) | rauc-grub: ext2 /boot | rauc-grub: vfat /boot | rauc-grub: + in-place env (fix) | rauc-grub: UEFI, grubenv on ESP |
|---|---|---|---|---|---|---|---|---|---|---|
| OTA-AUTH-01 | Arbitrary software installation (artifact substitution) | mcuboot-sim,mender-integration,tuf-conformance | ✅ | ✅ | ✅ | ✅ | — | — | — | — |
| OTA-AUTH-02 | Metadata tampering without keys | tuf-conformance | ✅ | ✅ | ✅ | — | — | — | — | — |
| OTA-AUTH-03 | Signature / keyid confusion | tuf-conformance | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-FRESH-01 | Indefinite freeze (replay of expired metadata) | tuf-conformance | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-FRESH-02 | Rollback (replay of older validly signed metadata / firmware) | mcuboot-sim,tuf-conformance | ✅ | ✅ | ✅ | ❌ | — | — | — | — |
| OTA-FRESH-03 | Mix-and-match | tuf-conformance | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-FRESH-04 | Fast-forward (attacker-inflated version locks out recovery) | tuf-conformance | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-KEY-01 | Online-key compromise -> downgrade to older firmware | tuf-conformance | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-KEY-02 | Online-key compromise -> arbitrary software | — | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-KEY-03 | Compromised key not revoked after root rotation | tuf-conformance | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-KEY-04 | Online-key compromise -> indefinite freeze with fresh signatures | — | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-DOS-01 | Endless data (metadata) | — | ✅ | ✅ | ✅ | — | — | — | — | — |
| OTA-DOS-02 | Endless data (artifact beyond signed length) | — | ✅ | ✅ | ✅ | — | — | — | — | — |
| OTA-DOS-03 | Slow retrieval (metadata) | — | ❌ | ❌ | ✅ | — | — | — | — | — |
| OTA-DOS-04 | Slow retrieval (artifact) | — | ❌ | ❌ | ✅ | — | — | — | — | — |
| OTA-DOS-05 | Malicious mirror prevents updates (no fallback) | — | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-NET-01 | Interrupted transfer, recovery on retry | aktualizr-tests,mender-integration | ✅ | ✅ | ✅ | — | — | — | — | — |
| OTA-PWR-01 | Power loss during metadata update (trust state must not brick) | — | ✅ | ✅ | ✅ | n/a | n/a | n/a | n/a | n/a |
| OTA-PWR-02 | Power loss during artifact download/storage | — | ✅ | ✅ | ⚠️ | — | — | — | — | — |
| OTA-PWR-03 | Power loss while writing the inactive A/B slot | mcuboot-sim | n/a | n/a | n/a | ✅ 100 states, 44 DEGRADED | ✅ 53 states, 1 DEGRADED | ✅ 58 states, 4 DEGRADED | ✅ 212 states, 0 DEGRADED | ✅ 56 states, 3 DEGRADED |
| OTA-PWR-04 | Power loss during boot-slot switch / first boot (fallback via boot counter) | mcuboot-sim | n/a | n/a | n/a | ✅ | — | — | — | — |
| OTA-PWR-05 | Power loss leaves the update state unusable (device boots but can no longer be updated) | — | n/a | n/a | n/a | ✅ env unreadable in 0/16 | 🟡 env unreadable in 1/14 | 🟡 env unreadable in 4/22 | ✅ env unreadable in 0/68 | 🟡 env unreadable in 2/20 |
| OTA-PWR-06 | Power loss corrupts the RUNNING slot (writable rootfs) during an update | — | n/a | n/a | n/a | ✅ BRICK 0 of 18 torn states | — | ✅ BRICK 0 of 11 torn states | ❌ BRICK 3 of 44 torn states | — |
| OTA-INST-01 | Wrong software installation (wrong device/hardware class) | tuf-conformance | — | — | — | — | — | — | — | — |
| OTA-INST-02 | Partial bundle installation (multi-ECU / multi-image) | — | n/a | n/a | n/a | — | — | — | — | — |
| OTA-PARSE-01 | Malformed metadata / manifest triggers parser fault | oss-fuzz | — | — | — | — | — | — | — | — |
| OTA-INST-03 | Extraneous dependencies | — | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-INST-04 | TOCTOU between verification and use | — | — | — | — | — | — | — | — | — |
| OTA-INST-05 | Wrong delta precursor | — | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| OTA-AUTH-04 | Extra data after a valid image | — | — | — | — | — | — | — | — | — |
| OTA-AUTH-05 | Debug / pre-production build accepted | — | n/a | n/a | n/a | — | — | — | — | — |
| OTA-AUTHZ-01 | Unapproved firmware / override of critical manifest elements | tuf-conformance | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-CONF-01 | Eavesdropping on update content (image disclosure) | — | n/a | n/a | n/a | — | — | — | — | — |
| OTA-CONF-02 | Confidential manifest element exposure | — | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| OTA-DOS-06 | Drop-request (update traffic blocked) | — | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-FRESH-05 | Cross-device replay of image-less Director metadata | — | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| OTA-TIME-01 | Absent or invalid time attestation | — | — | — | — | n/a | n/a | n/a | n/a | n/a |
| OTA-REP-01 | Version-report replay / attacker-authored version report | — | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| OTA-NET-02 | Missing transport / update-server authentication | — | — | — | — | — | — | — | — | — |
| OTA-PARSE-02 | Unsupported spec / encoding version accepted | — | — | — | — | n/a | n/a | n/a | n/a | n/a |

Readings of block-level results per threat: see the module docstring of `otabench/threatmatrix.py`.
