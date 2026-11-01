# otabench: An Executable Cross-Ecosystem Benchmark for the Security and Fault Tolerance of Software Update Systems

*Draft for ACM SCORED 2027 (≈10 pages, ACM two-column). Status: full text of all sections; numbers
marked **[rerun]** come from runs under host load and are being repeated on a quiet host; numbers
marked **[pending]** wait for runs in progress. Bracketed citations [x] refer to the reference list
at the end; the thesis list (`docs/thesis/references.md`) has the full bibliographic data.*

## Abstract

Software update systems are a primary channel for both attacks and large-scale outages, and
regulation such as the EU Cyber Resilience Act now makes a secure update mechanism mandatory.
Yet the properties that update specifications require — authenticity, freshness, compromise
resilience, atomic installation — are tested, if at all, only inside individual ecosystems, and
resilience to power loss during an update is not systematically tested for update clients at
all. We present otabench, an open executable benchmark that evaluates update clients and A/B
updaters as black boxes against one machine-readable catalog of 40 threats spanning TUF, Uptane,
IETF SUIT and Linux A/B updaters, mapped to specification clauses and regulatory requirements.
Existing executable suites cover 15 of the 40 threats; otabench covers 26. otabench reuses the
tuf-conformance client protocol, adds a device-adapter protocol for A/B updaters in QEMU,
adversarial repositories, and power-loss injection at process, block and system level, with
prefix, reordering and sector-tearing crash models over a dm-log-writes trace. Negative-control
implementations and mutants validate every oracle. Applied to four TUF clients, one SUIT
processor and three A/B updater versions, otabench finds four specification-level divergences
between TUF clients, a window in which a power cut after a reported-successful RAUC install
silently reverts the slot switch, bootloader-environment corruption that leaves devices bootable
but no longer updatable — on journaling ext4 with default settings too —, corruption of the
running slot under torn writes, an A/B updater that reports failure for an update it applied,
and confirms a signature-coverage flaw in the RAUC version shipped by Debian 12. A 30-line in-place
environment writer removes the RAUC window and corruption in all tested states.

## 1 Introduction

The update mechanism is the most privileged component of a deployed system: it installs the code
the device will trust next. Attacks on it have been studied since package managers were shown to
be vulnerable to substitution, rollback and freeze attacks from a malicious mirror [1], and key
compromise without dedicated defenses was shown to be fatal [2]. This line of work produced The
Update Framework (TUF) [3], its automotive variant Uptane [4], and the IETF SUIT architecture and
manifest for constrained devices [5, 6]. Embedded Linux converged on A/B updating with a
bootloader fallback, implemented by RAUC, SWUpdate and Mender.

Fault tolerance matters as much as security. The CrowdStrike incident of 19 July 2024 affected
about 8.5 million Windows hosts through the content-delivery path [7]; embedded devices add power
loss at an arbitrary moment of installation. Regulation now demands both: the Cyber Resilience
Act requires vulnerabilities to be fixed through secure updates and availability of essential
functions to be protected [9]; UN Regulation No. 156 requires vehicles to recover a previous
version or a safe state after an interrupted update [10]; Russian FSTEC orders require integrity
control of updates [11, 12]. None of these documents contains an executable test, and the
existing executable suites are tied to one ecosystem: tuf-conformance checks TUF clients at the
metadata level [14], the MCUboot simulator checks one bootloader under write failures [15].

**Gap.** To our knowledge there is no open executable benchmark that checks implementations of
different update ecosystems against one threat catalog and includes power loss at the level of
block writes. The closest precedents are threat × implementation matrices built by manual
analysis [1, 17] and test derivation for single Uptane implementations [18–20].

**Contributions.**
1. A machine-readable catalog of 40 threats for TUF, Uptane, SUIT and A/B updaters in which
   faults are first-class next to attacks, each traced to specification and regulatory clauses,
   and an analysis of its coverage by existing executable suites (§3).
2. otabench, an open bench that tests implementations as black boxes through two adapter
   protocols (update clients, A/B updaters), with an adversarial repository, power-loss injection
   at three levels and three block-level crash models, and oracles validated by negative-control
   implementations and mutants (§4).
3. An evaluation on four TUF clients (python-tuf, go-tuf, tuf-js, tough), one SUIT processor and
   RAUC 1.8, RAUC 1.15.2 and SWUpdate with GRUB (§5), with findings that process-level crash
   testing cannot reveal and a fix validated by the same scenarios (§6).

## 2 Background

**TUF and Uptane.** A TUF client updates trusted metadata in a fixed order — root, timestamp,
snapshot, targets with delegations — checking signature thresholds, expiry and version
monotonicity, then downloads an artifact of at most the signed length and verifies its hashes
[3, §5]. Uptane splits the repository into an Image and a Director repository and adds full and
partial verification on ECUs, a secure time source and explicit requirements against slow
retrieval [4, §5.4].

**SUIT.** A SUIT manifest is a CBOR command sequence authenticated with COSE; the processor
checks conditions (vendor and class identifiers, image digest) and executes directives
(fetch, copy, install) [6].

**A/B updaters.** RAUC and SWUpdate write the inactive slot, then switch the bootloader's
primary slot; the bootloader counts boot attempts and falls back if the new slot is never
confirmed. With GRUB, the switch is a rewrite of the 1024-byte environment file `grubenv`.

**Existing executable tests.** tuf-conformance runs a client binary through `init`, `refresh`
and `download` against a simulated repository [14]. The MCUboot simulator interrupts flash
writes during image swaps [15]. Mender and aktualizr ship integration tests that interrupt
network transfers; OSS-Fuzz fuzzes several parsers.

## 3 Threat catalog

**Schema.** A catalog entry describes one attack or one fault the update system must withstand:
class (authenticity, freshness, key compromise, availability, fault tolerance, installation,
parsing, confidentiality), violated property, attacker model (`net`, `online-keys`,
`offline-keys`, `fault`), ecosystems, references to clauses of TUF 1.0.37, Uptane 2.1.0, SUIT
RFCs, EN 18031, OWASP ISVS, ETSI EN 303 645, the CRA and FSTEC documents, expected behavior
(block, survive, out of scope) and the bench scenarios that execute it. A `spec_status` field
separates "is the property provided?" from "is the specification violated?": slow-retrieval
protection was removed from TUF's goals in 1.0.7 but is mandatory in Uptane 2.1.0 §5.4. The
catalog is YAML validated by a JSON Schema; all 40 entries' references were checked against the
source texts. Regulatory traceability goes through protected properties and is marked as
interpretation where a document does not name the property: the CRA requires authenticity,
integrity and availability after an incident but names neither rollback, freeze nor key
compromise.

**Faults as threats.** Seven entries are faults: interrupted transfer; power loss during a
metadata update, during artifact storage, while writing the inactive slot and at the slot switch
or first boot; and two added after our experiments — power loss that leaves the device bootable
but no longer updatable (OTA-PWR-05) and corruption of the running slot (OTA-PWR-06).

**Coverage (RQ1).** A threat counts as covered by a suite if the suite contains a test that
checks it by intent; test names were matched against the suites' sources at pinned commits and
assertions were read. Table 1 summarizes.

*Table 1 — Catalog coverage by class (40 threats).*

| Class | Threats | Existing suites | otabench | otabench only | Nobody |
|---|---|---|---|---|---|
| authenticity | 8 | 4 | 4 | 1 | 3 |
| freshness | 6 | 4 | 3 | 0 | 2 |
| key compromise | 4 | 2 | 3 | 2 | 0 |
| availability | 6 | 0 | 6 | 6 | 0 |
| fault tolerance | 7 | 3 | 7 | 4 | 0 |
| installation | 5 | 1 | 1 | 1 | 3 |
| parsing | 2 | 1 | 2 | 1 | 0 |
| confidentiality | 2 | 0 | 0 | 0 | 2 |
| **Total** | **40** | **15** | **26** | **15** | **10** |

Existing suites cover 15 threats (38%): tuf-conformance 11, the MCUboot simulator 4, Mender's
tests 2, aktualizr and OSS-Fuzz one each; for two MCUboot tests the developers themselves note
that the check is weaker than the name suggests, so this is an upper bound. The availability
class (endless and slow data, malicious mirror, blocked traffic) is not covered at all, nor are
power loss during metadata update and artifact storage in clients, nor loss of updatability.
No suite we examined contains executable SUIT tests. Coverage by otabench is defined by the
existence of a scenario, not by its execution in every ecosystem of the entry (§7).

## 4 Design of otabench

**Black box through adapters.** An implementation is reached only through an adapter. *Update
clients* use the tuf-conformance protocol unchanged: an executable with `init`, `refresh` and
`download`; python-tuf and go-tuf need no code of ours, tuf-js needs 53 significant lines.
*A/B updaters* are described by a YAML device adapter (protocol v2): artifact roles and paths,
shell commands executed in the QEMU guest through qemu-guest-agent (`install`, `status` as
`key=value` lines, `reboot`, `unconfirm`, `slot_digest`), and a regular expression that extracts
the slot the bootloader selected from the serial console. Configuration variants (file system of
the environment partition, writeback parameters, UEFI, fixes) are declared as guest steps;
adapters can `extend` each other. The RAUC 1.8 adapter has 49 lines, RAUC 1.15.2 extends it
with 4, SWUpdate has 46. Scenarios know only artifact *roles* — a valid new version, an older
version, a validly signed unbootable image, an image signed with a foreign key — never the
artifact format; the format lives in per-updater build scripts.

**Adversarial repository.** For clients, a TUF repository simulator is served by an HTTP/1.1
server that applies per-scenario rules to requests: substitute, replay older metadata, stream
endlessly, trickle at 2 B/s, truncate, drop, or reset the connection, and records who closed the
connection, which gives a censored time-to-abort.

**Power loss at three levels.**
*Process level:* the client is killed at event-based points: a rehearsal counts the N requests
of an update; each request is then killed at arrival, right after its response and 10 ms after
it (3N points), and the next run must recover.
*Block level:* one install is recorded with QEMU's `blklogwrites` (dm-log-writes format). Crash
states are rebuilt on a raw copy of the disk and booted through overlays. The *prefix* model
applies entries 0..k. The *reordering* model, for each interval between FLUSH barriers, applies
bounded subsets of the volatile writes (none, all, one, all-but-one), as a disk with a volatile
cache may expose. The *sector-tearing* model additionally keeps only the first k ∈ {1, n/2}
sectors of a multi-sector write. Timestamped markers written with O_DIRECT map "δ seconds after
the updater reported success" to log positions.
*System level:* the VM is powered off through QMP during the first boot of the new slot.

**Oracles.** Verdicts use only observables common to all implementations of a profile. For
clients: the trusted metadata on disk and the exit code. For A/B updaters each crash state is
classified by comparing two views of the A/B state — the bootloader's (serial console) and the
OS's (`status`): OK; DEGRADED (boots, but the environment is unreadable, the fallback rule fired,
or the views disagree); INCONSISTENT (the booted (slot, version) pair is neither the old nor the
new one); BRICK (no boot; confirmed by a second boot of the same state with a doubled timeout).
Liveness — can the next update be installed? — is checked for a subset of states.

**Validating the bench.** A negative-control client (`naive`) and mutants with one defense
removed each must fail exactly the scenarios that test that defense; for A/B updaters,
configurations without a journal are specificity controls for the window and the fix variants
are controls for the fix; a hand-written verify-then-reopen installer is the control for the
TOCTOU scenario. Preconditions that cannot be established yield ERROR rather than PASS (for
example, if an install of the genuine artifact fails in the same state, a rejected downgrade
proves nothing). Systematic crash points form a census: any bad state yields FAIL and no
confidence interval is attached; random trials report survival with a 95% Wilson interval.

## 5 Evaluation

**Setup.** One host (Windows 11, Ryzen 5 3600, 32 GB). Client scenarios ran natively and in a
Linux container; A/B updaters ran in QEMU 11.1 with WHPX (Debian 12 guest, GRUB 2.06, 2 vCPU,
1 GiB). Reboots are emulated by power cycles because warm reboots hang under WHPX. Implementations:
python-tuf 7.0.1, go-tuf v2.4.2, tuf-js 6.0.1, tough 0.24.0 (Linux only), libcsuit (commit
00f5609), RAUC 1.8 (Debian 12 package), RAUC 1.15.2 (release tarball) and SWUpdate 2024.12.1.

### 5.1 TUF clients (RQ2, RQ3)

21 scenarios × 9 implementations (3 real, the control and 5 mutants) were run on Windows and on
Linux; verdicts agree in 188 of 189 cells (the exception is a mutant in a scenario with random
kill delays). All three clients blocked every authenticity, freshness and online-key attack and
aborted endless data within 0.10–0.64 s. Attack block rates: python-tuf 15/17, go-tuf 14/17,
tuf-js 17/17. All clients survived every process-level kill point; the event-based points kill a
mutant that replaces root non-atomically, which random delays never did. Every scenario of the
core set kills at least one mutant.

**Four divergences between implementations of one specification.**
(1) *Slow retrieval:* at 2 B/s python-tuf and go-tuf did not abort within 120 s; tuf-js aborted
after 100 s on its overall timeout. Not a TUF 1.0.37 violation, but Uptane clients built on these
libraries must add this defense themselves.
(2) *spec_version:* go-tuf and tough accepted correctly signed metadata with `spec_version`
2.0.0 and persisted it as trusted; python-tuf and tuf-js rejected it. tuf-conformance has no
such test.
(3) *One key under two keyids:* with threshold 2 and the same key listed twice, python-tuf and
tuf-js count one signature twice, go-tuf and tough do not. The class was published for go-tuf < 0.3.2;
python-tuf maintainers consider key uniqueness the delegator's responsibility. This is a
divergence between documented positions, not a new vulnerability.
(4) *Equal timestamp version:* TUF 1.0.37 §5.4.3.1 keeps the trusted timestamp when a new one has
the same version; Uptane 2.1.0 full verification accepts an equal version. python-tuf, go-tuf and
tuf-js keep the trusted file; tough accepts the equal-version timestamp with new content
(its check is `old <= new`, citing TUF 1.0.16). The impact is low — the file must still be signed
by the timestamp key — but it shows that version rules differ between the specifications and
between implementations of one of them.

**tough.** Connected later with a 105-line Rust adapter and run in the Linux container on the
whole suite: 17 of 19 attacks blocked (python-tuf 16 of 19 in the same run), endless data aborted
within 0.25–0.58 s, slow retrieval aborted after ~30 s by its HTTP transport timeout, all 15
event-based kill points and 10 download kills survived.

### 5.2 SUIT

A six-scenario authenticity and parsing profile on libcsuit separates the processor from its
own example with suppressed condition failures (the control): a payload with a wrong digest is
rejected by the former and accepted by the latter. For 6 of 21 malformed inputs
`suit_process_envelope()` returned success having processed nothing, and the stock example
dereferences NULL when printing the empty report.

### 5.3 A/B updaters: system level

All three updaters passed the happy path, rejected foreign-key artifacts without touching the
bootloader state, and fell back when the new slot was unbootable or lost power during its first
boot. When the current slot was not confirmed before the install, only the bench's rescue rule
in `grub.cfg` saved the device — a property of the integration, which is why both variants are
run. All three accept a downgrade in the default configuration; RAUC 1.15.2's
`min-bundle-version` and SWUpdate's `-N` reject it.

### 5.4 A/B updaters: block level (RQ3)

*Table 2 — Bad crash states by model (bad = DEGRADED, INCONSISTENT or BRICK; no run produced an
INCONSISTENT state). Prefix: 45 points over the whole install (`crash-replay`) or the 24 entries
before install completion (region); reordering and tearing: bounded subsets in that region.*

| Updater, environment fs | Prefix | Reordering | Torn (extra states) |
|---|---|---|---|
| RAUC 1.8, ext4 | 17/45 DEGRADED (12 view divergence, 5 rescue) | 11/16 divergence | 10/18 divergence |
| RAUC 1.8, ext2 | 0/24 (region) | 1/14 env unreadable | — |
| RAUC 1.8, vfat | 0/24 (region) | 4/22 env unreadable | 0/11 |
| RAUC 1.8, UEFI ESP | 1/24 env unreadable (region) | 2/20 env unreadable | — |
| RAUC 1.15.2, ext4 / vfat / ESP | 18/49 DEGRADED, **1 env unreadable at install start** | 11/26 / 4/28 / 2/28 | — |
| RAUC + in-place writer (ext4, ext2, vfat, ESP) | 0 | 0 | 0–2 BRICK per variant (running slot, §6.3) |
| SWUpdate, ext4 / ext2 | 7/46 DEGRADED (1 divergence, 6 rescue) | 0/18 / **20/50 env unreadable** | — |

**Window after success (RAUC).** On ext4, a power cut up to 4 s after `rauc install` reported
success makes GRUB boot the old slot while Linux, after journal replay, sees the new one:
W ∈ (4; 5] s. Eight configurations establish the mechanism: the window is the same for
`commit=1/5/30`, shrinks to (0; 1] s with `vm.dirty_writeback_centisecs=100` alone, is unchanged
with `dirty_expire_centisecs=100` alone, and disappears without a journal (ext2, vfat). GRUB does
not replay the ext4 journal and reads the old inode of the rewritten file until writeback moves
the metadata home. RAUC 1.15.2 still writes through `grub-editenv` and shows the same divergence
states; its window length **[rerun]**.

**Window after success (SWUpdate).** SWUpdate writes `grubenv.new` and renames it without fsync.
At +0, +2 and +4 s after success *both* views still show the old state, from +6 s both show the
new one: the update is lost consistently rather than with divergent views **[rerun on a quiet
host]**.

**Loss of updatability.** On file systems without a journal, the reordering model produced an
empty or invalid `grubenv` (ext2 1 of 14 states, vfat 4 of 22). On RAUC 1.15.2 with the default
ext4 the prefix model hit one such state at the start of the install, where RAUC marks the target
slot bad by rewriting `grubenv`: restored from the trace, the file has zero length, GRUB falls
back, and `rauc install` fails (`grub-editenv failed`) — ext4 had committed the truncation before
the new data, the classic zero-length window of delayed allocation. SWUpdate's rename without
fsync left an unreadable environment in 20 of 50 states on ext2, also in prefix states. In
the UEFI layout recommended by RAUC's documentation, with `grubenv` on the ESP, even the prefix
model produced one. Such a device boots, but every further `rauc install` fails with
`grub-editenv` errors: it has silently dropped out of OTA (OTA-PWR-05). Liveness checks from
restored states confirmed this.

### 5.5 Installation-time attacks

**Signature coverage (RAUC plain bundles > 2 GiB, CVE-2026-34155).** In a container we built a
plain bundle with a 2.07 GiB payload, signed by RAUC 1.8 (Debian 12 package 1.8-2, the version in
our A/B image). RAUC 1.8's `rauc info --keyring` — the verification path of `rauc install` —
accepted the bundle after one byte was flipped 1 GiB into the payload, and accepted a *foreign*
squashfs (other rootfs, manifest version 666) with the genuine bundle's signature appended: the
size passed to OpenSSL overflows and the signature covers only the bytes before the first NUL,
here five bytes of the squashfs superblock. RAUC 1.15.2 rejects both and refuses to sign such a
bundle. A small tampered bundle is rejected by both versions (sensitivity control).

**TOCTOU between verification and use (OTA-INST-04).** The genuine bundle sits in a directory
owned by an unprivileged update service, which holds a writable descriptor (or opens the file
late) and overwrites it with the foreign-key artifact 2, 6 or 12 s into the install. The oracle
compares the digest of the target slot with an unattacked install. The verify-then-reopen
control installed the attacker's image in 3 of 4 trials (FAIL). RAUC 1.8 and 1.15.2 refused the
install within 0.2–0.8 s whenever the attacker held a writable descriptor (RAUC ≥ 1.5 takes
ownership of the bundle and checks leases), and a late open by the attacker failed with EACCES;
SWUpdate rejected every swapped stream by its per-image hashes. All three PASS, the boot state
untouched.

### 5.6 Cost (RQ4)

*Table 3 — Cost of connecting an implementation (significant lines of code we wrote).*

| Implementation | Adapter | Artifact driver |
|---|---|---|
| python-tuf, go-tuf | 0 (tuf-conformance clients) | repository simulator |
| tuf-js | 53 | repository simulator |
| libcsuit | example + 3 patches | library test manifests |
| RAUC 1.8 + GRUB | 49 | image build script (125) |
| RAUC 1.15.2 + GRUB | 4 (`extends`) | upgrade script (105) |
| SWUpdate + GRUB | 46 | image build script (101) + guest files (76) |

Scenario code did not change for any new implementation. A full client run takes about
4 minutes; a block-level scenario 10–25 minutes (≈10–20 s per crash state).

## 6 Findings in depth

### 6.1 A 30-line fix, validated by the same scenarios

Both RAUC findings have one cause: `grub-editenv` opens `grubenv` with `O_TRUNC` and rewrites it.
The file gets a new block, its metadata change, and an intermediate "empty file" state exists.
GRUB's own `save_env` rewrites the existing blocks in place. A custom RAUC bootloader backend
(`bootloader=custom`) with the same variables writes the 1024-byte block at offset 0 without
`O_TRUNC` and calls fsync. With it, the window disappeared on ext4 and no bad state remained on
ext4, ext2, vfat and the ESP under the prefix, reordering and tearing models (Table 2); all
variables fit into the first sector of the block, so any sector-level outcome is a valid old or
new environment. A temp-file-plus-rename scheme would reintroduce the window on ext4, because the
rename again changes metadata invisible to a reader that does not replay the journal.

### 6.2 The prefix model is not enough

On ext2 and vfat the prefix model found nothing, the reordering model found unreadable
environments. Negative results of the prefix model are therefore no evidence of absence for
disks with volatile caches, and the reordering model is mandatory in the method.

### 6.3 The A/B scheme does not protect the running slot

Under sector tearing, states in which a 4 KiB write to the ext4 journal of the *running* slot A
was torn made A unmountable (`error loading journal`), and the device looped through kernel
panics: slot B was not yet primary and there was nothing to fall back to. During one install the
running slot received 382 writes (rw root, journald and the ext4 journal). With the root mounted
read-only it received none, and the tearing model produced no BRICK (one apparent BRICK was a
boot timeout under host load; the same state booted on isolated replay, which led to the
second-boot confirmation rule). The model is pessimistic — many devices write 4 KiB atomically
— but it turns "keep the root read-only" from advice into a measured property.

## 7 Discussion and limitations

*Compliance.* The bench produces reproducible evidence within its models, not a proof of
conformity with the CRA, UN R156 or FSTEC requirements; it tests the delivery and installation
mechanism, not the update packages themselves.

*Internal validity.* Oracles were checked with controls and mutants; ERROR isolates harness
failures, but any exception becomes ERROR and could hide a harness defect. Three harness
artifacts were found and fixed during the evaluation (a late kill timer, an HTTP/1.0 behavior
that triggered an assertion in Node.js, a racy "unconfirmed" precondition).

*Construct validity.* Thresholds for endless and slow data are bench policy; raw times are
published. Reordering uses bounded subsets around the environment rewrite, so counts of bad
states are lower bounds.

*External validity.* One Windows host with WHPX; reboots emulated by power cycles; emulated disk
without power-loss protection; Uptane and network attacks on A/B updaters not evaluated; SUIT
represented by one implementation. Coverage by otabench means a scenario exists, not that it ran
in every ecosystem of the entry.

## 8 Related work

*Update security:* attacks on package managers [1], survivable key compromise [2], TUF [3],
Uptane [4] and its formal analysis [16], SUIT [5, 6], IoT firmware update analyses [17], test
derivation for Uptane from attack trees and CSP models [18–20]. *Crash consistency:* analysis of
application update protocols (ALICE) [21], bounded black-box crash testing of file systems
(CrashMonkey) [22], emulation of lost unsynced data (LazyFS) [23]; we transfer these ideas to
update systems as the object under test and combine them with an adversarial repository.
*Conformance and differential testing of protocol implementations:* TLS-Anvil, JWT test suites
and JSON parser differentials [24–26]; benchmark validity by ground truth from fuzzing
evaluation practice [27].

## 9 Conclusion

otabench makes a cross-ecosystem threat catalog executable. It shows that most availability and
fault-tolerance threats are untested by existing suites, separates implementations of one
specification, and finds in A/B updaters defects that only block-level crash models expose.
Catalog, bench, raw results and drafts of upstream reports are open.

## Artifact appendix (outline)

Repository with the bench, catalog (YAML + JSON Schema), adapters, raw results of every run
(`results.json`, `pilot.json`, block-level traces available on request because of size), Docker
images for the client profile, the SUIT profile and RAUC verification; CI runs unit tests and a
short client run on Linux. A/B experiments need QEMU and the image build scripts.

## References (short form; full data in the thesis list)

[1] Cappos et al., A Look in the Mirror, CCS 2008. [2] Samuel et al., Survivable Key Compromise,
CCS 2010. [3] TUF Specification 1.0.37. [4] Uptane Standard 2.1.0. [5] RFC 9019. [6] RFC 9124 and
draft-ietf-suit-manifest. [7] Microsoft, CrowdStrike outage, 2024. [9] Regulation (EU) 2024/2847.
[10] UN Regulation No. 156. [11, 12] FSTEC orders No. 117 (2025) and No. 239. [14] tuf-conformance.
[15] MCUboot simulator. [16] Lorch et al., RAID 2024. [17] IoT firmware update analysis (AoT,
EuroS&P 2023). [18–20] Mahmood et al., ICSTW 2020 and Vehicular Communications 2022; Kirk et al.,
JLAMP 2022. [21] Pillai et al., OSDI 2014. [22] Mohan et al., OSDI 2018. [23] LazyFS, 2023.
[24–26] TLS-Anvil (USENIX Security 2022), JWT test suites, JSON parser differentials (AsiaCCS
2024). [27] Schloegel et al., SoK: Prudent Evaluation Practices for Fuzzing, S&P 2024.
