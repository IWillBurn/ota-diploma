# Requirements traceability: OTA update specifications → threat classes → client behaviour → conformance observation

Scope: defensive conformance-testing documentation for an OTA-client benchmark (TUF, Uptane, IETF SUIT, Linux/MCU A/B updaters). All clause numbers below were read from local copies of the primary texts (scratchpad `dl/`, `pdf/`); anything not located in the text is marked **NOT FOUND**. Threat names are quoted exactly as the specs name them. TUF section numbers are Bikeshed auto-numbers; they are confirmed by the spec's own cross-references (e.g. "go to step 5.3.10", "steps 5.6.7.1 - 5.6.7.2") and by the 2020 commit message that cites "Section 1.5.2. Goals to protect against specific attacks".

Local evidence base (all read as data only): `dl/tuf-spec.md` (byte-identical to tag `v1.0.37` of the spec repo, verified with `diff` against `git show v1.0.37:tuf-spec.md`), `dl/uptane-2.1.0.txt` + `dl/uptane-standard.md`, `dl/rfc9019.txt`, `dl/rfc9124.txt`, `dl/draft-ietf-suit-*.txt`, `dl/queue.xml` (RFC Editor queue snapshot), `dl/isvs/*`, `dl/ab/*`, `dl/updeploy/*`, `dl/conf/tufconf-readme.md`, `dl/taps-readme.md`, `pdf/uptane-raid.txt`; plus a blob-less clone of `theupdateframework/specification` for history.

## 1. Spec versions, dates and official URLs

### Takeaway
All six primary documents were pinned to exact versions; the only status ambiguity is the SUIT manifest: the latest local text is draft-ietf-suit-manifest-37 (18 June 2026, Standards Track, still an Internet-Draft), while the local RFC Editor queue snapshot still lists -34 "in queue / formatting".

### Cited Findings
| Document | Version / number | Date | Status (as stated in text) | Official URL |
|---|---|---|---|---|
| The Update Framework Specification | 1.0.37 (`Text Macro: VERSION 1.0.37`) | `Date: 2026-10-08`; git tag `v1.0.37` = commit `d4cb705` 2026-10-08 "spec: only skip target roles if they appear in the same delegation path (#327)" | `Status: LS` (living standard) | https://github.com/theupdateframework/specification/tree/v1.0.37 ; rendered "latest": https://theupdateframework.github.io/specification/latest/ |
| Uptane Standard for Design and Implementation | 2.1.0 (title line of `uptane-2.1.0.txt`) | Changelog: "[2.1.0] - 2023-06-6" (sic) | Minor release, "no breaking changes"; git tag `2.1.0` = `46497aa` | https://github.com/uptane/uptane-standard/tree/2.1.0 |
| Uptane Deployment Best Practices (companion, [DEPLOY]) | same changelog file | — | informative companion | https://uptane.github.io/deployment-considerations/index.html |
| RFC 9019 "A Firmware Update Architecture for Internet of Things" | RFC 9019 | April 2021 | Informational (IETF) | https://www.rfc-editor.org/rfc/rfc9019 |
| RFC 9124 "A Manifest Information Model for Firmware Updates in Internet of Things (IoT) Devices" | RFC 9124 | January 2022 | Informational (IETF) | https://www.rfc-editor.org/rfc/rfc9124 |
| "A CBOR-based Serialization Format for the SUIT Manifest" | draft-ietf-suit-manifest-37 (local -34 also present) | 18 June 2026 (-37), expires 20 December 2026; -34 dated 28 May 2025 | "Intended status: Standards Track"; Internet-Draft "work in progress" | https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/ |
| OWASP IoT Security Verification Standard (ISVS) | 1.0 | "Version 1.0, October 2025"; CHANGELOG "[1.0] - 2025-10-04" | Official release, 165 requirements, levels L1–L3 | https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS |

- TUF 1.0.37 header: `Status: LS`, `Date: 2026-10-08`, `Text Macro: VERSION 1.0.37`, editors Cappos, Kuppusamy, Lock, Moore, Pühringer — [TUF spec v1.0.37](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- Previous TUF tag v1.0.36 = 2026-08-10 "Only define THRESHOLD once (#322)" — [spec repo tags](https://github.com/theupdateframework/specification/tags)
- Uptane 2.1.0 changelog: "V.2.1.0 is a minor release containing no breaking changes… largely wording clarifications"; relaxed Director check of ECU-report time from SHALL to SHOULD; relaxed completion rule when Director indicates no new targets — [Uptane changelog, Deployment Best Practices site](https://github.com/uptane/deployment-considerations) (local `dl/updeploy/changelog.md`; exact page URL not verified)
- Uptane 2.0.0 (2022-01-18) changed slow-retrieval monitoring in §5.4 and image-length check in §5.4.3.4 from SHOULD to SHALL, and removed the Uptane Time Server — [Uptane changelog](https://github.com/uptane/deployment-considerations) (local `dl/updeploy/changelog.md`)
- RFC Editor queue snapshot (`dl/queue.xml`, section "IETF STREAM: SOFTWARE UPDATES FOR INTERNET OF THINGS"): entry `draft-ietf-suit-manifest` → `<draft>draft-ietf-suit-manifest-34.txt</draft>`, `<date-received>2025-02-25</date-received>`, `<assignment>formatting</assignment>`, normative refs to suit-report, trust-domains, firmware-encryption, mti, update-management all `IN-QUEUE` — [RFC Editor queue](https://www.rfc-editor.org/current_queue.php)
- Other SUIT drafts in the same queue snapshot: suit-mud-10 (blocked), suit-firmware-encryption-26 (blocked), suit-trust-domains-12 (formatting), suit-mti-23 (ref_checker), suit-report-19 (blocked; local file is -22), suit-update-management-16 (blocked, received 2026-09-30) — [RFC Editor queue](https://www.rfc-editor.org/current_queue.php)
- ISVS 1.0 counts: V1 40, V2 34, V3 49, V4 46, V5 13 requirements per RELEASE_NOTES; CHANGELOG lists different per-chapter counts (V2 32, V3 47, V4 42, V5 12) — [ISVS RELEASE_NOTES / CHANGELOG](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS)
- ISVS repository's only visible git tag is `1.0RC` (checked with `git ls-remote --tags`), although the in-repo docs say "Official Release - October 2025" — [ISVS repo](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS)

### Inferences
- For citation in the thesis, pin TUF to the tag URL (`/tree/v1.0.37`) rather than "latest", because "latest" will drift.
- The SUIT manifest should be cited as "draft-ietf-suit-manifest-37 (work in progress, Standards Track)"; the RFC Editor queue entry at -34 suggests the document was approved and then revised, but the reason is not stated in any local file.

### Gaps
- Why -35…-37 of the SUIT manifest exist while the queue snapshot still shows -34 is not explained locally (no "changes since" section found in -37). Check the datatracker history before submission.
- ISVS RELEASE_NOTES vs CHANGELOG per-chapter requirement counts conflict; actual count not recomputed here.
- The rendered TUF URL with a version path (`/specification/v1.0.37/`) was not opened in this session; only the tag and "latest" URL are evidenced.

## 2. TUF 1.0.37 — threat classes, enforcing client-workflow steps, TAPs

### Takeaway
TUF 1.0.37 §1.5.2 "Goals to protect against specific attacks" names **ten** attack classes; **"Slow retrieval attacks" is no longer listed**: it was removed by commit `f9122f1` (Joshua Lock, 2020-09-08), merged via PR #111 on 2020-09-29 and first released in **TUF spec v1.0.7** (last version listing it: v1.0.6, "Last modified: 23 September 2020"). Most classes map to explicitly labelled steps in §5 "Detailed client workflow"; "Extraneous dependencies attacks" and "Malicious mirrors preventing updates" have no dedicated client step.

### Cited Findings

**2.1 Exact list, §1.5.2 "Goals to protect against specific attacks" (order as in spec)** — [TUF v1.0.37 §1.5.2](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#goals-to-protect-against-specific-attacks)

| # | Name exactly as in spec | One-line meaning (paraphrase of the spec sentence) |
|---|---|---|
| 1 | **Arbitrary installation attacks.** | attacker cannot provide arbitrary files in response to download requests |
| 2 | **Endless data attacks.** | attacker cannot respond with huge amounts of data that interfere with the client system |
| 3 | **Extraneous dependencies attacks.** | attacker cannot cause download/installation of unintended dependencies |
| 4 | **Fast-forward attacks.** | attacker cannot arbitrarily raise metadata version numbers so that later legitimate updates look like rollbacks |
| 5 | **Indefinite freeze attacks.** | attacker cannot keep serving the same outdated metadata without the client noticing |
| 6 | **Malicious mirrors preventing updates.** | a repository mirror cannot prevent updates from good mirrors |
| 7 | **Mix-and-match attacks.** | attacker cannot make clients use a combination of metadata that never coexisted on the repository |
| 8 | **Rollback attacks.** | attacker cannot make clients install software older than what the client previously knew to be available |
| 9 | **Vulnerability to key compromises.** | compromise of a single key or fewer than a threshold of keys (online or offline) cannot compromise clients |
| 10 | **Wrong software installation.** | attacker cannot provide a file (trusted or untrusted) that is not the one the client wanted |

- §1.5.2 preamble: "When saying the framework protects against an attack, it means the attack will be unsuccessful. It does not mean that a client will always successfully update during an attack… Nevertheless, the framework must detect when a client is unable to update." — [TUF v1.0.37 §1.5.2](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- §1.5 Goals: "online keys … must not be used for any role that clients ultimately trust for files they may install"; §1.5.3 Goals for PKI: "All keys must be easily and safely revocable." — [TUF v1.0.37 §1.5, §1.5.3](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- §2.2 "Threat model and analysis": adversary "can respond to client requests, whether by acting as a man-in-the-middle or through compromising repository mirrors… can deny updates to users if no good mirrors are accessible. An inability to obtain updates is noticed by the framework." and "A detailed threat analysis is outside the scope of this document." — [TUF v1.0.37 §2.2](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- Terminology mismatch inside the spec: the goal is named "Arbitrary installation attacks" (§1.5.2), but the enforcing steps are labelled "**Check for an arbitrary software attack.**" (§5.3.4, §5.4.2, §5.5.3, §5.6.3) — [TUF v1.0.37 §5](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#detailed-client-workflow)

**2.2 "Slow retrieval" removal (verified in the spec repo history)**
- `git log -S "Slow retrieval attacks" -- tuf-spec.md` returns only two commits: `daf0e49` (2017-10-11, file added) and `f9122f1662426b217accbc4017d1a3f36afc3e16` (2020-09-08, Joshua Lock, "Remove slow retrieval attacks from protections") — [commit f9122f1](https://github.com/theupdateframework/specification/commit/f9122f1662426b217accbc4017d1a3f36afc3e16)
- Commit rationale (quoted): "For slow retrieval attacks, nothing in the specification provides any protections against this class of attack… protecting against slow retrieval attacks becomes an aspiration for implementations and implementers are left to their own devices"; also notes "The reference implementation does not currently protect against slow retrieval attacks." — [commit f9122f1](https://github.com/theupdateframework/specification/commit/f9122f1662426b217accbc4017d1a3f36afc3e16)
- Merged as "Merge pull request #111 from joshuagl/joshuagl/rm-slow-retrieval" (`7c9c173`, 2020-09-29), which is exactly tag **v1.0.7** ("Version: **1.0.7**", "Last modified: **29 September 2020**") — [PR #111](https://github.com/theupdateframework/specification/pull/111)
- Removed text as it stood in v1.0.6: "**Slow retrieval attacks.** An attacker cannot prevent clients from being aware of interference with receiving updates by responding to client requests so slowly that automated updates never complete." — [TUF v1.0.6](https://github.com/theupdateframework/specification/blob/v1.0.6/tuf-spec.md)
- Contrast: Uptane 2.1.0 still lists "_Slow retrieval attack:_" (§4.3.2) and §5.4 requires "All ECUs SHALL monitor the download speed of image metadata and image binaries to detect and respond to a slow retrieval attack." — [Uptane 2.1.0 §4.3.2, §5.4](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)

**2.3 Client-workflow numbering (§5 "Detailed client workflow")** — [TUF v1.0.37 §5](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#detailed-client-workflow)
- 5.1 Record fixed update start time · 5.2 Load trusted root metadata · 5.3 Update the root role (5.3.1–5.3.12) · 5.4 Update the timestamp role (5.4.1–5.4.5; 5.4.3.1–5.4.3.2) · 5.5 Update the snapshot role (5.5.1–5.5.7) · 5.6 Update the targets role (5.6.1–5.6.7, incl. 5.6.7.1, 5.6.7.2.1, 5.6.7.2.2) · 5.7 Fetch target (5.7.1–5.7.3).
- §5 preamble: "Errors raised during the update process should not leave clients in an unrecoverable state."

**2.4 Threat class → enforcing steps → required client behaviour → conformance observable**

| TUF §1.5.2 class | Enforcing steps (exact) | Required client behaviour (spec wording, condensed) | How a conformance check observes it |
|---|---|---|---|
| Arbitrary installation attacks | 5.3.4, 5.4.2, 5.5.3, 5.6.3 ("Check for an arbitrary software attack"); 5.5.2, 5.6.2 (hash vs. parent); 5.7.1–5.7.3 (target hashes) | metadata MUST be signed by THRESHOLD of keys from trusted root (root N+1 also by its own threshold); target hashes MUST match targets metadata; else discard, abort, report | serve mis-signed/under-threshold metadata or a target whose hash differs → client exits non-zero, no target written, trusted metadata on disk unchanged |
| Endless data attacks | 5.3.3 (W bytes per root; max Y root files); 5.4.1 (X bytes); 5.5.1 (length from timestamp or Y bytes); 5.6.1 (length from snapshot or Z bytes); 5.6.7.1 (max roles visited); 5.7.3 (up to targets-metadata length) | download only up to the bound; stop root walk after Y files; stop delegation search after app-specific max | serve oversize/endless bodies → bytes read ≤ bound (proxy byte counter), client terminates, no oversize file persisted |
| Extraneous dependencies attacks | no step labelled for it; indirect: 5.6.3 + 5.6.7 (only signed, correctly delegated target metadata) + 5.7.1 | only targets found via the signed delegation search are fetched | **NOT FOUND** as a dedicated step; observe that only the requested target path is fetched |
| Fast-forward attacks | 5.3.11 (delete trusted timestamp/snapshot if keys rotated — recovery); prevention by threshold signatures 5.4.2/5.5.3; version equality 5.5.4/5.6.4 | after timestamp/snapshot key rotation, delete trusted timestamp and snapshot metadata | rotate timestamp key in new root after a high-version timestamp → client accepts lower-version timestamp signed by new key |
| Indefinite freeze attacks | 5.1 (fixed update start time); 5.3.10, 5.4.4, 5.5.6, 5.6.5 ("Check for a freeze attack"); §6.1 note on withheld root | expiry MUST be later than fixed start time; else abort and report potential freeze | serve expired metadata / run client under faketime → refusal; tuf-conformance uses `faketime` for this |
| Malicious mirrors preventing updates | no §5 step; §2.1.5 Mirrors role, §4.7 mirrors.json, §2.2 | — | **NOT FOUND** in client workflow; observe only "failure detected and reported" |
| Mix-and-match attacks | 5.5.2 (snapshot hashes vs timestamp), 5.5.4 (snapshot version vs timestamp), 5.6.2 (targets hashes vs snapshot), 5.6.4 (targets version vs snapshot); §2.1.3 | hashes/versions MUST match the parent role's listing; else discard, abort | serve snapshot/targets whose version/hash differs from parent → abort, trusted metadata unchanged |
| Rollback attacks | 5.3.5 (root exactly N+1); 5.4.3.1 (timestamp version strictly greater; equal → abort without error); 5.4.3.2 (snapshot version in timestamp non-decreasing); 5.5.5 (targets versions non-decreasing; previously listed targets filenames still listed); persistence 5.3.8, 5.4.5, 5.5.7, 5.6.6 | discard, abort, report rollback | serve lower-version metadata after a successful run → refusal; also check persisted file version unchanged |
| Vulnerability to key compromises | 5.3.1–5.3.9 (root chain N→N+1, dual threshold); unique-KEYID threshold counting in 5.3.4/5.4.2/5.5.3/5.6.3; 5.3.11; §4.2.1 KEYID; §6.1 | each KEY contributes one SIGNATURE; duplicate KEYID counted once | duplicate-signature / duplicate-keyid metadata → rejected if threshold not met by distinct keys |
| Wrong software installation | 5.6.7 (pre-order DFS, terminating delegations 5.6.7.2.1), 5.7.1–5.7.3 | verify desired target against its targets metadata; no metadata → abort, "no such target" | request target X, serve file for Y with valid metadata for Y → refused / hash mismatch |

Supporting format clauses:
- §4.2.1 Object format: KEYID is "a hexdigest of the SHA-256 hash of the canonical form of the key. The keyid MUST be unique in the 'signatures' array"; Note: list "SHOULD only contain one SIGNATURE per KEYID" — [TUF v1.0.37 §4.2.1](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#file-formats-object-format)
- §4.3 root.json SPEC_VERSION: "clients MUST verify that 'spec_version' matches the expected version number." — [TUF v1.0.37 §4.3](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#file-formats-root)
- §6.1 Key management and migration: "an attacker, who controls the repository, can launch freeze attacks by withholding new root metadata… limited by the expiration time of the latest root metadata available to the client." — [TUF v1.0.37 §6.1](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md#key-management-and-migration)
- §7.1 "Support for bogus clocks" is listed under "Future directions and open questions" (no requirement) — [TUF v1.0.37 §7.1](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- tuf-conformance suite depends on the `faketime` tool and supports per-test "expected failures" (`.xfails`) — [tuf-conformance README](https://github.com/theupdateframework/tuf-conformance)

**2.5 TAPs** — spec §1.5.4 "TUF Augmentation Proposal (TAP) support": "This major version (1.x.y) of the specification adheres to the following TAPs": TAP 6, TAP 9, TAP 10, TAP 11 — [TUF v1.0.37 §1.5.4](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md). Status from the TAPs index — [TAPs README](https://github.com/theupdateframework/taps):

| TAP | Title | Status | Relevance to benchmark |
|---|---|---|---|
| 3 | Multi-role delegations | Accepted | Uptane §5.4.4.8 cites [TAP-3] |
| 4 | Multiple repository consensus on entrusted targets | Accepted | basis of Uptane repository mapping (§5.2.6) |
| 6 | Include specification version in metadata | Accepted; in spec §1.5.4 | §4.3 SPEC_VERSION check (OTA-PARSE) |
| 8 | Key rotation and explicit self-revocation | Accepted | OTA-KEY-03 |
| 9 | Mandatory metadata signing schemes | Accepted; in spec §1.5.4 | OTA-AUTH-03 |
| 10 | Remove native support for compressed metadata | Accepted; in spec §1.5.4 | — |
| 11 | Using POUFs for Interoperability | Accepted; in spec §1.5.4 | — |
| 12 | Improving keyid flexibility | Accepted | OTA-AUTH-03 |
| 13 | User Selection of the Top-Level Target Files Through Mapping Metadata | Draft | — |
| 14 | Managing TUF Versions | Deferred | — |
| 15 | Succinct hashed bin delegations | Accepted | — |
| 16 | Snapshot Merkle Trees | Draft | OTA-DOS (snapshot size) |
| 17 | Remove Signature Wrapper from the TUF Specification | Draft | — |
| 18 | Ephemeral identity verification using sigstore's Fulcio for TUF developer key management | Draft | — |
| 19 | Content Addressable Systems and TUF | Draft | — |
| 20 | Self-revocation | Accepted | OTA-KEY-03 |
| 21 | ML-DSA signing scheme for TUF metadata | Accepted | ISVS 3.4.13 (PQC) |
| 5 | Setting URLs for roles in the root metadata file | Rejected | — |
| 7 | **Conformance testing** | **Rejected** | conformance now handled by the separate tuf-conformance suite |

### Inferences
- A benchmark test for "slow retrieval" against a pure-TUF client cannot be justified by TUF 1.0.37 normative text; justify it via Uptane §5.4 (SHALL monitor download speed) or as an implementation-quality (non-normative) check, and cite commit `f9122f1`/PR #111 for the removal.
- TUF does not define the bounds W/X/Y/Z numerically; a conformance check can only verify that *some* bound is applied (e.g., body much larger than any plausible "tens of kilobytes" is not consumed in full). Note that the letter Y is reused in 5.3.3 (count of root files) and 5.5.1 (snapshot bytes) — an editorial ambiguity.
- The asymmetry "equal timestamp version → abort silently, no error" (5.4.3.1) matters for test oracles: an "equal version" test must not expect an error code.
- TAP 8 and TAP 20 being "Accepted" while not listed in §1.5.4 implies self-revocation is not mandatory for 1.x.y conformance.

### Gaps
- The exact 1.0.37 rendered anchor numbering (e.g., whether a viewer shows "5.6.7.2.1") was inferred from Bikeshed numbering plus the spec's own references, not from a rendered HTML page.
- TAP status reflects the local `taps-readme.md` snapshot; TAP 8 vs TAP 20 overlap (both mention self-revocation) not investigated.

## 3. Uptane 2.1.0 — threat model, full vs partial verification, time requirements

### Takeaway
Uptane 2.1.0 §4 ("Threat model and attack strategies") names **ten** attack types grouped under four attacker goals (§4.3.1–§4.3.4), including two TUF lacks: "_Partial bundle installation attack_" and "_Drop-request attack_", and it keeps "_Slow retrieval attack_" with a client SHALL in §5.4. Primaries SHALL do full verification (§5.4.4.2, 10 steps); Secondaries SHALL at least do partial verification (§5.4.4.1: time + Director Targets only). Time is a SHALL for "a secure source of time" (§5.4), but the per-install time check (§5.4.3.1) is only SHOULD/optional. The RAID 2024 formal analysis showed that this leaves a freeze attack open on partial-verification Secondaries.

### Cited Findings

**3.1 Threat-model structure** — [Uptane 2.1.0 §4](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)
- §4.1 "Attacker goals" (in increasing severity): read updates; deny installation of updates; cause ECUs to fail; control ECUs/vehicle.
- §4.2 "Attacker capabilities": MitM outside the vehicle and/or inside on vehicle buses; compromise "either a Director repository or Image repository server, and any keys stored on that repository, but not both"; compromise "either a Primary ECU or a Secondary ECU, but not both in the same vehicle."
- §3.5 "Design requirements": an attacker "has to compromise two or more modules to breach the SOTA mechanism."

**3.2 Named attack types (exact names, §4.3)** — [Uptane 2.1.0 §4.3](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)

| § | Attacker goal | Attack name (exact) | One-line meaning (paraphrase) | Client-side check labelled in §5.4.4 / §5.4.3 |
|---|---|---|---|---|
| 4.3.1 | Read updates | _Eavesdrop attack_ | read confidential content of an update encrypted for a specific ECU | 5.4.3.4 step 6 (decryption with ECU key); 5.2.3.1.1 (encrypted-image info "CONDITIONALLY REQUIRED") |
| 4.3.2 | Deny installation | _Drop-request attack_ | block network traffic outside or inside the vehicle | **NOT FOUND** as a labelled check; version report carries "An indicator of any detected security attack" (5.4.2.1.2) |
| 4.3.2 | Deny installation | _Slow retrieval attack_ | slow traffic to just above timeout while both ends believe it is unimpeded | §5.4: "All ECUs SHALL monitor the download speed…"; alert to Director SHOULD |
| 4.3.2 | Deny installation | _Freeze attack_ | keep sending a properly signed but old bundle | 5.4.4.3 s3, 5.4.4.4 s4, 5.4.4.5 s7, 5.4.4.6 s5 ("Checks for a freeze attack"); 5.2.3.1 vehicle identifier in image-less Director Targets |
| 4.3.2 | Deny installation | _Partial bundle installation attack_ | install a valid signed bundle, then block selected updates within it | **NOT FOUND** as a labelled check (atomicity declared out of scope in [DEPLOY], see below) |
| 4.3.2 | Deny installation | _Denial of service attack_ | against Uptane repositories or infrastructure | server-side; no client step |
| 4.3.3 | Interfere with ECU functionality | _Rollback attack_ | install a previously valid but older revision | 5.4.4.3 s2.4, 5.4.4.4 s3, 5.4.4.5 s4–s6, 5.4.4.6 s4; release counter 5.4.3.4 s5 and 5.4.4.2 s10.2.3 |
| 4.3.3 | Interfere with ECU functionality | _Endless data attack_ | send data until the ECU runs out of storage | byte bounds: 5.4.4.3 s2.2 (X), 5.4.4.4 s1 (Y), 5.4.4.5 s1 (from Timestamp), 5.4.4.6 s1 (Z), 5.4.3.3 s4 (image up to Targets length); length check in 5.4.3.4 |
| 4.3.3 | Interfere with ECU functionality | _Mix-and-match attack_ | install a bundle of individually valid but mutually incompatible images | 5.4.4.5 s2, 5.4.4.6 s2 ("Checks for a mix-and-match attack"); Director SHALL consider dependencies/conflicts (5.3.2.1 s5) |
| 4.3.4 | Control an ECU or vehicle | _Arbitrary software attack_ | ECU installs and runs attacker-chosen code | 5.4.4.3 s2.3, 5.4.4.4 s2, 5.4.4.5 s3, 5.4.4.6 s3 ("Checks for an arbitrary software attack"); 5.4.4.2 s10 Director/Image match; 5.4.3.4 s7 hashes |

- Also named outside §4.3: "replay attack" (5.2.3.1: Director Targets with no images "SHALL include a vehicle identifier in order to avoid a replay attack"; 5.4.2.1.2: version report nonce/counter "SHALL change each update cycle"); "recovery from fast-forward attacks [MERCURY]" (5.4.4.3 s4) — [Uptane 2.1.0 §5.2.3.1, §5.4.2.1.2, §5.4.4.3](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)
- Semantic difference vs TUF: Uptane's "Mix-and-match attack" (§4.3.3) is about mutually incompatible *images*, whereas TUF's "Mix-and-match attacks" (§1.5.2) is about *metadata* that never coexisted. Uptane still labels the snapshot/targets version-hash checks (5.4.4.5 s2, 5.4.4.6 s2) "Checks for a mix-and-match attack" — [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md); [TUF v1.0.37 §1.5.2](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)

**3.3 Full vs partial verification (exact clauses)** — [Uptane 2.1.0 §5.4](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)

| Clause | Requirement |
|---|---|
| §5.4 | "All ECUs SHALL verify image metadata as specified in Section 5.4.4 before installing… A Primary ECU SHALL perform full verification… If a Secondary cannot perform full verification, it SHALL, at the very least, perform partial verification." |
| §5.4.1 item 1 | Partial-verification Secondaries "SHALL have the Root and Targets metadata from the Director repository"; full-verification ECUs "SHALL have a complete set of metadata (Root, Targets, Snapshot, and Timestamp) from both repositories… as well as the repository mapping metadata" |
| §5.4.2.3 | Primary "SHALL download metadata for all targets and perform a full verification" |
| §5.4.2.6 | Primary SHALL make available all metadata a Secondary needs; for partial: "at a minimum… only the Targets metadata file from the Director repository"; "Each Secondary SHALL store the latest copy of all metadata required for its own verification." |
| §5.4.4 | restates Primary SHALL / Secondary SHOULD full / SHALL at least partial; failures "SHOULD NOT leave ECUs in an unrecoverable state" |
| §5.4.4.1 Partial verification | SHALL: (1) load and verify current or most recent securely attested time; (2) download and check Director Targets per §5.4.4.6. "This verification procedure is the smallest set of Uptane checks permissible for an Uptane Secondary ECU." |
| §5.4.4.2 Full verification | SHALL consult repository mapping metadata first; 10 steps: time → Director Root (5.4.4.3) → Director Timestamp (5.4.4.4) → Director Snapshot (5.4.4.5, stop if unchanged) → Director Targets (5.4.4.6) → (SHOULD stop if no new targets) Image Root → Image Timestamp → Image Snapshot → Image top-level Targets → step 10: Director vs Image Targets match (length, hashes, "SHALL match" custom metadata such as hardware identifier and release counter; release counter non-decreasing). Errors SHALL return an error code; attack-specific failure SHOULD return an attack-type code |
| §5.4.4.3–5.4.4.6 | per-role "How to check" procedures; each is introduced with "an ECU SHOULD:" (not SHALL) |
| §5.4.4.6 s6–s8 | Director Targets: no delegations; no ECU identifier more than once; (Primary) all listed ECU identifiers present in the vehicle |
| §5.4.4.7 / §5.4.4.8 | delegation resolution SHALL include hardware identifier and path match; multi-role delegations per [TAP-3] with agreement threshold |

- [DEPLOY] rationale: partial-verification ECUs "could be instructed to install malicious software by an attacker in possession of the Director repository's Targets key" and "have no truly secure way to invalidate a signing key" — [Uptane Deployment Best Practices, "Full vs. partial verification"](https://uptane.github.io/deployment-considerations/ecus.html) (local `dl/updeploy/ecus.md`)

**3.4 Time-related requirements** — [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)

| Clause | Strength | Requirement |
|---|---|---|
| §5.4 | SHALL | ECU "SHALL have a secure way of verifying the current time, or a sufficiently recent attestation of the time"; "ECUs SHALL have a secure source of time. An OEM/Uptane implementer can use any external source of time that is demonstrably secure." |
| §5.4.1 item 2 | SHALL (provisioned) | "The current time, or a secure attestation of a sufficiently recent time." |
| §5.4.2 step 2 / §5.4.2.2 | SHALL | "The Primary SHALL load the current time from a secure source." |
| §5.4.2.5 | SHOULD | "The Primary SHOULD send the time to each ECU." |
| §5.4.2.1.2 | SHALL | version report contains "The latest time the ECU can verify at the time this version report was generated" and a nonce/counter that "SHALL change each update cycle" |
| §5.4.3 step 1 / §5.4.3.1 | optional / SHOULD | "This is optional if the ECU does not have the capacity to verify a time message"; "IF the ECU has the capability… SHOULD load and verify the current time, or the most recent securely attested time." |
| §5.4.4.1 s1, §5.4.4.2 s1 | SHALL | load and verify current or most recent securely attested time |
| §5.4.4.3 s3, 5.4.4.4 s4, 5.4.4.5 s7, 5.4.4.6 s5 | SHOULD (procedures) | current/attested time "lower than the expiration timestamp" (freeze checks) |
| §5.2.1 | SHALL | every role payload contains "An expiration date and time" |
| §5.3.2.1 step 3 | SHOULD | Director checks "The time sent in the ECU version report" (relaxed SHALL→SHOULD in 2.1.0 per changelog) |

**3.5 Editorial issues in 2.1.0 relevant to test oracles** — [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)
- §5.4.4.3 s2.4: root version "SHALL be less than or equal to" the new version, "Effectively… indeed N+1" — TUF 5.3.5 says "MUST be exactly… N+1".
- §5.4.4.4 s3: Timestamp version "less than or equal" accepted — TUF 5.4.3.1 requires strictly greater (equal → abort without error).
- §5.3.2.1 announces "the following six-step process" but lists seven steps, and step 7 cites "dependency resolution in step 4" (dependency handling is step 5).
- §5.4.4.2 steps 4 and 6 say "Directory repository" (typo for Director).

**3.6 RAID 2024 formal analysis (Lorch, Larraz, Tinelli, Chowdhury)** — [RAID 2024 paper, DOI 10.1145/3678890.3678927](https://doi.org/10.1145/3678890.3678927); author PDF [raid2024-37.pdf](https://raid2024.github.io/papers/raid2024-37.pdf); local technical-report text `pdf/uptane-raid.txt`
- Abstract: the approach "is able to discover six new vulnerabilities while rediscovering all five known ones"; the Uptane standards body "positively acknowledged our findings".
- Properties P1–P8 (Table 6): checks for freeze; VVM replay; rollback; arbitrary software; attacker-authored VVM; mix-and-match; mixed-bundles; incompatible image. Threat models: A1 outside-vehicle MitM; A2 outside + inside MitM; A3 full MitM + director keys; A4 A3 + timestamp & snapshot image-repo keys; A5 A4 + targets image-repo keys; A6 A5 + root image-repo keys; A* A1 + primary ECU key.
- Table 5 "Attacks" lists: Freeze (P1, A1), VVM Replay I (P2, A1, optional features 1,2 omitted), VVM Replay II (P2, A2, feature 3 omitted), Rollback I (P3, A3), Rollback II (P3, A2), Arbitrary software (P4, A3), Attacker-authored VVM I (P5, A1), Attacker-authored VVM II (P5, A*), Mix-and-match (P6, A3), Mixed-bundles (P7, A2), Incompatible image (P8, A3).
- Finding 1 (Freeze Attack, partial-verification Secondary): "In section 5.4.3.1 of the standard, there is no indication to abort the update process if the attestation of the latest time is absent or invalid… This interpretation leads to the freeze attack succeeding."
- Finding OPT1: omitting optional features (1) metadata version increments and (2) image version numbers in Targets lets an A1 adversary do "a specific kind of rollback attack".
- Discussion: "both VVM replay attacks… have been addressed in the newest version of Uptane (version 2.1), and there is an active GitHub issue addressing the freeze attack."

**3.7 Deployment Best Practices statements used in the cross-walk** — local `dl/updeploy/*`, [Uptane Deployment Best Practices](https://uptane.github.io/deployment-considerations/index.html)
- "Atomic installation of a bundle of images": "Uptane does not provide a way to guarantee atomic installations because the problem of atomicity is out of its scope"; suggests reporting via vehicle version manifest, bounded retries, or two-phase commit with a gateway coordinator (`customizations.md`).
- "Avoiding Director replay attacks": empty Director Targets "could potentially be replayed to another vehicle, creating a 'freeze' attack"; mitigation: include VIN/"device_id" and client aborts on mismatch (`security_considerations.md`) — now normative in Std §5.2.3.1.
- "ASN.1 decoding": improper decoding "may lead to arbitrary code execution or denial-of-service attacks"; decoders SHOULD be tested "via unit tests and fuzzing"; prefer DER (`security_considerations.md`).
- "Rolling back software": rollback protection = metadata version numbers + image release counters; never incrementing release counters "SHOULD NOT be used" (`exceptional_operations.md`).
- Key compromise: Director keeps online Timestamp/Snapshot/Targets keys, so its compromise "can lead to some security threats, such as mix-and-match attacks"; Image-repo compromise allows "arbitrary software attacks"; recovery = Root revokes/replaces keys, plus manual update for partial-verification Secondaries (`key_management.md`).

### Inferences
- For a benchmark, Uptane gives a normative hook for slow-retrieval detection (SHALL monitor) but no numeric threshold ("pre-defined threshold"), so the observable is "client reports/aborts below an implementer threshold", not a fixed rate.
- Because §5.4.4.3–5.4.4.6 are SHOULD-level procedures invoked by SHALL-level §5.4.4.1/§5.4.4.2, a conformance report should label failures of these steps as "SHALL (via 5.4.4.x)" to avoid disputes over normative strength.
- The RAID Finding 1 suggests a concrete benchmark test: drop/garble the time message to a partial-verification Secondary and check that it does not keep accepting replayed Director Targets.

### Gaps
- The issue number of the "active GitHub issue addressing the freeze attack" is not given in the local paper text.
- The marks distinguishing "new" vs "known" attacks in RAID Table 5 were lost in PDF-to-text extraction; only the paper's statement that VVM replay, attacker-authored VVM and incompatible-image attacks were "not previously considered" survives.
- Uptane has no labelled client check for "Drop-request attack" or "Partial bundle installation attack": **NOT FOUND**.

## 4. RFC 9124 — THREAT.*, REQ.SEC.*, REQ.USE.* identifiers and mitigation links

### Takeaway
RFC 9124 §4 defines **18 THREAT.\*** (§4.2.1–§4.2.18, STRIDE-classified), **21 REQ.SEC.\*** (§4.3.1–§4.3.21) and **14 REQ.USE.\*** (§4.5.1–§4.5.14), each REQ with explicit "Mitigates:" / "Satisfies:" and "Implemented by:" lines. The threat model "only covers elements related to the transport of firmware updates" (physical access out of scope). It names no power-loss, endless-data or slow-retrieval threat.

### Cited Findings
- §4.1 Threat Model: uses STRIDE; "This threat model only covers elements related to the transport of firmware updates… threats to an IoT device due to physical access are out of scope." — [RFC 9124 §4.1](https://www.rfc-editor.org/rfc/rfc9124#section-4.1)

**4.1 THREAT identifiers (§4.2)** — [RFC 9124 §4.2](https://www.rfc-editor.org/rfc/rfc9124#section-4.2)

| § | Identifier: title (exact) | STRIDE class (exact) | One-line meaning (paraphrase) | "Mitigated by:" (exact) |
|---|---|---|---|---|
| 4.2.1 | THREAT.IMG.EXPIRED: Old Firmware | Elevation of Privilege | old but valid manifest + old valid image re-sent to exploit a known vulnerability | REQ.SEC.SEQUENCE |
| 4.2.2 | THREAT.IMG.EXPIRED.OFFLINE: Offline Device + Old Firmware | Elevation of Privilege | long-offline device given an old (but newer-than-installed) vulnerable image | REQ.SEC.EXP, REQ.USE.MFST.PRE_CHECK |
| 4.2.3 | THREAT.IMG.INCOMPATIBLE: Mismatched Firmware | Denial of Service | valid image for the wrong device type, signed by an actor authorised for both | REQ.SEC.COMPATIBLE |
| 4.2.4 | THREAT.IMG.FORMAT: The Target Device Misinterprets the Type of Payload | Denial of Service | payload format misinterpreted → incorrect installation | REQ.SEC.AUTH.IMG_TYPE |
| 4.2.5 | THREAT.IMG.LOCATION: The Target Device Installs the Payload to the Wrong Location | Denial of Service | image written to the wrong storage location | REQ.SEC.AUTH.IMG_LOC |
| 4.2.6 | THREAT.NET.REDIRECT: Redirection to Inauthentic Payload Hosting | Denial of Service | device tricked into fetching payload from an attacker-controlled site | REQ.SEC.AUTH.REMOTE_LOC |
| 4.2.7 | THREAT.NET.ONPATH: Traffic Interception | Spoofing Identity, Tampering with Data | on-path attacker monitors/modifies/drops manifests, payloads, reports | REQ.SEC.AUTHENTIC, REQ.SEC.IMG.CONFIDENTIALITY, REQ.SEC.AUTH.REMOTE_LOC, REQ.SEC.MFST.CONFIDENTIALITY, REQ.SEC.REPORTING |
| 4.2.8 | THREAT.IMG.REPLACE: Payload Replacement | Elevation of Privilege | downloaded firmware replaced after manifest verification | REQ.SEC.AUTH.EXEC |
| 4.2.9 | THREAT.IMG.NON_AUTH: Unauthenticated Images | Elevation of Privilege / all types | attacker-installed firmware via manipulated payload or metadata | REQ.SEC.AUTHENTIC |
| 4.2.10 | THREAT.UPD.WRONG_PRECURSOR: Unexpected Precursor Images | Denial of Service / all types | valid manifest applied to an unexpected precursor (e.g., delta base) | REQ.SEC.AUTH.PRECURSOR |
| 4.2.11 | THREAT.UPD.UNAPPROVED: Unapproved Firmware | Denial of Service, Elevation of Privilege | firmware not approved by owner/Operator installed (multi-party rights) | REQ.SEC.RIGHTS, REQ.SEC.ACCESS_CONTROL |
| 4.2.12 | THREAT.IMG.DISCLOSURE: Reverse Engineering of Firmware Image for Vulnerability Analysis | all types | image reverse-engineered to find vulnerabilities | REQ.SEC.IMG.CONFIDENTIALITY |
| 4.2.13 | THREAT.MFST.OVERRIDE: Overriding Critical Manifest Elements | Elevation of Privilege | authorised non-author overrides critical manifest elements (e.g., digest+URI) | REQ.SEC.ACCESS_CONTROL |
| 4.2.14 | THREAT.MFST.EXPOSURE: Confidential Manifest Element Exposure | Information Disclosure | third party extracts sensitive info from the manifest | REQ.SEC.MFST.CONFIDENTIALITY |
| 4.2.15 | THREAT.IMG.EXTRA: Extra Data after Image | all types | extra code appended after a valid authentic image | REQ.SEC.IMG.COMPLETE_DIGEST |
| 4.2.16 | THREAT.KEY.EXPOSURE: Exposure of Signing Keys | all types | third party obtains (direct or indirect, e.g., HSM) access to a signing key | REQ.SEC.KEY.PROTECTION, REQ.SEC.KEY.ROTATION |
| 4.2.17 | THREAT.MFST.MODIFICATION: Modification of Manifest or Payload prior to Signing | all types | manifest/payload altered before signing | REQ.SEC.MFST.CHECK, REQ.SEC.MFST.TRUSTED |
| 4.2.18 | THREAT.MFST.TOCTOU: Modification of Manifest between Authentication and Use | all types | manifest modified between time of check and time of use | REQ.SEC.MFST.CONST |

**4.2 REQ.SEC identifiers (§4.3)** — [RFC 9124 §4.3](https://www.rfc-editor.org/rfc/rfc9124#section-4.3)

| § | Identifier: title (exact) | Key normative sentence (condensed) | "Mitigates:" | "Implemented by:" |
|---|---|---|---|---|
| 4.3.1 | REQ.SEC.SEQUENCE: Monotonic Sequence Numbers | manifests MUST contain monotonically increasing sequence numbers; devices must reject smaller than onboard; no rollover | THREAT.IMG.EXPIRED | Monotonic Sequence Number (§3.2) |
| 4.3.2 | REQ.SEC.COMPATIBLE: Vendor, Device-Type Identifiers | devices MUST only apply firmware intended for them | THREAT.IMG.INCOMPATIBLE | Vendor ID (§3.3), Class ID (§3.4) |
| 4.3.3 | REQ.SEC.EXP: Expiration Time | manifest MAY expire; with secure clock + expiry, device must reject after expiry | THREAT.IMG.EXPIRED.OFFLINE | Expiration Time (§3.7) |
| 4.3.4 | REQ.SEC.AUTHENTIC: Cryptographic Authenticity | authenticity of update MUST be demonstrable; image tied to manifest by digest | THREAT.IMG.NON_AUTH, THREAT.NET.ONPATH | Signature (§3.15), Payload Digests (§3.13) |
| 4.3.5 | REQ.SEC.AUTH.IMG_TYPE: Authenticated Payload Type | payload type MUST be authenticated | THREAT.IMG.FORMAT | Payload Format (§3.8), Signature (§3.15) |
| 4.3.6 | REQ.SEC.AUTH.IMG_LOC: Authenticated Storage Location | storage location MUST be authenticated | THREAT.IMG.LOCATION | Storage Location (§3.10) |
| 4.3.7 | REQ.SEC.AUTH.REMOTE_LOC: Authenticated Remote Payload | remote payload location MUST be authenticated | THREAT.NET.REDIRECT, THREAT.NET.ONPATH | Payload Indicator (§3.12) |
| 4.3.8 | REQ.SEC.AUTH.EXEC: Secure Execution | target SHOULD verify firmware at boot (authenticated size + digest) | THREAT.IMG.REPLACE | Payload Digests (§3.13), Size (§3.14) |
| 4.3.9 | REQ.SEC.AUTH.PRECURSOR: Authenticated Precursor Images | differential updates MUST specify an authenticated precursor digest | THREAT.UPD.WRONG_PRECURSOR | Precursor Image Digest (§3.5) |
| 4.3.10 | REQ.SEC.AUTH.COMPATIBILITY: Authenticated Vendor and Class IDs | compatibility identifiers MUST be authenticated | THREAT.IMG.INCOMPATIBLE | Vendor ID (§3.3), Class ID (§3.4) |
| 4.3.11 | REQ.SEC.RIGHTS: Rights Require Authenticity | exercising rights MUST be accompanied by proof of authenticity | THREAT.UPD.UNAPPROVED | Signature (§3.15) |
| 4.3.12 | REQ.SEC.IMG.CONFIDENTIALITY: Payload Encryption | information model MUST enable encrypted payloads | THREAT.IMG.DISCLOSURE, THREAT.NET.ONPATH | Encryption Wrapper (§3.20) |
| 4.3.13 | REQ.SEC.ACCESS_CONTROL: Access Control | exercise of rights MUST be validated against an ACL | THREAT.MFST.OVERRIDE, THREAT.UPD.UNAPPROVED | Client-side code, not specified in manifest |
| 4.3.14 | REQ.SEC.MFST.CONFIDENTIALITY: Encrypted Manifests | format MUST allow partial/full manifest encryption | THREAT.MFST.EXPOSURE, THREAT.NET.ONPATH | Manifest Encryption Wrapper / Transport Security |
| 4.3.15 | REQ.SEC.IMG.COMPLETE_DIGEST: Whole Image Digest | digest SHOULD cover all fixed-size space; variable-size MUST be exactly payload size | THREAT.IMG.EXTRA | Payload Digests (§3.13) |
| 4.3.16 | REQ.SEC.REPORTING: Secure Reporting | status reports MUST use an authenticated, confidential channel | THREAT.NET.ONPATH | Transport Security / report-generating manifest |
| 4.3.17 | REQ.SEC.KEY.PROTECTION: Protected Storage of Signing Keys | signing keys SHOULD be inaccessible to networked devices (HSM / air-gap) | THREAT.KEY.EXPOSURE | hardware-assisted isolation (out of manifest scope) |
| 4.3.18 | REQ.SEC.KEY.ROTATION: Protected Storage of Signing Keys (sic, same title as 4.3.17) | keys SHOULD be replaced from time to time; signing keys SHOULD be delegates of the trust anchor; time-based expiry needs a secure clock | THREAT.KEY.EXPOSURE | secure storage technology (out of manifest scope) |
| 4.3.19 | REQ.SEC.MFST.CHECK: Validate Manifests prior to Deployment | manifests SHOULD be verified prior to deployment | THREAT.MFST.MODIFICATION | Testing infrastructure |
| 4.3.20 | REQ.SEC.MFST.TRUSTED: Construct Manifests in a Trusted Environment | high-risk: SHOULD build manifests in protected (e.g., air-gapped) environment | THREAT.MFST.MODIFICATION | physical/network security |
| 4.3.21 | REQ.SEC.MFST.CONST: Manifest Kept Immutable between Check and Use | manifest and extracted data MUST be immutable between check and use; MUST fit internal/secure memory | THREAT.MFST.TOCTOU | proper system design avoiding TOCTOU |

**4.3 REQ.USE identifiers (§4.5)** — [RFC 9124 §4.5](https://www.rfc-editor.org/rfc/rfc9124#section-4.5). REQ.USE items carry "Satisfies:" (user stories), not "Mitigates:"; the only threat link is THREAT.IMG.EXPIRED.OFFLINE → REQ.USE.MFST.PRE_CHECK (stated on the threat side, §4.2.2).

| § | Identifier: title (exact) | One-line meaning | Satisfies | Implemented by |
|---|---|---|---|---|
| 4.5.1 | REQ.USE.MFST.PRE_CHECK: Pre-installation Checks | format MUST carry all info needed to process an update (pre-checks) | USER_STORY.MFST.PRE_CHECK, USER_STORY.INSTALL.INSTRUCTIONS | Additional Installation Instructions (§3.16) |
| 4.5.2 | REQ.USE.MFST.TEXT: Descriptive Manifest Information | operator MUST be able to tell what a manifest does and which devices accept it | USER_STORY.MFST.ADMINISTRATION | Manifest Text Information (§3.17) |
| 4.5.3 | REQ.USE.MFST.OVERRIDE_REMOTE: Override Remote Resource Location | format MUST be able to redirect payload fetches | USER_STORY.OVERRIDE | Aliases (§3.18) |
| 4.5.4 | REQ.USE.MFST.COMPONENT: Component Updates | MUST express multi-payload, multi-authority updates | USER_STORY.OVERRIDE, USER_STORY.COMPONENT | Dependencies, StorageIdentifier, ComponentIdentifier |
| 4.5.5 | REQ.USE.MFST.MULTI_AUTH: Multiple Authentications | MUST carry multiple signatures | USER_STORY.MULTI_AUTH | Signature (§3.15) |
| 4.5.6 | REQ.USE.IMG.FORMAT: Format Usability | MUST accommodate any operator payload format | USER_STORY.IMG.FORMAT | Payload Format (§3.8) |
| 4.5.7 | REQ.USE.IMG.NESTED: Nested Formats | MUST accommodate nested formats and announce nesting steps | USER_STORY.IMG.CONFIDENTIALITY | Processing Steps (§3.9) |
| 4.5.8 | REQ.USE.IMG.VERSIONS: Target Version Matching | MUST specify multiple applicable firmware versions (list/range) | USER_STORY.IMG.CURRENT_VERSION | Required Image Version List (§3.6) |
| 4.5.9 | REQ.USE.IMG.SELECT: Select Image by Destination | MUST list equivalent payloads by XIP address | USER_STORY.IMG.SELECT | XIP Address (§3.21) |
| 4.5.10 | REQ.USE.EXEC: Executable Manifest | MUST describe an executable system (XIP and complex OS) | USER_STORY.EXEC.MFST | Runtime Metadata (§3.23) |
| 4.5.11 | REQ.USE.LOAD: Load-Time Information | MUST carry load-time metadata (crypto info, load address, compression) | USER_STORY.EXEC.DECOMPRESS | Load-Time Metadata (§3.22) |
| 4.5.12 | REQ.USE.PAYLOAD: Payload in Manifest Envelope | MUST allow payload inside the manifest structure | USER_STORY.MFST.IMG | Payload (§3.24) |
| 4.5.13 | REQ.USE.PARSE: Simple Parsing | manifest structure MUST be simple to parse "to reduce the attack vectors against manifest parsers" | USER_STORY.MFST.PARSE | N/A |
| 4.5.14 | REQ.USE.DELEGATION: Delegation of Authority in Manifest | MUST deliver delegation info (new verification key) | USER_STORY.MFST.DELEGATION | Delegation Chain (§3.25) |

### Inferences
- The THREAT→REQ graph is almost bijective. The one asymmetry: REQ.SEC.AUTH.COMPATIBILITY (§4.3.10) says it mitigates THREAT.IMG.INCOMPATIBLE, but §4.2.3 lists only REQ.SEC.COMPATIBLE. The cross-walk should cite both for OTA-INST-01.
- RFC 9124 has no threat identifiers for availability during transfer (endless data, slow retrieval), power loss, or fast-forward. Mark those cells **NOT FOUND** in the cross-walk rather than forcing a mapping.
- REQ.SEC.SEQUENCE explicitly allows a deliberate firmware downgrade through a new manifest with a higher sequence number. So RFC 9124 "rollback protection" protects the *manifest* sequence, not the firmware version, and a test oracle must compare sequence numbers, not image versions.

### Gaps
- The SUIT manifest draft's concrete realisation of each REQ (e.g., `suit-manifest-sequence-number`) was not traced clause-by-clause in this note; only RFC 9124 identifiers are listed.
- Neither RFC 9124 nor RFC 9019 errata were checked (no local errata file); the duplicated title on §4.3.18 may have an erratum.

## 5. OWASP ISVS 1.0 — software/firmware update requirement IDs

### Takeaway
ISVS 1.0's dedicated update requirements are **V3 "Software Platform Requirements" → "Software Updates" 3.4.1–3.4.13**. Related update-relevant controls are in V1 (1.2.7, 1.2.9, 1.3.13, 1.5.2, 1.6.1–1.6.4), V3 Bootloader (3.1.4, 3.1.5, 3.1.9) and V5 (5.1.2). ISVS states verification goals at the requirement level ("Verify that…"). Anti-rollback (3.4.6) is **L3 only**. ISVS has no requirement for freshness/freeze, mix-and-match, endless data or slow retrieval.

### Cited Findings
**5.1 V3 "Software Updates" (3.4.x)**: text abbreviated to one line, level marks as in table — [ISVS 1.0 V3](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS) (local `dl/isvs/V3-Software_Platform_Requirements.md`)

| ID | Requirement (one line, close to original wording) | L1 | L2 | L3 |
|---|---|---|---|---|
| 3.4.1 | packages and user-space applications use OTA updates decoupled from firmware updates | | ✓ | ✓ |
| 3.4.2 | devices can be updated automatically upon a pre-defined schedule | ✓ | ✓ | ✓ |
| 3.4.3 | updates are cryptographically signed by a trusted source and authenticity is verified before execution | ✓ | ✓ | ✓ |
| 3.4.4 | update process not vulnerable to TOCTOU ("applying the update right after the authenticity… is validated") | ✓ | ✓ | ✓ |
| 3.4.5 | updates do not modify user-configured preferences, security and/or privacy settings without notifying the user | ✓ | ✓ | ✓ |
| 3.4.6 | device cannot be downgraded to known vulnerable versions (anti-rollback) | | | ✓ |
| 3.4.7 | on update failure, the device reverts to a backup image or notifies the IoT ecosystem | ✓ | ✓ | ✓ |
| 3.4.8 | unsigned debug pre-production firmware builds cannot be flashed onto devices | ✓ | ✓ | ✓ |
| 3.4.9 | encrypted firmware images are securely decrypted on the device | | ✓ | ✓ |
| 3.4.10 | device authenticates to the update server component prior to downloading the update | ✓ | ✓ | ✓ |
| 3.4.11 | firmware updates are stored encrypted server-side | | ✓ | ✓ |
| 3.4.12 | software and firmware updates are transmitted using an encrypted communication channel | ✓ | ✓ | ✓ |
| 3.4.13 | update signing/verification supports PQ signatures (ML-DSA, SLH-DSA) or hybrid schemes for devices operating beyond 2030 | | | ✓ |

**5.2 Related update-relevant IDs elsewhere** — [ISVS 1.0](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS) (local `dl/isvs/V1…`, `V3…`, `V5…`)

| ID | Requirement (one line) | Levels |
|---|---|---|
| 1.2.7 | code-integrity protection enabled and locked in hardware before shipping (e.g., secure boot enabled, boot configuration locked) | L2, L3 |
| 1.2.9 | all components incl. drivers, SDKs, radio modules can be updated with security patches per support/EOL policy | L2, L3 |
| 1.3.13 | debug and release firmware images are signed using different keys | L2, L3 |
| 1.5.2 | response strategy exists for compromised device credentials (esp. root keys / non-updatable crypto material) | L2, L3 |
| 1.6.1 | minimum security-update support period defined and publicly disclosed, with end date | L1–L3 |
| 1.6.2 | users notified when the security-update support period ends | L1–L3 |
| 1.6.3 | security updates provided at no additional cost during the support period | L1–L3 |
| 1.6.4 | critical/high-severity security updates deliverable independently of feature updates | L2, L3 |
| 3.1.4 | first-stage bootloader authenticity verified by an immutable ROM-based trusted component (hardware root of trust) | L2, L3 |
| 3.1.5 | bootloader stages / application code cryptographically verified before executing subsequent boot steps | L2, L3 |
| 3.1.9 | secure-boot verification supports PQ (ML-DSA / SLH-DSA) or hybrid schemes for devices beyond 2030 | L3 |
| 5.1.2 | platform supports validating the authenticity of the first-stage bootloader | L2, L3 |

- V3 Control Objective: update systems must "ensure devices only run cryptographically signed software free of known vulnerabilities" — [ISVS 1.0 V3](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS)
- V3 references include "TGC Guidance for Secure Update of Software and Firmware on Embedded Systems" (TCG, v1r72) and U-Boot FIT signature verification — [ISVS 1.0 V3 References](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS)

### Inferences
- In the cross-walk, ISVS supplies device-level controls (signing, anti-rollback, fallback, TOCTOU, transport encryption). Freshness classes (freeze, mix-and-match, fast-forward) and DoS classes have **no ISVS ID**.
- 3.4.4 (TOCTOU) aligns with RFC 9124 REQ.SEC.MFST.CONST / THREAT.MFST.TOCTOU and THREAT.IMG.REPLACE; 3.4.7 (revert or notify) is the only ISVS hook for power-loss/failed-install classes.

### Gaps
- The ISVS repository's per-file URLs (branch/path) were not verified; cite chapter + ID.

## 6. A/B updater guarantees: atomicity, fallback, boot counting, power-loss safety

### Takeaway
All five updaters promise that an interrupted update (crash, power cut) leaves either the old or the new system bootable. Each puts that guarantee in a different layer: RAUC/SWUpdate/Mender rely on the **bootloader** (boot order + attempt counter/flag + userspace "mark-good"/"commit"), OSTree on an **atomic symlink swap** of boot configuration, MCUboot on a **resumable swap with trailer status** plus a test/confirm "revert" mechanism. Boot counting is **delegated to the bootloader** in RAUC, SWUpdate and Mender, and **NOT FOUND** in the local OSTree docs. The normative anchors in the specs are RFC 9019 §3 ("Devices must not fail when a disruption, such as a power failure or network interruption, occurs during the update process") and SUIT manifest -37 §6.3.1 "Resilience to Disruption".

### Cited Findings
URLs below are the canonical doc pages matching each local source file; page paths were inferred from file names and not opened in this session.

| Updater | Atomicity | Fallback / rollback | Boot counting / confirmation | Power-loss safety | Source (local file → page) |
|---|---|---|---|---|---|
| **RAUC** | "**Fail-Safe & Atomic**: An update may be interrupted at any point without breaking the running system." | "select one of the redundant slots as fallback or boot into a recovery system. This handling is up to your bootloader." | `status mark-good` / `status mark-bad` "interact through the boot loader interface"; Barebox *bootchooser* "maintains information about priority and remaining boot attempts" (`remaining_attempts`); checklist: "Bootloader detects failed boots via a counter", "Boot counter is reset on a successful boot" | RAUC "will… deactivate the slot to be updated before writing to it, and reactivate it after completing the installation successfully"; atomic bootloader update "will prevent a non-bootable system caused by an error or power-loss during the update" (slot types `boot-emmc`, `boot-mbr-switch`, `boot-gpt-switch`, `boot-raw-fallback`) | `rauc-index.rst`, `rauc-basic.rst`, `rauc-integration.rst`, `rauc-advanced.rst`, `rauc-checklist.rst` → [RAUC docs](https://rauc.readthedocs.io/en/latest/) |
| **SWUpdate** | "An atomic update is generally a must feature for an embedded system." | "Double copy with fall-back… guarantee that there is always a working copy even if the software update is interrupted or a power off occurs"; single-copy: bootloader restarts SWUpdate | U-Boot boot counter suggested: "if the boot counter is greater as a limit, can start automatically SWUpdate"; transaction flag `recovery_status` = "progress"/"failed"/unset | "If a power off occurs, it must be guaranteed that the system is able to work again"; "double copy: SWUpdate did not switch between stand-by and current copy"; U-Boot redundant env (`CONFIG_ENV_OFFSET_REDUND`) is "power-off safe"; GRUB env written to temp file then renamed; `--cache-file` "allows one to resume an update after a power cut" | `swu-overview.rst`, `swu-swupdate.rst` → [SWUpdate docs](https://sbabic.github.io/swupdate/overview.html) |
| **Mender** | "Mender comes with built-in support for a dual redundant scheme (also known as A/B scheme), ensuring that the device always returns to a working state on failure." | "If something causes the device to reboot before committing the update, the bootloader knows that something went wrong and will **roll back**" | client sets a bootloader flag to flip partitions; "On the first boot following an update, the Mender Client will **commit** the update" | requirement: "must be able to recover from an update that fails, including loss of power or network connectivity during the update process"; client "verifies the checksum" of the inactive partition before flipping | `mender-intro.md`, `mender-yocto.md` → [Mender docs](https://docs.mender.io/) |
| **Mender MCU (Zephyr + MCUboot)** | "atomic, **fail-safe OTA updates** with automatic rollback on failure" | via MCUboot | via MCUboot | via MCUboot | `mender-zephyr.md` → [Mender docs](https://docs.mender.io/) |
| **Mender Orchestrator** (multi-component) | "necessitating an atomic update of all Components" | "rolls back the entire System if any Component update process fails - always resulting in a well defined state of the System as a whole" | — | — | `mender-intro.md` → [Mender docs](https://docs.mender.io/) |
| **OSTree** | "OSTree is designed to implement fully atomic and safe upgrades; more generally, atomic transitions between lists of bootable deployments." | currently booted deployment "must always be in the new set" of deployments | **NOT FOUND** in local OSTree docs | "If the system crashes or you pull the power, you will have either the old system, or the new one."; `/boot` "swapped directory pattern": populate `/ostree/boot.1`, "then atomically swap the symbolic link" | `ostree-atomic.md`, `ostree-intro.md` → [OSTree "Atomic Upgrades"](https://ostreedev.github.io/ostree/atomic-upgrades/) |
| **MCUboot** | swap strategies (scratch / offset / move), overwrite-only, direct-xip, RAM-load | "test" swap → image must mark itself "OK", else "MCUboot will perform a 'revert' swap during the next boot"; "Test swaps are supported to provide a rollback mechanism to prevent devices from becoming 'bricked' by bad firmware" | confirmation via trailer `image_ok` ("0x01=confirmed; 0xff=not confirmed"), `copy_done`; no boot counter (revert on next reset if unconfirmed) | "the bootloader must work properly even when it is reset during the middle of an image swap"; "Reset recovery": "Bootutil recovers from this condition by using the image trailers"; swap status "can thus used to resume a swap operation" | `mcuboot-design.md` → [MCUboot design](https://docs.mcuboot.com/design.html) |

Security-relevant extras from the same docs (used in §7):
- MCUboot integrity check runs "immediately before it gets copied into the primary slot"; image "*may* contain a signature TLV" (signature verification is configuration-dependent); `MCUBOOT_VALIDATE_PRIMARY_SLOT_ONCE` "is reducing the security level" — [MCUboot design, "Integrity check"](https://docs.mcuboot.com/design.html)
- MCUboot downgrade prevention: software (`MCUBOOT_DOWNGRADE_PREVENTION`, "only available when the overwrite-based image update strategy is used") and hardware security counter (`MCUBOOT_HW_ROLLBACK_PROT`, counter "stored in a non-volatile and trusted component") — [MCUboot design, "Downgrade prevention"](https://docs.mcuboot.com/design.html)
- Mender: "If Artifact signature verification is enabled, the client needs to have access to the public part of the key pair" (`ArtifactVerifyKey`) — signature verification is opt-in — [Mender docs, Security](https://docs.mender.io/)
- RAUC: "Cryptographic signing and verification of updates using OpenSSL (signatures based on x.509 certificates)"; "Update compatibility check" — [RAUC docs](https://rauc.readthedocs.io/en/latest/)

Normative spec anchors for power loss / disruption:
- RFC 9019 §3 Architecture: "Devices must not fail when a disruption, such as a power failure or network interruption, occurs during the update process."; the download protocol "needs to offer features like… mechanisms to resume interrupted or corrupted transfers." — [RFC 9019 §3](https://www.rfc-editor.org/rfc/rfc9019#section-3)
- RFC 9019 §4: "An IoT device needs a recovery strategy in case the firmware update/invocation process fails"; §4.1 The Bootloader: "either the bootloader must be able to select different, valid firmware or it must be able to obtain new, valid firmware." — [RFC 9019 §4, §4.1](https://www.rfc-editor.org/rfc/rfc9019#section-4)
- draft-ietf-suit-manifest-37 §6.3.1 "Resilience to Disruption": "systems implementing the manifest processor MUST guarantee that manifests can be either resumed or reapplied" (fallback/recovery image; idempotent manifests via Try-Each; journal in non-volatile memory, e.g. a SUIT Report) — [draft-ietf-suit-manifest-37 §6.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest-37#section-6.3.1)
- TUF §5.3.8 / 5.4.5 / 5.5.7 / 5.6.6 "Persist … metadata" (client MUST write to non-volatile storage) and §5 note "Errors… should not leave clients in an unrecoverable state"; no atomic-write requirement — [TUF v1.0.37 §5](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md)
- Uptane §5.4.3.3: "The ECU SHOULD first create a backup of its previous working image"; §5.4.3.5 pre-conditions "could include ensuring the ECU has a backup of its current image and metadata"; §5.4.4 "Errors… SHOULD NOT leave ECUs in an unrecoverable state" — [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)
- ISVS 3.4.7: "in the event of an update failure, the device reverts to a backup image or notifies the IoT ecosystem." — [ISVS 1.0 V3](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS)

### Inferences
- A power-loss conformance check has to observe two different invariants. (a) "Bootable": after a cut at any write offset, the device boots a valid image (all updaters promise this). (b) "Trust-store consistent": persisted metadata or the counter is never torn. None of TUF, Uptane, RFC 9124 or ISVS states (b) as an explicit requirement, so OTA-PWR-01 traces only to the general "unrecoverable state" notes.
- The boot-switch commit point differs per updater: bootloader variable (RAUC/SWUpdate/Mender), symlink swap (OSTree), trailer magic/`image_ok` (MCUboot). A benchmark should inject faults around that point specifically.

### Gaps
- `dl/ab/ostree-sign.md` is a saved "404: Not Found" page, so OSTree signature/verification guarantees could not be cited from local files.
- OSTree's boot-counting integration (e.g., via external tools) was not found in the local files: **NOT FOUND**.
- SWUpdate/RAUC exact doc-page URLs and the version of each doc snapshot were not recorded in the local files.

## 7. Cross-walk: benchmark catalog IDs → TUF § | Uptane § | RFC 9124 ID | ISVS ID

### Takeaway
The authenticity and freshness rows (AUTH, FRESH) are covered by TUF and Uptane with step-level clauses. RFC 9124 and ISVS cover them only partially (sequence number, expiry, signing, anti-rollback). The DoS, power-loss and partial-bundle rows have almost no normative client clause in TUF, RFC 9124 or ISVS; their only anchors are Uptane §4.3/§5.4, RFC 9019 §3/§4 and SUIT -37 §6.3.1. The specs name **14 additional classes** missing from the catalog; new IDs are proposed in 7.2.

### Cited Findings
Sources for every cell: [TUF v1.0.37](https://github.com/theupdateframework/specification/blob/v1.0.37/tuf-spec.md), [Uptane 2.1.0](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md), [RFC 9124](https://www.rfc-editor.org/rfc/rfc9124), [ISVS 1.0](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS), plus [RFC 9019](https://www.rfc-editor.org/rfc/rfc9019), [draft-ietf-suit-manifest-37](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/), [Uptane DEPLOY](https://uptane.github.io/deployment-considerations/index.html) and [RAID 2024](https://doi.org/10.1145/3678890.3678927) where noted. "≈" marks a closest-but-not-equivalent clause; **NOT FOUND** means no clause was located in the text read.

**7.1 Matrix**

| Catalog ID | Class | TUF 1.0.37 § | Uptane 2.1.0 § | RFC 9124 ID | ISVS 1.0 ID | Conformance observable (one line) |
|---|---|---|---|---|---|---|
| OTA-AUTH-01 | Artifact substitution | 1.5.2 "Arbitrary installation attacks", "Wrong software installation"; 5.7.1–5.7.3; 4.5 (LENGTH, HASHES) | 4.3.4 "Arbitrary software attack"; 5.4.2.4; 5.4.3.4 s7 + length SHALL; 5.4.4.2 s10.2.1 | THREAT.IMG.NON_AUTH → REQ.SEC.AUTHENTIC (§3.13 Payload Digests); THREAT.IMG.REPLACE → REQ.SEC.AUTH.EXEC; THREAT.NET.REDIRECT → REQ.SEC.AUTH.REMOTE_LOC | 3.4.3; 3.4.4 | substituted artifact is rejected and never installed or exposed to the app |
| OTA-AUTH-02 | Metadata tampering | 5.3.4, 5.4.2, 5.5.3, 5.6.3 (signature threshold); 5.5.2, 5.6.2 (hash vs parent) | 5.4.4.3 s2.3, 5.4.4.4 s2, 5.4.4.5 s2–s3, 5.4.4.6 s3; 5.4.4.6 s6–s8 (Director-specific) | THREAT.NET.ONPATH, THREAT.IMG.NON_AUTH → REQ.SEC.AUTHENTIC; THREAT.MFST.OVERRIDE → REQ.SEC.ACCESS_CONTROL | 3.4.3 | tampered metadata discarded; trusted copy on disk unchanged; error reported |
| OTA-AUTH-03 | Signature / keyid binding | 4.2.1 (KEYID = SHA-256 of canonical key; "MUST be unique in the 'signatures' array"); 5.3.4/5.4.2/5.5.3/5.6.3 ("each KEY MUST only contribute one SIGNATURE"); TAP 9, TAP 12 | 5.2.1 (public key identifier); 5.2.2 ("Each key SHALL have a unique public key identifier"); "threshold of unique keys" in 5.4.4.3 s2.3, 5.4.4.4 s2, 5.4.4.5 s3, 5.4.4.6 s3 | REQ.SEC.AUTHENTIC (§3.15 Signature); REQ.USE.MFST.MULTI_AUTH; dedicated THREAT **NOT FOUND** | 3.4.3 (generic); 1.3.13 (separate debug/release keys) | duplicate signatures / mismatched keyid do not count toward threshold → rejection |
| OTA-FRESH-01 | Indefinite freeze | 1.5.2 "Indefinite freeze attacks"; 5.1; 5.3.10, 5.4.4, 5.5.6, 5.6.5; 6.1 (withheld root bounded by expiry) | 4.3.2 "Freeze attack"; 5.4 (secure time SHALL); 5.4.4.3 s3, 5.4.4.4 s4, 5.4.4.5 s7, 5.4.4.6 s5; 5.2.3.1 (vehicle identifier); RAID Finding 1 (5.4.3.1 gap) | THREAT.IMG.EXPIRED.OFFLINE → REQ.SEC.EXP (MAY-level expiry), REQ.USE.MFST.PRE_CHECK | **NOT FOUND** | expired metadata (by fixed start time / attested time) → abort + "freeze" report |
| OTA-FRESH-02 | Rollback | 1.5.2 "Rollback attacks"; 5.3.5, 5.4.3.1, 5.4.3.2, 5.5.5 | 4.3.3 "Rollback attack"; 5.4.4.3 s2.4, 5.4.4.4 s3, 5.4.4.5 s4–s6, 5.4.4.6 s4; release counter 5.2.3.1.1, 5.4.3.4 s5, 5.4.4.2 s10.2.3 | THREAT.IMG.EXPIRED → REQ.SEC.SEQUENCE (SUIT -37 §8.4.2 `suit-manifest-sequence-number`) | 3.4.6 (L3) | lower-version metadata / lower release counter rejected after a prior success |
| OTA-FRESH-03 | Mix-and-match | 1.5.2 "Mix-and-match attacks" (metadata combination); 2.1.3; 5.5.2, 5.5.4, 5.6.2, 5.6.4 | 4.3.3 "Mix-and-match attack" (incompatible *images*); 5.4.4.5 s2, 5.4.4.6 s2; 5.3.2.1 s5 (Director SHALL consider dependencies/conflicts) | **NOT FOUND** (≈ REQ.USE.MFST.COMPONENT / §3.19 Dependencies; usability, not threat) | **NOT FOUND** | snapshot/targets version or hash not matching parent listing → abort |
| OTA-FRESH-04 | Fast-forward | 1.5.2 "Fast-forward attacks"; 5.3.11 (delete timestamp/snapshot on key rotation) | 5.4.4.3 s4 ("recovery from fast-forward attacks [MERCURY]"); not in §4.3 list | **NOT FOUND** | **NOT FOUND** | after timestamp/snapshot key rotation, client accepts new lower-version timestamp/snapshot |
| OTA-KEY-01 | Key compromise: online keys → downgrade | 1.5 (online keys not used for roles clients ultimately trust); 1.5.2 "Vulnerability to key compromises"; 5.4.3.1–5.4.3.2, 5.5.5 (checks against persisted trusted versions) | 4.2 (Director *or* Image repo, not both); 5.2.3.1.1 release counter ("even in cases where the Director repository is compromised"); 5.4.4.2 s10.2.3; DEPLOY "Preventing rollback attacks in case of Director compromise" | THREAT.KEY.EXPOSURE → REQ.SEC.KEY.PROTECTION, REQ.SEC.KEY.ROTATION; THREAT.IMG.EXPIRED → REQ.SEC.SEQUENCE | 3.4.6; 1.5.2 | metadata validly signed by online keys but pointing to older artifacts is still rejected |
| OTA-KEY-02 | Key compromise: online keys → arbitrary software | 1.5; 2.1.4; 5.6.3 (targets threshold from root); 5.7.3 | 4.2; 5.4 (Primary SHALL full verification); 5.4.4.2 s10 (Director vs Image match); DEPLOY ecus.md (partial-verification weakness) | THREAT.KEY.EXPOSURE → REQ.SEC.KEY.PROTECTION; THREAT.UPD.UNAPPROVED → REQ.SEC.RIGHTS | 3.4.3; 1.5.2 | artifact signed only by online/Director keys and absent from offline/Image metadata is rejected (full-verification ECU) |
| OTA-KEY-03 | Revocation after rotation | 1.5.3 ("All keys must be easily and safely revocable"); 5.3.1–5.3.9 (root chain, dual threshold 5.3.4); 5.3.11; 6.1; TAP 8, TAP 20 | 5.4.4.3 s2 (root chain) and s4; 5.4.4.1 note (optional Director Root check for Targets-key rotation); DEPLOY key_management.md | REQ.SEC.KEY.ROTATION; REQ.USE.DELEGATION (§3.25 Delegation Chain) | 1.5.2 (process only); 2.1.11 (device credentials, ≈) | metadata signed by a revoked key is rejected after the client walks to the new root |
| OTA-KEY-04 | Freeze with online keys | 2.1.4; 5.4.3.2, 5.5.5 (no version regression); 5.5.6, 5.6.5 (expiry bounds); 6.1 | 4.3.2 "Freeze attack"; 5.4.4.6 s5; DEPLOY key_management.md (longer expiry gives "more time to execute freeze attacks") | ≈ THREAT.KEY.EXPOSURE + REQ.SEC.EXP | **NOT FOUND** | freshly signed timestamp over stale snapshot/targets: stale role expires → abort |
| OTA-DOS-01 | Endless data (metadata) | 1.5.2 "Endless data attacks"; 5.3.3 (W bytes, Y files), 5.4.1 (X), 5.5.1 (length or Y), 5.6.1 (length or Z), 5.6.7.1 (max roles) | 4.3.3 "Endless data attack"; 5.4.4.3 s2.2 (X), 5.4.4.4 s1 (Y), 5.4.4.5 s1, 5.4.4.6 s1 (Z) | **NOT FOUND** (≈ REQ.SEC.MFST.CONST: manifest "MUST fit within internal memory") | **NOT FOUND** | bytes consumed ≤ configured bound; client terminates cleanly |
| OTA-DOS-02 | Endless data (artifact) | 5.7.3 ("up to the number of bytes specified in the targets metadata"); 4.5 LENGTH | 5.4.3.3 s4 ("up to the number of bytes specified in the Targets metadata"); 5.4.3.4 length SHALL; 5.2.3.1 size | ≈ THREAT.IMG.EXTRA → REQ.SEC.IMG.COMPLETE_DIGEST; §3.14 Size (REQ.SEC.AUTH.EXEC) | **NOT FOUND** | download stops at declared length; oversize artifact not persisted |
| OTA-DOS-03 | Slow retrieval (metadata) | **NOT FOUND** in 1.0.37 (removed v1.0.7, commit f9122f1, PR #111) | 4.3.2 "Slow retrieval attack"; 5.4 ("SHALL monitor the download speed of image metadata…"; alert SHOULD) | **NOT FOUND** | **NOT FOUND** | below-threshold rate detected → abort/report within bounded time |
| OTA-DOS-04 | Slow retrieval (artifact) | **NOT FOUND** in 1.0.37 (as above) | 4.3.2; 5.4 ("…and image binaries") | **NOT FOUND** | **NOT FOUND** | as above, for artifact transfer |
| OTA-DOS-05 | Mirrors preventing updates | 1.5.2 "Malicious mirrors preventing updates"; 2.1.5; 2.2; 4.7 mirrors.json; no §5 step | **NOT FOUND** (≈ 4.3.2 "Drop-request attack", "Denial of service attack") | ≈ THREAT.NET.REDIRECT → REQ.SEC.AUTH.REMOTE_LOC | **NOT FOUND** | with one bad and one good mirror, update succeeds from the good one, or failure is reported |
| OTA-NET-01 | Interrupted transfer | §5 preamble ("should still be able to update again in the future") | 5.4.3.3 ("If any part of this step fails, the ECU SHALL jump to the final step"); 5.4.4 (SHOULD NOT leave unrecoverable) | ≈ THREAT.NET.ONPATH ("modified or not delivered"); RFC 9019 §3 (resume interrupted transfers); SUIT -37 §6.3.1 | 3.4.7 | truncated download → no install, trusted state unchanged, next cycle succeeds |
| OTA-PWR-01 | Power loss: trust store | 5.3.8, 5.4.5, 5.5.7, 5.6.6 (persist; no atomicity stated); §5 preamble | 5.4.2.6 ("Each Secondary SHALL store the latest copy…"); 5.4.3.3 s4 (retain previous Targets on failure) | **NOT FOUND** (SUIT -37 §6.3.1 journal) | **NOT FOUND** | after cut during metadata persist, client restarts with a valid previous or new trusted set |
| OTA-PWR-02 | Power loss: artifact | 5.7.3 ("MUST write the file to non-volatile storage"; no atomicity stated) | 5.4.3.3 (backup SHOULD); 5.4.3.5 (backup pre-condition) | **NOT FOUND** (RFC 9019 §3; SUIT -37 §6.3.1) | 3.4.7 | partial artifact never treated as verified; re-download or resume |
| OTA-PWR-03 | Power loss: A/B slot write | **NOT FOUND** (1.4 non-goal: "performing the actual update of application files") | ≈ 5.4.3.5; DEPLOY customizations.md | **NOT FOUND** (≈ THREAT.IMG.LOCATION → REQ.SEC.AUTH.IMG_LOC) | 3.4.7 | cut during inactive-slot write → active slot still boots |
| OTA-PWR-04 | Power loss: boot switch | **NOT FOUND** (1.4 non-goal) | **NOT FOUND** | ≈ REQ.SEC.AUTH.EXEC (verify at boot); RFC 9019 §4.1 | 3.4.7; 3.1.5 | cut around commit point (bootloader var / symlink / trailer) → old or new boots, never neither |
| OTA-INST-01 | Wrong software / compatibility | 1.5.2 "Wrong software installation"; 5.6.7; 5.7.1–5.7.2 | 5.4.3.4 s3 (hardware identifier), s4 (filename valid for ECU); 5.2.3.1.1; 5.4.4.6 s7–s8; 5.4.4.7 s4.1 | THREAT.IMG.INCOMPATIBLE → REQ.SEC.COMPATIBLE, REQ.SEC.AUTH.COMPATIBILITY; THREAT.IMG.FORMAT → REQ.SEC.AUTH.IMG_TYPE; THREAT.IMG.LOCATION → REQ.SEC.AUTH.IMG_LOC | **NOT FOUND** | validly signed image for another hardware ID/class is rejected |
| OTA-INST-02 | Partial bundle installation | **NOT FOUND** | 4.3.2 "Partial bundle installation attack" (no labelled check); DEPLOY "Atomic installation… out of its scope" | **NOT FOUND** (≈ REQ.USE.MFST.COMPONENT) | ≈ 3.4.7 | blocking one component → reported via version report; no silent mixed state |
| OTA-PARSE-01 | Malformed manifest | 4.3 SPEC_VERSION ("clients MUST verify that 'spec_version' matches"); otherwise **NOT FOUND** | **NOT FOUND** in Standard; DEPLOY "ASN.1 decoding" (SHOULD fuzz; prefer DER) | REQ.USE.PARSE (§4.5.13); REQ.SEC.MFST.CONST; SUIT -37 §6.1 (fail on unsupported version), §6.2 (verify signature "prior to parsing/executing") | **NOT FOUND** | malformed input → controlled rejection, no crash/hang (fuzz harness) |

**7.2 Classes named by the specs but missing from the catalog (proposed IDs)**

| Proposed ID | Class (exact source name) | TUF § | Uptane § | RFC 9124 ID | ISVS ID |
|---|---|---|---|---|---|
| OTA-INST-03 | "Extraneous dependencies attacks" | 1.5.2 (no dedicated step) | ≈ 5.3.2.1 s5 (Director dependencies) | **NOT FOUND** | **NOT FOUND** |
| OTA-INST-04 | TOCTOU between verification and use ("THREAT.MFST.TOCTOU", "THREAT.IMG.REPLACE") | **NOT FOUND** (≈ 2 "Fetching": app gets file only after checks) | ≈ 5.4.3.4 (checks SHOULD be on image in secondary storage) | THREAT.MFST.TOCTOU → REQ.SEC.MFST.CONST; THREAT.IMG.REPLACE → REQ.SEC.AUTH.EXEC | 3.4.4 |
| OTA-INST-05 | Wrong delta precursor ("THREAT.UPD.WRONG_PRECURSOR") | **NOT FOUND** | ≈ 3.2.2.4 "Update one ECU with multiple deltas" (use case) | THREAT.UPD.WRONG_PRECURSOR → REQ.SEC.AUTH.PRECURSOR | **NOT FOUND** |
| OTA-AUTH-04 | "THREAT.IMG.EXTRA: Extra Data after Image" | ≈ 5.7.3 (hash over declared length) | ≈ 5.4.3.4 (length SHALL match) | THREAT.IMG.EXTRA → REQ.SEC.IMG.COMPLETE_DIGEST | **NOT FOUND** |
| OTA-AUTH-05 | Debug / pre-production build acceptance | **NOT FOUND** | **NOT FOUND** | **NOT FOUND** | 3.4.8; 1.3.13 |
| OTA-AUTHZ-01 | Unapproved firmware / override of critical elements ("THREAT.UPD.UNAPPROVED", "THREAT.MFST.OVERRIDE") | ≈ 5.6.7 delegations (terminating) | ≈ 5.4.4.8 multi-role delegations | THREAT.UPD.UNAPPROVED → REQ.SEC.RIGHTS, REQ.SEC.ACCESS_CONTROL; THREAT.MFST.OVERRIDE → REQ.SEC.ACCESS_CONTROL | **NOT FOUND** |
| OTA-CONF-01 | "Eavesdrop attack" / "THREAT.IMG.DISCLOSURE" | **NOT FOUND** (1.5: "not concerned with exposing… the contents of updates") | 4.3.1; 5.4.3.4 s6; 5.2.3.1.1 | THREAT.IMG.DISCLOSURE → REQ.SEC.IMG.CONFIDENTIALITY | 3.4.9, 3.4.11, 3.4.12 |
| OTA-CONF-02 | "THREAT.MFST.EXPOSURE" | **NOT FOUND** (1.5) | **NOT FOUND** | THREAT.MFST.EXPOSURE → REQ.SEC.MFST.CONFIDENTIALITY | **NOT FOUND** |
| OTA-DOS-06 | "Drop-request attack" | ≈ 1.5.2 note ("must detect when a client is unable to update") | 4.3.2 | ≈ THREAT.NET.ONPATH | **NOT FOUND** |
| OTA-FRESH-05 | Cross-device replay of image-less Director metadata ("replay attack") | **NOT FOUND** | 5.2.3.1 (vehicle identifier SHALL); DEPLOY "Avoiding Director replay attacks" | **NOT FOUND** | **NOT FOUND** |
| OTA-TIME-01 | Absent/invalid time attestation (RAID "Finding 1: Freeze Attack") | 5.1 (fixed start time); 7.1 bogus clocks (open question) | 5.4, 5.4.2.2, 5.4.3.1, 5.4.4.1 s1, 5.4.4.2 s1 | ≈ REQ.SEC.EXP, REQ.SEC.KEY.ROTATION (secure clock) | **NOT FOUND** |
| OTA-REP-01 | Version-report replay / attacker-authored VVM (RAID P2, P5) | **NOT FOUND** | 5.4.2.1.2 (nonce SHALL change); 5.3.2.1 s3–s4 (Director checks, SHOULD) | THREAT.NET.ONPATH → REQ.SEC.REPORTING | 1.4.7 (≈ log integrity) |
| OTA-NET-02 | Transport / server authentication | 1.5.1 (designed to be secure without TLS) | DEPLOY customizations.md "Using Uptane with transport security" (not read in detail) | REQ.SEC.REPORTING; ≈ THREAT.NET.ONPATH | 3.4.10, 3.4.12; 4.1.1, 4.1.5 |
| OTA-PARSE-02 | Unsupported spec/encoding version | 4.3 SPEC_VERSION | **NOT FOUND** | ≈ REQ.USE.PARSE; SUIT -37 §6.1 | **NOT FOUND** |

Out of client scope (server/supply chain; listed for completeness): "Denial of service attack" against repositories (Uptane 4.3.2), THREAT.KEY.EXPOSURE as key-storage practice (REQ.SEC.KEY.PROTECTION), THREAT.MFST.MODIFICATION (REQ.SEC.MFST.CHECK, REQ.SEC.MFST.TRUSTED), ISVS 3.4.11 server-side encryption — [RFC 9124 §4.3](https://www.rfc-editor.org/rfc/rfc9124#section-4.3); [Uptane 2.1.0 §4.3.2](https://github.com/uptane/uptane-standard/blob/2.1.0/uptane-standard.md)

### Inferences
- The specs disagree on the strictness of equal-version checks (TUF: root exactly N+1 and timestamp strictly greater; Uptane: "less than or equal" accepted). A cross-implementation benchmark therefore needs per-spec oracles for OTA-FRESH-02.
- "Mix-and-match" means different things in TUF (metadata) and Uptane (images). Splitting OTA-FRESH-03 into metadata (FRESH-03a) and image-set (FRESH-03b) variants would avoid conflating TUF §1.5.2 and Uptane §4.3.3.
- Power-loss rows (PWR-01…04) lack normative client clauses in TUF, Uptane, RFC 9124 and ISVS. Their thesis justification should cite RFC 9019 §3, SUIT -37 §6.3.1 and the updaters' own documented guarantees (§6), and label them "robustness, not security conformance".

### Gaps
- Uptane DEPLOY "Using Uptane with transport security" (`customizations.md`) was not read in full; OTA-NET-02's Uptane cell is a heading-level reference.
- No local text gives a numeric threshold for slow-retrieval detection or endless-data bounds; benchmark parameters will be implementer-chosen.
- RFC 9124 identifiers were not traced to concrete SUIT -37 CBOR fields beyond §6.1, §6.2, §6.3.1 and §8.4.2.
