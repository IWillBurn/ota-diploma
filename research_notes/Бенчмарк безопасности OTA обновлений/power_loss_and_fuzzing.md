# Power-loss / crash-resilience testing of OTA update installation, and fuzzing of update-metadata parsers

Scope note: research run on 2026-10-31. "Verified" means the claim was read from the cited page or repository during this session. Repository-structure claims (fuzz harness present or absent) were checked over HTTP against GitHub and OSS-Fuzz on 2026-10-31. A claim marked UNVERIFIED rests on background knowledge or on a URL not fetched in this session. Check those before citing them in the thesis.

---

## Q1. Academic crash-consistency work: core technique and bug classes of each line of work

### Takeaway
Three methods are worth borrowing for an OTA benchmark:
- **Record-and-replay of the block/syscall stream with exhaustive or bounded enumeration of crash points.** Used by ALICE/BOB, CrashMonkey/ACE, Torturing Databases and SnapCC.
- **A page-cache-emulating FUSE layer that drops unsynced data.** Used by LazyFS and CuttleFS.
- **"Run to the end once, count operations N, then interrupt at every i in 1..N."** Used by eXplode-style model checking and the MCUboot simulator (see Q3).

Across all of them, the bugs cluster around the same few sites: log/metadata files, rename/fsync ordering, and recovery code. Those are the same sites where OTA updaters keep their state (bootloader env, status files, TUF trusted metadata).

### Cited Findings

**eXplode (OSDI 2006)**
- Junfeng Yang, Can Sar and Dawson Engler, "EXPLODE: A Lightweight, General System for Finding Serious Storage System Errors", OSDI '06, pp. 131–146 — [USENIX](https://static.usenix.org/event/osdi06/tech/yang_junfeng.html)
- Technique: it borrows from model checking but uses the real system code as its own model. User-written checkers drive the storage system into corner cases, including crash recovery. — [paper HTML](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/yang_junfeng/yang_junfeng_html/index.html)
- Targets: three version-control systems, Berkeley DB, an NFS implementation, ten file systems, a RAID system and VMware GSX. It found bugs in every system checked, 36 in total. — [USENIX](https://static.usenix.org/event/osdi06/tech/yang_junfeng.html)

**ALICE and BOB (OSDI 2014)**
- Pillai et al., "All File Systems Are Not Created Equal: On the Complexity of Crafting Crash-Consistent Applications", OSDI 2014. ALICE analyzes application update protocols and finds "crash vulnerabilities": code whose correctness depends on persistence properties the file system may not provide. — [USENIX abstract](https://www.usenix.org/node/186195); [PDF/landing](https://research.cs.wisc.edu/adsl/Publications/alice-osdi14.html)
- Findings: 60 vulnerabilities across 11 widely used applications (databases, KV stores, VCS, distributed systems, virtualization software). — [USENIX](https://www.usenix.org/node/186195)
  - A secondary summary gives the consequence breakdown as 5 silent failures, 12 durability losses, 25 inaccessible applications and 17 errors on access. — [Colyer summary](https://blog.acolyer.org/2016/02/11/fs-not-equal/)
  - The 60 static vulnerabilities correspond to 156 dynamic ones. — [course notes](https://courses.cs.washington.edu/courses/cse551/17wi/notes/crash.html)
- The companion tool BOB (Block Order Breaker) showed that persistence properties (atomicity, ordering of operations) vary widely across six Linux file systems. Testing an application on one file system therefore does not generalize. — [USENIX](https://www.usenix.org/node/186195); [Colyer](https://blog.acolyer.org/2016/02/11/fs-not-equal/)
- Mechanism (UNVERIFIED detail, from background knowledge of the paper):
  - ALICE records a syscall trace (strace-based) and converts it into logical operations.
  - An "Abstract Persistence Model" then generates crash states. Each state is a prefix of the operations with some later operations dropped or reordered, as far as the model allows.
  - A user-supplied checker runs on each state.
  - Code: `github.com/madthanu/alice` (URL not fetched).

**Torturing Databases for Fun and Profit (OSDI 2014)**
- Mai Zheng, Joseph Tucek, Dachuan Huang, Feng Qin, Mark Lillibridge et al., OSDI '14, pp. 449–464 — [USENIX](https://www.usenix.org/node/186197); [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)
- Framework components:
  - ACID-exercising workloads.
  - Record/replay of a high-fidelity block trace, captured by a modified iSCSI driver and replayed onto the original image to simulate the power fault.
  - A ranking algorithm that chooses where to inject faults.
  - A multi-layer tracer for root-cause diagnosis. — [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)
- Fault model: clean termination of the I/O stream. Blocks written before the cut are intact, and blocks after it are lost, with no corruption or reordering. This is the "idealized" case that well-written software should survive. — [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)
- Result: 8 databases tested, from open-source KV stores to commercial OLTP. All 8 misbehaved and 7 clearly violated ACID. — [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)

**Understanding the Robustness of SSDs under Power Fault (FAST 2013)**
- Zheng, Tucek, Qin, Lillibridge, FAST '13, pp. 271–284 — [USENIX](https://www.usenix.org/conference/fast13/understanding-robustness-ssds-under-power-fault); [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2013_FAST_SSD.pdf)
- Method: an automated hardware fault-injection framework ran 15 SSDs from 5 vendors, plus 2 HDDs, through more than 3,000 power-cycle tests.
- Result: 13 of 15 SSDs failed. Failure classes were bit corruption, shorn writes, unserializable writes, metadata corruption and total device failure ("bricking"). — [USENIX](https://www.usenix.org/conference/fast13/understanding-robustness-ssds-under-power-fault)
- Per-class device counts are reported only second-hand: 3 bit corruption, 3 shorn writes, 8 serializability errors, 1 lost a third of its data, 1 bricked. — [Storage Bits mirror](https://www.macsurfer.com/redir.php?u=766257) (check against the PDF)

**CrashMonkey and ACE: Bounded Black-Box Crash Testing (OSDI 2018)**
- Mohan, Martinez, Ponnapalli, Raju, Chidambaram, "Finding Crash-Consistency Bugs with Bounded Black-Box Crash Testing", OSDI 2018 — [USENIX](https://www.usenix.org/conference/osdi18/presentation/mohan); [arXiv 1810.02904](https://arxiv.org/abs/1810.02904); journal version in ACM TOS 15(2) — [ACM DL](https://dl.acm.org/doi/10.1145/3320275); earlier HotStorage'17 version — [PDF](https://www.cs.utexas.edu/~vijay/papers/hotstorage17-crashmonkey.pdf)
- B3 idea: treat the file system as a black box and exhaustively enumerate small workloads within bounds. Crashes are injected only after persistence points (fsync, fdatasync, sync), followed by a check of the recovered state. — [arXiv](https://arxiv.org/abs/1810.02904)
- Empirical motivation from a study of 5 years of Linux FS crash bugs: most reproduce with 3 or fewer operations on a fresh FS, and all of them occur after fsync-related crashes. — [arXiv](https://arxiv.org/abs/1810.02904)
- Tooling:
  - CrashMonkey is a record-and-replay framework that simulates power-loss crashes and checks recovery.
  - ACE (Automatic Crash Explorer) generates workloads exhaustively within user bounds.
- Results: reproduced 24 of 26 known bugs across 7 kernels and 3 file systems, and found 10 new bugs, including non-atomic rename(). — [arXiv](https://arxiv.org/abs/1810.02904)

**Janus (IEEE S&P 2019) and Hydra (SOSP 2019)**
- Janus: Wen Xu, Hyungon Moon, Sanidhya Kashyap, Po-Ning Tseng, Taesoo Kim, "Fuzzing File Systems via Two-Dimensional Input Space Exploration", IEEE S&P 2019 — [PDF](https://sanidhya.github.io/pubs/2019/janus.pdf)
  - It mutates the on-disk image metadata and the syscall sequence together.
  - It found 90 bugs in upstream Linux, 62 acknowledged.
  - It targets memory-safety bugs. Crash consistency is listed only as a possible extension. — [PDF](https://sanidhya.github.io/pubs/2019/janus.pdf); [slides](https://sanidhya.github.io/pubs/2019/janus-slides.pdf)
- Hydra: Seulbae Kim, Meng Xu, Sanidhya Kashyap, Jungyeon Yoon, Wen Xu, Taesoo Kim, "Finding Semantic Bugs in File Systems with an Extensible Fuzzing Framework", SOSP 2019, pp. 147–161 — [PDF](https://gts3.org/assets/papers/2019/kim:hydra.pdf); [code](https://github.com/sslab-gatech/hydra)
  - It plugs bug-class checkers into a fuzzer. One of them is the in-house crash-consistency checker SymC3, alongside POSIX-violation and FS-specific logic checkers.
  - It found crash-consistency bugs in ext4, Btrfs and F2FS, plus one in the verified FSCQ. — [PDF](https://gts3.org/assets/papers/2019/kim:hydra.pdf)
  - The bug count conflicts between sources: 91 new bugs in the paper record vs 155 in the Georgia Tech news item. — [news](https://cc.gatech.edu/news/628763/hydra-first-fuzzing-framework-find-any-file-system-bug)

**CuttleFS (USENIX ATC 2020)**
- Rebello, Patel, Alagappan, Arpaci-Dusseau, "Can Applications Recover from fsync Failures?", ATC 2020, pp. 753–767 — [USENIX](https://www.usenix.org/conference/atc20/presentation/rebello)
- CuttleFS is a FUSE FS with its own user-space page cache that emulates the fsync-failure behaviors of ext4, XFS and Btrfs.
- None of the 5 applications tested (PostgreSQL, LMDB, LevelDB, SQLite, Redis) handled fsync failure sufficiently.
- The authors recommend that recovery rely only on on-disk state. — [USENIX](https://www.usenix.org/conference/atc20/presentation/rebello)

**Chipmunk (EuroSys 2023, Best Paper) and Mumak (EuroSys 2023): persistent memory**
- Chipmunk: LeBlanc, Pailoor, Saran, Dillig, Bornholt, Chidambaram, EuroSys 2023, DOI 10.1145/3552326.3567498 — [PDF](https://www.cs.utexas.edu/~isil/chipmunk.pdf); [NSF PAR](https://par.nsf.gov/biblio/10469308)
  - It tests POSIX PM file systems for crash consistency.
  - It uses ACE workloads plus Syzkaller gray-box fuzzing and builds on CrashMonkey.
  - It found 23 new bugs in 5 PM file systems.
- Mumak: Gonçalves, Matos, Rodrigues, EuroSys 2023 — [PDF](https://www.dpss.inesc-id.pt/~rodrigo/joao-mumak-eurosys23.pdf); [code](https://github.com/task3r/mumak)
  - Black-box PM bug detection whose bug coverage is comparable to other tools while running up to 25× faster.
  - It found 4 new crash-consistency bugs.
  - It is relevant mainly for its methodology of pruning the space of failure points.

**LazyFS (PVLDB 2024)**
- Maria Ramos, João Azevedo, Kyle Kingsbury, José Pereira, Tânia Esteves, Ricardo Macedo, João Paulo, "When Amnesia Strikes: Understanding and Reproducing Data Loss Bugs with Fault Injection", PVLDB 17(11):3017–3030, 2024, doi:10.14778/3681954.3681980 — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf); [code](https://github.com/dsrhaslab/lazyfs). The venue is VLDB 2024, not FAST.
- Mechanism: a FUSE passthrough FS with its own page cache that never flushes in the background. Data reaches the backend only on fsync-family calls, on injected partial-persistence faults, or on LRU eviction when the cache is full. — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Faults:
  - Lost writes: either crash LazyFS, or `clear-cache` to drop unsynced data while keeping the mount.
  - Torn writes: `torn-seq` persists selected writes from a sequence, and `torn-op` splits one large write and persists only some parts.
  - Faults are triggered by a static TOML config or by commands sent through a Unix FIFO. — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Profiling output: before injecting a fault, LazyFS reports which cached blocks will be lost, and it records a syscall trace (open, write, fsync, rename and so on) with fault moments. — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Results on PostgreSQL, etcd, ZooKeeper, Redis, LevelDB, PebblesDB and Lightning Network:
  - Automated reproduction of 5 known bugs.
  - Clarified 7 ambiguous user-reported bugs.
  - Found 8 new bugs, causing data loss, corruption and unavailability. — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
  - In 9 of the 12 studied bugs the problem was in log or metadata files (for example LevelDB CURRENT/MANIFEST, ZooKeeper txn logs, etcd WAL).
  - A typical trigger is "crash before any sync after rename(000002.dbtmp)". — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Stated limitations, both important for OTA:
  - It cannot test durability of FS metadata, such as whether an inode or rename update was flushed.
  - O_DIRECT I/O bypasses it and is out of scope. — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Integrated into Jepsen: after a kill, a call discards unfsynced writes. MongoDB used it this way in its tests. — [Jepsen API](https://jepsen-io.github.io/jepsen/jepsen.lazyfs.html); [MongoDB SERVER-66250](https://jira.mongodb.org/browse/SERVER-66250)

**2021–2026 work**
- *Understanding and Detecting Software Upgrade Failures in Distributed Systems* (DUPTester), Zhang et al., SOSP 2021. A study of 123 real upgrade failures in 8 distributed systems; DUPTester found 20 unknown upgrade failures. It is about version-incompatibility rather than power loss, but its "full-stop vs rolling upgrade" scenario taxonomy is reusable. — [PDF](https://www.cs.purdue.edu/homes/yonglezh/pub/upgrade-sosp21.pdf); [artifact review](https://sysartifacts.github.io/sosp2021/summaries/duptester)
- SquirrelFS (OSDI 2024) uses the Rust compiler to statically check crash-consistency invariants (static approach, not testing). — [PDF](https://www.usenix.org/system/files/osdi24-leblanc.pdf)
- Silhouette (FAST 2025) checks whether PM file systems correctly implement their own consistency mechanisms (journaling, logging) instead of enumerating crash states. — [PDF](https://www.usenix.org/system/files/fast25-jiao.pdf)
- PoWER (OSDI 2025) is a tool-agnostic verification technique for crash consistency. — [PDF](https://www.usenix.org/system/files/osdi25-leblanc.pdf)
- SnapCC (ACM TOSEM 2025) systematically explores persistent on-disk states as crash-recovery inputs and found 7 new bugs in UFS, XFS, BCacheFS and OpenZFS. — [ACM DL](https://dl.acm.org/doi/10.1145/3718738)
- Background on formal crash-consistency models (Ferrite): Bornholt et al., "Specifying and Checking File System Crash-Consistency Models", ASPLOS 2016 — [ACM DL](https://dl.acm.org/doi/10.1145/2872362.2872406)

### Inferences
- The CrashMonkey finding that "all bugs follow fsync-related crashes" and the LazyFS finding that "most bugs are in log/metadata files" together justify the crash-point selection strategy in Q8. Concentrate crash points immediately before and after each fsync/fdatasync/rename/flush issued by the updater, and do not spread them uniformly in time.
- OTA updaters write two kinds of data.
  - Large sequential slot images. These are usually written to a raw partition and are atomic by A/B design.
  - Small state files: bootloader env (U-Boot env, grubenv, barebox-state), RAUC status, Mender store, SWUpdate ustate, TUF trusted metadata. These are exactly the "log/metadata" class where the literature finds bugs, so the benchmark should weight them most.
- LazyFS cannot model metadata durability (rename, directory entries). Updaters rely on write-tmp/fsync/rename (TUF clients, GRUB env workarounds), so LazyFS alone under-approximates crash states. Block-level replay (dm-log-writes) is needed as a complement.
- ALICE is old research code (UNVERIFIED: Python-2-era) and may be hard to run in 2026. Its crash-state generation is easy to reimplement on top of `strace -f -e trace=%file,%desc` output for small state directories.

### Gaps
- A Hydra-era workshop or Janus-era follow-up that specifically targets update/installer software was not found.
- No 2023–2026 paper specifically on crash-consistency testing of OTA/firmware updaters was found. A search for "firmware OTA power interruption fault injection" returned only practitioner guides (see Q5). This looks like a genuine research gap and supports the thesis's novelty claim.
- The exact CrashMonkey crash-state counts and ACE workload counts per bound (seq-1/2/3) were not extracted. Read the OSDI'18 PDF for those numbers.

---

## Q2. Linux tooling for injecting crashes and faults at process, FS and block level

### Takeaway
For block-level power-cut simulation, the most important tools are:
- **dm-log-writes + replay-log**: records every write and flush in on-disk order, and replays prefixes up to marks or FUA/flush points.
- **dm-flakey `drop_writes`**: silently drops all writes after a point, which is a coarse power cut.
- **QEMU blkdebug**: a state-machine-driven error injector inside the VM's block layer.

For the process level, strace `--inject` can deliver SIGKILL or an error at the Nth occurrence of a chosen syscall, which gives deterministic, enumerable kill points without modifying the updater. LazyFS and CharybdeFS cover file-level semantics. libfiu, eBPF `bpf_override_return` and the kernel fault-injection framework cover error-path testing rather than power loss.

### Cited Findings

**dm-log-writes**
- What it logs: it takes `log-writes <dev_path> <log_dev_path>`, passes I/O to dev_path, and logs every write with its data to log_dev_path. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
- Ordering model: writes are logged in completion order and attached to the next REQ_PREFLUSH. Only after the flush completes are they logged, followed by the flush. Example: "W1,W2,W3,C3,C2,Wflush,C1,Cflush" is logged as "W3,W2,flush,W1…". This models what is actually on disk at a power failure. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
- FUA requests are logged on completion, since they bypass the device cache. DISCARDs are logged like writes. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
- Marks are added with `dmsetup message log 0 mark <name>`, and the automatic end mark is `dm-log-writes-end`. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
- Replay commands, verbatim from the docs:
  - `replay-log --log /dev/sdc --replay /dev/sdb --end-mark fsync`
  - Incremental check: `replay-log --log /dev/sdc --replay /dev/sdb --start-mark mkfs --fsck "btrfsck /dev/sdb" --check fua`, which replays to each FUA, runs fsck, and continues until the log ends or fsck fails. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html)
  - The replay tool lives at [josefbacik/log-writes](https://github.com/josefbacik/log-writes) and inside xfstests under `src/log-writes/` (`log-writes.c`, `replay-log.c`). — [xfstests src](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/plain/src/log-writes/)
- Usage in xfstests: helper library `common/dmlogwrites` provides `_log_writes_init`, `_log_writes_mark`, `_log_writes_replay_log`, `_log_writes_find_next_fua`, `_log_writes_replay_log_range` and `_log_writes_mark_to_entry_number`. — [common/dmlogwrites](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/plain/common/dmlogwrites)
  - Tests generic/455, 457, 470 and 482 use it. generic/482 runs fsstress on a dm-thin volume under log-writes, then replays to each FUA and checks the FS. — [generic/482](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/plain/tests/generic/482)

**dm-flakey**
- Table: `<dev> <offset> <up interval> <down interval> [<num_features> [<features>]]`. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
- Features:
  - `drop_writes`: writes are silently discarded.
  - `error_writes` and `error_reads`.
  - `corrupt_bio_byte <Nth> <r|w> <value> <flags>`.
  - `random_read_corrupt` / `random_write_corrupt <probability 0..1e9>`. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
- The docs suggest combining it with dm-delay. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
- Using `drop_writes` to simulate a power cut follows the pattern xfstests uses for log-replay tests: freeze writes at a moment, then remount. The helper name `_flakey_drop_and_remount` is UNVERIFIED.

**dm-dust**
- Emulates bad sectors at chosen blocks. Table: `<device_path> <offset> <blksz>`. Messages: `addbadblock`, `removebadblock`, `enable`, `disable`, `quiet`. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/dm-dust.html)
- A write to a listed bad block removes it from the list, mimicking a drive remapping the sector. It is meant for testing read-error handling. — [kernel docs](https://docs.kernel.org/admin-guide/device-mapper/dm-dust.html)

**dm-error**
- dm-error (all I/O fails) can be swapped in with `dmsetup suspend/load/resume` to make a device "vanish" at a precise instant. UNVERIFIED (doc page not fetched): https://docs.kernel.org/admin-guide/device-mapper/

**Kernel fault-injection framework**
- `fail_make_request` makes block I/O fail for devices that opt in via `/sys/block/<dev>/make-it-fail`.
- `fail_function` forces error returns from functions annotated `ALLOW_ERROR_INJECTION()`.
- Common debugfs knobs: `probability`, `interval`, `times`, `space`, `verbose`, `task-filter`. — [kernel docs](https://docs.kernel.org/fault-injection/fault-injection.html)

**eBPF `bpf_override_return`**
- A kprobe-attached BPF program can short-circuit a function and set its return value. Requirements: `CONFIG_BPF_KPROBE_OVERRIDE`, and only functions tagged `ALLOW_ERROR_INJECTION`. — [docs.ebpf.io](https://docs.ebpf.io/linux/helper-function/bpf_override_return/); [LWN 740146](https://lwn.net/Articles/740146/)
- A 2024 third-party article says only x86 supports it. That is stale or uncertain. — [besthub](https://besthub.dev/articles/exploring-kprobe-override-for-kernel-error-injection-7d0428175143)
- bpftrace's `override()` builtin was not verified (UNVERIFIED).

**strace `--inject` (man page, strace 7.1, 2026-06-25)**
- Syntax: `--inject=syscall_set[:error=errno|:retval=value][:signal=sig][:syscall=…][:delay_enter=…][:delay_exit=…][:poke_enter/exit=…][:when=expr]`. — [man7 strace.1](https://man7.org/linux/man-pages/man1/strace.1.html)
- `signal=sig` "is delivered on entering every system call specified". With `signal=` alone the syscall's outcome is not altered. With `error=`/`retval=` plus `signal=`, "both injection of a fault or success and signal delivery are performed". `error=` replaces the syscall number with -1, so the call does not execute. — [man7 strace.1](https://man7.org/linux/man-pages/man1/strace.1.html)
- `when=first[..last][+[step]]` counts per syscall and per tracee. first and step range over 1..65535. — [man7 strace.1](https://man7.org/linux/man-pages/man1/strace.1.html)

**libfiu**
- `fiu-run -x` preloads POSIX wrappers through LD_PRELOAD so libc/POSIX calls can fail at named points. Example: `fiu-run -x -c "enable_random name=posix/io/rw/read,probability=0.05" fortune`.
- `fiu-ctrl` toggles failure points in a running process. — [fiu-run man](https://blitiri.com.ar/p/libfiu/doc/man-fiu-run.html); [POSIX docs](https://blitiri.com.ar/p/libfiu/doc/posix.html)

**FUSE fault injectors**
- CharybdeFS (ScyllaDB): a passthrough FUSE FS with a Thrift RPC interface (Python scripting). It can inject EIO, EDQUOT, ENOMEM, EBUSY and delays, filtered by path regex. — [GitHub](https://github.com/scylladb/charybdefs); [blog](https://www.scylladb.com/2016/02/16/fault-injection-filesystem-software-testing/); [cookbook](https://www.scylladb.com/2016/05/02/fault-injection-filesystem-cookbook)
- LazyFS covers lost and torn writes; see Q1.

**QEMU block-layer and VM control**
- blkdebug: an ini-style config of `[inject-error]` and `[set-state]` rules. Rules match block events (for example `read_aio`, `write_aio`) and an internal state variable that starts at 1, with options `errno`, `once` and `sector`. The documented example injects EIO on the 2nd `write_aio` through a 1→2 state transition. — [current docs](https://qemu.googlesource.com/qemu/+/refs/heads/master/docs/devel/testing/blkdebug.rst); [older blkdebug.txt](https://qemu.googlesource.com/qemu/+/205e5de4251f4c18e1f17f2e7aaa42ff92c3e05f/docs/blkdebug.txt)
- QMP commands: `quit` (exit emulator), `stop` (pause), `system_reset` (reset guest), `system_powerdown` (ACPI power-button event, not a power cut). — [qmp-commands.txt](https://github.com/qemu/qemu/blob/85f96549100a7239ceae15c9a5b0ba8cdd95bdaa/docs/qmp-commands.txt)
  - `system_reset` only requests a reset, so a harness must wait for the QMP RESET event. — [qtest patch 2024](https://patchew.org/QEMU/20241212150949.16806-1-farosas@suse.de/20241212150949.16806-3-farosas@suse.de)
  - SHUTDOWN events distinguish `host-qmp-quit` from `host-qmp-system-reset`. — [patch](https://patchew.org/QEMU/20181203092617.24090-1-d.csapak@proxmox.com/20181203092617.24090-4-d.csapak@proxmox.com)
- Cache modes: writethrough, writeback (the QEMU default), none, directsync, unsafe. — [SUSE](https://documentation.suse.com/sles-12/html/SLES-all/cha-cachemodes.html); [Thomas-Krenn](https://www.thomas-krenn.com/en/wiki/Qemu_drive_cache_option)
  - With writeback the guest is told of a volatile cache and must send flushes. Unsafe ignores flushes and risks loss on a *host* failure.
  - "writethrough and none behave the same for host crash safety" is "not at all true". — [OpenStack Nova commit](https://opendev.org/openstack/nova/commit/b9dc86d8d646472195070022ff7ae4c372bef4ca)
- nbdkit filters: `error` (inject errors at rates, controllable by a trigger file), `delay` (read/write latency), `log` (log every NBD transaction), `evil` (random read corruption). — [nbdkit-basic-filters](https://mankier.com/package/nbdkit-basic-filters)

### Inferences
- **Killing QEMU is not a full power cut.** When the QEMU process is killed (`quit` or `kill -9`), guest RAM is lost: the guest page cache, the updater's buffers, dirty U-Boot env in RAM. Data QEMU has already written to the host image file survives, because the host kernel did not crash. A QEMU kill therefore models power loss on a disk *without* a volatile write cache, or with an ideal PLP (power-loss-protection) cache. To also model loss of the virtual disk's volatile cache, meaning writes not yet flushed by the guest, add a recording layer:
  - host-side dm-log-writes on a loop/dm device used as a raw QEMU drive with `cache=none` (or `directsync`) so writes reach dm promptly, or
  - dm-log-writes inside the guest kernel.
  Then replay prefixes up to flush points, plus subsets of writes since the last flush. This is an inference from the dm-log-writes and cache-mode semantics above; validate it empirically.
- **Deterministic kill points.** `strace -f --inject=renameat2,rename:error=EIO:signal=SIGKILL:when=N` gives a deterministic "crash just before the Nth rename", because `error=` guarantees the call is not executed. For "crash just after syscall X", inject SIGKILL on the next syscall of any kind. Whether `signal=SIGKILL` alone (no error=) lets the syscall run before death should be checked empirically. The man page says the outcome "is not altered", but SIGKILL at the syscall-entry stop may prevent execution (UNVERIFIED).
- **Negative control.** `libeatmydata` (LD_PRELOAD that turns fsync into a no-op; UNVERIFIED URL https://www.flamingspork.com/projects/libeatmydata/) or `mount -o nobarrier` can serve as a negative control. Running the updater with fsync disabled should make the oracle report failures. If it does not, the crash-state generator is not exercising durability.

### Gaps
- No up-to-date, maintained "NBD write-recorder with replay" tool equivalent to dm-log-writes for QEMU disks was found. nbdkit's `log` filter logs requests, but it was not confirmed to log data payloads for replay.
- QEMU documentation for `-snapshot`, `savevm`/`loadvm` and qcow2 overlays was not fetched in this session. These are standard features, but quote the official docs (https://www.qemu.org/docs/master/system/invocation.html; UNVERIFIED for exact wording).

---

## Q3. Embedded and bootloader power-fail testing, and how RAUC, SWUpdate and Mender test themselves

### Takeaway
MCUboot has the most rigorous open, automated methodology:
1. A Rust flash simulator counts all flash operations N in a clean upgrade.
2. It re-runs the upgrade interrupted after each operation i = 1..N, plus random multi-interruption runs.
3. After each run it reboots the bootloader and checks image contents and trailer flags.

The Linux A/B updaters rely mostly on bootloader boot-counting (U-Boot bootcount/altbootcmd, barebox bootchooser, systemd-boot tries, GRUB env scripts):
- RAUC's CI runs in QEMU but explicitly cannot test reboots.
- Mender documents a manual "pull the power" integration check.
- No public automated power-cut suite was found for SWUpdate or Mender.

The best public automated example on the Linux side is Apertis's LAVA-run `aum-power-cut` test.

### Cited Findings

**MCUboot simulator (`sim/`)**
- Described in the README as "a small simulator designed to exercise the mcuboot upgrade code, specifically testing untimely reset scenarios to make sure the code is robust". It is written in Rust and run with `cargo test` (feature flags such as `sig-rsa`); a single test runs with `cargo test -- basic_revert`. — [sim/README.rst](https://github.com/mcu-tools/mcuboot/blob/main/sim/README.rst)
- In `sim/src/image.rs`, an upgrade "without fails" first counts the flash operations, giving `total_count`. — [image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs)
  - `run_perm_with_fails()` loops `for i in 1 .. total_flash_ops`, logging "Try interruption at {i}", calling `try_upgrade(Some(i))`, booting again and verifying the image contents of both slots and the trailer (magic/flags).
  - Failures are reported as "{fails} out of {total} failed {pct}%".
  - `run_perm_with_random_fails(n)` injects several random interruptions.
  - `run_revert_with_fails()` interrupts at every step of a revert.
  - Other tests include `run_norevert`, `run_with_status_fails_with_reset`, `run_secondary_leftover_trailer`, `run_signfail_upgrade` and `run_hw_rollback_prot`. — [image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs)
- `sim/simflash` models erase-before-write NOR flash with a `write_safe` bitmap, configurable alignment and erased value, "bad regions" with a failure rate, and `verify_writes`. It raises a `SimulatedFail` error ("Write failed by chance"). — [simflash/src/lib.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/simflash/src/lib.rs)
- The simulator has caught real bugs. An interrupted *revert* caused an extra swap on the next boot. The fix (PR #485) added a `swap-type` trailer field and extended the test so that it also interrupts during the revert stage. — [PR #485](https://github.com/JuulLabs-OSS/mcuboot/pull/485); [commit](https://git.trustedfirmware.org/plugins/gitiles/mirror/mcuboot/+/a1c1204f65f4c6d55602a1da87dccffec7c57c92)
- Field reports show residual risk outside the simulator's model, for example a brick on power loss during "swap using move". — [Nordic DevZone](https://devzone.nordicsemi.com/f/nordic-q-a/96156/mcuboot-swap-using-move-will-brick-device-when-power-interrupted-during-move)

**U-Boot boot counting**
- Enabled by `CONFIG_BOOTCOUNT_LIMIT`, and disabled if `bootlimit` is undefined.
- `bootcount` increments on each reboot only while `upgrade_available` ≠ 0. When the count exceeds `bootlimit`, `altbootcmd` runs; if `altbootcmd` is undefined, U-Boot drops to the prompt.
- Userspace must reset `upgrade_available` and `bootcount` to 0 after a successful boot. — [U-Boot docs](https://docs.u-boot-project.org/en/latest/_sources/api/bootcount.rst.txt)
- CIP's SWUpdate demo could fail to boot after a power failure because U-Boot environment *redundancy* was not enabled. — [CIP issue #5](https://gitlab.com/cip-project/cip-sw-updates/cip-sw-updates-tasks/-/issues/5)

**barebox bootchooser**
- It boots the highest-priority target with remaining_attempts > 0, decrements on each start, and needs an explicit reset (`bootchooser -s` / `barebox-state`) to mark success. `disable_on_zero_attempts` is optional. — [barebox docs](https://www.barebox.org/doc/latest/_sources/user/bootchooser.rst.txt)
- A known RAUC integration pitfall is the state-prefix mismatch: it must be `bootstate`. — [barebox ML](https://lore.barebox.org/barebox/c55ef6c5-c7ea-0663-47b9-141773985ba2@pengutronix.de/)

**GRUB environment**
- `grub-editenv` and GRUB's `save_env` write grubenv in place, which can leave it invalid or empty on power loss. Write-temp-then-rename has been proposed. — [grub-devel 2021-02](https://lists.gnu.org/archive/html/grub-devel/2021-02/msg00052.html)
- 3mdeb describes `grubenv.new` + rename and a redundant double-copy scheme with checksums. — [3mdeb PDF](https://shop.3mdeb.com/wp-content/uploads/2021/06/Redundant-GRUB2-env-file.pdf)
- RAUC's GRUB integration needs a custom script, because GRUB has no built-in slot-selection logic. — [RAUC examples](https://rauc.readthedocs.io/en/latest/_sources/examples.rst.txt)
- A RAUC user reported env corruption that blocked updates, and noted that a power cut while writing env on FAT can corrupt the whole boot partition. — [RAUC ML](https://mail-archive.com/rauc@pengutronix.de/msg00221.html)

**systemd-boot / sysupdate**
- Boot counting is encoded in the entry file name as `+LEFT[-DONE]` ("tries left" / "tries done"), with the initial value from `/etc/kernel/tries`.
- `systemd-boot-check-no-failures.service` marks the entry good. — [systemd.io AUTOMATIC_BOOT_ASSESSMENT](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT)
- A secondary source says sysupdate writes to the inactive slot and updates GPT attributes with tries-left/priority. — [botmonster blog](https://botmonster.com/self-hosting/atomic-linux-updates-systemd-sysupdate/) (secondary; verify against systemd docs)

**RAUC's own testing**
- The full suite runs with `./qemu-test`. A test is selected with `test=` (a meson test name, such as `install` or `pytest-install`).
- The VM provides emulated block, NAND/MTD and eMMC devices without host root.
- The mock boot backend is GRUB, and **"Rebooting is not supported, so testing covers only a single boot cycle."** — [RAUC contributing](https://rauc.readthedocs.io/en/latest/contributing.html)
- GitHub Actions runs `./qemu-test` with and without service/GPT, plus `meson test` under QEMU user-mode for other architectures. — [RAUC CI workflow](https://github.com/rauc/rauc/actions/runs/9092465269/workflow)
- Pengutronix has a QEMU + Yocto evaluation tutorial (manual). — [Pengutronix blog](https://www.pengutronix.de/de/blog/2022-02-03-tutorial-evaluating-rauc-on-qemu-a-quick-setup-with-yocto.html)
- Rollback confirmation uses the `rauc-mark-good` service. — [meta-rauc-community discussion #164](https://github.com/rauc/meta-rauc-community/discussions/164)

**SWUpdate**
- SWUpdate sets `ustate=IN_PROGRESS` at update start. "A power cut during an update can be detected by checking that variable's value." `ustate` and `recovery_status` are not set atomically together. — [patch 2022](https://patchwork.ozlabs.org/project/swupdate/patch/20220407070931.310272-1-sbabic@denx.de/)
- The in-tree `test/` directory has cmocka-style unit tests (`test_parser.c`, `test_json.c`, `test_mender_artifact.c`, `test_installer.c`, `test_flash_handler.c`, …). No power-fail or fuzz harness is present. — [swupdate/test](https://github.com/sbabic/swupdate/tree/master/test) (directory listing checked 2026-10-31)

**Mender**
- The integration checklist (3.3) includes a manual test: reboot, pull power before the Mender client starts, restore power, and verify rollback. Mender must not have started, or it would auto-commit. — [Mender docs 3.3](https://docs.mender.io/3.3/client-installation/integration-checklist)
- `mender-qa` is described as "Repository to run and test Mender in QEMU". — [GitHub](https://github.com/mendersoftware/mender-qa)
- `mender-testkit` (PyPI) is shared integration-test infrastructure: a docker-compose backend, QEMU devices and pytest fixtures. — [PyPI](https://pypi.org/project/mender-testkit/)
- A community `mender-bootloader-validation.py` (Yocto recipe) covers A/B switch, update and rollback. — [Mender Hub](https://hub.mender.io/t/mender-validation-automatic-integration-checking/7218)
- A field report: a power cut during download on Mender 1.7 left the device on the wrong partition. — [Mender Hub](https://hub.mender.io/t/mender-1-7-standalone-power-failure-case-failing/462)

**Hardware-in-the-loop**
- labgrid power resources and drivers: NetworkPowerPort (gude, apc, tapo, tplink…), PDUDaemonPort, YKUSH, USBPowerPort (uhubctl), SiSPM, Tasmota (MQTT), LAAPowerPort, ManualPowerDriver, ExternalPowerDriver (`cmd_on`/`cmd_off`/`cmd_cycle`, `delay`), DigitalOutputPowerDriver (relay). — [labgrid configuration](https://labgrid.readthedocs.io/en/latest/configuration.html)
- labgrid's **QEMUDriver** implements `ConsoleProtocol` and `PowerProtocol` (args: `qemu_bin`, `machine`, `cpu`, `memory`, `kernel`, `disk`, `flash`, `bios`, `boot_args`, `extra_args`, `disk_opts`, `nic`, `display`). Strategies are ShellStrategy, UBootStrategy and BareboxStrategy. — [labgrid configuration](https://labgrid.readthedocs.io/en/latest/configuration.html)
- A labgrid example loop power-cycles a target repeatedly through a strategy until a condition fails. — [Debian labgrid example](https://sources.debian.org/src/labgrid/0.4.1-6/examples/library/test.py)
- Apertis (OSTree-based update manager) automated `aum-power-cut` in LAVA: start an update, cut power, and check that the update is not applied. — [aum-power-cut](https://lavaphabbridge.apertis.org/testcases/v2019/aum-power-cut.html); [manual variant](https://lavaphabbridge.apertis.org/testcases/v2020/apertis-update-manager-powercut.html)
  - A 2024 commit notes that on modern boards, delays over 3 s let the upgrade complete, so the test failed and the delay was capped. This shows how sensitive time-based crash points are. — [Apertis commit](https://gitlab.apertis.org/tests/apertis-test-cases/-/commit/2ee9764b2b404c1c53e74fffffeb81407d8e97eb); [aum-offline-upgrade MR 60](https://gitlab.apertis.org/tests/aum-offline-upgrade/-/merge_requests/60/commits)
- Apertis bootcount rollback tests use manual power cycles to exceed the bootcount. — [Apertis MR](https://gitlab.apertis.org/tests/apertis-test-cases/-/merge_requests/670/diffs)

### Inferences
- The MCUboot "count ops, then interrupt at every op" loop transfers directly to Linux updaters if "flash op" is replaced by a block-level write (dm-log-writes entry index) or a persistence-relevant syscall (strace count). Its oracle maps to a Linux A/B system as follows:
  - "primary slot = new image, secondary = old, trailer flags = expected" becomes "booted slot ∈ {old, new}, the slot's hash equals the expected image, and boot-selection state is consistent".
- The time-based cutting used by Apertis is fragile, as shown by the 3-second-delay fix. Event-based or operation-count-based triggers should be preferred.
- RAUC's in-tree QEMU tests cannot reboot. A benchmark that adds reboot-after-crash cycles therefore covers something the upstream CI does not.
- U-Boot env without redundancy and grubenv written in place are concrete, known-weak configurations. They make good **positive controls** (expected to fail) for validating the harness.

### Gaps
- No public, automated power-cut test suite was found inside the RAUC, SWUpdate or Mender repositories.
  - The `mender-integration` / `mender-testkit` test lists were not inspected for rollback or power tests.
  - Whether Pengutronix or Linutronix run internal labgrid power-cut farms for RAUC could not be confirmed.
- Zephyr-specific power-fail tests (for example twister + MCUboot on QEMU) were not checked.
- No public automated power-cut test was found for barebox bootchooser or for U-Boot's redundant env (`CONFIG_ENV_REDUNDANT` / libubootenv).

---

## Q4. Industry practice: eMMC/flash power-loss testing, Android A/B and Virtual A/B, Chrome OS, OSTree, systemd-sysupdate

### Takeaway
Public industry evidence is thin and mostly about design:
- Android Virtual A/B says snapshot merges are resumable after a reboot.
- update_engine fixed non-atomic checkpointing.
- Chrome OS autotest has `autoupdate_Interruptions` (reboot, suspend, network pull) and checks that the update resumes from its prior progress.
- OSTree claims atomic deployment through a symlink swap plus fsync.
- eMMC/flash power-loss qualification is done with proprietary SPOR (sudden power-off recovery) rigs. The JEDEC procedure itself is not public.

### Cited Findings
- **Android Virtual A/B**: "If the device is rebooted during the merge process, the merge process resumes after reboot". Updates are merged only after a successful boot, and a failed boot reverts automatically. The page does not describe power-loss testing. — [AOSP Virtual A/B](https://source.android.com/docs/core/ota/virtual_ab)
- **update_engine**: commit "Make checkpointing atomic". Interruption during checkpointing previously made resume impossible; new prefs are now written first and swapped in atomically. The test used was `update_device.py` with OTA resume. — [OmniROM mirror of AOSP update_engine](https://gerrit.omnirom.org/plugins/gitiles/android_system_update_engine/+/5eece04aafc34b4044738431f525e1aa350758bb%5E%21)
- **Android recovery (legacy non-A/B)**: before installing, recovery saves an incremented retry count in the BCB so that an update interrupted by power-off is detected and reapplied. — [recovery commit](https://gerrit.twrp.me/plugins/gitiles/android_bootable_recovery/+/99b73be3a8f3a97ff11f3e50a4169292a2f36fb1)
- **Chrome OS**:
  - `autoupdate_Interruptions` ("Tests using the chromebook during an update", suite `au-perbuild`) interrupts by reboot or suspend. It fails if the download already finished; otherwise it waits for a target progress, interrupts, and checks that the update resumed where it left off. — [control.full](https://android.googlesource.com/platform/external/autotest/+/eaa785b4d10f8d126f279d26d47245d7fdd2d640/server/site_tests/autoupdate_Interruptions/control.full)
  - An older variant also pulled the network for minutes. — [autotest commit](https://cos.googlesource.com/mirrors/cros/chromiumos/third_party/autotest/+/060fefb3fb59ecf3e480cd02e44c0abae29e1aa8%5E%21/)
  - `autoupdate_ForcedOOBEUpdate` reboots mid-update and checks progress continues. — [same search, autotest mirrors](https://android.googlesource.com/platform/external/autotest/+/7dbebb9dc6c5868b03fe2c032381f2a103c604de%5E1..7dbebb9dc6c5868b03fe2c032381f2a103c604de/)
- **OSTree**:
  - Toradex states upgrades are atomic through a symlink swap between deployments, with staging, fsync and hardlink farms. Its author's harsh "reset without sync" test found ext4 replayed the journal and `ostree fsck` came back clean. This is an anecdote, not a suite. — [Toradex blog](https://toradex.com/blog/is-torizon-ota-safe-for-power-loss)
  - A 2017 upstream thread says a leftover partial deployment is garbage-collected and rebuilt. — [ostree-list](https://mail.gnome.org/archives/ostree-list/2017-January/msg00000.html)
  - Apertis's LAVA `aum-power-cut` is the most concrete automated public example (see Q3).
- **eMMC/flash**:
  - HCC Embedded uses eMMC "reliable write" and custom test hardware with a verification suite. — [Power Systems Design](https://www.powersystemsdesign.com/hcc-demonstrates-secure-memory-power-tech-at-embedded-world-2015-psdtv/111)
  - A patent notes that random power cuts ignore the device's internal state, and proposes cutting power during write or garbage-collection operations. — [US10008288B2](https://patents.google.com/patent/US10008288)
  - Vendor datasheets only claim the device "would work properly after power cycling". — [Longsys/FORESEE eMMC spec](https://files.pine64.org/doc/datasheet/pine64/E-00517%20FORESEE_eMMC_NCEMAM8B-16G%20SPEC.pdf)
- **NASA software engineering handbook**: lists "power interruptions during an update" as a scenario to simulate and recommends hardware-in-the-loop testing. — [NASA SWEHB R095](https://swehb.nasa.gov/display/SITE/R095+-+Incomplete+testing+of+the+software+update+capabilities)
- **Practitioner guides**:
  - Cut power at controlled transfer percentages with a programmable relay or MOSFET, then capture serial logs and partition dumps. — [DEV/beefed.ai](https://dev.to/beefedai/fail-safe-firmware-update-dfu-strategies-and-testing-103f)
  - Rollback paths are often never validated through fault-recovery testing. — [Applied Logix](https://appliedlogix.rebuildmanufacturing.com/blogs/are-your-bootloaders-ready-for-real-world-ota-failures)
  - Memfault has an OTA testing guide. — [Memfault](https://memfault.com/blog/ota-testing-101-the-ultimate-guide/) (not fetched)

### Inferences
- "Resume from same progress after interruption" (Chrome OS) and "merge resumes after reboot" (Android VAB) are **liveness** properties. The benchmark oracle should check liveness alongside **safety** (bootable, atomic): after a crash, re-running the updater must eventually complete.
- Industry runs most eMMC/flash power-loss validation on real hardware with programmable power. In QEMU, emulated flash and eMMC do not model FTL power-loss failures (shorn writes, metadata corruption as in FAST'13). The thesis should state this as a threat to validity and treat "ideal disk" (prefix/flush semantics) as the fault model, in line with the "clean termination" model of Torturing Databases.

### Gaps
- JEDEC JESD84 (eMMC) power-fail and reliable-write text, and any JEDEC power-loss test procedure, are not publicly available. None was found.
- No public description was found of how Google validates Virtual A/B merge crash safety (for example VTS or CTS tests that cut power during snapuserd merge).
- No upstream test was found for systemd-sysupdate or OSTree that interrupts a deployment at controlled points.

---

## Q5. Metrics used to quantify crash resilience

### Takeaway
The literature reports mostly count-based metrics:
- bugs found, or known bugs reproduced
- vulnerabilities per application, classified by consequence
- failing devices per number of power cycles
- the MCUboot ratio "failed interruption points / total flash operations (%)"

Coverage-style metrics (crash states explored, workloads per bound) appear in CrashMonkey/ACE. "Bricking rate" appears in practitioner and SSD-study language, not as a formal metric. No standard metric suite for OTA crash resilience was found, so the thesis must define one.

### Cited Findings
- MCUboot: per-test fraction of failing interruption points, printed as "X out of N failed Y%", with N = total flash operations in a clean upgrade. — [image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs)
- CrashMonkey/ACE: known bugs reproduced (24/26), new bugs (10), kernels and file systems covered, and workload bounds (sequence length ≤ 3). — [arXiv](https://arxiv.org/abs/1810.02904)
- ALICE: vulnerabilities per application (60 static, 156 dynamic), split by consequence: silent corruption, durability loss, inaccessibility, error on access. — [USENIX](https://www.usenix.org/node/186195); [Colyer](https://blog.acolyer.org/2016/02/11/fs-not-equal/)
- Torturing Databases: databases that violate each ACID property (7 of 8). — [PDF](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)
- SSD study: devices failing out of 15, failure-type taxonomy (bit corruption, shorn writes, unserializable writes, metadata corruption, dead device), number of power-cycle tests (>3,000). — [USENIX](https://www.usenix.org/conference/fast13/understanding-robustness-ssds-under-power-fault)
- LazyFS: bugs reproduced, ambiguous bugs clarified, new bugs, and consequence classes (data loss, corruption, unavailability). — [PDF](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- Mumak: bug coverage compared with other tools, plus speed-up (up to 25×). — [PDF](https://www.dpss.inesc-id.pt/~rodrigo/joao-mumak-eurosys23.pdf)
- Chrome OS: binary resume-from-same-progress check. Apertis: binary "update not applied after power cut" check. — [autotest](https://android.googlesource.com/platform/external/autotest/+/eaa785b4d10f8d126f279d26d47245d7fdd2d640/server/site_tests/autoupdate_Interruptions/control.full); [Apertis](https://lavaphabbridge.apertis.org/testcases/v2019/aum-power-cut.html)

### Inferences
Proposed OTA-specific metric set (all derived; see Q8):
- **Brick rate** = crash points after which the device does not reach a healthy userspace within K boots and T seconds, divided by crash points tested.
- **Atomicity-violation rate** = crash points after which the booted rootfs is neither the exact old nor the exact new image (hash mismatch), or the bootloader env is unparsable.
- **Rollback correctness** = fraction of "new slot unhealthy" scenarios that revert to the old slot within `bootlimit` or tries.
- **Liveness / retry success** = fraction of crash points after which re-running the updater completes the update.
- **Time to recovery** = boots and seconds from power-on to the healthy marker.
- **Crash-state coverage** = distinct post-crash block images (by hash) and the fraction of persistence points (fsync/flush/FUA/rename) at which a crash was injected.
- **Unique bugs** = distinct root causes.
- Report rates with Wilson 95% confidence intervals. Stratify by crash-point class: download phase, slot write, env/state write, reboot/commit phase, rollback phase.

### Gaps
- No paper was found that formally defines a "bricking rate" or a standard crash-resilience metric for update systems.

---

## Q6. Fuzzing update-metadata and manifest parsers: OSS-Fuzz coverage, in-repo harnesses, structure-aware and differential fuzzing

### Takeaway
Among the target OTA projects, only **RAUC** is integrated into OSS-Fuzz. Since a 2023 build script it has `manifest` and `bundle` fuzzers with a dictionary and seed corpora. SWUpdate, Mender, go-tuf, python-tuf, tough, tuf-js, QCBOR, t_cose, libcsuit, MCUboot and Uptane/aktualizr are **not** OSS-Fuzz projects, and none showed a dedicated fuzz directory at top level.

Several *dependencies* are OSS-Fuzzed: libconfig (SWUpdate's sw-description format), libcbor, cbor2, json-c, cJSON, jansson, rapidjson, simdjson, serde_json, nlohmann json, glib, openssl, u-boot, systemd, ostree, and sigstore / sigstore-go / sigstore-java.

That leaves room for a benchmark contribution: harnesses for TUF metadata, SUIT envelopes and Mender artifacts, plus differential fuzzing of the four TUF canonical-JSON implementations and of CBOR deterministic decoders.

### Cited Findings

**OSS-Fuzz project presence**
- Checked 2026-10-31 by HTTP status of `https://raw.githubusercontent.com/google/oss-fuzz/master/projects/<name>/project.yaml`, under the OSS-Fuzz projects tree [google/oss-fuzz/projects](https://github.com/google/oss-fuzz/tree/master/projects).
- **Present (200):** rauc, libcbor, cbor2, libconfig, json-c, cjson, jansson, json, rapidjson, simdjson, serde_json, sigstore, sigstore-go, sigstore-java, u-boot, systemd, ostree, glib, openssl.
- **Absent (404):** qcbor, t_cose, tinycbor, go-tuf, python-tuf, tuf, tough, swupdate, mender, mender-artifact, mcuboot, zephyr, grub, grub2, go-cose, libcsuit, uptane, aktualizr, securesystemslib, in-toto, canonicaljson, go-json, notation-go, nlohmann-json.
- Caveat: a project could exist under a different directory name. "json" is presumably nlohmann/json (UNVERIFIED mapping).

**RAUC fuzzing**
- OSS-Fuzz `project.yaml`: main_repo github.com/rauc/rauc, primary contact jlu@pengutronix.de. — [project](https://github.com/google/oss-fuzz/tree/master/projects/rauc)
- `build.sh` (© 2023) builds with `meson -Dfuzzing=true` and network, streaming, json, gpt and service disabled. It copies `$BUILD/fuzz/*` executables, `*.dict` files and seed corpora. — [build.sh](https://raw.githubusercontent.com/google/oss-fuzz/master/projects/rauc/build.sh)
- The RAUC repo's `fuzz/` contains `manifest.c`, `bundle.c`, `manifest_fuzzer.dict`, `manifest_fuzzer.corpus`, `bundle_fuzzer.corpus`, `localfuzzer.c`, `fuzz.h` and `meson.build`. — [rauc/fuzz](https://github.com/rauc/rauc/tree/master/fuzz)

**SWUpdate**
- The default sw-description parser is libconfig, with an alternative JSON parser. — [SWUpdate sw-description docs](https://sbabic.github.io/swupdate/sw-description.html)
- The repo has unit tests `test/test_parser.c`, `test_json.c` and `test_mender_artifact.c`, but no fuzz harness was found. — [swupdate/test](https://github.com/sbabic/swupdate/tree/master/test)
- libconfig itself is OSS-Fuzzed (see above).

**TUF clients**
- `go-tuf/metadata/metadata_test.go` contains no `func Fuzz` (checked by grep). — [go-tuf](https://github.com/theupdateframework/go-tuf)
- The python-tuf `tests/` folder has unit and simulator tests, including `repository_simulator.py` and `test_updater_*.py`, but no fuzz/Atheris tests. — [python-tuf/tests](https://github.com/theupdateframework/python-tuf/tree/develop/tests) (branch name UNVERIFIED)
- tough's workspace (`tough`, `tuftool`, `olpc-cjson`, `tough-kms`, `tough-ssm`, `integ`) has no `fuzz/` crate. — [tough](https://github.com/awslabs/tough)
- tuf-js packages are `canonical-json`, `cli`, `client`, `models` and `repo-mock`. — [tuf-js](https://github.com/theupdateframework/tuf-js)
- Absence of fuzzing is shown only at directory level. In-file Go fuzz functions in other `_test.go` files were not exhaustively searched (UNVERIFIED).

**tuf-conformance**
- A specification-conformance suite for TUF clients. A client provides an executable implementing the "client-under-test CLI protocol" (CLIENT-CLI.md) and runs it through the GitHub Action `theupdateframework/tuf-conformance@v2`, with an `.xfails` file for unsupported tests.
- Bundled clients are python-tuf and go-tuf. — [tuf-conformance](https://github.com/theupdateframework/tuf-conformance)

**SUIT and CBOR**
- libcsuit vendors QCBOR and t_cose and ships `testfiles/` and a `test/` dir, but no fuzz dir. QCBOR and t_cose have `test/` dirs and no fuzz dirs. — [libcsuit](https://github.com/yuichitk/libcsuit); [QCBOR](https://github.com/laurencelundblade/QCBOR); [t_cose](https://github.com/laurencelundblade/t_cose)
- TrustedFirmware task T316 aims to test t_cose against COSE-C, a cross-implementation (differential) check. — [TF T316](https://developer.trustedfirmware.org/T316)
- Microsoft CCF added a libFuzzer harness for CBOR parse, serialize and to_string round-trips, seeded with COSE_Sign1 and receipt shapes and int64 edge cases (PR dated 2026-04-28). — [CCF PR #7839](https://github.com/microsoft/CCF/pull/7839)
- fxamacker/cbor (Go) does coverage-guided fuzzing and supports Core Deterministic Encoding. — [cbor-fuzz](https://github.com/fxamacker/cbor-fuzz)
- A cross-language canonical CBOR / dCBOR conformance harness exists (Rust, Kotlin, TS adapters, byte-for-byte agreement, strict rejection of non-canonical input). — [GitHub topic deterministic-encoding](https://github.com/topics/deterministic-encoding)
- Android's libcppbor fuzzer feeds the same input to several parser APIs. — [AOSP commit](https://android.googlesource.com/platform/tools/security/+/c55b07c)

**JSON parser differentials**
- Nicolas Seriot, "Parsing JSON is a Minefield" (2016, updated later): more than 30 parsers tested, and no two accepted and rejected the same set of documents. — [seriot.ch](https://seriot.ch/projects/parsing_json.html); [The Register](https://www.theregister.co.uk/2016/11/01/json_parsers_tested/)
- JSONTestSuite has more than 300 files named by expected result: `y_` must accept, `n_` must reject, `i_` implementation-defined. Some cases (for example NaN) were later reclassified to `i_`. — [seriot.ch](https://seriot.ch/projects/parsing_json.html); [JSONTestSuite fork](https://github.com/jbee/JSONTestSuite) (canonical upstream is github.com/nst/JSONTestSuite; UNVERIFIED URL)

**Structure-aware fuzzing tools (URLs not fetched; UNVERIFIED but standard)**
- libprotobuf-mutator: https://github.com/google/libprotobuf-mutator
- Atheris (Python): https://github.com/google/atheris
- Go native fuzzing: https://go.dev/doc/security/fuzz
- cargo-fuzz: https://github.com/rust-fuzz/cargo-fuzz
- Jazzer.js: https://github.com/CodeIntelligenceTesting/jazzer.js

**Known parser-differential vulnerability classes (UNVERIFIED pointers)**
- Bishop Fox, "An Exploration of JSON Interoperability Vulnerabilities" (2021: duplicate keys, number precision, comment and truncation handling): https://bishopfox.com/blog/json-interoperability-vulnerabilities
- Android "Master Key" APK/ZIP parser differential (2013) as the classic update-signature-bypass-by-differential example.

**TUF threat model (spec v1.0.37, last modified 2026-10-08)**
- §1.5.2 lists endless-data, rollback and indefinite-freeze attacks.
- The page as fetched does not contain the phrase "slow retrieval attacks". Earlier spec versions did list it (UNVERIFIED when it was removed).
- Download caps: root N+1 up to W bytes, timestamp up to X bytes, snapshot up to the length in timestamp or Y, targets up to the length in snapshot or Z, target files up to the length in targets metadata. — [TUF spec](https://theupdateframework.github.io/specification/latest/)

### Inferences
Concrete fuzz targets for the benchmark, in priority order:
1. **Reuse** RAUC's OSS-Fuzz `manifest` and `bundle` fuzzers as a calibrated baseline. Coverage and crash counts can be compared with ClusterFuzz history.
2. **SWUpdate**: a libFuzzer harness around the sw-description parser entry (`parser/parser.c`, both the libconfig and JSON paths). Use the existing `test/data` as seeds, built with ASan/UBSan, and a dictionary of sw-description tags.
3. **Mender artifact**: Go native fuzz on the `mender-artifact/areader` reader (tar-in-tar plus header JSON plus manifest). SWUpdate's own Mender-artifact parser (`test_mender_artifact.c` exists) is a second implementation, which allows **differential** fuzzing of two Mender-artifact parsers.
4. **TUF metadata**:
   - go-tuf `metadata.Root/Targets/...FromBytes` (Go fuzz)
   - python-tuf `Metadata.from_bytes` (Atheris)
   - tough `schema` deserialization (cargo-fuzz)
   - tuf-js `models` (Jazzer.js)
   - Differential oracle: accept/reject agreement and, for accepted inputs, equality of re-serialized canonical JSON across implementations (tough `olpc-cjson`, tuf-js `canonical-json`, python securesystemslib, go-securesystemslib `cjson`; the last two UNVERIFIED as exact module locations).
   - Disagreements on duplicate keys, big integers, Unicode escapes or non-canonical whitespace in *signed* portions are security-relevant: a signature computed over one interpretation could be verified against another.
5. **SUIT**: a libFuzzer harness for libcsuit's envelope decode (QCBOR plus t_cose COSE_Sign1 verification), seeded from `testfiles/` and the SUIT draft examples. Add differential deterministic-CBOR acceptance across QCBOR, libcbor, cbor2 and fxamacker/cbor.
6. **Structure-aware generation**: JSON grammar via libprotobuf-mutator, or a TUF-schema-aware generator that produces valid-but-edge-case metadata (expired, version jumps, threshold edge, delegation cycles). This complements tuf-conformance, which tests semantic conformance rather than robustness.
- Fuzzing metrics: edge coverage over time, unique crashes (deduplicated by stack), time to first crash, executions per second, and differential disagreement count by class.

### Gaps
- No ClusterFuzz bug statistics for RAUC's fuzzers were retrieved, because the OSS-Fuzz issue tracker was not queried.
- No published parser-differential CVEs specific to TUF canonical JSON or SUIT/CBOR were found in this session.
- Whether Uptane implementations (aktualizr, ota-tuf) ever had fuzzing was not checked beyond the OSS-Fuzz absence.

---

## Q7. Network-level fault and attack emulation for slow-retrieval, endless-data and interrupted-download tests

### Takeaway
**Toxiproxy** is the most precise tool for per-connection, scriptable TCP faults: bandwidth caps, slicing with delays, hard byte limits, resets and timeouts. **tc netem** (directly or through **Pumba** for containers) covers packet-level delay, loss, corruption and rate. Endless-data and "malicious server" scenarios need a custom HTTP repository server rather than a proxy, for example a repository simulator or a mitmproxy script that rewrites responses. TUF's spec-mandated byte caps (W/X/Y/Z) are the oracle for endless-data tests.

### Cited Findings
- **Toxiproxy** toxics (each with `stream` upstream or downstream and a `toxicity` probability): — [Shopify/toxiproxy](https://github.com/Shopify/toxiproxy)
  - `latency` (latency, jitter)
  - `bandwidth` (rate in KB/s)
  - `slow_close`
  - `timeout` (0 = black-hole)
  - `reset_peer`
  - `slicer` (average_size, size_variation, delay in µs)
  - `limit_data` (close after N bytes)
  - `packet_loss`
  - `down` (disable proxy)
- **Pumba**: chaos testing for Docker, containerd and Podman. `pumba netem` supports delay, loss (with probability and correlation), duplicate, corrupt and rate, and runs tc in a helper container sharing the target's network namespace (`--tc-image`). Example: `pumba netem --duration 5m delay --time 3000 mydb`. — [Pumba README](https://github.com/alexei-led/pumba/blob/master/README.md)
- **tc-netem** man page: https://man7.org/linux/man-pages/man8/tc-netem.8.html (not fetched; UNVERIFIED for option details)
- **comcast**: https://github.com/tylertreat/comcast (not fetched; UNVERIFIED)
- **mitmproxy**: https://docs.mitmproxy.org/ (not fetched; UNVERIFIED)
- **TUF download caps** (endless-data defense) and threat list: see Q6. — [TUF spec](https://theupdateframework.github.io/specification/latest/)
- **python-tuf** ships `tests/repository_simulator.py`, an in-memory repository used by its updater tests. It is a natural base for injecting oversized or slow responses. — [python-tuf tests](https://github.com/theupdateframework/python-tuf/tree/develop/tests)
- **Chrome OS** autotest interrupts updates by pulling the network for minutes and expects resumption. — [autotest commit](https://cos.googlesource.com/mirrors/cros/chromiumos/third_party/autotest/+/060fefb3fb59ecf3e480cd02e44c0abae29e1aa8%5E%21/)

### Inferences
Mapping of test scenarios to tools:
- **Slow retrieval** → toxiproxy `bandwidth` (rate=1 KB/s) or `slicer` with large `delay`. Oracle: the client enforces a timeout or minimum-throughput policy, or reports failure. It must not hang forever or install partial data.
- **Endless data** → custom server returning an infinite or oversized body for timestamp.json or root.json, or a mitmproxy response rewrite. Oracle: the download is aborted at ≤ W/X/Y/Z bytes and memory is bounded.
- **Interrupted download / resume** → toxiproxy `limit_data` N bytes, or `reset_peer`, swept over N. Oracle: no partial target is accepted (hash and length check), and resume or retry eventually succeeds. For Mender, RAUC and SWUpdate streaming installs, the slot is left in a state the bootloader will not select.
- **Combined network + power loss** → cut the connection with `limit_data` at byte N, then cut power at level 3 within the same run. This tests a streaming-install updater (RAUC streaming, SWUpdate streaming, Mender) at the worst point.

### Gaps
- Whether the TUF spec's removal of "slow retrieval" from the threat list was deliberate, and in which version, was not verified. Check the spec changelog or git history before relying on it.

---

## Q8. Recommended design: a three-level power-loss experiment feasible for one master's student (Linux + QEMU)

### Takeaway
Run one shared methodology at three fidelity levels:
1. Golden run to record the operation trace and count N.
2. Crash at selected points from that trace.
3. Recover by restart or reboot.
4. Check a fixed set of invariants.

The levels differ only in the unit of "operation":
- **L1, process:** persistence-relevant syscalls via strace `--inject`, with LazyFS optionally under the state directory.
- **L2, block:** dm-log-writes entries and flush/FUA marks, replayed with replay-log.
- **L3, full system:** QEMU kill or reset at phase markers, on qcow2 overlays, booting through the real bootloader logic.

This mirrors the MCUboot simulator loop and CrashMonkey's persistence-point focus, and it gives comparable metrics across RAUC, SWUpdate, Mender and the TUF/Uptane/SUIT clients.

### Cited Findings (building blocks)
- **Exhaustive "interrupt at every op i of N" loop with post-reboot verification** of images and boot-state flags, plus random multi-fault runs. — [MCUboot image.rs](https://github.com/mcu-tools/mcuboot/blob/main/sim/src/image.rs)
- **Crash after persistence points, small bounded workloads, black-box oracle.** — [CrashMonkey/ACE](https://arxiv.org/abs/1810.02904)
- **Block-level record and replay to marks or each FUA, with a check command per prefix.** — [dm-log-writes docs](https://docs.kernel.org/admin-guide/device-mapper/log-writes.html); [xfstests generic/482](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/plain/tests/generic/482)
- **"Clean termination of the I/O stream" as the baseline fault model.** — [Torturing Databases](https://www.ece.iastate.edu/%7Emai/docs/papers/2014_OSDI_DB.pdf)
- **Lost and torn unsynced writes at the file level** (with the limitation that metadata durability is not modeled). — [LazyFS](https://www.vldb.org/pvldb/vol17/p3017-ramos.pdf)
- **Deterministic syscall-level SIGKILL and error injection.** — [strace man](https://man7.org/linux/man-pages/man1/strace.1.html)
- **QEMU as a labgrid target with PowerProtocol**, and QMP quit / system_reset with the RESET-event wait. — [labgrid](https://labgrid.readthedocs.io/en/latest/configuration.html); [QMP](https://github.com/qemu/qemu/blob/85f96549100a7239ceae15c9a5b0ba8cdd95bdaa/docs/qmp-commands.txt); [qtest patch](https://patchew.org/QEMU/20241212150949.16806-1-farosas@suse.de/20241212150949.16806-3-farosas@suse.de)
- **Boot-selection mechanisms to check after reboot:** U-Boot bootcount/altbootcmd, barebox bootchooser, systemd-boot tries. — [U-Boot](https://docs.u-boot-project.org/en/latest/_sources/api/bootcount.rst.txt); [barebox](https://www.barebox.org/doc/latest/_sources/user/bootchooser.rst.txt); [systemd](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT)
- **Known weak configurations, usable as positive controls:** non-redundant U-Boot env, grubenv written in place. — [CIP issue](https://gitlab.com/cip-project/cip-sw-updates/cip-sw-updates-tasks/-/issues/5); [grub-devel](https://lists.gnu.org/archive/html/grub-devel/2021-02/msg00052.html)
- **Time-based cut points are fragile** (the Apertis 3-second delay issue), so prefer event-based triggers. — [Apertis commit](https://gitlab.apertis.org/tests/apertis-test-cases/-/commit/2ee9764b2b404c1c53e74fffffeb81407d8e97eb)

### Inferences: the concrete design

**Systems under test (SUT) and images**
- Build three Yocto images for `qemux86-64` (or `qemuarm64`): meta-rauc-community, meta-mender (Mender ships qemux86-64 support) and meta-swupdate. Each uses a dual rootfs (A/B) plus a data partition.
- Use at least two boot-selection backends: U-Boot with bootcount and GRUB or barebox, and optionally systemd-boot with sysupdate as a fourth "reference" updater.
- Run the TUF/Uptane/SUIT clients (python-tuf, go-tuf, tuf-js, tough, libcsuit) as ordinary processes; they only need L1 and L2.
- Keep each base image read-only. Per run, `qemu-img create -f qcow2 -b base.raw -F raw run-<id>.qcow2` and delete it afterwards, so reset is O(1). Use `-snapshot` for throwaway runs. (QEMU doc wording UNVERIFIED.)

**Level 1: process-level (fast, thousands of runs per hour)**
- *Instrumentation:* a golden run under `strace -f -tt -e trace=openat,write,pwrite64,writev,fsync,fdatasync,sync_file_range,rename,renameat2,unlinkat,ftruncate,ioctl,mount,umount2 -o golden.trace <updater install cmd>`. This gives a per-syscall-class count N_c, the analogue of MCUboot's `total_flash_ops`.
- *Crash points:*
  - (a) **Exhaustive** over all fsync, fdatasync, rename and renameat2 occurrences, both *before* the call (`--inject=<sc>:error=EIO:signal=SIGKILL:when=k`) and *after* it (SIGKILL on the next syscall).
  - (b) **Stratified sample** of k ≈ 20–50 `write`/`pwrite64` indices per phase.
  - (c) **Double faults**: crash at i during install, then crash at j during the recovery or resume run, following MCUboot's interrupted-revert bug class.
- *Optional page-cache loss:* mount the updater's state directory on **LazyFS**:
  - `/var/lib/rauc`, `/data/mender`, the SWUpdate state and env files, the TUF client metadata dir and the target cache.
  - After the kill, send `clear-cache` (or use LazyFS's crash-at-op config) so unsynced writes vanish.
  - For large writes, add `torn-op` variants.
  - Because LazyFS does not model metadata (rename) durability, rename-durability questions are deferred to L2.
- *Oracle after restart:*
  - The updater starts without fatal error.
  - State files parse.
  - TUF clients: trusted root, timestamp, snapshot and targets load, and versions never go below the pre-crash trusted versions (rollback protection persists).
  - No target is reported installed unless its hash and length match.
  - Re-running the update completes (liveness).
- *Applicability:* RAUC (`rauc install` in a container with loop-device slots), SWUpdate (`swupdate -i` with loop-device handlers), Mender (`mender-update install` standalone), and all TUF/SUIT clients.

**Level 2: block-write level (medium speed, highest crash-state fidelity)**
- *Setup:* build the device layout on host loop devices (or inside the QEMU guest): `bootenv` (U-Boot env copy 1 and 2, or the grubenv file system), `rootfsA`, `rootfsB`, `data`. Wrap each, or one whole-disk device, in `dm-log-writes` with a separate log device.
- *Phase marks:* insert them from updater hooks with `dmsetup message log 0 mark <phase>`:
  - RAUC: pre-install / post-install handlers and slot hooks.
  - SWUpdate: pre/post-install scripts.
  - Mender: state scripts such as `ArtifactInstall_Enter/Leave` and `ArtifactReboot_Enter`.
- *Crash-state generation:*
  - (a) Replay **every prefix ending at a flush or FUA** (`replay-log … --check flush|fua`, or xfstests `_log_writes_find_next_fua`).
  - (b) For each flush epoch, replay the prefix plus **random subsets or permutations of the writes since the last flush**. This is the BOB/CrashMonkey reorder model; dm-log-writes already logs writes in on-disk order relative to flushes.
  - (c) **Every prefix** inside the small env/state partitions, which are cheap to cover exhaustively.
  - (d) Optional **torn-sector** variants: write only the first 512 B of a 4 KiB write to the env partition.
- *Deduplication:* hash each replayed image, and test only unique crash states. Report the count as "unique crash states explored".
- *Oracle per crash state:*
  - `fsck -n` on file-system partitions.
  - Parse the boot env (`fw_printenv` with libubootenv for redundant U-Boot env, `grub-editenv list`, `barebox-state` dump) and compute *which slot the bootloader will choose*, using a small Python model of each bootloader's documented algorithm (bootcount/bootlimit/altbootcmd, bootchooser priority/attempts, systemd-boot tries).
  - The chosen slot's content hash must equal the old or the new image exactly.
  - Send a sample of the states, plus all "suspicious" ones, to L3 for a real boot.
- *Positive controls:* (i) U-Boot env without redundancy, (ii) grubenv updated in place without rename, (iii) the updater run under eatmydata. The harness must report failures for these. If it does not, the crash-state generator is too weak.

**Level 3: full-system QEMU (slow, end-to-end ground truth)**
- *Harness:* labgrid with QEMUDriver (PowerProtocol on/off) plus UBootStrategy, BareboxStrategy or ShellStrategy, or plain Python using the QMP socket. Use the serial console for phase markers: updater logs and hook scripts that `echo PHASE:<x> > /dev/console`.
- *Power-cut mechanisms:*
  - **Hard power cut**: `kill -9 <qemu-pid>` or QMP `quit`. This loses guest RAM, but writes already issued to the image persist.
  - **Hard reset**: QMP `system_reset`, then wait for the RESET event.
  - **Loss of the disk's volatile cache**: run L3 on a host dm-log-writes device (`-drive file=/dev/mapper/lw,format=raw,cache=none`), then post-process with L2 replay for the epoch at which the VM was killed.
- *Crash-point selection:* event-based, not time-based.
  - (a) At each phase marker plus a random delay drawn uniformly over that phase's duration measured in the golden run.
  - (b) A fixed count per phase, for example 30 per phase × 5 phases (download, slot write, env/state commit, reboot-into-new, mark-good/commit) × 3 updaters × 2 bootloaders ≈ 900 runs.
  - (c) Plus the crash points that L1 and L2 flagged.
- *Post-crash protocol:* power on, then let the system boot up to K = bootlimit + 2 times without intervention. Record:
  - the booted slot
  - `rauc status --output-format=json`, `mender-update show-artifact`, or the SWUpdate `ustate`/`recovery_status` env
  - bootloader variables
  - time to the healthy marker (systemd `multi-user.target` reached plus the updater's mark-good)
  Then re-run the update to test liveness.
- *Invariants (oracle):*
  1. **No brick**: a healthy marker within K boots and T seconds.
  2. **Atomicity**: the booted rootfs hash ∈ {H_old, H_new}, with no mixed or corrupted slot booted.
  3. **Boot-state consistency**: env parseable, and the updater's view of the active/primary slot equals the bootloader's.
  4. **Correct rollback**: if the new slot cannot become healthy, the system returns to the old slot within the documented attempts.
  5. **No silent commit**: the system never reports "update successful" while running the old slot, and never marks the new slot good before the health check (the auto-commit hazard warned about in Mender's checklist).
  6. **Liveness**: a re-run of the update succeeds.
  7. **Security state** (TUF/Uptane clients on the device): trusted metadata versions are monotonic across the crash.

**Metrics (all levels; see Q5)**
- Brick rate, atomicity-violation rate, rollback correctness, liveness success, time-to-recovery (median/p95 boots and seconds), unique crash states explored, persistence-point coverage, and unique root-cause bugs.
- Report each with Wilson 95% CIs, stratified by phase and by level.
- Cross-level agreement: the fraction of L2-predicted failures confirmed by L3 boots measures the validity of the cheaper levels.

**Feasibility estimates (inference; calibrate in pilot)**
- L1: about 1–5 s per run → about 10⁴ runs per day per core.
- L2: replay plus check about 1–10 s per state.
- L3: about 20–90 s per crash-boot cycle on KVM → about 1–4 ×10³ runs per day on a 4–8-core workstation.
- Everything runs in CI-like scripts (pytest + labgrid). No physical hardware is needed. An optional appendix could validate a handful of L3 findings on a real board with a USB relay through labgrid's `DigitalOutputPowerDriver` or `USBPowerDriver`.

**Threats to validity to state explicitly**
- QEMU and loop devices do not model FTL power-loss pathologies (shorn writes, metadata corruption, dead devices; FAST'13). The fault model is "ideal disk with volatile cache".
- LazyFS ignores metadata durability.
- Bootloader-logic models in L2 must be validated against L3 boots.
- Time-based triggers are sensitive to host speed (the Apertis precedent), which is why event and operation-count triggers are used.

### Gaps
- How long each SUT's install takes in QEMU, and therefore the real run budget, must be measured in a pilot.
- Whether RAUC, SWUpdate and Mender hooks fire at fine enough granularity for useful L2 marks must be checked per updater. Otherwise use dm-log-writes entry numbers (`_log_writes_mark_to_entry_number`) as the crash-point index.
- Whether to model eMMC-specific behavior (boot partitions, reliable write, `mmc-utils`) in QEMU's emulated eMMC was not researched.
