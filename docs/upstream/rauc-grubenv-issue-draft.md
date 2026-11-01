# Draft issue for rauc/rauc

> **Status: draft, not posted.** Post only after the author has reviewed it and, ideally,
> after reproducing on current RAUC (1.15+) and on a UEFI boot with grubenv on the ESP.
> Checked 2026-11-01: no existing RAUC issue on grubenv power-loss robustness
> (search "grubenv OR grub-editenv OR grub env"); master `src/bootloaders/grub.c` still
> writes via `grub-editenv <path> set ...`; the GRUB integration docs suggest the EFI
> partition for grubenv and do not discuss power loss.

---

**Title:** GRUB backend: power loss shortly after an install can (a) silently revert the slot switch on ext4, (b) leave an empty grubenv on vfat/ext2 that blocks all further installs

**Body:**

We test A/B updaters with power cuts in QEMU. Every guest write is logged
(`blklogwrites`), then the disk is rebuilt at crash points and booted. Setup: RAUC 1.8
(Debian 12), GRUB 2.06, BIOS boot, grubenv on a separate partition, our `grub.cfg`
following the documented `ORDER`/`<slot>_OK`/`<slot>_TRY` scheme. We see two effects of
`grub-editenv` truncating and rewriting the file.

1. **ext4 holds grubenv: a window of ~5 s after `rauc install` succeeds.** A power cut in
   this window makes GRUB boot the *old* slot, while Linux, after journal replay, reports
   the new slot as primary. The window does not depend on `commit=` and shrinks to ≤1 s
   with `vm.dirty_writeback_centisecs=100`. Our explanation: the rewritten file gets a new
   block, and GRUB reads the stale on-disk inode because it does not replay the journal.
   No brick, but bootloader and OS disagree and the update is silently not applied.
2. **vfat or ext2 holds grubenv (no journal): an empty file.** If the disk cache loses or
   reorders unflushed writes during the rewrite, grubenv can end up 0 bytes. The device
   still boots (GRUB falls back to defaults or reads the old block), but
   `rauc status` cannot determine the primary, and every `rauc install` fails immediately:
   `Failed marking slot rootfs.1 non-bootable: grub backend: Failed to run grub-editenv`.
   The device has dropped out of OTA until someone repairs the environment.

A custom backend (`bootloader=custom`) with the same variables, which rewrites the
1024-byte block **in place** (no `O_TRUNC`, `pwrite` + `fsync`, as GRUB's own `save_env`
does), removed both effects in all our crash states on ext4, ext2 and vfat. A
temp-file-plus-rename scheme would not help on ext4, because the rename again changes
metadata that GRUB cannot see without journal replay.

Questions / suggestions:
* Would an in-place write mode for the GRUB backend be acceptable (opt-in, e.g.
  `grubenv-write=inplace`)? It keeps `grub-editenv` compatibility for reading.
* At minimum, a note in the GRUB integration docs: where grubenv lives (journaling or not),
  and the fact that a power cut right after an install can revert the switch or empty the
  file. For environments larger than one sector, a redundant two-copy environment with a
  checksum could also be mentioned.

Reproduction scripts and data: (link to the otabench repository once public).

---

## Notes for the author (not part of the issue)
* Evidence: `docs/pilot-ab.md`, sections «Механизм окна», «Модель перестановок», «Исправление».
* Before posting: (1) repeat with current RAUC; (2) repeat with UEFI GRUB and grubenv on
  the real ESP; (3) Linux/KVM host. Our reordering model emulates a volatile disk cache;
  say so explicitly if asked whether real eMMC shows it.
* No @-handles in the issue.
