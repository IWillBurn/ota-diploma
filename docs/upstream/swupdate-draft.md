# Draft issues for sbabic/swupdate

> **Status: draft, not posted.** Post only after the author has reviewed it, and after checking
> the current SWUpdate release (tested: 2024.12.1 from Debian bookworm-backports, package
> `2024.12.1+dfsg-3~bpo12+1`, GRUB bootloader handler, A/B with `installed-directly`).
> Evidence: otabench `bench/results/pilot-ab-20261101-*` (scenarios `net-endless`,
> `reorder:ext2`, `reorder:vfat`, `crash-replay`, `window:*`), `docs/pilot-ab.md`.

---

## 1. Download reports failure for an update that was installed

**Title:** `-d` download: extra data after a complete .swu makes the run fail although the update was applied

When the HTTP server keeps sending data after a complete `.swu` (no Content-Length), SWUpdate
installs all images, writes the boot environment of the new slot (`ORDER`, `<slot>_OK`,
`ustate=1` in our integration), stops reading after about 3.4 MiB and then exits with an error:

```
ERROR channel_curl.c : channel_callback_ipc : 202 : Writing into SWUpdate IPC stream failed.
ERROR channel_curl.c : channel_get_file : 1447 : Channel operation returned error (23): 'Failed writing received data to disk/application'
```

The process exit code is 1, but after a reboot the device runs the new version. Reproduced in
three runs. A fleet manager that relies on the result would count an applied update as failed
(and might retry or roll back). Expected: the result reflects the installation; trailing data
after the cpio trailer is either ignored or makes the install fail *before* the bootloader is
switched.

## 2. GRUB environment written via rename without fsync

**Title:** GRUB handler: power loss after a successful install can lose the update and leave an unusable grubenv

The GRUB environment is written to `grubenv.new` and renamed over `grubenv` without fsync of the
file or the directory. With power cuts emulated from a block-level write log:

* ext4: up to 4 s after `swupdate` reports success, both GRUB and Linux still see the old
  environment — the reported update is lost (durability window). At +5 and +6 s Linux (after
  journal replay) already sees the new environment while GRUB still reads the old one; from
  +8 s both see the new one. Measured with 1 s steps, one VM, no other load
  (`pilot-ab-20261102-110256`).
* ext2: 20 of 50 crash states around the environment rewrite leave a 1024-byte `grubenv` that
  contains data of other files (strings of a GRUB module): the renamed inode reached the disk
  before its data. GRUB falls back to its defaults; the next `swupdate` run fails
  (`SWUpdate *failed*`), so the device has left OTA.
* vfat: in one run all 38 crash states around the environment rewrite, including the final
  state 35 s after the success report, give Linux an empty `grubenv`, while GRUB still reads
  the previous block and boots the old slot. Restored from the write log on an idle host, the
  final state has a zero-length `grubenv` (`grub-editenv: error: invalid environment block.`)
  and the next `swupdate` run fails, so the device has left OTA. In another run both views had
  the new environment from +5 s: on vfat the length of this window depends on when writeback
  happens to run.

Suggested fix: `fsync()` the new file before `rename()`, then `fsync()` the directory (or, as
GRUB's own `save_env` does, rewrite the existing 1024-byte block in place).

---

## Notes for the author (not part of the issue)
* Same rig as the RAUC findings; the in-place writer used there is the reference fix.
* Check whether newer SWUpdate releases changed `bootloader/grub.c` before posting.
* No @-handles in the issue.
