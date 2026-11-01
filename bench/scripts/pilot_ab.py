"""A/B pilot: RAUC 1.8 + GRUB on Debian 12 in QEMU (system level and block level).

Scenarios (each starts from a fresh qcow2 overlay of ab-v1.qcow2):
  happy          install v2 -> reboot -> B/v2 -> confirmed -> reboot -> still B/v2
  broken         install validly signed but unbootable v2 -> must fall back to A/v1
  attacker       bundle signed with a foreign key -> must be rejected, slot untouched
  downgrade      on B/v2 install v1 -> is the downgrade accepted?  (RAUC default config)
  cut-firstboot  power cut during the first, unconfirmed boot of B -> safe fallback,
                 then a retry must succeed (liveness)
  crash-replay   block level: log every write of one install (blklogwrites), rebuild
                 the disk at each crash point (all barriers + sampled writes) and boot it

  python pilot_ab.py [--only happy,broken,...] [--points 30] [--liveness 3]
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402
from otabench.writelog import WriteLog  # noqa: E402

AB = Path(r"P:\vm\ab-v1.qcow2")
GRUB_RX = re.compile(r"otabench-grub: (RESCUE|ORDER=\[([^\]]*)\] A_OK=(\S*) A_TRY=(\S*) "
                     r"B_OK=(\S*) B_TRY=(\S*) -> (\w))")
READY_S = 180
ENV_LIST = ("E=$(sed -n 's/^grubenv=//p' /etc/rauc/system.conf); "
            "[ -n \"$E\" ] || E=$(sed -n 's/^env=//p' /etc/otabench-bootenv.conf 2>/dev/null); "
            "[ -n \"$E\" ] || E=/boot-ab/grub/grubenv; grub-editenv \"$E\" list")
CHECK_READY_S = 120  # per crash state; a fallback boot needs ~25 s
VARIANT_DIR = Path(r"P:\vm\variants")
_FSTAB = "sed -i 's#^LABEL=boot .*#/dev/vda3 /boot-ab {fs} {opts} 0 2#' /etc/fstab"
_REFORMAT = ("rm -rf /root/bs && mkdir /root/bs && cp -a /boot-ab/. /root/bs/ && umount /boot-ab && "
             "{mkfs} && mount -t {fs} /dev/vda3 /boot-ab && cp -r /root/bs/. /boot-ab/ && "
             "grub-install --target=i386-pc --boot-directory=/boot-ab --modules='part_gpt {mod}' "
             "/dev/vda 2>&1 | tail -1 && " + _FSTAB + " && grub-editenv /boot-ab/grub/grubenv list && sync")
VARIANTS = {  # /boot-ab configurations for the grubenv-window experiment
    "ext4-c5": "true",  # as built: ext4, default commit=5
    "ext4-c1": _FSTAB.format(fs="ext4", opts="defaults,commit=1")
               + " && mount -o remount,commit=1 /boot-ab",
    "ext4-c30": _FSTAB.format(fs="ext4", opts="defaults,commit=30")
                + " && mount -o remount,commit=30 /boot-ab",
    # no procps in the image: systemd-sysctl applies sysctl.d at boot, /proc/sys right now
    "ext4-wb1": "printf 'vm.dirty_writeback_centisecs = 100\\nvm.dirty_expire_centisecs = 100\\n' > "
                "/etc/sysctl.d/90-otabench.conf && echo 100 > /proc/sys/vm/dirty_writeback_centisecs"
                " && echo 100 > /proc/sys/vm/dirty_expire_centisecs",
    # split the two writeback knobs: which one sets the ~5 s window?
    "ext4-wbonly": "printf 'vm.dirty_writeback_centisecs = 100\\n' > /etc/sysctl.d/90-otabench.conf"
                   " && echo 100 > /proc/sys/vm/dirty_writeback_centisecs",
    "ext4-exponly": "printf 'vm.dirty_expire_centisecs = 100\\n' > /etc/sysctl.d/90-otabench.conf"
                    " && echo 100 > /proc/sys/vm/dirty_expire_centisecs",
    "ext2": _REFORMAT.format(mkfs="mkfs.ext2 -q -F -L boot /dev/vda3", fs="ext2", opts="defaults",
                             mod="ext2"),
    "vfat": "(command -v mkfs.vfat || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y -qq dosfstools)) >/dev/null && "
            + _REFORMAT.format(mkfs="mkfs.vfat -n boot /dev/vda3 >/dev/null 2>&1", fs="vfat",
                               opts="defaults", mod="fat"),
}

# --- the fix under test: RAUC custom backend that rewrites grubenv IN PLACE ---------
_BOOTENV_B64 = base64.b64encode((ROOT / "vm" / "guest" / "otabench-bootenv").read_bytes()).decode()
_INPLACE = (
    "echo " + _BOOTENV_B64 + " | base64 -d > /usr/local/sbin/otabench-bootenv"
    " && chmod 755 /usr/local/sbin/otabench-bootenv"
    " && sed -i -e 's/^bootloader=grub$/bootloader=custom/' -e '/^grubenv=/d' /etc/rauc/system.conf"
    " && printf '\\n[handlers]\\nbootloader-custom-backend=/usr/local/sbin/otabench-bootenv\\n'"
    " >> /etc/rauc/system.conf"
    " && systemctl restart rauc && rauc status mark-good"
    " && /usr/local/sbin/otabench-bootenv dump | tr '\\n' ' '"
    " && rauc status --output-format=json > /dev/null")
# the slot image must carry the same backend: rebuild v2 from the reconfigured slot A
_REBUNDLE = (
    "rm -rf /data/staging /data/b-v2 && mkdir -p /data/staging && cp -ax /. /data/staging/"
    " && rm -rf /data/staging/usr/share/doc/* /data/staging/usr/share/man/*"
    " /data/staging/usr/share/locale/* /data/staging/var/lib/apt/lists/*"
    " && echo 2 > /data/staging/etc/otabench-version"
    " && sz=$(du -sxm /data/staging | cut -f1) && img=$((sz * 125 / 100 + 64))"
    " && mkdir -p /data/b-v2"
    " && mkfs.ext4 -q -F -L rootfs -d /data/staging /data/b-v2/rootfs.ext4 ${img}M"
    " && sed 's/@VERSION@/2/' /root/manifest.raucm > /data/b-v2/manifest.raucm"
    " && rm -f /data/bundles/v2.raucb"
    " && rauc bundle --cert=/data/keys/dev.cert.pem --key=/data/keys/dev.key.pem"
    " /data/b-v2 /data/bundles/v2.raucb > /dev/null"
    " && rm -rf /data/b-v2 /data/staging && ls -l /data/bundles/v2.raucb")
VARIANTS["ext4-inplace"] = _INPLACE + " && " + _REBUNDLE
VARIANTS["ext2-inplace"] = VARIANTS["ext2"] + " && " + _INPLACE + " && " + _REBUNDLE
VARIANTS["vfat-inplace"] = VARIANTS["vfat"] + " && " + _INPLACE + " && " + _REBUNDLE

# --- UEFI: GRUB for x86_64-efi on the real ESP (vda15, vfat), grubenv on the ESP --------
# RAUC's GRUB integration docs suggest the EFI partition for grubenv on UEFI systems.
_ESP_ENV = "/boot/efi/EFI/BOOT/grub/grubenv"
_UEFI = (
    "mkdir -p /boot/efi && (mountpoint -q /boot/efi || mount -t vfat /dev/vda15 /boot/efi)"
    " && grub-install --target=x86_64-efi --efi-directory=/boot/efi"
    # unsigned core: Debian's signed (shim) GRUB ignores --boot-directory and boots the stock menu
    " --boot-directory=/boot/efi/EFI/BOOT --removable --no-nvram --no-uefi-secure-boot"
    " --modules='part_gpt ext2 fat' 2>&1 | tail -1"
    " && test -s /boot/efi/EFI/BOOT/BOOTX64.EFI && test -d /boot/efi/EFI/BOOT/grub/x86_64-efi"
    " && cp /boot-ab/grub/grub.cfg /boot/efi/EFI/BOOT/grub/grub.cfg"
    " && cp /boot-ab/grub/grubenv " + _ESP_ENV +
    " && sed -i 's#^grubenv=.*#grubenv=" + _ESP_ENV + "#' /etc/rauc/system.conf"
    " && echo '/dev/vda15 /boot/efi vfat defaults,nofail 0 2' >> /etc/fstab"
    " && echo 'env=" + _ESP_ENV + "' > /etc/otabench-bootenv.conf"
    " && systemctl restart rauc && rauc status mark-good && grub-editenv " + _ESP_ENV + " list"
    " | tr '\\n' ' ' && sync")
VARIANTS["uefi-esp"] = _UEFI + " && " + _REBUNDLE
VARIANTS["uefi-esp-inplace"] = _UEFI + " && " + _INPLACE + " && " + _REBUNDLE
UEFI_VARIANTS = {"uefi-esp", "uefi-esp-inplace"}


class Pilot:
    def __init__(self, work: Path) -> None:
        self.work = work
        work.mkdir(parents=True, exist_ok=True)
        self.n = 0
        self.uefi = False  # set while a UEFI variant is under test
        self.torn = False  # reorder: also emit sector-torn states (--torn)

    # ---------------------------------------------------------------- helpers
    def fresh(self, name: str, base: Path = AB, base_fmt: str = "qcow2",
              log: Path | None = None) -> VM:
        self.n += 1
        d = self.work / name
        d.mkdir(exist_ok=True)
        ov = make_overlay(base, d / f"{name}-{self.n}.qcow2", base_fmt)
        return VM(ov, d, log_writes=log, name=f"{name}-{self.n}", uefi=self.uefi).start()

    @staticmethod
    def grub_runs(vm: VM) -> list[dict]:
        """One entry per GRUB run; a RESCUE line belongs to the selection line after it."""
        runs, rescue = [], False
        for m in GRUB_RX.finditer(vm.serial_text()):
            if m.group(1) == "RESCUE":
                rescue = True
                continue
            runs.append({"order": m.group(2), "A_OK": m.group(3), "A_TRY": m.group(4),
                         "B_OK": m.group(5), "B_TRY": m.group(6), "slot": m.group(7),
                         "rescue": rescue})
            rescue = False
        return runs

    @staticmethod
    def state(vm: VM) -> dict:
        rc, out, _ = vm.agent.sh(
            "sed -n 's/.*rauc.slot=\\([AB]\\).*/\\1/p' /proc/cmdline; cat /etc/otabench-version;"
            " echo ---; " + ENV_LIST + "; echo ---;"
            " rauc status --output-format=json 2>/dev/null", 60)
        head, env, rauc = (out.split("---\n") + ["", ""])[:3]
        lines = head.split()
        st = {"slot": lines[0] if lines else None, "version": lines[1] if len(lines) > 1 else None,
              "env": dict(kv.split("=", 1) for kv in env.split("\n") if "=" in kv)}
        try:
            j = json.loads(rauc)
            st["rauc_booted"], st["rauc_primary"] = j.get("booted"), j.get("boot_primary")
        except ValueError:
            st["rauc_booted"] = st["rauc_primary"] = None
        return st

    @staticmethod
    def install(vm: VM, bundle: str) -> tuple[int, float, str]:
        t = time.monotonic()
        rc, out, err = vm.agent.sh(f"rauc install /data/bundles/{bundle}.raucb", 1200)
        return rc, time.monotonic() - t, (out + err).strip().splitlines()[-1:] and \
            (out + err).strip().splitlines()[-1]

    def reboot(self, vm: VM, timeout: float = READY_S) -> float | None:
        """Reboot and wait until the guest agent answers again; returns seconds."""
        before = len(self.grub_runs(vm))
        t = time.monotonic()
        vm.agent.spawn("sleep 1; systemctl reboot")
        deadline = t + timeout
        while time.monotonic() < deadline and len(self.grub_runs(vm)) <= before:
            time.sleep(0.5)
        if not vm.agent.wait(max(1, deadline - time.monotonic())):
            return None
        return time.monotonic() - t

    def boot_confirmed(self, vm: VM, slot: str = "A") -> bool:
        """A real update agent installs only from a confirmed (mark-good) boot."""
        return vm.agent.wait(READY_S) and self.wait_confirmed(vm, slot)

    @staticmethod
    def wait_confirmed(vm: VM, slot: str, timeout: float = 90) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rc, out, _ = vm.agent.sh(ENV_LIST, 30)
            env = dict(kv.split("=", 1) for kv in out.split() if "=" in kv)
            if env.get(f"{slot}_OK") == "1" and env.get(f"{slot}_TRY") == "0":
                return True
            time.sleep(2)
        return False

    def _check_point(self, raw: Path, k: int, wl: WriteLog, e0: int, e_inst: int,
                     markers: dict[int, int]) -> dict:
        """Boot the disk state 'power lost right after log entry k' and classify it."""
        t = time.monotonic()
        cvm = self.fresh("crash", base=raw, base_fmt="raw")
        try:
            ready = cvm.agent.wait(CHECK_READY_S)
            st = self.state(cvm) if ready else {}
            runs = self.grub_runs(cvm)
        finally:
            cvm.power_cut()
        cvm.disk.unlink(missing_ok=True)  # keep the serial log for post-mortem
        pair = (st.get("slot"), st.get("version"))
        env = st.get("env", {})
        env_ok = "ORDER" in env
        first = runs[0] if runs else {}
        rescue = any(r.get("rescue") for r in runs)
        # bootloader acted on an older A/B state than the OS sees after journal replay
        diverged = bool(first) and first.get("order") != env.get("ORDER")
        if not ready:
            v = "BRICK"
        elif pair not in {("A", "1"), ("B", "2")}:
            v = "INCONSISTENT"
        elif not env_ok or rescue or diverged:
            v = "DEGRADED"
        else:
            v = "OK"
        marker = next((sec for sec, idx in markers.items() if idx == k), None)
        r = {"entry": k, "phase": round((k - e0) / max(1, e_inst - e0), 3),
             "after_install_s": marker, "barrier": wl.entries[k].is_barrier,
             "verdict": v, "slot": pair[0], "version": pair[1], "env_ok": env_ok,
             "rescue": rescue, "diverged": diverged, "grub_order": first.get("order"),
             "linux_order": env.get("ORDER"), "boots": len(runs),
             "check_s": round(time.monotonic() - t, 1)}
        tag = f"+{marker}s" if marker is not None else f"{r['phase']:.0%}"
        print(f"    crash@{k} ({tag}{' B' if r['barrier'] else ''}): {v} {pair[0]}/{pair[1]} "
              f"grub=[{first.get('order')}] linux=[{env.get('ORDER')}]{' RESCUE' if rescue else ''}",
              flush=True)
        return r

    # ---------------------------------------------------------------- /boot-ab variants
    def variant(self, config: str) -> Path:
        """ab-v1 with a different /boot-ab configuration (cached overlay in P:/vm/variants)."""
        out = VARIANT_DIR / f"ab-{config}.qcow2"
        if out.exists():
            return out
        VARIANT_DIR.mkdir(parents=True, exist_ok=True)
        tmp = make_overlay(AB, VARIANT_DIR / f"ab-{config}.tmp.qcow2")
        vm = VM(tmp, VARIANT_DIR, net=True, name=f"variant-{config}").start()
        try:
            if not self.boot_confirmed(vm, "A"):
                raise RuntimeError("base image did not boot/confirm")
            rc, out_s, err = vm.agent.sh(VARIANTS[config], 1200)
            if rc != 0:
                raise RuntimeError(f"variant {config} failed: {(out_s + err)[-600:]}")
            _, info, _ = vm.agent.sh("findmnt -no FSTYPE,OPTIONS /boot-ab; grep boot-ab /etc/fstab;"
                                     " cat /proc/sys/vm/dirty_writeback_centisecs"
                                     " /proc/sys/vm/dirty_expire_centisecs", 30)
            print(f"    variant {config}: {' | '.join(info.strip().splitlines())}", flush=True)
        finally:
            vm.shutdown(90)
        tmp.rename(out)
        return out

    def window(self, config: str, *args, **kw) -> dict:
        self.uefi = config in UEFI_VARIANTS
        try:
            return self._window_impl(config, *args, **kw)
        finally:
            self.uefi = False

    def _window_impl(self, config: str, offsets: tuple[int, ...], region: int) -> dict:
        """When does the bootloader start to see the new A/B state after a successful
        `rauc install`, for one /boot-ab configuration? Also replays every write in the
        `region` log entries before install completion (where grubenv is rewritten)."""
        base = self.variant(config)
        d = self.work / f"window-{config}"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        mark = ("yes {t} | head -c 4096 > /tmp/m && dd if=/tmp/m of=/data/{n} bs=4096 "
                "count=1 oflag=direct conv=fsync status=none")
        vm = self.fresh(f"window-{config}", base=base, log=log)
        try:
            if not self.boot_confirmed(vm, "A"):
                raise RuntimeError(f"variant {config} did not boot/confirm")
            _, fsinfo, _ = vm.agent.sh("findmnt -no FSTYPE,OPTIONS /boot-ab; cat "
                                       "/proc/sys/vm/dirty_writeback_centisecs "
                                       "/proc/sys/vm/dirty_expire_centisecs", 30)
            vm.agent.sh(mark.format(t=tag_a, n="mark-start"), 60)
            rc, t_inst, _ = self.install(vm, "v2")
            t_done = time.monotonic()
            for sec in offsets:
                time.sleep(max(0.0, t_done + sec - time.monotonic()))
                vm.agent.sh(mark.format(t=f"{tag_b}-{sec}", n=f"mark-end-{sec}"), 60)
        finally:
            vm.power_cut()
        wl = WriteLog(log)
        e0 = wl.find(tag_a.encode())
        markers = {sec: wl.find(f"{tag_b}-{sec}".encode(), e0) for sec in offsets}
        e_inst = markers[offsets[0]]
        cps = sorted(set(range(max(e0, e_inst - region), e_inst)) | set(markers.values()))
        raw = d / "replay.raw"
        subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(base), str(raw)], check=True)
        applied, results = 0, []
        try:
            for k in cps:
                wl.apply(raw, applied, k + 1)
                applied = k + 1
                results.append(self._check_point(raw, k, wl, e0, e_inst, markers))
        finally:
            raw.unlink(missing_ok=True)
        by_s = {r["after_install_s"]: r for r in results if r["after_install_s"] is not None}
        old = [x for x in offsets if (by_s[x]["grub_order"] or "").startswith("A")]
        new = [x for x in offsets if (by_s[x]["grub_order"] or "").startswith("B")]
        reg = [r for r in results if r["after_install_s"] is None]
        counts = {v: sum(r["verdict"] == v for r in reg)
                  for v in ("OK", "DEGRADED", "INCONSISTENT", "BRICK")}
        bad = sum(r["verdict"] in ("BRICK", "INCONSISTENT") for r in results)
        return {"verdict": "FAIL" if bad else "PASS", "config": config, "boot_ab": fsinfo.strip(),
                "detail": f"bootloader sees the new state from +{min(new) if new else None}s "
                          f"(old until +{max(old) if old else None}s); env-rewrite region {counts}",
                "old_until_s": max(old) if old else None, "new_from_s": min(new) if new else None,
                "install_rc": rc, "install_s": round(t_inst, 1), "region_entries": len(reg),
                "region_counts": counts, "region_rescue": sum(r["rescue"] for r in reg),
                "region_diverged": sum(r["diverged"] for r in reg),
                "markers": {x: {k_: by_s[x][k_] for k_ in ("slot", "grub_order", "linux_order", "verdict")}
                            for x in offsets},
                "points": results}

    def reorder(self, config: str, *args, **kw) -> dict:
        self.uefi = config in UEFI_VARIANTS
        try:
            return self._reorder_impl(config, *args, **kw)
        finally:
            self.uefi = False

    def _reorder_impl(self, config: str, region: int) -> dict:
        """Volatile-cache model: between two FLUSH barriers the disk may persist any subset
        of the writes. Bounded subsets (none / all / only one / all but one) for every
        barrier interval in the last `region` log entries before install completion."""
        base = self.variant(config)
        d = self.work / f"reorder-{config}"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        mark = ("yes {t} | head -c 4096 > /tmp/m && dd if=/tmp/m of=/data/{n} bs=4096 "
                "count=1 oflag=direct conv=fsync status=none")
        vm = self.fresh(f"reorder-{config}", base=base, log=log)
        try:
            if not self.boot_confirmed(vm, "A"):
                raise RuntimeError(f"variant {config} did not boot/confirm")
            vm.agent.sh(mark.format(t=tag_a, n="mark-start"), 60)
            rc, t_inst, _ = self.install(vm, "v2")
            vm.agent.sh(mark.format(t=tag_b, n="mark-end"), 60)
        finally:
            vm.power_cut()
        wl = WriteLog(log)
        e0 = wl.find(tag_a.encode())
        e_inst = wl.find(tag_b.encode(), e0)
        states = sorted(wl.crash_states(max(e0, e_inst - region), e_inst, torn=self.torn),
                        key=lambda x: (x["base_end"], x["label"]))
        raw = d / "replay.raw"
        subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(base), str(raw)], check=True)
        applied, results = 0, []
        try:
            for stt in states:
                wl.apply(raw, applied, stt["base_end"])
                applied = stt["base_end"]
                undo = wl.apply_with_undo(raw, stt["extra"], stt.get("partial"))
                try:
                    k = max([stt["base_end"] - 1] + stt["extra"]
                            + ([stt["partial"][0]] if stt.get("partial") else []))
                    r = self._check_point(raw, k, wl, e0, e_inst, {})
                finally:
                    wl.undo(raw, undo)
                r.update(label=stt["label"], interval=stt["interval"], volatile=stt["volatile"],
                         prefix_state=stt["label"] == "kept-all", torn=bool(stt.get("partial")))
                print(f"      ^ {stt['label']} in {stt['interval']} (volatile={stt['volatile']})",
                      flush=True)
                results.append(r)
        finally:
            raw.unlink(missing_ok=True)
        counts = {v: sum(r["verdict"] == v for r in results)
                  for v in ("OK", "DEGRADED", "INCONSISTENT", "BRICK")}
        nonprefix = [r for r in results if not r["prefix_state"]]
        np_counts = {v: sum(r["verdict"] == v for r in nonprefix)
                     for v in ("OK", "DEGRADED", "INCONSISTENT", "BRICK")}
        bad = counts["INCONSISTENT"] + counts["BRICK"]
        return {"verdict": "FAIL" if bad else "PASS", "config": config,
                "detail": f"{len(results)} states in {len({tuple(r['interval']) for r in results})} "
                          f"barrier intervals: {counts}; non-prefix states only: {np_counts}",
                "install_rc": rc, "install_s": round(t_inst, 1), "counts": counts,
                "nonprefix_counts": np_counts, "env_lost": sum(not r["env_ok"] for r in results),
                "rescue": sum(r["rescue"] for r in results),
                "diverged": sum(r["diverged"] for r in results), "points": results}

    # ---------------------------------------------------------------- scenarios
    def happy_variant(self, config: str) -> dict:
        base = self.variant(config)
        self.uefi = config in UEFI_VARIANTS
        try:
            return self.happy(base, f"happy-{config}")
        finally:
            self.uefi = False

    def happy(self, base: Path = AB, name: str = "happy") -> dict:
        vm = self.fresh(name, base=base)
        try:
            t_boot = vm.agent.wait(READY_S) and time.monotonic() - vm.t_start
            self.wait_confirmed(vm, "A")
            s0 = self.state(vm)
            rc, t_inst, last = self.install(vm, "v2")
            s1 = self.state(vm)
            t_rb = self.reboot(vm)
            s2 = self.state(vm) if t_rb else {}
            conf = bool(t_rb) and self.wait_confirmed(vm, "B")
            t_rb2 = self.reboot(vm) if conf else None
            s3 = self.state(vm) if t_rb2 else {}
        finally:
            vm.power_cut()
        ok = (s0.get("slot"), s0.get("version")) == ("A", "1") and rc == 0 and \
            (s2.get("slot"), s2.get("version")) == ("B", "2") and conf and \
            (s3.get("slot"), s3.get("version")) == ("B", "2")
        return {"verdict": "PASS" if ok else "FAIL", "boot_s": round(t_boot or 0, 1),
                "install_s": round(t_inst, 1), "install_rc": rc, "install_msg": last,
                "reboot_to_ready_s": round(t_rb or 0, 1), "states": [s0, s1, s2, s3]}

    def broken(self, confirm: bool = True) -> dict:
        vm = self.fresh("broken" if confirm else "broken-unconf")
        try:
            vm.agent.wait(READY_S) and (not confirm or self.wait_confirmed(vm, "A"))
            rc, t_inst, last = self.install(vm, "v2-broken")
            t_rec = self.reboot(vm, timeout=300)
            st = self.state(vm) if t_rec else {}
            runs = self.grub_runs(vm)
        finally:
            vm.power_cut()
        ok = rc == 0 and (st.get("slot"), st.get("version")) == ("A", "1")
        path = "RESCUE branch" if any(r.get("rescue") for r in runs[1:]) else "regular OK/TRY logic"
        return {"verdict": "PASS" if ok else "FAIL", "fallback_path": path, "resets": vm.resets,
                "detail": f"validly signed unbootable image -> fell back to A/v1 via {path}" if ok else
                          "no fallback" if t_rec is None else f"booted {st.get('slot')}/{st.get('version')}",
                "install_rc": rc, "install_s": round(t_inst, 1),
                "recovery_s": round(t_rec or 0, 1), "grub_runs": runs[1:], "state": st}

    def attacker(self) -> dict:
        vm = self.fresh("attacker")
        try:
            vm.agent.wait(READY_S)
            rc, t_inst, last = self.install(vm, "v2-attacker")
            st = self.state(vm)
        finally:
            vm.power_cut()
        untouched = st.get("env", {}).get("ORDER") == "A B" and st.get("env", {}).get("B_OK") == "0"
        ok = rc != 0 and untouched
        return {"verdict": "PASS" if ok else "FAIL", "install_rc": rc, "install_msg": last,
                "bootloader_untouched": untouched}

    def downgrade(self) -> dict:
        vm = self.fresh("downgrade")
        try:
            self.boot_confirmed(vm, "A")
            self.install(vm, "v2")
            self.reboot(vm)
            self.wait_confirmed(vm, "B")
            s_mid = self.state(vm)
            rc, t_inst, last = self.install(vm, "v1")
            t_rb = self.reboot(vm) if rc == 0 else None
            st = self.state(vm) if t_rb else self.state(vm)
        finally:
            vm.power_cut()
        accepted = rc == 0 and st.get("version") == "1"
        return {"verdict": "FAIL" if accepted else "PASS",
                "detail": "v2 -> v1 downgrade accepted and booted (no version check in default "
                          "RAUC config; needs an integrator hook)" if accepted else
                          f"downgrade rejected (rc={rc}: {last})",
                "before": s_mid, "after": st}

    def cut_firstboot(self, delay: float = 3.0, confirm: bool = True) -> dict:
        vm = self.fresh("cutfb" if confirm else "cutfb-unconf")
        disk = vm.disk
        try:
            vm.agent.wait(READY_S) and (not confirm or self.wait_confirmed(vm, "A"))
            rc, _, _ = self.install(vm, "v2")
            before = len(self.grub_runs(vm))
            vm.agent.spawn("sleep 1; systemctl reboot")
            t = vm.wait_serial(r"otabench-grub: ORDER=\[B A\].*-> B", 120, occurrence=1)
            time.sleep(delay)  # kernel is booting B, mark-good has not run yet
            vm.power_cut()
            runs_cut = self.grub_runs(vm)[before:]
        except Exception:
            vm.power_cut()
            raise
        vm2 = VM(disk, disk.parent, name="cutfb-after").start()
        try:
            ready = vm2.agent.wait(READY_S)
            st = self.state(vm2) if ready else {}
            runs_after = self.grub_runs(vm2)
            rc2 = None
            st2 = {}
            if ready:  # liveness: the update must still be installable
                rc2, _, _ = self.install(vm2, "v2")
                if rc2 == 0 and self.reboot(vm2):
                    st2 = self.state(vm2)
        finally:
            vm2.power_cut()
        safe = (st.get("slot"), st.get("version")) in {("A", "1"), ("B", "2")}
        live = (st2.get("slot"), st2.get("version")) == ("B", "2")
        path = "RESCUE branch" if any(r.get("rescue") for r in runs_after[:1]) else "regular OK/TRY logic"
        return {"verdict": "PASS" if safe and live else "FAIL" if not safe else "PARTIAL",
                "fallback_path": path,
                "detail": f"after cut booted {st.get('slot')}/{st.get('version')} via {path}; retry -> "
                          f"{st2.get('slot')}/{st2.get('version')}",
                "cut_after_grub_s": round(t or 0, 1), "grub_at_cut": runs_cut,
                "after_cut": st, "after_retry": st2, "install_rc": rc}

    def crash_replay(self, points: int, liveness: int,
                     after_install: tuple[int, ...] = (0, 10, 20, 30, 45, 60)) -> dict:
        d = self.work / "replay"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        # 1. golden run with every write logged
        vm = self.fresh("replay", log=log)
        try:
            self.boot_confirmed(vm, "A")
            mark = ("yes {t} | head -c 4096 > /tmp/m && dd if=/tmp/m of=/data/{n} bs=4096 "
                    "count=1 oflag=direct conv=fsync status=none")
            vm.agent.sh(mark.format(t=tag_a, n="mark-start"), 60)
            rc, t_inst, _ = self.install(vm, "v2")
            t_done = time.monotonic()
            for sec in after_install:  # markers at fixed times after `rauc install` returned
                time.sleep(max(0.0, t_done + sec - time.monotonic()))
                vm.agent.sh(mark.format(t=f"{tag_b}-{sec}", n=f"mark-end-{sec}"), 60)
        finally:
            vm.power_cut()
        wl = WriteLog(log)
        e0 = wl.find(tag_a.encode())
        markers = {sec: wl.find(f"{tag_b}-{sec}".encode(), e0) for sec in after_install}
        e_inst = markers[after_install[0]]  # install finished here
        e1 = markers[after_install[-1]]
        win = wl.summary(e0, e1 + 1)
        barriers = [e.idx for e in wl.entries[e0:e1 + 1] if e.is_barrier]
        writes = [e.idx for e in wl.entries[e0:e1 + 1] if e.is_write]
        sampled = [writes[int(i * (len(writes) - 1) / max(1, points // 3))]
                   for i in range(points // 3 + 1)] if writes else []
        cps = sorted(set(barriers) | set(sampled) | {e0, e1} | set(markers.values()))
        if len(cps) > points:  # keep markers and the barriers near the end, thin the rest
            keep = set(barriers[-(points // 2):]) | {e0, e1} | set(markers.values())
            rest = [c for c in cps if c not in keep]
            step = max(1, len(rest) // max(1, points - len(keep)))
            cps = sorted(keep | set(rest[::step]))
        # 2. raw disk at log start
        raw = d / "replay.raw"
        t = time.monotonic()
        subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(AB), str(raw)], check=True)
        t_conv = time.monotonic() - t
        applied, results = 0, []
        for k in cps:
            wl.apply(raw, applied, k + 1)
            applied = k + 1
            results.append(self._check_point(raw, k, wl, e0, e_inst, markers))
        # 3. liveness: after a crash state, the update must still go through
        live = []
        if liveness:
            subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(AB), str(raw)], check=True)
            applied = 0
            picks = [cps[int(i * (len(cps) - 1) / max(1, liveness - 1))] for i in range(liveness)]
            for k in sorted(set(picks)):
                wl.apply(raw, applied, k + 1)
                applied = k + 1
                lvm = self.fresh("live", base=raw, base_fmt="raw")
                before, after, ok = {}, {}, False
                try:
                    if lvm.agent.wait(READY_S):
                        before = self.state(lvm)
                        self.wait_confirmed(lvm, before.get("slot") or "A")
                        rc2, _, _ = self.install(lvm, "v2")  # goes to the *inactive* slot
                        if rc2 == 0 and self.reboot(lvm):
                            after = self.state(lvm)
                            ok = after.get("version") == "2" and after.get("slot") != before.get("slot")
                finally:
                    lvm.power_cut()
                live.append({"entry": k, "retry_ok": ok,
                             "before": f"{before.get('slot')}/{before.get('version')}",
                             "after": f"{after.get('slot')}/{after.get('version')}"})
                print(f"    liveness@{k}: {'ok' if ok else 'FAILED'} {live[-1]['before']} -> "
                      f"{live[-1]['after']}", flush=True)
        raw.unlink(missing_ok=True)
        counts = {v: sum(r["verdict"] == v for r in results)
                  for v in ("OK", "DEGRADED", "INCONSISTENT", "BRICK")}
        switch = next((r["entry"] for r in results if r["slot"] == "B"), None)
        window = {r["after_install_s"]: {"slot": r["slot"], "grub_order": r["grub_order"],
                                         "linux_order": r["linux_order"]}
                  for r in results if r["after_install_s"] is not None}
        bad = counts["INCONSISTENT"] + counts["BRICK"]
        return {"verdict": "PASS" if not bad and all(x["retry_ok"] for x in live) else
                "FAIL" if bad else "PARTIAL",
                "log": {"entries_total": len(wl), "superblock_entries": wl.nr_super,
                        "install_window": [e0, e1], **win},
                "install_rc": rc, "install_s": round(t_inst, 1), "raw_convert_s": round(t_conv, 1),
                "install_entry": e_inst,
                "crash_points": len(results), "counts": counts,
                "first_point_booting_B": switch, "after_install_window": window,
                "diverged_points": sum(r["diverged"] for r in results),
                "mean_check_s": round(sum(r["check_s"] for r in results) / max(1, len(results)), 1),
                "points": results, "liveness": live}


def save(stamp: str, results: dict) -> None:
    out_dir = ROOT / "results" / f"pilot-ab-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pilot.json").write_text(json.dumps(
        {"started": stamp, "image": str(AB), "rauc": "1.8 (Debian 12)", "host": "Windows 11 + "
         "QEMU 11.1 WHPX", "results": results}, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--points", type=int, default=30)
    ap.add_argument("--liveness", type=int, default=3)
    ap.add_argument("--window", default="0,2,4,6,8,10,20,30",
                    help="seconds after `rauc install` returns at which crash points are taken")
    ap.add_argument("--region", type=int, default=24,
                    help="window: replay every entry this far before install completion")
    ap.add_argument("--offsets", default="0,1,2,3,4,5,6,8,10,15,20,30")
    ap.add_argument("--torn", action="store_true",
                    help="reorder: also tear multi-sector writes at sector granularity")
    ap.add_argument("--work", default="")
    ap.add_argument("--keep-disks", action="store_true",
                    help="keep per-scenario qcow2 overlays (~1.2 GB each) for post-mortem")
    a = ap.parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    work = Path(a.work) if a.work else Path(r"P:\vm\pilot") / stamp
    p = Pilot(work)
    p.torn = a.torn
    plan = {"happy": p.happy, "broken": p.broken, "attacker": p.attacker,
            "downgrade": p.downgrade, "cut-firstboot": p.cut_firstboot,
            "broken-unconfirmed": lambda: p.broken(confirm=False),
            "cut-unconfirmed": lambda: p.cut_firstboot(confirm=False),
            "crash-replay": lambda: p.crash_replay(
                a.points, a.liveness, tuple(int(x) for x in a.window.split(",")))}
    offs = tuple(int(x) for x in a.offsets.split(","))
    for cfg in VARIANTS:
        plan[f"window:{cfg}"] = (lambda c: lambda: p.window(c, offs, a.region))(cfg)
        plan[f"reorder:{cfg}"] = (lambda c: lambda: p.reorder(c, a.region))(cfg)
        plan[f"happy:{cfg}"] = (lambda c: lambda: p.happy_variant(c))(cfg)
    names = a.only.split(",") if a.only else list(plan)
    results = {}
    for n in names:
        t = time.monotonic()
        print(f"== {n}", flush=True)
        try:
            r = plan[n]()
        except Exception as e:  # noqa: BLE001
            r = {"verdict": "ERROR", "detail": f"{type(e).__name__}: {e}"}
        r["wall_s"] = round(time.monotonic() - t, 1)
        results[n] = r
        if not a.keep_disks:  # serial logs and golden.log stay, disks go
            for disk in work.rglob("*.qcow2"):
                disk.unlink(missing_ok=True)
        print(f"   {r['verdict']}  {r.get('detail', '')}  ({r['wall_s']}s)", flush=True)
        save(stamp, results)  # incremental: a long run never loses finished scenarios
    print(f"\nresults: {ROOT / 'results' / f'pilot-ab-{stamp}' / 'pilot.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
