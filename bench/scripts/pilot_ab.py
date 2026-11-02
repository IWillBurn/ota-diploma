"""A/B pilot: an A/B updater in QEMU, system level and block level.

The updater is reached only through its device adapter (adapter protocol v2,
docs/adapter-protocol.md): bench/updaters/<name>.yaml says how to install an artifact,
how to read the device status and how to read the bootloader's decisions from the serial
console. Nothing below knows about RAUC or GRUB.

Scenarios (each starts from a fresh qcow2 overlay of the adapter's image or of a variant):
  happy          install v2 -> reboot -> other slot / v2 -> confirmed -> reboot -> still there
  broken         install a validly signed but unbootable v2 -> fall back to the initial slot
  attacker       artifact signed with a foreign key -> rejected, boot state untouched,
                 the device still boots the initial slot
  downgrade      on v2 install v1 -> is the downgrade accepted?
  toctou         the artifact sits in a directory of an unprivileged update service; that
                 service swaps it for a foreign-key artifact while the updater runs ->
                 the image installed must be the one verified (OTA-INST-04)
  cut-firstboot  power cut during the first, unconfirmed boot of the new slot -> safe
                 fallback, then a retry must succeed (liveness)
  crash-replay   block level: log every write of one install (blklogwrites), rebuild
                 the disk at each crash point (all barriers + sampled writes) and boot it
  window:<cfg>   when does the bootloader see the new A/B state after the install returned
  reorder:<cfg>  reordering model (bounded subsets of unflushed writes; --torn: sector tears)
  happy:<cfg>    end-to-end update on a variant of the adapter (rauc-grub: ext4-*, ext2,
                 vfat, *-inplace = the fix, uefi-esp* = OVMF + grubenv on the ESP)

  python pilot_ab.py [--updater rauc-grub] [--only happy,broken,...] [--points 30]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench import __version__  # noqa: E402
from otabench.bundleserver import BundleServer  # noqa: E402
from otabench.device import Device  # noqa: E402
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402
from otabench.writelog import WriteLog  # noqa: E402

READY_S = 180
CHECK_READY_S = 120  # per crash state; a fallback boot needs ~25 s
VARIANT_DIR = Path(r"P:\vm\variants")
VERDICTS = ("OK", "DEGRADED", "INCONSISTENT", "BRICK")
# a 4 KiB block with a unique tag, written with O_DIRECT: finds a moment in the write log
ENV_HEADER = b"# GRUB Environment Block"
# network scenarios (B8): the guest reaches the host's loopback as 10.0.2.2 (QEMU user net)
NET_HOST = "10.0.2.2"
NET_CAP_S = 600       # the server gives up on one response after this long
NET_SLOW_BPS = 64     # trickle rate of the slow scenario, as for TUF artifacts (Table 4.2)
# policy: how long the bench waits for the install per scenario; slow uses the client
# profile's 120 s, endless the artifact time plus margin
NET_LIMIT_S = {"ok": 900.0, "tamper": 900.0, "drop": 900.0, "slow": 150.0, "endless": 300.0}
UPLOAD = ("python3 -c \"import os,sys,urllib.request as u; p=sys.argv[1]; f=open(p,'rb'); "
          "r=u.Request(sys.argv[2], data=f, method='PUT', headers={{'Content-Length': str(os.path.getsize(p))}}); "
          "print(u.urlopen(r, timeout=900).status)\" {path} {url}")
# toctou: (how the attacker gets write access, seconds after the install starts)
TOCTOU_TRIALS = (("held", 2.0), ("held", 6.0), ("held", 12.0), ("late", 6.0))
# Runs as `nobody` in the guest. held: a writable descriptor opened BEFORE the install
# starts (a compromised download service keeps its file open); late: the file is opened
# only at swap time (the service merely owns the file). Then the artifact's bytes are
# replaced by the foreign-key artifact's.
TOCTOU_ATTACKER = r"""
import os, sys, time
b, evil, mode, delay, d = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
fd = os.open(b, os.O_RDWR) if mode == "held" else None
open(d + "/ready", "w").close()
while not os.path.exists(d + "/go"):
    time.sleep(0.02)
t0 = time.monotonic()
time.sleep(delay)
t1 = time.monotonic()
try:
    if fd is None:
        fd = os.open(b, os.O_RDWR)
    n = 0
    with open(evil, "rb") as src:
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = src.read(1 << 20)
            if not chunk:
                break
            n += os.write(fd, chunk)
    os.ftruncate(fd, n)
    os.fsync(fd)
    print(f"swapped {n} bytes at +{t1 - t0:.2f}s in {time.monotonic() - t1:.2f}s", flush=True)
except OSError as e:
    print(f"swap failed at +{t1 - t0:.2f}s: {e}", flush=True)
"""
MARK = ("yes {tag} | head -c 4096 > /tmp/m && dd if=/tmp/m of={dir}/{name} bs=4096 "
        "count=1 oflag=direct conv=fsync status=none")


def _counts(results: list[dict]) -> dict:
    return {v: sum(r["verdict"] == v for r in results) for v in VERDICTS}


class Pilot:
    def __init__(self, work: Path, dev: Device, variant_dir: Path = VARIANT_DIR) -> None:
        self.work, self.dev, self.variant_dir = work, dev, variant_dir
        work.mkdir(parents=True, exist_ok=True)
        self.n = 0
        self.uefi = False  # set while a UEFI variant is under test
        self.torn = False  # reorder: also emit sector-torn states (--torn)
        self.settle = 0.0  # reorder: seconds between install return and the end marker
        self.region_at = "end"  # reorder: before the end marker | around env writes | window
        self.sample_intervals = 15  # reorder --region-at window: intervals sampled
        self.updater_version: str | None = None
        self.base_override: Path | None = None  # system scenarios on a variant
        self.netsrv: BundleServer | None = None  # network scenarios (B8)

    # ---------------------------------------------------------------- helpers
    def fresh(self, name: str, base: Path | None = None, base_fmt: str = "qcow2",
              log: Path | None = None, net: bool = False) -> VM:
        self.n += 1
        d = self.work / name
        d.mkdir(exist_ok=True)
        ov = make_overlay(base or self.base_override or self.dev.image,
                          d / f"{name}-{self.n}.qcow2", base_fmt)
        return VM(ov, d, log_writes=log, name=f"{name}-{self.n}", uefi=self.uefi, net=net).start()

    def boot_runs(self, vm: VM) -> list[dict]:
        return self.dev.boot_runs(vm.serial_text())

    def state(self, vm: VM) -> dict:
        if self.updater_version is None:
            self.updater_version = self.dev.version(vm) or ""
        return self.dev.status(vm)

    def install(self, vm: VM, role: str) -> tuple[int, float, str]:
        return self.dev.install(vm, role)

    def mark(self, vm: VM, tag: str, name: str) -> None:
        vm.agent.sh(MARK.format(tag=tag, dir=self.dev.scratch_dir, name=name), 60)

    def good_states(self) -> set[tuple[str, str]]:
        """(slot, version) pairs that are consistent at any moment of an update."""
        return {self.dev.initial, self.dev.updated}

    def reboot(self, vm: VM, timeout: float = READY_S) -> float | None:
        """Reboot and wait until the guest agent answers again; returns seconds."""
        before = len(self.boot_runs(vm))
        t = time.monotonic()
        vm.agent.spawn("sleep 1; " + self.dev.cmd_reboot)
        deadline = t + timeout
        while time.monotonic() < deadline and len(self.boot_runs(vm)) <= before:
            time.sleep(0.5)
        if not vm.agent.wait(max(1, deadline - time.monotonic())):
            return None
        return time.monotonic() - t

    def wait_boot(self, vm: VM, before: int, slot: str, timeout: float) -> float | None:
        """Seconds since VM start when a bootloader run after the first `before` runs
        has selected `slot`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(r.get("slot") == slot for r in self.boot_runs(vm)[before:]):
                return time.monotonic() - vm.t_start
            time.sleep(0.05)
        return None

    def boot_confirmed(self, vm: VM, slot: str | None = None) -> bool:
        """A real update agent installs only from a confirmed (mark-good) boot."""
        return vm.agent.wait(READY_S) and self.wait_confirmed(vm, slot or self.dev.initial_slot)

    def wait_confirmed(self, vm: VM, slot: str, timeout: float = 90) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.dev.status(vm, 120)  # the command may wait up to 90 s for mounts
            if st["slot"] == slot and st["confirmed"]:
                return True
            time.sleep(2)
        return False

    def _check_point(self, raw: Path, k: int, wl: WriteLog, e0: int, e_inst: int,
                     markers: dict[int, int]) -> dict:
        """Boot the disk state 'power lost right after log entry k' and classify it."""
        t = time.monotonic()

        def boot(timeout: float) -> tuple[bool, dict, list[dict]]:
            cvm = self.fresh("crash", base=raw, base_fmt="raw")
            try:
                ready = cvm.agent.wait(timeout)
                return ready, self.state(cvm) if ready else {}, self.boot_runs(cvm)
            finally:
                cvm.power_cut()
                cvm.disk.unlink(missing_ok=True)  # keep the serial log for post-mortem

        ready, st, runs = boot(CHECK_READY_S)
        retry = None
        if not ready:
            # A BRICK is confirmed on a second boot of the very same state with twice the
            # timeout: a guest that is merely slow under host load is not a brick
            # (01.11.2026: one such false BRICK while four VMs ran in parallel).
            ready, st, runs = boot(2 * CHECK_READY_S)
            retry = "booted on retry" if ready else "confirmed"
        pair = (st.get("slot"), st.get("version"))
        env_ok = bool(st.get("env_ok"))
        first = runs[0] if runs else {}
        rescue = any(r.get("rescue") for r in runs)
        # the bootloader acted on an older A/B state than the OS sees after journal replay
        diverged = bool(first) and first.get("order") != st.get("order")
        if not ready:
            v = "BRICK"
        elif pair not in self.good_states():
            v = "INCONSISTENT"
        elif not env_ok or rescue or diverged:
            v = "DEGRADED"
        else:
            v = "OK"
        marker = next((sec for sec, idx in markers.items() if idx == k), None)
        r = {"entry": k, "phase": round((k - e0) / max(1, e_inst - e0), 3),
             "after_install_s": marker, "barrier": wl.entries[k].is_barrier,
             "verdict": v, "slot": pair[0], "version": pair[1], "env_ok": env_ok,
             "rescue": rescue, "diverged": diverged, "boot_slot": first.get("slot"),
             "boot_order": first.get("order"), "os_order": st.get("order"), "boots": len(runs),
             "brick_retry": retry, "jobs_wait_s": st.get("jobs_wait_s"),
             "check_s": round(time.monotonic() - t, 1)}
        tag = f"+{marker}s" if marker is not None else f"{r['phase']:.0%}"
        print(f"    crash@{k} ({tag}{' B' if r['barrier'] else ''}): {v} {pair[0]}/{pair[1]} "
              f"boot=[{first.get('order')}] os=[{st.get('order')}]{' RESCUE' if rescue else ''}"
              f"{f' (first boot timed out; {retry})' if retry else ''}",
              flush=True)
        return r

    # ---------------------------------------------------------------- variants
    def variant(self, config: str) -> Path:
        """The adapter's image in configuration `config` (cached overlay; the cache key
        changes with the base image and with the variant's scripts)."""
        out = self.variant_dir / f"{self.dev.variant_id(config)}.qcow2"
        if out.exists():
            return out
        self.variant_dir.mkdir(parents=True, exist_ok=True)
        tmp = make_overlay(self.dev.image, out.with_suffix(".tmp.qcow2"))
        vm = VM(tmp, self.variant_dir, net=True, name=f"variant-{config}").start()
        try:
            if not self.boot_confirmed(vm):
                raise RuntimeError("base image did not boot/confirm")
            for step, script in self.dev.variant_scripts(config):
                rc, so, se = vm.agent.sh(script, 1200)
                if rc != 0:
                    raise RuntimeError(f"variant {config}, step {step} failed: {(so + se)[-600:]}")
            info = self.dev.info(vm)
            print(f"    variant {config}: {' | '.join(info.splitlines())}", flush=True)
        finally:
            vm.shutdown(90)
        tmp.rename(out)
        return out

    def _on_variant(self, config: str, fn, *args, **kw) -> dict:
        self.uefi = self.dev.firmware(config) == "uefi"
        try:
            return fn(config, *args, **kw)
        finally:
            self.uefi = False

    def window(self, config: str, *args, **kw) -> dict:
        return self._on_variant(config, self._window_impl, *args, **kw)

    def reorder(self, config: str, *args, **kw) -> dict:
        return self._on_variant(config, self._reorder_impl, *args, **kw)

    def happy_variant(self, config: str) -> dict:
        base = self.variant(config)
        return self._on_variant(config, lambda c: self.happy(base, f"happy-{c}"))

    def on_variant(self, config: str, fn) -> dict:
        """Run a system scenario on the variant `config` instead of the base image."""
        base = self.variant(config)
        self.base_override = base
        try:
            return self._on_variant(config, lambda c: fn())
        finally:
            self.base_override = None

    def _window_impl(self, config: str, offsets: tuple[int, ...], region: int) -> dict:
        """When does the bootloader start to see the new A/B state after a successful
        install, for one configuration? Also replays every write in the `region` log
        entries before install completion (where the boot state is rewritten)."""
        base = self.variant(config)
        d = self.work / f"window-{config}"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        vm = self.fresh(f"window-{config}", base=base, log=log)
        try:
            if not self.boot_confirmed(vm):
                raise RuntimeError(f"variant {config} did not boot/confirm")
            info = self.dev.info(vm)
            self.mark(vm, tag_a, "mark-start")
            rc, t_inst, _ = self.install(vm, "v2")
            t_done = time.monotonic()
            for sec in offsets:
                time.sleep(max(0.0, t_done + sec - time.monotonic()))
                self.mark(vm, f"{tag_b}-{sec}", f"mark-end-{sec}")
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
        old = [x for x in offsets if by_s[x]["boot_slot"] == self.dev.initial_slot]
        new = [x for x in offsets if by_s[x]["boot_slot"] == self.dev.target_slot]
        reg = [r for r in results if r["after_install_s"] is None]
        counts = _counts(reg)
        bad = sum(r["verdict"] in ("BRICK", "INCONSISTENT") for r in results)
        return {"verdict": "FAIL" if bad else "PASS", "config": config, "device_info": info,
                "detail": f"bootloader sees the new state from +{min(new) if new else None}s "
                          f"(old until +{max(old) if old else None}s); env-rewrite region {counts}",
                "old_until_s": max(old) if old else None, "new_from_s": min(new) if new else None,
                "install_rc": rc, "install_s": round(t_inst, 1), "region_entries": len(reg),
                "region_counts": counts, "region_rescue": sum(r["rescue"] for r in reg),
                "region_diverged": sum(r["diverged"] for r in reg),
                "markers": {x: {k_: by_s[x][k_] for k_ in
                                ("slot", "boot_slot", "boot_order", "os_order", "verdict")}
                            for x in offsets},
                "points": results}

    def _reorder_impl(self, config: str, region: int) -> dict:  # noqa: C901
        """Volatile-cache model: between two FLUSH barriers the disk may persist any subset
        of the writes. Bounded subsets (none / all / only one / all but one) for every
        barrier interval in the last `region` log entries before install completion."""
        base = self.variant(config)
        d = self.work / f"reorder-{config}"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        vm = self.fresh(f"reorder-{config}", base=base, log=log)
        try:
            if not self.boot_confirmed(vm):
                raise RuntimeError(f"variant {config} did not boot/confirm")
            self.mark(vm, tag_a, "mark-start")
            rc, t_inst, _ = self.install(vm, "v2")
            if self.settle:  # let background writeback reach the disk before the end marker
                time.sleep(self.settle)
            self.mark(vm, tag_b, "mark-end")
        finally:
            vm.power_cut()
        wl = WriteLog(log)
        e0 = wl.find(tag_a.encode())
        e_inst = wl.find(tag_b.encode(), e0)
        lo, hi = max(e0, e_inst - region), e_inst
        env_idx: list[int] = []
        if self.region_at == "env":  # around the last boot-environment write
            env_idx = wl.find_all(ENV_HEADER, e0, e_inst)
            if not env_idx:
                raise RuntimeError("precondition: no boot-environment write between the markers")
            # the last environment write is the slot switch; earlier ones (marking the
            # target slot bad before writing it) are outside the window of interest
            lo = max(e0, env_idx[-1] - region)
            hi = min(e_inst, env_idx[-1] + region // 2)
        sample = None
        if self.region_at == "window":  # the whole install, a sample of its intervals
            lo, hi, sample = e0, e_inst, self.sample_intervals
        # the open interval after the last flush is a crash point too (no-fsync writers)
        states = sorted(wl.crash_states(lo, hi, torn=self.torn, open_tail=self.region_at != "end",
                                        sample=sample),
                        key=lambda x: (x["base_end"], x["label"]))
        if not states:
            raise RuntimeError(f"precondition: the reordering model has no state in entries "
                               f"[{lo}, {hi}] (no FLUSH-bounded interval with volatile writes)")
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
        counts = _counts(results)
        nonprefix = [r for r in results if not r["prefix_state"]]
        np_counts = _counts(nonprefix)
        bad = counts["INCONSISTENT"] + counts["BRICK"]
        return {"verdict": "FAIL" if bad else "PASS", "config": config,
                "region": [lo, hi], "region_at": self.region_at, "settle_s": self.settle,
                "sampled_intervals": sample,
                "env_entries": env_idx,
                "detail": f"{len(results)} states in {len({tuple(r['interval']) for r in results})} "
                          f"barrier intervals: {counts}; non-prefix states only: {np_counts}",
                "install_rc": rc, "install_s": round(t_inst, 1), "counts": counts,
                "nonprefix_counts": np_counts, "env_lost": sum(not r["env_ok"] for r in results),
                "rescue": sum(r["rescue"] for r in results),
                "diverged": sum(r["diverged"] for r in results), "points": results}

    # ---------------------------------------------------------------- scenarios
    def happy(self, base: Path | None = None, name: str = "happy") -> dict:
        vm = self.fresh(name, base=base)
        try:
            t_boot = vm.agent.wait(READY_S) and time.monotonic() - vm.t_start
            self.wait_confirmed(vm, self.dev.initial_slot)
            s0 = self.state(vm)
            rc, t_inst, last = self.install(vm, "v2")
            s1 = self.state(vm)
            t_rb = self.reboot(vm)
            s2 = self.state(vm) if t_rb else {}
            conf = bool(t_rb) and self.wait_confirmed(vm, self.dev.target_slot)
            t_rb2 = self.reboot(vm) if conf else None
            s3 = self.state(vm) if t_rb2 else {}
        finally:
            vm.power_cut()
        pair = lambda s: (s.get("slot"), s.get("version"))  # noqa: E731
        ok = pair(s0) == self.dev.initial and rc == 0 and pair(s2) == self.dev.updated \
            and conf and pair(s3) == self.dev.updated
        return {"verdict": "PASS" if ok else "FAIL", "boot_s": round(t_boot or 0, 1),
                "install_s": round(t_inst, 1), "install_rc": rc, "install_msg": last,
                "reboot_to_ready_s": round(t_rb or 0, 1), "states": [s0, s1, s2, s3]}

    def prepare(self, vm: VM, confirm: bool) -> dict:
        """Precondition of a scenario that starts on the initial slot: its boot is confirmed
        (confirm=True) or deterministically NOT confirmed. Racing the install against the
        boot-time confirmation service is not reproducible (both outcomes were observed),
        so the bench waits for the confirmation and lets the adapter undo it."""
        if not vm.agent.wait(READY_S):
            raise RuntimeError("precondition: the guest did not come up")
        if not self.wait_confirmed(vm, self.dev.initial_slot):
            raise RuntimeError("precondition: the boot of the initial slot was never confirmed")
        if not confirm:
            if not self.dev.cmd_unconfirm:
                raise RuntimeError(f"precondition: adapter {self.dev.name} has no 'unconfirm' command")
            rc, out, err = vm.agent.sh(self.dev.cmd_unconfirm, 60)
            st = self.dev.status(vm)
            if rc != 0 or st["confirmed"] or st["slot"] != self.dev.initial_slot:
                raise RuntimeError(f"precondition: 'unconfirm' did not take effect (rc={rc}): "
                                   f"{(out + err).strip()[-200:]}")
            return {"confirmed_at_install": False, "env_at_install": st["env"]}
        return {"confirmed_at_install": True}

    def broken(self, confirm: bool = True) -> dict:
        vm = self.fresh("broken" if confirm else "broken-unconf")
        try:
            pre = self.prepare(vm, confirm)
            rc, t_inst, last = self.install(vm, "v2-broken")
            t_rec = self.reboot(vm, timeout=300)
            st = self.state(vm) if t_rec else {}
            runs = self.boot_runs(vm)
        finally:
            vm.power_cut()
        ok = rc == 0 and (st.get("slot"), st.get("version")) == self.dev.initial
        path = "rescue rule" if any(r.get("rescue") for r in runs[1:]) else "regular boot-attempt logic"
        return {"verdict": "PASS" if ok else "FAIL", "fallback_path": path, "resets": vm.resets,
                "detail": f"validly signed unbootable image -> fell back to "
                          f"{'/'.join(self.dev.initial)} via {path}" if ok else
                          "no fallback" if t_rec is None else f"booted {st.get('slot')}/{st.get('version')}",
                "install_rc": rc, "install_s": round(t_inst, 1), **pre,
                "recovery_s": round(t_rec or 0, 1), "boot_runs": runs[1:], "state": st}

    def attacker(self) -> dict:
        vm = self.fresh("attacker")
        try:
            self.boot_confirmed(vm)
            s0 = self.state(vm)
            rc, t_inst, last = self.install(vm, "v2-attacker")
            s1 = self.state(vm)
            t_rb = self.reboot(vm)
            s2 = self.state(vm) if t_rb else {}
        finally:
            vm.power_cut()
        untouched = s1.get("env") == s0.get("env") and s1.get("order") == s0.get("order")
        stays = (s2.get("slot"), s2.get("version")) == self.dev.initial
        ok = rc != 0 and untouched and stays
        return {"verdict": "PASS" if ok else "FAIL", "install_rc": rc, "install_msg": last,
                "install_s": round(t_inst, 1), "bootloader_untouched": untouched,
                "boot_state_reported": bool(s0.get("env")),
                "after_reboot": f"{s2.get('slot')}/{s2.get('version')}",
                "detail": "foreign-key artifact rejected, boot state untouched, still boots "
                          f"{'/'.join(self.dev.initial)}" if ok else
                          f"rc={rc}, untouched={untouched}, after reboot {s2.get('slot')}/{s2.get('version')}"}

    def downgrade(self) -> dict:
        vm = self.fresh("downgrade")
        try:
            self.boot_confirmed(vm)
            self.install(vm, "v2")
            self.reboot(vm)
            self.wait_confirmed(vm, self.dev.target_slot)
            s_mid = self.state(vm)
            rc, t_inst, last = self.install(vm, "v1")
            t_rb = self.reboot(vm) if rc == 0 else None
            st = self.state(vm)
            ctl = None
            if rc != 0:  # control: in the same state a non-older artifact must still install,
                rc_c, _, last_c = self.install(vm, "v2")  # else the rejection proves nothing
                ctl = {"rc": rc_c, "msg": last_c}
                if rc_c != 0:
                    raise RuntimeError("precondition: the control install of v2 failed as well "
                                       f"({last_c[:120]}); the rejected downgrade is not "
                                       "attributable to a version check")
        finally:
            vm.power_cut()
        accepted = rc == 0 and st.get("version") == self.dev.artifact("v1").version
        return {"verdict": "FAIL" if accepted else "PASS",
                "detail": "v2 -> v1 downgrade accepted and booted (no version check in this "
                          "configuration; needs an integrator hook)" if accepted else
                          f"downgrade rejected (rc={rc}: {last})",
                "rebooted": t_rb is not None, "control_install": ctl, "before": s_mid, "after": st}

    def _toctou_trial(self, mode: str | None, delay: float, ref: str | None) -> dict:
        """One install of a copy of v2 that an unprivileged process may swap for the
        foreign-key artifact (mode None = control, no attacker)."""
        art, evil = self.dev.artifact("v2").path, self.dev.artifact("v2-attacker").path
        d = f"{self.dev.scratch_dir}/otabench-toctou"
        b = f"{d}/update{Path(art).suffix}"
        tag = f"{mode}-{delay:g}" if mode else "control"
        vm = self.fresh(f"toctou-{tag}")
        try:
            self.boot_confirmed(vm)
            s0 = self.state(vm)
            rc, out, err = vm.agent.sh(
                f"rm -rf {d} && mkdir -p {d} && cp {art} {b} && cp {evil} {d}/evil && "
                f"chown -R nobody:nogroup {d} && chmod 0666 {b} && chmod 0644 {d}/evil && "
                f"echo {base64.b64encode(TOCTOU_ATTACKER.encode()).decode()} | base64 -d > "
                f"{d}/attacker.py && sync", 600)
            if rc != 0:
                raise RuntimeError(f"precondition: staging the artifact failed: {(out + err)[-200:]}")
            if mode:
                vm.agent.spawn(f"cd / && runuser -u nobody -- python3 {d}/attacker.py {b} "
                               f"{d}/evil {mode} {delay} {d} > {d}/attacker.log 2>&1")
                deadline = time.monotonic() + 60
                while vm.agent.sh(f"test -e {d}/ready", 10)[0] != 0:
                    if time.monotonic() > deadline:
                        raise RuntimeError("precondition: the attacker process did not start")
                    time.sleep(0.5)
            vm.agent.sh(f"touch {d}/go", 10)
            rc, t_inst, last = self.dev.install(vm, "v2", path=b)
            tail = self.dev.last_output
            s1 = self.state(vm)
            alog = vm.agent.sh(f"sleep 2; cat {d}/attacker.log 2>/dev/null", 30)[1].strip() if mode else ""
            digest = self.dev.slot_digest(vm, self.dev.target_slot) if rc == 0 else None
        finally:
            vm.power_cut()
        t = self.dev.target_slot
        boot = lambda s: (s.get("order"), s.get("env", {}).get(f"{t}_OK"),  # noqa: E731
                          s.get("env", {}).get(f"{t}_TRY"))
        if rc != 0:
            outcome = "blocked" if boot(s1) == boot(s0) else "failed, boot state changed"
        else:
            outcome = "genuine" if ref is None or digest == ref else "substituted"
        return {"trial": tag, "install_rc": rc, "install_s": round(t_inst, 1),
                "install_msg": last, "install_tail": tail, "attacker": alog, "slot_digest": digest,
                "outcome": outcome, "safe": outcome in ("blocked", "genuine"),
                "boot_before": boot(s0), "boot_after": boot(s1)}

    def toctou(self) -> dict:
        ctl = self._toctou_trial(None, 0.0, None)
        if ctl["install_rc"] != 0:
            raise RuntimeError("precondition: the unattacked copy of v2 did not install "
                               f"({ctl['install_msg'][:160]}); the scenario cannot tell a "
                               "blocked attack from a broken setup")
        trials = [self._toctou_trial(m, dl, ctl["slot_digest"]) for m, dl in TOCTOU_TRIALS]
        bad = [t for t in trials if not t["safe"]]
        return {"verdict": "FAIL" if bad else "PASS", "metric": "census",
                "detail": (f"{len(bad)} of {len(trials)} trials unsafe: "
                           + "; ".join(f"{t['trial']} {t['outcome']}" for t in bad)) if bad else
                          "all trials safe: " + ", ".join(f"{t['trial']} {t['outcome']}" for t in trials),
                "control": ctl, "trials": trials}

    # ---------------------------------------------------------------- network (B8)
    def _artifact_server(self, vm: VM) -> tuple[BundleServer, str]:
        """The adversarial artifact server on the host, holding this adapter's v2 (uploaded
        from the guest once and cached, keyed by adapter, image and artifact path)."""
        art = self.dev.artifact("v2").path
        base = self.base_override or self.dev.image  # a variant may carry its own v2
        st = base.stat()
        key = hashlib.sha256(f"{self.dev.name}|{base}|{st.st_size}|{st.st_mtime_ns}|{art}"
                             .encode()).hexdigest()[:10]
        store = self.variant_dir.parent / "artifacts" / f"{self.dev.name}-{key}-v2{Path(art).suffix}"
        if self.netsrv is None or self.netsrv.store != store:
            if self.netsrv:
                self.netsrv.stop()
            self.netsrv = BundleServer(store, cap_s=NET_CAP_S).start()
        if not store.exists():
            up = f"http://{NET_HOST}:{self.netsrv.port}/upload"
            rc, out, err = vm.agent.sh(f"for i in 1 2 3 4 5 6 7 8 9 10; do {UPLOAD.format(path=shlex.quote(art), url=up)} "
                                       "&& exit 0; sleep 3; done; exit 1", 900)
            if rc != 0 or not store.exists():
                raise RuntimeError(f"precondition: uploading the artifact to the host failed: {(out + err)[-200:]}")
        return self.netsrv, f"http://{NET_HOST}:{self.netsrv.port}/v2{Path(art).suffix}"

    def net(self, kind: str) -> dict:
        """Install over the network from the adversarial server (OTA-AUTH-01/02 in transit,
        OTA-NET-01, OTA-DOS-02, OTA-DOS-04 for A/B updaters)."""
        vm = self.fresh(f"net-{kind}", net=True)
        limit = NET_LIMIT_S[kind]
        try:
            if not self.boot_confirmed(vm):
                raise RuntimeError("precondition: the initial slot did not come up confirmed")
            s0 = self.state(vm)
            srv, url = self._artifact_server(vm)
            size = srv.size
            srv.set_mode({"ok": "ok", "tamper": f"tamper:{size // 2}", "drop": f"drop:{size // 2}",
                          "slow": f"slow:{NET_SLOW_BPS}:{size // 4}", "endless": "endless"}[kind])
            t0 = time.monotonic()
            try:
                rc, t_inst, last = self.dev.install_url(vm, url, timeout=limit)
            except TimeoutError:
                rc, t_inst, last = None, time.monotonic() - t0, f"still running after {limit:.0f} s"
                vm.agent.sh("pkill -KILL -f 'swupdate|rauc install' ; sleep 2", 30)
            tail = self.dev.last_output if rc is not None else ""
            reqs = [{"range": r.range, "status": r.status, "sent": r.sent, "want": r.want,
                     "closed_by": r.closed_by, "s": round((r.t1 or time.monotonic()) - r.t0, 1)}
                    for r in srv.log]
            applied = srv.applied
            s1 = self.state(vm)
            ctl = None
            # control: the same device still installs an honest download. Not after a
            # timeout: the updater may still be busy (RAUC's CLI is only a D-Bus client of
            # the service, which keeps installing), and the verdict is decided already.
            if kind != "ok" and rc not in (0, None):
                srv.set_mode("ok")
                rc_c, t_c, last_c = self.dev.install_url(vm, url, timeout=600)
                ctl = {"rc": rc_c, "s": round(t_c, 1), "msg": last_c}
                if rc_c != 0:
                    raise RuntimeError(f"precondition: an honest network install failed as well ({last_c[:120]})")
            t_rb = self.reboot(vm)
            s2 = self.state(vm) if t_rb else {}
        finally:
            vm.power_cut()
        t = self.dev.target_slot
        boot = lambda s: (s.get("order"), s.get("env", {}).get(f"{t}_OK"))  # noqa: E731
        pair = (s2.get("slot"), s2.get("version"))
        untouched = boot(s1) == boot(s0)
        extra = sum(max(0, r["sent"] - r["want"]) for r in reqs if r["want"])  # past what was asked
        if kind == "ok":
            ok, why = rc == 0 and pair == self.dev.updated, f"installed and booted {pair[0]}/{pair[1]}"
        elif kind == "tamper":
            ok = rc not in (0, None) and untouched
            why = "tampered download rejected, boot state untouched" if ok else \
                f"rc={rc}, boot state {'untouched' if untouched else 'CHANGED'}"
        elif kind == "drop":
            ok = (rc == 0 and pair == self.dev.updated) or (rc not in (0, None) and untouched)
            why = ("connection cut at 50%: recovered within the same install" if rc == 0 else
                   "connection cut at 50%: install failed safely, an honest retry installed") if ok else \
                f"rc={rc}, after reboot {pair[0]}/{pair[1]}"
        elif kind == "slow":
            ok = rc not in (0, None) and untouched
            why = (f"slow download ({NET_SLOW_BPS} B/s) aborted after {t_inst:.0f} s" if ok else
                   f"no abort within {limit:.0f} s at {NET_SLOW_BPS} B/s" if rc is None else f"rc={rc}")
        else:  # endless: the threat (OTA-DOS-02) is unbounded reading; the report is noted apart
            ok = rc is not None
            switched = not untouched
            mismatch = (rc == 0) != switched if rc is not None else None
            why = (f"stopped {extra / 2**20:.0f} MiB past the artifact after {t_inst:.0f} s" if ok else
                   f"still reading after {limit:.0f} s ({extra / 2**20:.0f} MiB past the artifact)")
            if mismatch:
                why += ("; reported FAILURE although the boot state was switched to the new slot"
                        if switched else "; reported success, but the boot state was not switched")
        # the honest network install is the baseline: if it fails, nothing else can be judged
        verdict = "PASS" if ok else ("ERROR" if kind == "ok" else "FAIL")
        if kind != "ok" and not applied:  # e.g. the client never read past the cut point
            verdict, why = "ERROR", f"precondition: the {kind} attack never took effect ({why})"
        if kind == "ok" and not ok:
            why = f"precondition: the honest network install did not work (rc={rc}: {tail.splitlines()[-2:] if tail else last})"
        return {"verdict": verdict, "detail": why, "mode": srv.mode if kind == "ok" else kind,
                "install_rc": rc, "install_s": round(t_inst, 1), "install_msg": last, "install_tail": tail,
                "requests": reqs, "attack_applied": applied, "bytes_past_artifact": extra, "artifact_size": size,
                "boot_untouched_after_failure": untouched, "control_install": ctl,
                "status_mismatch": ((rc == 0) == untouched) if rc is not None else None,
                "after_reboot": f"{pair[0]}/{pair[1]}", "before": s0, "after": s1}

    def cut_firstboot(self, delay: float = 3.0, confirm: bool = True) -> dict:
        vm = self.fresh("cutfb" if confirm else "cutfb-unconf")
        disk = vm.disk
        try:
            pre = self.prepare(vm, confirm)
            rc, _, _ = self.install(vm, "v2")
            before = len(self.boot_runs(vm))
            vm.agent.spawn("sleep 1; " + self.dev.cmd_reboot)
            t = self.wait_boot(vm, before, self.dev.target_slot, 120)
            time.sleep(delay)  # the kernel is booting the new slot, confirmation has not run yet
            vm.power_cut()
            runs_cut = self.boot_runs(vm)[before:]
        except Exception:
            vm.power_cut()
            raise
        vm2 = VM(disk, disk.parent, name="cutfb-after", uefi=self.uefi).start()
        try:
            ready = vm2.agent.wait(READY_S)
            st = self.state(vm2) if ready else {}
            runs_after = self.boot_runs(vm2)
            rc2 = None
            st2 = {}
            if ready:  # liveness: the update must still be installable
                rc2, _, _ = self.install(vm2, "v2")
                if rc2 == 0 and self.reboot(vm2):
                    st2 = self.state(vm2)
        finally:
            vm2.power_cut()
        safe = (st.get("slot"), st.get("version")) in self.good_states()
        live = (st2.get("slot"), st2.get("version")) == self.dev.updated
        path = "rescue rule" if any(r.get("rescue") for r in runs_after[:1]) else "regular boot-attempt logic"
        return {"verdict": "PASS" if safe and live else "FAIL" if not safe else "PARTIAL",
                "fallback_path": path,
                "detail": f"after cut booted {st.get('slot')}/{st.get('version')} via {path}; retry -> "
                          f"{st2.get('slot')}/{st2.get('version')}",
                "cut_after_boot_s": round(t or 0, 1), "boot_at_cut": runs_cut,
                "after_cut": st, "after_retry": st2, "install_rc": rc, "retry_rc": rc2, **pre}

    def crash_replay(self, points: int, liveness: int,
                     after_install: tuple[int, ...] = (0, 10, 20, 30, 45, 60)) -> dict:
        d = self.work / "replay"
        d.mkdir(exist_ok=True)
        log = d / "golden.log"
        tag_a, tag_b = (f"OTABENCH-MARK-{w}-{secrets.token_hex(6)}" for w in ("START", "END"))
        # 1. golden run with every write logged
        vm = self.fresh("replay", log=log)
        try:
            self.boot_confirmed(vm)
            self.mark(vm, tag_a, "mark-start")
            rc, t_inst, _ = self.install(vm, "v2")
            t_done = time.monotonic()
            for sec in after_install:  # markers at fixed times after the install returned
                time.sleep(max(0.0, t_done + sec - time.monotonic()))
                self.mark(vm, f"{tag_b}-{sec}", f"mark-end-{sec}")
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
        subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(self.dev.image), str(raw)],
                       check=True)
        t_conv = time.monotonic() - t
        applied, results = 0, []
        try:
            for k in cps:
                wl.apply(raw, applied, k + 1)
                applied = k + 1
                results.append(self._check_point(raw, k, wl, e0, e_inst, markers))
        except BaseException:
            raw.unlink(missing_ok=True)
            raise
        # 3. liveness: after a crash state, the update must still go through
        live = []
        if liveness:
            subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", str(self.dev.image),
                            str(raw)], check=True)
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
                        self.wait_confirmed(lvm, before.get("slot") or self.dev.initial_slot)
                        rc2, _, _ = self.install(lvm, "v2")  # goes to the *inactive* slot
                        if rc2 == 0 and self.reboot(lvm):
                            after = self.state(lvm)
                            ok = after.get("version") == self.dev.artifact("v2").version \
                                and after.get("slot") != before.get("slot")
                finally:
                    lvm.power_cut()
                live.append({"entry": k, "retry_ok": ok,
                             "before": f"{before.get('slot')}/{before.get('version')}",
                             "after": f"{after.get('slot')}/{after.get('version')}"})
                print(f"    liveness@{k}: {'ok' if ok else 'FAILED'} {live[-1]['before']} -> "
                      f"{live[-1]['after']}", flush=True)
        raw.unlink(missing_ok=True)
        counts = _counts(results)
        switch = next((r["entry"] for r in results if r["slot"] == self.dev.target_slot), None)
        window = {r["after_install_s"]: {"slot": r["slot"], "boot_order": r["boot_order"],
                                         "os_order": r["os_order"]}
                  for r in results if r["after_install_s"] is not None}
        bad = counts["INCONSISTENT"] + counts["BRICK"]
        return {"verdict": "PASS" if not bad and all(x["retry_ok"] for x in live) else
                "FAIL" if bad else "PARTIAL",
                "log": {"entries_total": len(wl), "superblock_entries": wl.nr_super,
                        "install_window": [e0, e1], **win},
                "install_rc": rc, "install_s": round(t_inst, 1), "raw_convert_s": round(t_conv, 1),
                "install_entry": e_inst,
                "crash_points": len(results), "counts": counts,
                "first_point_booting_target": switch, "after_install_window": window,
                "diverged_points": sum(r["diverged"] for r in results),
                "mean_check_s": round(sum(r["check_s"] for r in results) / max(1, len(results)), 1),
                "points": results, "liveness": live}


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


RUN_INFO: dict = {}


def save(stamp: str, results: dict) -> None:
    out_dir = ROOT / "results" / f"pilot-ab-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pilot.json").write_text(json.dumps(
        {"started": stamp, "bench_version": __version__,
         "host": "Windows 11 + QEMU 11.1 WHPX", **RUN_INFO, "results": results},
        indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--updater", default="rauc-grub",
                    help="device adapter: bench/updaters/<name>.yaml (or a path to a .yaml)")
    ap.add_argument("--only", default="")
    ap.add_argument("--points", type=int, default=30)
    ap.add_argument("--liveness", type=int, default=3)
    ap.add_argument("--window", default="0,2,4,6,8,10,20,30",
                    help="crash-replay: seconds after the install returns at which markers are taken")
    ap.add_argument("--region", type=int, default=24,
                    help="window/reorder: replay every entry this far before install completion")
    ap.add_argument("--offsets", default="0,1,2,3,4,5,6,8,10,15,20,30")
    ap.add_argument("--torn", action="store_true",
                    help="reorder: also tear multi-sector writes at sector granularity")
    ap.add_argument("--settle", type=float, default=0.0,
                    help="reorder: wait this long after the install before the end marker")
    ap.add_argument("--sample-intervals", type=int, default=15,
                    help="reorder --region-at window: barrier intervals sampled over the install")
    ap.add_argument("--region-at", choices=("end", "env", "window"), default="end",
                    help="reorder: region before the end marker (default) or around the "
                         "boot-environment writes, incl. the open interval after the last flush")
    ap.add_argument("--work", default="")
    ap.add_argument("--variant-dir", default=str(VARIANT_DIR))
    ap.add_argument("--keep-disks", action="store_true",
                    help="keep per-scenario qcow2 overlays (~1.2 GB each) for post-mortem")
    a = ap.parse_args()
    dev = Device(a.updater, Path(a.updater) if a.updater.endswith(".yaml") else None)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    work = Path(a.work) if a.work else Path(r"P:\vm\pilot") / stamp
    p = Pilot(work, dev, Path(a.variant_dir))
    p.torn = a.torn
    p.settle, p.region_at, p.sample_intervals = a.settle, a.region_at, a.sample_intervals
    RUN_INFO.update(params=vars(a), git_commit=_git_commit(), check_ready_s=CHECK_READY_S)
    plan = {"happy": p.happy, "broken": p.broken, "attacker": p.attacker,
            "downgrade": p.downgrade, "cut-firstboot": p.cut_firstboot, "toctou": p.toctou,
            **{f"net-{k}": (lambda k: lambda: p.net(k))(k) for k in ("ok", "tamper", "drop", "slow", "endless")},
            "broken-unconfirmed": lambda: p.broken(confirm=False),
            "cut-unconfirmed": lambda: p.cut_firstboot(confirm=False),
            "crash-replay": lambda: p.crash_replay(
                a.points, a.liveness, tuple(int(x) for x in a.window.split(",")))}
    offs = tuple(int(x) for x in a.offsets.split(","))
    for cfg in dev.variants:
        plan[f"window:{cfg}"] = (lambda c: lambda: p.window(c, offs, a.region))(cfg)
        plan[f"reorder:{cfg}"] = (lambda c: lambda: p.reorder(c, a.region))(cfg)
        plan[f"happy:{cfg}"] = (lambda c: lambda: p.happy_variant(c))(cfg)
        for sname, fn in (("broken", p.broken), ("attacker", p.attacker),
                          ("downgrade", p.downgrade), ("cut-firstboot", p.cut_firstboot)):
            plan[f"{sname}:{cfg}"] = (lambda c, f: lambda: p.on_variant(c, f))(cfg, fn)
        for k in ("ok", "tamper", "drop", "slow", "endless"):
            plan[f"net-{k}:{cfg}"] = (lambda c, k: lambda: p.on_variant(c, lambda: p.net(k)))(cfg, k)
    names = a.only.split(",") if a.only else list(plan)
    unknown = [n for n in names if n not in plan]
    if unknown:
        ap.error(f"unknown scenario(s) {unknown}; known: {', '.join(plan)}")
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
        RUN_INFO["updater"] = {"adapter": dev.name, "file": str(dev.file.relative_to(ROOT))
                               if dev.file.is_relative_to(ROOT) else str(dev.file),
                               "version": p.updater_version, "image": str(dev.image)}
        save(stamp, results)  # incremental: a long run never loses finished scenarios
    print(f"\nresults: {ROOT / 'results' / f'pilot-ab-{stamp}' / 'pilot.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
