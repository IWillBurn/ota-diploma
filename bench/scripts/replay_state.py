"""Post-mortem tool: rebuild one crash state from a saved write log, boot it, inspect it,
and optionally check liveness (can the next update still be installed?).

  python replay_state.py --base P:/vm/variants/ab-vfat.qcow2 \
      --log P:/vm/pilot/20261101-103655/reorder-vfat/golden.log \
      --base-end 1568 --extra 1569 [--liveness] [--updater rauc-grub]

State = log entries [0, base_end) applied in order, plus the listed `extra` entries
(e.g. one surviving volatile write), exactly as WriteLog.crash_states() builds them.
`--base` must be the very disk the log was recorded on (a log only replays onto the
same bytes), so logs recorded before adapter v2 keep their old `ab-<variant>` bases.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.device import Device  # noqa: E402
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402
from otabench.writelog import WriteLog  # noqa: E402


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--base-end", type=int, required=True)
    ap.add_argument("--extra", default="", help="comma-separated entry indices")
    ap.add_argument("--partial", default="", help="torn write: ENTRY,SECTORS (first k sectors only)")
    ap.add_argument("--liveness", action="store_true")
    ap.add_argument("--uefi", action="store_true", help="boot with OVMF (uefi-* variants)")
    ap.add_argument("--updater", default="rauc-grub", help="device adapter (bench/updaters/<name>.yaml)")
    ap.add_argument("--work", default=r"P:\vm\postmortem")
    a = ap.parse_args()
    dev = Device(a.updater, Path(a.updater) if a.updater.endswith(".yaml") else None)
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    extra = [int(x) for x in a.extra.split(",") if x]
    wl = WriteLog(Path(a.log))
    raw = work / "state.raw"
    subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", a.base, str(raw)], check=True)
    out = {"base_end": a.base_end, "extra": extra}
    try:
        wl.apply(raw, 0, a.base_end)
        partial = [int(x) for x in a.partial.split(",")] if a.partial else None
        wl.apply_with_undo(raw, extra, partial)
        out["partial"] = partial
        ov = make_overlay(raw, work / "state.qcow2", "raw")
        name = f"state-{a.base_end}-{'-'.join(map(str, extra)) or 'none'}"
        vm = VM(ov, work, name=name, uefi=a.uefi).start()
        try:
            ready = vm.agent.wait(120)  # = CHECK_READY_S in pilot_ab.py
            out["ready"] = ready
            runs = dev.boot_runs(vm.serial_text())
            out["boot_runs"] = runs
            if ready:
                out["status"] = dev.status(vm)
                out["probe"] = dev.debug(vm)
                if a.liveness:
                    rc, secs, last = dev.install(vm, "v2")
                    out["install"] = {"rc": rc, "s": round(secs, 1), "msg": last}
                    if rc == 0:
                        vm.agent.spawn("sleep 1; " + dev.cmd_reboot)
                        deadline = time.monotonic() + 150
                        while time.monotonic() < deadline and \
                                len(dev.boot_runs(vm.serial_text())) <= len(runs):
                            time.sleep(0.5)
                        out["after_reboot_ready"] = vm.agent.wait(150)
                        if out["after_reboot_ready"]:
                            out["after_reboot"] = dev.status(vm)
                        out["boot_runs_after"] = dev.boot_runs(vm.serial_text())[len(runs):]
        finally:
            vm.power_cut()
            ov.unlink(missing_ok=True)
    finally:
        raw.unlink(missing_ok=True)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
