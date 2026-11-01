"""Post-mortem tool: rebuild one crash state from a saved write log, boot it, inspect it,
and optionally check liveness (can the next update still be installed?).

  python replay_state.py --base P:/vm/variants/ab-vfat.qcow2 \
      --log P:/vm/pilot/20261101-103655/reorder-vfat/golden.log \
      --base-end 1568 --extra 1569 [--liveness]

State = log entries [0, base_end) applied in order, plus the listed `extra` entries
(e.g. one surviving volatile write), exactly as WriteLog.crash_states() builds them.
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
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402
from otabench.writelog import WriteLog  # noqa: E402

PROBE = ("sed -n 's/.*rauc.slot=\\([AB]\\).*/\\1/p' /proc/cmdline; cat /etc/otabench-version;"
         " echo ---; ls -l /boot-ab/grub/grubenv; grub-editenv /boot-ab/grub/grubenv list 2>&1;"
         " echo ---; rauc status --output-format=json 2>&1 | head -c 600")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--base-end", type=int, required=True)
    ap.add_argument("--extra", default="", help="comma-separated entry indices")
    ap.add_argument("--liveness", action="store_true")
    ap.add_argument("--work", default=r"P:\vm\postmortem")
    a = ap.parse_args()
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    extra = [int(x) for x in a.extra.split(",") if x]
    wl = WriteLog(Path(a.log))
    raw = work / "state.raw"
    subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "raw", a.base, str(raw)], check=True)
    out = {"base_end": a.base_end, "extra": extra}
    try:
        wl.apply(raw, 0, a.base_end)
        wl.apply_with_undo(raw, extra)
        ov = make_overlay(raw, work / "state.qcow2", "raw")
        name = f"state-{a.base_end}-{'-'.join(map(str, extra)) or 'none'}"
        vm = VM(ov, work, name=name).start()
        try:
            ready = vm.agent.wait(150)
            out["ready"] = ready
            grub = [ln.strip() for ln in vm.serial_text().splitlines() if "otabench-grub" in ln]
            out["grub"] = grub
            if ready:
                out["probe"] = vm.agent.sh(PROBE, 60)[1]
                if a.liveness:
                    t = time.monotonic()
                    rc, o, e = vm.agent.sh("rauc install /data/bundles/v2.raucb", 1200)
                    out["install"] = {"rc": rc, "s": round(time.monotonic() - t, 1),
                                      "msg": (o + e).strip().splitlines()[-3:]}
                    if rc == 0:
                        n = len(grub)
                        vm.agent.spawn("sleep 1; systemctl reboot")
                        deadline = time.monotonic() + 150
                        while time.monotonic() < deadline and vm.serial_text().count("otabench-grub:") <= n:
                            time.sleep(0.5)
                        out["after_reboot_ready"] = vm.agent.wait(150)
                        if out["after_reboot_ready"]:
                            out["after_reboot"] = vm.agent.sh(PROBE, 60)[1]
                        out["grub_after"] = [ln.strip() for ln in vm.serial_text().splitlines()
                                             if "otabench-grub" in ln][len(grub):]
        finally:
            vm.power_cut()
            ov.unlink(missing_ok=True)
    finally:
        raw.unlink(missing_ok=True)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
