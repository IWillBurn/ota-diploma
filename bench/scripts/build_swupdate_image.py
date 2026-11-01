"""Build the A/B image for SWUpdate (backlog A3): the same disk layout and grub.cfg as the
RAUC image, but the update is installed by SWUpdate (Debian 12 bookworm-backports,
2024.12.1; its GRUB env writer is identical in 2026.05.1).

SWUpdate does not implement A/B selection itself; as in typical GRUB integrations the
bootloader script decides. The integration therefore reuses grub.cfg and its variables
(ORDER, <S>_OK, <S>_TRY): the .swu sets them in its `bootenv` section through SWUpdate's
own GRUB env writer, which writes `grubenv.new` and renames it over `grubenv`. SWUpdate
writes the env at the path compiled into the package (/boot/grub/grubenv), so /boot-ab/grub
is bind-mounted on /boot/grub. A boot is confirmed by the image itself
(otabench-mark-good.service -> grub-editenv, as the integrator would do).

Artifacts in /data/swu (sw-description signed with CMS, rootfs gzip-compressed):
  v1.swu  v2.swu  v2-broken.swu (PID 1 exits)  v2-attacker.swu (foreign key)

  python build_swupdate_image.py [--out P:/vm/ab-v1-swupdate.qcow2]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_ab_image import serve  # noqa: E402

from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402

GUEST = ROOT / "vm" / "guest"  # served to the guest; SWUpdate files in swupdate/

STEPS = [
    ("swupdate package",
     "echo 'deb http://deb.debian.org/debian bookworm-backports main' > "
     "/etc/apt/sources.list.d/bookworm-backports.list && apt-get update -qq && "
     "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cpio && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -t bookworm-backports swupdate "
     ">/dev/null && dpkg-query -W -f='${Version}\\n' swupdate && "
     "for u in swupdate.service swupdate.socket swupdate-progress.service rauc.service; do "
     "systemctl disable --now $u 2>/dev/null || true; done && systemctl mask rauc.service", 1200),
    ("grub env path",
     "mkdir -p /boot/grub && grep -q ' /boot/grub ' /etc/fstab || "
     "echo '/boot-ab/grub /boot/grub none bind,nofail 0 0' >> /etc/fstab; "
     "mountpoint -q /boot/grub || mount --bind /boot-ab/grub /boot/grub; "
     "test \"$(stat -c %d:%i /boot/grub/grubenv)\" = \"$(stat -c %d:%i /boot-ab/grub/grubenv)\"", 60),
    ("confirmation + keys",
     "curl -fsS http://10.0.2.2:@PORT@/swupdate/otabench-mark-good -o /usr/local/sbin/otabench-mark-good && "
     "chmod 755 /usr/local/sbin/otabench-mark-good && "
     "curl -fsS http://10.0.2.2:@PORT@/swupdate/otabench-mark-good.service "
     "-o /etc/systemd/system/otabench-mark-good.service && systemctl daemon-reload && "
     "systemctl enable -q otabench-mark-good.service && mkdir -p /etc/swupdate && "
     "cp /data/keys/dev.cert.pem /etc/swupdate/dev.cert.pem && "
     "curl -fsS http://10.0.2.2:@PORT@/swupdate/sw-description.in -o /root/sw-description.in && "
     "curl -fsS http://10.0.2.2:@PORT@/swupdate/mk-swu -o /usr/local/sbin/otabench-mk-swu && "
     "chmod 755 /usr/local/sbin/otabench-mk-swu && echo 1.0.0 > /etc/otabench-semver && /usr/local/sbin/otabench-mark-good && "
     "grub-editenv /boot-ab/grub/grubenv list", 120),
    ("staging rootfs",
     "rm -rf /data/bundles /data/staging && mkdir -p /data/staging /data/swu && "
     "cp -ax /. /data/staging/ && rm -rf /data/staging/usr/share/doc/* /data/staging/usr/share/man/* "
     "/data/staging/usr/share/locale/* /data/staging/var/lib/apt/lists/* "
     "/data/staging/var/cache/apt/*.bin && du -sxh /data/staging", 900),
    ("swu v1", "otabench-mk-swu v1 1 1.0.0 dev", 1500),
    ("swu v2", "otabench-mk-swu v2 2 2.0.0 dev", 1500),
    ("swu v2-attacker", "otabench-mk-swu v2-attacker 2 2.0.0 attacker", 1500),
    ("swu v2-broken",
     "rm -f /data/staging/usr/sbin/init && "
     "curl -fsS http://10.0.2.2:@PORT@/broken-init -o /data/staging/usr/sbin/init && "
     "chmod 755 /data/staging/usr/sbin/init && otabench-mk-swu v2-broken 2-broken 2.0.0 dev", 1500),
    ("cleanup", "rm -rf /data/staging && ls -lh /data/swu && sync && fstrim -av >/dev/null", 300),
]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=r"P:\vm\ab-v1.qcow2")
    ap.add_argument("--out", default=r"P:\vm\ab-v1-swupdate.qcow2")
    ap.add_argument("--work", default=r"P:\vm\build-swupdate")
    a = ap.parse_args()
    out, work = Path(a.out), Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    port = serve(GUEST)
    disk = make_overlay(Path(a.base), work / "swupdate.qcow2")
    vm = VM(disk, work, net=True, mem=2048, smp=4, name="swupdate").start()
    t0 = time.monotonic()
    try:
        if not vm.agent.wait(240):
            raise RuntimeError("guest agent did not come up")
        for name, cmd, timeout in STEPS:
            t = time.monotonic()
            print(f"[{time.monotonic() - t0:6.0f}s] {name} ...", flush=True)
            rc, so, se = vm.agent.sh("set -e\n" + cmd.replace("@PORT@", str(port)), timeout)
            tail = "\n".join((so + se).strip().splitlines()[-8:])
            print(f"           rc={rc} in {time.monotonic() - t:.0f}s" + (f"\n{tail}" if tail else ""),
                  flush=True)
            if rc != 0:
                raise RuntimeError(f"step {name} failed")
        vm.shutdown(120)
    except Exception:
        vm.power_cut()
        raise
    print("flattening ->", out, flush=True)
    out.unlink(missing_ok=True)
    subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "qcow2", str(disk), str(out)], check=True)
    disk.unlink(missing_ok=True)
    print(f"done in {time.monotonic() - t0:.0f}s: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
