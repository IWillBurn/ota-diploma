"""Build the A/B pilot image: Debian 12 + RAUC 1.8 + GRUB slot selection.

Disk layout (GPT, 12 GiB):
  vda14 BIOS boot  -> GRUB core, prefix (hd0,gpt3)/grub
  vda15 EFI        (unused)
  vda1  rootfs A   = the original Debian root, version 1   (slot rootfs.0, bootname A)
  vda2  rootfs B   same size as A                          (slot rootfs.1, bootname B)
  vda3  boot       GRUB modules, grub.cfg, grubenv  -> /boot-ab
  vda4  data       RAUC status file, bundles, keys  -> /data

Bundles left in /data/bundles (all signed with the dev key unless stated):
  v1.raucb  v2.raucb  v2-broken.raucb (PID 1 exits)  v2-attacker.raucb (foreign key)

  python build_ab_image.py --base P:/vm/debian-12-nocloud-amd64.qcow2 --out P:/vm/ab-v1.qcow2
"""

from __future__ import annotations

import argparse
import functools
import json
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402

GUEST = ROOT / "vm" / "guest"
LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


def serve(directory: Path) -> int:
    handler = functools.partial(_Quiet, directory=str(directory))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def steps(port: int) -> list[tuple[str, str, int]]:
    get = f"curl -fsS http://10.0.2.2:{port}"
    variant = r"""
mk_variant() {  # $1=name $2=version $3=key-prefix  (no `set -e`: it would kill the login shell)
  echo "$2" > /data/staging/etc/otabench-version &&
  sz=$(du -sxm /data/staging | cut -f1) && img=$((sz * 125 / 100 + 64)) &&
  mkdir -p /data/b-$1 &&
  mkfs.ext4 -q -F -L rootfs -d /data/staging /data/b-$1/rootfs.ext4 ${img}M &&
  sed "s/@VERSION@/$2/" /root/manifest.raucm > /data/b-$1/manifest.raucm &&
  rauc bundle --cert=/data/keys/$3.cert.pem --key=/data/keys/$3.key.pem /data/b-$1 /data/bundles/$1.raucb &&
  rm -rf /data/b-$1
}"""
    return [
        ("packages", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                     "fdisk rauc rauc-service qemu-guest-agent squashfs-tools >/dev/null", 900),
        ("partition B/boot/data",
         "sfdisk --relocate gpt-bak-std /dev/vda && A=$(blockdev --getsz /dev/vda1) && "
         f"printf 'size=%s, type={LINUX}, name=rootfs-B\\nsize=256MiB, type={LINUX}, name=boot\\n"
         f"type={LINUX}, name=data\\n' $A | sfdisk --append --no-reread --force /dev/vda && "
         "(partx -a /dev/vda 2>/dev/null; true) && udevadm settle && "
         "test -b /dev/vda2 -a -b /dev/vda3 -a -b /dev/vda4 && lsblk -o NAME,SIZE /dev/vda", 120),
        ("filesystems", "mkfs.ext4 -q -F -L boot /dev/vda3 && mkfs.ext4 -q -F -L data /dev/vda4 && "
                        "mkdir -p /boot-ab /data && mount /dev/vda3 /boot-ab && mount /dev/vda4 /data", 120),
        ("grub", f"grub-install --target=i386-pc --boot-directory=/boot-ab --modules='part_gpt ext2' "
                 f"/dev/vda && {get}/grub.cfg -o /boot-ab/grub/grub.cfg && "
                 "sed -i \"s/@KVER@/$(uname -r)/g\" /boot-ab/grub/grub.cfg && "
                 "grub-editenv /boot-ab/grub/grubenv create && "
                 "grub-editenv /boot-ab/grub/grubenv set 'ORDER=A B' A_OK=1 A_TRY=0 B_OK=0 B_TRY=0 && "
                 "grub-editenv /boot-ab/grub/grubenv list", 120),
        ("fstab", f"{get}/fstab -o /etc/fstab && echo 1 > /etc/otabench-version", 30),
        ("rauc config", f"mkdir -p /etc/rauc /data/keys /data/bundles && {get}/system.conf -o "
                        f"/etc/rauc/system.conf && {get}/otabench-mark-good.service -o "
                        "/etc/systemd/system/otabench-mark-good.service && systemctl enable -q "
                        f"otabench-mark-good.service && {get}/manifest.raucm -o /root/manifest.raucm", 60),
        ("keys", "cd /data/keys && for k in dev attacker; do openssl req -x509 -newkey rsa:2048 "
                 "-nodes -days 3650 -subj /CN=otabench-$k -keyout $k.key.pem -out $k.cert.pem "
                 "2>/dev/null; done && cp dev.cert.pem /etc/rauc/keyring.pem && cd /", 60),
        ("staging rootfs", "mkdir -p /data/staging && cp -ax /. /data/staging/ && "
                           "rm -rf /data/staging/usr/share/doc/* /data/staging/usr/share/man/* "
                           "/data/staging/usr/share/locale/* /data/staging/var/lib/apt/lists/* "
                           "/data/staging/var/cache/apt/*.bin && du -sxh /data/staging", 900),
        ("bundle v1", variant + "\nmk_variant v1 1 dev", 1200),
        ("bundle v2", variant + "\nmk_variant v2 2 dev", 1200),
        ("bundle v2-attacker", variant + "\nmk_variant v2-attacker 2 attacker", 1200),
        ("bundle v2-broken", f"rm -f /data/staging/usr/sbin/init && {get}/broken-init -o "
                             "/data/staging/usr/sbin/init && chmod 755 /data/staging/usr/sbin/init"
                             + variant + "\nmk_variant v2-broken 2-broken dev", 1200),
        ("cleanup", "rm -rf /data/staging && ls -lh /data/bundles && sync && fstrim -av", 300),
    ]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=r"P:\vm\debian-12-nocloud-amd64.qcow2")
    ap.add_argument("--out", default=r"P:\vm\ab-v1.qcow2")
    ap.add_argument("--work", default=r"P:\vm\build")
    a = ap.parse_args()
    work, out = Path(a.work), Path(a.out)
    work.mkdir(parents=True, exist_ok=True)
    (work / "build-serial.log").unlink(missing_ok=True)

    port = serve(GUEST)
    disk = make_overlay(Path(a.base), work / "build.qcow2", size="12G")
    vm = VM(disk, work, net=True, mem=2048, smp=4, name="build", discard=True).start()
    t0 = time.monotonic()
    try:
        con = vm.console()
        con.login()
        for name, cmd, timeout in steps(port):
            t = time.monotonic()
            print(f"[{time.monotonic() - t0:6.0f}s] {name} ...", flush=True)
            res = con.run(cmd, timeout)
            tail = "\n".join(res.strip().splitlines()[-6:])
            print(f"           done in {time.monotonic() - t:.0f}s" + (f"\n{tail}" if tail else ""),
                  flush=True)
        con.send("systemctl poweroff\n")
        if not vm.wait_exit(120):
            vm.power_cut()
    except Exception:
        vm.power_cut()
        raise

    print("flattening ->", out, flush=True)
    out.unlink(missing_ok=True)
    subprocess.run([qemu_exe("qemu-img"), "convert", "-O", "qcow2", str(disk), str(out)], check=True)
    disk.unlink(missing_ok=True)  # the build overlay (~2.4 GB) is no longer needed
    info = json.loads(subprocess.run([qemu_exe("qemu-img"), "info", "--output=json", str(out)],
                                     capture_output=True, text=True, check=True).stdout)
    print(f"image: virtual {info['virtual-size'] / 2**30:.0f} GiB, "
          f"on disk {info['actual-size'] / 2**30:.2f} GiB; total {time.monotonic() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
