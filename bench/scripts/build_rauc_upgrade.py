"""Build the A/B image with a current upstream RAUC (backlog C1).

Starts from ab-v1.qcow2 (Debian 12 + the Debian package RAUC 1.8), builds RAUC from the
release tarball inside the guest and installs it over the package (/usr prefix, same
systemd and D-Bus files), then rebuilds the v2 bundle from the upgraded slot A so that
slot B runs the same RAUC. v1, v2-broken and v2-attacker stay as they are: their content
is the downgrade target, an unbootable image and a foreign-key bundle.

The tarball is downloaded on the host, checked against the SHA-256 below and served to
the guest over QEMU user networking (10.0.2.2), like build_ab_image.py does.

  python build_rauc_upgrade.py [--version 1.15.2] [--out P:/vm/ab-v1-rauc1.15.2.qcow2]
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from build_ab_image import serve  # noqa: E402

from otabench.device import Device  # noqa: E402
from otabench.vm import VM, make_overlay, qemu_exe  # noqa: E402

RELEASES = {  # version -> SHA-256 of rauc-<version>.tar.xz (GitHub release asset)
    "1.15.2": "127a24cde208c65b837ae978c695a00730f1094ee8b6c7d48cf58ef846eae340",
}
BUILD_DEPS = ("build-essential meson ninja-build pkg-config libglib2.0-dev libssl-dev "
              "libjson-glib-dev libdbus-1-dev libcurl4-openssl-dev libnl-genl-3-dev libfdisk-dev")
RUNTIME_LIBS = ("libglib2.0-0 libssl3 libjson-glib-1.0-0 libdbus-1-3 libcurl4 libnl-3-200 "
                "libnl-genl-3-200 libfdisk1")


def steps(port: int, version: str, sha: str) -> list[tuple[str, str, int]]:
    tar = f"rauc-{version}.tar.xz"
    return [
        ("build deps", "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                       f"--no-install-recommends {BUILD_DEPS} xz-utils >/dev/null && apt-mark hold rauc "
                       f"rauc-service >/dev/null && apt-mark manual {RUNTIME_LIBS} >/dev/null", 1500),
        ("source", f"cd /root && curl -fsS http://10.0.2.2:{port}/{tar} -o {tar} && "
                   f"echo '{sha}  {tar}' | sha256sum -c - && tar -xJf {tar}", 120),
        ("configure", f"cd /root/rauc-{version} && meson setup build --prefix=/usr --sysconfdir=/etc "
                      "--localstatedir=/var -Dtests=false -Dhtmldocs=false -Dmanpages=false "
                      "-Dstreaming=true -Dnetwork=true -Dgpt=enabled 2>&1 | tail -25", 600),
        ("compile + install", f"cd /root/rauc-{version} && ninja -C build >/dev/null && "
                              "ninja -C build install >/dev/null && hash -r && rauc --version", 1800),
        ("service", "systemctl daemon-reload && systemctl restart rauc && sleep 1 && "
                    "rauc status --output-format=json >/dev/null && rauc status mark-good && "
                    "if ldd /usr/bin/rauc | grep 'not found'; then exit 3; fi && rauc --version", 120),
        ("remove build deps", f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq {BUILD_DEPS} "
                              ">/dev/null && apt-get autoremove -y -qq --purge >/dev/null && "
                              f"apt-get clean && rm -rf /root/rauc-{version} /root/{tar} && "
                              "if ldd /usr/bin/rauc | grep 'not found'; then exit 3; fi && rauc --version", 900),
    ]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.15.2", choices=sorted(RELEASES))
    ap.add_argument("--base", default=r"P:\vm\ab-v1.qcow2")
    ap.add_argument("--out", default="")
    ap.add_argument("--work", default=r"P:\vm\build-rauc")
    a = ap.parse_args()
    out = Path(a.out or rf"P:\vm\ab-v1-rauc{a.version}.qcow2")
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    src = work / "src"
    src.mkdir(exist_ok=True)
    tar = src / f"rauc-{a.version}.tar.xz"
    if not tar.exists():
        url = f"https://github.com/rauc/rauc/releases/download/v{a.version}/{tar.name}"
        print("download", url, flush=True)
        urllib.request.urlretrieve(url, tar)  # noqa: S310 (fixed https URL)
    sha = hashlib.sha256(tar.read_bytes()).hexdigest()
    if sha != RELEASES[a.version]:
        raise SystemExit(f"{tar.name}: sha256 {sha} != {RELEASES[a.version]}")
    port = serve(src)
    dev = Device("rauc-grub")
    disk = make_overlay(Path(a.base), work / "upgrade.qcow2")
    vm = VM(disk, work, net=True, mem=2048, smp=4, name="upgrade").start()
    t0 = time.monotonic()
    try:
        if not vm.agent.wait(240):
            raise RuntimeError("guest agent did not come up")
        for name, cmd, timeout in steps(port, a.version, sha) + [
                ("rebundle v2", dict(dev.variant_scripts("ext4-inplace"))["rebundle"], 1500)]:
            t = time.monotonic()
            print(f"[{time.monotonic() - t0:6.0f}s] {name} ...", flush=True)
            rc, so, se = vm.agent.sh(cmd if cmd.startswith("set -e") else "set -e\n" + cmd, timeout)
            tail = "\n".join((so + se).strip().splitlines()[-6:])
            print(f"           rc={rc} in {time.monotonic() - t:.0f}s" + (f"\n{tail}" if tail else ""),
                  flush=True)
            if rc != 0:
                raise RuntimeError(f"step {name} failed")
        print("version in guest:", dev.version(vm), flush=True)
        vm.agent.sh("sync; fstrim -av >/dev/null 2>&1; true", 300)
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
