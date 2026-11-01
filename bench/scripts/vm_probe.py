"""Probe the VM toolchain of this host: boot a guest, time it, optionally log every
block write (QEMU blklogwrites, dm-log-writes format), then cut power via QMP.

  python vm_probe.py --base P:/vm/debian-12-nocloud-amd64.qcow2 --work DIR [--accel whpx] [--log-writes]

Prints seconds-to-login, size/number of logged writes, and the QMP power-cut result.
This is the seed of the system-level runner (level 3 power-cut + level 2 write log).
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

QEMU_DIR = Path(r"C:\Program Files\qemu")


def exe(name: str) -> str:
    p = QEMU_DIR / f"{name}.exe"
    return str(p) if p.exists() else (shutil.which(name) or name)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def qmp(port: int, command: str) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        f = s.makefile("r", encoding="utf-8")
        f.readline()  # greeting
        for name in ("qmp_capabilities", command):
            s.sendall(json.dumps({"execute": name}).encode() + b"\n")
            while True:
                line = f.readline()
                if not line:
                    return {"closed": True}
                msg = json.loads(line)
                if "return" in msg or "error" in msg:
                    break
        return msg


def count_log_entries(path: Path) -> tuple[int, int]:
    """dm-log-writes superblock: magic u64, version u64, nr_entries u64, sectorsize u32."""
    try:
        with open(path, "rb") as f:
            magic, version, nr, sector = struct.unpack("<QQQI", f.read(28))
        return (nr, sector) if magic == 0x6A736677736872 else (-1, 0)
    except (OSError, struct.error):
        return (-1, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--accel", default="whpx,kernel-irqchip=off")
    ap.add_argument("--log-writes", action="store_true")
    ap.add_argument("--timeout", type=float, default=300)
    a = ap.parse_args()

    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    disk = work / "probe.qcow2"
    serial = work / "serial.log"
    wlog = work / "writes.log"
    for p in (disk, serial, wlog):
        p.unlink(missing_ok=True)
    subprocess.run([exe("qemu-img"), "create", "-q", "-f", "qcow2", "-b",
                    str(Path(a.base).resolve()), "-F", "qcow2", str(disk)], check=True)

    port = free_port()
    cmd = [exe("qemu-system-x86_64"), "-accel", a.accel, "-m", "1024", "-smp", "2",
           "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
           "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off", "-nic", "none"]
    if a.log_writes:
        wlog.write_bytes(b"")
        cmd += ["-blockdev", f"driver=file,node-name=f0,filename={disk}",
                "-blockdev", "driver=qcow2,node-name=disk,file=f0",
                "-blockdev", f"driver=file,node-name=logf,filename={wlog}",
                "-blockdev", "driver=blklogwrites,node-name=logged,file=disk,log=logf",
                "-device", "virtio-blk-pci,drive=logged"]
    else:
        cmd += ["-drive", f"file={disk},if=virtio,format=qcow2"]

    t0 = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    booted = None
    while time.monotonic() - t0 < a.timeout:
        if proc.poll() is not None:
            print("QEMU exited early:", proc.stdout.read().decode(errors="replace")[-800:])
            return 1
        try:
            if b"login:" in serial.read_bytes():
                booted = time.monotonic() - t0
                break
        except OSError:
            pass
        time.sleep(0.2)

    print(f"accel={a.accel} log_writes={a.log_writes}")
    print(f"seconds_to_login={booted:.1f}" if booted else f"no login prompt within {a.timeout}s")
    if a.log_writes:
        nr, sector = count_log_entries(wlog)
        size = wlog.stat().st_size if wlog.exists() else 0
        print(f"write_log: {size / 1048576:.1f} MiB, entries={nr}, sectorsize={sector}")
    print("power cut:", qmp(port, "quit"))
    proc.wait(10)
    return 0 if booted else 1


if __name__ == "__main__":
    sys.exit(main())
