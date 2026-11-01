"""Which partitions receive writes during an install (from a blklogwrites golden.log).

OTA-PWR-06 is about writes to the RUNNING slot while the inactive one is installed; this
counts them, per partition, between the START and the first END marker of a pilot run.

  python slot_writes.py P:/vm/pilot/<run>/reorder-ext4-inplace/golden.log [...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.writelog import WriteLog  # noqa: E402

# ab-v1.qcow2 (scripts/build_ab_image.py), 512-byte sectors, read from /sys/block/vda/*
LAYOUT = {"vda1 (slot A)": (262144, 6027264), "vda2 (slot B)": (6289408, 6027264),
          "vda3 (/boot-ab)": (12316672, 524288), "vda4 (/data)": (12840960, 12322816),
          "vda15 (ESP)": (8192, 253952), "vda14 (BIOS boot)": (2048, 6144)}


def part_of(sector: int) -> str:
    for name, (start, size) in LAYOUT.items():
        if start <= sector < start + size:
            return name
    return "other"


def analyse(log: Path) -> dict:
    wl = WriteLog(log)
    e0 = wl.find(b"OTABENCH-MARK-START-")
    e1 = wl.find(b"OTABENCH-MARK-END-", e0)
    out: dict[str, dict] = {}
    for e in wl.entries[e0:e1 + 1]:
        if not e.is_write:
            continue
        r = out.setdefault(part_of(e.sector), {"writes": 0, "sectors": 0})
        r["writes"] += 1
        r["sectors"] += e.nr_sectors
    return {"log": str(log), "window": [e0, e1], "partitions": out}


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    for arg in sys.argv[1:]:
        print(json.dumps(analyse(Path(arg)), ensure_ascii=False, indent=1))
