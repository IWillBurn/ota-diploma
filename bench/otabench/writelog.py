"""dm-log-writes log reader/replayer (the format QEMU's `blklogwrites` driver writes).

Layout: sector 0 = superblock {u64 magic, u64 version, u64 nr_entries, u32 sectorsize};
then for every request one header sector {u64 sector, u64 nr_sectors, u64 flags,
u64 data_len} padded to sectorsize, followed by the written data (writes and
write-zeroes carry data, flush/discard do not, marks carry data_len bytes).

Two replay models:
* prefix (WriteLog.apply): crash state k = the disk at log start with entries 0..k
  applied in order. Every prefix is a state a disk may expose after power loss, but
  prefixes are only a SUBSET of what a disk with a volatile write cache can expose;
* reordering (WriteLog.crash_states): between two FLUSH barriers any subset of the
  unflushed writes may persist (bounded subsets; optionally sector-torn writes).
  Writes after the last FLUSH of the selected region are not permuted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

MAGIC = 0x6A736677736872
FLUSH, FUA, DISCARD, MARK = 1, 2, 4, 8


@dataclass
class Entry:
    idx: int
    sector: int
    nr_sectors: int
    flags: int
    data_off: int  # offset of the payload in the log file, 0 = none

    @property
    def is_write(self) -> bool:
        return self.nr_sectors > 0 and not self.flags & (DISCARD | MARK)

    @property
    def is_barrier(self) -> bool:
        return bool(self.flags & (FLUSH | FUA))


class WriteLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        size = self.path.stat().st_size
        with open(self.path, "rb") as f:
            magic, self.version, self.nr_super, self.sectorsize = struct.unpack("<QQQI", f.read(28))
            if magic != MAGIC:
                raise ValueError(f"{path}: not a dm-log-writes log (magic {magic:#x})")
            ss = self.sectorsize
            self.entries: list[Entry] = []
            pos = ss
            while pos + ss <= size:
                f.seek(pos)
                sector, nr, flags, data_len = struct.unpack("<QQQQ", f.read(32))
                if flags & MARK:
                    dlen = -(-data_len // ss) * ss
                elif nr and not flags & DISCARD:
                    dlen = nr * ss
                else:
                    dlen = 0
                if pos + ss + dlen > size:
                    break
                self.entries.append(Entry(len(self.entries), sector, nr, flags,
                                          pos + ss if dlen else 0))
                pos += ss + dlen
        self.parsed_bytes = pos

    def __len__(self) -> int:
        return len(self.entries)

    def data(self, e: Entry, f) -> bytes:
        f.seek(e.data_off)
        return f.read(e.nr_sectors * self.sectorsize)

    def find(self, pattern: bytes, start: int = 0) -> int:
        """Index of the first write entry (>= start) whose payload contains pattern."""
        with open(self.path, "rb") as f:
            for e in self.entries[start:]:
                if e.is_write and pattern in self.data(e, f):
                    return e.idx
        raise LookupError(f"pattern {pattern[:40]!r} not found in {self.path}")

    def find_all(self, pattern: bytes, start: int = 0, end: int | None = None) -> list[int]:
        """Indices of all write entries in [start, end) whose payload contains pattern."""
        with open(self.path, "rb") as f:
            return [e.idx for e in self.entries[start:end]
                    if e.is_write and pattern in self.data(e, f)]

    def apply(self, raw: Path, start: int, end: int) -> int:
        """Apply entries[start:end] to a raw disk image; returns bytes written."""
        n = 0
        with open(self.path, "rb") as log, open(raw, "r+b") as disk:
            for e in self.entries[start:end]:
                if e.is_write:
                    buf = self.data(e, log)
                    disk.seek(e.sector * self.sectorsize)
                    disk.write(buf)
                    n += len(buf)
        return n

    # ---------------------------------------------------------------- reordering model
    def crash_states(self, start: int, end: int, max_volatile: int = 8,
                     torn: bool = False, open_tail: bool = False,
                     sample: int | None = None) -> list[dict]:
        """Crash states that a disk with a volatile write cache may expose, for crashes
        between consecutive FLUSH barriers inside [start, end].

        For the interval (a, b) between flushes a < b: everything up to and including a is
        durable, FUA writes in (a, b) are durable, the other writes V in (a, b) are volatile
        and any subset of them may have reached the media. Emitted subsets (bounded, in the
        spirit of CrashMonkey/ALICE): none of V, all of V (= the prefix state), only one
        w in V, all but one w in V. Each state: {"label", "base_end" (exclusive prefix),
        "extra" (entry indices applied on top, in log order)}.

        open_tail=True also treats (last flush, end] as an interval: a writer that never
        flushes (SWUpdate's grubenv) leaves its writes volatile at a crash at `end`.

        sample=N keeps N evenly spaced intervals that contain volatile writes (for a model of
        a whole install window, where the full set of intervals is too large to boot).

        torn=True adds sector-level tearing: a device only guarantees that a single
        sector is written atomically, so a multi-sector write w may persist only its
        first k sectors (k = 1 and k = half). Such states carry "partial": [w, k]."""
        flushes = [e.idx for e in self.entries[start:end + 1] if e.flags & FLUSH]
        if open_tail:
            # writes after the last flush are still volatile at a crash at `end`: add the
            # open interval (last flush before `start` or in the region, end]
            before = [e.idx for e in self.entries[:start] if e.flags & FLUSH]
            if not flushes or flushes[0] > start:
                flushes = ([before[-1]] if before else [start - 1]) + flushes
            flushes.append(end + 1)
        states: list[dict] = []
        pairs = [(a, b) for a, b in zip(flushes, flushes[1:])
                 if any(e.is_write and not e.flags & FUA for e in self.entries[a + 1:b])]
        if sample and len(pairs) > sample:  # evenly spaced intervals over the whole range
            pairs = [pairs[round(i * (len(pairs) - 1) / (sample - 1))] for i in range(sample)]
        for a, b in pairs:
            inner = [e for e in self.entries[a + 1:b] if e.is_write]
            fua = [e.idx for e in inner if e.flags & FUA]
            vol = [e.idx for e in inner if not e.flags & FUA]
            if not vol:
                continue
            pick = vol if len(vol) <= max_volatile else \
                [vol[int(i * (len(vol) - 1) / (max_volatile - 1))] for i in range(max_volatile)]
            cand = [("lost-all", []), ("kept-all", vol)]
            cand += [(f"only-{w}", [w]) for w in pick]
            if len(vol) > 1:
                cand += [(f"all-but-{w}", [x for x in vol if x != w]) for w in pick]
            seen = set()
            for label, sub in cand:
                extra = sorted(set(fua) | set(sub))
                key = tuple(extra)
                if key in seen:
                    continue
                seen.add(key)
                states.append({"interval": [a, b], "label": label, "base_end": a + 1,
                               "extra": extra, "volatile": len(vol)})
            if torn:
                for w in pick:
                    nr = self.entries[w].nr_sectors
                    for k in sorted({1, nr // 2} - {0, nr}):
                        states.append({"interval": [a, b], "label": f"torn-{w}-{k}of{nr}",
                                       "base_end": a + 1, "extra": sorted(fua),
                                       "partial": [w, k], "volatile": len(vol)})
        return states

    def apply_with_undo(self, raw: Path, idxs: list[int],
                        partial: list[int] | None = None) -> list[tuple[int, bytes]]:
        """Apply the given entries (and optionally the first k sectors of entry w,
        partial=[w, k]); return what is needed to undo them (old sector data)."""
        undo: list[tuple[int, bytes]] = []
        todo = [(i, None) for i in idxs] + ([(partial[0], partial[1])] if partial else [])
        with open(self.path, "rb") as log, open(raw, "r+b") as disk:
            for i, k in sorted(todo):
                e = self.entries[i]
                if not e.is_write:
                    continue
                buf = self.data(e, log)
                if k is not None:
                    buf = buf[:k * self.sectorsize]
                off = e.sector * self.sectorsize
                disk.seek(off)
                undo.append((off, disk.read(len(buf))))
                disk.seek(off)
                disk.write(buf)
        return undo

    @staticmethod
    def undo(raw: Path, undo: list[tuple[int, bytes]]) -> None:
        with open(raw, "r+b") as disk:
            for off, old in reversed(undo):
                disk.seek(off)
                disk.write(old)

    def summary(self, start: int = 0, end: int | None = None) -> dict:
        es = self.entries[start:end]
        return {"entries": len(es), "writes": sum(e.is_write for e in es),
                "barriers": sum(e.is_barrier for e in es),
                "discards": sum(bool(e.flags & DISCARD) for e in es),
                "bytes": sum(e.nr_sectors * self.sectorsize for e in es if e.is_write)}
