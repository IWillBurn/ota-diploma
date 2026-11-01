"""Unit tests for the dm-log-writes reader, the crash-state models, the Wilson interval and
the in-place GRUB environment writer — no VM needed."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.report import wilson  # noqa: E402
from otabench.writelog import FLUSH, FUA, MAGIC, MARK, WriteLog  # noqa: E402

SS = 512


def _log(path: Path, entries: list[tuple[int, int, int, bytes]]) -> Path:
    """Write a dm-log-writes log: entries are (sector, nr_sectors, flags, data)."""
    out = bytearray(struct.pack("<QQQI", MAGIC, 1, len(entries), SS).ljust(SS, b"\0"))
    for sector, nr, flags, data in entries:
        out += struct.pack("<QQQQ", sector, nr, flags, len(data)).ljust(SS, b"\0")
        if data:
            out += data.ljust(-(-len(data) // SS) * SS, b"\0")
    path.write_bytes(bytes(out))
    return path


def _w(sector: int, nr: int, fill: bytes, flags: int = 0) -> tuple[int, int, int, bytes]:
    return (sector, nr, flags, fill * (nr * SS))


@pytest.fixture()
def wl(tmp_path: Path) -> WriteLog:
    # 0 mark | 1 A | 2 flush | 3 B(2) | 4 C fua | 5 D(8) | 6 flush | 7 E | 8 F
    return WriteLog(_log(tmp_path / "golden.log", [
        (0, 0, MARK, b"install-start"),
        _w(0, 1, b"A"),
        (0, 0, FLUSH, b""),
        _w(1, 2, b"B"),
        _w(3, 1, b"C", FUA),
        _w(4, 8, b"D"),
        (0, 0, FLUSH, b""),
        _w(12, 1, b"E"),
        _w(13, 1, b"F"),
    ]))


def test_parse(wl: WriteLog) -> None:
    assert len(wl) == 9
    assert [e.is_write for e in wl.entries] == [False, True, False, True, True, True, False, True, True]
    assert [e.is_barrier for e in wl.entries] == [False, False, True, False, True, False, True, False, False]
    assert wl.summary() == {"entries": 9, "writes": 6, "barriers": 3, "discards": 0, "bytes": 14 * SS}


def test_truncated_log_is_cut_at_last_complete_entry(tmp_path: Path, wl: WriteLog) -> None:
    raw = wl.path.read_bytes()
    cut = tmp_path / "cut.log"
    cut.write_bytes(raw[:-SS // 2])  # last entry's payload incomplete
    assert len(WriteLog(cut)) == 8


def test_not_a_log(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_bytes(b"\0" * SS)
    with pytest.raises(ValueError):
        WriteLog(p)


def test_find(wl: WriteLog) -> None:
    assert wl.find(b"DDDD") == 5
    assert wl.find_all(b"EE") == [7]
    assert wl.find_all(b"A", 2) == []
    with pytest.raises(LookupError):
        wl.find(b"ZZZ")


def test_prefix_apply(tmp_path: Path, wl: WriteLog) -> None:
    disk = tmp_path / "disk.raw"
    disk.write_bytes(b"\0" * 16 * SS)
    assert wl.apply(disk, 0, 5) == 4 * SS  # A, B(2), C
    d = disk.read_bytes()
    assert d[:SS] == b"A" * SS and d[SS:3 * SS] == b"B" * 2 * SS and d[3 * SS:4 * SS] == b"C" * SS
    assert d[4 * SS:] == b"\0" * 12 * SS


def test_reorder_states(wl: WriteLog) -> None:
    st = wl.crash_states(0, 8)
    # one interval (2, 6): volatile B and D, C is FUA and always durable
    assert {s["label"] for s in st} == {"lost-all", "kept-all", "only-3", "only-5"}
    by = {s["label"]: s for s in st}
    assert all(s["base_end"] == 3 and s["interval"] == [2, 6] and s["volatile"] == 2 for s in st)
    assert by["lost-all"]["extra"] == [4]
    assert by["kept-all"]["extra"] == [3, 4, 5]
    assert by["only-3"]["extra"] == [3, 4]
    # all-but-3 == only-5 and all-but-5 == only-3: duplicates are dropped
    assert len(st) == 4


def test_open_tail(wl: WriteLog) -> None:
    st = wl.crash_states(0, 8, open_tail=True)
    tail = [s for s in st if s["interval"] == [6, 9]]
    assert {s["label"] for s in tail} == {"lost-all", "kept-all", "only-7", "only-8"}
    assert all(s["base_end"] == 7 for s in tail)
    # without open_tail the writes after the last flush are not permuted
    assert not [s for s in wl.crash_states(0, 8) if s["interval"][0] == 6]


def test_open_tail_without_flush_in_region(wl: WriteLog) -> None:
    st = wl.crash_states(7, 8, open_tail=True)
    assert {tuple(s["interval"]) for s in st} == {(6, 9)}


def test_torn(wl: WriteLog) -> None:
    torn = [s for s in wl.crash_states(0, 8, torn=True) if "partial" in s]
    assert {s["label"] for s in torn} == {"torn-3-1of2", "torn-5-1of8", "torn-5-4of8"}
    assert all(s["extra"] == [4] for s in torn)  # only FUA writes besides the torn one


def test_sample(tmp_path: Path) -> None:
    ents = []
    for i in range(10):
        ents += [_w(i, 1, bytes([65 + i])), (0, 0, FLUSH, b"")]
    log = WriteLog(_log(tmp_path / "many.log", [(0, 0, FLUSH, b"")] + ents))
    all_iv = {tuple(s["interval"]) for s in log.crash_states(0, len(log) - 1)}
    assert len(all_iv) == 10
    some = {tuple(s["interval"]) for s in log.crash_states(0, len(log) - 1, sample=3)}
    assert len(some) == 3 and min(all_iv) in some and max(all_iv) in some


def test_apply_with_undo(tmp_path: Path, wl: WriteLog) -> None:
    disk = tmp_path / "disk.raw"
    orig = os.urandom(16 * SS)
    disk.write_bytes(orig)
    undo = wl.apply_with_undo(disk, [3, 4], partial=[5, 1])
    d = disk.read_bytes()
    assert d[SS:3 * SS] == b"B" * 2 * SS and d[3 * SS:4 * SS] == b"C" * SS
    assert d[4 * SS:5 * SS] == b"D" * SS and d[5 * SS:12 * SS] == orig[5 * SS:12 * SS]  # torn
    WriteLog.undo(disk, undo)
    assert disk.read_bytes() == orig


def test_wilson() -> None:
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = wilson(10, 10)
    assert lo == pytest.approx(0.7225, abs=1e-3) and hi == 1.0
    lo, hi = wilson(1, 10)
    assert (lo, hi) == (pytest.approx(0.0179, abs=1e-3), pytest.approx(0.4042, abs=1e-3))
    assert wilson(0, 0) == (0.0, 1.0)


# ---------------------------------------------------------------- otabench-bootenv

BOOTENV = ROOT / "vm" / "guest" / "otabench-bootenv"
HEADER = b"# GRUB Environment Block\n"


def _env(tmp_path: Path, body: bytes) -> Path:
    p = tmp_path / "grubenv"
    p.write_bytes((HEADER + body).ljust(1024, b"#"))
    return p


def _bootenv(env: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BOOTENV), *args], capture_output=True, text=True,
                          env={**os.environ, "OTABENCH_GRUBENV": str(env)})


def test_bootenv_set_primary_in_place(tmp_path: Path) -> None:
    env = _env(tmp_path, b"ORDER=A B\nA_OK=1\nA_TRY=0\nB_OK=0\nB_TRY=0\n")
    ino = env.stat().st_ino
    r = _bootenv(env, "set-primary", "B")
    assert r.returncode == 0, r.stderr
    buf = env.read_bytes()
    assert len(buf) == 1024 and buf.startswith(HEADER) and buf.endswith(b"#")
    assert b"ORDER=B A\n" in buf and b"B_OK=1\nB_TRY=0\n" in buf
    assert env.stat().st_ino == ino  # same file, rewritten in place
    assert _bootenv(env, "get-primary").stdout.strip() == "B"


def test_bootenv_states(tmp_path: Path) -> None:
    env = _env(tmp_path, b"ORDER=B A\nA_OK=1\nA_TRY=0\nB_OK=1\nB_TRY=1\n")
    assert _bootenv(env, "get-primary").stdout.strip() == "A"  # B is being tried
    assert _bootenv(env, "set-state", "B", "bad").returncode == 0
    assert _bootenv(env, "get-state", "B").stdout.strip() == "bad"
    assert "B_OK=0" in _bootenv(env, "dump").stdout


def test_bootenv_rejects_damaged_block(tmp_path: Path) -> None:
    env = tmp_path / "grubenv"
    env.write_bytes(b"")  # what a torn truncate+rewrite leaves on vfat
    r = _bootenv(env, "get-primary")
    assert r.returncode != 0 and "not a 1024-byte" in r.stderr


def _bootenv_r(env: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BOOTENV), *args], capture_output=True, text=True,
                          env={**os.environ, "OTABENCH_GRUBENV": str(env), "OTABENCH_REDUNDANT": "1"})


def test_bootenv_redundant_copies(tmp_path: Path) -> None:
    env = _env(tmp_path, b"ORDER=A B\nA_OK=1\nA_TRY=0\nB_OK=0\nB_TRY=0\n")
    copy1 = Path(str(env) + ".1")
    assert _bootenv_r(env, "init-redundant").returncode == 0
    assert b"SEQ=1" in env.read_bytes() and b"SEQ=0" in copy1.read_bytes()
    assert _bootenv_r(env, "set-primary", "B").returncode == 0  # goes to the older copy
    assert b"SEQ=2" in copy1.read_bytes() and b"ORDER=B A" in copy1.read_bytes()
    assert b"ORDER=A B" in env.read_bytes()  # the previous state stays intact
    assert _bootenv_r(env, "get-primary").stdout.strip() == "B"
    copy1.write_bytes(b"")  # torn / emptied newer copy: fall back to the older one
    assert _bootenv_r(env, "get-primary").stdout.strip() == "A"
    assert _bootenv_r(env, "set", "A_TRY=1").returncode == 0  # rewrites the unreadable copy
    assert b"SEQ=2" in copy1.read_bytes() and b"A_TRY=1" in copy1.read_bytes()
    env.write_bytes(b"")
    copy1.write_bytes(b"")
    r = _bootenv_r(env, "dump")
    assert r.returncode != 0 and "no readable copy" in r.stderr
