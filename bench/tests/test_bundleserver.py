"""The adversarial artifact server for network scenarios of A/B updaters (B8)."""

from __future__ import annotations

import http.client
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from otabench.bundleserver import BundleServer  # noqa: E402

DATA = os.urandom(300_000)


@pytest.fixture()
def srv(tmp_path: Path):
    s = BundleServer(tmp_path / "artifact.bin", cap_s=5).start()
    c = http.client.HTTPConnection("127.0.0.1", s.port, timeout=10)
    c.request("PUT", "/upload", body=DATA, headers={"Content-Length": str(len(DATA))})
    assert c.getresponse().status == 201
    yield s
    s.stop()


def get(s: BundleServer, headers: dict | None = None) -> tuple[int, bytes, dict]:
    c = http.client.HTTPConnection("127.0.0.1", s.port, timeout=10)
    c.request("GET", "/update.swu", headers=headers or {})
    r = c.getresponse()
    try:
        body = r.read()
    except http.client.IncompleteRead as e:
        body = e.partial
    return r.status, body, dict(r.getheaders())


def test_ok_and_range(srv: BundleServer) -> None:
    st, body, h = get(srv)
    assert st == 200 and body == DATA and h["Content-Length"] == str(len(DATA))
    st, body, h = get(srv, {"Range": "bytes=10-19"})
    assert st == 206 and body == DATA[10:20] and h["Content-Range"] == f"bytes 10-19/{len(DATA)}"
    st, body, _ = get(srv, {"Range": "bytes=-8"})
    assert st == 206 and body == DATA[-8:]


def test_tamper_flips_one_byte(srv: BundleServer) -> None:
    srv.set_mode("tamper:1000")
    _, body, _ = get(srv)
    diff = [i for i in range(len(DATA)) if body[i] != DATA[i]]
    assert diff == [1000] and body[1000] == DATA[1000] ^ 0xFF


def test_drop_once(srv: BundleServer) -> None:
    srv.set_mode("drop:100000")
    _, body, _ = get(srv)
    assert len(body) == 100000 and srv.log[-1].closed_by == "server"
    _, body, _ = get(srv)  # the next request is served in full
    assert body == DATA


def test_slow_and_endless(srv: BundleServer) -> None:
    srv.set_mode("slow:20000:250000")
    t = time.monotonic()
    _, body, _ = get(srv)
    assert body == DATA and time.monotonic() - t >= 2.0  # 50 KB at 20 KB/s
    srv.cap_s = 1.0
    srv.set_mode("endless")
    _, body, h = get(srv)
    assert "Content-Length" not in h and len(body) > len(DATA) and body[:len(DATA)] == DATA
    assert srv.log[-1].closed_by == "cap"
