"""Adversarial HTTP server for one A/B artifact (backlog B8: network attacks on A/B updaters).

The guest reaches it through QEMU user networking as http://10.0.2.2:<port>/ (the host's
loopback). The artifact first gets onto the host by an upload from the guest (PUT /upload),
because bundles are built inside the guest. Modes (set per scenario, `mode` attribute):

  ok                  serve the file, Content-Length, Range requests honoured
  slow:<Bps>:<after>  after <after> bytes, trickle the rest at <Bps> bytes per second
  drop:<after>        close the connection after <after> bytes (once; later requests are ok)
  endless             no Content-Length; after the file, keep sending random bytes
  tamper:<offset>     flip one byte at <offset> of the served data

The server records every request: method, Range, bytes sent, who closed, duration.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CHUNK = 64 * 1024


@dataclass
class Req:
    method: str
    path: str
    range: str | None
    status: int = 0
    sent: int = 0
    want: int = 0  # bytes the request asked for (Content-Length / range)
    t0: float = field(default_factory=time.monotonic)
    t1: float = 0.0
    closed_by: str = ""  # "server" (end of response or drop), "client" (reset/broken pipe), "cap"


class BundleServer:
    def __init__(self, store: Path, port: int = 0, cap_s: float = 900.0) -> None:
        self.store, self.cap_s = Path(store), cap_s
        self.store.parent.mkdir(parents=True, exist_ok=True)
        self.mode = "ok"
        self.log: list[Req] = []
        self._dropped = False
        # Thresholds count bytes served across ALL responses since set_mode(): a streaming
        # client (RAUC) reads the artifact in thousands of small Range requests, none of
        # which reaches an offset inside one response.
        self.total = 0
        self.applied = False  # the attack of the current mode actually took effect
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        outer = self

        class H(_Handler):
            server_ref = outer

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "BundleServer":
        self._t.start()
        return self

    def stop(self) -> None:
        self.stop_event.set()
        self.httpd.shutdown()
        self.httpd.server_close()

    def set_mode(self, mode: str) -> None:
        with self.lock:
            self.mode, self._dropped, self.total, self.applied = mode, False, 0, False
            self.log.clear()

    @property
    def size(self) -> int:
        return self.store.stat().st_size


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_ref: BundleServer

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_PUT(self) -> None:  # noqa: N802 - the guest uploads the artifact once
        n = int(self.headers.get("Content-Length", "0"))
        tmp = self.server_ref.store.with_suffix(".part")
        with open(tmp, "wb") as f:
            left = n
            while left:
                b = self.rfile.read(min(CHUNK, left))
                if not b:
                    break
                f.write(b)
                left -= len(b)
        if left:
            self.send_error(400, "short upload")
            return
        os.replace(tmp, self.server_ref.store)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(head=True)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(head=False)

    def _serve(self, head: bool) -> None:
        srv = self.server_ref
        rec = Req(self.command, self.path, self.headers.get("Range"))
        srv.log.append(rec)
        size = srv.size
        start, end = 0, size - 1
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rec.range or "")
        mode = srv.mode
        if m:  # endless: the requested range first, then garbage without end
            if m.group(1):
                start = int(m.group(1))
                end = int(m.group(2)) if m.group(2) else size - 1
            else:  # suffix range: last N bytes
                start = max(0, size - int(m.group(2)))
            end = min(end, size - 1)
            rec.status = 206
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        else:
            rec.status = 200
            self.send_response(200)
        rec.want = end - start + 1
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Accept-Ranges", "bytes")
        if mode == "endless":
            self.send_header("Connection", "close")
            self.close_connection = True
        else:
            self.send_header("Content-Length", str(end - start + 1))
        self.end_headers()
        if head:
            rec.closed_by, rec.t1 = "server", time.monotonic()
            return
        try:
            self._body(srv, rec, start, end, mode)
        except (ConnectionError, OSError):
            rec.closed_by = rec.closed_by or "client"
        rec.t1 = time.monotonic()

    def _body(self, srv: BundleServer, rec: Req, start: int, end: int, mode: str) -> None:
        kind, _, arg = mode.partition(":")
        slow_bps, slow_after, drop_after, tamper_at = 0, 0, -1, -1
        if kind == "slow":
            a, _, b = arg.partition(":")
            slow_bps, slow_after = int(a), int(b or 0)
        elif kind == "drop" and not srv._dropped:
            drop_after = int(arg)
        elif kind == "tamper":
            tamper_at = int(arg)
        with open(srv.store, "rb") as f:
            f.seek(start)
            pos, deadline = start, rec.t0 + srv.cap_s
            while pos <= end:
                if srv.stop_event.is_set() or time.monotonic() > deadline:
                    rec.closed_by = "cap"
                    self.close_connection = True
                    return
                n = CHUNK
                slow_now = bool(slow_bps) and srv.total >= slow_after
                if slow_now:
                    n = max(1, slow_bps)
                elif slow_bps:  # do not overshoot the point where the trickle starts
                    n = min(n, max(1, slow_after - srv.total))
                n = min(n, end - pos + 1)
                if drop_after >= 0:
                    with srv.lock:
                        if srv._dropped:  # another connection already took the cut
                            drop_after = -1
                        elif srv.total + n >= drop_after:
                            n = drop_after - srv.total
                            if n <= 0:
                                srv._dropped = srv.applied = True
                                rec.closed_by = "server"
                                self.close_connection = True
                                self.connection.shutdown(2)
                                return
                buf = bytearray(f.read(n))
                if 0 <= tamper_at - pos < len(buf):
                    buf[tamper_at - pos] ^= 0xFF
                    srv.applied = True
                self.wfile.write(buf)
                rec.sent += len(buf)
                with srv.lock:
                    srv.total += len(buf)
                pos += len(buf)
                if slow_now:
                    srv.applied = True
                    time.sleep(len(buf) / slow_bps)
            if kind == "endless":  # past the end of the artifact: garbage, forever
                srv.applied = True
                junk = os.urandom(CHUNK)
                while time.monotonic() < deadline and not srv.stop_event.is_set():
                    self.wfile.write(junk)
                    rec.sent += len(junk)
                rec.closed_by = "cap"
                self.close_connection = True
                return
        rec.closed_by = "server"
