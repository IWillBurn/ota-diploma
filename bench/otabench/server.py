"""Adversarial HTTP repository server.

Every scenario gets its own *scene*: a TUF RepositorySimulator (borrowed from
tuf-conformance) plus an ordered list of attack rules. A rule matches a request
path and decides how the bytes go on the wire: substituted, replayed from an older
version, streamed endlessly, dripped slowly, cut off half-way, throttled.

tuf-conformance attacks at the *metadata* level: whatever it serves is a
complete, well-formed HTTP response. This server adds the *transport* level
(endless data, slow retrieval, dropped connections) and hooks for fault
injection (callbacks fire when a given file starts or finishes being served,
which is how the power-cut scenarios pick their kill points).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse

from tuf_conformance._internal.repository_simulator import RepositorySimulator

Matcher = Callable[[str], bool]


# ---------------------------------------------------------------- matchers
def role(name: str) -> Matcher:
    """Match metadata/<name>.json and metadata/<N>.<name>.json."""

    def _m(path: str) -> bool:
        if not path.startswith("metadata/") or not path.endswith(".json"):
            return False
        stem = path[len("metadata/") : -len(".json")]
        return stem == name or stem.partition(".")[2] == name

    return _m


def role_version(name: str, version: int) -> Matcher:
    return lambda p: p == f"metadata/{version}.{name}.json"


def nth_request(n: int) -> Matcher:
    """Match the n-th request (1-based) this rule sees, whatever its path. Used for
    event-based fault injection: 'act at the client's i-th network operation'."""
    seen = [0]

    def _m(path: str) -> bool:
        seen[0] += 1
        return seen[0] == n

    return _m


def target(name: str | None = None) -> Matcher:
    def _m(path: str) -> bool:
        if not path.startswith("targets/"):
            return False
        return name is None or path.endswith(name)

    return _m


# ---------------------------------------------------------------- rules
@dataclass
class Rule:
    match: Matcher
    action: str = "normal"  # normal|substitute|endless|slow|throttle|truncate|error|drop
    data: bytes | Callable[[], bytes] | None = None  # for substitute
    rate_bps: float = 0.0  # slow / throttle
    status: int = 503  # error
    once: bool = False
    on_start: Callable[[str], None] | None = None
    on_sent: Callable[[str], None] | None = None
    hits: int = 0


@dataclass
class RequestRecord:
    path: str
    action: str
    t_start: float
    t_end: float = 0.0
    bytes_sent: int = 0
    client_aborted: bool = False  # client closed the connection before we finished
    capped: bool = False  # harness cap hit: the client never gave up by itself


@dataclass
class Caps:
    """Hard limits so that a defenceless client cannot hang the benchmark."""

    endless_bytes: int = 64 * 1024 * 1024
    endless_seconds: float = 30.0
    slow_seconds: float = 120.0


@dataclass
class Scene:
    name: str
    sim: RepositorySimulator
    rules: list[Rule] = field(default_factory=list)
    log: list[RequestRecord] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_rule(self, rule: Rule) -> Rule:
        self.rules.insert(0, rule)  # newest rule wins
        return rule

    def clear_rules(self) -> None:
        self.rules.clear()

    def records(self, matcher: Matcher | None = None) -> list[RequestRecord]:
        with self.lock:
            return [r for r in self.log if matcher is None or matcher(r.path)]


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 with keep-alive, like real mirrors and CDNs. A body without a length
    # (endless stream) is close-delimited and says so with "Connection: close". Under
    # HTTP/1.0 the server closed the socket after every response, and Node's HTTP client
    # (undici) asserted when that happened while it was applying backpressure.
    protocol_version = "HTTP/1.1"
    server: AdversarialServer

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        scene_name, _, path = self.path.lstrip("/").partition("/")
        scene = self.server.scenes.get(parse.unquote(scene_name))
        if scene is None:
            self.send_error(404, "unknown scene")
            return

        rule = None
        with scene.lock:
            for r in scene.rules:
                if r.match(path) and not (r.once and r.hits):
                    r.hits += 1
                    rule = r
                    break
        action = rule.action if rule else "normal"
        rec = RequestRecord(path, action, time.monotonic())
        with scene.lock:
            scene.log.append(rec)
        if rule and rule.on_start:
            rule.on_start(path)

        try:
            if action == "error":
                self.send_error(rule.status)
            elif action == "drop":  # close the connection without any response
                self.close_connection = True
            elif action == "endless":
                self._endless(rec)
            else:
                if action == "substitute":
                    data = rule.data() if callable(rule.data) else rule.data
                else:
                    try:
                        data = scene.sim.fetch(path)
                    except (ValueError, IndexError, KeyError) as e:
                        self.send_error(404, str(e))
                        return
                if action == "slow":
                    self._paced(rec, data, rule.rate_bps, chunk=1)
                elif action == "throttle":
                    self._paced(rec, data, rule.rate_bps, chunk=16384)
                elif action == "truncate":
                    self._send_head(len(data))
                    half = data[: max(1, len(data) // 2)]
                    self.wfile.write(half)
                    rec.bytes_sent = len(half)
                    self.wfile.flush()
                    self.close_connection = True
                else:
                    self._send_head(len(data))
                    self.wfile.write(data)
                    rec.bytes_sent = len(data)
        except (ConnectionError, OSError):
            rec.client_aborted = True
        finally:
            rec.t_end = time.monotonic()
        if rule and rule.on_sent and not rec.client_aborted:
            rule.on_sent(path)

    # -- helpers ---------------------------------------------------------
    def _send_head(self, length: int | None) -> None:
        self.send_response(200)
        if length is not None:
            self.send_header("Content-Length", str(length))
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()

    def _endless(self, rec: RequestRecord) -> None:
        """Valid-looking JSON prefix followed by an unbounded string body."""
        caps = self.server.caps
        self._send_head(None)
        self.wfile.write(b'{"signed": {"_type": "timestamp", "padding": "')
        chunk = b"A" * 65536
        deadline = time.monotonic() + caps.endless_seconds
        while rec.bytes_sent < caps.endless_bytes and time.monotonic() < deadline:
            self.wfile.write(chunk)
            rec.bytes_sent += len(chunk)
        rec.capped = True  # cap reached: the client did NOT abort on its own

    def _paced(self, rec: RequestRecord, data: bytes, rate_bps: float, chunk: int) -> None:
        self._send_head(len(data))
        interval = chunk / rate_bps
        deadline = time.monotonic() + self.server.caps.slow_seconds
        for i in range(0, len(data), chunk):
            if self.server.stopping.is_set() or time.monotonic() > deadline:
                rec.capped = True
                return
            self.wfile.write(data[i : i + chunk])
            self.wfile.flush()
            rec.bytes_sent += len(data[i : i + chunk])
            time.sleep(interval)


class AdversarialServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, caps: Caps | None = None) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.caps = caps or Caps()
        self.scenes: dict[str, Scene] = {}
        self.stopping = threading.Event()
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    def __enter__(self) -> AdversarialServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stopping.set()
        self.shutdown()
        self.server_close()

    def handle_error(self, request: object, client_address: object) -> None:
        pass  # clients that are killed or abort mid-request are the point of the exercise

    def new_scene(self, name: str) -> Scene:
        scene = Scene(name, RepositorySimulator(None))
        self.scenes[name] = scene
        return scene

    def urls(self, scene: Scene) -> tuple[str, str]:
        host, port = self.server_address[:2]
        q = parse.quote(scene.name, "")
        return (f"http://{host}:{port}/{q}/metadata/", f"http://{host}:{port}/{q}/targets/")
