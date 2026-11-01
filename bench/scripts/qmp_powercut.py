"""Cut the power of a running QEMU VM via QMP (no guest shutdown, no flush).

Usage:
  python qmp_powercut.py tcp:127.0.0.1:4444          # Windows / any OS
  python qmp_powercut.py unix:/tmp/qmp.sock          # Linux
  python qmp_powercut.py tcp:127.0.0.1:4444 --reset  # hard reset instead of power-off

QEMU must be started with e.g. `-qmp tcp:127.0.0.1:4444,server=on,wait=off`.
"""

import json
import socket
import sys


def connect(addr: str) -> socket.socket:
    kind, _, rest = addr.partition(":")
    if kind == "tcp":
        host, _, port = rest.rpartition(":")
        return socket.create_connection((host, int(port)), timeout=5)
    if kind == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(rest)
        return s
    raise SystemExit(f"unknown address {addr!r}: use tcp:HOST:PORT or unix:PATH")


def cmd(f, s: socket.socket, name: str) -> dict:
    s.sendall(json.dumps({"execute": name}).encode() + b"\n")
    while True:  # skip asynchronous events until the command's reply arrives
        line = f.readline()
        if not line:
            return {}
        msg = json.loads(line)
        if "return" in msg or "error" in msg:
            return msg


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    s = connect(sys.argv[1])
    f = s.makefile("r", encoding="utf-8")
    greeting = json.loads(f.readline())
    print("QMP:", greeting["QMP"]["version"]["qemu"])
    print("qmp_capabilities:", cmd(f, s, "qmp_capabilities"))
    action = "system_reset" if "--reset" in sys.argv else "quit"
    try:
        print(f"{action}:", cmd(f, s, action) or "(connection closed: VM is gone)")
    except (ConnectionError, OSError):
        print(f"{action}: connection closed, VM is gone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
