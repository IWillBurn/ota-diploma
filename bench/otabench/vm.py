"""QEMU VM control for system-level (level 3) and block-level (level 2) tests.

Channels to the guest (all over 127.0.0.1 TCP so it works on Windows and Linux):
  * QMP            power control: `quit` = pull the plug, `system_reset` = reset button
  * serial console boot log (always mirrored to a file) + scripted root shell
  * qemu-guest-agent (virtio-serial) for adapter commands: no guest network needed
Optional: QEMU `blklogwrites` records every guest write (dm-log-writes format).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

QEMU_DIR = Path(r"C:\Program Files\qemu")
DEFAULT_ACCEL = "whpx,kernel-irqchip=off"
OVMF_CODE = QEMU_DIR / "share" / "edk2-x86_64-code.fd"
OVMF_VARS = QEMU_DIR / "share" / "edk2-i386-vars.fd"  # QEMU ships the x86 vars template as i386


def qemu_exe(name: str) -> str:
    p = QEMU_DIR / f"{name}.exe"
    return str(p) if p.exists() else (shutil.which(name) or name)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_overlay(base: Path, overlay: Path, base_fmt: str = "qcow2", size: str | None = None) -> Path:
    overlay.unlink(missing_ok=True)
    cmd = [qemu_exe("qemu-img"), "create", "-q", "-f", "qcow2", "-b", str(Path(base).resolve()),
           "-F", base_fmt, str(overlay)]
    if size:
        cmd.append(size)
    subprocess.run(cmd, check=True)
    return overlay


def _connect(port: int, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)


# ------------------------------------------------------------------ QMP
class QMP:
    def __init__(self, port: int) -> None:
        self.port = port

    def call(self, command: str, arguments: dict | None = None) -> dict:
        with _connect(self.port, 10) as s:
            f = s.makefile("r", encoding="utf-8")
            f.readline()
            for name, args in (("qmp_capabilities", None), (command, arguments)):
                msg = {"execute": name}
                if args:
                    msg["arguments"] = args
                s.sendall(json.dumps(msg).encode() + b"\n")
                while True:
                    line = f.readline()
                    if not line:
                        return {"closed": True}
                    reply = json.loads(line)
                    if "return" in reply or "error" in reply:
                        break
            return reply


# ------------------------------------------------------------------ guest agent
class GuestAgent:
    """qemu-guest-agent client. Reconnects per call, resyncs with guest-sync-delimited,
    so it survives guest reboots."""

    def __init__(self, port: int) -> None:
        self.port = port

    def _call(self, command: str, arguments: dict | None, timeout: float) -> dict:
        with _connect(self.port, 5) as s:
            s.settimeout(timeout)
            sync_id = secrets.randbelow(2**31)
            s.sendall(b"\xff" + json.dumps({"execute": "guest-sync-delimited",
                                            "arguments": {"id": sync_id}}).encode() + b"\n")
            buf = b""
            while True:  # wait for 0xFF + our sync id
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("agent closed")
                buf += chunk
                if b"\xff" in buf:
                    tail = buf.split(b"\xff")[-1]
                    m = re.search(rb'"return":\s*(\d+)', tail)
                    if m and int(m.group(1)) == sync_id:
                        buf = tail[tail.index(b"\n") + 1:] if b"\n" in tail else b""
                        break
            msg = {"execute": command}
            if arguments:
                msg["arguments"] = arguments
            s.sendall(json.dumps(msg).encode() + b"\n")
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("agent closed")
                buf += chunk
            return json.loads(buf.split(b"\n", 1)[0])

    def ping(self, timeout: float = 3) -> bool:
        try:
            return "return" in self._call("guest-ping", None, timeout)
        except (OSError, ValueError, ConnectionError):
            return False

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ping():
                return True
            time.sleep(1)
        return False

    def exec(self, argv: list[str], timeout: float = 600) -> tuple[int, str, str]:
        r = self._call("guest-exec", {"path": argv[0], "arg": argv[1:], "capture-output": True}, 15)
        if "error" in r:
            raise RuntimeError(r["error"])
        pid = r["return"]["pid"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self._call("guest-exec-status", {"pid": pid}, 15)["return"]
            if st.get("exited"):
                out = base64.b64decode(st.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(st.get("err-data", "")).decode(errors="replace")
                return st.get("exitcode", -1), out, err
            time.sleep(0.5)
        raise TimeoutError(f"guest command timed out: {argv}")

    def sh(self, cmd: str, timeout: float = 600) -> tuple[int, str, str]:
        return self.exec(["/bin/sh", "-c", cmd], timeout)

    def spawn(self, cmd: str) -> int:
        """Start a shell command in the guest and return immediately (pid)."""
        r = self._call("guest-exec", {"path": "/bin/sh", "arg": ["-c", cmd],
                                      "capture-output": True}, 15)
        return r["return"]["pid"]


# ------------------------------------------------------------------ serial console
class SerialConsole:
    """Scripted root shell over the serial port (used to build images, before the
    guest agent exists). Every byte is also kept in self.text for inspection."""

    def __init__(self, port: int) -> None:
        self.sock = _connect(port, 30)
        self.sock.settimeout(None)
        self.buf = bytearray()
        self.pos = 0
        self.lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        while True:
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.buf += chunk

    def send(self, text: str) -> None:
        self.sock.sendall(text.encode())

    def expect(self, pattern: bytes, timeout: float) -> re.Match:
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                m = rx.search(self.buf, self.pos)
                if m:
                    self.pos = m.end()
                    return m
            time.sleep(0.1)
        with self.lock:
            tail = bytes(self.buf[-600:]).decode(errors="replace")
        raise TimeoutError(f"serial: {pattern!r} not seen in {timeout}s; tail:\n{tail}")

    def login(self, timeout: float = 240) -> None:
        deadline = time.monotonic() + timeout
        while True:
            self.send("\n")
            try:
                self.expect(rb"login:", 5)
                break
            except TimeoutError:
                if time.monotonic() > deadline:
                    raise
        self.send("root\n")
        self.expect(rb"[#$] ", 30)
        self.send("stty -echo cols 250; dmesg -n 1; export TERM=dumb PAGER=cat SYSTEMD_PAGER=\n")
        self.run("true", 30)

    def run(self, cmd: str, timeout: float = 900, check: bool = True) -> str:
        token = secrets.token_hex(4)
        start = len(self.buf)
        self.pos = start
        self.send(f"{cmd}; echo __RC_{token}_$?__\n")
        m = self.expect(rb"__RC_" + token.encode() + rb"_(\d+)__", timeout)
        with self.lock:
            out = bytes(self.buf[start:m.start()]).decode(errors="replace")
        rc = int(m.group(1))
        if check and rc != 0:
            raise RuntimeError(f"guest command failed rc={rc}: {cmd}\n{out[-1500:]}")
        return out.replace("\r", "")


# ------------------------------------------------------------------ VM
class VM:
    """One guest. With cold_reboot (default under WHPX) QEMU runs with -no-reboot and
    every guest reset is turned into a power cycle: the supervisor relaunches QEMU on
    the same disk. Reason: under WHPX a *warm* reset hangs the guest kernel right after
    GRUB (observed with Debian 12 / QEMU 11.1), while cold boots are reliable."""

    def __init__(self, disk: Path, work: Path, *, disk_format: str = "qcow2",
                 log_writes: Path | None = None, net: bool = False, mem: int = 1024,
                 smp: int = 2, accel: str = DEFAULT_ACCEL, name: str = "vm",
                 discard: bool = False, cold_reboot: bool | None = None,
                 uefi: bool = False) -> None:
        self.disk, self.work, self.fmt = Path(disk), Path(work), disk_format
        self.log_writes, self.net, self.mem, self.smp, self.accel = log_writes, net, mem, smp, accel
        self.discard, self.name, self.uefi = discard, name, uefi
        self.cold_reboot = ("whpx" in accel) if cold_reboot is None else cold_reboot
        self.work.mkdir(parents=True, exist_ok=True)
        self.serial_log = self.work / f"{name}-serial.log"
        self.qemu_log = self.work / f"{name}-qemu.log"
        self.vars = self.work / f"{name}-ovmf-vars.fd"
        if uefi and not self.vars.exists():  # per-VM writable copy of the NVRAM template
            self.vars.write_bytes(OVMF_VARS.read_bytes())
        self.qmp, self.agent = QMP(0), GuestAgent(0)
        self._new_ports()
        self.proc: subprocess.Popen | None = None
        self.t_start = 0.0
        self.resets = 0  # guest-initiated reboots (incl. panic=N reboots)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._log_started = False

    def _new_ports(self) -> None:
        self.p_serial, self.p_qmp, self.p_qga = free_port(), free_port(), free_port()
        self.qmp.port, self.agent.port = self.p_qmp, self.p_qga

    def cmdline(self) -> list[str]:
        c = [qemu_exe("qemu-system-x86_64"), "-accel", self.accel, "-m", str(self.mem),
             "-smp", str(self.smp), "-display", "none", "-monitor", "none",
             "-chardev", f"socket,id=ser0,host=127.0.0.1,port={self.p_serial},server=on,"
                         f"wait=off,logfile={self.serial_log},logappend=on",
             "-serial", "chardev:ser0",
             "-qmp", f"tcp:127.0.0.1:{self.p_qmp},server=on,wait=off",
             "-chardev", f"socket,id=qga0,host=127.0.0.1,port={self.p_qga},server=on,wait=off",
             "-device", "virtio-serial-pci",
             "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
             "-nic", "user,model=virtio-net-pci" if self.net else "none"]
        if self.cold_reboot:
            c.append("-no-reboot")
        if self.uefi:
            c += ["-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
                  "-drive", f"if=pflash,format=raw,unit=1,file={self.vars}"]
        if self.log_writes:
            append = self._log_started
            if not append:
                self.log_writes.write_bytes(b"")
                self._log_started = True
            c += ["-blockdev", f"driver=file,node-name=f0,filename={self.disk}",
                  "-blockdev", f"driver={self.fmt},node-name=disk,file=f0",
                  "-blockdev", f"driver=file,node-name=logf,filename={self.log_writes}",
                  "-blockdev", "driver=blklogwrites,node-name=logged,file=disk,log=logf"
                               + (",log-append=on" if append else ""),
                  "-device", "virtio-blk-pci,drive=logged"]
        else:
            extra = ",discard=unmap" if self.discard else ""
            c += ["-drive", f"file={self.disk},if=virtio,format={self.fmt}{extra}"]
        return c

    def _launch(self) -> None:
        with open(self.qemu_log, "ab") as out:
            self.proc = subprocess.Popen(self.cmdline(), stdout=out, stderr=subprocess.STDOUT)

    def start(self) -> VM:
        self._launch()
        self.t_start = time.monotonic()
        time.sleep(0.5)
        if self.proc.poll() is not None:
            raise RuntimeError("QEMU failed: " + self.qemu_log.read_text(errors="replace")[-800:])
        if self.cold_reboot:
            threading.Thread(target=self._supervise, daemon=True).start()
        return self

    def _supervise(self) -> None:
        while True:
            self.proc.wait()
            with self._lock:
                if self._stop.is_set():
                    return
                if "reboot: Power down" in self.serial_text()[-4000:]:
                    self._stop.set()
                    return
                self.resets += 1
                self._new_ports()
                self._launch()

    @property
    def alive(self) -> bool:
        return not self._stop.is_set() or (self.proc is not None and self.proc.poll() is None)

    def console(self) -> SerialConsole:
        return SerialConsole(self.p_serial)

    def serial_text(self) -> str:
        try:
            return self.serial_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def wait_serial(self, pattern: str, timeout: float, occurrence: int = 1) -> float | None:
        """Seconds since start when `pattern` has appeared `occurrence` times."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(rx.findall(self.serial_text())) >= occurrence:
                return time.monotonic() - self.t_start
            if not self.cold_reboot and self.proc and self.proc.poll() is not None:
                return None
            time.sleep(0.05)
        return None

    def power_cut(self) -> None:
        """Pull the plug: no guest shutdown, no flush; QEMU exits immediately."""
        with self._lock:
            self._stop.set()
        try:
            self.qmp.call("quit")
        except OSError:
            pass
        if not self.wait_exit(10):
            self.kill()

    def shutdown(self, timeout: float = 90) -> None:
        with self._lock:
            self._stop.set()
        try:
            self.agent._call("guest-shutdown", {"mode": "powerdown"}, 5)
        except (OSError, ValueError, ConnectionError):
            try:
                self.qmp.call("system_powerdown")
            except OSError:
                pass
        if not self.wait_exit(timeout):
            self.power_cut()

    def wait_exit(self, timeout: float) -> bool:
        if not self.proc:
            return True
        try:
            self.proc.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def kill(self) -> None:
        with self._lock:
            self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
