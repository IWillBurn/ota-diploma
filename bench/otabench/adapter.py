"""Client-under-test adapter.

The adapter protocol is the tuf-conformance CLI (init / refresh / download) so
that any client that already has a tuf-conformance entrypoint plugs in unchanged.
What otabench adds on top is process control: hard timeouts, wall-clock
measurement, and an external kill switch used to emulate a power cut at the
process level (SIGKILL / TerminateProcess: no atexit, no flush, no cleanup).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class ClientSpec:
    name: str
    spec: str  # tuf | uptane | suit | ab-updater
    command: list[str]
    language: str = ""
    version: str = ""
    control: bool = False  # negative control (deliberately broken)
    env: dict[str, str] = field(default_factory=dict)


def load_clients(path: Path) -> list[ClientSpec]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    subst = {
        "{python}": sys._base_executable,  # base interpreter: kill hits the real process
        "{root}": str(ROOT),
        "{node}": shutil.which("node") or "node",
        "{exe}": ".exe" if os.name == "nt" else "",
    }
    site = str(Path(sys.prefix) / ("Lib/site-packages" if os.name == "nt" else
                                   f"lib/python{sys.version_info[0]}.{sys.version_info[1]}/site-packages"))
    out = []
    for c in raw["clients"]:
        cmd = []
        for part in c["command"]:
            for k, v in subst.items():
                part = part.replace(k, v)
            cmd.append(part)
        env = {"PYTHONPATH": site} if "{python}" in c["command"][0] else {}
        env.update(c.get("env", {}))
        if c.get("path_prepend"):
            env["PATH"] = os.pathsep.join([*c["path_prepend"], os.environ.get("PATH", "")])
        out.append(ClientSpec(c["name"], c["spec"], cmd, c.get("language", ""),
                              c.get("version", ""), c.get("control", False), env))
    return out


@dataclass
class RunResult:
    exit_code: int | None
    duration: float
    timed_out: bool = False
    killed: bool = False
    stderr_tail: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.killed


class ClientRunner:
    def __init__(self, spec: ClientSpec, metadata_url: str, targets_url: str) -> None:
        self.spec = spec
        self.metadata_url = metadata_url
        self.targets_url = targets_url
        self._tmp = tempfile.TemporaryDirectory(prefix=f"otabench-{spec.name}-")
        self.base = Path(self._tmp.name)
        self.metadata_dir = self.base / "metadata"
        self.target_dir = self.base / "targets"
        self.metadata_dir.mkdir()
        self.target_dir.mkdir()
        self.kill_switch = threading.Event()
        self.proc_done = threading.Event()  # set once the current run's process is gone
        self.run_id = 0  # increments per run: a delayed kill checks it is still the same run

    def close(self) -> None:
        self._tmp.cleanup()

    # -- protocol ---------------------------------------------------------
    def init(self, trusted_root: bytes) -> RunResult:
        p = self.base / "initial_root.json"
        p.write_bytes(trusted_root)
        return self._run(["--metadata-dir", str(self.metadata_dir), "init", str(p)], 30)

    def refresh(self, timeout: float = 30) -> RunResult:
        return self._run(["--metadata-url", self.metadata_url,
                          "--metadata-dir", str(self.metadata_dir), "refresh"], timeout)

    def download(self, *names: str, timeout: float = 30) -> RunResult:
        args = ["--metadata-url", self.metadata_url, "--metadata-dir", str(self.metadata_dir)]
        for n in names:
            args += ["--target-name", n]
        args += ["--target-dir", str(self.target_dir), "--target-base-url", self.targets_url,
                 "download"]
        return self._run(args, timeout)

    # -- observation ------------------------------------------------------
    def trusted_version(self, role: str) -> int | None:
        try:
            md = json.loads((self.metadata_dir / f"{role}.json").read_bytes())
            return int(md["signed"]["version"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def metadata_parseable(self) -> dict[str, bool]:
        res = {}
        for f in self.metadata_dir.glob("*.json"):
            try:
                json.loads(f.read_bytes())
                res[f.name] = True
            except ValueError:
                res[f.name] = False
        return res

    def downloaded(self) -> list[bytes]:
        return [p.read_bytes() for p in sorted(self.target_dir.rglob("*")) if p.is_file()]

    # -- process control ----------------------------------------------------
    def kill_run(self, run_id: int) -> None:
        """Kill the run `run_id` if it is still the current, unfinished one. A late
        callback (server thread, timer) must not kill the run that follows."""
        if self.run_id == run_id and not self.proc_done.is_set():
            self.kill_switch.set()

    def _run(self, args: list[str], timeout: float) -> RunResult:
        env = {**os.environ, **self.spec.env}
        self.kill_switch.clear()
        self.proc_done.clear()
        self.run_id += 1
        t0 = time.monotonic()
        proc = subprocess.Popen(  # noqa: S603
            [*self.spec.command, *args], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        err_chunks: list[bytes] = []
        reader = threading.Thread(target=lambda: err_chunks.append(proc.stdout.read()), daemon=True)
        reader.start()
        killed = timed_out = False
        while proc.poll() is None:
            if self.kill_switch.is_set():
                proc.kill()
                killed = True
                break
            if time.monotonic() - t0 > timeout:
                proc.kill()
                timed_out = True
                break
            time.sleep(0.002)
        code = proc.wait()
        self.proc_done.set()
        dur = time.monotonic() - t0
        reader.join(1)
        lines = [ln for ln in b"".join(err_chunks).decode(errors="replace").splitlines()
                 if ln.strip() and not ln.startswith(("  ", "	", "Usage:", "Flags:", "Global Flags:"))]
        tail = lines[-2:]
        return RunResult(None if (killed or timed_out) else code, dur, timed_out, killed,
                         " | ".join(tail))
