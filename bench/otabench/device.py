"""Device-level adapter (adapter protocol v2): how the bench talks to an A/B updater
running inside a VM.

One YAML file per updater in bench/updaters/ (see docs/adapter-protocol.md). Every command
runs in the guest through qemu-guest-agent as `/bin/sh -c <command>`, so the updater can be
written in any language and shipped prebuilt: the bench only needs a shell, the
updater's own CLI and a status command that prints `key=value` lines.

The scenarios (scripts/pilot_ab.py) use only this interface; they know nothing about the
updater, its bundle format or its bootloader.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
UPDATERS = ROOT / "updaters"


class AdapterError(Exception):
    """The adapter definition cannot serve a request (missing role, variant, ...)."""


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@dataclass(frozen=True)
class Artifact:
    role: str
    path: str  # in the guest
    version: str  # what `status` reports after this artifact has been booted


class Device:
    """An updater under test, as described by bench/updaters/<name>.yaml."""

    def __init__(self, name: str, path: Path | None = None) -> None:
        self.file = Path(path) if path else UPDATERS / f"{name}.yaml"
        if not self.file.exists():
            raise AdapterError(f"no adapter definition {self.file}")
        raw = self._load(self.file)
        self.name = str(raw.get("name", name))
        self.description = str(raw.get("description", ""))
        self.image = Path(raw["image"])
        self.slots = [str(s) for s in raw.get("slots", ["A", "B"])]
        if len(self.slots) != 2:
            raise AdapterError(f"{self.name}: exactly two slots expected, got {self.slots}")
        self.initial_slot = str(raw["initial"]["slot"])
        self.initial_version = str(raw["initial"]["version"])
        self.target_slot = self.other(self.initial_slot)
        self.scratch_dir = str(raw.get("scratch_dir", "/data"))
        self.artifacts = {str(k): Artifact(str(k), str(v["path"]), str(v["version"]))
                          for k, v in (raw.get("artifacts") or {}).items()}
        c = raw["commands"]
        self.cmd_install = str(c["install"])
        self.cmd_status = str(c["status"])
        self.cmd_reboot = str(c.get("reboot", "systemctl reboot"))
        self.cmd_version = c.get("version")
        self.cmd_info = c.get("info")
        self.cmd_debug = c.get("debug")
        self.cmd_unconfirm = c.get("unconfirm")
        bl = raw.get("bootlog") or {}
        run, rescue = bl.get("run"), bl.get("rescue")
        if run and "(?P<slot>" not in run:
            raise AdapterError(f"{self.name}: bootlog.run must capture the selected slot as (?P<slot>...)")
        self._bootlog = (re.compile(f"(?P<_rescue>{rescue})|(?:{run})" if rescue else run)
                         if run else None)
        self.steps = raw.get("steps") or {}
        self.variants = raw.get("variants") or {}
        for v, spec in self.variants.items():
            for item in (spec or {}).get("steps", []):
                ref = item if isinstance(item, str) else item.get("step")
                if ref is not None and ref not in self.steps:
                    raise AdapterError(f"{self.name}: variant {v} refers to unknown step {ref!r}")

    @classmethod
    def _load(cls, path: Path, depth: int = 0) -> dict:
        """Read an adapter file; `extends: <name>` inherits another adapter in the same
        directory (mappings merge recursively, everything else is replaced)."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        parent = raw.pop("extends", None)
        if not parent:
            return raw
        if depth > 4:
            raise AdapterError(f"{path.name}: `extends` chain too deep")
        return _merge(cls._load(path.parent / f"{parent}.yaml", depth + 1), raw)

    # ------------------------------------------------------------------ static facts
    def other(self, slot: str) -> str:
        return next(s for s in self.slots if s != slot)

    def artifact(self, role: str) -> Artifact:
        try:
            return self.artifacts[role]
        except KeyError:
            raise AdapterError(f"updater {self.name} provides no artifact for role {role!r}") from None

    @property
    def initial(self) -> tuple[str, str]:
        """(slot, version) the image boots before any update."""
        return self.initial_slot, self.initial_version

    @property
    def updated(self) -> tuple[str, str]:
        """(slot, version) after the 'v2' artifact has been installed and booted."""
        return self.target_slot, self.artifact("v2").version

    # ------------------------------------------------------------------ guest commands
    def install(self, vm, role: str, timeout: float = 1200) -> tuple[int, float, str]:
        """Install the artifact for `role`; returns (exit code, seconds, last output line)."""
        cmd = self.cmd_install.replace("{artifact}", shlex.quote(self.artifact(role).path))
        t = time.monotonic()
        rc, out, err = vm.agent.sh(cmd, timeout)
        lines = (out + err).strip().splitlines()
        return rc, time.monotonic() - t, lines[-1] if lines else ""

    def status(self, vm, timeout: float = 60) -> dict:
        """Normalized device status (keys documented in docs/adapter-protocol.md)."""
        _, out, _ = vm.agent.sh(self.cmd_status, timeout)
        return self.parse_status(out)

    @staticmethod
    def parse_status(out: str) -> dict:
        kv: dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v
        return {"slot": kv.get("slot") or None,
                "version": kv.get("version") or None,
                "confirmed": kv.get("confirmed") == "1",
                # omitted -> the bench cannot judge the boot state, so it does not flag it
                "env_ok": kv.get("env_ok", "1") == "1",
                "order": kv.get("order"),
                "primary": kv.get("primary") or None,
                "env": {k[4:]: v for k, v in kv.items() if k.startswith("env.")}}

    def version(self, vm) -> str | None:
        if not self.cmd_version:
            return None
        rc, out, _ = vm.agent.sh(str(self.cmd_version), 30)
        return out.strip().splitlines()[0] if rc == 0 and out.strip() else None

    def info(self, vm) -> str:
        if not self.cmd_info:
            return ""
        return vm.agent.sh(str(self.cmd_info), 30)[1].strip()

    def debug(self, vm) -> str:
        if not self.cmd_debug:
            return ""
        return vm.agent.sh(str(self.cmd_debug), 60)[1]

    # ------------------------------------------------------------------ bootloader log
    def boot_runs(self, serial_text: str) -> list[dict]:
        """One entry per bootloader run seen on the serial console, in order. A `rescue`
        line marks the selection line that follows it."""
        if self._bootlog is None:
            return []
        runs, rescue = [], False
        for m in self._bootlog.finditer(serial_text):
            g = m.groupdict()
            if g.get("_rescue") is not None:
                rescue = True
                continue
            r = {k: v for k, v in g.items() if k != "_rescue"}
            r["rescue"] = rescue
            rescue = False
            runs.append(r)
        return runs

    # ------------------------------------------------------------------ variants
    def firmware(self, variant: str) -> str:
        return str((self.variants.get(variant) or {}).get("firmware", "bios"))

    def variant_scripts(self, variant: str) -> list[tuple[str, str]]:
        """Shell scripts (name, body) that turn the base image into `variant`. Each runs
        with `set -e`; uploads are embedded as base64."""
        if variant not in self.variants:
            raise AdapterError(f"updater {self.name} has no variant {variant!r}")
        out = []
        for item in (self.variants[variant] or {}).get("steps", []):
            item = {"step": item} if isinstance(item, str) else dict(item)
            if "run" in item:
                name, body, uploads = "run", str(item["run"]), {}
            else:
                name = item["step"]
                s = self.steps[name]
                body, uploads = (str(s.get("run", "")), s.get("upload") or {}) \
                    if isinstance(s, dict) else (str(s), {})
            env = "".join(f"{k}={shlex.quote(str(v))}\n" for k, v in (item.get("env") or {}).items())
            up = "".join(f"echo {base64.b64encode((ROOT / src).read_bytes()).decode()} "
                         f"| base64 -d > {shlex.quote(dst)}\n" for dst, src in uploads.items())
            out.append((name, "set -e\n" + env + up + body))
        return out

    def variant_id(self, variant: str) -> str:
        """Cache key: changes whenever the base image or the variant's scripts change."""
        st = self.image.stat()
        h = hashlib.sha256(f"{self.image.name}:{st.st_size}:{st.st_mtime_ns}:"
                           f"{self.firmware(variant)}".encode())
        for _, body in self.variant_scripts(variant):
            h.update(body.encode())
        return f"{self.name}-{variant}-{h.hexdigest()[:8]}"
