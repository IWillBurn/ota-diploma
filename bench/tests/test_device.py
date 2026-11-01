"""Unit tests for the device adapter (protocol v2) — no VM needed."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from otabench.device import AdapterError, Device  # noqa: E402

GRUB_LINE = ("otabench-grub: ORDER=[{o}] A_OK={a} A_TRY=0 B_OK={b} B_TRY=0 -> {s}\n")


@pytest.fixture()
def rauc() -> Device:
    return Device("rauc-grub")


def _adapter(tmp_path: Path, body: str) -> Device:
    img = tmp_path / "img.qcow2"
    img.write_bytes(b"x")
    p = tmp_path / "t.yaml"
    p.write_text(textwrap.dedent(body).replace("@IMG@", img.as_posix()), encoding="utf-8")
    return Device("t", p)


MINIMAL = """\
    name: t
    image: @IMG@
    initial: {slot: A, version: "1"}
    artifacts: {v2: {path: /x/v2.bin, version: "2"}}
    commands: {install: "inst {artifact}", status: "st"}
    bootlog: {run: 'pick (?P<slot>\\w)', rescue: 'RESCUE'}
    steps:
      s1: {run: "echo $X"}
      up: {upload: {/tmp/f: tests/test_device.py}, run: "cat /tmp/f"}
    variants:
      v: {steps: [{step: s1, env: {X: "a b"}}, {run: "true"}, up]}
      u: {firmware: uefi, steps: []}
"""


def test_rauc_adapter_loads(rauc: Device) -> None:
    assert rauc.initial == ("A", "1")
    assert rauc.updated == ("B", "2")
    assert {"v1", "v2", "v2-broken", "v2-attacker"} <= set(rauc.artifacts)
    assert rauc.firmware("uefi-esp") == "uefi" and rauc.firmware("ext2") == "bios"
    assert {"ext4-c5", "ext2", "vfat", "ext4-inplace", "uefi-esp", "ext4-inplace-rootro"} <= set(rauc.variants)


def test_parse_status_full() -> None:
    st = Device.parse_status("noise\nslot=B\nversion=2\nconfirmed=1\nenv_ok=1\norder=B A\n"
                             "primary=rootfs.1\nenv.ORDER=B A\nenv.X=a=b\n")
    assert st == {"slot": "B", "version": "2", "confirmed": True, "env_ok": True, "order": "B A",
                  "primary": "rootfs.1", "env": {"ORDER": "B A", "X": "a=b"}}


def test_parse_status_defaults() -> None:
    st = Device.parse_status("slot=\nversion=1\n")
    assert st["slot"] is None and st["confirmed"] is False
    assert st["env_ok"] is True  # not reported -> not judged
    assert st["order"] is None and st["env"] == {}
    assert Device.parse_status("env_ok=0")["env_ok"] is False


def test_boot_runs_rescue_marks_next_run(rauc: Device) -> None:
    text = (GRUB_LINE.format(o="A B", a=1, b=0, s="A")
            + "otabench-grub: RESCUE (no slot is OK and untried)\n"
            + GRUB_LINE.format(o="B A", a=1, b=1, s="A")
            + "otabench-grub: BOOT FAILED for A\n"
            + GRUB_LINE.format(o="B A", a=1, b=1, s="B"))
    runs = rauc.boot_runs(text)
    assert [(r["slot"], r["order"], r["rescue"]) for r in runs] == \
        [("A", "A B", False), ("A", "B A", True), ("B", "B A", False)]
    assert runs[0]["A_OK"] == "1" and "_rescue" not in runs[0]


def test_bootlog_requires_slot_group(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="slot"):
        _adapter(tmp_path, MINIMAL.replace("(?P<slot>", "("))


def test_unknown_step_rejected(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="unknown step"):
        _adapter(tmp_path, MINIMAL.replace("{run: \"true\"}, up]", "{run: \"true\"}, nope]"))


def test_missing_role_is_adapter_error(tmp_path: Path) -> None:
    d = _adapter(tmp_path, MINIMAL)
    with pytest.raises(AdapterError, match="v2-broken"):
        d.artifact("v2-broken")
    with pytest.raises(AdapterError):
        d.variant_scripts("nope")


def test_variant_scripts(tmp_path: Path) -> None:
    d = _adapter(tmp_path, MINIMAL)
    scripts = d.variant_scripts("v")
    assert [n for n, _ in scripts] == ["s1", "run", "up"]
    assert scripts[0][1] == "set -e\nX='a b'\necho $X"
    assert scripts[1][1] == "set -e\ntrue"
    assert scripts[2][1].startswith("set -e\necho ") and "| base64 -d > /tmp/f\ncat /tmp/f" in scripts[2][1]
    assert d.firmware("u") == "uefi" and d.variant_scripts("u") == []


def test_variant_id_tracks_scripts_and_image(tmp_path: Path) -> None:
    d1 = _adapter(tmp_path, MINIMAL)
    d2 = _adapter(tmp_path, MINIMAL.replace("echo $X", "echo ${X}"))
    assert d1.variant_id("v") != d2.variant_id("v")
    assert d1.variant_id("v") != d1.variant_id("u")
    before = d2.variant_id("v")
    img = tmp_path / "img.qcow2"
    img.write_bytes(b"xy")  # base image rebuilt
    assert d2.variant_id("v") != before


def test_install_substitutes_quoted_path(tmp_path: Path) -> None:
    d = _adapter(tmp_path, MINIMAL.replace("/x/v2.bin", "/x/my v2.bin"))

    class Agent:
        def sh(self, cmd, timeout):
            self.cmd = cmd
            return 0, "line1\nlast\n", ""

    class VM:
        agent = Agent()

    rc, secs, last = d.install(VM, "v2")
    assert (rc, last) == (0, "last") and VM.agent.cmd == "inst '/x/my v2.bin'"


def test_extends_inherits_and_overrides(tmp_path: Path) -> None:
    base = _adapter(tmp_path, MINIMAL)
    (tmp_path / "child.yaml").write_text(textwrap.dedent("""\
        name: child
        extends: t
        image: @IMG@
        commands: {install: "inst2 {artifact}"}
        variants:
          w: {steps: [s1]}
        """).replace("@IMG@", base.image.as_posix()), encoding="utf-8")
    c = Device("child", tmp_path / "child.yaml")
    assert c.name == "child" and c.cmd_install == "inst2 {artifact}"
    assert c.cmd_status == "st"  # inherited inside the merged `commands` mapping
    assert set(c.variants) == {"v", "u", "w"} and c.initial == ("A", "1")


def test_real_rauc_upgrade_adapter() -> None:
    d = Device("rauc1.15.2-grub")
    assert d.cmd_install == Device("rauc-grub").cmd_install
    assert "minver" in d.variants and set(d.variants) == set(Device("rauc-grub").variants) | {"minver"}


def test_install_path_override_and_slot_digest(tmp_path: Path) -> None:
    d = _adapter(tmp_path, MINIMAL)
    d.cmd_slot_digest = "dig {slot}"

    class Agent:
        def sh(self, cmd, timeout):
            self.cmd = cmd
            return 0, ("ab" * 32 + "\n") if cmd.startswith("dig") else "ok\n", ""

    class VM:
        agent = Agent()

    d.install(VM, "v2", path="/data/t/update.bin")
    assert VM.agent.cmd == "inst /data/t/update.bin"
    assert d.slot_digest(VM, "B") == "ab" * 32 and VM.agent.cmd == "dig B"


def test_control_installer_adapter() -> None:
    n, r = Device("naive-rauc-grub"), Device("rauc-grub")
    assert n.cmd_install != r.cmd_install and "mount -o loop" in n.cmd_install
    assert (n.cmd_status, n.cmd_slot_digest, n.image) == (r.cmd_status, r.cmd_slot_digest, r.image)
    assert n.artifact("v2-attacker").path == r.artifact("v2-attacker").path


ROLES = ("v1", "v2", "v2-broken", "v2-attacker")


@pytest.mark.parametrize("name", sorted(p.stem for p in (Path(__file__).resolve().parent.parent
                                                         / "updaters").glob("*.yaml")))
def test_every_adapter_provides_all_roles(name: str) -> None:
    """The artifact roles are the protocol-driver interface: scenarios know roles, not formats."""
    d = Device(name)
    for role in ROLES:
        a = d.artifact(role)
        assert a.path.startswith("/") and a.version
    assert d.artifact("v2").path != d.artifact("v2-attacker").path
    assert Path(d.artifact("v2").path).suffix == Path(d.artifact("v2-attacker").path).suffix
