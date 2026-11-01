"""Threat matrix over both levels: aggregation and block-level readings."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.threatmatrix import build, load_pilots  # noqa: E402

CAT = {"threats": [
    {"id": "OTA-FRESH-02", "title": "rollback", "expected": "block", "ecosystems": ["tuf", "ab-updater"],
     "coverage": {}, "bench": ["rollback-timestamp", "online-keys-downgrade", "ab:downgrade"]},
    {"id": "OTA-PWR-05", "title": "liveness", "expected": "survive", "ecosystems": ["ab-updater"],
     "coverage": {}, "bench": ["ab:reorder:*"]},
    {"id": "OTA-PWR-06", "title": "running slot", "expected": "survive", "ecosystems": ["ab-updater"],
     "coverage": {}, "bench": ["ab:reorder:* --torn"]},
    {"id": "OTA-AUTH-03", "title": "keyid", "expected": "block", "ecosystems": ["tuf"],
     "coverage": {"tuf-conformance": ["t"]}, "bench": ["arb-keyid-spoofing"]},
]}
MVP = {"clients": [{"name": "a"}, {"name": "b"}, {"name": "naive", "control": True}],
       "results": [
           {"scenario": "rollback-timestamp", "client": "a", "verdict": "PASS"},
           {"scenario": "online-keys-downgrade", "client": "a", "verdict": "PARTIAL"},
           {"scenario": "rollback-timestamp", "client": "b", "verdict": "ERROR"},
           {"scenario": "online-keys-downgrade", "client": "b", "verdict": "PASS"},
           {"scenario": "arb-keyid-spoofing", "client": "a", "verdict": "PASS"}]}


def _pt(v: str, env_ok: bool = True, torn: bool = False) -> dict:
    return {"verdict": v, "env_ok": env_ok, "torn": torn}


def _pilots(tmp_path: Path) -> dict:
    old = {"started": "1", "results": {
        "downgrade": {"verdict": "PASS"},
        "reorder:vfat": {"verdict": "PASS", "points": [_pt("OK"), _pt("DEGRADED", env_ok=False)]}}}
    new = {"started": "2", "updater": {"adapter": "rauc-grub"}, "results": {
        "downgrade": {"verdict": "FAIL"},  # latest run wins
        "reorder:vfat": {"verdict": "FAIL", "points": [_pt("OK"), _pt("BRICK", torn=True)]}}}
    for name, d in (("old", old), ("new", new)):
        (tmp_path / f"{name}.json").write_text(json.dumps(d), encoding="utf-8")
    return load_pilots([tmp_path / "old.json", tmp_path / "new.json"])


def test_mvp_aggregation_worst_wins() -> None:
    cols, rows = build(CAT, MVP, {})
    assert cols == ["a", "b"]  # controls are not columns
    r = {x["id"]: x for x in rows}
    assert r["OTA-FRESH-02"]["cells"]["a"][0] == "PARTIAL"
    assert r["OTA-FRESH-02"]["cells"]["b"][0] == "ERROR"  # an ERROR never yields PASS
    assert r["OTA-PWR-05"]["cells"]["a"][0] == "n/a"


def test_pilot_readings(tmp_path: Path) -> None:
    pilots = _pilots(tmp_path)
    assert ("rauc-grub", "vfat") in pilots and ("rauc-grub", "ext4-c5") in pilots
    cols, rows = build(CAT, None, pilots)
    r = {x["id"]: x for x in rows}
    vfat = "rauc-grub: vfat /boot"
    default = "rauc-grub: ext4 /boot (default)"
    assert r["OTA-FRESH-02"]["cells"][default][0] == "FAIL"
    # the latest vfat run had a torn run: its plain states only feed PWR-05 when not torn
    assert r["OTA-PWR-06"]["cells"][vfat] == ("FAIL", "BRICK 1 of 1 torn states")
    assert r["OTA-PWR-05"]["cells"][vfat][0] == "PARTIAL"  # env lost in the earlier non-torn run
    assert r["OTA-AUTH-03"]["cells"][vfat][0] == "n/a"
