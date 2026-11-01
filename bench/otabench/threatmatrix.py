"""One threat x implementation matrix over both levels (backlog A5, B2).

Rows are the catalog threats, columns the implementations: the real TUF clients of an
MVP run (results.json) and the configurations of each A/B updater adapter seen in pilot
runs (pilot.json). A cell aggregates every scenario the catalog maps to the threat:
FAIL > PARTIAL > ERROR > PASS (an ERROR never lets a cell claim PASS); "—" means no
scenario ran for this implementation, "n/a" that the threat does not apply to its
ecosystem.

Block-level scenarios get threat-specific readings of the per-state verdicts
(ch. 2, tables 2.6-2.7):
  OTA-PWR-03  any BRICK / INCONSISTENT state (prefix or reordering model) -> FAIL
  OTA-PWR-05  liveness: a state whose boot environment is unreadable (env_ok false) or a
              failed liveness retry -> PARTIAL (all states safe, liveness lost in some)
  OTA-PWR-06  sector-torn states (--torn) that do not boot (BRICK) -> FAIL
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

RANK = {"FAIL": 4, "PARTIAL": 3, "ERROR": 2, "PASS": 1}
ICON = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "🟡", "ERROR": "⚠️"}

# configurations of the rauc-grub adapter that are deployment choices (the ext4-c*/wb*
# variants are mechanism experiments and stay out of the threat matrix)
COLUMNS = {
    "ext4-c5": "ext4 /boot (default)", "ext2": "ext2 /boot", "vfat": "vfat /boot",
    "uefi-esp": "UEFI, grubenv on ESP", "ext4-inplace": "+ in-place env (fix)",
    "ext2-inplace": "+ in-place env (fix)", "vfat-inplace": "+ in-place env (fix)",
    "uefi-esp-inplace": "+ in-place env (fix)",
}


def _worst(vs: list[str]) -> str | None:
    return max(vs, key=lambda v: RANK.get(v, 0)) if vs else None


def _points(r: dict) -> list[dict]:
    return r.get("points") or []


def _block_reading(threat: str, r: dict) -> tuple[str, dict] | None:
    """(verdict, counts) for a block-level pilot result read for one threat."""
    pts = _points(r)
    torn = [p for p in pts if p.get("torn")]
    plain = [p for p in pts if not p.get("torn")]
    if threat == "OTA-PWR-03":
        if not plain:
            return ("ERROR", {}) if r.get("verdict") == "ERROR" else None
        bad = sum(p["verdict"] in ("BRICK", "INCONSISTENT") for p in plain)
        deg = sum(p["verdict"] == "DEGRADED" for p in plain)
        return ("FAIL" if bad else "PASS", {"states": len(plain), "bad": bad, "degraded": deg})
    if threat == "OTA-PWR-05":
        if not plain:
            return None
        lost = sum(not p.get("env_ok", True) for p in plain)
        live_fail = sum(not x.get("retry_ok", True) for x in r.get("liveness") or [])
        return ("PARTIAL" if lost or live_fail else "PASS",
                {"states": len(plain), "lost": lost, "retry_failed": live_fail})
    if threat == "OTA-PWR-06":
        if not torn:
            return None
        n = sum(p["verdict"] == "BRICK" for p in torn)
        return ("FAIL" if n else "PASS", {"torn": len(torn), "brick": n})
    return None


def _note(threat: str, c: dict) -> str:
    if not c:
        return ""
    if threat == "OTA-PWR-03":
        return (f"{c['bad']} bad of {c['states']} states" if c["bad"] else
                f"{c['states']} states, {c['degraded']} DEGRADED")
    if threat == "OTA-PWR-05":
        return f"env unreadable in {c['lost']}/{c['states']}" + (
            f", retry failed {c['retry_failed']}" if c.get("retry_failed") else "")
    if threat == "OTA-PWR-06":
        return f"BRICK {c['brick']} of {c['torn']} torn states"
    return ""


BLOCK_THREATS = ("OTA-PWR-03", "OTA-PWR-05", "OTA-PWR-06")


def load_pilots(paths: list[Path]) -> dict[tuple[str, str], dict[str, dict]]:
    """(adapter, configuration) -> scenario -> latest result."""
    runs = []
    for p in paths:
        d = json.loads(p.read_text(encoding="utf-8"))
        runs.append((d.get("started", ""), d))
    out: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    for _, d in sorted(runs, key=lambda x: x[0]):
        adapter = (d.get("updater") or {}).get("adapter", "rauc-grub")
        params_torn = bool((d.get("params") or {}).get("torn"))
        for name, r in d["results"].items():
            torn_run = params_torn or any(p.get("torn") for p in _points(r))
            kind, _, cfg = name.partition(":")
            cfg = cfg or "ext4-c5"  # system scenarios run on the adapter's base image
            key = f"{kind}{' --torn' if torn_run and kind == 'reorder' else ''}"
            out[(adapter, cfg)][key] = r
    return out


def build(catalog: dict, mvp: dict | None, pilots: dict) -> tuple[list[str], list[dict]]:
    cols: list[tuple[str, str, str]] = []  # (label, ecosystem, key)
    if mvp:
        for c in mvp["clients"]:
            if not c.get("control"):
                cols.append((c["name"], c.get("spec") or "tuf", f"mvp:{c['name']}"))
    labels: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for (adapter, cfg) in pilots:
        if cfg in COLUMNS:
            labels[f"{adapter}: {COLUMNS[cfg]}"].append((adapter, cfg))
    for label in labels:
        cols.append((label, "ab-updater", f"ab:{label}"))
    mvp_cell = {(r["scenario"], r["client"]): r for r in (mvp or {}).get("results", [])}

    rows = []
    for t in catalog["threats"]:
        row = {"id": t["id"], "title": t["title"], "expected": t["expected"],
               "existing": ",".join(sorted(k for k, v in (t.get("coverage") or {}).items() if v)),
               "cells": {}}
        for label, eco, key in cols:
            if eco not in t["ecosystems"]:
                row["cells"][label] = ("n/a", "")
                continue
            got: list[str] = []
            counts: dict = {}
            for sid in t["bench"]:
                if key.startswith("mvp:") and not sid.startswith("ab:"):
                    r = mvp_cell.get((sid, key[4:]))
                    if r:
                        got.append(r["verdict"])
                elif key.startswith("ab:") and sid.startswith("ab:"):
                    name = sid[3:]
                    torn = name.endswith(" --torn")
                    base = name.removesuffix(" --torn")
                    for adapter, cfg in labels[key[3:]]:
                        res = pilots[(adapter, cfg)]
                        if base in ("window:*", "reorder:*", "crash-replay"):
                            kind = base.split(":")[0] + (" --torn" if torn else "")
                            r = res.get(kind)
                            if not r:
                                continue
                            if t["id"] in BLOCK_THREATS:
                                rd = _block_reading(t["id"], r)
                                if rd:
                                    got.append(rd[0])
                                    for k, n in rd[1].items():
                                        counts[k] = counts.get(k, 0) + n
                            else:
                                got.append(r["verdict"])
                        elif base in res:
                            got.append(res[base]["verdict"])
            v = _worst(got)
            notes = _note(t["id"], counts)
            row["cells"][label] = (v or "—", notes)
        rows.append(row)
    return [c[0] for c in cols], rows


def write(catalog: dict, mvp: dict | None, pilots: dict, out: Path) -> list[Path]:
    cols, rows = build(catalog, mvp, pilots)
    out.mkdir(parents=True, exist_ok=True)
    tested = [r for r in rows if any(v not in ("n/a", "—") for v, _ in r["cells"].values())]
    lines = ["# otabench: threat × implementation matrix (both levels)", "",
             f"{len(rows)} threats, {len(tested)} exercised by at least one implementation. "
             "Cell = worst verdict over the threat's scenarios (FAIL > PARTIAL > ERROR > PASS); "
             "— = not exercised, n/a = threat does not apply to this ecosystem.", "",
             "| Threat | Title | Existing suites | " + " | ".join(cols) + " |",
             "|---|---|---|" + "---|" * len(cols)]
    for r in rows:
        cells = []
        for c in cols:
            v, note = r["cells"][c]
            cells.append(f"{ICON.get(v, v)}" + (f" {note}" if note else ""))
        lines.append(f"| {r['id']} | {r['title']} | {r['existing'] or '—'} | " + " | ".join(cells) + " |")
    lines += ["", "Readings of block-level results per threat: see the module docstring of "
              "`otabench/threatmatrix.py`."]
    md = out / "threat-matrix.md"
    md.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    cp = out / "threat-matrix.csv"
    with cp.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["threat", "title", "expected", "existing_suites", *cols])
        for r in rows:
            w.writerow([r["id"], r["title"], r["expected"], r["existing"],
                        *[r["cells"][c][0] for c in cols]])
    return [md, cp]
