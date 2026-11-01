"""Render results.json + catalog into a threat x implementation matrix."""

from __future__ import annotations

import html
from collections import defaultdict
from pathlib import Path

import yaml

ICON = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "🟡", "ERROR": "⚠️", None: "·"}


SCHEMA = Path(__file__).resolve().parent.parent / "catalog" / "threats.schema.json"


class CatalogError(ValueError):
    pass


def load_catalog(path: Path, schema: Path = SCHEMA) -> dict:
    """Load the threat catalog and refuse it unless it matches catalog/threats.schema.json
    and every id is unique."""
    catalog = yaml.safe_load(path.read_text(encoding="utf-8"))
    import json

    import jsonschema

    try:
        jsonschema.validate(catalog, json.loads(schema.read_text(encoding="utf-8")))
    except jsonschema.ValidationError as e:
        where = "/".join(str(p) for p in e.absolute_path)
        raise CatalogError(f"{path.name}: {where}: {e.message}") from None
    ids = [t["id"] for t in catalog["threats"]]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise CatalogError(f"{path.name}: duplicate ids {dup}")
    return catalog


def coverage_table(catalog: dict) -> list[dict]:
    """Per threat: is it covered by existing suites, by otabench, by both, or nobody."""
    rows = []
    for t in catalog["threats"]:
        existing = sorted(k for k, v in (t.get("coverage") or {}).items() if v)
        rows.append({"id": t["id"], "title": t["title"], "class": t["class"],
                     "ecosystems": t["ecosystems"], "existing": existing,
                     "bench": t.get("bench", []), "level": t.get("level", "")})
    return rows


def _matrix(run: dict):
    clients = [c["name"] for c in run["clients"]]
    cell = {(r["scenario"], r["client"]): r for r in run["results"]}
    scen = list(dict.fromkeys(r["scenario"] for r in run["results"]))
    return clients, scen, cell


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return (max(0.0, mid - half), min(1.0, mid + half))


def is_fault(r: dict) -> bool:
    """Fault-tolerance scenario (power cut, network loss) rather than an attack."""
    return any(t.startswith(("OTA-PWR", "OTA-NET")) for t in r.get("threats", []))


def _metric_str(r: dict) -> str:
    m = r.get("metrics") or {}
    parts = []
    if "time_to_abort_s" in m:
        parts.append(f"abort {m['time_to_abort_s']}s")
    if "bytes_pushed" in m:
        v = m["bytes_pushed"]
        parts.append(f"{v / 1048576:.1f} MiB" if v >= 1048576 else f"{v / 1024:.0f} KiB"
                     if v >= 10240 else f"{v} B")
    if "survival_rate" in m and m.get("census"):
        # every point of a defined set was tried: a census, not a sample -> no interval
        parts.append(f"survived {m.get('survived')}/{m.get('trials')} kill points (census)")
    elif "survival_rate" in m:
        lo, hi = wilson(int(m.get("survived", 0)), int(m.get("trials", 0)))
        parts.append(f"survival {m['survival_rate']:.0%} [{lo:.0%}–{hi:.0%}] (n={m.get('trials')})")
    if isinstance(m.get("mean_recovery_s"), (int, float)):
        parts.append(f"recovery {m['mean_recovery_s']}s")
    if m.get("torn_file_observed"):
        parts.append(f"torn file {m['torn_file_observed']}×")
    if m.get("torn_file_after_drop"):
        parts.append("torn file after drop")
    return ", ".join(parts)


def differential(run: dict) -> list[str]:
    """Scenarios where non-control implementations disagree (differential testing)."""
    controls = {c["name"] for c in run["clients"] if c.get("control")}
    by_s = defaultdict(set)
    for r in run["results"]:
        if r["client"] not in controls and r["verdict"] != "ERROR":
            by_s[r["scenario"]].add(r["verdict"])
    return [s for s, v in by_s.items() if len(v) > 1]


def summary(run: dict) -> dict[str, dict]:
    """Block rate over the *common* scenario set: scenarios where no client under
    comparison produced ERROR, so that rates are comparable between clients."""
    names = [c["name"] for c in run["clients"]]
    by = {(r["scenario"], r["client"]): r for r in run["results"]}
    scen = [s for s in dict.fromkeys(r["scenario"] for r in run["results"]) if s != "baseline"]
    common = [s for s in scen if all(by.get((s, c), {}).get("verdict") not in (None, "ERROR")
                                     for c in names)]
    out = {}
    fault = {s for s in common if is_fault(by[(s, names[0])])}
    for c in names:
        def score(ss: list[str]) -> float:
            return sum(1.0 if by[(s, c)]["verdict"] == "PASS" else
                       0.5 if by[(s, c)]["verdict"] == "PARTIAL" else 0.0 for s in ss)
        atk = [s for s in common if s not in fault]
        flt = [s for s in common if s in fault]
        out[c] = {"scored": len(atk), "blocked": score(atk),
                  "block_rate": round(score(atk) / len(atk), 3) if atk else 0.0,
                  "faults": len(flt), "survived": score(flt),
                  "survive_rate": round(score(flt) / len(flt), 3) if flt else 0.0,
                  "excluded": [s for s in scen if s not in common]}
    return out


def mutation_score(run: dict) -> list[tuple[str, list[str]]]:
    """For each scenario: which control clients / mutants it kills (FAIL or PARTIAL).
    A scenario that kills nothing has not shown it can detect anything."""
    controls = [c["name"] for c in run["clients"] if c.get("control")]
    by = {(r["scenario"], r["client"]): r["verdict"] for r in run["results"]}
    scen = [s for s in dict.fromkeys(r["scenario"] for r in run["results"]) if s != "baseline"]
    return [(s, [c for c in controls if by.get((s, c)) in ("FAIL", "PARTIAL")]) for s in scen]


def to_markdown(run: dict, catalog: dict) -> str:
    clients, scen, cell = _matrix(run)
    diff = set(differential(run))
    lines = ["# otabench: threat × implementation matrix", "",
             f"Run: {run['started']} · host: {run['host']['os']} · trials: {run['params']['trials']}",
             "", "| Scenario | Threats | " + " | ".join(clients) + " |",
             "|---|---|" + "---|" * len(clients)]
    for s in scen:
        any_r = cell[(s, clients[0])]
        name = f"**{s}** ⚡" if s in diff else s
        row = [name, ", ".join(any_r["threats"])]
        for c in clients:
            r = cell.get((s, c))
            row.append(f"{ICON[r['verdict']] if r else '·'} {_metric_str(r) if r else ''}".strip())
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "⚡ = differential finding: real implementations of the same spec disagree.", "",
              "## Rates over the common scenario set (PARTIAL counts 0.5)", "",
              "| Client | spec | attacks blocked | rate | faults survived | rate |",
              "|---|---|---|---|---|---|"]
    specs = {c["name"]: c for c in run["clients"]}
    for c, s in summary(run).items():
        tag = " (control)" if specs[c].get("control") else ""
        lines.append(f"| {c}{tag} | {specs[c]['spec']} | {s['blocked']}/{s['scored']} | "
                     f"{s['block_rate']:.0%} | {s['survived']}/{s['faults']} | {s['survive_rate']:.0%} |")
    excl = next(iter(summary(run).values()), {}).get("excluded", [])
    if excl:
        lines += ["", f"Excluded from the rate because some client returned ERROR: {', '.join(excl)}"]
    if any(c.get("control") for c in run["clients"]):
        lines += ["", "## Mutation analysis (which controls each scenario kills)", "",
                  "| Scenario | killed controls |", "|---|---|"]
        for s, killed in mutation_score(run):
            lines.append(f"| {s} | {', '.join(killed) or '**none**'} |")
    lines += ["", "## Details", ""]
    for s in scen:
        for c in clients:
            r = cell.get((s, c))
            if r and r["detail"]:
                lines.append(f"- `{s}` / {c}: {r['verdict']} — {r['detail']}")
    lines += ["", "## Catalog coverage", "", "| Threat | Class | Existing suites | otabench |",
              "|---|---|---|---|"]
    for row in coverage_table(catalog):
        lines.append(f"| {row['id']} {row['title']} | {row['class']} | "
                     f"{', '.join(row['existing']) or '—'} | {', '.join(row['bench']) or '—'} |")
    return "\n".join(lines) + "\n"


def to_html(run: dict, catalog: dict) -> str:
    clients, scen, cell = _matrix(run)
    diff = set(differential(run))
    cls = {"PASS": "pass", "FAIL": "fail", "PARTIAL": "partial", "ERROR": "err"}
    th = "".join(f"<th>{html.escape(c)}</th>" for c in clients)
    body = []
    for s in scen:
        r0 = cell[(s, clients[0])]
        tds = []
        for c in clients:
            r = cell.get((s, c))
            if not r:
                tds.append("<td></td>")
                continue
            tip = html.escape(r["detail"])
            tds.append(f'<td class="{cls[r["verdict"]]}" title="{tip}"><b>{r["verdict"]}</b>'
                       f'<small>{html.escape(_metric_str(r))}</small></td>')
        mark = ' <span class="diff" title="implementations disagree">⚡</span>' if s in diff else ""
        body.append(f"<tr><th class='s'>{html.escape(s)}{mark}<small>{html.escape(r0['title'])}</small>"
                    f"</th><td class='t'>{html.escape(', '.join(r0['threats']))}</td>{''.join(tds)}</tr>")
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>otabench matrix</title>
<style>
:root{{--bg:#fbfbfa;--fg:#1d1d1b;--mut:#6b6b66;--line:#e3e2de;--pass:#e3f1e6;--fail:#f8e1de;--partial:#fbf0d4;--err:#ececec}}
@media (prefers-color-scheme:dark){{:root{{--bg:#191917;--fg:#ecebe7;--mut:#9b9a94;--line:#33332f;--pass:#1f3a27;--fail:#4a2320;--partial:#4a3d1a;--err:#2c2c2a}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:24px 16px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid var(--line);padding:6px 8px;vertical-align:top;text-align:left}}
small{{display:block;color:var(--mut);font-size:12px;font-weight:400}}td.pass{{background:var(--pass)}}td.fail{{background:var(--fail)}}
td.partial{{background:var(--partial)}}td.err{{background:var(--err)}}td.t{{font-family:ui-monospace,monospace;font-size:12px}}
.wrap{{overflow-x:auto}}h1{{font-size:20px}}
</style><h1>otabench: threat × implementation</h1>
<p>{html.escape(run['started'])} · {html.escape(run['host']['os'])} · trials={run['params']['trials']}</p>
<div class="wrap"><table><tr><th>scenario</th><th>threats</th>{th}</tr>{''.join(body)}</table></div>
<p>⚡ differential finding: real implementations of the same spec disagree.</p></html>"""


def to_csv(run: dict) -> str:
    """Long format, one row per (scenario, client): ready for pandas / thesis tables."""
    import csv
    import io

    keys = ["time_to_abort_s", "bytes_pushed", "survival_rate", "trials", "mean_recovery_s",
            "torn_file_observed"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scenario", "threats", "client", "verdict", *keys, "detail"])
    for r in run["results"]:
        m = r.get("metrics") or {}
        w.writerow([r["scenario"], " ".join(r["threats"]), r["client"], r["verdict"],
                    *[m.get(k, "") for k in keys], r["detail"]])
    return buf.getvalue()


def write_reports(run: dict, catalog: dict, out_dir: Path) -> tuple[Path, Path, Path]:
    (out_dir / "matrix.csv").write_text(to_csv(run), encoding="utf-8")
    md = out_dir / "matrix.md"
    md.write_text(to_markdown(run, catalog), encoding="utf-8")
    h = out_dir / "matrix.html"
    h.write_text(to_html(run, catalog), encoding="utf-8")
    return md, h, out_dir / "matrix.csv"
