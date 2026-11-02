"""otabench CLI.

  python -m otabench list
  python -m otabench coverage
  python -m otabench run [--clients python-tuf,go-tuf] [--scenarios a,b] [--trials 10] [--quick]
  python -m otabench report results/<run>/results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from . import scenarios as sc
from .adapter import ROOT, load_clients
from .report import coverage_table, load_catalog, summary, write_reports
from .runner import run_matrix, save
from .server import Caps

CATALOG = ROOT / "catalog" / "threats.yaml"
CLIENTS = ROOT / "clients.yaml"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="otabench")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios")
    sub.add_parser("coverage", help="catalog coverage analysis")
    r = sub.add_parser("run", help="run the matrix")
    r.add_argument("--clients", default="")
    r.add_argument("--scenarios", default="")
    r.add_argument("--trials", type=int, default=10)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--jobs", type=int, default=4)
    r.add_argument("--quick", action="store_true", help="short caps, 3 trials")
    r.add_argument("--out", default="")
    rep = sub.add_parser("report", help="re-render reports from results.json")
    rep.add_argument("results")
    th = sub.add_parser("threats", help="threat x implementation matrix over both levels")
    th.add_argument("--mvp", nargs="*", default=[], help="results.json of MVP runs (later wins)")
    th.add_argument("--pilot", nargs="*", default=[], help="pilot.json files (latest wins)")
    th.add_argument("--refuted", nargs="*", default=[], help="refuted.json lists of states a replay refuted")
    th.add_argument("--out", required=True)
    co = sub.add_parser("compliance", help="evidence per regulation clause for one implementation")
    co.add_argument("--mvp", nargs="*", default=[])
    co.add_argument("--pilot", nargs="*", default=[])
    co.add_argument("--refuted", nargs="*", default=[])
    co.add_argument("--impl", required=True, help="a column of the threat matrix, e.g. python-tuf")
    co.add_argument("--regs", default="cra,unr156,en18031,nist800193,fstec117,fstec239,fstec_method")
    co.add_argument("--out", required=True)
    a = p.parse_args(argv)
    catalog = load_catalog(CATALOG)

    if a.cmd in ("threats", "compliance"):
        from .threatmatrix import load_pilots, load_refuted, write

        mvp = None
        for f in a.mvp:  # merge runs: a later (scenario, client) result replaces an earlier one
            run = json.loads(Path(f).read_text(encoding="utf-8"))
            if mvp is None:
                mvp = run
                continue
            names = {c["name"] for c in mvp["clients"]}
            mvp["clients"] += [c for c in run["clients"] if c["name"] not in names]
            new = {(r["scenario"], r["client"]) for r in run["results"]}
            mvp["results"] = [r for r in mvp["results"] if (r["scenario"], r["client"]) not in new]
            mvp["results"] += run["results"]
        pilots = load_pilots([Path(x) for x in a.pilot], load_refuted([Path(x) for x in a.refuted]))
        if a.cmd == "compliance":
            from .compliance import write as write_compliance

            print(write_compliance(catalog, mvp, pilots, a.impl, a.regs.split(","), Path(a.out)))
            return 0
        for f in write(catalog, mvp, pilots, Path(a.out)):
            print(f)
        return 0

    if a.cmd == "list":
        for sid, (threats, title, _) in sc.REGISTRY.items():
            print(f"{sid:<26} {','.join(threats):<28} {title}")
        return 0

    if a.cmd == "coverage":
        rows = coverage_table(catalog)
        n = len(rows)
        ex = sum(1 for r in rows if r["existing"])
        be = sum(1 for r in rows if r["bench"])
        new = sum(1 for r in rows if r["bench"] and not r["existing"])
        none = sum(1 for r in rows if not r["bench"] and not r["existing"])
        for r in rows:
            print(f"{r['id']:<12} {r['class']:<16} existing={','.join(r['existing']) or '-':<22} "
                  f"bench={','.join(r['bench']) or '-'}")
        print(f"\n{n} threats: covered by existing suites {ex}, by otabench {be} "
              f"(of which {new} not covered elsewhere), uncovered {none}")
        return 0

    if a.cmd == "report":
        res = Path(a.results)
        run = json.loads(res.read_text(encoding="utf-8"))
        for f in write_reports(run, catalog, res.parent):
            print(f)
        return 0

    clients = load_clients(CLIENTS)
    if a.clients:
        want = a.clients.split(",")
        clients = [c for c in clients if c.name in want]
    sids = a.scenarios.split(",") if a.scenarios else list(sc.REGISTRY)
    unknown = [s for s in sids if s not in sc.REGISTRY]
    if unknown:
        print(f"unknown scenarios: {unknown}", file=sys.stderr)
        return 2
    caps = Caps(endless_seconds=10, slow_seconds=20) if a.quick else Caps()
    trials = 3 if a.quick else a.trials
    out = Path(a.out) if a.out else ROOT / "results" / datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"otabench: {len(clients)} clients x {len(sids)} scenarios, trials={trials}, jobs={a.jobs}")
    run = run_matrix(clients, sids, trials=trials, seed=a.seed, jobs=a.jobs, caps=caps)
    path = save(run, out)
    md, h, csv_path = write_reports(run, catalog, out)
    print(f"\nresults: {path}\nmatrix:  {md}\n         {h}\n         {csv_path}")
    for c, s in summary(run).items():
        print(f"  {c:<14} attacks blocked {s['block_rate']:.0%} ({s['blocked']}/{s['scored']}), "
              f"faults survived {s['survive_rate']:.0%} ({s['survived']}/{s['faults']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
