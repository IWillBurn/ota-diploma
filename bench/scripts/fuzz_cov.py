"""Coverage-guided fuzzing (backlog D5): go-tuf with Go native fuzzing, python-tuf with atheris.

Each target runs for a fixed time budget in Docker; the result per (implementation, version,
target) is PASS (no failure within the budget) or FAIL (crash or unexpected exception, with
the input and the first frames). Harnesses: bench/fuzz/go-tuf/fuzz_test.go,
bench/fuzz/python-tuf/fuzz_tuf.py. Both sign the fuzzed "signed" body with the key the trusted
root delegates to, so inputs reach the logic behind the signature check (OTA-PARSE-01 under a
broken repository / online-key holder), except the Parse targets, which fuzz unsigned bytes.

  python fuzz_cov.py [--budget 300] [--only go-tuf|python-tuf] [--out results/d5-covfuzz-<date>]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FUZZ = ROOT / "fuzz"
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
GO_TARGETS = ["FuzzParse", "FuzzTimestampFirst", "FuzzTimestampSecond", "FuzzSnapshot",
              "FuzzTargets", "FuzzRootUpdate"]
# v2.4.2: latest release (2026-11-01); 923b304: master with the nil checks of #743
# master needs Go >= 1.27 (ML-DSA support, #780)
GO_VERSIONS = {"v2.4.2": ("v2.4.2", "golang:1.25-bookworm"),
               "master-923b304": ("923b304", "golang:1.27-bookworm")}
PY_IMAGE = "otabench-atheris"
PY_TARGETS = ["parse", "timestamp_first", "timestamp_second", "snapshot", "targets", "root_update"]


def docker(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "run", "--rm", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, env=ENV)


def go_runs(work: Path, budget: int, parallel: int, only: list[str] | None = None) -> list[dict]:
    out = []
    for vname, (ver, image) in GO_VERSIONS.items():
        if only and vname not in only:
            continue
        d = work / f"go-tuf-{vname}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        shutil.copy(FUZZ / "go-tuf" / "fuzz_test.go", d)
        (d / "go.mod").write_text("module otabench/fuzz/gotuf\n\ngo 1.25\n", encoding="utf-8")
        mount = ["-v", f"{d.resolve()}:/src", "-v", "otabench-gomod:/go/pkg/mod", "-w", "/src", image]
        p = docker(mount + ["sh", "-c", f"go get github.com/theupdateframework/go-tuf/v2@{ver} && go mod tidy "
                                        "&& go list -m github.com/theupdateframework/go-tuf/v2"], 900)
        resolved = p.stdout.strip().splitlines()[-1] if p.returncode == 0 and p.stdout.strip() else ""
        if p.returncode != 0:
            out.append({"impl": "go-tuf", "version": vname, "target": "*", "verdict": "ERROR",
                        "detail": f"precondition: module setup failed: {p.stderr[-300:]}"})
            continue
        for tgt in GO_TARGETS:
            t0 = time.monotonic()
            p = docker(mount + ["sh", "-c", f"go test -run='^$' -fuzz='^{tgt}$' -fuzztime={budget}s "
                                            f"-parallel={parallel} 2>&1"], budget + 900)
            wall = round(time.monotonic() - t0, 1)
            txt = p.stdout
            execs = re.findall(r"execs: (\d+)", txt)
            r = {"impl": "go-tuf", "version": vname, "module": resolved, "target": tgt, "budget_s": budget,
                 "wall_s": wall, "execs": int(execs[-1]) if execs else None}
            if p.returncode == 0 and "PASS" in txt:
                r.update(verdict="PASS", detail=f"no failure in {budget} s")
            elif "Failing input written to" in txt:
                m = re.search(r"Failing input written to (testdata/fuzz/\S+)", txt)
                frames = [ln.strip() for ln in txt.splitlines()
                          if "go-tuf/v2" in ln and ".go:" in ln][:2]
                first = next((ln.strip() for ln in txt.splitlines() if "panic:" in ln or "--- FAIL" in ln), "")
                crasher = (d / m.group(1)).read_text(encoding="utf-8", errors="replace") if m else ""
                r.update(verdict="FAIL", detail=f"{first[:160]} at {'; '.join(frames)[:300]}",
                         input=crasher[:2000], time_to_failure_s=wall)
            else:
                r.update(verdict="ERROR", detail=f"precondition: go test rc={p.returncode}: {txt[-300:]}")
            print(f"  go-tuf {vname:15s} {tgt:20s} {r['verdict']:5s} {r['detail'][:110]}", flush=True)
            out.append(r)
    return out


def py_runs(work: Path, budget: int) -> list[dict]:
    out = []
    p = subprocess.run(["docker", "build", "-q", "-t", PY_IMAGE, str(FUZZ / "python-tuf")],
                       capture_output=True, text=True, env=ENV, timeout=1800)
    if p.returncode != 0:
        return [{"impl": "python-tuf", "target": "*", "verdict": "ERROR",
                 "detail": f"precondition: image build failed: {p.stderr[-300:]}"}]
    ver = docker([PY_IMAGE, "python", "-c", "import tuf; print(tuf.__version__)"], 120).stdout.strip()
    for tgt in PY_TARGETS:
        d = work / f"python-tuf-{tgt}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        t0 = time.monotonic()
        p = docker(["-v", f"{d.resolve()}:/out", "-w", "/out", PY_IMAGE, "python", "/h/fuzz_tuf.py", tgt,
                    f"-max_total_time={budget}", "-dict=/h/tuf.dict", "-artifact_prefix=/out/"], budget + 600)
        wall = round(time.monotonic() - t0, 1)
        txt = p.stdout + p.stderr
        execs = re.findall(r"#(\d+)\s", txt)
        r = {"impl": "python-tuf", "version": ver, "target": tgt, "budget_s": budget, "wall_s": wall,
             "execs": int(execs[-1]) if execs else None}
        crash = sorted(d.glob("crash-*"))
        if crash:
            exc = next((ln for ln in txt.splitlines() if "Uncaught Python exception" in ln), "")
            tail = [ln for ln in txt.splitlines() if re.match(r"\w+(Error|Exception)\b", ln.strip())][:1]
            frames = [ln.strip() for ln in txt.splitlines() if "/tuf/" in ln and "line" in ln][-2:]
            r.update(verdict="FAIL", detail=f"{(tail[0] if tail else exc).strip()[:160]} at {'; '.join(frames)[:300]}",
                     input=crash[0].read_bytes()[:2000].decode("utf-8", "replace"), time_to_failure_s=wall)
        elif p.returncode == 0 and ("Done" in txt or "max_total_time" in txt or execs):
            r.update(verdict="PASS", detail=f"no unexpected exception in {budget} s")
        else:
            r.update(verdict="ERROR", detail=f"precondition: rc={p.returncode}: {txt[-300:]}")
        print(f"  python-tuf {tgt:20s} {r['verdict']:5s} {r['detail'][:110]}", flush=True)
        out.append(r)
    return out


def go_ttf(out: Path, trials: int, budget: int, parallel: int) -> Path:
    """Repeated trials for the targets that fail on go-tuf v2.4.2: time to the first failure
    (Go's own fuzzing time) and which defect it hit. Each trial starts from the seed corpus
    only: a fresh container (fresh GOCACHE, so no cached fuzz corpus) and no testdata/."""
    ver, image = GO_VERSIONS["v2.4.2"]
    d = out / "work" / "go-tuf-ttf"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    shutil.copy(FUZZ / "go-tuf" / "fuzz_test.go", d)
    (d / "go.mod").write_text("module otabench/fuzz/gotuf\n\ngo 1.25\n", encoding="utf-8")
    mount = ["-v", f"{d.resolve()}:/src", "-v", "otabench-gomod:/go/pkg/mod", "-w", "/src", image]
    p = docker(mount + ["sh", "-c", f"go get github.com/theupdateframework/go-tuf/v2@{ver} && go mod tidy"], 900)
    if p.returncode != 0:
        raise SystemExit(f"module setup failed: {p.stderr[-300:]}")
    rows = []
    for tgt in ("FuzzTimestampSecond", "FuzzParse", "FuzzRootUpdate"):
        for k in range(trials):
            shutil.rmtree(d / "testdata", ignore_errors=True)
            p = docker(mount + ["sh", "-c", f"go test -run='^$' -fuzz='^{tgt}$' -fuzztime={budget}s "
                                            f"-parallel={parallel} 2>&1"], budget + 900)
            m = re.search(rf"--- FAIL: {tgt} \(([\d.]+)s\)", p.stdout)
            site = ("trustedmetadata.go:144" if "trustedmetadata.go:144" in p.stdout else
                    "ed25519 key length" if "bad public key length" in p.stdout else "")
            rows.append({"target": tgt, "trial": k + 1, "found": bool(m),
                         "time_s": float(m.group(1)) if m else None, "defect": site})
            print(f"  ttf {tgt:20s} #{k + 1:2d} {'%.1f s' % float(m.group(1)) if m else 'not found'} {site}", flush=True)
    summ = {}
    for tgt in sorted({r["target"] for r in rows}):
        ts = sorted(r["time_s"] for r in rows if r["target"] == tgt and r["found"])
        summ[tgt] = {"found": f"{len(ts)}/{trials}", "median_s": ts[len(ts) // 2] if ts else None,
                     "min_s": ts[0] if ts else None, "max_s": ts[-1] if ts else None,
                     "defects": sorted({r["defect"] for r in rows if r["target"] == tgt and r["found"]})}
    f = out / "ttf.json"
    f.write_text(json.dumps({"version": "v2.4.2", "budget_s": budget, "parallel": parallel, "trials": trials,
                             "summary": summ, "rows": rows}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    shutil.rmtree(d, ignore_errors=True)
    return f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ttf", type=int, default=0,
                    help="instead of the matrix: N repeated trials of the targets failing on go-tuf v2.4.2")
    ap.add_argument("--budget", type=int, default=300, help="seconds per target")
    ap.add_argument("--parallel", type=int, default=2, help="Go fuzz workers (keep the host usable)")
    ap.add_argument("--only", choices=("go-tuf", "python-tuf"))
    ap.add_argument("--go-versions", default="", help="comma-separated keys of GO_VERSIONS (default: all)")
    ap.add_argument("--out", default=str(ROOT / "results" / f"d5-covfuzz-{date.today():%Y-%m-%d}"))
    a = ap.parse_args()
    out = Path(a.out)
    work = out / "work"
    work.mkdir(parents=True, exist_ok=True)
    if a.ttf:
        print(go_ttf(out, a.ttf, a.budget, a.parallel))
        return 0
    res = []
    if a.only in (None, "go-tuf"):
        res += go_runs(work, a.budget, a.parallel, [v for v in a.go_versions.split(",") if v] or None)
    if a.only in (None, "python-tuf"):
        res += py_runs(work, a.budget)
    prev = out / "results.json"
    if prev.exists():  # keep the other implementation's results of an earlier --only run
        old = json.loads(prev.read_text(encoding="utf-8")).get("results", [])
        done = {(r["impl"], r.get("version")) for r in res}
        res = [r for r in old if (r["impl"], r.get("version")) not in done] + res
    doc = {"started": f"{date.today():%Y-%m-%d}", "budget_s": a.budget, "results": res}
    prev.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    lines = ["# Coverage-guided fuzzing (D5)", "", f"Budget per target: {a.budget} s.", "",
             "| Implementation | Version | Target | Verdict | Execs | Detail |", "|---|---|---|---|---|---|"]
    for r in res:
        lines.append(f"| {r['impl']} | {r.get('version', '')} | {r['target']} | {r['verdict']} | "
                     f"{r.get('execs') or ''} | {r['detail'][:200].replace('|', '/')} |")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    print(out / "summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
