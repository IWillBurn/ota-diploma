"""SUIT profile (backlog A6): libcsuit, through the otabench adapter image (otabench-suit).

The artifacts are libcsuit's own signed test manifests (trust anchor = the project's test
key); the bench derives the attacks from them, so it never needs the signing key:
  suit-baseline             expU + the genuine payload must be processed
  suit-payload-substitution payload altered, digest no longer matches   (OTA-AUTH-01)
  suit-manifest-tamper      one byte of the signed manifest flipped      (OTA-AUTH-02)
  suit-signature-tamper     one byte of the COSE signature flipped       (OTA-AUTH-02)
  suit-extra-data           bytes appended after the payload             (OTA-AUTH-04)
  suit-malformed            truncated envelope + 20 random inputs: no crash (OTA-PARSE-01)
Clients: libcsuit (adapter) and libcsuit-example (negative control: OTABENCH_SUPPRESS=1,
the upstream example's behaviour of suppressing failed conditions).

  python suit_bench.py [--out results/suit-<date>]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench import __version__  # noqa: E402
from otabench.report import load_catalog, write_reports  # noqa: E402

IMAGE = "otabench-suit"
TA = "8d82573a-926d-4754-9353-32dc29997f74.ta"
URI = f"https://example.org/{TA}"
MANIFEST = "/libcsuit/testfiles/suit_manifest_expU.suit"
CLIENTS = [
    {"name": "libcsuit", "spec": "suit", "language": "C", "version": "libcsuit 00f5609 (otabench adapter)",
     "control": False, "env": {}},
    {"name": "libcsuit-example", "spec": "suit", "language": "C",
     "version": "upstream example behaviour: failed conditions suppressed", "control": True,
     "env": {"OTABENCH_SUPPRESS": "1"}},
]


def run(work: Path, client: dict, manifest: str, payload: str | None) -> dict:
    """One processor run in the adapter container; work is mounted at /w."""
    out = work / "out"
    for p in sorted(out.rglob("*"), reverse=True) if out.exists() else []:
        p.unlink() if p.is_file() else p.rmdir()
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm", "-v", f"{work.resolve()}:/w"]
    for k, v in client["env"].items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [IMAGE, manifest, "-p", "/w/out"]
    if payload:
        cmd += ["-u", URI, "-f", payload]
    t = time.monotonic()
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=120,
                       env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    stored = {str(f.relative_to(out)): f.read_bytes() for f in out.rglob("*") if f.is_file()}
    return {"rc": p.returncode, "out": p.stdout + p.stderr, "stored": stored,
            "duration": time.monotonic() - t,
            "crashed": p.returncode >= 128 or p.returncode < 0}


def stored_ta(r: dict) -> bytes | None:
    return next((v for k, v in r["stored"].items() if Path(k).name == "ta"), None)


def scenarios(work: Path, genuine: bytes) -> dict:
    """name -> (threats, title, fn(client) -> (verdict, detail))"""
    (work / "good.ta").write_bytes(genuine)
    evil = bytearray(genuine)
    evil[10] ^= 0x7F
    (work / "evil.ta").write_bytes(bytes(evil))
    (work / "extra.ta").write_bytes(genuine + b"APPENDED")

    def baseline(c):
        r = run(work, c, MANIFEST, "/w/good.ta")
        ok = r["rc"] == 0 and stored_ta(r) == genuine
        return ("PASS" if ok else "ERROR"), "" if ok else f"rc={r['rc']}: {r['out'][-160:]}"

    def substitution(c):
        r = run(work, c, MANIFEST, "/w/evil.ta")
        if r["crashed"]:
            return "FAIL", f"processor crashed (rc={r['rc']})"
        if r["rc"] == 0:
            return "FAIL", "payload with a wrong digest accepted"
        return "PASS", ("rejected; the fetched bytes stay in the destination component "
                        "(the manifest fetches straight into it)" if stored_ta(r) == bytes(evil)
                        else "rejected")

    def tampered(offset_from_end: int | None, offset: int | None, what: str):
        def fn(c):
            data = bytearray(subprocess.run(["docker", "run", "--rm", "--entrypoint", "cat", IMAGE,
                                             MANIFEST], capture_output=True, check=True).stdout)
            i = len(data) - offset_from_end if offset_from_end else offset
            data[i] ^= 0xFF
            (work / "m.suit").write_bytes(bytes(data))
            r = run(work, c, "/w/m.suit", "/w/good.ta")
            if r["crashed"]:
                return "FAIL", f"processor crashed on a {what} (rc={r['rc']})"
            if r["rc"] == 0:
                return "FAIL", f"{what} accepted"
            return "PASS", "rejected"
        return fn

    def extra(c):
        r = run(work, c, MANIFEST, "/w/extra.ta")
        ta = stored_ta(r)
        if r["crashed"]:
            return "FAIL", f"processor crashed (rc={r['rc']})"
        if r["rc"] == 0 and ta and b"APPENDED" in ta:
            return "FAIL", "bytes after the signed image accepted"
        if r["rc"] == 0:
            return "PASS", "accepted exactly the signed length"
        return "PASS", "rejected"

    def malformed(c):
        rnd = random.Random(1)
        data = subprocess.run(["docker", "run", "--rm", "--entrypoint", "cat", IMAGE, MANIFEST],
                              capture_output=True, check=True).stdout
        inputs = [("truncated", data[:50])] + [(f"random{i}", rnd.randbytes(300)) for i in range(20)]
        crashes, accepted = [], []
        for name, blob in inputs:
            (work / "m.suit").write_bytes(blob)
            r = run(work, c, "/w/m.suit", None)
            if r["crashed"]:
                crashes.append(name)
            elif r["rc"] == 0:
                accepted.append(name)
        if crashes or accepted:
            return "FAIL", f"{len(crashes)} crashes, {len(accepted)} accepted of {len(inputs)} malformed inputs"
        return "PASS", f"{len(inputs)} malformed inputs rejected without a crash"

    return {
        "suit-baseline": ([], "expU with the genuine payload", baseline),
        "suit-payload-substitution": (["OTA-AUTH-01"], "payload altered, digest mismatch", substitution),
        "suit-manifest-tamper": (["OTA-AUTH-02"], "one byte of the signed manifest flipped", tampered(5, None, "tampered manifest")),
        "suit-signature-tamper": (["OTA-AUTH-02"], "one byte of the COSE signature flipped", tampered(None, 60, "tampered signature")),
        "suit-extra-data": (["OTA-AUTH-04"], "bytes appended after the payload", extra),
        "suit-malformed": (["OTA-PARSE-01"], "truncated envelope and 20 random inputs", malformed),
    }


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    out = Path(a.out) if a.out else ROOT / "results" / f"suit-{datetime.now():%Y-%m-%d}"
    work = ROOT / "results" / ".suit-work"
    work.mkdir(parents=True, exist_ok=True)
    genuine = subprocess.run(["docker", "run", "--rm", "--entrypoint", "cat", IMAGE,
                              f"/libcsuit/testfiles/{TA}"], capture_output=True, check=True).stdout
    scen = scenarios(work, genuine)
    started = datetime.now(UTC).isoformat(timespec="seconds")
    results = []
    for sid, (threats, title, fn) in scen.items():
        for c in CLIENTS:
            t = time.monotonic()
            verdict, detail = fn(c)
            results.append({"scenario": sid, "threats": threats, "title": title, "client": c["name"],
                            "verdict": verdict, "detail": detail, "metrics": {},
                            "duration_s": round(time.monotonic() - t, 2)})
            print(f"  {verdict:<8} {c['name']:<17} {sid:<26} {detail}", flush=True)
    run_doc = {"bench_version": __version__, "started": started,
               "host": {"os": f"{platform.system()} {platform.release()} (adapter in Docker, Ubuntu 22.04)",
                        "python": platform.python_version()},
               "params": {"trials": 1, "image": IMAGE, "manifest": MANIFEST},
               "clients": [{k: v for k, v in c.items() if k != "env"} for c in CLIENTS],
               "results": results}
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(run_doc, indent=2, ensure_ascii=False),
                                      encoding="utf-8")
    for f in write_reports(run_doc, load_catalog(ROOT / "catalog" / "threats.yaml"), out):
        print(f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
