"""Run the threat x implementation matrix."""

from __future__ import annotations

import json
import platform
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from . import scenarios as sc
from .adapter import ClientSpec
from .server import AdversarialServer, Caps


def run_one(server: AdversarialServer, client: ClientSpec, sid: str, trials: int, seed: int) -> dict:
    threats, title, fn = sc.REGISTRY[sid]
    ctx = sc.Ctx(server, client, trials=trials, seed=seed, scenario_id=sid)
    t0 = time.monotonic()
    try:
        out = fn(ctx)
    except sc.Precondition as e:
        out = sc.Outcome("ERROR", f"precondition: {e}")
    except Exception as e:  # noqa: BLE001
        out = sc.Outcome("ERROR", f"{type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        ctx.cleanup()
    return {"client": client.name, "scenario": sid, "threats": threats, "title": title,
            "wall_s": round(time.monotonic() - t0, 2), **asdict(out)}


def run_matrix(clients: list[ClientSpec], scenario_ids: list[str], *, trials: int, seed: int,
               jobs: int, caps: Caps, progress=print) -> dict:
    started = datetime.now(UTC).isoformat(timespec="seconds")
    results = []
    with AdversarialServer(caps) as server:
        pairs = [(c, s) for s in scenario_ids for c in clients]
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futs = {pool.submit(run_one, server, c, s, trials, seed): (c, s) for c, s in pairs}
            for f in futs:
                res = f.result()
                results.append(res)
                progress(f"  {res['verdict']:<8} {res['client']:<12} {res['scenario']:<26} "
                         f"{res['wall_s']:>6.1f}s  {res['detail']}")
    return {
        "otabench_version": __version__,
        "started": started,
        "host": {"os": platform.platform(), "python": platform.python_version()},
        "params": {"trials": trials, "seed": seed, "caps": asdict(caps)},
        "clients": [asdict(c) | {"command": c.command[-1].split("\\")[-1]} for c in clients],
        "results": results,
    }


def save(run: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "results.json"
    p.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
