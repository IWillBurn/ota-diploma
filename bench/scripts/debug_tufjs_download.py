"""Debug helper: does tuf-js fail on a 2 MiB download even without a kill?"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from otabench.adapter import ClientRunner, load_clients  # noqa: E402
from otabench.server import AdversarialServer, Rule, target  # noqa: E402

name = sys.argv[1] if len(sys.argv) > 1 else "tuf-js"
kill = "--kill" in sys.argv
spec = next(c for c in load_clients(Path(__file__).resolve().parent.parent / "clients.yaml")
            if c.name == name)
with AdversarialServer() as srv:
    sc = srv.new_scene("dbg")
    big = random.Random(1).randbytes(2 * 1024 * 1024)
    sc.sim.add_artifact("targets", big, "fw.bin")
    sc.sim.publish(["targets", "snapshot", "timestamp"])
    r = ClientRunner(spec, *srv.urls(sc))
    print("init", r.init(sc.sim.fetch_metadata("root", 1)))
    print("refresh", r.refresh())
    if kill:
        import threading

        sc.add_rule(Rule(target("fw.bin"), "throttle", rate_bps=1.5 * 1024 * 1024,
                         on_start=lambda _: threading.Timer(0.5, r.kill_switch.set).start()))
        print("download (killed)", r.download("fw.bin"))
        sc.clear_rules()
        r.kill_switch.clear()
    res = r.download("fw.bin")
    print("download", res)
    print("files", [(p.name, p.stat().st_size) for p in r.target_dir.rglob("*")])
    r.close()
