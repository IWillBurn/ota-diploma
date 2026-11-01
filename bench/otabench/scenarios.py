"""Attack and fault scenarios.

Each scenario is bound to one or more threat IDs from catalog/threats.yaml and
returns an Outcome with a verdict:

  PASS     the attack was blocked / the fault was survived
  FAIL     the attack succeeded / the client did not survive the fault
  PARTIAL  survived only some trials (fault-injection scenarios)
  ERROR    precondition failed (baseline broken) -- not a security verdict

Verdicts are decided by observable oracles only: what the client stored as
trusted metadata, what artifact bytes it left on disk, how it terminated, and
which side closed the connection first. Exit codes matter but never decide on
their own.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, TargetFile
from tuf.api.serialization.json import JSONSerializer

from .adapter import ClientRunner, ClientSpec
from .server import AdversarialServer, Rule, Scene, role, role_version, target

FW1 = b"firmware 1.0 (vulnerable)\n" * 512
FW2 = b"firmware 2.0 (patched)   \n" * 512
EVIL = b"#!/bin/sh\n# attacker payload\n" * 400


@dataclass
class Outcome:
    verdict: str
    detail: str = ""
    metrics: dict[str, float | int | str] = field(default_factory=dict)


@dataclass
class Ctx:
    server: AdversarialServer
    client: ClientSpec
    trials: int = 10
    seed: int = 1
    scenario_id: str = ""
    _n: int = 0
    _runners: list = field(default_factory=list)

    def cleanup(self) -> None:
        for r in self._runners:
            r.close()

    def fresh(self) -> tuple[Scene, ClientRunner]:
        """New repository + new client workspace, initialised and refreshed once."""
        self._n += 1
        scene = self.server.new_scene(f"{self.scenario_id}--{self.client.name}--{self._n}")
        scene.sim.add_artifact("targets", FW1, "fw.bin")
        scene.sim.publish(["targets", "snapshot", "timestamp"])  # v2
        md_url, t_url = self.server.urls(scene)
        r = ClientRunner(self.client, md_url, t_url)
        self._runners.append(r)
        res = r.init(scene.sim.fetch_metadata("root", 1))
        if not res.ok:
            raise Precondition(f"init failed: {res.stderr_tail}")
        return scene, r


class Precondition(Exception):
    pass


Scenario = Callable[[Ctx], Outcome]
REGISTRY: dict[str, tuple[list[str], str, Scenario]] = {}


def scenario(sid: str, threats: list[str], title: str) -> Callable[[Scenario], Scenario]:
    def deco(fn: Scenario) -> Scenario:
        REGISTRY[sid] = (threats, title, fn)
        return fn

    return deco


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise Precondition(msg)


def _effect_ok(res) -> Outcome:
    """Verdict policy: decided by the effect (nothing malicious stored or trusted), never
    by the exit code alone. A client that rejects the attack but still exits 0 gets PASS
    with a note: reporting is a usability defect, not an accepted attack."""
    return Outcome("PASS", "rejected" if not res.ok else "not accepted, but the client exited 0")


def _publish_fw2(scene: Scene) -> None:
    scene.sim.add_artifact("targets", FW2, "fw.bin")
    scene.sim.publish(["targets", "snapshot", "timestamp"])  # v3


def _signer(scene: Scene, rolename: str) -> object:
    return next(iter(scene.sim.signers[rolename].values()))


# =========================================================== baseline
@scenario("baseline", [], "Sanity: honest repository, plain download")
def baseline(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    res = r.download("fw.bin")
    ok = res.ok and r.downloaded() == [FW1]
    return Outcome("PASS" if ok else "ERROR", res.stderr_tail if not ok else "",
                   {"duration_s": round(res.duration, 3)})


# =========================================================== authenticity
@scenario("arb-target-substitution", ["OTA-AUTH-01"],
          "Mirror serves attacker bytes instead of the signed artifact")
def arb_target_substitution(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    scene.add_rule(Rule(target("fw.bin"), "substitute", data=EVIL[: len(FW1)].ljust(len(FW1), b"#")))
    res = r.download("fw.bin")
    accepted = any(b"attacker payload" in d for d in r.downloaded())
    if accepted:
        return Outcome("FAIL", "malicious artifact stored in target dir")
    return _effect_ok(res)


@scenario("arb-metadata-tamper", ["OTA-AUTH-02"],
          "Targets metadata modified in transit, original signature kept")
def arb_metadata_tamper(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    tampered = json.loads(scene.sim.fetch_metadata("targets"))
    tampered["signed"]["targets"]["evil.bin"] = {
        "length": len(EVIL), "hashes": {"sha256": hashlib.sha256(EVIL).hexdigest()}}
    scene.add_rule(Rule(role("targets"), "substitute", data=json.dumps(tampered).encode()))
    scene.add_rule(Rule(target("evil.bin"), "substitute", data=EVIL))
    res = r.download("evil.bin")
    if EVIL in r.downloaded():
        return Outcome("FAIL", "tampered metadata accepted, payload stored")
    return _effect_ok(res)


@scenario("arb-keyid-spoofing", ["OTA-AUTH-03"],
          "Attacker signs with own key but claims the legitimate keyid")
def arb_keyid_spoofing(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    t = copy.deepcopy(scene.sim.targets)
    t.targets["evil.bin"] = TargetFile.from_data("evil.bin", EVIL, ["sha256"])
    md = Metadata(t)
    md.sign(CryptoSigner.generate_ecdsa())
    legit_keyid = scene.sim.root.roles["targets"].keyids[0]
    raw = json.loads(md.to_bytes(JSONSerializer()))
    for s in raw["signatures"]:
        s["keyid"] = legit_keyid
    scene.add_rule(Rule(role("targets"), "substitute", data=json.dumps(raw).encode()))
    scene.add_rule(Rule(target("evil.bin"), "substitute", data=EVIL))
    res = r.download("evil.bin")
    if EVIL in r.downloaded():
        return Outcome("FAIL", "forged signature accepted")
    return _effect_ok(res)


# =========================================================== freshness
@scenario("freeze-expired-timestamp", ["OTA-FRESH-01"],
          "Mirror keeps replaying metadata after it expired (indefinite freeze)")
def freeze_expired(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    exp = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=4)
    scene.sim.timestamp.expires = exp
    scene.sim.publish(["timestamp"])
    _require(r.refresh().ok, "refresh before expiry failed")
    # the real repository moves on, the attacker keeps serving the frozen state
    frozen = scene.sim.fetch_metadata("timestamp")
    scene.add_rule(Rule(role("timestamp"), "substitute", data=frozen))
    _publish_fw2(scene)
    time.sleep(max(0.0, (exp - datetime.now(UTC)).total_seconds()) + 1.5)
    res = r.refresh()
    if res.ok:
        return Outcome("FAIL", "expired timestamp accepted")
    return Outcome("PASS", "expired metadata rejected")


@scenario("rollback-timestamp", ["OTA-FRESH-02"],
          "Replay of an older, validly signed, unexpired timestamp")
def rollback_timestamp(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _publish_fw2(scene)
    _require(r.refresh().ok, "refresh failed")
    _require(r.trusted_version("timestamp") == 3, "trusted timestamp != 3")
    old = scene.sim.signed_mds["timestamp"][1]  # v2
    scene.add_rule(Rule(role("timestamp"), "substitute", data=old))
    res = r.refresh()
    v = r.trusted_version("timestamp")
    if v is not None and v < 3:
        return Outcome("FAIL", f"trusted timestamp rolled back to v{v}")
    return Outcome("PASS", "rejected" if not res.ok else "kept v3 silently (exit 0)")


@scenario("mix-and-match", ["OTA-FRESH-03"],
          "Snapshot lists targets v3, mirror serves (older) targets v2 under that name")
def mix_and_match(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _publish_fw2(scene)
    scene.add_rule(Rule(role_version("targets", 3), "substitute",
                        data=scene.sim.signed_mds["targets"][1]))
    res = r.download("fw.bin")
    got_old = FW1 in r.downloaded()
    if got_old or r.trusted_version("targets") == 2:
        return Outcome("FAIL", "inconsistent metadata combination accepted; old firmware installed"
                       if got_old else "inconsistent targets trusted")
    return _effect_ok(res)


# =========================================================== key compromise
@scenario("online-keys-downgrade", ["OTA-KEY-01", "OTA-FRESH-02"],
          "Timestamp+snapshot keys compromised: snapshot points back to old targets (downgrade)")
def online_keys_downgrade(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _publish_fw2(scene)
    _require(r.download("fw.bin").ok and r.downloaded() == [FW2], "download of fw2 failed")
    scene.sim.snapshot.meta["targets.json"] = MetaFile(version=2)  # signed with real online key
    scene.sim.publish(["snapshot", "timestamp"])
    res = r.download("fw.bin")
    if FW1 in r.downloaded() or (r.trusted_version("targets") or 3) < 3:
        return Outcome("FAIL", "downgrade to vulnerable firmware accepted")
    return Outcome("PASS", "rejected" if not res.ok else "kept fw2, exit 0")


@scenario("online-keys-arbitrary", ["OTA-KEY-02", "OTA-AUTH-01"],
          "Timestamp+snapshot keys compromised: attacker signs new targets with the snapshot key")
def online_keys_arbitrary(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    t = copy.deepcopy(scene.sim.targets)
    t.version = len(scene.sim.signed_mds["targets"]) + 1
    t.targets["evil.bin"] = TargetFile.from_data("evil.bin", EVIL, ["sha256"])
    md = Metadata(t)
    md.sign(_signer(scene, "snapshot"))
    scene.sim.signed_mds["targets"].append(md.to_bytes(JSONSerializer()))
    scene.sim.snapshot.meta["targets.json"] = MetaFile(version=t.version)
    scene.sim.publish(["snapshot", "timestamp"])
    scene.add_rule(Rule(target("evil.bin"), "substitute", data=EVIL))
    res = r.download("evil.bin")
    if EVIL in r.downloaded():
        return Outcome("FAIL", "targets signed by wrong role accepted")
    return _effect_ok(res)


# =========================================================== availability
def _stream_verdict(ctx: Ctx, scene: Scene, matcher, res, declared: int | None) -> Outcome:
    recs = scene.records(matcher)
    _require(bool(recs), "attacked file was never requested")
    rec = recs[0]
    m = {"time_to_abort_s": round(res.duration, 2), "bytes_pushed": rec.bytes_sent,
         "requests": len(recs)}
    if declared is not None:
        m["declared_len"] = declared
    if rec.capped or res.timed_out:
        why = (f"{rec.bytes_sent / 1048576:.0f} MiB accepted" if rec.action == "endless"
               else f"still waiting after {res.duration:.0f}s")
        return Outcome("FAIL", f"client never gave up, harness cap hit ({why})", m)
    return Outcome("PASS", "client aborted the transfer itself", m)


@scenario("endless-metadata", ["OTA-DOS-01"],
          "timestamp.json is an endless stream (no Content-Length)")
def endless_metadata(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    scene.add_rule(Rule(role("timestamp"), "endless"))
    res = r.refresh(timeout=ctx.server.caps.endless_seconds + 20)
    return _stream_verdict(ctx, scene, role("timestamp"), res, None)


@scenario("endless-artifact", ["OTA-DOS-02"],
          "Artifact URL answers with an endless stream (no Content-Length), "
          "longer than the signed length")
def endless_artifact(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "refresh failed")
    scene.add_rule(Rule(target("fw.bin"), "endless"))
    res = r.download("fw.bin", timeout=ctx.server.caps.endless_seconds + 20)
    out = _stream_verdict(ctx, scene, target("fw.bin"), res, len(FW1))
    if any(len(d) > len(FW1) for d in r.downloaded()):
        out.verdict, out.detail = "FAIL", "over-long artifact stored"
    return out


@scenario("slow-metadata", ["OTA-DOS-03"],
          "snapshot.json is dripped at 2 bytes/s (below any read-gap timeout)")
def slow_metadata(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    scene.add_rule(Rule(role("snapshot"), "slow", rate_bps=2.0))
    res = r.refresh(timeout=ctx.server.caps.slow_seconds + 15)
    return _stream_verdict(ctx, scene, role("snapshot"), res, None)


@scenario("slow-artifact", ["OTA-DOS-04"],
          "Artifact is dripped at 64 bytes/s")
def slow_artifact(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "refresh failed")
    scene.add_rule(Rule(target("fw.bin"), "slow", rate_bps=64.0))
    res = r.download("fw.bin", timeout=ctx.server.caps.slow_seconds + 15)
    return _stream_verdict(ctx, scene, target("fw.bin"), res, len(FW1))


# =========================================================== fault tolerance
@scenario("dropped-connection", ["OTA-NET-01"],
          "Connection closed half-way through the artifact; next attempt must recover")
def dropped_connection(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    scene.add_rule(Rule(target("fw.bin"), "truncate", once=True))
    res1 = r.download("fw.bin")
    torn = [d for d in r.downloaded() if d != FW1]
    res2 = r.download("fw.bin")
    final_ok = res2.ok and r.downloaded() == [FW1]
    m = {"torn_file_after_drop": int(bool(torn)), "recovery_s": round(res2.duration, 3)}
    if res1.ok:
        return Outcome("FAIL", "truncated artifact reported as success", m)
    if not final_ok:
        return Outcome("FAIL", "did not recover: " + ("stale torn file trusted" if res2.ok else
                                                       res2.stderr_tail), m)
    return Outcome("PASS", "recovered" + (" (torn file was visible)" if torn else ""), m)


class _Killer:
    """Arms a kill of the *current* client run; cancelled once that run returns,
    so a late timer can never hit the recovery run that follows."""

    def __init__(self, r: ClientRunner, delay: float) -> None:
        self.r, self.delay = r, delay
        self.timers: list[threading.Timer] = []

    def __call__(self, _: str) -> None:
        t = threading.Timer(self.delay, self.r.kill_switch.set)
        self.timers.append(t)
        t.start()

    def disarm(self) -> None:
        for t in self.timers:
            t.cancel()
        self.r.kill_switch.clear()


def _artifact_state(r: ClientRunner, good: bytes) -> str:
    files = [p for p in sorted(r.target_dir.rglob("*")) if p.is_file()]
    if not files:
        return "no file"
    out = []
    for p in files:
        d = p.read_bytes()
        out.append(f"{p.name}:{'ok' if d == good else f'BAD {len(d)}B'}")
    return ",".join(out)


@scenario("powercut-refresh", ["OTA-PWR-01"],
          "Process killed at a random point of a metadata update incl. root rotation")
def powercut_refresh(ctx: Ctx) -> Outcome:
    rnd = random.Random(f"{ctx.seed}-{ctx.client.name}-refresh")
    survived = crashed = 0
    rec_times: list[float] = []
    points: dict[str, int] = {}
    reasons: dict[str, int] = {}
    for _ in range(ctx.trials):
        scene, r = ctx.fresh()
        _require(r.refresh().ok, "initial refresh failed")
        scene.sim.rotate_keys("timestamp")  # root v2 rotates the timestamp key
        scene.sim.publish(["root"])
        _publish_fw2(scene)
        point = rnd.choice(["root", "timestamp", "snapshot", "targets"])
        points[point] = points.get(point, 0) + 1
        killer = _Killer(r, rnd.uniform(0, 0.03))
        scene.add_rule(Rule(role(point), "normal", on_sent=killer))
        res = r.refresh()
        killer.disarm()
        crashed += int(res.killed)
        scene.clear_rules()
        res2 = r.refresh()
        parse_ok = all(r.metadata_parseable().values())
        vers = (r.trusted_version("root"), r.trusted_version("targets"))
        if res2.ok and parse_ok and vers == (2, 3):
            survived += 1
            rec_times.append(res2.duration)
        else:
            why = (f"recovery refresh failed: {res2.stderr_tail[:120]}" if not res2.ok else
                   "unparseable trust store" if not parse_ok else f"stale versions {vers}")
            reasons[why] = reasons.get(why, 0) + 1
    return _trials_outcome(ctx, survived, crashed, rec_times, reasons,
                           {"kill_points": ",".join(f"{k}:{v}" for k, v in sorted(points.items()))})


@scenario("powercut-download", ["OTA-PWR-02"],
          "Process killed at a random moment while a 2 MiB artifact is being fetched/stored")
def powercut_download(ctx: Ctx) -> Outcome:
    rnd = random.Random(f"{ctx.seed}-{ctx.client.name}-download")
    # control: the same 2 MiB download without any fault must work, otherwise a
    # platform problem would be misreported as a crash-consistency failure
    scene, r = ctx.fresh()
    big = random.Random(f"{ctx.seed}-control").randbytes(2 * 1024 * 1024)
    scene.sim.add_artifact("targets", big, "fw.bin")
    scene.sim.publish(["targets", "snapshot", "timestamp"])
    res = r.download("fw.bin")
    _require(res.ok and r.downloaded() == [big],
             f"honest 2 MiB download fails without any fault: {res.stderr_tail[:140]}")
    survived = crashed = torn_seen = 0
    rec_times: list[float] = []
    reasons: dict[str, int] = {}
    for i in range(ctx.trials):
        scene, r = ctx.fresh()
        big = random.Random(f"{ctx.seed}-{i}").randbytes(2 * 1024 * 1024)
        scene.sim.add_artifact("targets", big, "fw.bin")
        scene.sim.publish(["targets", "snapshot", "timestamp"])
        _require(r.refresh().ok, "refresh failed")
        killer = _Killer(r, rnd.uniform(0.05, 1.5))
        scene.add_rule(Rule(target("fw.bin"), "throttle", rate_bps=1.5 * 1024 * 1024,
                            on_start=killer))
        res = r.download("fw.bin")
        killer.disarm()
        crashed += int(res.killed)
        after_crash = _artifact_state(r, big)
        torn_seen += int("BAD" in after_crash)
        scene.clear_rules()
        res2 = r.download("fw.bin")
        if res2.ok and r.downloaded() == [big]:
            survived += 1
            rec_times.append(res2.duration)
        else:
            why = (f"after crash [{after_crash}] -> after retry exit={res2.exit_code} "
                   f"[{_artifact_state(r, big)}]")
            reasons[why] = reasons.get(why, 0) + 1
    return _trials_outcome(ctx, survived, crashed, rec_times, reasons,
                           {"torn_file_observed": torn_seen})


def _trials_outcome(ctx: Ctx, survived: int, crashed: int, rec: list[float],
                    reasons: dict[str, int], extra: dict) -> Outcome:
    m = {"trials": ctx.trials, "crashed": crashed, "survived": survived,
         "survival_rate": round(survived / ctx.trials, 3),
         "mean_recovery_s": round(sum(rec) / len(rec), 3) if rec else "-", **extra}
    if survived == ctx.trials:
        v = "PASS"
    elif survived == 0:
        v = "FAIL"
    else:
        v = "PARTIAL"
    why = "; ".join(f"{n}x {k}" for k, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:3])
    return Outcome(v, f"{survived}/{ctx.trials} survived ({crashed} killed mid-run)"
                   + (f" | {why}" if why else ""), m)
