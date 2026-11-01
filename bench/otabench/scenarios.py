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

from securesystemslib.signer import CryptoSigner, Signature, SSlibKey
from tuf.api.metadata import Metadata, MetaFile, TargetFile
from tuf.api.serialization.json import JSONSerializer

from .adapter import ClientRunner, ClientSpec
from .server import AdversarialServer, Rule, Scene, nth_request, role, role_version, target

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
        """New repository (fw.bin published as targets v2) + new client workspace, `init` done."""
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
        t = threading.Timer(self.delay, self.r.kill_run, args=(self.r.run_id,))
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


PHASES = ("request", "sent", "sent+10ms")


def _rotation_scene(ctx: Ctx) -> tuple[Scene, ClientRunner]:
    """Client at root v1 / targets v2; repository at root v2 (rotated timestamp key)
    and targets v3: the next refresh walks the whole client workflow."""
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "initial refresh failed")
    scene.sim.rotate_keys("timestamp")
    scene.sim.publish(["root"])
    _publish_fw2(scene)
    return scene, r


def _kill_at(r: ClientRunner, phase: str) -> dict:
    """Rule callbacks that kill the client at a given moment of its i-th request."""
    if phase == "request":  # the client waits for this response: kill before answering
        def on_start(_: str) -> None:
            r.kill_run(r.run_id)
            r.proc_done.wait(5)
        return {"on_start": on_start}
    delay = 0.010 if phase == "sent+10ms" else 0.0

    def on_sent(_: str) -> None:  # the client is parsing / verifying / storing it
        run = r.run_id  # the run that received the response; the kill is for it only
        if delay:
            time.sleep(delay)
        r.kill_run(run)
    return {"on_sent": on_sent}


@scenario("powercut-refresh", ["OTA-PWR-01"],
          "Process killed at every network operation of a metadata update incl. root rotation")
def powercut_refresh(ctx: Ctx) -> Outcome:
    """Event-based crash points (like the MCUboot simulator's 'fail at operation i'): a
    rehearsal refresh counts the client's N requests; then for every i in 1..N the
    client is killed (a) when request i arrives, before it is answered, (b) right after
    response i is sent, (c) 10 ms later. After each kill, a plain refresh must recover
    to root v2 / targets v3 with a parseable trust store."""
    scene, r = _rotation_scene(ctx)
    before = len(scene.records())
    _require(r.refresh().ok, "rehearsal refresh failed")
    seq = [rec.path for rec in scene.records()[before:]]
    _require(bool(seq), "rehearsal refresh made no requests")
    survived = crashed = not_reached = 0
    rec_times: list[float] = []
    reasons: dict[str, int] = {}
    failed_at: list[str] = []
    for i, path in enumerate(seq, 1):
        for phase in PHASES:
            scene, r = _rotation_scene(ctx)
            scene.add_rule(Rule(nth_request(i), "normal", **_kill_at(r, phase)))
            res = r.refresh()
            r.kill_switch.clear()
            crashed += int(res.killed)
            not_reached += int(not res.killed and phase == "request")
            scene.clear_rules()
            res2 = r.refresh()
            parse_ok = all(r.metadata_parseable().values())
            vers = (r.trusted_version("root"), r.trusted_version("targets"))
            if res2.ok and parse_ok and vers == (2, 3):
                survived += 1
                rec_times.append(res2.duration)
            else:
                why = (f"recovery refresh failed: {res2.stderr_tail[:100]}" if not res2.ok else
                       "unparseable trust store" if not parse_ok else f"stale versions {vers}")
                reasons[why] = reasons.get(why, 0) + 1
                failed_at.append(f"{i}:{path.rsplit('/', 1)[-1]}@{phase}")
    n = len(seq) * len(PHASES)
    return _trials_outcome(ctx, survived, crashed, rec_times, reasons,
                           {"census": 1, "requests": len(seq),
                            "request_seq": " ".join(q.rsplit("/", 1)[-1] for q in seq),
                            "request_points_not_reached": not_reached,
                            "failed_at": " ".join(failed_at) or "-"}, n=n)


@scenario("powercut-download", ["OTA-PWR-02"],
          "Process killed at a random moment while a 2 MiB artifact is being fetched/stored")
def powercut_download(ctx: Ctx) -> Outcome:
    rnd = random.Random(f"{ctx.seed}-{ctx.client.name}-download")
    # control: the same 2 MiB download without any fault must work, otherwise a
    # platform problem would be misreported as a crash-consistency failure. Three times:
    # a flaky platform crash (tuf-js / libuv on Windows) passed a single control once.
    for k in range(CONTROL_RUNS):
        scene, r = ctx.fresh()
        big = random.Random(f"{ctx.seed}-control-{k}").randbytes(2 * 1024 * 1024)
        scene.sim.add_artifact("targets", big, "fw.bin")
        scene.sim.publish(["targets", "snapshot", "timestamp"])
        res = r.download("fw.bin")
        _require(res.ok and r.downloaded() == [big],
                 f"honest 2 MiB download fails without any fault (control {k + 1}/{CONTROL_RUNS}, "
                 f"exit {res.exit_code}): {res.stderr_tail[:120]}")
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
        _require(_protocol_exit(res2),
                 f"retry after the kill crashed outside the CLI protocol (exit {res2.exit_code}, "
                 f"trial {i + 1}); same class as a platform crash, not a crash-consistency "
                 f"verdict: {res2.stderr_tail[:100]}")
        if res2.ok and r.downloaded() == [big]:
            survived += 1
            rec_times.append(res2.duration)
        else:
            why = (f"after crash [{after_crash}] -> after retry exit={res2.exit_code} "
                   f"[{_artifact_state(r, big)}]")
            reasons[why] = reasons.get(why, 0) + 1
    return _trials_outcome(ctx, survived, crashed, rec_times, reasons,
                           {"torn_file_observed": torn_seen})


# =========================================================== added for catalog coverage (D1)
TAIL = b"\n#!/bin/sh\n# appended after the signed image\n"


def _versions(r: ClientRunner) -> tuple:
    return tuple(r.trusted_version(x) for x in ("root", "timestamp", "snapshot", "targets"))


@scenario("online-keys-freeze", ["OTA-KEY-04", "OTA-FRESH-01"],
          "Timestamp+snapshot keys compromised: fresh online signatures keep pointing to expired targets")
def online_keys_freeze(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    exp = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=4)
    scene.sim.targets.expires = exp
    scene.sim.publish(["targets", "snapshot", "timestamp"])  # targets v3, expires soon
    _require(r.refresh().ok, "refresh before expiry failed")
    time.sleep(max(0.0, (exp - datetime.now(UTC)).total_seconds()) + 1.5)
    # the holder of the online keys re-signs fresh timestamp + snapshot that still point to
    # the now expired targets v3: every signature is valid and recent, the content is frozen
    scene.sim.publish(["snapshot", "timestamp"])
    res = r.refresh()
    if res.ok:
        return Outcome("FAIL", "expired targets accepted under fresh online signatures")
    return Outcome("PASS", "freeze detected: expired targets rejected")


def _failing_mirror(ctx: Ctx, rule: Rule, what: str) -> Outcome:
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "initial refresh failed")
    before = _versions(r)
    _publish_fw2(scene)
    scene.add_rule(rule)
    res = r.refresh(timeout=60)
    after = _versions(r)
    m = {"duration_s": round(res.duration, 2)}
    if res.timed_out:
        return Outcome("FAIL", f"client hung on a mirror that {what}", m)
    if res.ok:
        return Outcome("FAIL", f"refresh reported success although the mirror {what}", m)
    if not all(r.metadata_parseable().values()) or after != before:
        return Outcome("FAIL", f"trust store changed: {before} -> {after}", m)
    return Outcome("PASS", f"failure reported after {res.duration:.2f}s, trust store intact", m)


@scenario("mirror-errors", ["OTA-DOS-05"],
          "The only mirror answers every request with HTTP 503 (no fallback in the CLI protocol)")
def mirror_errors(ctx: Ctx) -> Outcome:
    return _failing_mirror(ctx, Rule(lambda p: True, "error", status=503), "answered only 503")


@scenario("drop-requests", ["OTA-DOS-06"],
          "Every request is dropped: the connection closes without a response")
def drop_requests(ctx: Ctx) -> Outcome:
    return _failing_mirror(ctx, Rule(lambda p: True, "drop"), "dropped every request")


@scenario("extra-data-artifact", ["OTA-AUTH-04"],
          "Artifact served with a few bytes appended after the signed image (finite, with Content-Length)")
def extra_data_artifact(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    scene.add_rule(Rule(target("fw.bin"), "substitute", data=FW1 + TAIL))
    res = r.download("fw.bin")
    got = r.downloaded()
    if any(TAIL in d for d in got):
        return Outcome("FAIL", "bytes after the signed image were stored")
    if got and got != [FW1]:
        return Outcome("FAIL", "a file different from the signed image was stored")
    if res.ok and got == [FW1]:
        return Outcome("PASS", "stored exactly the signed length")
    return Outcome("PASS", "rejected" if not res.ok else "nothing stored, but exit 0")


@scenario("unsupported-spec-version", ["OTA-PARSE-02"],
          "Validly signed timestamp declares spec_version 2.0.0 (unsupported major version)")
def unsupported_spec_version(ctx: Ctx) -> Outcome:
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "initial refresh failed")
    before = r.trusted_version("timestamp")
    scene.sim.timestamp.spec_version = "2.0.0"
    scene.sim.publish(["timestamp"])
    res = r.refresh()
    if (r.trusted_version("timestamp") or 0) > (before or 0):
        return Outcome("FAIL", "metadata of an unsupported major spec version became trusted")
    return _effect_ok(res)


@scenario("timestamp-same-version", ["OTA-FRESH-02"],
          "Timestamp re-signed with the SAME version but new content (snapshot v100)")
def timestamp_same_version(ctx: Ctx) -> Outcome:
    """Version rules differ between ecosystems: TUF 1.0.37 §5.4.3.1 requires a strictly
    greater timestamp version and, on an equal one, stops the update without error and keeps
    the trusted timestamp; Uptane 2.1.0 full verification (§5.4.4.4 s3) accepts an equal
    version. tuf-conformance has the same check (test_timestamp_content_changes)."""
    scene, r = ctx.fresh()
    _require(r.refresh().ok, "initial refresh failed")
    sim = scene.sim
    before = r.trusted_version("timestamp")
    _require(before == len(sim.signed_mds["timestamp"]), "trusted timestamp is not the latest")
    sim.timestamp.snapshot_meta.version = 100
    sim.timestamp.version -= 1          # publish() bumps it back: same version number,
    sim.signed_mds["timestamp"].pop()   # new content, served instead of the old bytes
    sim.publish(["timestamp"])
    res = r.refresh()
    try:
        md = json.loads((r.metadata_dir / "timestamp.json").read_bytes())
        snap_v = md["signed"]["meta"]["snapshot.json"]["version"]
    except (OSError, ValueError, KeyError) as e:
        return Outcome("FAIL", f"trusted timestamp unreadable after refresh: {e}")
    if snap_v == 100:
        return Outcome("FAIL", "a timestamp with an equal version but new content replaced the trusted one")
    return Outcome("PASS", "kept the trusted timestamp (exit 0, as TUF requires)" if res.ok else
                   "kept the trusted timestamp, but reported an error (TUF: stop without error)")


@scenario("threshold-key-twice", ["OTA-AUTH-03", "OTA-KEY-02"],
          "One snapshot key listed in root under two keyids; threshold 2 met by that key alone")
def threshold_key_twice(ctx: Ctx) -> Outcome:
    """TUF 1.0.37: 'each KEY MUST only contribute one SIGNATURE' to a threshold and clients
    'MUST calculate each KEYID'. tuf-conformance covers the same keyid repeated
    (test_duplicate_keys); here the same key material appears under a second, bogus keyid."""
    scene, r = ctx.fresh()
    sim = scene.sim
    signer = CryptoSigner.generate_ecdsa()  # the one key the attacker holds
    key = signer.public_key
    twin = SSlibKey("f" * 64, key.keytype, key.scheme, dict(key.keyval))
    sim.root.add_key(key, "snapshot")
    sim.root.add_key(twin, "snapshot")
    sim.root.roles["snapshot"].threshold = 2
    sim.publish(["root"])  # root v2, correctly signed by the root key
    snap = copy.deepcopy(sim.snapshot)
    snap.version = len(sim.signed_mds["snapshot"]) + 1
    md = Metadata(snap)
    md.sign(signer)
    md.signatures[twin.keyid] = Signature(twin.keyid, md.signatures[key.keyid].signature)
    sim.signed_mds["snapshot"].append(md.to_bytes(JSONSerializer()))
    sim.timestamp.snapshot_meta = MetaFile(version=snap.version)
    sim.publish(["timestamp"])
    res = r.refresh()
    if (r.trusted_version("snapshot") or 0) >= snap.version:
        return Outcome("FAIL", "one key counted twice towards threshold 2 (two keyids)")
    return _effect_ok(res)


CONTROL_RUNS = 3


def _protocol_exit(res) -> bool:
    """The CLI protocol allows exit codes 0 and 1 only. Anything else from a run that the
    bench did not kill (an abort, an access violation, 0xC0000409 = fast-fail) is a crash
    of the client process; the bench reports it as ERROR instead of guessing a verdict."""
    return res.killed or res.timed_out or res.exit_code in (0, 1)


def _trials_outcome(ctx: Ctx, survived: int, crashed: int, rec: list[float],
                    reasons: dict[str, int], extra: dict, n: int | None = None) -> Outcome:
    n = ctx.trials if n is None else n
    m = {"trials": n, "crashed": crashed, "survived": survived,
         "survival_rate": round(survived / n, 3),
         "mean_recovery_s": round(sum(rec) / len(rec), 3) if rec else "-", **extra}
    # One verdict rule for both levels (ch. 2, table 2.6): a census of crash points is
    # exhaustive over a defined set, so a single failed point is a counterexample -> FAIL.
    # Random trials are a sample: all survived -> PASS, none -> FAIL, otherwise PARTIAL.
    if survived == n:
        v = "PASS"
    elif survived == 0 or extra.get("census"):
        v = "FAIL"
    else:
        v = "PARTIAL"
    why = "; ".join(f"{c}x {k}" for k, c in sorted(reasons.items(), key=lambda kv: -kv[1])[:3])
    return Outcome(v, f"{survived}/{n} survived ({crashed} killed mid-run)"
                   + (f" | {why}" if why else ""), m)
