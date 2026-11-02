"""Structured mutations of the A/B updaters' update containers (backlog D5, OTA-PARSE-01).

The parts an updater reads BEFORE it has verified anything are its pre-authentication
attack surface: the cpio headers and the CMS signature of a SWUpdate .swu (parsed by wolfSSL
in the Debian build), the size trailer and the CMS signature of a RAUC bundle. Each mutated
container is handed to the updater in a Docker image with the same version as in the A/B
image (no VM):

  swu-mutations           SWUpdate 2024.12.1 (bookworm-backports), real install into a
                          slot file (`swupdate -i`, the adapter's flags); oracle: exit code and
                          the slot content after the run
  rauc-bundle-mutations   RAUC 1.8 (Debian 12) and 1.15.2, `rauc info --keyring` (the same
                          check_bundle as `rauc install`), plain and verity bundles

Verdict per input: crash/timeout (exit >= 124) -> FAIL; accepted with a payload other than the
genuine one -> FAIL (bypass); accepted with the genuine payload (a mutation of a field nobody
signs, e.g. a cpio mtime) -> recorded, not a failure; rejected -> PASS.

  python container_mutations.py [--only swu|rauc] [--out results/d5-container-mutations-<date>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}
SWU_IMAGE, RAUC_IMAGE = "otabench-swupdate-verify", "otabench-rauc-verify"
CRASH_RC = 124

SWU_BUILD = r"""
set -eu
cd /w
for k in dev attacker; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=$k -keyout $k.key -out $k.crt 2>/dev/null
done
head -c 1048576 /dev/urandom > rootfs.ext4 && gzip -1 -c rootfs.ext4 > rootfs.ext4.gz
sha=$(sha256sum rootfs.ext4.gz | cut -d' ' -f1)
cat > sw-description <<SWD
software =
{
	version = "2.0.0";
	description = "otabench 2";
	hardware-compatibility: [ "1.0" ];
	stable = {
		copyB: {
			images: (
				{
					filename = "rootfs.ext4.gz";
					device = "/tmp/slotB.img";
					type = "raw";
					compressed = "zlib";
					installed-directly = true;
					sha256 = "$sha";
				}
			);
		};
	};
}
SWD
mk() {
  openssl cms -sign -in sw-description -out sw-description.sig -signer $1.crt -inkey $1.key \
    -outform DER -nosmimecap -binary
  printf 'sw-description\nsw-description.sig\nrootfs.ext4.gz\n' | cpio -o -H crc --quiet > $2
}
mk attacker attacker.swu
mk dev good.swu
"""

# one container runs every input; slot file reset before each run, its digest reported after
SWU_RUN = r"""
cd /w
for f in mut/*; do
  : > /tmp/slotB.img
  timeout 20 swupdate -H otabench:1.0 -k /w/dev.crt -e stable,copyB -i "$f" >/dev/null 2>&1; rc=$?
  echo "$(basename "$f") $rc $(sha256sum /tmp/slotB.img | cut -c1-64)"
done
"""

RAUC_BUILD = r"""
set -eu
cd /w
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=otabench-dev -keyout dev.key -out dev.crt 2>/dev/null
for fmt in plain verity; do
  mkdir -p b-$fmt && head -c 65536 /dev/urandom > b-$fmt/rootfs.ext4
  printf '[update]\ncompatible=otabench-pilot\nversion=2\n\n[bundle]\nformat=%s\n\n[image.rootfs]\nfilename=rootfs.ext4\n' $fmt > b-$fmt/manifest.raucm
done
rauc bundle --cert=dev.crt --key=dev.key b-plain good-plain.raucb >/dev/null
/opt/rauc-1.15.2/bin/rauc bundle --cert=dev.crt --key=dev.key b-verity good-verity.raucb >/dev/null
rm -rf b-plain b-verity
"""

RAUC_RUN = r"""
# RAUC refuses plain bundles on an unknown filesystem (the Docker bind mount): run from the
# container's own filesystem
mkdir -p /tmp/mut && cp /w/mut/* /tmp/mut/ && cd /tmp
for f in mut/*; do
  for r in rauc /opt/rauc-1.15.2/bin/rauc; do
    out=$(timeout 10 $r info --keyring=/w/dev.crt --output-format=shell "$f" 2>/dev/null); rc=$?
    v=$(printf '%s\n' "$out" | sed -n "s/^RAUC_MF_VERSION='\(.*\)'/\1/p")
    h=$(printf '%s\n' "$out" | sed -n "s/^RAUC_IMAGE_DIGEST_[0-9]*='\(.*\)'/\1/p" | head -1)
    echo "$(basename "$f") $($r --version | cut -d' ' -f2) $rc ${v:--} ${h:--}"
  done
done
"""


def docker(image: str, work: Path, script: str, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "run", "--rm", "-v", f"{work.resolve()}:/w", "--entrypoint", "sh",
                           image, "-c", script], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=ENV)


def flip(b: bytes, i: int) -> bytes:
    x = bytearray(b)
    x[i] ^= 0xFF
    return bytes(x)


# ---- SWUpdate .swu (cpio "crc", 070702) ----

def cpio_entries(data: bytes) -> list[dict]:
    """Offsets of the cpio newc/crc entries: header (110 bytes), name, data."""
    out, off = [], 0
    while off + 110 <= len(data):
        h = data[off:off + 110]
        if h[:6] not in (b"070701", b"070702"):
            break
        fields = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        size, nsz = fields[6], fields[11]
        name = data[off + 110:off + 110 + nsz - 1].decode()
        doff = off + ((110 + nsz + 3) & ~3)
        out.append({"name": name, "hdr": off, "name_end": off + 110 + nsz, "data": doff, "size": size})
        if name == "TRAILER!!!":
            break
        off = doff + ((size + 3) & ~3)
    return out


FIELDS = ["ino", "mode", "uid", "gid", "nlink", "mtime", "filesize", "devmajor", "devminor",
          "rdevmajor", "rdevminor", "namesize", "check"]


def swu_mutants(good: bytes) -> dict[str, bytes]:
    ents = cpio_entries(good)
    names = {e["name"]: e for e in ents}
    assert ["sw-description", "sw-description.sig", "rootfs.ext4.gz"] == [e["name"] for e in ents[:3]], ents
    m: dict[str, bytes] = {"orig": good}
    for k, e in enumerate(ents[:3]):
        for i in range(e["hdr"], e["name_end"]):
            m[f"hdr{k}-flip{i - e['hdr']:03d}"] = flip(good, i)
        for j, fld in enumerate(FIELDS):
            o = e["hdr"] + 6 + 8 * j
            v = int(good[o:o + 8], 16)
            for tag, nv in (("zero", 0), ("max", 0xFFFFFFFF), ("smax", 0x7FFFFFFF),
                            ("inc", (v + 1) & 0xFFFFFFFF), ("dec", (v - 1) & 0xFFFFFFFF)):
                m[f"hdr{k}-{fld}-{tag}"] = good[:o] + f"{nv:08X}".encode() + good[o + 8:]
    for key, tag in (("sw-description", "swd"), ("sw-description.sig", "sig")):
        e = names[key]
        for i in range(e["data"], e["data"] + e["size"]):
            m[f"{tag}-flip{i - e['data']:04d}"] = flip(good, i)
    img = names["rootfs.ext4.gz"]
    for tag, i in (("first", img["data"]), ("mid", img["data"] + img["size"] // 2),
                   ("last", img["data"] + img["size"] - 1)):
        m[f"img-flip-{tag}"] = flip(good, i)
    for n in list(range(0, 4096, 32)) + [e[k] + d for e in ents[:3] for k in ("hdr", "data") for d in (-1, 0, 1)]:
        if 0 <= n < len(good):
            m[f"trunc{n:05d}"] = good[:n]
    sd, sg = names["sw-description"], names["sw-description.sig"]
    chunk = lambda e: good[e["hdr"]:e["data"] + ((e["size"] + 3) & ~3)]  # noqa: E731
    rest = good[sg["data"] + ((sg["size"] + 3) & ~3):]
    m["struct-sig-first"] = chunk(sg) + chunk(sd) + rest
    m["struct-dup-swd"] = chunk(sd) + chunk(sd) + chunk(sg) + rest
    m["struct-no-sig"] = chunk(sd) + rest
    m["struct-empty"] = b""
    m["struct-trailer-only"] = good[ents[-1]["hdr"]:] if ents[-1]["name"] == "TRAILER!!!" else b""
    return m


# ---- RAUC bundle: [payload][CMS][u64 big-endian CMS size] ----

def rauc_mutants(tag: str, good: bytes) -> dict[str, bytes]:
    sig = int.from_bytes(good[-8:], "big")
    start = len(good) - 8 - sig
    m: dict[str, bytes] = {f"{tag}-orig": good}
    for i in range(start, len(good)):
        m[f"{tag}-tail-flip{i - start:05d}"] = flip(good, i)
    for name, v in (("zero", 0), ("one", 1), ("dec", sig - 1), ("inc", sig + 1), ("file", len(good)),
                    ("file-8", len(good) - 8), ("2^31", 2 ** 31), ("2^32", 2 ** 32),
                    ("2^63-1", 2 ** 63 - 1), ("2^64-1", 2 ** 64 - 1)):
        m[f"{tag}-size-{name}"] = good[:-8] + v.to_bytes(8, "big")
    for k in list(range(1, 17)) + [8 + sig, 9 + sig, len(good) - 1]:
        if k < len(good):
            m[f"{tag}-cut{k}"] = good[:-k]
    for i in range(96):  # squashfs superblock
        m[f"{tag}-sqfs-flip{i:03d}"] = flip(good, i)
    return m


def write(work: Path, muts: dict[str, bytes]) -> None:
    d = work / "mut"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir()
    for k, v in muts.items():
        (d / k).write_bytes(v)


def swu(work: Path) -> dict:
    p = docker(SWU_IMAGE, work, SWU_BUILD, 600)
    if p.returncode != 0:
        return {"verdict": "ERROR", "detail": f"precondition: build failed: {p.stderr[-300:]}"}
    good = (work / "good.swu").read_bytes()
    genuine = hashlib.sha256(__import__("gzip").decompress(
        good[[e for e in cpio_entries(good) if e["name"] == "rootfs.ext4.gz"][0]["data"]:][
            :[e for e in cpio_entries(good) if e["name"] == "rootfs.ext4.gz"][0]["size"]])).hexdigest()
    muts = swu_mutants(good)
    muts["control-attacker"] = (work / "attacker.swu").read_bytes()
    write(work, muts)
    p = docker(SWU_IMAGE, work, SWU_RUN, 7200)
    rows = {r[0]: (int(r[1]), r[2]) for r in (ln.split() for ln in p.stdout.splitlines()) if len(r) == 3}
    if len(rows) != len(muts):
        return {"verdict": "ERROR", "detail": f"precondition: {len(rows)} of {len(muts)} inputs ran ({p.stderr[-200:]})"}
    empty = hashlib.sha256(b"").hexdigest()
    if rows["orig"] != (0, genuine) or rows["control-attacker"][0] == 0:
        return {"verdict": "ERROR", "detail": f"precondition: genuine {rows['orig']}, attacker {rows['control-attacker']}"}
    crashes = sorted(k for k, (rc, _) in rows.items() if rc >= CRASH_RC)
    bypass = sorted(k for k, (rc, h) in rows.items() if rc == 0 and h != genuine and k != "orig")
    benign = sorted(k for k, (rc, h) in rows.items() if rc == 0 and h == genuine and k != "orig")
    partial = sorted(k for k, (rc, h) in rows.items() if rc != 0 and h not in (empty, genuine))
    n = len(muts) - 2
    verdict = "FAIL" if crashes or bypass else "PASS"
    return {"verdict": verdict, "inputs": n, "crashes": crashes, "bypass": bypass, "accepted_genuine": benign,
            "rejected_after_writing_slot": len(partial),
            "detail": (f"{len(crashes)} crashes or timeouts, {len(bypass)} accepted with a foreign payload of {n} "
                       f"mutated .swu; {len(benign)} accepted with the genuine payload (unsigned cpio fields); "
                       f"{len(partial)} rejected after streaming into the inactive slot (installed-directly)")}


def rauc(work: Path) -> dict:
    p = docker(RAUC_IMAGE, work, RAUC_BUILD, 600)
    if p.returncode != 0:
        return {"verdict": "ERROR", "detail": f"precondition: build failed: {p.stderr[-300:]}"}
    muts: dict[str, bytes] = {}
    for fmt in ("plain", "verity"):
        muts.update(rauc_mutants(fmt, (work / f"good-{fmt}.raucb").read_bytes()))
    write(work, muts)
    p = docker(RAUC_IMAGE, work, RAUC_RUN, 7200)
    rows: dict[tuple[str, str], tuple[int, str, str]] = {}
    for r in (ln.split() for ln in p.stdout.splitlines()):
        if len(r) == 5:
            rows[(r[0], r[1])] = (int(r[2]), r[3], r[4])
    versions = sorted({v for _, v in rows})
    if len(rows) != 2 * len(muts) or len(versions) != 2:
        return {"verdict": "ERROR", "detail": f"precondition: {len(rows)} of {2 * len(muts)} runs ({p.stderr[-200:]})"}
    out = {"verdict": "PASS", "inputs": len(muts) - 2, "versions": {}}
    for v in versions:
        orig = {fmt: rows[(f"{fmt}-orig", v)] for fmt in ("plain", "verity")}
        if any(o[0] != 0 or o[1] != "2" for o in orig.values()):
            out["versions"][v] = {"verdict": "ERROR", "detail": f"precondition: genuine bundles {orig}"}
            out["verdict"] = "ERROR"
            continue
        mine = {k: x for (k, vv), x in rows.items() if vv == v and not k.endswith("-orig")}
        crashes = sorted(k for k, x in mine.items() if x[0] >= CRASH_RC)
        accepted = sorted(k for k, x in mine.items() if x[0] == 0)
        # the signature covers the manifest (with the image digest) and, for plain bundles,
        # the whole payload: an accepted mutant is a bypass unless it changed nothing signed
        bypass = [k for k in accepted
                  if mine[k][1:] != orig[k.split("-")[0]][1:] or (k.startswith("plain-sqfs"))]
        r = {"verdict": "FAIL" if crashes or bypass else "PASS", "crashes": crashes, "accepted": accepted,
             "bypass": bypass,
             "detail": f"{len(crashes)} crashes or timeouts, {len(bypass)} bypasses of {len(mine)} mutated bundles; "
                       f"{len(accepted)} accepted" + (f": {' '.join(accepted[:10])}" if accepted else "")}
        out["versions"][v] = r
        if r["verdict"] == "FAIL":
            out["verdict"] = "FAIL"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=("swu", "rauc"))
    ap.add_argument("--out", default=str(ROOT / "results" / f"d5-container-mutations-{date.today():%Y-%m-%d}"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    prev = out / "results.json"
    res = json.loads(prev.read_text(encoding="utf-8")) if prev.exists() else {}
    for name, fn in (("swu-mutations", swu), ("rauc-bundle-mutations", rauc)):
        if a.only and not name.startswith(a.only):
            continue
        work = out / f"work-{name}"
        work.mkdir(exist_ok=True)
        r = fn(work)
        res[name] = r
        print(f"{name}: {r['verdict']}  {r.get('detail', '')}")
        for v, x in (r.get("versions") or {}).items():
            print(f"   rauc {v}: {x['verdict']}  {x['detail']}")
        shutil.rmtree(work, ignore_errors=True)
    prev.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
