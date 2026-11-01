#!/usr/bin/env python
"""Deliberately naive TUF-like updater: a NEGATIVE CONTROL for otabench.

It models a typical hand-rolled updater: it does verify signatures (threshold of
root-listed keys) and the artifact hash, but it

* never checks expiration dates            -> freeze attacks succeed
* never compares versions with trusted ones -> rollback / mix-and-match succeed
* reads HTTP responses without size/time limits -> endless / slow data succeed
* writes metadata and artifacts in place (non-atomic) and trusts an existing
  artifact file without re-hashing it        -> torn writes survive a crash

A benchmark that cannot tell this client apart from a real TUF client is not
measuring anything, so every run should include it.

Mutants (mutation analysis of the benchmark itself): OTABENCH_MUTANT is a
comma-separated list of additional checks to switch off. Every scenario should
"kill" (FAIL) at least one mutant, otherwise it cannot detect anything.
  sig         accept metadata without verifying signatures
  role-keys   accept a signature by ANY key listed in root, not the role's keys
  hash        do not verify artifact hashes
  keep-torn   do not delete an artifact whose hash did not match

CLI is the tuf-conformance client-under-test protocol (init / refresh / download).
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request

from securesystemslib.signer import SSlibKey
from tuf.api.metadata import Metadata, Root


MUTANT = {m for m in os.environ.get("OTABENCH_MUTANT", "").split(",") if m}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url) as resp:  # no timeout, no length limit
        return resp.read()


def save(path: str, data: bytes) -> None:
    with open(path, "wb") as f:  # in-place, no fsync, no rename
        f.write(data)


def verify(md: Metadata, root: Root, role: str) -> None:
    if "sig" in MUTANT:
        return
    r = root.roles[role]
    payload = md.signed_bytes
    good = 0
    keyids = list(root.keys) if "role-keys" in MUTANT else r.keyids
    for keyid in keyids:
        sig = md.signatures.get(keyid)
        if sig is None:
            continue
        key: SSlibKey = root.keys[keyid]
        try:
            key.verify_signature(sig, payload)
            good += 1
        except Exception:  # noqa: BLE001
            pass
    if good < r.threshold:
        raise RuntimeError(f"{role}: {good}/{r.threshold} valid signatures")


def refresh(metadata_url: str, metadata_dir: str) -> Metadata:
    base = metadata_url.rstrip("/")
    root_md = Metadata.from_file(os.path.join(metadata_dir, "root.json"))
    root = root_md.signed
    # root rotation: follow N+1.root.json while it exists (signature-checked only)
    while True:
        try:
            raw = fetch(f"{base}/{root.version + 1}.root.json")
        except Exception:  # noqa: BLE001
            break
        new = Metadata.from_bytes(raw)
        verify(new, root, "root")
        root = new.signed
        save(os.path.join(metadata_dir, "root.json"), raw)

    raw = fetch(f"{base}/timestamp.json")
    ts = Metadata.from_bytes(raw)
    verify(ts, root, "timestamp")
    save(os.path.join(metadata_dir, "timestamp.json"), raw)

    snap_ver = ts.signed.snapshot_meta.version
    raw = fetch(f"{base}/{snap_ver}.snapshot.json")
    snap = Metadata.from_bytes(raw)
    verify(snap, root, "snapshot")
    save(os.path.join(metadata_dir, "snapshot.json"), raw)

    tgt_ver = snap.signed.meta["targets.json"].version
    raw = fetch(f"{base}/{tgt_ver}.targets.json")
    tgts = Metadata.from_bytes(raw)
    verify(tgts, root, "targets")
    save(os.path.join(metadata_dir, "targets.json"), raw)
    return tgts


def download(metadata_url, metadata_dir, names, target_dir, target_base_url) -> None:
    tgts = refresh(metadata_url, metadata_dir)
    for name in names:
        info = tgts.signed.targets.get(name)
        if info is None:
            raise RuntimeError(f"{name} not in targets")
        final = os.path.join(target_dir, name.replace("/", "_"))
        if os.path.exists(final):  # "cache": trusts any existing file
            continue
        sha = info.hashes["sha256"]
        url = f"{target_base_url.rstrip('/')}/{sha}.{name}"
        h = hashlib.sha256()
        with urllib.request.urlopen(url) as resp, open(final, "wb") as out:
            while chunk := resp.read(16384):  # streams straight into final path
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != sha and "hash" not in MUTANT:
            if "keep-torn" not in MUTANT:
                os.remove(final)
            raise RuntimeError(f"{name}: hash mismatch")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--metadata-url")
    p.add_argument("--metadata-dir", required=True)
    p.add_argument("--target-name", action="append")
    p.add_argument("--target-dir")
    p.add_argument("--target-base-url")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("init").add_argument("trusted_root")
    sub.add_parser("refresh")
    sub.add_parser("download")
    a = p.parse_args()
    try:
        if a.cmd == "init":
            with open(a.trusted_root, "rb") as f:
                save(os.path.join(a.metadata_dir, "root.json"), f.read())
        elif a.cmd == "refresh":
            refresh(a.metadata_url, a.metadata_dir)
        elif a.cmd == "download":
            download(a.metadata_url, a.metadata_dir, a.target_name, a.target_dir,
                     a.target_base_url)
        else:
            p.print_help()
            return 1
    except Exception as e:  # noqa: BLE001
        print(f"naive client: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
