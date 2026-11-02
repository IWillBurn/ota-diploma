"""Coverage-guided fuzzing of python-tuf's TrustedMetadataSet with atheris (backlog D5).

The fuzzed bytes are the "signed" body of one role; the harness signs it with the key that the
trusted root delegates to every role, so the input reaches the checks behind the signature (the
same threat model as go-tuf's harness and the scenario fuzz-metadata). The `parse` target feeds
unsigned envelopes instead. python-tuf documents RepositoryError (DeserializationError is one)
as the error of a bad repository; any other exception escapes Updater.refresh() and is reported
as a finding.

  python fuzz_tuf.py <target> [libFuzzer flags]    targets: parse timestamp_first
      timestamp_second snapshot targets root_update
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from securesystemslib.signer import CryptoSigner
    from tuf.api.exceptions import RepositoryError
    from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp
    from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
    from tuf.ngclient.config import EnvelopeType

SIGNER = CryptoSigner(Ed25519PrivateKey.from_private_bytes(b"\x07" * 32))
EXP = (datetime.now(timezone.utc) + timedelta(days=3650)).replace(microsecond=0)


def _signed(md: Metadata) -> bytes:
    md.signatures.clear()
    md.sign(SIGNER)
    return md.to_bytes()


root = Metadata(Root(expires=EXP))
for r in ("root", "timestamp", "snapshot", "targets"):
    root.signed.add_key(SIGNER.public_key, r)
ROOT = _signed(root)
TS = _signed(Metadata(Timestamp(expires=EXP)))
SN = _signed(Metadata(Snapshot(expires=EXP)))
TG = _signed(Metadata(Targets(expires=EXP)))
root.signed.version = 2
ROOT2 = _signed(root)


def body(raw: bytes) -> bytes:
    i = raw.index(b'"signed"')
    return raw[raw.index(b"{", i):raw.rindex(b"}")]


def sign(b: bytes, typ: str) -> bytes | None:
    """Envelope + signature for a fuzzed body of role `typ`; None if it does not parse as one
    (rejected before any signature check) or cannot be canonicalised for signing."""
    try:
        md = Metadata.from_bytes(b'{"signatures":[],"signed":' + b + b"}")
        if md.signed.type != typ:
            return None
        return _signed(md)
    except Exception:  # noqa: BLE001 - harness side, not the code under test
        return None


def trusted() -> TrustedMetadataSet:
    return TrustedMetadataSet(ROOT, EnvelopeType.METADATA)


def t_parse(data: bytes) -> None:
    try:
        TrustedMetadataSet(data, EnvelopeType.METADATA)
    except RepositoryError:
        pass


def t_timestamp_first(data: bytes) -> None:
    raw = sign(data, "timestamp")
    if raw is None:
        return
    try:
        trusted().update_timestamp(raw)
    except RepositoryError:
        pass


def t_timestamp_second(data: bytes) -> None:
    raw = sign(data, "timestamp")
    if raw is None:
        return
    tm = trusted()
    tm.update_timestamp(TS)
    try:
        tm.update_timestamp(raw)
    except RepositoryError:
        pass


def t_snapshot(data: bytes) -> None:
    raw = sign(data, "snapshot")
    if raw is None:
        return
    tm = trusted()
    tm.update_timestamp(TS)
    try:
        tm.update_snapshot(raw)
    except RepositoryError:
        pass


def t_targets(data: bytes) -> None:
    raw = sign(data, "targets")
    if raw is None:
        return
    tm = trusted()
    tm.update_timestamp(TS)
    tm.update_snapshot(SN)
    try:
        tm.update_targets(raw)
    except RepositoryError:
        pass


def t_root_update(data: bytes) -> None:
    raw = sign(data, "root")
    if raw is None:
        return
    try:
        trusted().update_root(raw)
    except RepositoryError:
        pass


TARGETS = {"parse": (t_parse, [ROOT, TS]), "timestamp_first": (t_timestamp_first, [body(TS)]),
           "timestamp_second": (t_timestamp_second, [body(TS)]), "snapshot": (t_snapshot, [body(SN)]),
           "targets": (t_targets, [body(TG)]), "root_update": (t_root_update, [body(ROOT2)])}

if __name__ == "__main__":
    fn, seeds = TARGETS[sys.argv.pop(1)]
    corpus = "corpus"
    os.makedirs(corpus, exist_ok=True)
    for k, s in enumerate(seeds):
        with open(os.path.join(corpus, f"seed{k}"), "wb") as f:
            f.write(s)
    atheris.Setup(sys.argv + [corpus], fn)
    atheris.Fuzz()
