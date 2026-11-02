"""The threat catalog matches its schema, and every scenario it names exists."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from otabench.report import CatalogError, load_catalog  # noqa: E402
from otabench.scenarios import REGISTRY  # noqa: E402

CATALOG = ROOT / "catalog" / "threats.yaml"
# scenario names of scripts/pilot_ab.py (+ replay_state.py), as the catalog writes them
AB = {"happy", "broken", "broken-unconfirmed", "attacker", "downgrade", "cut-firstboot",
      "cut-unconfirmed", "crash-replay", "window:*", "reorder:*", "reorder:* --torn",
      "replay-state-liveness", "toctou", "net-ok", "net-tamper", "net-drop", "net-slow", "net-endless"}
OTHER = {"rauc-sigcover",  # scripts/rauc_sigcover.py
         "fuzz-coverage",  # scripts/fuzz_cov.py
         "swu-mutations", "rauc-bundle-mutations"}  # scripts/container_mutations.py
SUIT = {"suit-mutations", "suit-payload-substitution", "suit-manifest-tamper", "suit-signature-tamper",
        "suit-extra-data", "suit-malformed"}  # scripts/suit_bench.py


def test_catalog_valid() -> None:
    cat = load_catalog(CATALOG)
    assert len(cat["threats"]) == 40


def test_bench_ids_exist() -> None:
    cat = load_catalog(CATALOG)
    for t in cat["threats"]:
        for sid in t["bench"]:
            if sid.startswith("ab:"):
                assert sid[3:] in AB, (t["id"], sid)
            elif sid.startswith("suit-"):
                assert sid in SUIT, (t["id"], sid)
            elif sid in OTHER:
                continue
            else:
                assert sid in REGISTRY, (t["id"], sid)


def test_registry_threats_in_catalog() -> None:
    ids = {t["id"] for t in load_catalog(CATALOG)["threats"]}
    for sid, (threats, _, _) in REGISTRY.items():
        assert set(threats) <= ids, sid


def _write(tmp_path: Path, cat: dict) -> Path:
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cat, allow_unicode=True), encoding="utf-8")
    return p


def test_schema_rejects_bad_entries(tmp_path: Path) -> None:
    base = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    bad_class = copy.deepcopy(base)
    bad_class["threats"][0]["class"] = "magic"
    with pytest.raises(CatalogError, match="threats/0/class"):
        load_catalog(_write(tmp_path, bad_class))
    no_verified = copy.deepcopy(base)
    del no_verified["threats"][1]["refs"]["verified"]
    with pytest.raises(CatalogError, match="verified"):
        load_catalog(_write(tmp_path, no_verified))
    dup = copy.deepcopy(base)
    dup["threats"][2]["id"] = dup["threats"][3]["id"]
    with pytest.raises(CatalogError, match="duplicate"):
        load_catalog(_write(tmp_path, dup))


def test_every_unexecuted_threat_states_why() -> None:
    """D1: a threat without a bench scenario carries the reason in `bench_gap`."""
    cat = load_catalog(CATALOG)
    missing = [t["id"] for t in cat["threats"] if not t.get("bench") and not t.get("bench_gap")]
    assert not missing, missing
