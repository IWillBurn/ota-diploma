"""Example compliance evidence report (backlog D6): for one implementation, every clause of
the selected regulations that the catalog traces to a threat, with the verdicts the bench
obtained for those threats.

The report is evidence, not a conformity assessment: a PASS means "not violated within the
bench's attacker and fault models in the tested configuration" (ch. 2.7).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date
from pathlib import Path

from .threatmatrix import ICON, RANK, build

REGS = {
    "cra": "Регламент (ЕС) 2024/2847 (CRA), приложение I",
    "unr156": "Правила ООН № 156",
    "en18031": "EN 18031-1:2024",
    "nist800193": "NIST SP 800-193",
    "fstec117": "Приказ ФСТЭК России № 117",
    "fstec239": "Приказ ФСТЭК России № 239",
    "fstec_method": "Методика тестирования обновлений безопасности (ФСТЭК России, 2022)",
}


def _clause(ref: str) -> str:
    """'Annex I Part I (2)(h) availability ...' -> 'Annex I Part I (2)(h)' (first words up to
    the description)."""
    words = ref.split()
    out = []
    for w in words:
        if out and (w[:1] in "'\"«“≈" or (not any(ch.isdigit() for ch in w) and w[:1].islower()
                                              and w not in ("п.", "Part", "Annex"))):
            break
        out.append(w)
    return " ".join(out) or ref


def write(catalog: dict, mvp: dict | None, pilots: dict, impl: str, regs: list[str], out: Path) -> Path:
    cols, rows = build(catalog, mvp, pilots)
    if impl not in cols:
        raise SystemExit(f"unknown implementation {impl!r}; known: {', '.join(cols)}")
    by_id = {r["id"]: r for r in rows}
    lines = [f"# Свидетельства соответствия: {impl}", "",
             f"Сформировано `otabench compliance` {date.today():%d.%m.%Y} из каталога угроз и результатов "
             "стенда. Это **свидетельства в границах моделей нарушителя и сбоя стенда** для испытанной "
             "конфигурации, а не оценка соответствия: PASS значит «нарушение не наблюдалось», "
             "«—» — угроза к этой реализации применима, но не испытана.", ""]
    for reg in regs:
        clauses: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for t in catalog["threats"]:
            for ref in (t.get("refs") or {}).get(reg, []):
                clauses[_clause(ref)].append((t["id"], ref))
        if not clauses:
            continue
        lines += [f"## {REGS.get(reg, reg)}", "",
                  "| Пункт | Угрозы каталога | Вердикт стенда | Итог по пункту |", "|---|---|---|---|"]
        for clause in sorted(clauses):
            cells, worst = [], None
            for tid, _ in clauses[clause]:
                v, note = by_id[tid]["cells"][impl]
                cells.append(f"{tid}: {ICON.get(v, v)}" + (f" ({note})" if note else ""))
                if v in RANK and (worst is None or RANK[v] > RANK[worst]):
                    worst = v
            tested = [c for c in cells if "n/a" not in c]
            if not tested:
                continue
            ran = sum(1 for c in tested if not c.split(": ", 1)[1].startswith("—"))
            if not worst:
                summary = "— не испытано"
            elif ran < len(tested):
                summary = f"{ICON.get(worst, '')} {worst} по {ran} из {len(tested)} угроз, остальные не испытаны"
            else:
                summary = f"{ICON.get(worst, '')} {worst}"
            lines.append(f"| {clause} | {', '.join(t for t, _ in clauses[clause])} | {'; '.join(tested)} | {summary} |")
        lines.append("")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return out
