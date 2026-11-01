"""Thesis figures (static SVG, light, print-friendly) generated from the result files.

  python make_figures.py            ->  docs/figures/fig4-1-matrix.svg, fig4-2-window.svg, fig4-3-fix.svg

Palette: reference instance of the dataviz method (status palette for verdicts, one hue
for magnitudes, categorical slots 1-2 for before/after; validated: CVD dE 24.7).
Every mark carries a <title> so the SVG shows a tooltip when opened in a browser.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
OUT = ROOT.parent / "docs" / "figures"

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e4e3df"
BLUE, ORANGE = "#2a78d6", "#eb6834"
STATUS = {"PASS": "#0ca30c", "FAIL": "#d03b3b", "PARTIAL": "#fab219", "ERROR": "#9b9a94"}
FONT = "font-family='Arial, Helvetica, sans-serif'"


def tint(hex_color: str, a: float) -> str:
    """Mix a colour into the surface (a = share of the colour)."""
    c = [int(hex_color[i:i + 2], 16) for i in (1, 3, 5)]
    s = [int(SURFACE[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(a * x + (1 - a) * y):02x}" for x, y in zip(c, s))


def esc(s: object) -> str:
    return html.escape(str(s), quote=True)


def text(x, y, s, size=12, color=INK, anchor="start", weight="normal") -> str:
    return (f"<text x='{x:.1f}' y='{y:.1f}' {FONT} font-size='{size}' fill='{color}' "
            f"text-anchor='{anchor}' font-weight='{weight}'>{esc(s)}</text>")


def hbar(x, y, w, h, color, title) -> str:
    """Horizontal bar anchored at the baseline (square left), 4px rounded data end."""
    if w <= 0:
        return ""
    r = min(4.0, w / 2, h / 2)
    d = (f"M{x:.1f},{y:.1f} H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} "
         f"V{y + h - r:.1f} Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z")
    return f"<path d='{d}' fill='{color}'><title>{esc(title)}</title></path>"


def svg(w, h, body: list[str], title: str) -> str:
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' "
            f"viewBox='0 0 {w} {h}' role='img' aria-label='{esc(title)}'>"
            f"<title>{esc(title)}</title><rect width='100%' height='100%' fill='{SURFACE}'/>"
            + "".join(body) + "</svg>\n")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ fig 4.1
SCEN_RU = {
    "arb-target-substitution": "подмена артефакта", "arb-metadata-tamper": "подделка метаданных",
    "arb-keyid-spoofing": "подмена keyid", "freeze-expired-timestamp": "заморозка",
    "rollback-timestamp": "откат timestamp", "mix-and-match": "mix-and-match",
    "online-keys-downgrade": "онлайн-ключи: даунгрейд", "online-keys-arbitrary": "онлайн-ключи: своё ПО",
    "endless-metadata": "бесконечные метаданные", "endless-artifact": "бесконечный артефакт",
    "slow-metadata": "медленные метаданные", "slow-artifact": "медленный артефакт",
    "dropped-connection": "обрыв соединения", "powercut-refresh": "обрыв питания: refresh",
    "powercut-download": "обрыв питания: загрузка",
}


def cell_note(r: dict) -> str:
    m = r.get("metrics") or {}
    if "survival_rate" in m:
        return f"{m.get('survived')}/{m.get('trials')}"
    if "time_to_abort_s" in m and r["scenario"].startswith("slow"):
        return "≥120 с" if r["verdict"] == "FAIL" else f"{m['time_to_abort_s']:.0f} с"
    if "bytes_pushed" in m and r["scenario"].startswith("endless") and r["verdict"] == "FAIL":
        return f"{m['bytes_pushed'] / 2**20:.0f} МиБ"
    return ""


def fig_matrix() -> str:
    run = load(RES / "full-2026-10-31-v2" / "results.json")
    clients = [c["name"] for c in run["clients"]]
    scen = [s for s in dict.fromkeys(r["scenario"] for r in run["results"]) if s != "baseline"]
    by = {(r["scenario"], r["client"]): r for r in run["results"]}
    lw, cw, ch, top = 190, 74, 30, 92
    w, h = lw + cw * len(clients) + 16, top + ch * len(scen) + 86
    body = [text(16, 24, "Рис. 4.1. Вердикты сценариев для TUF-клиентов и контрольных реализаций", 14, INK, weight="bold"),
            text(16, 42, "прогон 31.10.2026, 10 испытаний на сценарий обрыва; в ячейке — вердикт и ключевая метрика", 11, INK2)]
    for j, c in enumerate(clients):
        x = lw + j * cw + cw / 2
        name = c.replace("naive-", "мутант ").replace("naive", "naive (контроль)") if c.startswith("naive") else c
        for k, part in enumerate(name.split(" ", 1)):
            body.append(text(x, top - 22 + 13 * k, part, 11, INK if not c.startswith("naive") else INK2, "middle",
                             "bold" if not c.startswith("naive") else "normal"))
    body.append(f"<line x1='{lw + 3 * cw - 1:.1f}' y1='{top - 34}' x2='{lw + 3 * cw - 1:.1f}' "
                f"y2='{top + ch * len(scen)}' stroke='{MUTED}' stroke-width='1' stroke-dasharray='3 3'/>")
    for i, s in enumerate(scen):
        y = top + i * ch
        body.append(text(lw - 8, y + ch / 2 + 4, SCEN_RU.get(s, s), 11.5, INK, "end"))
        for j, c in enumerate(clients):
            r = by.get((s, c))
            if not r:
                continue
            v = r["verdict"]
            x = lw + j * cw
            tip = f"{s} / {c}: {v}" + (f" — {r['detail']}" if r.get("detail") else "")
            body.append(f"<rect x='{x + 1:.1f}' y='{y + 1:.1f}' width='{cw - 2}' height='{ch - 2}' rx='4' "
                        f"fill='{tint(STATUS[v], 0.28)}'><title>{esc(tip)}</title></rect>")
            note = cell_note(r)
            body.append(text(x + cw / 2, y + (12 if note else 19), v, 10.5, INK, "middle", "bold"))
            if note:
                body.append(text(x + cw / 2, y + 24, note, 9.5, INK2, "middle"))
    ly = top + ch * len(scen) + 26
    items = (("PASS", "атака заблокирована / сбой пережит"), ("FAIL", "атака удалась / сбой не пережит"),
             ("PARTIAL", "пережита часть испытаний"), ("ERROR", "не выполнено предусловие"))
    for n, (v, label) in enumerate(items):
        lx, yy = 16 + (n % 2) * 330, ly + (n // 2) * 20
        body.append(f"<rect x='{lx}' y='{yy - 10}' width='14' height='14' rx='3' fill='{tint(STATUS[v], 0.28)}' "
                    f"stroke='{STATUS[v]}' stroke-width='1'/>")
        body.append(text(lx + 20, yy + 1, f"{v} — {label}", 11, INK2))
    body.append(text(16, ly + 46, "Слева от пунктира — реальные реализации TUF, справа — контрольный клиент и его мутанты.", 11, INK2))
    return svg(w, h, body, "Вердикты сценариев для TUF-клиентов")


# ------------------------------------------------------------------ fig 4.2
WIN_RU = [
    ("ext4-c5", "ext4, commit=5 (по умолчанию)"), ("ext4-c1", "ext4, commit=1"), ("ext4-c30", "ext4, commit=30"),
    ("ext4-exponly", "ext4, dirty_expire = 1 с"), ("ext4-wbonly", "ext4, dirty_writeback = 1 с"),
    ("ext4-wb1", "ext4, оба параметра = 1 с"), ("ext2", "ext2 (без журнала)"), ("vfat", "vfat (без журнала)"),
    ("uefi-esp", "UEFI, ESP (vfat)"), ("ext4-inplace", "ext4 + запись на месте"),
    ("ext2-inplace", "ext2 + запись на месте"), ("vfat-inplace", "vfat + запись на месте"),
    ("uefi-esp-inplace", "UEFI ESP + запись на месте"),
]


def collect_windows() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(RES.glob("pilot-ab-*/pilot.json")):
        for name, r in load(p)["results"].items():
            if name.startswith("window:") and r.get("verdict") != "ERROR":
                out[name.split(":", 1)[1]] = r | {"_dir": p.parent.name}
    return out


def fig_window() -> str:
    win = collect_windows()
    rows = [(k, ru) for k, ru in WIN_RU if k in win]
    lw, top, bh, gap, scale, xmax = 230, 70, 14, 12, 52, 8
    w, h = lw + scale * xmax + 120, top + (bh + gap) * len(rows) + 88
    body = [text(16, 24, "Рис. 4.2. Сколько секунд после «succeeded» GRUB видит старое состояние A/B", 14, INK, weight="bold"),
            text(16, 42, "длина столбца — первая метка, на которой GRUB видит новое состояние; подпись — интервал", 11, INK2)]
    for t in range(0, xmax + 1):
        x = lw + t * scale
        body.append(f"<line x1='{x}' y1='{top - 8}' x2='{x}' y2='{top + (bh + gap) * len(rows) - gap + 4}' "
                    f"stroke='{GRID}' stroke-width='1'/>")
        body.append(text(x, top - 12, f"{t}", 10.5, MUTED, "middle"))
    body.append(text(lw + xmax * scale, top + (bh + gap) * len(rows) + 8, "секунды после успешной установки", 10.5, MUTED, "end"))
    for i, (k, ru) in enumerate(rows):
        r = win[k]
        y = top + i * (bh + gap)
        old, new = r.get("old_until_s"), r.get("new_from_s")
        label = ("окна нет" if not old and new == 0 and old is None else
                 f"{old}–{new} с" if old is not None and new is not None else f"≥{old} с")
        if old is None and new == 0:
            label = "окна нет"
        fix = k.endswith("inplace")
        body.append(text(lw - 8, y + bh - 2, ru, 11.5, INK if not fix else INK2, "end"))
        tip = f"{ru}: старое до +{old} с, новое с +{new} с ({r['_dir']})"
        body.append(hbar(lw, y, (new or 0) * scale, bh, BLUE, tip))
        body.append(text(lw + (new or 0) * scale + 6, y + bh - 2, label, 11, INK2))
    body.append(text(16, top + (bh + gap) * len(rows) + 40,
                     "Метки после установки: 0, 1, 2, 3, 4, 5, 6, 8, 10 с и далее; для ext4 по умолчанию окно лежит между 4 и 5 с.",
                     10.5, INK2))
    body.append(text(16, top + (bh + gap) * len(rows) + 58,
                     "Окно задаёт период фонового сброса (dirty_writeback), а не commit= и не dirty_expire; без журнала окна нет.",
                     10.5, INK2))
    return svg(w, h, body, "Окно, в котором GRUB видит старое состояние после успешной установки")


# ------------------------------------------------------------------ fig 4.3
FIX = [  # (label, before: (dir, scenario), after: (dir, scenario))
    ("ext4", ("pilot-ab-20261101-103655", "reorder:ext4-c5"), ("pilot-ab-20261101-111300", "reorder:ext4-inplace")),
    ("ext2", ("pilot-ab-20261101-103655", "reorder:ext2"), ("pilot-ab-20261101-111300", "reorder:ext2-inplace")),
    ("vfat", ("pilot-ab-20261101-103655", "reorder:vfat"), ("pilot-ab-20261101-111300", "reorder:vfat-inplace")),
    ("UEFI, ESP", ("pilot-ab-20261101-125344", "reorder:uefi-esp"), ("pilot-ab-20261101-125344", "reorder:uefi-esp-inplace")),
]


def bad_share(d: str, s: str) -> tuple[int, int, dict]:
    pts = load(RES / d / "pilot.json")["results"][s]["points"]
    bad = [p for p in pts if p["verdict"] != "OK"]
    why = {"нечитаемо": sum(not p["env_ok"] for p in bad),
           "расхождение": sum(p["env_ok"] and p["diverged"] for p in bad)}
    return len(bad), len(pts), why


def fig_fix() -> str:
    lw, top, bh, inner, group, scale = 110, 92, 14, 4, 22, 6.0
    w = lw + scale * 80 + 190
    h = top + len(FIX) * (2 * bh + inner + group) + 40
    body = [text(16, 24, "Рис. 4.3. Плохие состояния в модели перестановок: до и после записи окружения на месте", 14, INK, weight="bold"),
            text(16, 42, "доля состояний диска после обрыва, где окружение GRUB нечитаемо или GRUB и ОС видят разное", 11, INK2)]
    for lx, color, label in ((16, BLUE, "grub-editenv (встроенный бэкенд RAUC)"), (300, ORANGE, "запись на месте (исправление)")):
        body.append(f"<rect x='{lx}' y='54' width='12' height='12' rx='3' fill='{color}'/>")
        body.append(text(lx + 18, 64, label, 11, INK2))
    for t in range(0, 81, 20):
        x = lw + t * scale
        body.append(f"<line x1='{x}' y1='{top - 6}' x2='{x}' y2='{h - 44}' stroke='{GRID}' stroke-width='1'/>")
        body.append(text(x, top - 10, f"{t}%", 10.5, MUTED, "middle"))
    for i, (fs, before, after) in enumerate(FIX):
        y0 = top + i * (2 * bh + inner + group)
        body.append(text(lw - 8, y0 + bh + 4, fs, 12, INK, "end", "bold"))
        for k, (src, color) in enumerate(((before, BLUE), (after, ORANGE))):
            bad, n, why = bad_share(*src)
            y = y0 + k * (bh + inner)
            share = 100 * bad / n
            reason = ", ".join(f"{r}: {v}" for r, v in why.items() if v)
            tip = f"{fs}, {'до' if k == 0 else 'после'}: {bad} из {n} ({reason or 'все OK'}) — {src[0]}"
            body.append(hbar(lw, y, share * scale, bh, color, tip))
            body.append(text(lw + share * scale + 6, y + bh - 2,
                             f"{bad}/{n}" + (f" ({reason})" if reason else " — плохих состояний нет"), 11, INK2))
    body.append(text(16, h - 18, "Окно и префиксная модель — рис. 4.2 и разд. 4.3; разрыв по секторам — разд. 4.3.", 10.5, INK2))
    return svg(w, h, body, "Плохие состояния до и после исправления")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in (("fig4-1-matrix.svg", fig_matrix), ("fig4-2-window.svg", fig_window), ("fig4-3-fix.svg", fig_fix)):
        (OUT / name).write_text(fn(), encoding="utf-8", newline="\n")
        print(OUT / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
