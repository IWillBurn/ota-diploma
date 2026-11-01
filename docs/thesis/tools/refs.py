"""Thesis references: one numbered list for all chapters (backlog E2).

  python refs.py merge   one-shot: per-chapter lists -> docs/thesis/references.md, citations
                         renumbered in order of first mention (ch1 -> ch4), duplicates merged
                         (same DOI or URL, plus the ALIASES below), entries normalised to the
                         ГОСТ Р 7.0.100-2018 form used here
  python refs.py renumber  after edits: renumber the list and the citations by first mention
  python refs.py check   every [n] in the chapters exists in references.md, every entry is cited

Citations are `[n]`, `[n, m]`, `[n–m]` and `[n, §x.y]` (the locator is kept). Brackets with
other content (intervals such as [0; 0,03]) are left alone.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

THESIS = Path(__file__).resolve().parent.parent
CHAPTERS = ["ch1-analysis.md", "ch2-method.md", "ch3-implementation.md", "ch4-results.md"]
REFS = THESIS / "references.md"
HEADER = re.compile(r"^## Список источников к главе \d+\s*$", re.M)
CITE = re.compile(r"\[(\d+(?:\s*[–-]\s*\d+)?(?:\s*,\s*\d+(?:\s*[–-]\s*\d+)?)*)((?:\s*,\s*§[^\]]*)?)\](?!\()")
ENTRY = re.compile(r"^(\d+)\.\s+(.*\S)\s*$")
ACCESS = "01.11.2026"
XREF = re.compile(r"\s+к гл\.\s*(\d)")  # "[21] к гл. 2": a number from another chapter's list
# local entries that describe the same work as another chapter's entry without sharing a
# DOI/URL: (chapter index, number) -> [(chapter index, number), ...]
ALIASES = {(1, 4): [(0, 16), (0, 18)],  # ch2 "Uptane Standard 2.1.0 ; Deployment Best Practices"
           (1, 10): [(0, 50)]}          # ch2 OWASP ISVS 1.0 without URL
# the same work described differently in two chapters: (text in the later entry, text in
# the entry it duplicates); the longer description is kept
TEXT_ALIASES = [  # "chN:" restricts a pattern to one chapter; dashes are compared loosely
    ("theupdateframework.github.io/specification/latest", "blob/v1.0.37/tuf-spec.md"),
    ("Birkholz H. A Manifest Information Model", "RFC 9124. A Manifest Information Model"),
    ("UN Regulation No. 156. Uniform provisions", "UN Regulation No. 156 (Software update"),
    ("Regan A. Platform Firmware Resiliency", "NIST SP 800-193. Platform Firmware"),
    ("Meriac M. A Firmware Update Architecture", "RFC 9019. A Firmware Update Architecture"),
    ("Регламент (ЕС) 2024/2847", "Regulation (EU) 2024/2847 of the European Parliament"),
    ("EN 18031-1:2024. Common security requirements", "EN 18031-1:2024 [Электронный ресурс]"),
    ("№ 239 «Об утверждении", "№ 239 (требования"),
    ("программно-аппаратных средств : утв.", "программно-аппаратных средств: утв."),
    ("ch2:TLS-Anvil: Adapting", "ch1:TLS-Anvil: Adapting"),
    ("ch2:EXPLODE: A Lightweight", "ch1:EXPLODE: A Lightweight"),
    ("MCUboot: simulator (sim/README.rst", "MCUboot simulator: sim/README.rst"),
    ("ch2:All File Systems Are Not Created Equal", "ch1:All File Systems Are Not Created Equal"),
    ("ch2:Finding Crash-Consistency Bugs", "ch1:Finding Crash-Consistency Bugs"),
    ("ch2:When Amnesia Strikes", "ch1:When Amnesia Strikes"),
    ("ch2:Torturing Databases for Fun and Profit", "ch1:Torturing Databases for Fun and Profit"),
    ("Mender: интеграционные тесты, каталог tests/tests/", "mendersoftware/integration: tests/tests"),
]


MASK = re.compile(r"```.*?```|\$\$.*?\$\$|\$[^$\n]+\$|`[^`\n]*`", re.S)


def cites(body: str):
    """Citation matches outside math ($...$) and code (`...`)."""
    masked = [(m.start(), m.end()) for m in MASK.finditer(body)]
    for m in CITE.finditer(body):
        if not any(a <= m.start() < b for a, b in masked):
            yield m


GROUP = re.compile(r"((?:\[\d+\]\s*(?:,|–)\s*)+\[\d+\])(\s+к гл\.\s*\d)")


def _join_groups(body: str) -> str:
    """'[6], [7], [13]–[15] к гл. 2' -> '[6, 7, 13–15] к гл. 2' (one cross-reference)."""
    def one(m: re.Match) -> str:
        spec = re.sub(r"\]\s*(,|–)\s*\[", lambda x: ", " if x.group(1) == "," else "–", m.group(1))
        return spec + m.group(2)
    return GROUP.sub(one, body)


def _src(body: str, m: re.Match, ci: int) -> int:
    x = XREF.match(body, m.end())
    return int(x.group(1)) - 1 if x else ci


def split(text: str) -> tuple[str, list[tuple[int, str]]]:
    m = HEADER.search(text)
    if not m:
        return text, []
    body, tail = text[:m.start()], text[m.end():]
    entries = [(int(e.group(1)), e.group(2)) for e in map(ENTRY.match, tail.splitlines()) if e]
    return body, entries


def expand(spec: str) -> list[int]:
    out = []
    for part in spec.split(","):
        part = part.strip()
        if re.search(r"[–-]", part):
            a, b = (int(x) for x in re.split(r"\s*[–-]\s*", part))
            out += list(range(a, b + 1))
        elif part:
            out.append(int(part))
    return out


def compress(nums: list[int]) -> str:
    nums = sorted(set(nums))
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(f"{nums[i]}–{nums[j]}" if j - i >= 2 else ", ".join(map(str, nums[i:j + 1])))
        i = j + 1
    return ", ".join(out)


def key(text: str) -> str:
    doi = re.search(r"DOI:\s*(10\.\S+?)\.?(?:\s|$)", text, re.I)
    if doi:
        return "doi:" + doi.group(1).lower().rstrip(".")
    url = re.search(r"URL:\s*(\S+?)[.,;)]*(?:\s|$)", text)
    if url:
        return "url:" + url.group(1).rstrip("/").lower()
    return "txt:" + re.sub(r"[\W_]+", " ", text.lower()).strip()


def gost(text: str) -> str:
    """Normalise one entry to the ГОСТ Р 7.0.100-2018 conventions used in this thesis:
    en dash as the element separator, "– Текст : электронный" instead of the old
    "[Электронный ресурс]", an access date after every URL."""
    t = re.sub(r"\s+—\s+", " – ", text)
    t = re.sub(r"\s*\[Электронный ресурс\]\s*\.\s*", ". – Текст : электронный. ", t)
    t = re.sub(r"\s*\[Электронный ресурс\]\s*", ". – Текст : электронный ", t)
    t = re.sub(r"\.\.\s*– Текст", ". – Текст", t)
    t = t.replace("..", ".")
    t = re.sub(r"\(проверено (\d\d\.\d\d\.\d{4})\)", r"(дата обращения: \1)", t)
    if "URL:" in t and "дата обращения" not in t:
        t = re.sub(r"(URL:\s*\S+?)([.,;]?)(\s|$)", rf"\1 (дата обращения: {ACCESS})\2\3", t, count=1)
    t = re.sub(r"\s+\.", ".", t)
    return t if t.endswith(".") else t + "."


def _find(raw: dict, pat: str) -> list:
    chap = None
    if re.match(r"ch\d:", pat):
        chap, pat = int(pat[2]) - 1, pat[4:]
    loose = lambda x: x.replace("—", "–")  # noqa: E731
    return [cn for cn, e in raw.items() if (chap is None or cn[0] == chap) and loose(pat) in loose(e)]


def merge() -> int:
    texts = [(THESIS / c).read_text(encoding="utf-8") for c in CHAPTERS]
    parts = [(_join_groups(b), e) for b, e in (split(t) for t in texts)]
    local = [{n: e for n, e in entries} for _, entries in parts]
    gkey = {}  # (chapter, local) -> canonical key
    canon = {}  # key -> entry text (first, i.e. the most complete chapter-1 form)
    for ci, entries in enumerate(parts):
        for n, e in entries[1]:
            k = key(e)
            gkey[(ci, n)] = k
            canon.setdefault(k, e)
    # merge the TEXT_ALIASES pairs; each pattern must hit exactly one entry
    raw = {(ci, n): e for ci, (_, ent) in enumerate(parts) for n, e in ent}
    for dup, orig in TEXT_ALIASES:
        hits = {name: _find(raw, pat) for name, pat in (("dup", dup), ("orig", orig))}
        if len(hits["dup"]) != 1 or len(hits["orig"]) != 1:
            raise SystemExit(f"TEXT_ALIASES {dup[:40]!r}: {hits}")
        d, o = hits["dup"][0], hits["orig"][0]
        kd, ko = gkey[d], gkey[o]
        for cn, k in gkey.items():
            if k == kd:
                gkey[cn] = ko
        longer = max(canon[ko], canon[kd], key=len)
        canon[ko] = longer
    order: list[str] = []

    def keys_of(ci: int, n: int) -> list[str]:
        if (ci, n) in ALIASES:
            return [gkey[a] for a in ALIASES[(ci, n)]]
        if (ci, n) not in gkey:
            raise SystemExit(f"{CHAPTERS[ci]}: citation [{n}] has no entry")
        return [gkey[(ci, n)]]

    for ci, (body, _) in enumerate(parts):
        for m in cites(body):
            src = _src(body, m, ci)
            for n in expand(m.group(1)):
                for k in keys_of(src, n):
                    if k not in order:
                        order.append(k)
    uncited = [k for ci, (_, ent) in enumerate(parts) for n, _ in ent
               for k in keys_of(ci, n) if k not in order]
    for k in uncited:
        if k not in order:
            order.append(k)
    num = {k: i + 1 for i, k in enumerate(order)}

    for ci, (body, _) in enumerate(parts):
        out, pos = [], 0
        for m in cites(body):
            src = _src(body, m, ci)
            nums = [num[k] for n in expand(m.group(1)) for k in keys_of(src, n)]
            out += [body[pos:m.start()], f"[{compress(nums)}{m.group(2)}]"]
            x = XREF.match(body, m.end())
            pos = x.end() if x else m.end()
        new_body = ("".join(out) + body[pos:]).rstrip() + "\n"
        (THESIS / CHAPTERS[ci]).write_text(new_body, encoding="utf-8", newline="\n")

    lines = ["# Список использованных источников", "",
             "Общий для всех глав, нумерация — в порядке первого упоминания (гл. 1 → гл. 4). "
             "Оформление — по ГОСТ Р 7.0.100-2018; дата обращения ко всем электронным ресурсам — "
             f"{ACCESS}, если не указана другая. Проверка ссылок: `python docs/thesis/tools/refs.py check`.", ""]
    lines += [f"{num[k]}. {gost(canon[k])}" for k in order]
    REFS.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    total = sum(len(e) for _, e in parts)
    print(f"{total} chapter entries -> {len(order)} references ({total - len(order)} merged); "
          f"uncited: {len(set(uncited))}")
    for k in dict.fromkeys(uncited):
        print("  uncited:", num[k], canon[k][:90])
    return 0


def renumber() -> int:
    """After edits: renumber references.md and all citations in order of first mention."""
    lines = REFS.read_text(encoding="utf-8").splitlines()
    head = [ln for ln in lines if not ENTRY.match(ln)]
    entries = {int(m.group(1)): m.group(2) for m in map(ENTRY.match, lines) if m}
    bodies = [(THESIS / c).read_text(encoding="utf-8") for c in CHAPTERS]
    order: list[int] = []
    for body in bodies:
        for m in cites(body):
            for n in expand(m.group(1)):
                if n not in entries:
                    raise SystemExit(f"[{n}] is cited but not in references.md")
                if n not in order:
                    order.append(n)
    order += [n for n in entries if n not in order]
    new = {old: i + 1 for i, old in enumerate(order)}
    for c, body in zip(CHAPTERS, bodies):
        out, pos = [], 0
        for m in cites(body):
            out += [body[pos:m.start()], f"[{compress([new[n] for n in expand(m.group(1))])}{m.group(2)}]"]
            pos = m.end()
        (THESIS / c).write_text("".join(out) + body[pos:], encoding="utf-8", newline="\n")
    while head and not head[-1].strip():
        head.pop()
    REFS.write_text("\n".join(head + [""] + [f"{new[o]}. {entries[o]}" for o in order]) + "\n",
                    encoding="utf-8", newline="\n")
    moved = sum(1 for o in order if new[o] != o)
    print(f"{len(order)} references, {moved} renumbered")
    return 0


def check() -> int:
    entries = {int(m.group(1)) for m in map(ENTRY.match, REFS.read_text(encoding="utf-8").splitlines()) if m}
    cited: set[int] = set()
    bad = []
    for c in CHAPTERS:
        body = (THESIS / c).read_text(encoding="utf-8")
        for m in cites(body):
            for n in expand(m.group(1)):
                cited.add(n)
                if n not in entries:
                    bad.append(f"{c}: [{n}] not in references.md")
    for b in bad:
        print(b)
    unc = sorted(entries - cited)
    print(f"{len(entries)} references, {len(cited)} cited, uncited: {unc or 'none'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit({"merge": merge, "check": check, "renumber": renumber}[sys.argv[1] if len(sys.argv) > 1 else "check"]())
