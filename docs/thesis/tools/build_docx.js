// Build the thesis as a .docx laid out after GOST 7.32-2017 (backlog E7) from the markdown
// sources in docs/thesis. Figures: run render_figures.ps1 first (PNG in build/figures).
//   node docs/thesis/tools/build_docx.js  ->  docs/thesis/build/otabench-thesis.docx
//
// Layout: A4, margins left 30 / right 15 / top 20 / bottom 20 mm; Times New Roman 14 pt,
// 1.5 line spacing, first-line indent 1.25 cm, justified; chapters start on a new page;
// table captions above tables, figure captions below figures; page number bottom centre.
// Formulas ($...$, $$...$$) become simplified text and must be retyped in Word's
// equation editor; the build prints how many there are.
"use strict";
const fs = require("fs");
const path = require("path");
const docx = require("./node_modules/docx");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow,
  TableCell, WidthType, BorderStyle, ImageRun, PageBreak, Footer, PageNumber,
  TableOfContents, LevelFormat, convertMillimetersToTwip,
} = docx;

const THESIS = path.resolve(__dirname, "..");
const BUILD = path.join(THESIS, "build");
const FILES = ["intro.md", "ch1-analysis.md", "ch2-method.md", "ch3-implementation.md",
  "ch4-results.md", "conclusion.md", "references.md"];
const FONT = "Times New Roman";
const PT = (n) => n * 2; // half-points
const INDENT = convertMillimetersToTwip(12.5);
const LINE = 360; // 1.5 lines (240 = single)
const TEXT_WIDTH = convertMillimetersToTwip(210 - 30 - 15);
let formulas = 0;
let numInstance = 0;

// ---------------------------------------------------------------- inline markdown
const SUP = { 0: "⁰", 1: "¹", 2: "²", 3: "³", 4: "⁴", 5: "⁵", 6: "⁶", 7: "⁷", 8: "⁸", 9: "⁹",
  "+": "⁺", "-": "⁻", n: "ⁿ", i: "ⁱ", "*": "*" };
const sup = (x) => [...x].every((c) => c in SUP) ? [...x].map((c) => SUP[c]).join("") : "^" + x;

function latexToText(s) {
  formulas++;
  return s
    .replace(/\\dfrac\{([^{}]*)\}\{([^{}]*)\}/g, "($1)/($2)")
    .replace(/\\frac\{([^{}]*)\}\{([^{}]*)\}/g, "($1)/($2)")
    .replace(/\\sqrt\{([^{}]*)\}/g, "√($1)")
    .replace(/\\hat p/g, "p̂").replace(/\\hat\{p\}/g, "p̂")
    .replace(/\\pm/g, "±").replace(/\\le(q)?/g, "≤").replace(/\\ge(q)?/g, "≥")
    .replace(/\\in/g, "∈").replace(/\\cdot/g, "·").replace(/\\times/g, "×")
    .replace(/\\sum/g, "Σ").replace(/\\lfloor/g, "⌊").replace(/\\rfloor/g, "⌋")
    .replace(/\\mathrm\{([^{}]*)\}/g, "$1").replace(/\\text\{([^{}]*)\}/g, "$1")
    .replace(/\{,\}/g, ",").replace(/\\[;,!:]|\\ /g, " ").replace(/\\qquad|\\quad/g, "  ")
    .replace(/_\{([^{}]*)\}/g, "$1").replace(/\^\{([^{}]*)\}/g, (_, x) => sup(x))
    .replace(/\^([0-9*+\-n])/g, (_, x) => sup(x))
    .replace(/\\([a-zA-Z]+)/g, "$1").replace(/[{}]/g, "").replace(/\s+/g, " ").trim();
}

function runs(text, base = {}) {
  // **bold**, *italic*, `code`, $math$ ; links [t](u) -> t
  const out = [];
  text = text.replace(/\[([^\]]+)\]\((?!\.\.\/figures)[^)]+\)/g, "$1");
  const re = /(\*\*[^*]+\*\*|\*[^*\s][^*]*\*|`[^`]+`|\$[^$]+\$)/g;
  let pos = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > pos) out.push(new TextRun({ text: text.slice(pos, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(...runs(t.slice(2, -2), { ...base, bold: true }));
    else if (t.startsWith("`")) out.push(new TextRun({ ...base, text: t.slice(1, -1), font: "Courier New", size: PT(12) }));
    else if (t.startsWith("$")) out.push(new TextRun({ ...base, text: latexToText(t.slice(1, -1)), italics: true }));
    else out.push(...runs(t.slice(1, -1), { ...base, italics: true }));
    pos = m.index + t.length;
  }
  if (pos < text.length) out.push(new TextRun({ text: text.slice(pos), ...base }));
  return out;
}

const body = (text, opts = {}) => new Paragraph({
  children: runs(text), alignment: AlignmentType.JUSTIFIED,
  indent: { firstLine: INDENT }, spacing: { line: LINE, lineRule: "auto", after: 0 }, ...opts,
});

// ---------------------------------------------------------------- blocks
function table(lines) {
  const rows = lines.filter((l, i) => i !== 1).map((l) =>
    l.trim().replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|")));
  const n = Math.max(...rows.map((r) => r.length));
  const w = Math.floor(TEXT_WIDTH / n);
  const border = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
  const borders = { top: border, bottom: border, left: border, right: border };
  return new Table({
    width: { size: w * n, type: WidthType.DXA },
    columnWidths: Array(n).fill(w),
    rows: rows.map((r, ri) => new TableRow({
      tableHeader: ri === 0,
      children: Array.from({ length: n }, (_, ci) => new TableCell({
        width: { size: w, type: WidthType.DXA }, borders,
        margins: { top: 40, bottom: 40, left: 80, right: 80 },
        children: [new Paragraph({
          children: runs(r[ci] || "", { size: PT(12), bold: ri === 0 ? true : undefined }),
          spacing: { line: 240, lineRule: "auto", after: 0 },
          alignment: ri === 0 ? AlignmentType.CENTER : AlignmentType.LEFT,
        })],
      })),
    })),
  });
}

function image(alt, src) {
  const png = path.join(BUILD, "figures", path.basename(src).replace(/\.svg$/, ".png"));
  if (!fs.existsSync(png)) return body(`[рисунок: ${alt} — нет ${path.basename(png)}, запустите render_figures.ps1]`);
  const buf = fs.readFileSync(png);
  const wpx = buf.readUInt32BE(16), hpx = buf.readUInt32BE(20);
  const maxW = 600; // px at 96 dpi ≈ 159 mm
  const scale = Math.min(1, maxW / wpx);
  return new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60, line: 240, lineRule: "auto" },
    children: [new ImageRun({ type: "png", data: buf,
      transformation: { width: Math.round(wpx * scale), height: Math.round(hpx * scale) } })],
  });
}

function caption(text, kind) {
  // "*Таблица 4.1 — ...*" above the table (left), "*Рисунок 3.1 — ...*" below the figure (centre)
  const t = text.replace(/^\*|\*$/g, "").replace(/ — /, " – ");
  return new Paragraph({
    children: runs(t), spacing: { line: LINE, lineRule: "auto", before: kind === "table" ? 120 : 0, after: kind === "table" ? 60 : 120 },
    alignment: kind === "table" ? AlignmentType.LEFT : AlignmentType.CENTER,
    keepNext: kind === "table",
  });
}

function heading(level, text, structural) {
  const opts = {
    1: { heading: HeadingLevel.HEADING_1, alignment: AlignmentType.CENTER, pageBreakBefore: true, spacing: { after: 240, line: LINE, lineRule: "auto" } },
    2: { heading: HeadingLevel.HEADING_2, alignment: AlignmentType.LEFT, indent: { firstLine: INDENT }, spacing: { before: 240, after: 120, line: LINE, lineRule: "auto" } },
    3: { heading: HeadingLevel.HEADING_3, alignment: AlignmentType.LEFT, indent: { firstLine: INDENT }, spacing: { before: 180, after: 60, line: LINE, lineRule: "auto" } },
  }[Math.min(level, 3)];
  const t = structural ? text.toUpperCase() : text;
  return new Paragraph({ ...opts, keepNext: true,
    children: [new TextRun({ text: t, bold: true, font: FONT, size: PT(14), color: "000000" })] });
}

function convert(md, file) {
  const out = [];
  const lines = md.replace(/<!--[\s\S]*?-->/g, "").split(/\r?\n/);
  let i = 0;
  let para = [];
  const flush = () => { if (para.length) { out.push(body(para.join(" "))); para = []; } };
  let listOpen = false;
  while (i < lines.length) {
    const l = lines[i];
    let m;
    if (l.trim() && !/^\s*([*-]|\d+\.)\s+/.test(l)) listOpen = false;
    if (!l.trim()) { flush(); i++; continue; }
    if ((m = /^(#{1,6})\s+(.*)$/.exec(l))) {
      flush();
      const lvl = m[1].length;
      let text = m[2].trim();
      const structural = lvl === 1 && /^(Введение|Заключение|Список)/i.test(text);
      if (file === "references.md" && lvl === 1) text = "Список использованных источников";
      out.push(heading(lvl, text, structural || file === "references.md"));
      i++; continue;
    }
    if (l.startsWith("```")) {
      flush(); i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        out.push(new Paragraph({ spacing: { line: 240, lineRule: "auto", after: 0 },
          children: [new TextRun({ text: lines[i] || " ", font: "Courier New", size: PT(9) })] }));
        i++;
      }
      i++; continue;
    }
    if (l.trim().startsWith("$$")) {
      flush();
      let f = l.trim();
      while (!(f.length > 2 && f.endsWith("$$")) && i + 1 < lines.length) { i++; f += " " + lines[i].trim(); }
      out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120, line: LINE, lineRule: "auto" },
        children: [new TextRun({ text: latexToText(f.replace(/^\$\$|\$\$$/g, "")), italics: true })] }));
      i++; continue;
    }
    if ((m = /^!\[([^\]]*)\]\(([^)]+)\)/.exec(l.trim()))) { flush(); out.push(image(m[1], m[2])); i++; continue; }
    if (/^\*(Рисунок|Рис\.)\s/.test(l.trim())) { flush(); out.push(caption(l.trim(), "figure")); i++; continue; }
    if (/^\*Таблица\s/.test(l.trim())) { flush(); out.push(caption(l.trim(), "table")); i++; continue; }
    if (l.trim().startsWith("|")) {
      flush();
      const tl = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) { tl.push(lines[i]); i++; }
      out.push(table(tl));
      out.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
      continue;
    }
    if ((m = /^(\s*)([*-]|\d+\.)\s+(.*)$/.exec(l))) {
      flush();
      const numbered = /\d+\./.test(m[2]);
      if (numbered && !listOpen && !m[1].length) { numInstance++; listOpen = true; }
      let text = m[3];
      i++;
      while (i < lines.length && lines[i].trim() && /^\s{2,}\S/.test(lines[i]) && !/^\s*([*-]|\d+\.)\s/.test(lines[i])) {
        text += " " + lines[i].trim(); i++;
      }
      if (file === "references.md" && numbered) {
        out.push(new Paragraph({ children: runs(`${m[2]} ${text}`), alignment: AlignmentType.JUSTIFIED,
          indent: { firstLine: INDENT }, spacing: { line: LINE, lineRule: "auto", after: 0 } }));
      } else {
        out.push(new Paragraph({ children: runs(text), alignment: AlignmentType.JUSTIFIED,
          numbering: numbered ? { reference: "num", level: m[1].length >= 2 ? 1 : 0, instance: numInstance }
                              : { reference: "bullet", level: m[1].length >= 2 ? 1 : 0 },
          spacing: { line: LINE, lineRule: "auto", after: 0 } }));
      }
      continue;
    }
    para.push(l.trim());
    i++;
  }
  flush();
  return out;
}

// ---------------------------------------------------------------- document
const children = [];
for (const f of FILES) {
  const p = path.join(THESIS, f);
  if (!fs.existsSync(p)) { console.log(`skip ${f} (missing)`); continue; }
  children.push(...convert(fs.readFileSync(p, "utf8"), f));
}

const titlePage = [
  ...Array(8).fill(0).map(() => new Paragraph({ children: [] })),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { line: LINE, lineRule: "auto" },
    children: [new TextRun({ text: "ИСПОЛНЯЕМЫЙ КРОСС-ЭКОСИСТЕМНЫЙ БЕНЧМАРК БЕЗОПАСНОСТИ И ОТКАЗОУСТОЙЧИВОСТИ СИСТЕМ ОБНОВЛЕНИЯ ПРОГРАММНОГО ОБЕСПЕЧЕНИЯ", bold: true })] }),
  new Paragraph({ children: [] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "Выпускная квалификационная работа магистра (черновик)" })] }),
  ...Array(6).fill(0).map(() => new Paragraph({ children: [] })),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "[Титульный лист оформляется по шаблону вуза]", italics: true })] }),
];
const toc = [
  new Paragraph({ alignment: AlignmentType.CENTER, pageBreakBefore: true, spacing: { after: 240 },
    children: [new TextRun({ text: "СОДЕРЖАНИЕ", bold: true })] }),
  new TableOfContents("Содержание", { hyperlink: true, headingStyleRange: "1-3" }),
  new Paragraph({ children: [new TextRun({ text: "(Обновите поле содержания в Word: F9.)", italics: true, size: PT(12) })] }),
];

const page = { size: { width: convertMillimetersToTwip(210), height: convertMillimetersToTwip(297) },
  margin: { top: convertMillimetersToTwip(20), bottom: convertMillimetersToTwip(20),
            left: convertMillimetersToTwip(30), right: convertMillimetersToTwip(15) } };
const doc = new Document({
  creator: "IWillBurn", title: "otabench — ВКР (черновик)",
  styles: {
    default: { document: { run: { font: FONT, size: PT(14) }, paragraph: { spacing: { line: LINE, lineRule: "auto" } } } },
    paragraphStyles: [1, 2, 3].map((n) => ({ id: `Heading${n}`, name: `Heading ${n}`, basedOn: "Normal", next: "Normal",
      quickFormat: true, run: { font: FONT, size: PT(14), bold: true, color: "000000" },
      paragraph: { outlineLevel: n - 1 } })),
  },
  numbering: { config: [
    { reference: "bullet", levels: [
      { level: 0, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: convertMillimetersToTwip(17.5), hanging: convertMillimetersToTwip(5) } } } },
      { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: convertMillimetersToTwip(25), hanging: convertMillimetersToTwip(5) } } } } ] },
    { reference: "num", levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: "%1)", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: convertMillimetersToTwip(19), hanging: convertMillimetersToTwip(6.5) } } } },
      { level: 1, format: LevelFormat.DECIMAL, text: "%2)", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: convertMillimetersToTwip(26), hanging: convertMillimetersToTwip(6.5) } } } } ] },
  ] },
  features: { updateFields: true },
  sections: [
    { properties: { page }, children: titlePage },
    { properties: { page }, footers: { default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT] })] })] }) },
      children: [...toc, ...children] },
  ],
});

fs.mkdirSync(BUILD, { recursive: true });
Packer.toBuffer(doc).then((buf) => {
  const out = path.join(BUILD, "otabench-thesis.docx");
  fs.writeFileSync(out, buf);
  console.log(`${out}: ${(buf.length / 1024).toFixed(0)} KiB, ${children.length} blocks, ${formulas} formulas to retype`);
});
