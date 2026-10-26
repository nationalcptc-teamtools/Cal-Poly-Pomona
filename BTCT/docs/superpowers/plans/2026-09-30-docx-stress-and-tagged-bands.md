# Stress corpus and tagged header/footer lifting: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Six reproducible stress reports scored through Word with three new measurements, and a converter that lifts the running header and footer from typst's own `Header`/`Footer` artifacts when the PDF is tagged.

**Architecture:** A committed generator (`stress.py`) builds the stress documents into `.scratch/`; `scorecard.py --stress` scores them and reports `blankPages`, `bandInBody`, `inkPastMargin`. In `convert.py` a pure content-stream tool (`tagged.py`) removes Header/Footer artifact blocks; `detect_band` gains a tagged path built on the before/after text diff, the tagged band is stripped by removing its blocks instead of erasing a rectangle, `detect_toc` is gated on the tag tree, and a page-break check runs after conversion. Untagged PDFs keep today's code paths byte for byte.

**Tech Stack:** Python 3.13 venv (`.venv-pdf2docx`: pymupdf 1.28.2, pdf2docx 0.5.13, python-docx 1.2.0, numpy), typst 0.14.2, Word 16 via `render_word.ps1`.

**Spec:** [docs/superpowers/specs/2026-09-30-docx-stress-and-tagged-bands-design.md](../specs/2026-09-30-docx-stress-and-tagged-bands-design.md)

## Global Constraints

- Every line of the PDF's text stays in the Word file; the fallback ladder, font naming and carrying, unsafe-link removal, the redaction path, the one-compile rule and every limit in `export.mjs` are unchanged.
- Untagged PDFs keep today's behaviour exactly: every existing check in `test_convert.py` passes unchanged.
- Stress content is neutral filler only: generic finding titles, placeholder prose, harmless commands (`echo`, `ls`), synthetic images drawn by the generator. No realistic attack steps, payloads or exploit walkthroughs.
- The owner's CPTC template, report, image and fonts are never committed; stress outputs are never committed (they live under `.scratch/`).
- Scorecard rule unchanged; the three new measurements are reported numbers, not rules.
- The reference report keeps mean >= 0.9146.
- No em dashes (U+2014) anywhere written; check with the Grep tool (the Bash tool mangles escapes). Write multi-line code with the Write/Edit tools, not shell heredocs.
- Commits: plain messages, explicit paths only, never `docker-compose.yml`, never any Claude/AI attribution.
- Python runs as `.venv-pdf2docx\Scripts\python.exe -I -B` from `server/typst/pdf-to-docx/`.

## Correction to the spec, decided while planning

The spec says stress redactions are "applied by baking the images before compile, as the server does". The server's bake is JavaScript (`server/typst/bake.mjs` with `src/lib/blur-math.ts`), which the Python scorecard cannot call without a second runtime. The generator instead draws the redacted regions already pixelated into the PNG it writes (block-averaged, 12 px cells). The server's redaction path keeps its own tests; the stress set measures layout, which is what it is for.

## Review Focus

1. A tagged PDF whose Header artifact is empty on some pages (a cover with no header): the tagged path must still lift the band on the pages that have it and leave the cover alone. Pinned in Task 4 (`cases.TAGGED_SKIP_PAGES`).
2. Body text identical to header text (a heading that repeats the report title): only the artifact copy is lifted; the body copy stays. Pinned in Task 4 (`cases.TAGGED_TITLE_IN_BODY`).
3. A content stream where a literal string contains the bytes `EMC` or `BDC`, or a nested `BDC` inside the artifact: the remover must not cut in the wrong place. Pinned in Task 3 unit tests.
4. A PDF with `MarkInfo /Marked true` but no Header/Footer artifacts at all: the heuristic runs, as today. Pinned in Task 4 (untagged-equivalent check).
5. A 120-page stress document hitting the 120 s conversion budget: the result must be an honest timeout or a crowded-out warning, never a partial file reported as ok. Pinned in Task 2 (the scorecard records `error` rows and times) and observed in Task 7.

---

## File map

| File | Status | Responsibility |
|---|---|---|
| `server/typst/pdf-to-docx/stress.py` | create | generate the six stress documents |
| `server/typst/pdf-to-docx/tagged.py` | create | pure content-stream artifact remover and tag-tree reader |
| `server/typst/pdf-to-docx/test_tagged.py` | create | unit tests for `tagged.py` |
| `server/typst/pdf-to-docx/scorecard.py` | modify | `--stress`, `--cptc-template`, measurements |
| `server/typst/pdf-to-docx/scorecard_rules.py` | modify | measurement helpers (pure) |
| `server/typst/pdf-to-docx/test_scorecard_rules.py` | modify | tests for the helpers |
| `server/typst/pdf-to-docx/convert.py` | modify | tagged band path, tagged strip, TOC gate, page-break check |
| `server/typst/pdf-to-docx/cases.py`, `test_convert.py` | modify | new cases and checks |
| `server/typst/pdf-to-docx/corpus/SCORECARD.md` | modify | before and after stress runs |
| `README.md`, `CLAUDE.md`, `docs/typst-tab-2026-09.md` | modify | docs |

`$PY` below means `..\..\..\.venv-pdf2docx\Scripts\python.exe -I -B`, run from `server\typst\pdf-to-docx`. The owner's CPTC template folder is `C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report` (holds `main.typ`, `fonts\`, `assets\cover.png`); the reference report PDF is `.scratch\reference\reference.pdf` with fonts in that folder's `fonts\`.

---

### Task 1: The stress generator

**Files:**
- Create: `server/typst/pdf-to-docx/stress.py`

**Interfaces:**
- Produces: `stress.DOCUMENTS` (ordered dict name -> {"template": "cptc"|"findings"|"thesis"|"assessment", "findings": int}), `stress.build(name, out_root, cptc_template=None) -> str` (returns the document folder holding `main.typ`, `assets/`, and for CPTC `fonts/`; raises `ValueError` for a CPTC document when `cptc_template` is None), `stress.build_all(out_root, cptc_template=None) -> list[tuple[name, folder]]` (skips CPTC documents without a template), CLI `stress.py <out_root> [--cptc-template DIR]`.

The generator reuses the neutral generator already written at `.scratch/mock/generate.py` (read it first): its `image()`, `prose()`, `para()`, `s()` helpers and its CPTC fill logic (`once()` replacements, report card, narrative, finding blocks) move into `stress.py`, parameterised by finding count. Keep content neutral exactly as there.

- [ ] **Step 1: Write `stress.py`**

Structure (write it with the Write tool):

```python
"""Reproducible stress documents for the Word export, all neutral filler.

    <venv>/python -I -B stress.py <out_root> [--cptc-template DIR]

Builds each document into <out_root>/<name>/ (main.typ, assets/, fonts/ for
CPTC). The CPTC template belongs to the owner and is read from its folder,
never copied into the repo. Redacted regions are drawn already pixelated
into the PNGs (see the plan's correction note).
"""
import os, random, shutil, sys
import numpy as np
import pymupdf

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")

DOCUMENTS = {
    "stress-cptc-57": {"template": "cptc", "findings": 19},
    "stress-cptc-short": {"template": "cptc", "findings": 3},
    "stress-cptc-long": {"template": "cptc", "findings": 45},
    "stress-findings": {"template": "findings", "findings": 25},
    "stress-thesis": {"template": "thesis", "findings": 8},        # "findings" = chapters' sections
    "stress-assessment": {"template": "assessment", "findings": 6},  # = landscape sections
}
```

Then:
- `image(path, title, redact=False, width=960, height=540, rng)`: as in `.scratch/mock/generate.py`, and when `redact` is true, block-average two regions of the rendered pixmap before saving: convert `pix.samples` to a numpy array `(h, w, n)`, for each region `(0.03,0.2,0.4,0.12)` and `(0.03,0.5,0.3,0.1)` (fractions of width/height) replace each 12x12 cell by its mean, then `pymupdf.Pixmap(pymupdf.csRGB, w, h, bytes(arr), 0).save(path)`.
- `build_cptc(name, folder, template_dir, findings, rng)`: exactly the mock generator's fill with `LEVELS` counts derived from `findings` (split roughly 15% critical, 25% high, 30% medium, the rest low, at least 1 each), `finding-counts` set from those counts, every `{{\#\#}}` occurrence in the template replaced (loop `while "{{\\#\\#}}" in src`, first three with "19"-style values derived from the counts, the rest with the host count "96"), topology and narrative images; copy `template_dir/fonts/*` into `folder/fonts/` and `template_dir/assets/cover.png` into `folder/assets/`. `stress-cptc-57` must use `findings=19` and seed 7 so it reproduces the document the owner tested.
- `build_findings(folder, n, rng)`: read `corpus/findings/main.typ`, keep everything before the line `= Summary of findings` as the preamble, then append a summary table of `n` rows and `n` `#finding(...)` calls using that template's own `finding(id, title, severity, cvss, body)` signature, each body two paragraphs, a ```` ```text ```` block with `echo`/`ls` lines, one `#figure(image("assets/f-<i>.png", width: 80%), caption: [...])`, and a `#table` of 2 to 4 host rows. Severities cycle Critical, High, Medium, Low. Every third image redacted.
- `build_thesis(folder, n, rng)`: read `corpus/thesis/main.typ` and `refs.bib`; keep the preamble up to and including `#counter(heading).update(2)`; append `n` level-1 sections each with three level-2 subsections containing two paragraphs, one numbered equation (`$ x_i = sum_(j=1)^n a_(i j) y_j $`), one footnote, one citation of a key from `refs.bib` (`@miller1990` etc.), a figure with a generated image, and every second section a 3-column table figure; end with `#bibliography("refs.bib")`. Copy `refs.bib`.
- `build_assessment(folder, n, rng)`: read `corpus/assessment/main.typ`, keep the preamble before `= Scope`; append `n` blocks of: a portrait section with two paragraphs, a `#page(flipped: true)[...]` section holding a coloured 6-column matrix like the template's, then a 60-row host table with `table.header(repeat: true, ...)`.
- `build(name, out_root, cptc_template=None)` and `build_all(...)`: create `out_root/name/` fresh (remove if present), seed `random.Random` from a fixed per-name seed (`7` for `stress-cptc-57`, otherwise `sum(map(ord, name))`), dispatch, return the folder.
- `main(argv)`: parse `<out_root>` and optional `--cptc-template DIR`, call `build_all`, print `name: folder` per document.

- [ ] **Step 2: Build and compile every document**

```powershell
$PY stress.py ..\..\..\.scratch\stress-build --cptc-template C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report
foreach ($d in Get-ChildItem ..\..\..\.scratch\stress-build -Directory) {
  $fonts = @("--font-path", "corpus\fonts", "--font-path", "..\..\..\dist\fonts")
  if (Test-Path "$($d.FullName)\fonts") { $fonts += @("--font-path", "$($d.FullName)\fonts") }
  typst compile --root $d.FullName --ignore-system-fonts -j 1 @fonts "$($d.FullName)\main.typ" "$($d.FullName)\check.pdf"
  "{0}: exit {1}" -f $d.Name, $LASTEXITCODE
}
```

Expected: six `exit 0` lines and no warnings except the ones the corpus templates already print. Then count pages with pymupdf and confirm the targets within about 25%: cptc-57 = 57, cptc-short about 10, cptc-long about 120, findings about 40, thesis about 50, assessment about 30. Adjust the per-template counts in `DOCUMENTS` (and only them) until they land in range; `stress-cptc-57` must stay at 57 pages.

- [ ] **Step 3: Check the content rule and commit**

Grep the six generated `main.typ` files for `"@preview/`, `"@local/`, and confirm none contains anything but filler (spot-read one finding per document). Commit only `stress.py`:

```bash
git add server/typst/pdf-to-docx/stress.py
git commit -m "Add a generator for six stress reports of different lengths and templates"
```

---

### Task 2: Stress scoring and the three measurements, then the baseline

**Files:**
- Modify: `server/typst/pdf-to-docx/scorecard_rules.py`, `test_scorecard_rules.py`, `scorecard.py`, `corpus/SCORECARD.md`

**Interfaces:**
- Consumes: `stress.build_all(out_root, cptc_template)`.
- Produces: `scorecard_rules.blank_pages(ink_boxes, page_height, edge_fraction=0.12) -> int`, `scorecard_rules.ink_past_margin(ink_right_edges, content_right, slack=2.0) -> int`, `scorecard_rules.band_in_body(band_texts, body_text) -> bool`; row fields `blankPages`, `bandInBody`, `inkPastMargin`, `wordSeconds`; CLI `scorecard.py --stress [--cptc-template DIR]`.

- [ ] **Step 1: Failing tests for the helpers**

Add to `test_scorecard_rules.py` `main()` before the return:

```python
    # blank_pages: a page whose ink sits only in the top or bottom 12% counts.
    passed &= expect_true(rules.blank_pages([[(10, 740, 200, 760)], [(10, 100, 500, 600)]], 792) == 1,
                          "blank_pages counts a footer-only page")
    passed &= expect_true(rules.blank_pages([[]], 792) == 1, "blank_pages counts an empty page")
    passed &= expect_true(rules.ink_past_margin([530.0, 560.5, 559.0], 557.0) == 1,
                          "ink_past_margin counts pages beyond the edge plus 2 pt")
    passed &= expect_true(rules.band_in_body(["ACME Security Assessment"], "intro ACME Security Assessment body"),
                          "band_in_body finds header text in the body")
    passed &= expect_true(not rules.band_in_body(["ACME Security Assessment"], "intro body"),
                          "band_in_body is false when absent")
    passed &= expect_true(not rules.band_in_body(["12"], "page 12 of the body"),
                          "band_in_body ignores band pieces shorter than 4 squashed characters")
```

with a helper `def expect_true(ok, label): print("%-5s %s" % ("ok" if ok else "FAIL", label)); return ok`. Run `$PY test_scorecard_rules.py`; expect an `AttributeError`.

- [ ] **Step 2: Implement the helpers in `scorecard_rules.py`**

```python
import re

def blank_pages(ink_boxes, page_height, edge_fraction=0.12):
    """Pages whose ink lies only in the top or bottom edge_fraction of the page."""
    top, bottom = page_height * edge_fraction, page_height * (1 - edge_fraction)
    return sum(1 for boxes in ink_boxes if all(y1 <= top or y0 >= bottom for (_x0, y0, _x1, y1) in boxes))

def ink_past_margin(ink_right_edges, content_right, slack=2.0):
    """Pages whose rightmost ink passes the PDF's right content edge by more than slack points."""
    return sum(1 for right in ink_right_edges if right > content_right + slack)

def _squash(text):
    return re.sub(r"\s+", "", text).casefold()

def band_in_body(band_texts, body_text):
    """Whether any running-band text (4+ squashed characters) appears in the body text."""
    body = _squash(body_text)
    return any(len(_squash(t)) >= 4 and _squash(t) in body for t in band_texts)
```

Run the tests; expect all `ok`.

- [ ] **Step 3: Wire `--stress` and the measurements into `scorecard.py`**

- `parse()`: accept `--stress` (flag) and `--cptc-template DIR`.
- `main()`: when `--stress`, build with `stress.build_all(os.path.join(out_dir, "stress-src"), opts["cptc_template"])` and add a job per document `(name, "stress", folder, fonts, False)` where fonts are `corpus.font_dirs()` plus `folder/fonts` when present; compile each with the same typst arguments `corpus.compile_document` uses but `--root folder` (write a small `compile_folder(folder, pdf, extra_fonts)` in scorecard.py that mirrors `corpus.compile_document`). `--stress` jobs run instead of the corpus unless `--only` also names corpus documents.
- In `side()`: after `render()`, time the render (`wordSeconds`) and open the rendered PDF with pymupdf to compute, for the full side only: per page the ink boxes (`page.get_text("blocks")` boxes plus `page.get_image_info()` bboxes plus `page.get_drawings()` rects), `blankPages` via `rules.blank_pages`, and the rightmost ink per page for `inkPastMargin` via `rules.ink_past_margin(rights, content_right)` where `content_right` comes from `convert.content_bounds(pymupdf.open(pdf))[1]` (import convert).
- `bandInBody`: the band texts are read from the SOURCE PDF with `tagged.band_texts(pdf)` once Task 3 exists; until then (this task's baseline) use the text of the top and bottom 8% of every source-PDF page from page 2 on, deduplicated (a stand-in, recorded as such in SCORECARD.md). The body text is `convert.docx_text(docx, body_only=True)`.
- `table()`: add columns `blank`, `band in body`, `past margin`, `word s`.

- [ ] **Step 4: Run the before baseline**

Run in the background with output to a file (15 to 60 minutes; the long CPTC document is slow):

```powershell
$PY scorecard.py --stress --cptc-template C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report --out ..\..\..\.scratch\stress-before > ..\..\..\.scratch\stress-before.log 2>&1
```

Expected: six rows. The rule verdicts may fail (they are the input to Task 4); an `error` row is recorded as such (for example a timeout on `stress-cptc-long`). Append the table to `corpus/SCORECARD.md` under `## 2026-09-30: stress set, before tagged bands`, noting the `bandInBody` stand-in.

- [ ] **Step 5: Commit**

```bash
git add server/typst/pdf-to-docx/scorecard.py server/typst/pdf-to-docx/scorecard_rules.py server/typst/pdf-to-docx/test_scorecard_rules.py server/typst/pdf-to-docx/corpus/SCORECARD.md
git commit -m "Score the stress set with blank pages, band in body and ink past the margin"
```

---

### Task 3: The artifact remover and tag-tree reader

**Files:**
- Create: `server/typst/pdf-to-docx/tagged.py`, `server/typst/pdf-to-docx/test_tagged.py`

**Interfaces:**
- Produces: `tagged.tokenize(raw: bytes) -> list[tuple[int, int, str, bytes]]` (start, end, kind in {"op","name","num","str","hex","dict","array","other"}, token bytes); `tagged.remove_artifacts(raw: bytes, subtypes=("Header","Footer")) -> tuple[bytes, int] | None` (stream without those blocks and the number removed; `None` when a removed block is unbalanced in `q/Q` or `BT/ET`); `tagged.is_tagged(doc) -> bool` (catalog `MarkInfo` has `/Marked true` and a `StructTreeRoot`); `tagged.struct_types(doc) -> set[str]` (e.g. `{"/TOC", "/H1"}`); `tagged.stripped_copy(doc) -> tuple[pymupdf.Document, dict[int, int]] | None` (a copy with every page's Header/Footer artifacts removed, and removed-block counts per page index; `None` if any page fails); `tagged.band_texts(pdf_path) -> list[str]` (texts of rows that disappear when artifacts are removed, deduplicated).

- [ ] **Step 1: Failing unit tests**

`test_tagged.py` (check-style like `test_convert.py`):

```python
#!/usr/bin/env python3
"""Checks for tagged.py. Run: <venv>/python -I -B test_tagged.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged  # noqa: E402

def check(ok, label, detail=""):
    print("%-5s %s%s" % ("ok" if ok else "FAIL", label, (" -- " + str(detail)) if detail else ""))
    return bool(ok)

HEAD = b"/Artifact <</Type /Pagination /Subtype /Header>> BDC q BT /F1 9 Tf 50 780 Td (Report title) Tj ET Q EMC"
FOOT = b"/Artifact <</Type /Pagination /Subtype /Footer>> BDC BT /F1 9 Tf 50 20 Td (Page 3) Tj ET EMC"
BODY = b"/P <</MCID 0>> BDC BT /F1 11 Tf 50 700 Td (Body EMC BDC text) Tj ET EMC"

def main():
    passed = True
    out, n = tagged.remove_artifacts(HEAD + b"\n" + BODY + b"\n" + FOOT)
    passed &= check(n == 2, "both artifacts removed", n)
    passed &= check(b"Report title" not in out and b"Page 3" not in out, "their text is gone")
    passed &= check(b"(Body EMC BDC text) Tj" in out, "operator names inside a string do not cut the body")
    nested = b"/Artifact <</Subtype /Header>> BDC /Span <</MCID 1>> BDC BT (x) Tj ET EMC EMC " + BODY
    out, n = tagged.remove_artifacts(nested)
    passed &= check(n == 1 and out.strip().startswith(b"/P"), "a nested BDC inside the artifact is removed with it", out[:40])
    bg = b"/Artifact <</Type /Pagination /Subtype /Background>> BDC 0 0 m 10 10 l S EMC " + BODY
    out, n = tagged.remove_artifacts(bg)
    passed &= check(n == 0 and out == bg, "a Background artifact is kept")
    unbalanced = b"/Artifact <</Subtype /Header>> BDC q BT (x) Tj ET EMC Q " + BODY
    passed &= check(tagged.remove_artifacts(unbalanced) is None, "an artifact that opens q without closing it refuses")
    esc = b"/Artifact <</Subtype /Footer>> BDC BT (a \\) EMC ( nested ) b) Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(esc)
    passed &= check(n == 1 and b"(Body EMC BDC text)" in out, "escaped and nested parentheses in a string")
    hexs = b"/Artifact <</Subtype /Header>> BDC BT <454D43> Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(hexs)
    passed &= check(n == 1 and b"<454D43>" not in out, "a hex string inside the artifact goes with it")
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
```

Also add a document check at the end of `main()`, guarded by `shutil.which("typst")`: compile `cases.TAGGED_SKIP_PAGES` (defined in Task 4; skip this sub-check until then by testing `hasattr(cases, "TAGGED_SKIP_PAGES")`), and assert `tagged.is_tagged`, `"/H1" in tagged.struct_types(doc)`, and that `stripped_copy` removes at least one block on page 2.

Run `$PY test_tagged.py`; expect `ModuleNotFoundError`.

- [ ] **Step 2: Implement `tagged.py`**

```python
"""Read what typst tagged in its PDF: the Header/Footer artifacts and the structure tree.

PyMuPDF cannot say which marked-content block a text span came from, so the
running band is found by removing the Header and Footer artifact blocks from
each page's content stream and diffing the page's text before and after.
"""
import re
import pymupdf

DELIMS = b"()<>[]{}/%"
WS = b" \t\r\n\f\x00"

def tokenize(raw):
    tokens, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i:i + 1]
        if raw[i] in WS:
            i += 1
            continue
        start = i
        if c == b"%":
            while i < n and raw[i] not in b"\r\n":
                i += 1
            continue
        if c == b"(":
            depth, i = 1, i + 1
            while i < n and depth:
                if raw[i] == 0x5C:  # backslash escape
                    i += 2
                    continue
                if raw[i] == 0x28:
                    depth += 1
                elif raw[i] == 0x29:
                    depth -= 1
                i += 1
            tokens.append((start, i, "str", raw[start:i]))
            continue
        if raw[i:i + 2] == b"<<":
            depth, i = 0, i
            while i < n:
                if raw[i:i + 2] == b"<<":
                    depth += 1; i += 2; continue
                if raw[i:i + 2] == b">>":
                    depth -= 1; i += 2
                    if depth == 0:
                        break
                    continue
                if raw[i] == 0x28:  # a string inside the dict
                    j = i + 1; d = 1
                    while j < n and d:
                        if raw[j] == 0x5C: j += 2; continue
                        d += raw[j] == 0x28; d -= raw[j] == 0x29; j += 1
                    i = j; continue
                i += 1
            tokens.append((start, i, "dict", raw[start:i]))
            continue
        if c == b"<":
            i = raw.index(b">", i) + 1
            tokens.append((start, i, "hex", raw[start:i]))
            continue
        if c in (b"[", b"]"):
            tokens.append((start, i + 1, "array", c)); i += 1
            continue
        if c == b"/":
            i += 1
            while i < n and raw[i] not in WS and raw[i] not in DELIMS:
                i += 1
            tokens.append((start, i, "name", raw[start:i]))
            continue
        while i < n and raw[i] not in WS and raw[i] not in DELIMS:
            i += 1
        if i == start:
            i += 1
        word = raw[start:i]
        kind = "num" if re.fullmatch(rb"[+-]?(\d+\.?\d*|\.\d+)", word) else "op"
        tokens.append((start, i, kind, word))
    return tokens
```

Then:

```python
def remove_artifacts(raw, subtypes=("Header", "Footer")):
    wanted = [b"/Subtype /" + s.encode() for s in subtypes] + [b"/Subtype/" + s.encode() for s in subtypes]
    toks = tokenize(raw)
    cuts, stack = [], []   # stack of (is_target, start_offset, q_depth, bt_depth) per open marked-content block
    q = bt = 0
    removed = 0
    for idx, (s, e, kind, word) in enumerate(toks):
        if kind != "op":
            continue
        if word in (b"BDC", b"BMC"):
            tag = toks[idx - 2][3] if word == b"BDC" and idx >= 2 else (toks[idx - 1][3] if idx >= 1 else b"")
            props = toks[idx - 1][3] if word == b"BDC" and idx >= 1 else b""
            target = tag == b"/Artifact" and any(w in props for w in wanted)
            begin = toks[idx - 2][0] if word == b"BDC" else toks[idx - 1][0]
            stack.append((target, begin, q, bt))
        elif word == b"EMC" and stack:
            target, begin, q0, bt0 = stack.pop()
            if target and not any(t for t, *_ in stack):
                if q != q0 or bt != bt0:
                    return None
                cuts.append((begin, e)); removed += 1
        elif word == b"q": q += 1
        elif word == b"Q": q -= 1
        elif word == b"BT": bt += 1
        elif word == b"ET": bt -= 1
    if not cuts:
        return raw, 0
    out, last = [], 0
    for s, e in cuts:
        out.append(raw[last:s]); last = e
    out.append(raw[last:])
    return b"".join(out), removed

def is_tagged(doc):
    cat = doc.pdf_catalog()
    mark = doc.xref_get_key(cat, "MarkInfo")[1]
    return "/Marked true" in mark and doc.xref_get_key(cat, "StructTreeRoot")[0] != "null"

def struct_types(doc):
    types = set()
    for x in range(1, doc.xref_length()):
        try:
            if doc.xref_get_key(x, "Type")[1] == "/StructElem":
                types.add(doc.xref_get_key(x, "S")[1])
        except Exception:  # noqa: BLE001 - a broken object is simply not a struct element
            continue
    return types

def stripped_copy(doc):
    copy = pymupdf.open("pdf", doc.tobytes())
    counts = {}
    for index in range(copy.page_count):
        page = copy[index]
        page.clean_contents()
        xrefs = page.get_contents()
        if not xrefs:
            counts[index] = 0
            continue
        raw = copy.xref_stream(xrefs[0])
        result = remove_artifacts(raw)
        if result is None:
            copy.close()
            return None
        out, n = result
        if n:
            copy.update_stream(xrefs[0], out)
        counts[index] = n
    return copy, counts

def band_texts(pdf_path):
    import convert  # local: convert imports tagged
    doc = pymupdf.open(pdf_path)
    try:
        made = stripped_copy(doc)
        if made is None:
            return []
        copy, _ = made
        seen = []
        for i in range(doc.page_count):
            after = {r["text"] for r in convert.page_rows(copy[i])}
            for r in convert.page_rows(doc[i]):
                if r["text"] not in after and r["text"] not in seen:
                    seen.append(r["text"])
        copy.close()
        return seen
    finally:
        doc.close()
```

(`page.clean_contents()` merges a page's content streams into one; confirm by reading PyMuPDF 1.28 behaviour, and if a page still has several streams, process each.)

- [ ] **Step 3: Run the tests**

`$PY test_tagged.py`: all `ok`. Also run the tagged probe on the reference PDF: `stripped_copy` must succeed and remove 2 blocks on each page that carries both header and footer.

- [ ] **Step 4: Switch the scorecard's `bandInBody` to `tagged.band_texts`** (replace the stand-in from Task 2) and commit:

```bash
git add server/typst/pdf-to-docx/tagged.py server/typst/pdf-to-docx/test_tagged.py server/typst/pdf-to-docx/scorecard.py
git commit -m "Read typst's Header and Footer artifacts out of the PDF's content streams"
```

---

### Task 4: The tagged band path in `detect_band`, and the tagged strip

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py` (`detect_band` at ~803, `strip_bands` at ~1209, `convert()` band loop at ~5316 and strip at ~5389), `cases.py`, `test_convert.py`

**Interfaces:**
- Consumes: `tagged.is_tagged`, `tagged.stripped_copy`, `page_rows`, `row_id`, `describe_columns`, `normalize`.
- Produces: `convert.detect_tagged_bands(doc, declined) -> tuple[list[dict], dict | None] | None` (the bands in the same dict shape `detect_band` returns, plus the stripped copy's per-page counts; `None` means "use the heuristic"); band dicts gain `"source": "tagged" | "heuristic"`; decline counters `bands-tagged`, `bands-heuristic`, `bands-tagged-inconsistent`.

- [ ] **Step 1: Cases**

Add to `cases.py`, in the file's comment style:

```python
# A tagged report whose header and footer skip the cover and one landscape
# page. The tagged path must lift the band on the pages that carry it and
# leave the cover and the landscape page with no band.
TAGGED_SKIP_PAGES = """
#set page(
  paper: "us-letter", margin: 1in,
  header: context { if counter(page).get().first() > 1 [Quarterly Status Report #h(1fr) Blue Harbor] },
  footer: context { if counter(page).get().first() > 1 [#align(center)[#counter(page).display()]] },
)
#set text(size: 11pt)
#align(center + horizon, text(24pt)[Quarterly Status Report])
#pagebreak()
= Overview
#lorem(400)
#pagebreak()
= Details
#lorem(400)
"""

# The report title is both the running header and the first heading of the
# body. Only the header copy may be lifted; the heading stays in the body.
TAGGED_TITLE_IN_BODY = """
#set page(paper: "a4", margin: 2cm, header: [Quarterly Status Report], footer: context [#counter(page).display()])
#set text(size: 11pt)
= Quarterly Status Report
#lorem(500)
"""
```

- [ ] **Step 2: Failing checks**

Add to `run_documents()` in `test_convert.py`:

```python
        result, path = run_case(cases.TAGGED_SKIP_PAGES, workdir, "tagged-skip")
        passed &= check(result["declined"].get("bands-tagged", 0) == 1, "tagged-skip: the band came from the tags", result["declined"])
        passed &= check(result["headerFooter"]["header"] and result["headerFooter"]["footer"], "tagged-skip: header and footer lifted", result["headerFooter"])
        passed &= check(result["textCheck"]["missing"] == 0 and not result["textCheck"]["fellBack"], "tagged-skip: nothing lost", result["textCheck"])
        body = convert.docx_text(path, body_only=True)
        passed &= check("Blue Harbor" not in body, "tagged-skip: header text is not in the body")

        result, path = run_case(cases.TAGGED_TITLE_IN_BODY, workdir, "tagged-title")
        body = convert.compare_squash(convert.docx_text(path, body_only=True))
        passed &= check(body.count(convert.compare_squash("Quarterly Status Report")) == 1, "tagged-title: the heading copy stays in the body")
        passed &= check(result["declined"].get("bands-tagged", 0) == 1, "tagged-title: tagged path used", result["declined"])

        # Every existing case: untagged-equivalent behaviour. cases.TABLE has
        # no header or footer at all, so the heuristic must still find none.
        result, path = run_case(cases.TABLE, workdir, "table-tagged")
        passed &= check(not result["headerFooter"]["header"] and not result["headerFooter"]["footer"], "table: tagged PDF with no band artifacts lifts nothing", result["headerFooter"])
```

Also a check that a PDF with its tags stripped (open the TAGGED_SKIP_PAGES PDF, `doc.set_markinfo({"Marked": False})` if available in pymupdf 1.28, else delete the catalog `MarkInfo` key with `doc.xref_set_key(doc.pdf_catalog(), "MarkInfo", "null")`, save) converts through the heuristic path (`bands-heuristic` counted) with the same `headerFooter` result as before this task.

Run `$PY test_convert.py`; the new checks fail.

- [ ] **Step 3: Implement `detect_tagged_bands`**

Read `detect_band` (~803 to ~960) end to end first; the tagged path must return dicts with every key it returns (`edge, pages, top, bottom, text_top, text_bottom, columns, rule_under, strip_behind, strip_full_width, strip_span, members`) plus `source`. Algorithm:

1. `if not tagged.is_tagged(doc): return None`. `made = tagged.stripped_copy(doc)`; `None` -> `declined["bands-tagged-inconsistent"] += 1; return None`. If no page removed any block, return `None` (count nothing: the document has no tagged bands).
2. For each page `i`: `before = page_rows(doc[i])`, `after_texts = Counter(r["text"] for r in page_rows(copy[i]))`; a row of `before` is a band member when its text's count in `before` exceeds its remaining count in `after_texts` (consume counts, so a body heading identical to the header keeps one copy: the member is the row with the smaller `y0` for the top edge and larger `y1` for the bottom edge).
3. Guard: on every page, every member row must lie wholly above the first non-member row (header) or wholly below the last non-member row (footer); classify each member as top or bottom by that. Any member in between -> `bands-tagged-inconsistent`, return `None`.
4. Per edge: `pages` = sorted page indexes with members on that edge; `top`/`bottom` = min `y0` / max `y1` over those members minus/plus `BAND_PAD_PT`; `text_top`/`text_bottom` = min `y0` / max `y1`; `members` = `{row_id(i, row) ...}`; `columns` from `describe_columns` fed the same grouping `detect_band` uses (groups of `(page, row)` tuples sharing `normalize(text)` and rounded `y0`), ordered by `x0`; `rule_under`, `strip_behind`, `strip_span` = `None`, `strip_full_width` = `False`; `source` = `"tagged"`.
5. Return `(bands, counts)`; count `bands-tagged`.

In `convert()`: before the heuristic loop, when `"bands" not in skip`, call `detect_tagged_bands(doc, declined)`; if it returns bands, use them and skip `detect_band` (and its "no repeating header" warnings); otherwise run the loop as today and count `bands-heuristic` when it found any band. Note `declined` is created before this point (check; move the band step below its creation if not, without changing behaviour).

- [ ] **Step 4: Tagged strip**

In `convert()` where `strip_bands(doc, bands)` runs: when the bands are tagged, build the stripped PDF from `tagged.stripped_copy(doc)[0]` instead (save it to `stripped_pdf` with the same `garbage=3, deflate=True`), and leave `strip_bands` for heuristic bands. The page-number field, `apply_bands` and the text check use the same band dicts as before.

- [ ] **Step 5: Run everything**

`$PY test_convert.py` exit 0 (every pre-existing check still `ok`); `$PY test_tagged.py` exit 0 (now including its document sub-check).

- [ ] **Step 6: Commit**

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/cases.py server/typst/pdf-to-docx/test_convert.py
git commit -m "Lift the running header and footer from typst's own artifacts when the PDF is tagged"
```

---

### Task 5: Contents page only where the tag tree has one

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py` (`detect_toc` call in `convert()`), `cases.py`, `test_convert.py`

**Interfaces:**
- Consumes: `tagged.is_tagged`, `tagged.struct_types`.
- Produces: decline counter `toc-untagged`.

- [ ] **Step 1: Case and failing check**

```python
# A tagged document with a dot-leader list that is not a table of contents
# (a price list). Without a TOC element in the tag tree nothing is rebuilt.
DOT_LEADERS_NOT_TOC = """
#set page(paper: "a4", margin: 2cm)
= Price list
#for (item, price) in (("Consulting day", "900"), ("Report review", "400"), ("Retest", "650")) [
  #item #box(width: 1fr, repeat[.]) #price \\
]
#lorem(200)
"""
```

Check: `result["tocEntries"] == 0` and `result["declined"].get("toc-untagged", 0) == 1`. And on the reference-style case that has a real `#outline` (use `cases.REPORT` if it has one; else add a small case with `#outline()` and three headings), the tagged PDF still rebuilds entries (`tocEntries > 0`). Run; the first check fails.

- [ ] **Step 2: Implement**

In `convert()`: `if "toc" in skip: entries = []` as today; `elif tagged.is_tagged(doc) and "/TOC" not in tagged.struct_types(doc): entries = []; declined["toc-untagged"] += 1` else `entries = detect_toc(doc, bands)`.

- [ ] **Step 3: Run `$PY test_convert.py` (exit 0) and commit**

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/cases.py server/typst/pdf-to-docx/test_convert.py
git commit -m "Rebuild a contents page only where the PDF's tag tree has one"
```

---

### Task 6: One Word page per PDF page

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py`, `test_convert.py`

**Interfaces:**
- Produces: `convert.ensure_page_starts(document, page_first_lines) -> int` (page breaks inserted); `page_first_lines` is a list, per PDF page from the second on, of the squashed text of that page's first body row (band members excluded); decline counter `page-start-unfound` for a page whose first line cannot be located.

- [ ] **Step 1: Failing check**

Unit-level: build a python-docx `Document()` with one section and five paragraphs `"alpha one"`, `"bravo two"`, `"charlie three"`, `"delta four"`, `"echo five"`; call `ensure_page_starts(doc, [compare_squash("charlie three"), compare_squash("echo five")])`; assert it returns 2 and that the XML of the "charlie three" and "echo five" paragraphs now starts with a run holding `<w:br w:type="page"/>`. A second call returns 0 (idempotent: a paragraph already starting a page or a section is left alone).

- [ ] **Step 2: Implement**

```python
def ensure_page_starts(document, page_first_lines, declined=None):
    """Put a page break before each PDF page's first line where Word would not start a page.

    pdf2docx writes one section per page, so this is usually a no-op; it
    matters where two pages were merged into one section.
    """
    paragraphs = body_paragraphs(document)
    cursor, inserted = 0, 0
    for wanted in page_first_lines:
        found = None
        for k in range(cursor, len(paragraphs)):
            if compare_squash(paragraph_text(paragraphs[k])).startswith(wanted[:40]):
                found = k
                break
        if found is None:
            if declined is not None:
                declined["page-start-unfound"] += 1
            continue
        cursor = found + 1
        p = paragraphs[found]
        prev = p.getprevious()
        starts_section = prev is not None and prev.find(qn("w:pPr") + "/" + qn("w:sectPr")) is not None
        first_run = p.find(qn("w:r"))
        has_break = first_run is not None and first_run.find(qn("w:br")) is not None and first_run.find(qn("w:br")).get(qn("w:type")) == "page"
        if starts_section or has_break or found == 0:
            continue
        run = p.makeelement(qn("w:r"), {})
        br = run.makeelement(qn("w:br"), {qn("w:type"): "page"})
        run.append(br)
        ppr = p.find(qn("w:pPr"))
        p.insert(0 if ppr is None else list(p).index(ppr) + 1, run)
        inserted += 1
    return inserted
```

(Confirm `qn` is imported in convert.py; it is used by `body_paragraphs`.)

- [ ] **Step 3: Wire it in**

In `convert()`, after `decorate_document` on every rung that writes the file (top rung, fallback, plain rung), compute `page_first_lines` once from the PDF (first row per page from index 1 on, excluding band members) and call `ensure_page_starts(document, page_first_lines, declined)` before `document.save(part)`. The text check afterwards is unchanged (a page break adds no text).

- [ ] **Step 4: Run `$PY test_convert.py` (exit 0) and commit**

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/test_convert.py
git commit -m "Start a Word page wherever the PDF starts one"
```

---

### Task 7: After run, corpus check, docs

**Files:**
- Modify: `corpus/SCORECARD.md`, `README.md`, `CLAUDE.md`, `docs/typst-tab-2026-09.md`

- [ ] **Step 1: Stress after run** (background, output to a file):

```powershell
$PY scorecard.py --stress --cptc-template C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report --out ..\..\..\.scratch\stress-after > ..\..\..\.scratch\stress-after.log 2>&1
```

Append under `## 2026-09-30: stress set, after tagged bands` with a before/after note per document (pages, mean, blankPages, bandInBody, inkPastMargin, time).

- [ ] **Step 2: Full corpus with the reference**

```powershell
$PY scorecard.py --out ..\..\..\.scratch\corpus-after --reference-pdf ..\..\..\.scratch\reference\reference.pdf --reference-fonts C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report\fonts
```

Expected exit 0 (named reasons as before) and the reference at or above 0.9146. Any new violation is a finding: report it; fix only if it is a defect in Tasks 3 to 6, in its own commit.

- [ ] **Step 3: Suites**

`$PY test_convert.py`, `$PY test_tagged.py`, `$PY test_scorecard_rules.py` all exit 0; from the repo root `bun run test` passes.

- [ ] **Step 4: Docs**

- README (the pdf-to-docx dev section): `stress.py`, `scorecard.py --stress --cptc-template`, the three measurements, `tagged.py`, the tagged band path and its guard, the TOC gate, `ensure_page_starts`, the new `declined` counters.
- CLAUDE.md invariant #18: one sentence: when the PDF is tagged, the running header and footer are exactly typst's `Header`/`Footer` artifacts (removed from the content stream, not erased by rectangle), with the heuristic kept for untagged PDFs; a contents page is rebuilt only where the tag tree has a TOC. Add the stress commands to the Commands paragraph on Word converter scoring.
- `docs/typst-tab-2026-09.md`: a part ten with the before and after stress numbers, first person, file's voice.
- Grep every edited file for U+2014: 0 (CLAUDE.md keeps its existing count of 7).

- [ ] **Step 5: Commit**

```bash
git add server/typst/pdf-to-docx/corpus/SCORECARD.md README.md CLAUDE.md docs/typst-tab-2026-09.md
git commit -m "Docs: the stress set, and header and footer from the PDF's own tags"
```
