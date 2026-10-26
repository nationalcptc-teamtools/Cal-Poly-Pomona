# The Word export for any Typst document: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Score the PDF-to-Word converter on a corpus of varied Typst documents, make sure no layout pass leaves any of them worse than plain pdf2docx, and fix right-to-left text losing its word spaces.

**Architecture:** Everything lives in `server/typst/pdf-to-docx/`. `convert.py` gains two dev-only switches (`--raw`, `--skip`) and a `declined` counter. A committed corpus of Typst documents is compiled and converted by `test_convert.py` (Word-free checks) and by a new `scorecard.py` (renders through Word, scores full against raw with `compare_pages.py`, applies the rule from `scorecard_rules.py`). Regressions the scorecard finds are fixed by detectors that make a pass decline a shape, one per commit.

**Tech Stack:** Python 3.13 (Windows dev box) in a virtualenv from `requirements.txt` (pdf2docx 0.5.13, pymupdf 1.28.2, python-docx 1.2.0, fonttools 4.65.0, numpy); typst CLI 0.14.2; Microsoft Word 16 through COM from PowerShell 5.1.

**Spec:** [docs/superpowers/specs/2026-09-29-docx-generality-design.md](../specs/2026-09-29-docx-generality-design.md)

## Global Constraints

- Every line of the PDF's text stays in the Word file; the fallback ladder, font naming and carrying, unsafe-link removal, the redaction path and every limit in `export.mjs` are unchanged.
- `export.mjs` never passes `--raw` or `--skip`; they are argv-only dev switches.
- Corpus material is MIT, MIT-0, Apache-2.0 or OFL only, with its licence beside it. Corpus under 3 MB including fonts.
- No corpus `.typ` file may contain the text `"@preview/` or `"@local/` anywhere, comments included: `server/typst/package-spec.mjs` refuses any source that mentions a package spec.
- Nothing in `corpus/` reaches the Docker image (`.dockerignore`).
- The rule (spec, section 2): (1) top rung or a named reason; (2) Word pages equal the PDF's, or no further than raw's; (3) per document, full mean SSIM ≥ raw mean SSIM − 0.002; (4) no page more than 0.02 below the same page in raw; (5) the reference report's mean ≥ 0.9146; (6) full time ≤ 2 × raw time + 2 s. Tolerances in 3 to 5 widen only if Task 6's measured Word noise exceeds 0.002.
- A regression is fixed by a detector that makes the pass decline that shape, counted in `result.json` `declined`, not by retuning a shared threshold.
- No em dashes in anything written (code comments, docs, commit messages). Check with `grep -c` for the character before committing.
- Commits: never add a Claude co-author trailer or any other Claude attribution (CLAUDE.md).
- Python files in this folder are run as `<venv>/python -I -B <file>`; they are CRLF on disk (`autocrlf=true`), keep them that way.
- Update README.md and CLAUDE.md in the same change as any new command, flag or invariant (CLAUDE.md "Keep the docs in sync").

## Correction to the spec, decided while planning

The spec defines `--raw` as "pdf2docx's output with nothing done to it except the unsafe-link removal". Taken literally that output names PDF-internal font names and embeds no fonts, so Word substitutes fonts in the raw file and not in the full one, and rule 3 would reward the converter for its font work rather than for its layout passes. `--raw` therefore also keeps the font steps that are guarantees rather than layout: the font plan handed to pdf2docx, `name_runs`, `fill_bare_runs` and `fonts.embed`. Every placement, restructuring and repair pass is off. This is flagged to the owner at handoff.

The spec also names `../cptc-typst-report` as where the reference report lives. That folder holds an older 146 KB `FullReport.typ`, not the 23-page report every earlier number came from. `scorecard.py` therefore takes the reference as `--reference-pdf <file>` plus `--reference-fonts <dir>`, and skips it when they are not given.

**Reference inputs (found 2026-09-29).** The source is the live Typst Studio workspace `C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report\` (`main.typ`, `assets\cover.png`, `fonts\Poppins-*.ttf`, six faces). Compiled the way the server compiles (`typst compile --root <that dir> --ignore-system-fonts -j 1 --font-path <that dir>\fonts --font-path <repo>\dist\fonts main.typ`), it gives 23 pages and 1,776,160 bytes, which matches every earlier round. Use `--reference-pdf .scratch\reference\reference.pdf --reference-fonts C:\Users\rober\Desktop\university-tools\advanced-typst-editor\data\workspaces\cptc-report\fonts`; recompile the PDF with that command if `.scratch` has been cleared. Never commit the report, its image or its fonts. `.scratch/` is added to `.gitignore` in Task 1.

## Review Focus

1. **A corpus document the converter refuses outright** (a `ConvertError`, for example a page-complexity refusal): the test tier and the scorecard must report it as that document's row with the message, not crash the whole run. Pinned in Task 2 (`run_corpus_checks` catches per document) and Task 6 (`scorecard.py` records `error`).
2. **Word renders a different page count from the PDF**: page-by-page comparison must only pair pages that exist on both sides, and rule 2 must still fire. Pinned in Task 6 (`test_rules_page_count_*`).
3. **A right-to-left line whose PDF text comes back in visual (reversed) order from pymupdf**: the new text check must not report every RTL line missing on a correct file. Pinned in Task 7 (the positive check on a clean conversion of `rtl-arabic` must report 0 missing).
4. **Mixed-direction lines** (English with a Hebrew phrase, or the reverse): classification by majority of strong characters must not flip an English line into the word-sequence path because of one Hebrew word. Pinned in Task 7 (`is_rtl` checks).
5. **Word left running after a failed render** (COM exception mid-conversion): the next document's render must still work. Pinned in Task 6 (`render_word.ps1` closes and quits in `finally`, and `scorecard.py` treats a non-zero exit as that document's error).

---

## File map

| File | Status | Responsibility |
|---|---|---|
| `server/typst/pdf-to-docx/convert.py` | modify | `--raw`, `--skip`, `declined`, RTL check and repair, detectors |
| `server/typst/pdf-to-docx/corpus.py` | create | corpus list, font dirs, compile helper, expected failures |
| `server/typst/pdf-to-docx/corpus/<name>/main.typ` (12) | create | the documents |
| `server/typst/pdf-to-docx/corpus/fonts/` | create | Noto Sans, Noto Naskh Arabic, Noto Sans Hebrew, `OFL.txt` |
| `server/typst/pdf-to-docx/corpus/SCORECARD.md` | create | committed record of each scorecard run |
| `server/typst/pdf-to-docx/render_word.ps1` | create | one DOCX to PDF through Word |
| `server/typst/pdf-to-docx/scorecard_rules.py` | create | pure rule evaluation |
| `server/typst/pdf-to-docx/scorecard.py` | create | orchestration: compile, convert twice, render, score, evaluate |
| `server/typst/pdf-to-docx/test_scorecard_rules.py` | create | tests for the rule |
| `server/typst/pdf-to-docx/compare.ps1` | modify | `-Raw`, `-Skip`, uses `render_word.ps1` |
| `server/typst/pdf-to-docx/test_convert.py` | modify | switch checks, corpus tier, RTL checks |
| `.dockerignore` | modify | exclude the corpus |
| `README.md`, `CLAUDE.md`, `docs/typst-tab-2026-09.md` | modify | docs |

All commands below run from `server/typst/pdf-to-docx/` unless they say otherwise, with `$PY` meaning `..\..\..\.venv-pdf2docx\Scripts\python.exe` (PowerShell) or `../../../.venv-pdf2docx/Scripts/python.exe` (Git Bash). The repo already gitignores `.venv-pdf2docx/` at its root, so that is where the venv goes (the spec said `.venv` in this folder; the existing name wins).

---

### Task 1: Environment, and the `--raw` / `--skip` switches

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py` (constants near line 222, `decorate_document` at 4398, `convert` at 4494, `main` at 4785)
- Modify: `server/typst/pdf-to-docx/test_convert.py` (new `run_switch_checks`, `__main__` at 1777)

**Interfaces:**
- Produces: `convert.convert(pdf_path, docx_path, budget_seconds=None, line_breaks="pdf", font_dirs=(), convert_fonts=True, raw=False, skip=frozenset())`; `convert.SKIPPABLE` (tuple of pass names); result dict gains `"mode": "full" | "raw"`, `"skipped": [names]`, `"declined": {name: count}`. CLI: `--raw`, `--skip=a,b` (unknown name: exit 2).

- [ ] **Step 1: Build the venv and confirm the existing checks pass**

From the repo root, in PowerShell:

```powershell
py -3.13 -m venv .venv-pdf2docx
.\.venv-pdf2docx\Scripts\python.exe -m pip install --require-hashes -r server\typst\pdf-to-docx\requirements.txt
bun run fonts
bun run build
cd server\typst\pdf-to-docx
..\..\..\.venv-pdf2docx\Scripts\python.exe -I -B test_convert.py
```

Expected: the last lines show no `FAIL`, exit code 0, and the count of `ok` lines is 268 (the figure recorded in `docs/typst-tab-2026-09.md` part eight). If pip reports a missing hash for a Windows wheel, stop and report it: the requirements file must not be edited by hand.

- [ ] **Step 2: Write the failing switch checks**

Add to `test_convert.py`, above `def describe(path):`:

```python
def run_switch_checks():
    """The two dev-only switches, and that the server never passes them."""
    import cases

    passed = True
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "export.mjs"), encoding="utf-8") as handle:
        export_source = handle.read()
    passed &= check("--raw" not in export_source and "--skip" not in export_source,
                    "switches: export.mjs never passes --raw or --skip")
    passed &= check(convert.main(["convert.py", "--skip=nope", "a.pdf", "b.docx", "c.json"]) == 2,
                    "switches: an unknown pass name is a usage error")

    if shutil.which("typst") is None:
        print("SKIP  the switch checks need the typst CLI on PATH")
        return passed
    workdir = tempfile.mkdtemp(prefix="btct-switch-test-")
    try:
        pdf = os.path.join(workdir, "report.pdf")
        compile_case(cases.REPORT, pdf)
        full = convert.convert(pdf, os.path.join(workdir, "full.docx"))
        passed &= check(full["mode"] == "full" and full["skipped"] == [] and full["declined"] == {},
                        "switches: a plain run says full, skipped nothing, declined nothing",
                        (full["mode"], full["skipped"], full["declined"]))
        passed &= check(full["headerFooter"]["header"] and full["tocEntries"] > 0,
                        "switches: the case has a header and a contents page to switch off",
                        (full["headerFooter"], full["tocEntries"]))

        skipped = convert.convert(pdf, os.path.join(workdir, "skip.docx"), skip=frozenset({"bands", "toc"}))
        passed &= check(not skipped["headerFooter"]["header"] and not skipped["headerFooter"]["footer"],
                        "switches: --skip=bands keeps the bands in the body", skipped["headerFooter"])
        passed &= check(skipped["tocEntries"] == 0, "switches: --skip=toc rebuilds no contents page",
                        skipped["tocEntries"])
        passed &= check(skipped["skipped"] == ["bands", "toc"], "switches: the result names what was skipped",
                        skipped["skipped"])
        passed &= check(skipped["textCheck"]["missing"] == 0, "switches: skipping loses no text",
                        skipped["textCheck"])

        raw = convert.convert(pdf, os.path.join(workdir, "raw.docx"), raw=True)
        passed &= check(raw["mode"] == "raw" and raw["tocEntries"] == 0
                        and not raw["headerFooter"]["header"],
                        "switches: --raw rebuilds nothing", (raw["mode"], raw["tocEntries"], raw["headerFooter"]))
        passed &= check(raw["textCheck"]["missing"] == 0 and not raw["textCheck"]["fellBack"],
                        "switches: --raw still runs the text check", raw["textCheck"])
        passed &= check(sorted(raw["skipped"]) == sorted(convert.SKIPPABLE),
                        "switches: --raw is every pass skipped", raw["skipped"])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return passed
```

And in `__main__`, after `ok = run_documents() and ok`:

```python
    ok = run_switch_checks() and ok
```

- [ ] **Step 3: Run it and watch it fail**

Run: `$PY -I -B test_convert.py`
Expected: a `TypeError` about the unexpected keyword `skip` (or `FAIL switches: an unknown pass name is a usage error`). If `FAIL switches: the case has a header and a contents page to switch off` appears after the implementation, `cases.REPORT` no longer has both; pick the case in `cases.py` that does and use it instead.

- [ ] **Step 4: Add the pass names and the counter**

In `convert.py`, after `RHYTHM_TOLERANCE_PT = 0.25` (line 222) and its comment block, add:

```python
# The passes a developer may turn off with --skip, to find which one a
# regression comes from without editing code. Font naming and embedding are
# not here: they are guarantees, not layout. The server never passes --skip.
SKIPPABLE = ("bands", "toc", "panels", "swatches", "align", "pictures", "line-breaks",
             "text-repair", "hyphens", "pitch-cut", "rhythm")
```

Make sure `from collections import Counter` is imported at the top (it is already used by `missing_from_docx`; if the import is `import collections`, write `collections.Counter` below instead).

- [ ] **Step 5: Honour `skip` in `decorate_document`**

Replace the body of `decorate_document` from `warnings = []` down to `return squares, warnings` with:

```python
    warnings = []
    skip = look.get("skip", frozenset())
    started_look = time.monotonic()
    panels = [] if "panels" in skip else look["panels"]
    shaded, panel_tables = shade_run_of_paragraphs(document, panels, plain=not place)
    swatches = [] if "swatches" in skip else look["swatches"]
    squares = restore_swatches(document, swatches, look["face"])
    aligned = [] if "align" in skip else look["aligned"]
    align_paragraphs(document, aligned)
    if place and "pictures" not in skip:
        fit_pictures(document, look["pictures"])
    repairs += time.monotonic() - started_look
    room = affordable(started, budget_seconds, repairs)
    if place and room and look["lineBreaks"] == "pdf" and "line-breaks" not in skip:
        force_line_breaks(document, look["aligned"], shaded)
    if place and not room:
        warnings.append(CROWDED_OUT)
    if "text-repair" not in skip:
        repair_text(document, look["pairs"], shaded)
    if "hyphens" not in skip:
        restore_break_hyphens(document, look["broken"], shaded)
    # Last, because it reads the spacing and the line count of every block the
    # passes above have finished writing.
    if place and room:
        seams = () if "pitch-cut" in skip else split_pitch_changes(document, anchors, shaded)
        if "rhythm" not in skip:
            align_vertical_rhythm(document, anchors, look["height"], panel_tables, look["rules"],
                                  seams, look["boxes"])
    name_runs(document, look["plan"])
    fill_bare_runs(document)
    return squares, warnings
```

Before editing, read `split_pitch_changes` (line 3687) and `align_vertical_rhythm` (3767): if either requires `seams` to be a list rather than any iterable, use `[]` instead of `()`. Also check `rejoin_unplaced(seams, written)` callers: skipping `pitch-cut` with `rhythm` on must not raise.

- [ ] **Step 6: Honour `raw` and `skip` in `convert`**

Change the signature:

```python
def convert(pdf_path, docx_path, budget_seconds=None, line_breaks="pdf", font_dirs=(),
            convert_fonts=True, raw=False, skip=frozenset()):
```

Add at the top of the function body, after `warnings = []`:

```python
    # --raw is every pass off and pdf2docx's own file, with only the font
    # steps that are guarantees kept (see the plan's note on the spec).
    skip = frozenset(SKIPPABLE) if raw else frozenset(skip)
    declined = Counter()
```

Wrap the band-detection loop so it does not run (or warn) when skipped:

```python
        bands = []
        if "bands" not in skip:
            for edge, name in (("top", "header"), ("bottom", "footer")):
                ...  # the existing loop body, unchanged, one level deeper
```

Replace `entries = detect_toc(doc, bands)` with:

```python
        entries = [] if "toc" in skip else detect_toc(doc, bands)
```

In the `look = {...}` dict add `"skip": skip, "declined": declined`.

Then make the conversion itself branch. Directly after `fell_back = False` and `try:`, add a raw branch and move the existing repaired path under `else:` (indent everything from `started = time.monotonic()` through the end of the second fallback `if missing and (budget_seconds is None ...)` block by one level):

```python
    try:
        started = time.monotonic()
        if raw:
            run_pdf2docx(plain_pdf, part, font_plan)
            if not os.path.exists(part) or os.path.getsize(part) == 0:
                raise ConvertError("the converter produced no Word file")
            document = Document(part)
            name_runs(document, font_plan)
            fill_bare_runs(document)
            document.save(part)
            squares = []
            repair_warnings = []
            checked_lines = plain_lines
            missing = missing_from_docx(plain_lines, docx_text(part, body_only=False))
        else:
            run_pdf2docx(stripped_pdf, part, font_plan)
            ...  # the existing code, unchanged, one level deeper
```

`started = time.monotonic()` moves above the `if` (it is used by the font step after the branch). In the `else` branch delete the now-duplicated `started = time.monotonic()` line. `look` is only built in the `else` branch; `declined` exists in both.

In the returned dict add:

```python
        "mode": "raw" if raw else "full",
        "skipped": sorted(skip),
        "declined": dict(declined),
```

- [ ] **Step 7: Parse the flags in `main`**

In `main`, after `convert_fonts = "--no-font-conversion" not in flags`:

```python
    raw = "--raw" in flags
    skip = set()
    for flag in flags:
        if flag.startswith("--skip="):
            skip |= {name for name in flag.split("=", 1)[1].split(",") if name}
    unknown = sorted(skip - set(SKIPPABLE))
    if unknown:
        print("unknown pass name(s) for --skip: %s (known: %s)" % (", ".join(unknown), ", ".join(SKIPPABLE)),
              file=sys.stderr)
        return 2
```

Move this block above the `len(args) not in (3, 4)` usage check so `--skip=nope` returns 2 even before arguments are validated. Extend the usage line to `usage: convert.py [--line-breaks=pdf|word] [--fonts=DIR] [--no-font-conversion] [--raw] [--skip=PASS,...]`. Pass `raw=raw, skip=frozenset(skip)` into `convert(...)`. `main` calls `cap_address_space()` first; move that below the new flag block so a usage error does not change the test process's limits.

- [ ] **Step 8: Run all checks**

Run: `$PY -I -B test_convert.py`
Expected: exit 0, no `FAIL`, the original 268 `ok` lines plus the new `switches:` lines.

- [ ] **Step 9: Syntax-check the server and commit**

From the repo root: `bun run test -- src/test/typst` (the export-side suites still pass; nothing there changed).

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/test_convert.py
git commit -m "Give the converter a raw mode and a way to skip one pass"
```

---

### Task 2: The corpus runner, the Word-free tier, and the three plain documents

**Files:**
- Create: `server/typst/pdf-to-docx/corpus.py`
- Create: `server/typst/pdf-to-docx/corpus/memo/main.typ`, `corpus/letter/main.typ`, `corpus/cv/main.typ`, each with a `README.md`
- Create: `server/typst/pdf-to-docx/corpus/fonts/NotoSans-Regular.ttf`, `NotoSans-Bold.ttf`, `OFL.txt`
- Modify: `server/typst/pdf-to-docx/test_convert.py`, `.dockerignore`

**Interfaces:**
- Consumes: `convert.convert(..., font_dirs=...)`, result fields from Task 1.
- Produces: `corpus.DOCUMENTS` (dict name → category), `corpus.EXPECTED_FAILURES` (dict name → reason string), `corpus.font_dirs() -> list[str]`, `corpus.documents() -> list[tuple[name, category, source_dir]]`, `corpus.compile_document(source_dir, pdf_path) -> None` (raises `subprocess.CalledProcessError` with typst's stderr).

- [ ] **Step 1: Fetch the Noto Sans faces and the OFL**

From `server/typst/pdf-to-docx/`, in Git Bash:

```bash
mkdir -p corpus/fonts
base=https://github.com/notofonts/notofonts.github.io/raw/main/fonts
curl -fsSL -o corpus/fonts/NotoSans-Regular.ttf $base/NotoSans/hinted/ttf/NotoSans-Regular.ttf
curl -fsSL -o corpus/fonts/NotoSans-Bold.ttf $base/NotoSans/hinted/ttf/NotoSans-Bold.ttf
curl -fsSL -o corpus/fonts/OFL.txt https://raw.githubusercontent.com/notofonts/latin-greek-cyrillic/main/OFL.txt
ls -la corpus/fonts
```

Expected: two `.ttf` files of roughly 400 to 600 KB and an `OFL.txt` that begins "Copyright". If a URL 404s, find the same file on `https://github.com/notofonts/notofonts.github.io/tree/main/fonts/NotoSans` and use that path; do not substitute a different family.

- [ ] **Step 2: Write `corpus.py`**

```python
"""The corpus the Word export is scored on, beyond the reference report.

Each entry is a folder under corpus/ with a main.typ. The documents are
compiled the way the server compiles a report (--root on the folder, system
fonts ignored, one job), with corpus/fonts and the report fonts the client
build ships. test_convert.py converts every one of them without Word;
scorecard.py also renders them through Word and scores them.

A document that is known to fail a Word-free check at the moment is listed in
EXPECTED_FAILURES with the reason. The tier fails both when an unlisted
document fails and when a listed one passes, so the list only ever shrinks
on purpose.
"""

import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))

# name -> category. Every name must have corpus/<name>/main.typ.
DOCUMENTS = {
    "memo": "plain",
    "letter": "plain",
    "cv": "plain",
}

# name -> why it fails a Word-free check today. Filled in from the baseline
# run in this task, emptied by the triage tasks.
EXPECTED_FAILURES = {}


def font_dirs():
    """corpus/fonts, then the report fonts the client build ships."""
    dirs = [os.path.join(CORPUS, "fonts")]
    for candidate in (os.path.join(REPO, "dist", "fonts"), os.path.join(REPO, "public", "fonts")):
        if os.path.isdir(candidate):
            dirs.append(candidate)
            break
    return [d for d in dirs if os.path.isdir(d)]


def documents():
    """[(name, category, source_dir)], in DOCUMENTS order."""
    return [(name, category, os.path.join(CORPUS, name)) for name, category in DOCUMENTS.items()]


def compile_document(source_dir, pdf_path):
    args = ["typst", "compile", "--root", source_dir, "--ignore-system-fonts", "-j", "1"]
    for directory in font_dirs():
        args += ["--font-path", directory]
    args += [os.path.join(source_dir, "main.typ"), pdf_path]
    subprocess.run(args, check=True, capture_output=True, text=True, encoding="utf-8")
```

- [ ] **Step 3: Write the three plain documents**

`corpus/memo/main.typ`:

```typst
#set page(paper: "us-letter", margin: 1in)
#set text(font: "Libertinus Serif", size: 11pt)
#set par(justify: true)

#align(center, text(16pt, weight: "bold")[MEMORANDUM])
#v(0.8em)
#grid(
  columns: (auto, 1fr),
  column-gutter: 1em,
  row-gutter: 0.6em,
  [*To:*], [All engineering staff],
  [*From:*], [Office of the CISO],
  [*Date:*], [29 September 2026],
  [*Subject:*], [Rotation of shared service credentials],
)
#v(0.4em)
#line(length: 100%, stroke: 0.6pt)

Following the internal assessment completed last month, every shared service
account in the build and deployment pipeline will have its credentials rotated
before the end of the quarter. The assessment found four accounts whose
passwords had not changed since they were created, and two of those were
readable by any member of the engineering group.

The rotation happens in three waves. The first covers the accounts used by the
continuous integration runners and starts on Monday. The second covers the
deployment keys held in the configuration repository. The third covers the
monitoring and backup agents, which need a maintenance window because the
agents restart when their credentials change.

#lorem(120)

Questions about the schedule go to the security team's queue rather than to
individual engineers, so that every answer is recorded once and can be found
again.

#lorem(90)
```

`corpus/letter/main.typ`:

```typst
#set page(paper: "a4", margin: (x: 2.5cm, y: 2cm))
#set text(font: "Libertinus Serif", size: 11pt)
#set par(justify: true)

#align(right)[
  Contoso Security Ltd \
  12 Harbour Street \
  Bristol BS1 4XX
]
#v(1.5em)
Ms Jane Doe \
Head of IT \
Fabrikam Inc. \
400 Market Road \
Leeds LS1 2AB
#v(1em)
#align(right)[29 September 2026]
#v(1em)
Dear Ms Doe,

Thank you for the opportunity to carry out the external assessment of
Fabrikam's internet-facing services. This letter confirms that fieldwork is
complete and summarises what happens next.

#lorem(80)

#lorem(60)

The full report will follow within ten working days. If you would like to
discuss any finding before then, please contact me directly.

#v(1.2em)
Yours sincerely,
#v(3em)
Alex Smith \
Principal Consultant, Contoso Security Ltd
```

`corpus/cv/main.typ` (note the escaped `\@`: a bare `@` in markup is a reference):

```typst
#set page(paper: "us-letter", margin: 0.6in)
#set text(font: "Noto Sans", size: 10pt)
#let accent = rgb("#1f4e79")
#let section(title) = {
  v(0.8em)
  text(12pt, weight: "bold", fill: accent, upper(title))
  v(-0.6em)
  line(length: 100%, stroke: 0.8pt + accent)
}

#grid(
  columns: (2.1in, 1fr),
  column-gutter: 0.3in,
  block(fill: luma(240), inset: 12pt, radius: 4pt, width: 100%)[
    #text(18pt, weight: "bold")[Sam Rivera]
    #v(0.2em)
    Security Engineer
    #section("Contact")
    sam.rivera\@example.com \
    +44 20 7946 0000 \
    Bristol, UK
    #section("Skills")
    - Web application testing
    - Active Directory
    - Python, Go, Rust
    - Cloud (AWS, Azure)
    #section("Certifications")
    OSCP (2023) \
    CRTO (2024) \
    OSWE (2025)
  ],
  [
    #section("Experience")
    *Senior Penetration Tester*, Contoso Security #h(1fr) 2023 to now \
    #lorem(40)
    - Led thirty internal network assessments.
    - Built the team's reporting pipeline.
    *Penetration Tester*, Northwind Labs #h(1fr) 2020 to 2023 \
    #lorem(35)
    #section("Education")
    *BSc Computer Science*, University of Bristol #h(1fr) 2016 to 2020 \
    First-class honours. Dissertation on fuzzing network protocols.
    #section("Projects")
    *BTCT*: collaborative notes for penetration testers. \
    #lorem(25)
  ],
)
```

Each folder gets a one-line `README.md`, for example `corpus/memo/README.md`: `Almost pure text: a justified memo with a label grid and a rule. Hand-written for this corpus.` (letter: `Address blocks, a right-aligned date and a signature gap. Hand-written.`; cv: `A shaded sidebar in a two-column grid, section rules, bullet lists, a sans face. Hand-written.`).

- [ ] **Step 4: Check they compile**

```bash
for d in memo letter cv; do typst compile --root corpus/$d --ignore-system-fonts --font-path corpus/fonts --font-path ../../../dist/fonts corpus/$d/main.typ /tmp/$d.pdf && echo "$d ok"; done
grep -rn '"@preview/\|"@local/' corpus || echo "no package specs"
```

Expected: three `ok` lines (a warning about an unknown font is a failure here: fix the name), then `no package specs`.

- [ ] **Step 5: Write the corpus tier in `test_convert.py`**

Add above `def describe(path):`:

```python
def check_corpus_document(name, source, workdir):
    """(passed, why) for one corpus document, without Word."""
    import corpus

    pdf = os.path.join(workdir, name + ".pdf")
    out = os.path.join(workdir, name + ".docx")
    try:
        corpus.compile_document(source, pdf)
    except subprocess.CalledProcessError as err:
        return False, "typst failed: " + (err.stderr or "")[:200]
    try:
        result = convert.convert(pdf, out, font_dirs=corpus.font_dirs())
    except convert.ConvertError as err:
        return False, "refused: " + str(err)[:200]
    text = result["textCheck"]
    if text["fellBack"] or text["missing"]:
        return False, "text check %s" % text
    try:
        document = Document(out)
    except Exception as err:  # noqa: BLE001 - any failure to open is the finding
        return False, "python-docx cannot open it: %s" % err
    unsafe = convert.unsafe_docx_targets(out)
    if unsafe:
        return False, "unsafe link targets %s" % unsafe[:2]
    sections = len(document.sections)
    if not 1 <= sections <= result["pages"] + 1:
        return False, "%d sections for %d PDF pages" % (sections, result["pages"])
    return True, "%d pages, %d sections, %d warnings" % (result["pages"], sections, len(result["warnings"]))


def run_corpus_checks():
    import corpus

    if shutil.which("typst") is None:
        print("SKIP  the corpus needs the typst CLI on PATH")
        return True
    passed = True
    for name, _category, source in corpus.documents():
        passed &= check(os.path.isfile(os.path.join(source, "main.typ")), "corpus: %s has a main.typ" % name)
    workdir = tempfile.mkdtemp(prefix="btct-corpus-test-")
    started = time.monotonic()
    try:
        for name, _category, source in corpus.documents():
            ok, why = check_corpus_document(name, source, workdir)
            expected = corpus.EXPECTED_FAILURES.get(name)
            if expected is None:
                passed &= check(ok, "corpus: %s converts cleanly" % name, why)
            else:
                passed &= check(not ok, "corpus: %s still fails as expected (%s)" % (name, expected), why)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print("      corpus took %.1f s" % (time.monotonic() - started))
    return passed
```

And in `__main__` after the switch checks:

```python
    ok = run_corpus_checks() and ok
```

- [ ] **Step 6: Run and record the baseline**

Run: `$PY -I -B test_convert.py`
Expected: three `corpus:` lines. For every document that fails, do NOT fix the converter in this task: add it to `EXPECTED_FAILURES` with the printed reason, for example `"cv": "text check {'pdfLines': 41, 'missing': 2, 'fellBack': True}"`, and re-run until the run exits 0. Note the `corpus took` time in the commit message.

- [ ] **Step 7: Keep the corpus out of the image**

Append to `.dockerignore` (repo root):

```
# The Word converter's test corpus: documents and fonts for scoring, never
# needed at runtime, and the Dockerfile copies server/typst/ whole.
server/typst/pdf-to-docx/corpus
```

Verify: `grep -n "pdf-to-docx/corpus" .dockerignore` prints the line.

- [ ] **Step 8: Commit**

```bash
git add server/typst/pdf-to-docx/corpus.py server/typst/pdf-to-docx/corpus server/typst/pdf-to-docx/test_convert.py .dockerignore
git commit -m "Start a corpus of other people's documents: three plain ones"
```

---

### Task 3: The academic documents

**Files:**
- Create: `corpus/ieee/` (vendored `charged-ieee`: `main.typ`, `lib.typ`, `refs.bib`, `LICENSE`, `README.md`)
- Create: `corpus/thesis/main.typ`, `corpus/thesis/refs.bib`, `README.md`
- Create: `corpus/notes/main.typ`, `README.md`
- Modify: `corpus.py` (`DOCUMENTS`, maybe `EXPECTED_FAILURES`)

**Interfaces:**
- Consumes: `corpus.DOCUMENTS`, `corpus.EXPECTED_FAILURES`, the tier from Task 2.

- [ ] **Step 1: Vendor `charged-ieee`**

In a scratch folder (not the repo):

```powershell
cd $env:TEMP
typst init "@preview/charged-ieee" ieee-probe
Get-ChildItem ieee-probe
Get-ChildItem "$env:LOCALAPPDATA\typst\packages\preview\charged-ieee"
```

`typst init` downloads the newest version and writes its template. Open the package folder's `LICENSE`. If it is not MIT-0, MIT, Apache-2.0 or OFL, stop and report; do not vendor it. Otherwise copy into `corpus/ieee/`: the package's `LICENSE`, its library file (named in its `typst.toml` as `entrypoint`, usually `lib.typ`), the template's `main.typ` and `refs.bib`. Then in `corpus/ieee/main.typ` replace the import line `#import "@preview/charged-ieee:<version>": ieee` with `#import "lib.typ": ieee`. Record the version in `corpus/ieee/README.md`: `charged-ieee <version>, vendored from Typst Universe under <licence>. Two columns, maths, footnotes, references. The template asks for TeX Gyre Termes, which the export does not ship, so typst falls back to the default serif; that is what a user without the font gets too.`

Check: `grep -rn '"@preview/\|"@local/' corpus/ieee || echo "clean"` prints `clean` (a package spec even in a comment makes the server refuse the report).

- [ ] **Step 2: Write the thesis chapter**

`corpus/thesis/refs.bib`:

```bibtex
@inproceedings{godefroid2008,
  author = {Godefroid, Patrice and Levin, Michael Y. and Molnar, David},
  title = {Automated Whitebox Fuzz Testing},
  booktitle = {Network and Distributed System Security Symposium},
  year = {2008},
}
@article{miller1990,
  author = {Miller, Barton P. and Fredriksen, Lars and So, Bryan},
  title = {An Empirical Study of the Reliability of UNIX Utilities},
  journal = {Communications of the ACM},
  volume = {33},
  number = {12},
  pages = {32--44},
  year = {1990},
}
@inproceedings{pham2020,
  author = {Pham, Van-Thuan and B{\"o}hme, Marcel and Roychoudhury, Abhik},
  title = {AFLNet: A Greybox Fuzzer for Network Protocols},
  booktitle = {IEEE International Conference on Software Testing},
  year = {2020},
}
```

`corpus/thesis/main.typ`:

```typst
#set page(
  paper: "a4",
  margin: (inside: 3cm, outside: 2cm, y: 2.5cm),
  numbering: "1",
  header: context {
    if counter(page).get().first() > 1 {
      set text(9pt)
      emph[Chapter 3. Fuzzing stateful protocols]
      h(1fr)
      counter(page).display()
    }
  },
)
#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true, first-line-indent: 1.2em)
#set heading(numbering: "1.1")
#set math.equation(numbering: "(1)")
#show figure.where(kind: table): set figure.caption(position: top)

#outline(depth: 2)
#pagebreak()
#counter(heading).update(2)

= Fuzzing stateful protocols

== Background
Random testing of programs has a long history: the first large study fed
random input to UNIX utilities and crashed a quarter of them @miller1990.
Whitebox approaches later used symbolic execution to reach deeper states
@godefroid2008.#footnote[Symbolic execution tracks inputs as formulas rather
than values, so a solver can pick the next input.] Network protocols add a
difficulty neither addresses: the server's response depends on every message
before it @pham2020.

A useful measure of how much a fuzzer has explored is the entropy of the
states it reached, where $p_i$ is the fraction of inputs that ended in state
$i$:

$ H = - sum_(i=1)^n p_i log_2 p_i $ <eq:entropy>

As @eq:entropy shows, a fuzzer that keeps reaching one state scores zero
however many inputs it sends.#footnote[This is the measure used in the
evaluation in Section 3.3.]

#figure(
  rect(width: 80%, height: 4cm, fill: luma(230), stroke: 0.6pt)[
    #align(center + horizon)[INIT #sym.arrow.r AUTH #sym.arrow.r READY #sym.arrow.r CLOSED]
  ],
  caption: [The four states of the target protocol.],
) <fig:states>

== Method
@fig:states shows the states the harness tracks. #lorem(110)

#figure(
  table(
    columns: 3,
    align: (left, right, right),
    table.header([*Fuzzer*], [*States*], [*Crashes*]),
    [Random], [2], [0],
    [AFLNet], [4], [3],
    [This work], [4], [7],
  ),
  caption: [States reached and crashes found in 24 hours.],
) <tab:results>

== Results
@tab:results summarises the runs. #lorem(140)

$ "coverage"(t) = 1 - e^(-lambda t) $

#lorem(100)

#bibliography("refs.bib")
```

`corpus/thesis/README.md`: `A thesis chapter: outline, a header from page 2, numbered headings, equations and figures, footnotes, a local bibliography. Hand-written.`

- [ ] **Step 3: Write the lecture notes**

`corpus/notes/main.typ`:

```typst
#set page(paper: "a4", margin: 2cm)
#set text(font: "Libertinus Serif", size: 11pt)
#set heading(numbering: "1.")
#let thm-counter = counter("thm")
#let env(kind, fill, bar) = body => {
  thm-counter.step()
  block(fill: fill, stroke: (left: 3pt + bar), inset: 10pt, width: 100%, radius: 2pt)[
    *#kind #context thm-counter.display().* #body
  ]
}
#let definition = env("Definition", rgb("#f3fbef"), rgb("#3a8a2e"))
#let theorem = env("Theorem", rgb("#eef4ff"), rgb("#2b5cb8"))
#let remark = env("Remark", rgb("#fff6e5"), rgb("#c77700"))

= Lecture 4: Hash functions

#definition[
  A hash function is a map $H: {0,1}^* -> {0,1}^n$ that is cheap to compute
  for any input.
]

Three properties are usually asked of a cryptographic hash function:

+ *Preimage resistance.* Given $y$, finding $x$ with $H(x) = y$ is hard.
+ *Second preimage resistance.* Given $x$, finding $x' != x$ with
  $H(x') = H(x)$ is hard.
  - This is weaker than collision resistance.
  - It is what a file checksum relies on.
+ *Collision resistance.* Finding any pair $x != x'$ with $H(x) = H(x')$
  is hard.

#theorem[
  If $H$ is collision resistant then it is second preimage resistant.
]

#remark[
  The converse fails: a function can resist second preimages and still have
  collisions that are easy to find.
]

#lorem(90)

= Lecture 5: The birthday bound

#theorem[
  Among $q$ uniformly random values in a set of size $N$, a collision occurs
  with probability at least $1 - e^(-q(q-1) slash 2N)$.
]

#lorem(120)

#definition[
  The *work factor* of an attack is the expected number of evaluations of $H$
  it needs.
]

#lorem(80)
```

`corpus/notes/README.md`: `Lecture notes: coloured theorem and definition boxes with a left bar (shaded blocks that are not code panels), numbered and nested lists, inline maths. Hand-written.`

- [ ] **Step 4: Register them and run the tier**

In `corpus.py` add to `DOCUMENTS`: `"ieee": "academic", "thesis": "academic", "notes": "academic",`.

Run: `$PY -I -B test_convert.py`
Expected: exit 0 after listing any new failures in `EXPECTED_FAILURES` with their printed reasons (do not fix the converter here). Compile check first if a document fails with `typst failed`: that is a document bug, fix the document.

- [ ] **Step 5: Commit**

```bash
git add server/typst/pdf-to-docx/corpus server/typst/pdf-to-docx/corpus.py
git commit -m "Corpus: an IEEE paper, a thesis chapter and lecture notes"
```

---

### Task 4: The pentest documents

**Files:**
- Create: `corpus/findings/main.typ`, `corpus/assessment/main.typ`, `corpus/exec-letter/main.typ`, each with `README.md`
- Modify: `corpus.py`

**Interfaces:**
- Consumes: the tier from Task 2.

- [ ] **Step 1: Write the findings report**

`corpus/findings/main.typ`:

````typst
#set page(
  paper: "a4",
  margin: (x: 2cm, top: 2.6cm, bottom: 2.2cm),
  header: [
    #set text(8pt, fill: luma(110))
    Northwind Labs #h(1fr) Web Application Assessment
    #v(-0.5em)
    #line(length: 100%, stroke: 0.4pt + luma(160))
  ],
  footer: context [
    #set text(8pt, fill: luma(110))
    CONFIDENTIAL #h(1fr) Page #counter(page).display("1 of 1", both: true)
  ],
)
#set text(font: "Noto Sans", size: 10pt)
#set heading(numbering: "1.")
#show heading.where(level: 1): set text(fill: rgb("#0b3d91"))
#show raw.where(block: true): block.with(fill: luma(245), inset: 8pt, radius: 3pt, width: 100%)

#let severity-colour = (
  Critical: rgb("#6a1b9a"),
  High: rgb("#c62828"),
  Medium: rgb("#ef6c00"),
  Low: rgb("#2e7d32"),
)

#let finding(id, title, severity, cvss, body) = block(
  breakable: false,
  stroke: 0.6pt + luma(200),
  radius: 4pt,
  width: 100%,
  clip: true,
)[
  #block(fill: severity-colour.at(severity), inset: 8pt, width: 100%, spacing: 0pt)[
    #text(fill: white, weight: "bold")[#id #h(0.6em) #title #h(1fr) #severity (CVSS #cvss)]
  ]
  #block(inset: 10pt, spacing: 0pt)[#body]
]

= Summary of findings

#table(
  columns: (auto, 1fr, auto),
  fill: (_, row) => if row == 0 { luma(230) },
  table.header([*ID*], [*Finding*], [*Severity*]),
  [NW-01], [SQL injection in the order search], text(fill: severity-colour.Critical)[*Critical*],
  [NW-02], [Session token not rotated at login], text(fill: severity-colour.High)[*High*],
  [NW-03], [Verbose errors disclose stack traces], text(fill: severity-colour.Medium)[*Medium*],
  [NW-04], [Missing security headers], text(fill: severity-colour.Low)[*Low*],
)

= Findings

#finding("NW-01", "SQL injection in the order search", "Critical", "9.8")[
  The `q` parameter of `/orders/search` is concatenated into a SQL query.
  A single quote returns a database error and a boolean payload changes the
  number of rows returned.

  ```http
  GET /orders/search?q=1'%20OR%20'1'='1 HTTP/1.1
  Host: shop.northwind.example
  ```

  *Affected hosts*
  #table(columns: (auto, auto), [shop.northwind.example], [10.20.0.15],
    [shop-staging.northwind.example], [10.20.8.15])

  *Recommendation.* Use parameterised queries for every database call.
]

#v(0.8em)
#finding("NW-02", "Session token not rotated at login", "High", "7.5")[
  The `SESSION` cookie issued before authentication stays valid afterwards,
  so an attacker who plants a token can ride the victim's session.
  #lorem(40)

  *Recommendation.* Issue a new session identifier at every privilege change.
]

#v(0.8em)
#finding("NW-03", "Verbose errors disclose stack traces", "Medium", "5.3")[
  #lorem(60)
  ```text
  java.lang.NullPointerException
      at com.northwind.orders.SearchController.search(SearchController.java:88)
  ```
]

#v(0.8em)
#finding("NW-04", "Missing security headers", "Low", "3.1")[
  #lorem(50)
]
````

`corpus/findings/README.md`: `A findings report unlike the reference: severity-coloured card headers, a summary table, code blocks, a running header with a rule and "Page N of M" footer, a sans face. Hand-written.`

- [ ] **Step 2: Write the assessment with a landscape page**

`corpus/assessment/main.typ`:

```typst
#set page(paper: "a4", margin: 2cm, numbering: "1")
#set text(font: "Libertinus Serif", size: 10.5pt)
#set heading(numbering: "1.")

= Scope
The assessment covered the 10.0.0.0/24 internal range and the three domain
controllers named in the rules of engagement. #lorem(120)

= Method
#lorem(160)

#page(flipped: true)[
  = Risk matrix
  #let cell(label, colour) = table.cell(fill: colour)[#align(center)[#label]]
  #table(
    columns: (auto, 1fr, 1fr, 1fr, 1fr, 1fr),
    rows: 1.2cm,
    align: horizon,
    [], [*Rare*], [*Unlikely*], [*Possible*], [*Likely*], [*Almost certain*],
    [*Severe*], cell("Medium", rgb("#ffe08a")), cell("High", rgb("#ffb366")), cell("High", rgb("#ffb366")), cell("Critical", rgb("#ff6b6b")), cell("Critical", rgb("#ff6b6b")),
    [*Major*], cell("Low", rgb("#b7e4a8")), cell("Medium", rgb("#ffe08a")), cell("High", rgb("#ffb366")), cell("High", rgb("#ffb366")), cell("Critical", rgb("#ff6b6b")),
    [*Moderate*], cell("Low", rgb("#b7e4a8")), cell("Medium", rgb("#ffe08a")), cell("Medium", rgb("#ffe08a")), cell("High", rgb("#ffb366")), cell("High", rgb("#ffb366")),
    [*Minor*], cell("Low", rgb("#b7e4a8")), cell("Low", rgb("#b7e4a8")), cell("Medium", rgb("#ffe08a")), cell("Medium", rgb("#ffe08a")), cell("High", rgb("#ffb366")),
    [*Negligible*], cell("Low", rgb("#b7e4a8")), cell("Low", rgb("#b7e4a8")), cell("Low", rgb("#b7e4a8")), cell("Low", rgb("#b7e4a8")), cell("Medium", rgb("#ffe08a")),
  )
  #lorem(60)
]

= Hosts
#table(
  columns: (auto, auto, auto, 1fr),
  table.header(repeat: true, [*Host*], [*Address*], [*OS*], [*Open services*]),
  ..range(1, 91).map(i => (
    [WS-#str(1000 + i)],
    [10.0.0.#i],
    [#if calc.rem(i, 3) == 0 [Windows Server 2019] else [Windows 11]],
    [#if calc.rem(i, 5) == 0 [SMB, RDP, WinRM] else [SMB, RDP]],
  )).flatten(),
)

= Conclusion
#lorem(80)
```

`corpus/assessment/README.md`: `An assessment with a landscape page in the middle (a coloured risk matrix) and a 90-row host table whose header repeats across pages. Hand-written.`

- [ ] **Step 3: Write the executive letter summary**

`corpus/exec-letter/main.typ`:

```typst
#set page(paper: "us-letter", margin: (x: 1in, y: 0.9in))
#set text(font: "Noto Sans", size: 10.5pt)

#grid(
  columns: (auto, 1fr),
  column-gutter: 10pt,
  align: horizon,
  polygon(fill: rgb("#0b3d91"), (0pt, 24pt), (12pt, 0pt), (24pt, 24pt)),
  text(14pt, weight: "bold", fill: rgb("#0b3d91"))[Contoso Security],
)
#v(1.5em)
#text(9pt, fill: luma(100))[29 September 2026 #h(1fr) Ref. CS-2026-114]
#v(1em)
#text(16pt, weight: "bold")[Executive summary: external assessment]
#v(0.5em)

To the board of Fabrikam Inc.,

We tested Fabrikam's internet-facing estate between 1 and 14 September 2026.
The overall risk is *moderate*: no critical issue was found, and the two high
findings are fixable within a normal release cycle.

#v(0.6em)
#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  column-gutter: 8pt,
  ..(("0", "Critical", rgb("#6a1b9a")), ("2", "High", rgb("#c62828")),
     ("5", "Medium", rgb("#ef6c00")), ("9", "Low", rgb("#2e7d32"))).map(((n, label, colour)) =>
    block(stroke: 1pt + colour, radius: 4pt, inset: 8pt, width: 100%)[
      #align(center)[#text(20pt, weight: "bold", fill: colour)[#n] \ #label]
    ])
)
#v(0.6em)

#lorem(90)

#lorem(60)

#v(2em)
#grid(
  columns: (1fr, 1fr),
  [
    #line(length: 70%, stroke: 0.5pt)
    Alex Smith \
    Principal Consultant
  ],
  [
    #line(length: 70%, stroke: 0.5pt)
    Priya Natarajan \
    Engagement Lead
  ],
)
```

`corpus/exec-letter/README.md`: `A one-page executive letter: a drawn logo, a row of four severity tiles, sparse text and a two-person signature block. Hand-written.`

- [ ] **Step 4: Register, compile-check, run the tier**

In `corpus.py` add `"findings": "pentest", "assessment": "pentest", "exec-letter": "pentest",` to `DOCUMENTS`. Compile each once by hand as in Task 2 step 4 (fix any document error). Then run `$PY -I -B test_convert.py`; list new failures in `EXPECTED_FAILURES` with the printed reasons.

- [ ] **Step 5: Commit**

```bash
git add server/typst/pdf-to-docx/corpus server/typst/pdf-to-docx/corpus.py
git commit -m "Corpus: three pentest documents unlike the reference report"
```

---

### Task 5: The right-to-left and mixed-script documents

**Files:**
- Create: `corpus/fonts/NotoNaskhArabic-Regular.ttf`, `NotoNaskhArabic-Bold.ttf`, `NotoSansHebrew-Regular.ttf`, `NotoSansHebrew-Bold.ttf`
- Create: `corpus/rtl-arabic/main.typ`, `corpus/rtl-mixed/main.typ`, `corpus/rtl-in-shapes/main.typ`, each with `README.md`
- Modify: `corpus.py`

**Interfaces:**
- Consumes: the tier from Task 2.

- [ ] **Step 1: Fetch the faces**

```bash
base=https://github.com/notofonts/notofonts.github.io/raw/main/fonts
for f in NotoNaskhArabic/hinted/ttf/NotoNaskhArabic-Regular.ttf NotoNaskhArabic/hinted/ttf/NotoNaskhArabic-Bold.ttf \
         NotoSansHebrew/hinted/ttf/NotoSansHebrew-Regular.ttf NotoSansHebrew/hinted/ttf/NotoSansHebrew-Bold.ttf; do
  curl -fsSL -o corpus/fonts/$(basename $f) $base/$f
done
du -sh corpus
```

Expected: four more `.ttf` files; `du` reports under 3 MB for the whole corpus. Both families are OFL, covered by the `OFL.txt` already present (add a line at its top naming the three families it covers).

- [ ] **Step 2: Write the Arabic section**

`corpus/rtl-arabic/main.typ`:

```typst
#set page(paper: "a4", margin: 2cm, numbering: "1")
#set text(font: "Noto Naskh Arabic", lang: "ar", size: 12pt)
#set par(justify: true)
#set heading(numbering: "1.")

= الملخص التنفيذي

أجرى فريقنا تقييمًا أمنيًا للشبكة الداخلية للشركة خلال الفترة من الأول إلى
الرابع عشر من سبتمبر. وقد شمل التقييم خوادم الملفات وأجهزة التحكم في النطاق
وتطبيقات الويب الداخلية.

وجدنا أن كلمات المرور الافتراضية ما زالت مستخدمة على ثلاثة أجهزة، وأن
التحديثات الأمنية لم تُطبَّق على خادمين منذ أكثر من عام. كما أن بعض الحسابات
المشتركة تملك صلاحيات أوسع مما تحتاجه.

= النتائج الرئيسية

#table(
  columns: (auto, 1fr, auto),
  table.header([*الرقم*], [*النتيجة*], [*الخطورة*]),
  [١], [كلمات مرور افتراضية على أجهزة الشبكة], [عالية],
  [٢], [تحديثات أمنية غير مطبقة], [عالية],
  [٣], [صلاحيات زائدة للحسابات المشتركة], [متوسطة],
  [٤], [غياب تسجيل الأحداث على خوادم الملفات], [منخفضة],
)

= التوصيات

+ تغيير جميع كلمات المرور الافتراضية فورًا.
+ وضع جدول شهري لتطبيق التحديثات الأمنية.
+ مراجعة صلاحيات الحسابات المشتركة كل ثلاثة أشهر.

نوصي بإعادة التقييم بعد ستة أشهر للتأكد من معالجة جميع النتائج، ويمكن لفريقنا
تقديم الدعم خلال مرحلة المعالجة عند الحاجة.
```

`corpus/rtl-arabic/README.md`: `Arabic throughout: right-to-left justified paragraphs, numbered headings, a table and an enumerated list with Arabic-Indic digits. Hand-written.`

- [ ] **Step 3: Write the Hebrew and English mix**

`corpus/rtl-mixed/main.typ`:

```typst
#set page(paper: "a4", margin: 2cm)
#set text(font: ("Noto Sans", "Noto Sans Hebrew"), size: 10.5pt)
#set par(justify: true)

= Policy review

The client's information security policy, titled "מדיניות אבטחת מידע", was
last revised in 2024. Its section on remote access ("גישה מרחוק") requires
multi-factor authentication, which we confirmed is enforced for the VPN but
not for the webmail portal.

#text(lang: "he")[
  = סיכום הממצאים

  במהלך הבדיקה נמצאה חולשת SQL injection בשרת ההזמנות, וכן נמצא כי גרסת
  Apache בשרת הראשי חשופה ל-CVE-2026-1234. מומלץ לעדכן את השרת בהקדם
  ולהפעיל אימות דו-שלבי גם בפורטל הדואר.
]

#table(
  columns: (1fr, 1fr),
  table.header([*English*], [*עברית*]),
  [Default credentials], [סיסמאות ברירת מחדל],
  [Missing patches], [עדכונים חסרים],
  [Weak TLS configuration], [הגדרת TLS חלשה],
)

#lorem(60)
```

`corpus/rtl-mixed/README.md`: `English with Hebrew phrases inside a line, a Hebrew section with English terms inside it, and a two-direction table. Hand-written.`

- [ ] **Step 4: Write English with Arabic inside shapes**

`corpus/rtl-in-shapes/main.typ`:

````typst
#set page(paper: "us-letter", margin: 1in)
#set text(font: ("Libertinus Serif", "Noto Naskh Arabic"), size: 11pt)
#show raw: set text(font: ("DejaVu Sans Mono", "Noto Naskh Arabic"))
#show raw.where(block: true): block.with(fill: luma(240), inset: 8pt, radius: 3pt, width: 100%)

= Stored cross-site scripting in the comment form

The comment field of the Arabic storefront accepts markup. The request below
stores a comment that runs script for every visitor who opens the product page.

```http
POST /ar/products/88/comments HTTP/1.1
Host: shop.example
Content-Type: application/x-www-form-urlencoded

comment=مرحبا بالعالم<script>alert(1)</script>
```

#figure(
  rect(width: 70%, height: 3cm, fill: luma(230))[#align(center + horizon)[screenshot]],
  caption: [The product page after the payload runs: #text(lang: "ar")[صفحة المنتج بعد تنفيذ الشيفرة]],
)

#lorem(80)
````

`corpus/rtl-in-shapes/README.md`: `An English finding with Arabic inside a code panel and inside a figure caption, the two shapes the converter restructures. Hand-written.`

- [ ] **Step 5: Register, compile-check, run the tier**

Add `"rtl-arabic": "rtl", "rtl-mixed": "rtl", "rtl-in-shapes": "rtl",` to `DOCUMENTS`. Compile each by hand (a missing-glyph warning is a document bug: fix the font list). Run `$PY -I -B test_convert.py`; list new failures in `EXPECTED_FAILURES`. These documents will very likely PASS the text check today even though their spaces are lost: that is the bug Task 7 makes visible, so do not be surprised.

- [ ] **Step 6: Commit**

```bash
git add server/typst/pdf-to-docx/corpus server/typst/pdf-to-docx/corpus.py
git commit -m "Corpus: Arabic, Hebrew with English, and Arabic inside shapes"
```

---

### Task 6: The scorecard, the noise measurement, and the baseline

**Files:**
- Create: `server/typst/pdf-to-docx/render_word.ps1`, `scorecard_rules.py`, `test_scorecard_rules.py`, `scorecard.py`, `corpus/SCORECARD.md`
- Modify: `server/typst/pdf-to-docx/compare.ps1`

**Interfaces:**
- Consumes: `corpus.documents()`, `corpus.compile_document`, `corpus.font_dirs()`, `convert.py` CLI (`--raw`, `--skip`, `--fonts=`), `compare_pages.py <reference.pdf> <candidate.pdf> <out-dir> <label>` writing `<label>-scores.json` with `{"referencePages", "candidatePages", "scores": [{"page", "mad", "ssim", "offset"}], "sheets"}`.
- Produces: `scorecard_rules.evaluate(row, tolerance=MEAN_TOLERANCE, reference_floor=REFERENCE_FLOOR) -> list[str]`; row shape `{"name", "pdfPages", "full": {"wordPages", "ssim": [float], "seconds", "result"}, "raw": {...same}, "isReference": bool}`; `scorecard.py [--out DIR] [--only a,b] [--skip PASSES] [--noise] [--reference-pdf FILE --reference-fonts DIR]`.

- [ ] **Step 1: Extract the Word render**

`render_word.ps1`:

```powershell
# One Word file to PDF through Word itself, for scoring. A developer tool:
# needs Microsoft Word, never runs in Docker.
#
#   .\render_word.ps1 -Docx <in.docx> -Pdf <out.pdf>
#
# Prints "pages: N" and exits 0, or exits 1 with the error. Word is always
# closed and released, so a failed render does not leave WINWORD.EXE holding
# the next document.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Docx,
  [Parameter(Mandatory = $true)][string]$Pdf
)
$ErrorActionPreference = "Stop"
$Docx = (Resolve-Path $Docx).Path
if (Test-Path $Pdf) { Remove-Item -Force $Pdf }
$Pdf = [System.IO.Path]::GetFullPath($Pdf)
$word = $null
$doc = $null
$code = 0
try {
  $word = New-Object -ComObject Word.Application
  $word.Visible = $false
  $word.DisplayAlerts = 0
  # FileName, ConfirmConversions, ReadOnly, AddToRecentFiles.
  $doc = $word.Documents.Open($Docx, $false, $true, $false)
  $doc.Fields.Update() | Out-Null
  $doc.Repaginate()
  $pages = $doc.ComputeStatistics(2)  # wdStatisticPages
  $doc.SaveAs2([string]$Pdf, 17)      # wdFormatPDF
  Write-Output "pages: $pages"
} catch {
  Write-Error $_
  $code = 1
} finally {
  if ($doc) { $doc.Close([ref]0) | Out-Null }
  if ($word) { $word.Quit() | Out-Null }
  foreach ($o in @($doc, $word)) {
    if ($o) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($o) }
  }
  [System.GC]::Collect()
  [System.GC]::WaitForPendingFinalizers()
}
exit $code
```

In `compare.ps1`, replace step 3 (the block from `# 3. Word's own opinion` through the closing `}` of its `finally`) with:

```powershell
# 3. Word's own opinion of that file, as a PDF.
$rendered = Join-Path $Out "converted.pdf"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here "render_word.ps1") -Docx $docx -Pdf $rendered
if ($LASTEXITCODE -ne 0) { throw "Word could not render $docx" }
```

and add two parameters, `[switch]$Raw` and `[string]$Skip`, passed into `$convertArgs` before the paths:

```powershell
if ($Raw) { $convertArgs += "--raw" }
if ($Skip) { $convertArgs += "--skip=$Skip" }
```

Update the usage comment at the top of `compare.ps1` to mention `-Raw` and `-Skip <pass,...>`.

- [ ] **Step 2: Write the failing rule tests**

`test_scorecard_rules.py`:

```python
#!/usr/bin/env python3
"""Checks for scorecard_rules.py. Run: <venv>/python -I -B test_scorecard_rules.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scorecard_rules as rules  # noqa: E402


def row(full_ssim, raw_ssim, pdf_pages=None, full_pages=None, raw_pages=None,
        full_seconds=1.0, raw_seconds=1.0, fell_back=False, missing=0, reference=False):
    pdf_pages = pdf_pages if pdf_pages is not None else len(full_ssim)
    return {
        "name": "doc",
        "isReference": reference,
        "pdfPages": pdf_pages,
        "full": {"wordPages": full_pages if full_pages is not None else len(full_ssim), "ssim": full_ssim,
                 "seconds": full_seconds,
                 "result": {"textCheck": {"missing": missing, "fellBack": fell_back}}},
        "raw": {"wordPages": raw_pages if raw_pages is not None else len(raw_ssim), "ssim": raw_ssim,
                "seconds": raw_seconds,
                "result": {"textCheck": {"missing": 0, "fellBack": False}}},
    }


def expect(violations, prefix, label):
    ok = any(v.startswith(prefix) for v in violations)
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", label, violations))
    return ok


def expect_none(violations, label):
    ok = not violations
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", label, violations))
    return ok


def main():
    passed = True
    passed &= expect_none(rules.evaluate(row([0.95, 0.93], [0.90, 0.91])), "better than raw passes")
    passed &= expect_none(rules.evaluate(row([0.899, 0.91], [0.90, 0.91])), "inside the mean tolerance passes")
    passed &= expect(rules.evaluate(row([0.80, 0.80], [0.90, 0.90])), "3:", "a worse mean is rule 3")
    passed &= expect(rules.evaluate(row([0.99, 0.87], [0.90, 0.90])), "4:", "one page 0.03 worse is rule 4")
    passed &= expect(rules.evaluate(row([0.95], [0.90], fell_back=True)), "1:", "a fallback is rule 1")
    passed &= expect(rules.evaluate(row([0.95], [0.90], missing=2)), "1:", "missing text is rule 1")
    # Rule 2: full lands further from the PDF's page count than raw does.
    passed &= expect(rules.evaluate(row([0.9, 0.9, 0.9], [0.9, 0.9], pdf_pages=2, full_pages=3, raw_pages=2)),
                     "2:", "test_rules_page_count_worse is rule 2")
    passed &= expect_none(rules.evaluate(row([0.9, 0.9], [0.9, 0.9, 0.9], pdf_pages=2, full_pages=2, raw_pages=3)),
                          "test_rules_page_count_better passes")
    # Pages are only paired where both sides have one: a three-page full
    # against a two-page raw compares two pages and does not index past raw.
    passed &= expect_none(rules.evaluate(row([0.9, 0.9, 0.1], [0.9, 0.9], pdf_pages=3, full_pages=3, raw_pages=2)),
                          "test_rules_page_count_unpaired_page_is_not_scored")
    passed &= expect(rules.evaluate(row([0.90], [0.80], reference=True)), "5:", "the reference below its floor is rule 5")
    passed &= expect_none(rules.evaluate(row([0.92], [0.80], reference=True)), "the reference above its floor passes")
    passed &= expect(rules.evaluate(row([0.95], [0.90], full_seconds=9.0, raw_seconds=3.0)), "6:",
                     "full slower than twice raw plus 2 s is rule 6")
    passed &= expect(rules.evaluate({"name": "doc", "error": "typst failed"}), "error:", "an errored row reports it")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
```

Run: `$PY -I -B test_scorecard_rules.py`
Expected: `ModuleNotFoundError: No module named 'scorecard_rules'`.

- [ ] **Step 3: Write `scorecard_rules.py`**

```python
"""The rule a converter change meets before it is committed (spec, section 2).

Pure: a row in, a list of violations out, each starting with the rule's
number so a table can sort and a test can match on it. An empty list passes.
"""

# Widened only if scorecard.py --noise measures Word's run-to-run noise above
# it; the value in use is written at the top of SCORECARD.md.
MEAN_TOLERANCE = 0.002
PAGE_TOLERANCE = 0.02
REFERENCE_FLOOR = 0.9146
TIME_FACTOR = 2.0
TIME_SLACK_SECONDS = 2.0


def mean(values):
    return sum(values) / len(values) if values else 0.0


def evaluate(row, tolerance=MEAN_TOLERANCE, reference_floor=REFERENCE_FLOOR):
    if row.get("error"):
        return ["error: %s" % row["error"]]
    full, raw = row["full"], row["raw"]
    violations = []
    text = full["result"]["textCheck"]
    if text["fellBack"] or text["missing"]:
        violations.append("1: not at the top rung (%d missing, fell back %s)" % (text["missing"], text["fellBack"]))
    pdf = row["pdfPages"]
    if abs(full["wordPages"] - pdf) > abs(raw["wordPages"] - pdf):
        violations.append("2: %d Word pages against the PDF's %d (raw: %d)" % (full["wordPages"], pdf, raw["wordPages"]))
    if mean(full["ssim"]) < mean(raw["ssim"]) - tolerance:
        violations.append("3: mean %.4f against raw %.4f" % (mean(full["ssim"]), mean(raw["ssim"])))
    for index, (a, b) in enumerate(zip(full["ssim"], raw["ssim"])):
        if a < b - PAGE_TOLERANCE:
            violations.append("4: page %d at %.4f against raw %.4f" % (index + 1, a, b))
    if row.get("isReference") and mean(full["ssim"]) < reference_floor:
        violations.append("5: reference mean %.4f below %.4f" % (mean(full["ssim"]), reference_floor))
    if full["seconds"] > TIME_FACTOR * raw["seconds"] + TIME_SLACK_SECONDS:
        violations.append("6: %.1f s against raw %.1f s" % (full["seconds"], raw["seconds"]))
    return violations
```

Note `zip` stops at the shorter list, which is what pairs only the pages both sides have.

Run: `$PY -I -B test_scorecard_rules.py`
Expected: every line `ok`, exit 0.

- [ ] **Step 4: Write `scorecard.py`**

```python
#!/usr/bin/env python3
"""Score the Word export on the corpus: full converter against raw pdf2docx.

    <venv>/python -I -B scorecard.py [--out DIR] [--only a,b] [--skip PASSES]
        [--noise] [--reference-pdf FILE --reference-fonts DIR]

A developer tool. Needs typst on PATH and Microsoft Word; never runs in Docker
and is not part of any test suite. For each document: compile once, convert
twice (full, and --raw), render both through Word, score both against the PDF
with compare_pages.py, then apply scorecard_rules.evaluate. Writes
scorecard.json and scorecard.md into --out (default: a new temp folder) and
prints the table. Exit 0 when every row passes.

--skip is passed to the full conversion only, to try a document with one pass
off. --noise renders every raw file twice and reports how far Word's own
rendering moves the mean, which is what the tolerance must exceed.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus  # noqa: E402
import scorecard_rules  # noqa: E402

RENDER = os.path.join(HERE, "render_word.ps1")
CONVERT = os.path.join(HERE, "convert.py")
COMPARE = os.path.join(HERE, "compare_pages.py")


def run_convert(pdf, docx, fonts, extra):
    result_path = docx + ".json"
    args = [sys.executable, "-I", "-B", CONVERT] + ["--fonts=%s" % d for d in fonts] + extra + [pdf, docx, result_path]
    started = time.monotonic()
    proc = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
    seconds = time.monotonic() - started
    with open(result_path, encoding="utf-8") as handle:
        result = json.load(handle)
    if proc.returncode != 0 or not result.get("ok"):
        raise RuntimeError("convert.py: %s" % (result.get("message") or proc.stderr[-300:]))
    return result, seconds


def render(docx, pdf):
    proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", RENDER,
                           "-Docx", docx, "-Pdf", pdf], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("Word render failed: %s" % (proc.stderr or proc.stdout)[-300:])
    for line in proc.stdout.splitlines():
        if line.startswith("pages:"):
            return int(line.split(":", 1)[1])
    raise RuntimeError("Word render printed no page count")


def score(reference_pdf, candidate_pdf, out_dir, label):
    subprocess.run([sys.executable, "-I", "-B", COMPARE, reference_pdf, candidate_pdf, out_dir, label],
                   capture_output=True, text=True)
    with open(os.path.join(out_dir, "%s-scores.json" % label), encoding="utf-8") as handle:
        data = json.load(handle)
    return [page["ssim"] for page in data["scores"]]


def side(name, mode, pdf, fonts, extra, out_dir):
    docx = os.path.join(out_dir, "%s-%s.docx" % (name, mode))
    rendered = os.path.join(out_dir, "%s-%s.word.pdf" % (name, mode))
    result, seconds = run_convert(pdf, docx, fonts, extra)
    word_pages = render(docx, rendered)
    ssim = score(pdf, rendered, out_dir, "%s-%s" % (name, mode))
    return {"wordPages": word_pages, "ssim": ssim, "seconds": seconds, "result": result, "rendered": rendered,
            "docx": docx}


def score_document(name, category, pdf, fonts, skip, out_dir, is_reference=False):
    import pymupdf

    with pymupdf.open(pdf) as doc:
        pdf_pages = doc.page_count
    full_extra = ["--skip=%s" % skip] if skip else []
    row = {"name": name, "category": category, "isReference": is_reference, "pdfPages": pdf_pages,
           "full": side(name, "full", pdf, fonts, full_extra, out_dir),
           "raw": side(name, "raw", pdf, fonts, ["--raw"], out_dir)}
    row["violations"] = scorecard_rules.evaluate(row)
    return row


def mean(values):
    return scorecard_rules.mean(values)


def table(rows, tolerance):
    lines = [
        "Mean tolerance in use: %.4f. Numbers come from this machine's Word; a record, not a CI gate." % tolerance,
        "",
        "| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw "
        "| seconds full / raw | declined | verdict |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        if row.get("error"):
            lines.append("| %s | %s | | | | | | | error: %s |" % (row["name"], row.get("category", ""), row["error"]))
            continue
        full, raw = row["full"], row["raw"]
        declined = ", ".join("%s %d" % (k, v) for k, v in sorted(full["result"].get("declined", {}).items())) or "none"
        verdict = "pass" if not row["violations"] else "; ".join(row["violations"])
        lines.append("| %s | %s | %d | %d / %d | %.4f / %.4f | %.4f / %.4f | %.1f / %.1f | %s | %s |" % (
            row["name"], row["category"], row["pdfPages"], full["wordPages"], raw["wordPages"],
            mean(full["ssim"]), mean(raw["ssim"]), min(full["ssim"] or [0]), min(raw["ssim"] or [0]),
            full["seconds"], raw["seconds"], declined, verdict))
    return "\n".join(lines) + "\n"


def parse(argv):
    opts = {"out": None, "only": None, "skip": "", "noise": False, "reference_pdf": None, "reference_fonts": None}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--noise":
            opts["noise"] = True
        elif arg in ("--out", "--only", "--skip", "--reference-pdf", "--reference-fonts") and i + 1 < len(argv):
            opts[arg[2:].replace("-", "_")] = argv[i + 1]
            i += 1
        else:
            raise SystemExit("unknown argument %s" % arg)
        i += 1
    return opts


def main(argv):
    opts = parse(argv)
    out_dir = opts["out"] or tempfile.mkdtemp(prefix="btct-scorecard-")
    os.makedirs(out_dir, exist_ok=True)
    only = set(opts["only"].split(",")) if opts["only"] else None
    jobs = [(n, c, s, corpus.font_dirs(), False) for n, c, s in corpus.documents() if not only or n in only]
    if opts["reference_pdf"] and (not only or "reference" in only):
        fonts = [opts["reference_fonts"]] + corpus.font_dirs() if opts["reference_fonts"] else corpus.font_dirs()
        jobs.append(("reference", "reference", opts["reference_pdf"], fonts, True))

    rows = []
    for name, category, source, fonts, is_reference in jobs:
        print("... %s" % name, flush=True)
        try:
            if is_reference:
                pdf = source
            else:
                pdf = os.path.join(out_dir, name + ".pdf")
                corpus.compile_document(source, pdf)
            if opts["noise"]:
                first = side(name, "raw", pdf, fonts, ["--raw"], out_dir)
                again = os.path.join(out_dir, "%s-raw-again.word.pdf" % name)
                render(first["docx"], again)
                second = score(pdf, again, out_dir, "%s-raw-again" % name)
                rows.append({"name": name, "noise": abs(mean(first["ssim"]) - mean(second))})
                continue
            rows.append(score_document(name, category, pdf, fonts, opts["skip"], out_dir, is_reference))
        except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as err:
            message = getattr(err, "stderr", None) or str(err)
            rows.append({"name": name, "category": category, "error": str(message)[:200], "violations": ["error"]})

    if opts["noise"]:
        worst = max((r.get("noise", 0.0) for r in rows), default=0.0)
        for r in rows:
            print("%-16s %s" % (r["name"], ("noise %.5f" % r["noise"]) if "noise" in r else r.get("error")))
        print("worst noise %.5f (tolerance %.4f)" % (worst, scorecard_rules.MEAN_TOLERANCE))
        return 0
    with open(os.path.join(out_dir, "scorecard.json"), "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=1)
    text = table(rows, scorecard_rules.MEAN_TOLERANCE)
    with open(os.path.join(out_dir, "scorecard.md"), "w", encoding="utf-8") as handle:
        handle.write(text)
    print(text)
    print("written to %s" % out_dir)
    return 0 if all(not r.get("violations") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 5: Smoke-test on one document**

Run: `$PY -I -B scorecard.py --only memo --out ..\..\..\.scratch\scorecard-smoke`
Expected: one table row for `memo` with numbers in every column, and `written to ...`. `.scratch/` must be gitignored; if `git status` shows it, add `.scratch/` to `.gitignore` in this commit. If Word prompts or hangs, kill `WINWORD.EXE` and check `render_word.ps1` by hand on the produced `.docx`.

- [ ] **Step 6: Measure Word's noise**

Run: `$PY -I -B scorecard.py --noise --out ..\..\..\.scratch\scorecard-noise`
Expected: one `noise` line per document and a `worst noise` line. If the worst exceeds 0.002, set `MEAN_TOLERANCE` in `scorecard_rules.py` to the worst noise rounded up to the next 0.001, re-run `test_scorecard_rules.py` (the "inside the mean tolerance" row may need its numbers moved to stay inside), and say so in the commit message.

- [ ] **Step 7: Run the baseline and commit it**

Ask the owner for the reference report's PDF and its fonts folder if they have not been given (see the handoff note). Then:

Run: `$PY -I -B scorecard.py --out ..\..\..\.scratch\scorecard-baseline --reference-pdf <pdf> --reference-fonts <dir>`

Create `corpus/SCORECARD.md`:

```markdown
# Word export scorecard

Each run of `scorecard.py`, newest first. `full` is `convert.py` as the server runs it; `raw` is pdf2docx with only the font guarantees (see the plan's note). Scores are mean structural similarity per page against the PDF, rendered through this machine's Word 16, so they are a record and not a CI gate. Word's run-to-run noise measured on <date>: <worst noise>.

## Baseline, <date>, before any converter change

<paste scorecard.md here>
```

Expected: the table shows which documents break which rule; this is the input to Task 9, not a failure of this task. The exit code will be 1 if anything violates; that is fine here.

- [ ] **Step 8: Commit**

```bash
git add server/typst/pdf-to-docx/render_word.ps1 server/typst/pdf-to-docx/compare.ps1 \
  server/typst/pdf-to-docx/scorecard.py server/typst/pdf-to-docx/scorecard_rules.py \
  server/typst/pdf-to-docx/test_scorecard_rules.py server/typst/pdf-to-docx/corpus/SCORECARD.md .gitignore
git commit -m "Score the Word export on the corpus against raw pdf2docx"
```

---

### Task 7: Make the text check see right-to-left spacing

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py` (near `compare_squash` at 4220 and `missing_from_docx` at 4300)
- Modify: `server/typst/pdf-to-docx/test_convert.py`

**Interfaces:**
- Produces: `convert.is_rtl(text) -> bool`; `convert.compare_words(text) -> str` (each whitespace-separated word squashed with `compare_squash`, joined by one space); `missing_from_docx` unchanged in signature.

- [ ] **Step 1: Look at what the two sides hold today**

```bash
cd server/typst/pdf-to-docx
$PY -I -B - <<'EOF'
import os, sys, tempfile
sys.path.insert(0, ".")
import convert, corpus
work = tempfile.mkdtemp()
for name in ("rtl-arabic", "rtl-mixed"):
    pdf = os.path.join(work, name + ".pdf"); out = os.path.join(work, name + ".docx")
    corpus.compile_document(os.path.join(corpus.CORPUS, name), pdf)
    convert.convert(pdf, out, font_dirs=corpus.font_dirs())
    import pymupdf
    rows = convert.page_rows(pymupdf.open(pdf)[0])
    print(name, "PDF:", [r["text"] for r in rows[:4]])
    print(name, "DOCX:", convert.docx_text(out, body_only=False)[:400])
EOF
```

Record in the task notes: (a) whether pymupdf's row text for Arabic reads in logical order (first word of the sentence first, "أجرى فريقنا") or reversed; (b) whether the Word text has lost the spaces between Arabic words; (c) the same for Hebrew. If (a) is reversed, `compare_words` must reverse the word order of RTL lines on the PDF side before comparing; add that to Step 3 and a check to Step 2. If (b) shows spaces intact, stop and report: the bug the spec describes is not reproduced and Task 8 needs rethinking.

- [ ] **Step 2: Write the failing checks**

Add to `test_convert.py`, above `def describe(path):`:

```python
def strip_rtl_spaces(src, dst):
    """Copy a Word file with the spaces removed from every run that holds RTL text."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "word/document.xml":
                tree = ElementTree.fromstring(data)
                for node in tree.iter(W + "t"):
                    if node.text and convert.is_rtl(node.text):
                        node.text = node.text.replace(" ", "")
                data = ElementTree.tostring(tree, xml_declaration=True, encoding="UTF-8")
            zout.writestr(item, data)


def run_rtl_check_checks():
    import corpus

    passed = True
    passed &= check(convert.is_rtl("أجرى فريقنا تقييمًا"), "rtl: an Arabic line is right-to-left")
    passed &= check(convert.is_rtl("במהלך הבדיקה נמצאה חולשת SQL injection"),
                    "rtl: a Hebrew line with two English words is right-to-left")
    passed &= check(not convert.is_rtl('The policy, titled "מדיניות אבטחת מידע", was revised in 2024.'),
                    "rtl: an English line quoting Hebrew stays left-to-right")
    passed &= check(not convert.is_rtl("1. 2. 3."), "rtl: digits and punctuation are not right-to-left")
    passed &= check(convert.compare_words("  أجرى   فريقنا تقييمًا ") == "أجرى فريقنا تقييمًا",
                    "rtl: words are squashed and joined by one space", convert.compare_words("أجرى   فريقنا"))

    if shutil.which("typst") is None:
        print("SKIP  the RTL document checks need the typst CLI on PATH")
        return passed
    workdir = tempfile.mkdtemp(prefix="btct-rtl-test-")
    try:
        pdf = os.path.join(workdir, "ar.pdf")
        corpus.compile_document(os.path.join(corpus.CORPUS, "rtl-arabic"), pdf)
        doc = pymupdf.open(pdf)
        lines = convert.body_lines(doc, [])
        doc.close()
        # A Word file whose Arabic has had its spaces stripped must fail.
        # Built from a fresh conversion so this check does not depend on
        # whether Task 8's repair has landed yet.
        converted = os.path.join(workdir, "ar.docx")
        convert.convert(pdf, converted, font_dirs=corpus.font_dirs())
        stripped = os.path.join(workdir, "ar-stripped.docx")
        strip_rtl_spaces(converted, stripped)
        missing = convert.missing_from_docx(lines, convert.docx_text(stripped, body_only=False))
        passed &= check(len(missing) > 0, "rtl: Arabic with its spaces stripped is reported missing", len(missing))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return passed
```

In `__main__`: `ok = run_rtl_check_checks() and ok`.

Run: `$PY -I -B test_convert.py`
Expected: `AttributeError: module 'convert' has no attribute 'is_rtl'`.

- [ ] **Step 3: Implement the classification and the word comparison**

In `convert.py`, after `compare_squash`:

```python
def is_rtl(text):
    """Is this line right-to-left, by a majority of its strong characters?

    One Hebrew phrase quoted in an English sentence leaves it left-to-right,
    and English terms inside a Hebrew sentence leave it right-to-left.
    Digits, punctuation and spaces have no strong direction and do not vote.
    """
    rtl = ltr = 0
    for ch in text:
        kind = unicodedata.bidirectional(ch)
        if kind in ("R", "AL"):
            rtl += 1
        elif kind == "L":
            ltr += 1
    return rtl > 0 and rtl >= ltr


def compare_words(text):
    """A right-to-left line for the comparison: its words squashed, one space apart.

    compare_squash drops whitespace because a re-flow may move it, and that is
    exactly what hid pdf2docx running an Arabic line together: with the spaces
    gone on both sides, a line with none left compares equal. For a
    right-to-left line the word boundaries are content, so they are kept.
    """
    return " ".join(w for w in (compare_squash(part) for part in text.split()) if w)
```

In `missing_from_docx`, keep the squashed test exactly as it is and add the word test for RTL pieces. After `haystack = compare_squash(docx_body_text)` add:

```python
    # Right-to-left pieces are also looked for word by word, against the Word
    # text with its whitespace collapsed rather than removed.
    spaced = compare_words(docx_body_text)
```

Inside the per-piece counting, count RTL pieces in both forms. Replace the two loops with:

```python
    wanted = Counter()
    wanted_words = Counter()
    for line in pdf_lines:
        for piece in (line["pieces"] or [line["text"]]):
            squashed = compare_squash(piece)
            if len(squashed) >= COMPARE_MIN_CHARS:
                wanted[squashed] += 1
                if is_rtl(piece) and len(piece.split()) >= 2:
                    wanted_words[compare_words(piece)] += 1
    have = {piece: haystack.count(piece) for piece in wanted}
    have_words = {piece: spaced.count(piece) for piece in wanted_words}

    missing = []
    for line in pdf_lines:
        raw_pieces = line["pieces"] or [line["text"]]
        pieces = [compare_squash(piece) for piece in raw_pieces]
        looked_for = [p for p in pieces if len(p) >= COMPARE_MIN_CHARS]
        word_pieces = [compare_words(piece) for piece in raw_pieces
                       if len(compare_squash(piece)) >= COMPARE_MIN_CHARS and is_rtl(piece) and len(piece.split()) >= 2]
        if (any(have.get(p, 0) < wanted[p] for p in looked_for)
                or any(have_words.get(p, 0) < wanted_words[p] for p in word_pieces)):
            missing.append(line["text"])
    return missing
```

If Step 1 found pymupdf returns RTL lines in visual order, apply the reversal on the PDF side only: in the two places `compare_words(piece)` is computed from a PDF piece, use `compare_words(" ".join(reversed(piece.split())))`, and add a `check` pinning that a reversed PDF line matches the logical Word text.

Also extend the docstring of `missing_from_docx` with one paragraph on the RTL word test and why.

- [ ] **Step 4: Run the checks**

Run: `$PY -I -B test_convert.py`
Expected: all `rtl:` checks `ok`. The corpus tier will now FAIL for the RTL documents whose spaces are lost (they now fall back and still miss lines). Move them into `corpus.EXPECTED_FAILURES` with reason `"RTL spaces lost by pdf2docx (Task 8)"`. Every other check, including the reference cases, stays `ok`: a left-to-right document takes no new path.

- [ ] **Step 5: Commit**

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/test_convert.py server/typst/pdf-to-docx/corpus.py
git commit -m "Compare a right-to-left line word by word, so lost spaces are caught"
```

---

### Task 8: Put the spaces back in right-to-left text, and mark its direction

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py`
- Modify: `server/typst/pdf-to-docx/test_convert.py`, `corpus.py`

**Interfaces:**
- Consumes: `is_rtl`, `compare_squash`, `compare_words` (Task 7); `body_paragraphs(document)` (line 1533), `paragraph_text(element)` (1542).
- Produces: `convert.respace(run_texts, pdf_text) -> list[str] | None` (pure); `convert.restore_rtl(document, rtl_lines, declined) -> int` (paragraphs repaired); `look["rtl"]` (list of PDF RTL line texts).

- [ ] **Step 1: Write the failing checks for the pure function**

Add to `run_rtl_check_checks` (before the typst section):

```python
    passed &= check(convert.respace(["أجرىفريقنا", "تقييمًا"], "أجرى فريقنا تقييمًا") == ["أجرى فريقنا ", "تقييمًا"],
                    "respace: a space goes back inside a run and at a run boundary",
                    convert.respace(["أجرىفريقنا", "تقييمًا"], "أجرى فريقنا تقييمًا"))
    passed &= check(convert.respace(["أجرى فريقنا"], "أجرى فريقنا") == ["أجرى فريقنا"],
                    "respace: a run that already has its spaces is unchanged")
    passed &= check(convert.respace(["شيء آخر"], "أجرى فريقنا") is None,
                    "respace: text that does not match the line is left alone")
    passed &= check(convert.respace(["SQLinjection", "חולשת"], "חולשת SQL injection") is None,
                    "respace: a different word order is not guessed at")
```

Run: `$PY -I -B test_convert.py`
Expected: `AttributeError: ... 'respace'`.

- [ ] **Step 2: Implement `respace`**

After `compare_words` in `convert.py`:

```python
def respace(run_texts, pdf_text):
    """The runs of one paragraph with the PDF line's word spaces put back.

    Walks the PDF line and the runs together, character by character, over
    their squashed forms (so invisibles and dashes do not break the walk).
    Where the PDF has whitespace and the runs do not, a space is inserted in
    the run the next word starts in, at the end of the run before when the
    boundary falls between two runs. Returns None when the runs' letters are
    not exactly the PDF line's letters in the same order: that is a different
    line, or a re-ordered one, and guessing would write spaces into the wrong
    words.
    """
    if compare_squash("".join(run_texts)) != compare_squash(pdf_text):
        return None
    # Positions in the concatenated run text after which a space belongs.
    joined = "".join(run_texts)
    want_space_before = set()
    j = 0
    pending = False
    for ch in pdf_text:
        if ch.isspace():
            pending = True
            continue
        if not compare_squash(ch):
            continue
        while j < len(joined) and not compare_squash(joined[j]):
            j += 1
        if j >= len(joined):
            return None
        if pending and j > 0 and not joined[j - 1].isspace():
            want_space_before.add(j)
        pending = False
        j += 1
    if not want_space_before:
        return list(run_texts)
    out, offset = [], 0
    for index, text in enumerate(run_texts):
        pieces = []
        for k, ch in enumerate(text):
            if offset + k in want_space_before and k > 0:
                pieces.append(" ")
            pieces.append(ch)
        rebuilt = "".join(pieces)
        # A boundary at the very start of this run goes at the end of the
        # previous one, so the run's own formatting is not stretched.
        if offset in want_space_before and index > 0:
            out[-1] = out[-1] + " "
        out.append(rebuilt)
        offset += len(text)
    return out
```

Run: `$PY -I -B test_convert.py`
Expected: the four `respace:` checks `ok`. The first expects `["أجرى فريقنا ", "تقييمًا"]`: the boundary between the two runs is written at the end of the first run.

- [ ] **Step 3: Write the failing document check**

Add to the typst part of `run_rtl_check_checks`, after the stripped-file check:

```python
        result = convert.convert(pdf, converted, font_dirs=corpus.font_dirs())
        passed &= check(result["textCheck"]["missing"] == 0 and not result["textCheck"]["fellBack"],
                        "rtl: the Arabic document keeps every word apart at the top rung", result["textCheck"])
        with zipfile.ZipFile(converted) as archive:
            xml = archive.read("word/document.xml").decode("utf-8")
        passed &= check("<w:bidi" in xml and "<w:rtl" in xml,
                        "rtl: its paragraphs and runs are marked right-to-left")
```

Run: `$PY -I -B test_convert.py`
Expected: both new checks `FAIL`.

- [ ] **Step 4: Implement `restore_rtl` and wire it in**

After `respace`:

```python
def restore_rtl(document, rtl_lines, declined):
    """Put the word spaces back in right-to-left paragraphs and mark them RTL.

    `rtl_lines` is the PDF's right-to-left line texts. Each Word paragraph
    whose text is right-to-left is matched to the PDF line with the same
    squashed letters; its runs get the PDF's spaces through respace, the
    paragraph gets w:bidi and each run w:rtl, so Word sets it right-to-left.
    A paragraph that matches no line (pdf2docx merged or split lines) is left
    alone and counted as declined, never guessed at.
    """
    by_squash = {}
    for text in rtl_lines:
        by_squash.setdefault(compare_squash(text), text)
    repaired = 0
    for paragraph in body_paragraphs(document):
        text = paragraph_text(paragraph)
        if not text or not is_rtl(text):
            continue
        runs = [r for r in paragraph.iter(W_NS + "r")]
        texts = [r.find(W_NS + "t") for r in runs]
        pairs = [(r, t) for r, t in zip(runs, texts) if t is not None and t.text]
        line = by_squash.get(compare_squash("".join(t.text for _, t in pairs)))
        rebuilt = respace([t.text for _, t in pairs], line) if line else None
        if rebuilt is None:
            declined["rtl-respace"] += 1
            continue
        for (run, node), value in zip(pairs, rebuilt):
            node.text = value
            node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            props = run.find(W_NS + "rPr")
            if props is None:
                props = run.makeelement(W_NS + "rPr", {})
                run.insert(0, props)
            if props.find(W_NS + "rtl") is None:
                props.append(props.makeelement(W_NS + "rtl", {}))
        ppr = paragraph.find(W_NS + "pPr")
        if ppr is None:
            ppr = paragraph.makeelement(W_NS + "pPr", {})
            paragraph.insert(0, ppr)
        if ppr.find(W_NS + "bidi") is None:
            ppr.insert(0, ppr.makeelement(W_NS + "bidi", {}))
        repaired += 1
    return repaired
```

Before writing it, read `body_paragraphs` and `paragraph_text` (lines 1533 to 1545) and the existing `set_flag`/`flag_of` helpers (4051 to 4066): if they already create `rPr`/`pPr` children in schema order, use them instead of the inline `makeelement` calls above (Word refuses a file whose property children are out of order, see `docs/typst-tab-2026-09.md` "Word refuses to open a file whose property elements are out of order"). `w:bidi` sits early in `pPr` (after `pStyle`, `keepNext`, `keepLines`, `pageBreakBefore`, `framePr`, `widowControl`, `numPr`, `suppressLineNumbers`, `pBdr`, `shd`, `tabs`, `suppressAutoHyphens`, `kinsoku`, `wordWrap`, `overflowPunct`, `topLinePunct`, `autoSpaceDE`, `autoSpaceDN`); `w:rtl` sits after `w:cs` and `w:em`-group items near the end of `rPr`. Insert at the position that keeps that order; the file must open in Word.

In `convert()`, where the other `look` inputs are read (next to `aligned = flush_left_runs(...)`):

```python
        rtl_lines = [line["text"] for line in body_lines(doc, []) if is_rtl(line["text"])]
```

Add `"rtl": rtl_lines` to `look`. In `decorate_document`, directly before `repair_text(...)`:

```python
    if look.get("rtl"):
        restore_rtl(document, look["rtl"], look["declined"])
```

(`restore_rtl` is text repair, not layout, so it runs at every rung including `place=False`; `--raw` does not run `decorate_document` and so leaves pdf2docx's own output for the baseline.)

Then make the layout passes decline RTL paragraphs, in `convert()` right after `aligned = flush_left_runs(...)`:

```python
        kept = []
        for run in aligned:
            if any(is_rtl(line["text"]) for line in run["lines"]):
                declined["align-rtl"] += 1
            else:
                kept.append(run)
        aligned = kept
```

Check `flush_left_runs`' `lines` entries carry `"text"` (they are `page_rows` rows); if the key differs, use it. `aligned` feeds both `align_paragraphs` and `force_line_breaks`, so both now leave RTL paragraphs alone.

- [ ] **Step 5: Run everything**

Run: `$PY -I -B test_convert.py`
Expected: all `rtl:` checks `ok`. Remove the RTL documents from `corpus.EXPECTED_FAILURES` that now pass (the tier fails on a listed document that passes, which is the reminder). Open `rtl-arabic`'s converted file in Word once by hand (`compare.ps1 -Source corpus\rtl-arabic -Out ..\..\..\.scratch\ar -Fonts corpus\fonts,..\..\..\dist\fonts`) and confirm it opens without a repair prompt and reads right-to-left.

- [ ] **Step 6: Re-run the scorecard for the RTL documents and commit**

Run: `$PY -I -B scorecard.py --only rtl-arabic,rtl-mixed,rtl-in-shapes --out ..\..\..\.scratch\scorecard-rtl`
Expected: no rule-1 violation on the three; if rule 3 or 4 fires, the passes that still touch RTL content need a decline, found with `--skip` as in Task 9.

Add the run to `corpus/SCORECARD.md` under a new `## <date>: right-to-left spaces` heading.

```bash
git add server/typst/pdf-to-docx/convert.py server/typst/pdf-to-docx/test_convert.py \
  server/typst/pdf-to-docx/corpus.py server/typst/pdf-to-docx/corpus/SCORECARD.md
git commit -m "Put the word spaces back in right-to-left text and mark its direction"
```

---

### Task 9: Triage: every document at least as good as raw

This task repeats once per violation in the baseline scorecard. Its code is not knowable until the scorecard has run; the procedure and the shape of each fix are fixed.

**Files:**
- Modify: `server/typst/pdf-to-docx/convert.py`, `cases.py`, `test_convert.py`, `corpus.py`, `corpus/SCORECARD.md`

**Interfaces:**
- Consumes: `look["declined"]` / `declined` Counter (Task 1), `--skip`, `scorecard.py --only --skip`.

For each violation row in the latest `SCORECARD.md`, most severe first (error, then 1, 2, 4, 3, 6):

- [ ] **Step 1: Find the pass**

Run the document with one pass skipped at a time until the violation disappears:

```powershell
foreach ($p in "bands","toc","panels","swatches","align","pictures","line-breaks","text-repair","hyphens","pitch-cut","rhythm") {
  & $PY -I -B scorecard.py --only <doc> --skip $p --out ..\..\..\.scratch\bisect-$p | Select-String "<doc>"
}
```

Note which single skip clears it (if none does, try pairs starting with `pitch-cut,rhythm` and `align,line-breaks`, which depend on each other). Open the contact sheet and overlay for the worst page from the full run (`<out>\<doc>-full-worst.png`) and describe what the pass did wrong in one sentence.

- [ ] **Step 2: Reduce it to a case**

Write the smallest Typst source that shows the same shape and add it to `cases.py` as a new constant with a comment in the file's style (what shape, what the pass did, what must happen instead). Add a check in `run_documents` in `test_convert.py` that converts it and asserts the pass declined, for example:

```python
        result, path = run_case(cases.<NEW_CASE>, workdir, "<new-case>")
        passed &= check(result["declined"].get("<pass>-<reason>", 0) > 0,
                        "<new-case>: <pass> declines <shape>", result["declined"])
        passed &= check(result["textCheck"]["missing"] == 0, "<new-case>: no line lost", result["textCheck"])
```

Run `test_convert.py`; the `declined` check must FAIL.

- [ ] **Step 3: Add the detector**

In the pass's function, detect the shape and skip it, counting the decline. The pass functions do not all receive `look`; thread the `declined` Counter through as a keyword argument defaulting to `None` (and guard `if declined is not None:`), passed from `decorate_document` as `look["declined"]`. The detector must be cheap (a check over data the pass already has); a detector that reads the PDF again goes in `convert()` next to the other `look` inputs instead. Name the counter `<pass>-<reason>`, e.g. `rhythm-two-column`.

Do not change a shared threshold (the constants block at the top of `convert.py`) unless the shape cannot be told apart any other way; if you do, the whole corpus, the reference report and every existing case must still pass, and the commit message says which constant moved and why.

- [ ] **Step 4: Prove it**

Run: `$PY -I -B test_convert.py` (exit 0), then `$PY -I -B scorecard.py --out ..\..\..\.scratch\scorecard-<doc>-fix --reference-pdf <pdf> --reference-fonts <dir>` over the WHOLE corpus, not just the document.
Expected: the violation is gone, no new violation appears anywhere, the reference row still passes rule 5. If another document got worse, the detector is too broad: narrow it and repeat.

- [ ] **Step 5: Record and commit**

Append the run to `corpus/SCORECARD.md` under `## <date>: <pass> declines <shape>`. Update `EXPECTED_FAILURES` if a Word-free failure was fixed.

```bash
git add server/typst/pdf-to-docx
git commit -m "<Pass> declines <shape>, which <what it did wrong>"
```

Repeat Steps 1 to 5 until the scorecard exits 0.

---

### Task 10: Gains, time-boxed

**Files:** as Task 9.

- [ ] **Step 1: Pick the candidates**

From the latest scorecard, list documents where full's mean beats raw's by less than 0.01. For each, open the full run's worst-page overlay and write one sentence naming the largest visible difference.

- [ ] **Step 2: One change at a time**

For each difference that is general (would apply to other documents of that shape, not only this one), implement it as a pass change with a case in `cases.py` and a check, exactly as Task 9 steps 2 to 4, judged by the same rule over the whole corpus.

- [ ] **Step 3: Stop condition**

Stop when a change moves the corpus mean (mean of the per-document means, reference included) by less than 0.002, as the last round stopped. Record every attempt in `SCORECARD.md`, including the ones reverted, with their numbers, under `## <date>: gains`.

- [ ] **Step 4: Commit each kept change separately** with a message naming the shape and the gain.

---

### Task 11: Docs and final verification

**Files:**
- Modify: `docs/typst-tab-2026-09.md`, `README.md`, `CLAUDE.md`

- [ ] **Step 1: The results section**

Append to `docs/typst-tab-2026-09.md` a section `### Fidelity, part nine: other people's documents`, in the file's existing first-person style (read part eight first): why the corpus exists; the baseline table (from `SCORECARD.md`); each decline added, with the shape and the numbers before and after; the RTL finding from Task 7 step 1 and the fix; the noise figure; what is still out, precisely; and a "Measured and reverted" list from Task 10.

- [ ] **Step 2: README**

In the README's DOCX/pdf-to-docx section (search for `PDF2DOCX_PYTHON`, around line 939, and the `pdf2docx-venv` notes around 1393): add the venv command from Task 1 step 1, the corpus (`corpus/`, what the four categories are, `EXPECTED_FAILURES`), `scorecard.py` usage including `--reference-pdf/--reference-fonts` and `--noise`, `render_word.ps1`, `compare.ps1 -Raw -Skip`, the two `convert.py` dev flags with the statement that the server never passes them, and the rule. Update the Table of Contents anchor if a heading is added.

- [ ] **Step 3: CLAUDE.md**

In invariant #18, after the sentence about the converter verifying that the Word file still contains every line of the PDF's text, add: `A converter pass must also not make any document in \`server/typst/pdf-to-docx/corpus/\` score below raw pdf2docx on \`scorecard.py\`; a pass that hurts a shape gets a detector that declines it (counted in \`result.json\` \`declined\`), not a retuned threshold. Right-to-left lines are compared word by word, because squashing whitespace hid pdf2docx dropping their spaces.` In the Commands section, add one line for `scorecard.py` and the venv next to the existing converter notes. Mention that `.dockerignore` keeps the corpus out of the image.

- [ ] **Step 4: Final verification**

```bash
cd server/typst/pdf-to-docx
$PY -I -B test_convert.py; echo "test_convert exit $?"
$PY -I -B test_scorecard_rules.py; echo "rules exit $?"
$PY -I -B scorecard.py --out ../../../.scratch/scorecard-final --reference-pdf <pdf> --reference-fonts <dir>; echo "scorecard exit $?"
cd ../../..
bun run test
bun run build
EM=$(printf '\342\200\224')
for f in README.md CLAUDE.md docs/typst-tab-2026-09.md server/typst/pdf-to-docx/*.py server/typst/pdf-to-docx/*.ps1 server/typst/pdf-to-docx/corpus/SCORECARD.md; do printf "%s " "$f"; grep -c "$EM" "$f"; done
grep -l typst_ts_web_compiler dist/assets/index-*.js || echo "entry bundle clean"
docker build --build-arg WITH_REPORT_BINS=0 -t btct-corpus-check . && docker run --rm btct-corpus-check ls /app/server/typst/pdf-to-docx
```

Expected: all three Python runs exit 0; `bun run test` shows the same pass count as before this plan (592 tests at last record); `bun run build` succeeds; every em-dash count is 0; `entry bundle clean`; the image listing shows no `corpus` directory.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md docs/typst-tab-2026-09.md
git commit -m "Docs: the Word export scored on other people's documents"
```
