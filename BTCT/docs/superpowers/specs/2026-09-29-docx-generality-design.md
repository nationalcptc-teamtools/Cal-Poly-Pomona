# The Word export for any Typst document: design

Date: 2026-09-29. Branch: `lw-version`. Status: approved design, no code yet. Runs before the report MCP server ([2026-09-29-typst-mcp-design.md](2026-09-29-typst-mcp-design.md)).

## Why

Every fidelity number the Word export has (mean 0.9151, 23 pages in Word against 23 in the PDF) was measured on one document, the owner's CPTC report. The layout passes in `server/typst/pdf-to-docx/convert.py` (line breaks, paragraph and cell placement, contents-page leaders, code panels as tables, the leading cut) are heuristics tuned against that template. On any other template nobody knows whether they help, do nothing, or make the file look worse than plain pdf2docx would have. The fallback ladder protects text and nothing else, so a pass that places blocks badly in someone else's layout ships without a word.

The export will be used for other pentest report templates, academic papers and theses, plain documents, and right-to-left or mixed-script content. The one known correctness bug is in the last group: pdf2docx runs an Arabic or Hebrew line together, and the text check cannot see it.

## Outcome

- A corpus of varied Typst documents, each scored against the PDF with the full converter and with plain pdf2docx.
- No document scores below plain pdf2docx, and the owner's report does not regress.
- Right-to-left text keeps its word spaces, and the text check fails when it does not.

Unchanged: every line of the PDF's text in the Word file, the fallback ladder, font naming and carrying, unsafe-link removal, the redaction path, the time budget and every limit in `export.mjs`.

Rejected approaches: making the layout passes opt-in for documents that look like the reference template (every other document would get plain pdf2docx quality forever), and a second route for simple documents such as typst HTML through pandoc (measured before and rejected: every piece of styling gone, and two routes mean two sets of guarantees).

## Section 1: the corpus

`server/typst/pdf-to-docx/corpus/<name>/` holds `main.typ`, any vendored template files, a `LICENSE` for vendored material and a `README` line naming what the document stresses. Only MIT, MIT-0, Apache-2.0 and OFL material is accepted. Fonts the documents need (Arabic and Hebrew faces such as Noto Naskh Arabic and Noto Sans Hebrew, OFL) live in `corpus/fonts/` and are passed with `--font-path` and `--fonts=`, as the server passes a report's fonts.

| Category | Document | Stresses |
|---|---|---|
| Pentest | a second findings template, vendored if a permissive one exists, otherwise hand-written in a style clearly unlike the reference | finding cards, severity colours, header and footer |
| | a hand-written assessment with a landscape risk matrix and a host table spanning pages | orientation change mid-document, repeated table headers |
| | an executive letter-style summary | sparse layout, signature block, logo |
| Academic | `charged-ieee`, vendored | two columns, maths, footnotes, references |
| | a thesis chapter, hand-written | numbered figures and equations, footnotes, a local `.bib`, outline |
| | lecture notes with theorem and definition boxes | shaded boxes that are not code panels, nested lists |
| Plain | a memo | almost pure text |
| | a letter | address blocks, right-aligned date |
| | a CV, vendored (for example `basic-resume`) | sidebar and grid layout, icons |
| RTL and mixed | an Arabic report section | right-to-left paragraphs and headings |
| | Hebrew and English mixed in paragraphs and a table | direction changes inside a line |
| | an English report quoting Arabic in a code panel and a caption | right-to-left inside shapes the converter restructures |

The owner's CPTC report is the thirteenth document. It is not committed; the scorecard reads it from `../cptc-typst-report` when that folder exists and skips it otherwise.

`@preview` imports are rewritten to local paths (the export refuses package imports), and only the files a document uses are copied. Target: under 3 MB for the whole corpus with fonts. `.dockerignore` gains `server/typst/pdf-to-docx/corpus` and `server/typst/pdf-to-docx/.venv`, because the Dockerfile copies `server/typst/` whole.

## Section 2: measuring

**Dev-only switches in `convert.py`,** argv only. `export.mjs` never passes them, and a test pins that.
- `--raw`: write pdf2docx's output with nothing done to it except the unsafe-link removal, which happens on the PDF before conversion. This is the baseline.
- `--skip=<pass>,<pass>`: turn off named passes in `decorate_document` and the two band repairs (for example `line-breaks`, `rhythm`, `panels`, `pictures`, `pitch-cut`, `bands`, `toc`), to narrow a regression to one pass without editing code.

`compare.ps1` passes both through as `-Raw` and `-Skip`.

**`scorecard.ps1`.** For each corpus document, and the owner's report when present: compile once, convert full and raw, render both through Word, score both against the PDF with `compare_pages.py`. It writes `scorecard.json` and a markdown table with, per document: PDF pages and Word pages (full and raw), mean and worst structural similarity (full and raw), the pages where full lost to raw, the fallback rung used, passes declined, conversion time, and converter warnings. Contact sheets and overlays go to an uncommitted scratch folder. `corpus/SCORECARD.md` is committed and updated each round, and says that its numbers come from this machine's Word: a record, not a CI gate.

**The rule** every converter change meets before it is committed:
1. Every document converts at the top rung, or its row names why.
2. Word's page count equals the PDF's, or is no further from it than raw's.
3. Per document, full's mean structural similarity is at least raw's minus 0.002.
4. No page scores more than 0.02 below the same page in raw.
5. The owner's report keeps a mean of at least 0.9146 (0.9151 less noise).
6. No document converts in more than twice raw's time plus 2 s.

Before any of that, step 0 renders every raw file twice to measure Word's own run-to-run noise. If it exceeds 0.002, the thresholds in rules 3 to 5 widen to match and the results doc says so.

**Word-free tier.** `test_convert.py` gains one check per corpus document: it compiles and converts without error; the text check passes at the top rung; python-docx opens the file; `unsafe_docx_targets` is empty; the converter's section count is within one of the PDF's page count (a sanity bound, not rule 2). If the corpus takes `test_convert.py` past two minutes, these move behind a `--corpus` flag, decided by measurement.

## Section 3: fixing, right-to-left, docs

**Order of work.**
0. A virtualenv at `server/typst/pdf-to-docx/.venv` from `requirements.txt` with `--require-hashes`, as the image builds it.
1. Corpus and scorecard, then a baseline commit of `SCORECARD.md` before any converter change.
2. Triage. For each broken rule: narrow it with `--skip`; reduce the shape to a minimal document in `cases.py`; fix it with a detector that makes the pass decline that shape, not by retuning a shared threshold. A decline is counted in `result.json` as `declined: {pass: count}`. A shared threshold changes only when all 13 documents and every existing case still pass. One fix per commit, scorecard re-run each time.
3. Gains. Once nothing is worse than raw, look at documents where full barely beats raw for general improvements, judged by the same rule. The round stops when a change moves the corpus mean by less than 0.002.

**Right-to-left.**
- First confirm, on the RTL corpus documents, exactly what pdf2docx writes: whether spaces are lost, whether logical order and run direction survive. The fix follows the finding.
- The text check: a line whose strong characters are mostly right-to-left (`unicodedata.bidirectional` R or AL) is compared as a word sequence with spaces kept, not squashed. A negative test strips the spaces from a converted file's RTL runs and asserts the check fails; today it passes.
- The repair: restore spaces from the PDF's own word boundaries (`page.get_text("words")`), and mark those paragraphs `w:bidi` and their runs `w:rtl`.
- The layout passes decline right-to-left paragraphs unless the scorecard shows they help there.

**Docs.** `docs/typst-tab-2026-09.md` gains "Fidelity, part nine: other people's documents", with per-document before and after numbers and the declines. README: the corpus, the scorecard, the two dev flags, the venv. CLAUDE.md invariant #18 gains one sentence: a converter pass must not make any corpus document score below raw pdf2docx. Every file touched has no em dashes (the grep check in CLAUDE.md returns 0).
