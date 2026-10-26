# Word export: stress corpus and tagged header/footer lifting (stages 0 and 1)

Date: 2026-09-30. Branch: `lw-version`. Status: approved design, no code yet.

Background: [reports/Typst to DOCX export.md](../../../reports/Typst%20to%20DOCX%20export.md) (research, stages 0 to 5) and [2026-09-29-docx-generality-design.md](2026-09-29-docx-generality-design.md) (the corpus and scorecard this builds on). Stages 2 onward (a Rust reader of Typst's own layout) get their own spec.

## Why

A 57-page filled-out copy of the CPTC template exported to a Word file that Word lays out as 83 pages against the PDF's 57, mean page similarity 0.645 (the owner's real report scores 0.915). The root failure: the heuristic running-band detector refused to lift the header and footer, so they stayed in the page body, every page grew by the band's height, and content spilled into near-empty footer-only pages. Screenshots overlapping paragraphs and justified text running past the right margin were visible too.

The PDFs typst 0.14.2 writes are tagged. Probed on the reference report and the stress report: `StructTreeRoot` present, `MarkInfo /Marked true`, the running header and footer wrapped in `/Artifact` marked content with `/Subtype /Header` and `/Subtype /Footer`, and a structure tree with `Document, H1..H3, P, L/LI, Table/TR/TD, TOC/TOCI, Figure, Caption, Code, Link`. pdf2docx 0.5.13 reads none of it.

## Outcome

- Six stress reports of different lengths and templates, generated reproducibly, scored by the existing scorecard with three new measurements.
- When the PDF is tagged, the header and footer are exactly what typst marked as Header and Footer, not a guess; the contents page is rebuilt only where the tag tree has a TOC.
- Unchanged: every line of the PDF's text in the Word file, the fallback ladder, font naming and carrying, unsafe-link removal, the redaction path, the one-compile rule, every limit in `export.mjs`. Untagged PDFs keep today's behaviour exactly.

## Section 1: the stress corpus (stage 0)

All content is neutral filler: generic finding titles, placeholder prose, harmless command snippets, synthetic images drawn by the generator. Nothing resembles a real attack walkthrough.

| # | Name | Template | Size | Stresses |
|---|---|---|---|---|
| 1 | `stress-cptc-57` | CPTC | 57 pages, 19 findings, 44 images, 8 redacted | the document the owner tested |
| 2 | `stress-cptc-short` | CPTC | about 10 pages, 3 findings, 6 images | sparse pages |
| 3 | `stress-cptc-long` | CPTC | about 120 pages, 45 findings, about 95 images | length and the 120 s conversion limit |
| 4 | `stress-findings` | corpus `findings` | about 40 pages, 25 cards | a different card and table style, long summary table |
| 5 | `stress-thesis` | corpus `thesis` | about 50 pages | equations, figures, footnotes, bibliography, header from page 2 |
| 6 | `stress-assessment` | corpus `assessment` | about 30 pages | several landscape sections, long tables with repeated header rows |

**Where they live.** A committed generator, `server/typst/pdf-to-docx/stress.py`, builds each document (source, images, redaction regions) with a fixed seed into a cache directory under `.scratch/`; outputs are never committed, which keeps the corpus under its 3 MB cap. The CPTC template belongs to the owner, so documents 1 to 3 are built only when `--cptc-template <dir>` names a folder holding its `main.typ` (and `fonts/`, `assets/cover.png`), exactly as the reference report is handled; without it they are skipped. Documents 4 to 6 expand the committed corpus templates.

**Scorecard.** `scorecard.py --stress [--cptc-template <dir>]` scores the stress set the same way as the corpus (full against raw through Word, the existing rule). Redaction regions are applied by baking the images before compile, as the server does, so the redaction path is exercised.

**New measurements** (reported per document, not pass/fail rules until a baseline exists):
- `blankPages`: Word pages whose only ink is in the top or bottom 12% of the page.
- `bandInBody`: whether any text the PDF places in its running header or footer appears in the Word body (`document.xml`) rather than a header or footer part.
- `inkPastMargin`: pages where the Word render has ink beyond the PDF's right content edge plus 2 pt.
Plus the existing page counts and conversion time. Word render time is recorded too.

## Section 2: tagged bands and contents (stage 1)

**Reading the tags.** PyMuPDF cannot tell which marked-content block a span came from, so the converter does not join tags to spans. For each page it removes every `BDC` ... `EMC` block whose properties are `/Artifact` with `/Subtype /Header` or `/Subtype /Footer` (nesting-aware, operating on the page's cleaned content stream), and diffs the page's text before and after. The spans that disappeared are that page's band members, with their exact boxes.

**Where it plugs in.** `detect_band(doc, edge)` gains a tagged path taken when the catalog has `MarkInfo /Marked true` and at least one page carries a Header or Footer artifact. It returns the same band description the heuristic returns (members, zone, columns, pages, rule), so `apply_bands`, `strip_bands` callers, the PAGE field and the first-page rules are unchanged. The edited PDF (artifacts removed) becomes the input pdf2docx converts on the repaired rung, replacing the rectangle erase for tagged bands; the rectangle erase stays for heuristic bands.

**Guard.** The tagged path is used only when, on every page, every removed span lies wholly above the page's first remaining body line (header) or wholly below its last (footer). Otherwise it declines (`bands-tagged-inconsistent`) and the heuristic runs. Which path ran is counted: `bands-tagged` or `bands-heuristic`.

**Contents page.** `detect_toc` rebuilds a table of contents only when the tag tree contains a `/TOC` structure element; with no TOC element it returns nothing (`toc-untagged` when the PDF is tagged and has none). For untagged PDFs the current detector runs unchanged.

**Page breaks.** pdf2docx writes one section per PDF page. The converter verifies that the section count equals the PDF page count after conversion and, where two PDF pages were merged into one section, inserts a page break at the first paragraph whose text begins the later page. It adds nothing when the counts match.

**Safety.** The text check and the fallback ladder are unchanged: a tagged lift that loses a line sends the file down the ladder exactly as a heuristic one does. Band members found by the tagged path are excluded from the body comparison and checked in the header and footer parts, as today.

**Out of scope for stage 1:** tables from `Table/TR/TD` (needs joining tag ids to glyph positions, unverified; stage 2), justified lines past the margin (measured by `inkPastMargin`, not fixed), image overlap (measured through similarity, not fixed).

## Tests

- New `cases.py` documents: a header and footer that skip some pages; a header whose text also appears in the body; the same tagged document with its tags removed (the heuristic path must run and the result must match today's).
- A unit test of the artifact-block remover on a hand-built content stream with nested marked content.
- `test_convert.py` stays green; the corpus and the reference report must still pass the rule (reference mean at least 0.9146).
- Scorecard before and after on the six stress documents, recorded in `corpus/SCORECARD.md`, with the new measurements.

## Docs

README (the stress corpus, `--stress`, `--cptc-template`, the new measurements, the tagged path), CLAUDE.md invariant #18 (bands come from typst's Header/Footer artifacts when the PDF is tagged), `docs/typst-tab-2026-09.md` (a part ten with the before and after numbers). No em dashes.
