# Word export scorecard

Each run of `scorecard.py`, newest first. `full` is `convert.py` as the server runs it; `raw` is pdf2docx with only the font guarantees (see the plan's note). Scores are mean structural similarity per page against the PDF, rendered through this machine's Word 16, so they are a record and not a CI gate. Word's run-to-run noise, measured again on 2026-09-29 over three separate `scorecard.py --noise` runs (every raw file of the 12 corpus documents and the reference converted three times and rendered six times, in three Word sessions): 0.00000 on every document's mean, within a run and across runs, so `MEAN_TOLERANCE` stays at 0.002. Two earlier sessions did move a raw side on a byte-identical file: in one, letter (0.8952 to 0.8864), cv (0.8559 to 0.8404) and rtl-arabic (0.7643 to 0.7652); in another, the reference (0.7684 to 0.7665). In the first, Word wrote letter's page as 595.13 pt wide instead of 595.32 pt and set cv with a different word count, so that session laid the documents out differently rather than rendering them differently. A tolerance wide enough to absorb 0.0155 would let any change through; instead, a verdict that turns on a raw side moving from its value in the table below is re-run before it is believed.

## 2026-10-10: a footer strip down to the page's edge

The CPTC footer's grey strip runs to the bottom of the page, 22.3 pt tall. Word shades a paragraph over its own line only and sets a footer above the edge, so it came back 12.6 pt tall with 4.8 pt of white under it. The band now keeps the strip's vertical extent (`strip_y`); a strip that reaches the edge gives the footer no distance and an exact line as tall as the strip, with the runs raised by `w:position` onto the PDF's baseline. Measured through Word on page 4 of stress-cptc-57: strip 769.8 to 792.1 (PDF 769.7 to 792.0), baseline 784.2 (PDF 784.0). The colour was already `F3F3F3`; Word fades header and footer on screen while the body is edited.

Corpus plus the reference (`--reference-pdf`, with the template's Poppins), exit 0. Only the reference has a strip to the edge, and only the reference moved: 0.9152 to **0.9215**, 23 Word pages for 23. Every other row is identical to four places to the run below.

| document | Word full / raw | mean full / raw | verdict |
|---|---|---|---|
| reference | 23 / 44 | 0.9215 / 0.7684 | pass |

## 2026-10-10: the long report's lost lines were the PDF's

stress-cptc-long kept falling back, and the three lines it lost were blamed on its rebuilt contents page. They were not the contents page's. Its report card, 50 rows inside a `#figure`, is too tall for one page, and typst never splits a figure: rows 27 to 50 are set on top of one another at the foot of page 11, with no warning. Raw pdf2docx loses the same three lines, and so does every rung, so climbing down only threw away the lifted header and footer and cost two more conversions (269 s in all).

Two changes. `stress.py` lets the card break across pages once it has more than 26 rows (`REPORT_CARD_PAGE_ROWS`), as an author would; the 57-page and short reports have 19 and 3 rows and their source is unchanged. And `convert.py` now finds text the PDF draws on top of other text (`overprinted_boxes`, glyph by glyph), names it in the warning with its page, and puts back a rung it climbed down from when every line that rung lost is overprinted and the last rung lost it too (`better_rung`). A first version put a rung back whenever its losses recurred below, which kept rtl-mixed's top rung at 0.7817 against raw 0.7903; it was narrowed to overprinted text before this run.

The old, overprinted PDF now keeps the top rung (header and footer lifted on 117 pages, 27 contents entries rebuilt) with the three lines named as unreadable on page 11, in 250 s. The rebuilt report loses nothing:

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate. The stress job ran with the server's 105 s budget, as before.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | blank | band in body | past margin | word s | declined | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stress-cptc-long | stress | 120 | 120 / 238 | 0.7723 / 0.6400 | 0.4943 / 0.4911 | 145.0 / 121.3 | 0 | False | 15 | 32.0 | bands-tagged 1, rhythm-tall-row 6 | 4: page 11 at 0.4943 against raw 0.5375; 4: page 18 at 0.8209 against raw 0.8528 |

Before: 174 Word pages, 55 blank, the band in the body, mean 0.6444, rules 1 and 4 (36 pages). The corpus was scored again with both changes and kept the rule (exit 0). Against "corpus and reference, after tagged bands" every mean is within 0.0020, and the two that moved most moved on their raw side too, which is this Word session rather than the change: notes 0.8899 to 0.8879 (raw 0.7465 to 0.7458) and ieee 0.6234 to 0.6230 (raw 0.6241 to 0.6238). Nothing in the corpus is overprinted, so no rung of it is put back: rtl-arabic (0.7667) and rtl-mixed (0.7906) still end on their named last rung. thesis is 0.8513, as in the final review fixes.

## 2026-09-30: final review fixes

After the final review of the tagged header and footer: the coverage rule (every piece of a band on every page of that band, and never a band on one page of a longer document, else `bands-tagged-partial`), the header and footer given each to its own pages when Word has a section per PDF page (else `bands-pages-apart` and the bands stay in the body), `bands-tagged` counted only for bands that survive the page-size check (`bands-mixed-sizes` otherwise), and a failed second stripped copy that keeps the bands in the body instead of failing the export (`bands-tagged-restrip`). Two runs: the reference and thesis (`--only reference,thesis`, exit 0), and three stress documents (`--stress --only stress-cptc-57,stress-thesis,stress-assessment`, exit 1 on the same rows and verdicts as before).

- **reference** takes the tagged path and is unchanged to four places, 0.9152 against raw 0.7684, 23 Word pages. Its cover has neither band and every other page has both, so the two bands cover the same pages and the result is the same as before.
- **thesis** rose from 0.8502 to 0.8513. Its footer is on every page and its header starts on page two, and the first Word page used to get the header too, which the PDF's first page does not have. Now Word's first section carries the page-number footer and no header, and the other two carry both.
- **stress-cptc-57** is unchanged: 57 Word pages, 0.7759, the same rule 4 verdict on page 4.
- **stress-thesis** still falls back with nothing missing and the same mean. What sends it down has changed: its header also starts after its footer, pdf2docx did not write a section per page for it, and so the bands are not lifted (`bands-pages-apart`) before the contents-page loss described below is reached. It still counts `bands-tagged`, because that says which path read the document; the rung that was kept is the one with the bands in the body, as `fell back True` says.
- **stress-assessment** is unchanged as a file (0.9093, bands in the body). Its footer is a page number that sits lower on its landscape pages, so the tags now decline it (`bands-tagged-partial`), the heuristic finds the same bands, and the mixed page sizes drop them (`bands-mixed-sizes`). It no longer counts `bands-tagged`. The corpus assessment takes the same route and gains one warning ("No repeating header was found") with the same file.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | blank | band in body | past margin | word s | declined | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| thesis | academic | 3 | 3 / 4 | 0.8513 / 0.7685 | 0.7776 / 0.6059 | 15.0 / 14.6 | 0 | False | 2 | 14.1 | bands-tagged 1, rhythm-tall-row 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 14.4 / 12.7 | 0 | False | 10 | 12.1 | bands-tagged 1 | pass |
| stress-cptc-57 | stress | 57 | 57 / 112 | 0.7759 / 0.6502 | 0.5663 / 0.4872 | 57.4 / 46.4 | 0 | False | 14 | 22.7 | bands-tagged 1, rhythm-tall-row 6 | 4: page 4 at 0.6106 against raw 0.6367 |
| stress-thesis | stress | 54 | 57 / 57 | 0.6500 / 0.6498 | 0.5341 / 0.5337 | 90.1 / 59.5 | 1 | True | 29 | 19.2 | bands-pages-apart 1, bands-tagged 1 | 1: not at the top rung (0 missing, fell back True) |
| stress-assessment | stress | 31 | 31 / 31 | 0.9093 / 0.9019 | 0.8131 / 0.8106 | 58.1 / 57.9 | 0 | False | 15 | 24.8 | bands-mixed-sizes 1, bands-tagged-partial 1, rhythm-tall-row 1, toc-untagged 1 | pass |

## 2026-09-30: stress set, after tagged bands

The same six documents as the "before" run at the bottom of this file, after the tagged header and footer (`tagged.py`, `detect_tagged_bands`), the contents gate (`toc-untagged`) and `ensure_page_starts`. Every stress document counted `bands-tagged 1` in this run, but stress-assessment's bands were then dropped by the page-size check, so on that document the count named a path whose bands the file does not carry; since the final review fixes it is counted only for bands that survive that check (see the section above). stress-thesis's row comes from a second run (`--only stress-thesis`): in the full run its Word render left no scores file, an error in the harness and not in the file. The conversion itself was the same (0 missing, fell back) both times.

Before and after, full side (raw is unchanged code and moved only in its time):

| document | PDF pages | Word full before / after (raw) | mean full before / after (raw) | blank | band in body | past margin | seconds full | verdict before / after |
|---|---|---|---|---|---|---|---|---|
| stress-cptc-57 | 57 | 83 / 57 (112) | 0.6454 / 0.7759 (0.6502) | 26 / 0 | True / False | 15 / 14 | 81.5 / 51.8 | rules 1, 3, 4 (22 pages) / rule 4, page 4 only |
| stress-cptc-short | 26 | 26 / 26 (50) | 0.8049 / 0.8049 (0.6952) | 0 / 0 | False / False | 14 / 14 | 26.8 / 22.8 | pass / pass |
| stress-cptc-long | 119 | 174 / 174 (235) | 0.6444 / 0.6444 (0.6417) | 55 / 55 | True / True | 15 / 15 | 196.3 / 161.6 | rules 1, 4 (36 pages), 6 / rules 1, 4 (36 pages) |
| stress-findings | 41 | 41 / 41 (41) | 0.8853 / 0.8907 (0.8578) | 0 / 0 | False / False | 0 / 0 | 38.2 / 28.7 | pass / pass |
| stress-thesis | 54 | 57 / 57 (57) | 0.6500 / 0.6500 (0.6498) | 1 / 1 | True / True | 29 / 29 | 107.4 / 80.5 | rule 1 / rule 1 |
| stress-assessment | 31 | 31 / 31 (31) | 0.9093 / 0.9093 (0.9019) | 0 / 0 | True / False | 15 / 15 | 59.8 / 55.6 | pass / pass |

- **stress-cptc-57**, the document the owner tested, is the one this work was for. Before, the heuristic lifted its bands, the repaired rung lost text, and the file kept was the fallback with the bands in the body. Now: 57 Word pages for 57 PDF pages (83 before), no footer-only pages (26 before), the band out of the body, mean 0.6454 to 0.7759 against raw 0.6502, at the top rung with nothing missing. The one rule it breaks is rule 4 on page 4 (0.6106 against raw 0.6367), and raw's page 4 is a page holding nothing but its footer (`CONFIDENTIAL ... 2`, raw has 112 pages), which scores higher against the PDF's full text page than a text page drawn a few points off does. Full's page 4 is the right page, the executive summary, with one line wrapped differently. `past margin` is 14: justified lines Word sets wider than the PDF, which this work measures and does not fix.
- **stress-cptc-long** is unchanged and still does not reach the top rung. The repaired rung loses 3 lines of the rebuilt contents page (the first names `Outdated software component 20Weak configuration setting 21`), so the file kept is the fallback, which keeps the band in the body: 174 pages, 55 blank. It took 161.6 s. **The server kills the converter at 120 s, so in the app this document fails to export as Word at all**; the PDF is the way through.
- **stress-thesis** falls back as it did before: the repaired rung loses the one line `Contents`, the heading of its contents page, when the contents rebuild runs with the running bands lifted (`--skip=toc` or `--skip=bands` alone keeps it, and the converter from before this work, run on the same PDF, loses the same line). So its band stays in the body on the kept rung. The time fell from 107.4 s to 80.5 s.
- **stress-assessment**'s `band in body` went from True to False, and that is the measurement changing, not the file: the document mixes page sizes (landscape sections), so the bands stay in the body on both runs ("This report mixes page sizes..."), and its tagged band texts are page numbers, which `band_in_body` ignores as shorter than 4 characters, so the False understates it. The "before" stand-in read the top and bottom 8% of the page and found more. It counts `bands-tagged 1` because the tags were read before the page-size check dropped the bands, which the final review fixes corrected: it now counts `bands-tagged-partial` and `bands-mixed-sizes` instead. stress-findings gains 0.0054 with its footer read from the tags; it also counts `toc-untagged` (its tag tree has no `/TOC`), though the heuristic found no contents page in it before either.
- `pageBreaksInserted` was 0 on every document: pdf2docx already wrote one section per page.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | blank | band in body | past margin | word s | declined | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stress-cptc-57 | stress | 57 | 57 / 112 | 0.7759 / 0.6502 | 0.5663 / 0.4872 | 51.8 / 42.2 | 0 | False | 14 | 22.3 | bands-tagged 1, rhythm-tall-row 6 | 4: page 4 at 0.6106 against raw 0.6367 |
| stress-cptc-short | stress | 26 | 26 / 50 | 0.8049 / 0.6952 | 0.6079 / 0.5133 | 22.8 / 18.7 | 0 | False | 14 | 16.1 | bands-tagged 1, rhythm-tall-row 6 | pass |
| stress-cptc-long | stress | 119 | 174 / 235 | 0.6444 / 0.6417 | 0.4687 / 0.4614 | 161.6 / 94.0 | 55 | True | 15 | 38.0 | bands-tagged 1, rhythm-tall-row 5 | 1: not at the top rung (3 missing, fell back True); 4: 36 pages, the same pages as before |
| stress-findings | stress | 41 | 41 / 41 | 0.8907 / 0.8578 | 0.8028 / 0.7870 | 28.7 / 24.1 | 0 | False | 0 | 18.1 | bands-tagged 1, toc-untagged 1 | pass |
| stress-thesis | stress | 54 | 57 / 57 | 0.6500 / 0.6498 | 0.5341 / 0.5337 | 80.5 / 55.1 | 1 | True | 29 | 24.3 | bands-tagged 1 | 1: not at the top rung (0 missing, fell back True) |
| stress-assessment | stress | 31 | 31 / 31 | 0.9093 / 0.9019 | 0.8131 / 0.8106 | 55.6 / 52.4 | 0 | False | 15 | 25.5 | bands-tagged 1, rhythm-tall-row 1, toc-untagged 1 | pass |

## 2026-09-30: corpus and reference, after tagged bands

Exit 0. The reference report takes the tagged path and is unchanged to four places: 0.9152 against raw 0.7684, 23 Word pages. Two corpus rows moved, both because a band the heuristic handled differently is now read from the tags: findings 0.9204 to 0.9282 (its footer lifted from the artifacts), and thesis 0.8538 to 0.8502, still 0.08 over raw, because its running header, which the heuristic declined to lift ("could not be told apart from the body on enough pages"), is now lifted into a Word header; each of its three pages lost 0.001 to 0.007. In this run the first Word page got that header too, although the PDF's first page has only the page-number footer; since the final review fixes the first page gets the footer and no header (0.8513, see that section). Ten documents count `toc-untagged` and none of them had a rebuilt contents page before. Corpus mean 0.8352 to 0.8355; raw 0.7902.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | blank | band in body | past margin | word s | declined | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.8239 / 0.7689 | 0.8239 / 0.7689 | 7.2 / 7.1 | 0 | False | 1 | 11.4 | toc-untagged 1 | pass |
| letter | plain | 1 | 1 / 1 | 0.8987 / 0.8952 | 0.8987 / 0.8952 | 6.9 / 6.8 | 0 | False | 1 | 11.4 | toc-untagged 1 | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.3 / 1.3 | 0 | False | 1 | 11.5 | toc-untagged 1 | pass |
| ieee | academic | 2 | 2 / 2 | 0.6234 / 0.6241 | 0.6167 / 0.6169 | 16.8 / 16.4 | 0 | False | 2 | 10.3 | align-earlier-line 1, toc-untagged 1 | pass |
| thesis | academic | 3 | 3 / 4 | 0.8502 / 0.7685 | 0.7776 / 0.6059 | 13.3 / 14.4 | 0 | False | 2 | 12.0 | bands-tagged 1, rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8899 / 0.7465 | 0.8899 / 0.7465 | 15.9 / 16.0 | 0 | False | 1 | 12.1 | rhythm-tall-row 1, toc-untagged 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9282 / 0.8085 | 0.8832 / 0.6979 | 1.5 / 1.5 | 0 | False | 0 | 10.5 | bands-tagged 1, toc-untagged 1 | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8690 / 0.8616 | 0.7634 / 0.7632 | 14.8 / 14.8 | 0 | False | 5 | 11.4 | bands-tagged 1, rhythm-tall-row 3, toc-untagged 1 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.3 / 1.2 | 0 | False | 0 | 11.4 | toc-untagged 1 | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7667 / 0.7643 | 0.7667 / 0.7643 | 1.9 / 1.2 | 1 | False | 1 | 11.5 | align-rtl 3, bands-tagged 1, rtl-reorder-plain-rung 3, rtl-respace 10, toc-untagged 1 | named: RTL: pdf2docx drops letters from the Arabic table's cells (4 rows), which sends it to the last rung, where lines pdf2docx wrote in page order may not be reordered |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.6 / 1.4 | 0 | False | 0 | 10.4 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 8, toc-untagged 1 | named: RTL: pdf2docx cuts one Hebrew line into pieces around its English terms, which sends it to the last rung, where lines pdf2docx wrote in page order may not be reordered |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.9092 / 0.8819 | 0.9092 / 0.8819 | 6.8 / 7.4 | 0 | False | 1 | 9.8 | panels-partial 1, rtl-mixed-run 1, toc-untagged 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 14.0 / 11.9 | 0 | False | 10 | 15.4 | bands-tagged 1 | pass |

## 2026-09-29: final review fixes

What changed, from the whole-branch review:

- **Numbers beside right-to-left words in an English line.** The bidi algorithm draws a number that follows a Hebrew phrase to the phrase's left, so `Server שרת ראשי 12` and `Server 12 שרת ראשי` look the same on the page. The repair took the page's order for the reading and wrote the guess into Word, and the text check, reading the same way, passed it. Such a line is now read as the page shows it and declined by the repair (`rtl-ambiguous-number`), so pdf2docx's text stands and the check judges it. Case: `cases.RTL_AMBIGUOUS_NUMBERS`, three lines, all three declined; the conversion now names 3 missing lines instead of certifying the guess. No corpus document has the shape, so no row moved for it.
- **Arabic-Indic digits.** PyMuPDF hands typst's `١٢` back as `٢١` (the glyphs are drawn from the right, like the letters around them) and `٥٠٪` as `٠٥` with the `٪` attached elsewhere; pdf2docx writes the same. The logical reading now puts each run of digits in the order of its glyphs' left edges, so the check reads `١٢` and a Word file holding `٢١` fails it and is named. European digits were already in order. Case: `cases.RTL_ARABIC_DIGITS`. rtl-arabic's single-digit table numbers are unaffected.
- **The last rung marks runs, not paragraphs.** It used to add `w:bidi` and mirror the paragraph's indents and alignment, which is a move. The mark alone, without the mirroring, put rtl-arabic at 0.7621 against raw 0.7643 (rule 3) in `.scratch\scorecard-finalfix-rtl`; with no paragraph mark on that rung it is 0.7667, and rtl-mixed 0.7905 either way. The rungs above still mark and mirror.
- **`declined` is the kept rung's.** It used to add up every rung tried. rtl-arabic's `rtl-respace` 17 and rtl-mixed's 11 in the table below were two rungs summed; they are 10 and 8 now. `--raw` reports none (it used to carry `align-rtl`). `page-order-fallthrough` counts a pdf2docx whose blocks the page-order wrapper could not sort; none here.
- **scorecard.py** reads `corpus.EXPECTED_FAILURES`: a listed document that misses the top rung prints `named: <reason>` and is not a rule 1 violation; rules 2 to 6 still apply. This is the first full run to exit 0.

Corpus mean 0.8358 to 0.8352 (rtl-arabic 0.7746 to 0.7667, the paragraph mark it no longer gets on the last rung); raw 0.7902. Reference 0.9152, 23 pages.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.8239 / 0.7689 | 0.8239 / 0.7689 | 6.8 / 7.0 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.8987 / 0.8952 | 0.8987 / 0.8952 | 6.5 / 6.5 | none | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.4 / 1.4 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6234 / 0.6241 | 0.6167 / 0.6169 | 16.1 / 16.4 | align-earlier-line 1 | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 11.8 / 13.8 | rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8899 / 0.7465 | 0.8899 / 0.7465 | 15.3 / 15.0 | rhythm-tall-row 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.5 / 1.5 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8690 / 0.8616 | 0.7634 / 0.7632 | 13.7 / 14.2 | rhythm-tall-row 3 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.3 / 1.2 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7667 / 0.7643 | 0.7667 / 0.7643 | 2.2 / 1.4 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 10 | named: RTL: pdf2docx drops letters from the Arabic table's cells (4 rows), which sends it to the last rung, where lines pdf2docx wrote in page order may not be reordered |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 2.4 / 1.4 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 8 | named: RTL: pdf2docx cuts one Hebrew line into pieces around its English terms, which sends it to the last rung, where lines pdf2docx wrote in page order may not be reordered |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.9092 / 0.8819 | 0.9092 / 0.8819 | 7.0 / 7.2 | panels-partial 1, rtl-mixed-run 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 15.7 / 15.0 | none | pass |

## 2026-09-29: gains

Corpus mean (the mean of the 13 per-document full means, reference included) before this round: 0.8287.

**Attempt 1, kept: the rhythm walk measures its first move against the gap Word draws.** An English-only copy of rtl-in-shapes scored 0.8749 against raw 0.9248. The converter writes an empty paragraph above a page's first heading with 23 pt of spacing after it, and the heading's own spacing before is 3 pt; Word keeps the larger, so the heading was about 2 pt from the PDF's. The walk measured the first block's move against the 3 pt alone, read 18 to 23 pt, which is over `RHYTHM_ABSOLUTE_LIMIT_PT`, decided it had not understood where the page starts, and anchored on a block further down instead, whose place in Word it can only guess (the heading, drawn 2.2 pt off). The move is now the larger of the two touching spacings after the change less the larger of the two before it. No threshold changed. Pages that now keep the page top as their anchor: memo, letter, notes, rtl-in-shapes and two pages of assessment; the reference report's pages were all anchored on the page top already and its file is unchanged. Minimal case: `cases.SPACER_ABOVE_HEADING`, checked by adding the page up the way Word lays it out and comparing the heading block's first baseline with where the walk straddles the PDF's rows (80.21 against 80.22; 79.72 against 83.0 before). The `uneven-anchor` check now runs the relative walk directly, because its letter no longer reaches it. English copy of rtl-in-shapes: 0.9521 against raw 0.9248. Corpus mean 0.8287 to 0.8358 (+0.0070). memo 0.7965 to 0.8239, notes 0.8573 to 0.8899, rtl-in-shapes 0.8814 to 0.9092, assessment 0.8624 to 0.8690; letter 0.9018 to 0.8987 (raw 0.8952), because its page no longer falls back to the converter's spacing through the `rhythm-uneven-anchor` decline.

**Attempt 2, reverted: the alignment pass leaves a paragraph that starts before its run.** ieee was the one document where full was below raw (0.6227 against 0.6241), and `--skip align` alone brought it to 0.6238 (every other pass skipped one at a time left it at 0.6227 or 0.6229). The pass finds runs of lines that start at the text area's left edge and sets each matching paragraph flush left with no first-line indent. An IEEE paragraph indents its first line, so the run is its other lines, and the pass zeroed the indent the converter had read: every first line moved 9 to 10 pt left. The first version declined any paragraph that holds text before its run's first line: ieee 0.6238, rtl-in-shapes 0.9094, but assessment fell from 0.8690 to 0.8656, because a heading the converter joined to the paragraph under it is the same shape and there the pass helps. Declines: ieee 4, notes 2, assessment 2, the reference 2 (its mean unchanged), exec-letter 1, rtl-in-shapes 1. Corpus mean 0.8358 to 0.8356 (-0.0002).

**Attempt 3, kept: the same decline, only where the PDF's line just above the run is an indented first line.** That is, the line on the next row up starts more than `JUSTIFY_EDGE_PT` and at most `FIRST_LINE_INDENT_MAX_PT` (36 pt, new) in from the edge. Only ieee declines (1); every other document's row is unchanged to four places, the reference included (0.91522). ieee 0.6227 to 0.6234 against raw 0.6241, closer to raw but still under it, inside the tolerance. The other three paragraphs the first version declined are not this shape as the rows read, and the 0.0004 they were worth is left. Minimal case: `cases.INDENTED_FIRST_LINE`, checked by the decline and by every paragraph keeping its first-line indent (15.7 pt; 0 before). Corpus mean 0.83576 to 0.83582 (+0.00005).

**Stop.** Attempt 3 moved the corpus mean by less than 0.002, so the round ends there. Corpus mean for the round: 0.8287 to 0.8358. Candidates left, with what was seen:
- exec-letter (full equals raw, 0.7381): the page opens with a logo in a paragraph whose line height is `auto`, which the rhythm walk cannot model, so the walk stops at the second block and the whole page stays 4.3 pt low in Word. Needs a model of an automatic line holding an inline picture.
- exec-letter: pdf2docx draws the four rounded severity boxes as one table with a black rule above and an orange rule below instead of four boxes.
- letter lost 0.0031 of its previous full mean in attempt 1 (0.9018 to 0.8987, raw 0.8952) though every line in Word's PDF is within 0.4 pt of the PDF's vertically; the loss is not in the vertical placement.
- cv (0.8589 against 0.8559): the sidebar's name and title sit 5.2 and 3.1 pt high in both full and raw, which no pass touches.
- ieee: the three other paragraphs attempt 2 declined (0.0004 of mean).

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.8239 / 0.7689 | 0.8239 / 0.7689 | 6.7 / 6.8 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.8987 / 0.8952 | 0.8987 / 0.8952 | 6.9 / 6.8 | none | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.2 / 1.2 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6234 / 0.6241 | 0.6167 / 0.6169 | 16.1 / 16.2 | align-earlier-line 1 | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 15.7 / 15.6 | rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8899 / 0.7465 | 0.8899 / 0.7465 | 18.4 / 17.5 | rhythm-tall-row 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.8 / 1.7 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8690 / 0.8616 | 0.7634 / 0.7632 | 14.9 / 15.8 | rhythm-tall-row 3 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.3 / 1.4 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.8 / 1.5 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.5 / 1.4 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.9092 / 0.8819 | 0.9092 / 0.8819 | 6.6 / 7.0 | panels-partial 1, rtl-mixed-run 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 13.4 / 12.2 | none | pass |

## 2026-09-29: the right-to-left repair declines to mark a run that holds English

Found while looking at rtl-in-shapes: its HTTP request's last line, `comment=مرحبا بالعالم<script>alert(1)</script>`, is one run in pdf2docx's file, and the right-to-left repair marked every run holding an Arabic letter `w:rtl`, which lays the whole run out right to left, English included. Word showed the payload as `<script>alert(1)</script>بالعالم مرحبا=comment`. The text check could not see it, because the characters are all there in order; only the display order was wrong. Now a run with both right-to-left and left-to-right letters is left unmarked, so Word's own bidi algorithm orders it as the PDF did, counted as `rtl-mixed-run`. Minimal case: `cases.RTL_IN_CODE`, checked by reading the Word file for any `w:rtl` run with an English letter in it. rtl-in-shapes: 0.881374 against raw 0.881919 unrounded (0.881455 before this change). The raw sides are back to the previous run's values, which confirms the last run's raw movement was Word's.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 6.7 / 6.5 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.9018 / 0.8952 | 0.9018 / 0.8952 | 6.5 / 6.2 | rhythm-uneven-anchor 1 | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.6 / 1.3 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 14.4 / 13.7 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 11.2 / 11.2 | rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8573 / 0.7465 | 0.8573 / 0.7465 | 15.4 / 13.7 | rhythm-tall-row 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 2.2 / 1.6 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8624 / 0.8616 | 0.7634 / 0.7632 | 11.9 / 12.9 | rhythm-tall-row 3 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.3 / 1.3 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.7 / 1.4 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.5 / 1.4 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8814 / 0.8819 | 0.8814 / 0.8819 | 6.4 / 9.5 | panels-partial 1, rtl-mixed-run 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 17.8 / 15.7 | none | pass |

## 2026-09-29: panels declines a panel the converter coloured in part

rtl-in-shapes passed rule 3 only by rounding: unrounded, full 0.879864 against raw 0.881919, a floor of 0.879919. Scored unrounded with one pass skipped at a time, `--skip panels` (0.881455) and `--skip align` (0.880074) each cleared it, and `--skip rtl` did not (0.879897). pdf2docx colours the first three lines of the HTTP request itself, as cells of tables of their own, and leaves its body line bare; the panel pass found only that bare line to paint and shaded it as a stripe of its own. Now a panel some of whose paragraphs the converter has already coloured is left to the converter, counted as `panels-partial`. Minimal case: `cases.PANEL_PARTLY_SHADED` (English only: the shape is not about right-to-left text). rtl-in-shapes is now 0.881455 against 0.881919 unrounded, 0.0015 clear of the floor.

This run's raw side moved on letter (0.8952 to 0.8864), cv (0.8559 to 0.8404) and rtl-arabic (0.7643 to 0.7652) with byte-identical raw `document.xml` (checked on letter and cv), so Word rendered the same file differently from the previous run. Every full side is unchanged at four places. That is more run-to-run noise than the 2026-09-29 noise measurement found, and it only ever helped full's verdict here, so no verdict in this table depends on it.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 6.7 / 6.6 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.9018 / 0.8864 | 0.9018 / 0.8864 | 6.7 / 6.6 | rhythm-uneven-anchor 1 | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8404 | 0.8589 / 0.8404 | 1.4 / 1.4 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 19.6 / 18.8 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 15.2 / 15.5 | rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8573 / 0.7465 | 0.8573 / 0.7465 | 21.9 / 17.6 | rhythm-tall-row 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.4 / 1.4 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8624 / 0.8616 | 0.7634 / 0.7632 | 17.7 / 18.6 | rhythm-tall-row 3 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.3 / 1.5 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7652 | 0.7746 / 0.7652 | 1.9 / 1.8 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.7 / 1.4 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8815 / 0.8819 | 0.8815 / 0.8819 | 11.1 / 9.4 | panels-partial 1 | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 18.1 / 14.9 | none | pass |

## 2026-09-29: rhythm declines a heading joined to the paragraph under it

assessment was 0.0029 of mean under raw, and `--skip rhythm` alone cleared it (pages 2, 3 and 5 were under raw; 5 by 0.017). On page 5 the converter wrote "5. Conclusion" and the paragraph under it as one block at 13.7 pt, the paragraph's pitch in the PDF. The rhythm pass gives a block one exact height, no smaller than the one that holds its tallest row's ascent, and for the heading that is 16.4 pt, so the six body lines were spread 2.7 pt apart each (measured on Word's own PDF: the last line 8.4 pt low). Now a block of two or more rows whose smallest safe height exceeds its PDF pitch, while the converter's own height is already that pitch, keeps what the converter wrote and the walk carries on under it, counted as `rhythm-tall-row`. The second condition is what keeps the reference report as it was: its sub-headings over one line have the same excess (16.4 against 15.7) with a converter height off the pitch, the walk helps there, and a first version without it cost the reference 0.0003 (0.9149). Each page's walk now reports only the declines of the attempt the page keeps. Minimal case: `cases.HEADING_IN_PARAGRAPH`. assessment 0.8624 against raw 0.8616; notes rose from 0.8540 to 0.8573; thesis declines one block with no change at four places. The `rhythm-uneven-anchor` decline on one page each of thesis and assessment no longer happens, because those pages now keep an absolute walk.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 6.8 / 7.0 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.9018 / 0.8952 | 0.9018 / 0.8952 | 6.7 / 6.5 | rhythm-uneven-anchor 1 | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.3 / 1.2 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 15.8 / 15.6 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 13.1 / 12.6 | rhythm-tall-row 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8573 / 0.7465 | 0.8573 / 0.7465 | 14.8 / 14.5 | rhythm-tall-row 1 | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.4 / 1.5 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8624 / 0.8616 | 0.7634 / 0.7632 | 13.7 / 13.5 | rhythm-tall-row 3 | pass |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.2 / 1.2 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.4 / 1.6 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.3 / 1.1 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8799 / 0.8819 | 0.8799 / 0.8819 | 6.6 / 6.9 | none | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 13.0 / 11.2 | none | pass |

## 2026-09-29: rhythm declines an anchor that is not on the PDF's pitch

letter lost 0.05 of mean to raw, and `--skip rhythm` alone cleared it (0.9018). The rhythm walk could not trust the page top (its first block would have moved 14.3 pt), so it anchored on the first block it recognised, the right-aligned sender's address, and assumed that block ends where the PDF's rows do. The converter sets its three lines at 13.8 pt where the PDF has 14.4 pt, so it ends 1.2 pt away, and every block under it moved by that much (measured on Word's own PDF: +1.3 pt on every line, against -0.1 to +0.3 pt with the converter's spacing). Now a page whose anchor keeps a line height off its PDF pitch by `RHYTHM_TOLERANCE_PT` or more over its lines keeps the converter's spacing, counted as `rhythm-uneven-anchor`. Minimal case: `cases.UNEVEN_ANCHOR`. It also declines one page each of thesis and assessment, with no change to their means at four places, and the reference is untouched. The switch check that expected no declines on a plain run of `cases.REPORT` now expects each decline to be named after its pass, because that case declines one too. The reference's raw side moved from 0.7684 to 0.7665 with no change to raw's code, which is Word's noise on that file.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 6.6 / 6.7 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.9018 / 0.8952 | 0.9018 / 0.8952 | 6.4 / 6.2 | rhythm-uneven-anchor 1 | pass |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.2 / 1.2 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 15.4 / 15.5 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 12.9 / 13.0 | rhythm-uneven-anchor 1 | pass |
| notes | academic | 1 | 1 / 1 | 0.8540 / 0.7465 | 0.8540 / 0.7465 | 14.9 / 14.7 | none | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.4 / 1.4 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8587 / 0.8616 | 0.7634 / 0.7632 | 13.4 / 13.6 | rhythm-uneven-anchor 1 | 3: mean 0.8587 against raw 0.8616 |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.2 / 1.3 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.4 / 1.2 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.3 / 1.1 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8799 / 0.8819 | 0.8799 / 0.8819 | 6.7 / 6.6 | none | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7665 | 0.8106 / 0.6201 | 12.9 / 11.0 | none | pass |

## 2026-09-29: pdf2docx's borderless tables start at the block above them

findings lost nine prose lines at every rung, and so does raw. No pass did it: pdf2docx read the two-piece footer ("CONFIDENTIAL ... Page 1 of 2") as a borderless table and started that table at "the block just above it", walking a list that holds the page's lines first and its bordered tables last. So the block above was the hosts table far up the page, the borderless table reached up to the finding card's border, was cut into two columns where the footer's pieces sit, and every line in between lost the words across the cut. The converter now hands that step its blocks in page order (`stream_tables_in_page_order`, not applied to `--raw`). Minimal case: `cases.FOOTER_TABLE_REACH`. findings now converts at the top rung (0.9204 against raw 0.8085, and 2 Word pages where it had 3); every other row, the reference included, is unchanged to four places. memo's row comes from a second run (`--only memo`): the first full run's Word render left no scores file for it, an error in the harness and not in the file.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 8.3 / 8.0 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.8442 / 0.8952 | 0.8442 / 0.8952 | 8.7 / 8.0 | none | 3: mean 0.8442 against raw 0.8952; 4: page 1 at 0.8442 against raw 0.8952 |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.3 / 1.3 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 20.6 / 20.8 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 16.6 / 16.0 | none | pass |
| notes | academic | 1 | 1 / 1 | 0.8540 / 0.7465 | 0.8540 / 0.7465 | 19.5 / 20.4 | none | pass |
| findings | pentest | 2 | 2 / 3 | 0.9204 / 0.8085 | 0.8681 / 0.6979 | 1.5 / 1.9 | none | pass |
| assessment | pentest | 5 | 5 / 5 | 0.8587 / 0.8616 | 0.7634 / 0.7632 | 17.8 / 17.7 | none | 3: mean 0.8587 against raw 0.8616 |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.4 / 1.3 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.6 / 1.3 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.5 / 1.3 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8799 / 0.8819 | 0.8799 / 0.8819 | 7.9 / 8.7 | none | pass |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 16.6 / 13.7 | none | pass |

## 2026-09-29: right-to-left spaces

Right-to-left text is read in reading order with only the PDF's own space glyphs, compared word by word, and written back into the Word file in that order with its spaces, `w:rtl` on its runs (with the complex-script size and weight pdf2docx leaves out) and `w:bidi` on right-to-left paragraphs (with their indents and alignment mirrored). Digits are never turned round, and a reorder is refused unless it moves only whole words and numbers with every character kept. The last rung restructures nothing, so there only whitespace is rewritten. `memo` is a left-to-right control. rtl-in-shapes now reaches the top rung. rtl-arabic (table cells that lose letters) and rtl-mixed (one Hebrew line pdf2docx cuts apart) still fall to the last rung, where their page-order lines are left as pdf2docx wrote them; both are named in `corpus.EXPECTED_FAILURES`.

Measured on the way: plain `w:bidi` cost rtl-mixed 0.005 of mean (below raw) until the indents and alignment were mirrored with it, and `w:rtl` without `w:szCs` cost rtl-in-shapes 0.0012.

Note on rule 3 for rtl-in-shapes: the table prints 0.8799 against a floor of 0.8799, but unrounded the full mean is 0.879864 against raw 0.881919, a floor of 0.879919, so it is 0.000054 short. `scorecard_rules` compares the four-place scores `compare_pages.py` stores, and calls it a pass. Without the repair (`--skip=rtl`) the same document scores 0.879897, also short of that floor, by 0.000022.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 8.3 / 7.7 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7746 / 0.7643 | 0.7746 / 0.7643 | 1.4 / 1.3 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | 1: not at the top rung (7 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7905 / 0.7903 | 0.7905 / 0.7903 | 1.4 / 1.2 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | 1: not at the top rung (7 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8799 / 0.8819 | 0.8799 / 0.8819 | 7.8 / 8.1 | none | pass |

## Baseline, 2026-09-29, before any converter change

The `reference` row is the owner's real report (23 pages). It is scored from a local PDF and is not committed.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | declined | verdict |
|---|---|---|---|---|---|---|---|---|
| memo | plain | 1 | 1 / 1 | 0.7965 / 0.7689 | 0.7965 / 0.7689 | 6.6 / 6.9 | none | pass |
| letter | plain | 1 | 1 / 1 | 0.8442 / 0.8952 | 0.8442 / 0.8952 | 6.9 / 7.1 | none | 3: mean 0.8442 against raw 0.8952; 4: page 1 at 0.8442 against raw 0.8952 |
| cv | plain | 1 | 1 / 1 | 0.8589 / 0.8559 | 0.8589 / 0.8559 | 1.3 / 1.2 | none | pass |
| ieee | academic | 2 | 2 / 2 | 0.6227 / 0.6241 | 0.6167 / 0.6169 | 16.3 / 16.4 | none | pass |
| thesis | academic | 3 | 3 / 4 | 0.8538 / 0.7685 | 0.7842 / 0.6059 | 14.4 / 13.7 | none | pass |
| notes | academic | 1 | 1 / 1 | 0.8540 / 0.7465 | 0.8540 / 0.7465 | 15.6 / 16.3 | none | pass |
| findings | pentest | 2 | 3 / 3 | 0.8095 / 0.8085 | 0.7001 / 0.6979 | 1.8 / 1.4 | none | 1: not at the top rung (9 missing, fell back True) |
| assessment | pentest | 5 | 5 / 5 | 0.8587 / 0.8616 | 0.7634 / 0.7632 | 14.6 / 14.0 | none | 3: mean 0.8587 against raw 0.8616 |
| exec-letter | pentest | 1 | 1 / 1 | 0.7381 / 0.7381 | 0.7381 / 0.7381 | 1.2 / 1.2 | none | pass |
| rtl-arabic | rtl | 1 | 2 / 2 | 0.7643 / 0.7643 | 0.7643 / 0.7643 | 1.4 / 1.2 | none | 1: not at the top rung (15 missing, fell back True) |
| rtl-mixed | rtl | 1 | 1 / 1 | 0.7906 / 0.7903 | 0.7906 / 0.7903 | 1.4 / 1.1 | none | 1: not at the top rung (2 missing, fell back True) |
| rtl-in-shapes | rtl | 1 | 1 / 1 | 0.8799 / 0.8819 | 0.8799 / 0.8819 | 6.9 / 6.6 | none | 1: not at the top rung (1 missing, fell back True) |
| reference | reference | 23 | 23 / 44 | 0.9152 / 0.7684 | 0.8106 / 0.6241 | 14.3 / 12.4 | none | pass |

## 2026-09-30: stress set, before tagged bands

Six generated documents (`stress.py`, run with `scorecard.py --stress --cptc-template <owner template>`), converted full and raw, rendered through Word. Four new columns are reported numbers, not rules: `blank` (Word pages with ink only in the top or bottom 12%), `band in body` (a running-band text found in the Word body), `past margin` (Word pages whose rightmost ink passes the PDF's right content edge by more than 2 pt), and `word s` (Word's render time for the full file). `band in body` in this run used a stand-in: the text in the top and bottom 8% of every source-PDF page from page 2 on, deduplicated. Later runs use `tagged.band_texts`, the rows that disappear when the PDF's Header and Footer artifacts are removed.

`past margin` now ignores boxes wholly in the top or bottom 12% of the page (the running header and footer), so it counts body overrun only. The stress jobs ran with the server's 105 s budget as convert.py's trailing argument (`SERVER_BUDGET_SECONDS`, from export.mjs); corpus jobs run without one.

Mean tolerance in use: 0.0020. Numbers come from this machine's Word; a record, not a CI gate.

| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw | seconds full / raw | blank | band in body | past margin | word s | declined | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stress-cptc-57 | stress | 57 | 83 / 112 | 0.6454 / 0.6502 | 0.4657 / 0.4872 | 81.5 / 42.8 | 26 | True | 15 | 25.8 | rhythm-tall-row 5 | 1: not at the top rung (0 missing, fell back True); 3: mean 0.6454 against raw 0.6502; 4: page 6 at 0.6322 against raw 0.8528; 4: page 8 at 0.6932 against raw 0.8334; 4: page 10 at 0.7234 against raw 0.8332; 4: page 12 at 0.5077 against raw 0.5861; 4: page 15 at 0.4657 against raw 0.5745; 4: page 16 at 0.4845 against raw 0.6030; 4: page 18 at 0.6294 against raw 0.6523; 4: page 20 at 0.5649 against raw 0.6805; 4: page 22 at 0.4895 against raw 0.6829; 4: page 24 at 0.6497 against raw 0.6715; 4: page 25 at 0.5532 against raw 0.6846; 4: page 28 at 0.6454 against raw 0.6896; 4: page 30 at 0.5833 against raw 0.6859; 4: page 31 at 0.5185 against raw 0.5873; 4: page 36 at 0.5860 against raw 0.6855; 4: page 42 at 0.5782 against raw 0.7028; 4: page 43 at 0.5714 against raw 0.6802; 4: page 46 at 0.6132 against raw 0.6961; 4: page 48 at 0.5785 against raw 0.7125; 4: page 52 at 0.6089 against raw 0.6800; 4: page 54 at 0.5659 against raw 0.6738; 4: page 55 at 0.5241 against raw 0.6229 |
| stress-cptc-short | stress | 26 | 26 / 50 | 0.8049 / 0.6952 | 0.6079 / 0.5133 | 26.8 / 20.3 | 0 | False | 14 | 16.0 | rhythm-tall-row 6 | pass |
| stress-cptc-long | stress | 119 | 174 / 235 | 0.6444 / 0.6417 | 0.4687 / 0.4614 | 196.3 / 79.7 | 55 | True | 15 | 41.3 | rhythm-tall-row 5 | 1: not at the top rung (3 missing, fell back True); 4: page 6 at 0.6322 against raw 0.8528; 4: page 8 at 0.7116 against raw 0.8316; 4: page 12 at 0.5333 against raw 0.5804; 4: page 14 at 0.4687 against raw 0.6929; 4: page 15 at 0.5329 against raw 0.5571; 4: page 19 at 0.5373 against raw 0.6460; 4: page 23 at 0.5537 against raw 0.6561; 4: page 29 at 0.4832 against raw 0.5722; 4: page 35 at 0.5778 against raw 0.7328; 4: page 37 at 0.6961 against raw 0.7306; 4: page 40 at 0.5566 against raw 0.6356; 4: page 41 at 0.5065 against raw 0.6077; 4: page 47 at 0.5396 against raw 0.6555; 4: page 52 at 0.5904 against raw 0.6135; 4: page 53 at 0.5444 against raw 0.6533; 4: page 56 at 0.6330 against raw 0.6825; 4: page 59 at 0.5145 against raw 0.6061; 4: page 65 at 0.5444 against raw 0.6105; 4: page 67 at 0.6297 against raw 0.6617; 4: page 71 at 0.5159 against raw 0.6061; 4: page 73 at 0.6245 against raw 0.6930; 4: page 76 at 0.5776 against raw 0.6150; 4: page 77 at 0.5517 against raw 0.6379; 4: page 79 at 0.5907 against raw 0.6150; 4: page 83 at 0.5830 against raw 0.6943; 4: page 88 at 0.5743 against raw 0.6052; 4: page 89 at 0.5850 against raw 0.7382; 4: page 91 at 0.6815 against raw 0.7430; 4: page 95 at 0.5160 against raw 0.6016; 4: page 97 at 0.6522 against raw 0.6885; 4: page 100 at 0.5838 against raw 0.6904; 4: page 101 at 0.5511 against raw 0.6664; 4: page 107 at 0.5524 against raw 0.6824; 4: page 109 at 0.6645 against raw 0.6858; 4: page 113 at 0.5771 against raw 0.7313; 4: page 119 at 0.6314 against raw 0.7785; 6: 196.3 s against raw 79.7 s |
| stress-findings | stress | 41 | 41 / 41 | 0.8853 / 0.8578 | 0.7992 / 0.7870 | 38.2 / 28.4 | 0 | False | 0 | 16.2 | none | pass |
| stress-thesis | stress | 54 | 57 / 57 | 0.6500 / 0.6498 | 0.5341 / 0.5337 | 107.4 / 54.3 | 1 | True | 29 | 24.8 | none | 1: not at the top rung (0 missing, fell back True) |
| stress-assessment | stress | 31 | 31 / 31 | 0.9093 / 0.9019 | 0.8131 / 0.8106 | 59.8 / 53.3 | 0 | True | 15 | 29.0 | rhythm-tall-row 1 | pass |
