# OOXML (DOCX) fidelity limits and DOCX writer libraries, for a Typst to DOCX exporter

Researched 2026-09-29. Every finding carries its source link at the end of the line. No em dashes by project rule; the fact and its source are separated by a link, not a dash.

## What OOXML can express precisely

### Takeaway
WordprocessingML can state almost every paragraph, table and page-setup value a Typst layout produces, in exact units (twentieths of a point for spacing, half-points for font size and kerning thresholds, twips for page size). What it stores is a set of reflow parameters, not positions. Headers, first-page and odd/even variants, repeating table header rows, floating anchored drawings, simple and complex fields, embedded fonts and native math (OMML) are all first-class.

### Cited Findings
- `w:spacing` (ISO/IEC 29500 §17.3.1.33) sets inter-line and inter-paragraph spacing. Attributes: `before`, `after` (twentieths of a point), `beforeLines`/`afterLines` (line units), `beforeAutospacing`/`afterAutospacing`, `line`, and `lineRule`. The spec example `w:line="276" w:lineRule="auto"` means 1.15 lines (276/240), so with `auto` the `line` value is in 240ths of a line. [MS Learn: SpacingBetweenLines](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.spacingbetweenlines)
- Space between two paragraphs is not additive: "a consumer shall use the maximum of the inter-line spacing in each paragraph, the spacing after the first paragraph and the spacing before the second paragraph". Example: after=240 (12 pt) then before=80 (4 pt) yields 12 pt. [MS Learn: SpacingBetweenLines](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.spacingbetweenlines)
- Typst paragraph spacing also collapses to the greater value when adjacent paragraphs differ (default `spacing: 1.2em`), and `leading` (default `0.65em`) is measured bottom edge of one line to top edge of the next, not baseline to baseline. [Typst docs: par](https://typst.app/docs/reference/model/par/)
- `w:tblHeader` in `w:trPr` repeats a row at the top of every page the table continues onto; it can be applied to several leading rows to make a multi-row header, and is ignored on a row not contiguous with the first row. [MS Learn: TableHeader](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.tableheader)
- `w:titlePg` in `w:sectPr` gives a section a different first-page header and footer; even/odd headers are a separate document-level switch, `w:evenAndOddHeaders` (§17.10.1). If `titlePg` is true and no first-page header exists, a blank header is used rather than falling back. [MS Learn: TitlePage](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.titlepage)
- `w:fldSimple w:instr="..."` holds a field instruction plus a cached result run (spec example: `FILENAME` with cached text "Example Document.docx"); field semantics are defined by field codes in §17.16.5. [MS Learn: SimpleField](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.simplefield)
- `w:kern w:val` turns on font kerning only for runs whose size is at or above the threshold (half-points); if never set in the style hierarchy, no kerning is applied. [MS Learn: Kern](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.kern)
- A drawing is either inline ("affects the line height and layout of its line, like a character glyph") or floating (`wp:anchor`: "anchored within the text, but can be absolutely positioned in the document relative to the page"), with children `positionH`, `positionV`, `simplePos`, `extent`, `effectExtent` and one of `wrapNone`, `wrapSquare`, `wrapThrough`, `wrapTight`, `wrapTopAndBottom`. [MS Learn: Anchor](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.drawing.wordprocessing.anchor)
- Page size is stored exactly per section; A4 appears as 11906 x 16838 twips (210 x 297 mm). Explicit breaks (`w:br w:type="page"`), cached `lastRenderedPageBreak` markers and a `compatibilityMode` value are also stored. [DEV: A .docx does not store where its pages end](https://dev.to/pm_cheng_3f36acecfb9c59f5/a-docx-does-not-store-where-its-pages-end-pee)
- Embedded fonts: Word saves them as obfuscated `.odttf` parts under `word/fonts/`, referenced from `fontTable.xml` via `w:embedRegular` (and the bold/italic siblings) with an `r:id` and a `fontKey` GUID. [Wikipedia: ODTTF](https://en.wikipedia.org/wiki/ODTTF); [gist: extract embedded fonts from docx](https://gist.github.com/FrancoisCapon/8db243283cc18be24a9ce6351e478b13)
- Obfuscation is an XOR of the first 32 bytes of the font with the GUID from the part name (byte order reversed from the formatted GUID); the rest is plain OpenType. [Wikipedia: ODTTF](https://en.wikipedia.org/wiki/ODTTF)
- Microsoft's own guide to TrueType embedding in Office. [Microsoft Support KB 290952](https://support.microsoft.com/en-us/kb/290952); overview of what Word does and does not embed. [Office Watch: Font embedding](https://office-watch.com/2023/font-embedding-in-microsoft-office/)
- Math: OMML is the XML Word has used for equations since Word 2007 (`m:oMath`), stored in docx/pptx/xlsx. Word ships `mml2omml.xsl` and `omml2mml.xsl` for MathML conversion, usable outside Word. OMML exists because Presentation MathML lacks explicit n-ary and math-function elements. [MS Learn archive: OfficeMath (Murray Sargent)](https://learn.microsoft.com/en-us/archive/blogs/murrays/officemath); [Math in Office blog](https://devblogs.microsoft.com/math-in-office/officemath/)
- The `w:compat` block has 66 child switches, among them `doNotExpandShiftReturn` (do not justify a line that ends in a soft break), `noExtraLineSpacing` (do not center content on exact-height lines), `suppressTopSpacing`, `suppressBottomSpacing`, `suppressSpBfAfterPgBrk`, `spacingInWholePoints`, `useAnsiKerningPairs`, `usePrinterMetrics`, `wpJustification`, `doNotBreakWrappedTables`, `adjustLineHeightInTable`, `growAutofit`, `autofitToFirstFixedWidthCell`, `wrapTrailSpaces` and `compatSetting` (custom name/uri/value, which carries `compatibilityMode`). [MS Learn: Compatibility](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.compatibility)

### Inferences
- An exporter should write every length explicitly (spacing before/after on every paragraph, `lineRule="exact"` with a computed value, explicit table and cell widths) rather than rely on style inheritance, because the missing-value default is "no spacing" and Word's paragraph gap is a max, which happens to match Typst's collapse rule.
- Typst's `leading` is an edge-to-edge gap, while Word's exact line rule is a line pitch. An exporter has to convert: pitch = font's ascent+descent box (as Typst measures it) + leading. That is a source of per-line drift if the ascent/descent Typst uses differs from what Word derives from the same font.
- Page-number (PAGE, NUMPAGES), TOC, REF and SEQ are field codes; the file carries only a cached result, so what Word shows depends on whether it recalculates.

### Gaps
- I did not fetch the individual spec pages for `lineRule` enum values `exact`/`atLeast`, tab stops (`w:tabs`), cell margins (`w:tblCellMar`), borders/shading (`w:tcBorders`, `w:shd`), merged cells (`w:gridSpan`, `w:vMerge`), footnotes (`w:footnoteReference`), text frames (`w:framePr`), text boxes (`wps:txbx`), hyphenation (`w:autoHyphenation` in settings) or letter spacing (`w:spacing` inside `w:rPr`, twentieths of a point). They are standard ISO/IEC 29500 elements, but the precise quoted semantics are not in these notes.
- `w:updateFields` (ask Word to update fields on open): the MS Learn class page I tried returned 404, so its exact behavior (and the prompt it raises) is unsourced here.
- The TOC, SEQ and REF field switch syntax (`\o "1-3" \h \z \u`, `\* ARABIC`, `\h`) is not sourced.

## What Word cannot match from a TeX/Typst layout, and why page counts drift

### Takeaway
A DOCX does not store where lines or pages end; Word recomputes both on open from local glyph and printer metrics, with a line breaker that differs from Typst's whole-paragraph optimizer. Exact line heights, explicit breaks and compat switches narrow the drift but cannot remove it. Absolute placement is only available through floating anchors, which are still tied to an anchor paragraph.

### Cited Findings
- Typst's `linebreaks` has two modes: `simple` ("first-fit") and `optimized` ("optimize the line breaks for the whole paragraph"); the default `auto` uses optimized breaking for justified paragraphs. Justified paragraphs also get hyphenation when `hyphenate` is `auto` and the language is known. [Typst docs: par](https://typst.app/docs/reference/model/par/)
- Knuth-Plass considers every way to break the paragraph and minimizes total badness; a greedy breaker fills each line as full as it can and "doesn't consider what happens on line 2 when it commits to the break on line 1". [Forme: implementing TeX line breaking](https://www.formepdf.com/blog/tex-line-breaking-algorithm); [Wikipedia: Knuth-Plass](https://en.wikipedia.org/wiki/Knuth%E2%80%93Plass_line-breaking_algorithm)
- "Which sentence ends page 3 is computed at open time by whatever program opens it, from glyph metrics that live on that machine", and Word folds printer metrics into the same calculation, so the same file paginates differently on another laptop. [DEV: A .docx does not store where its pages end](https://dev.to/pm_cheng_3f36acecfb9c59f5/a-docx-does-not-store-where-its-pages-end-pee)
- Same source: PPTX keeps absolute coordinates per object, while DOCX stores "reflow parameters"; cached field results (e.g. "page 1 of 10") are shown stale by renderers that do not recompute. [DEV: A .docx does not store where its pages end](https://dev.to/pm_cheng_3f36acecfb9c59f5/a-docx-does-not-store-where-its-pages-end-pee)
- Word's page count can change when printing or exporting, and with the selected printer. [Microsoft Q&A: page count changes when printing/exporting](https://learn.microsoft.com/en-us/answers/questions/5068197/word-page-count-changes-when-printing-exporting)
- LibreOffice can run a Word document onto an extra page; a missing font changes line spacing enough to move a page break; installing every font the document uses is the fix for stable server-side counts. [Medium: Word document statistics in Python (Jul 2026)](https://medium.com/@alice.yang_10652/get-word-document-statistics-in-python-count-words-pages-more-0b469022b3c2); [MakeUseOf: same Word file in three suites](https://www.makeuseof.com/opened-word-file-in-three-free-office-suites-one-handled-better/)
- An open-source DOCX layout engine documents two places where it departs from Word's line-height rules (line gap, pictures under proportional spacing), showing that line height itself is engine-specific. [rdocx issue #162](https://github.com/tensorbee/rdocx/issues/162)
- A LibreOffice fork's PR describes a "Word-parity policy for the three places LibreOffice and Word disagree". [libreoffice-core PR #16](https://github.com/theolivenbaum/libreoffice-core/pull/16)
- Compat switches that control drift sources: `usePrinterMetrics`, `spacingInWholePoints` (only whole-point expand/condense), `useAnsiKerningPairs`, `noExtraLineSpacing`, `suppressTopSpacing`/`suppressBottomSpacing` (exact height ignored at top or bottom of page), `suppressSpBfAfterPgBrk`, `doNotExpandShiftReturn` (a manual line break on a justified line does not get stretched), `wpJustification`, `doNotBreakWrappedTables`. [MS Learn: Compatibility](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.compatibility)
- Floating objects are "anchored within the text" even when positioned relative to the page, so a floating image still moves with its anchor paragraph's page. [MS Learn: Anchor](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.drawing.wordprocessing.anchor)

### Inferences
- The one reliable way to get Typst's line breaks in Word is to impose them: end each laid-out line with `w:br` (soft break) and set `doNotExpandShiftReturn` so justified lines ending in a soft break are not stretched. The cost is that the text no longer reflows when edited, and any width shortfall on the Word side (a different glyph advance) wraps a line early and adds a line, so one extra wrapped line per paragraph can still add pages.
- Exact line pitch (`lineRule="exact"`) plus explicit before/after spacing plus embedded fonts removes the main vertical-drift causes; horizontal drift (kerning, shaping, justification algorithm) remains, which is why forced breaks are the lever.
- Rotated content, clip paths, and a grid that spans pages have no direct WordprocessingML text equivalent in what I sourced; the realistic options are to rasterize/vectorize them as a picture (inline or anchored) or to approximate with tables.
- Page-level absolute layout (Typst `place`) maps to `wp:anchor` with `positionH/positionV relativeFrom="page"`, but each anchor needs a host paragraph on the right page, so it inherits the pagination drift.

### Gaps
- I found no Microsoft primary source that names Word's line-breaking algorithm; "Word breaks greedily" is widely assumed but I could not cite it directly. The greedy description above is the generic definition, not a Word statement.
- No source measured how much page-count drift a Typst or LaTeX document shows after DOCX conversion.
- No sourced detail on Word's OpenType shaping (ligatures via `w14:ligatures`, contextual alternates) or on how Word handles CFF/OTF outlines when embedding.

## DOCX writer libraries: maturity in 2026

### Takeaway
For writing from scratch: docx.js (JS) has the widest documented feature set among the open-source writers (fields, TOC, footnotes, math, floating images, frames, font embedding); docx-rs (Rust) is active and covers headers, footnotes, TOC, floating images and numbering; python-docx 1.2.0 (June 2025) is stable but still has no field or footnote API. docx4j and the Open XML SDK are full-schema and actively released in 2026; Aspose.Words is commercial and releases monthly.

### Cited Findings
- **docx-rs (Rust, bokuweb)**: "A .docx file writer with Rust/WebAssembly"; README feature list includes headers/footers/page settings, footnotes, tracked changes, TOC, nested tables, inline and floating images, numbering and styles, sections, comments, bookmarks, hyperlinks; states "OOXML is a large specification, so support is not exhaustive". About 557 stars, 841 commits, needs Rust 1.88. [GitHub: bokuweb/docx-rs](https://github.com/bokuweb/docx-rs)
- docx-rs 0.4.19 released 2026-02-08; a 0.4.20 release followed about three months before the search date; around 61.5k downloads a month and used by 38 crates. [docs.rs: docx-rs](https://docs.rs/crate/docx-rs/latest); [lib.rs: docx-rs](https://lib.rs/crates/docx-rs); [crates.io versions](https://crates.io/crates/docx-rs/versions)
- **docx.js (dolanmiu/docx)**: declarative API for Node and browser, about 5.9k stars, 4,135+ commits, active CI. [GitHub: dolanmiu/docx](https://github.com/dolanmiu/docx)
- docx.js documentation covers page numbers, table of contents, footnotes, endnotes, bookmarks, math, floating images, text frames, numbering, sections, font embedding, comments, hyperlinks and fields. [docx.js.org](https://docx.js.org/)
- **python-docx**: 1.2.0 released 2025-06-16, Python 3.9+, "Production/Stable", maintainer scanny. [PyPI: python-docx](https://pypi.org/project/python-docx/)
- python-docx supports headers and footers, but has no API for page-number fields; its own docs say page numbering is rendered at runtime. [python-docx docs: headers and footers](https://python-docx.readthedocs.io/en/latest/user/hdrftr.html)
- python-docx has never shipped footnotes; third-party add-ons fill the gap. [GitHub: python-docx-footnotes](https://github.com/droza123/python-docx-footnotes); low-level footnote PR never merged: [python-docx PR #624](https://github.com/python-openxml/python-docx/pull/624)
- A long-standing python-docx issue reports it destroying `PAGE` and `NUMPAGES` fields in headers/footers during manipulation. [python-docx issue #686](https://github.com/python-openxml/python-docx/issues/686)
- The fork python-docx-ng adds `Paragraph.add_field()` with builders for PAGE, TOC, REF and SEQ, plus footnotes and endnotes. [PyPI: python-docx-ng](https://pypi.org/project/python-docx-ng/)
- **docx4j (Java)**: releases in 2026 include 11.5.11 (2026-03-07), 17.0.3 (2026-08-18), 17.0.4 (2026-09-02, "equation support", "markdown support") and 17.1.0 (2026-09-07, PDF via XSL-FO improvements, WMF/EMF support). [docx4java forum announcements](https://www.docx4java.org/forums/news/forum/global/); [Maven: org.docx4j](https://mvnrepository.com/artifact/org.docx4j)
- **Open XML SDK (.NET, Microsoft)**: DocumentFormat.OpenXml 3.5.1 is current on NuGet; 3.4.1 (2026-01-06) updated bundled schemas to the Q3 2025 Office release. It is a strongly typed layer over every schema element (the class pages cited above are its reference). [NuGet: DocumentFormat.OpenXml](https://www.nuget.org/packages/documentformat.openxml); [GitHub: dotnet/Open-XML-SDK](https://github.com/dotnet/Open-XML-SDK)
- **Aspose.Words (commercial)**: monthly releases, NuGet at 26.9.0; Java 26.5 had 44 fixes, 26.1 improved rendering of fields and equations. It has its own layout engine, so it can also render DOCX to PDF. [NuGet: Aspose.Words](https://www.nuget.org/packages/Aspose.Words/); [Aspose.Words for Java 2026 release notes](https://releases.aspose.com/words/java/release-notes/2026/)

### Inferences
- For a writer that must emit PAGE/NUMPAGES/TOC/SEQ/REF fields, footnotes, anchored images and OMML, docx.js is the most complete open-source option; docx-rs covers most of it natively in Rust (useful if the exporter lives next to the Typst compiler, which is Rust); python-docx would need raw `OxmlElement` XML for fields and footnotes.
- The Open XML SDK and docx4j expose the whole schema, so nothing in section 1 is unreachable with them, but they are low-level and bring a .NET or JVM runtime.
- Whatever the library, compat settings, `w:fldChar` complex fields and font embedding may need raw XML injection; I did not confirm per-library API coverage for `w:compat` or `w:framePr`.

### Gaps
- docx.js latest version number and release date were not returned by the fetch.
- Per-library coverage matrix for OMML writing, `w:compat` flags and embedded font obfuscation was not verified line by line.
- Whether docx-rs supports arbitrary fields (PAGE, SEQ, REF) beyond TOC is not stated in its README.

## Validation: checking that a generated DOCX renders the same

### Takeaway
The practical pipeline is: render the DOCX to PDF (Word itself for ground truth, LibreOffice headless as a free second opinion), rasterize both PDFs and compare per page (pixel or SSIM with tolerance), plus page count and per-page text order. LibreOffice is not a Word oracle; it disagrees with Word on pagination and changes between versions.

### Cited Findings
- `soffice --headless --convert-to pdf --outdir <dir> <file>` is a free, scriptable converter used as an oracle; a proposed differential harness compares page count, per-page text ordering and per-page rasterized similarity (SSIM/pixelmatch at low DPI with tolerance bands) with LibreOffice and Word as black-box baselines. [next-gen-editor issue #89](https://github.com/IbraheemAlz/next-gen-editor/issues/89)
- The same input gives slightly different PDFs across LibreOffice versions (reflowed lines, shifted tables, font substitution), which turns pixel comparison into false regressions. [DEV: replacing headless LibreOffice with a Rust binary](https://dev.to/nixan/we-replaced-headless-libreoffice-with-a-single-rust-binary-for-docx-pdf-7po)
- pdf-visual-diff (npm) rasterizes PDFs with pdf.js and compares images with jimp for visual regression tests. [npm: pdf-visual-diff](https://www.npmjs.com/package/pdf-visual-diff)
- Other projects run PDF export parity checks by pixel comparison against LibreOffice's output. [gtk-office-suite issue #1105](https://github.com/tuna-os/gtk-office-suite/issues/1105); [reamkit PR #69](https://github.com/alex-krassavin/reamkit/pull/69)
- Page count needs every font installed on the rendering host; otherwise LibreOffice substitutes and moves breaks. [Medium: Word document statistics in Python](https://medium.com/@alice.yang_10652/get-word-document-statistics-in-python-count-words-pages-more-0b469022b3c2)

### Inferences
- Word (via COM automation on Windows, or Word's own PDF export) is the only oracle for "renders the same in Word". LibreOffice is useful for catching gross breakage in CI, and should run with pinned version and fonts.
- Text-content comparison (every PDF line present in the DOCX, in order) catches losses that pixel diffs miss; pixel/SSIM diffs catch placement drift that text checks miss. Using both is the defensible gate.

### Gaps
- No source quantified typical SSIM thresholds that separate acceptable drift from real regressions for DOCX-vs-PDF comparison.
- No source found for a headless, non-Windows way to get Word's exact layout (aside from commercial engines like Aspose, whose fidelity to Word was not measured here).
