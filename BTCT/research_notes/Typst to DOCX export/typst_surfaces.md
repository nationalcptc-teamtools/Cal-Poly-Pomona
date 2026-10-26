# Typst surfaces for a DOCX exporter (as of 2026-09-29)

Version context: the app runs the typst CLI 0.14.2. Upstream is now at 0.15.1 (0.15.0 released 2026-06-15; workspace `Cargo.toml` on `main` reads `version = "0.15.1"`). Several surfaces below changed in 0.15, and any Rust tool built on the crates pins its own compiler version, so it would not be the same compiler as the app's 0.14.2 binary.

## 1. Typst HTML export: status, elements, custom HTML, what is dropped, roadmap

### Takeaway
HTML export still sits behind the `html` feature flag in 0.15.1 and is officially "not for production", but its element coverage is now broad (headings, paragraphs, tables, figures, images, footnotes, outline, bibliography, and since 0.15 math as MathML). It evaluates the real program (show rules, context, counters) and templates can emit custom markup via `target()` + `html.elem`/typed `html.*`. It is semantic output only: no CSS, no page model, so page headers/footers, `#place` geometry, colours and shapes do not come through as structure (shapes need `html.frame`, which embeds an SVG).

### Cited Findings
- Docs page (version 0.15.1): HTML export is "still very incomplete and only available for experimentation behind a feature flag"; enable with `--features html` on the CLI (or `TYPST_FEATURES=html`) or as an experimental setting in the web app; "Do not use this feature for production use cases." Source: [Typst docs: HTML](https://typst.app/docs/reference/html/)
- Goal is to "capture the structure of an input document and produce semantically rich HTML that retains this structure"; "Typst cannot simply produce perfect HTML for your existing Typst documents"; instead you check `target()` and generate raw HTML elements, "primarily intended for use in templates and show rules". Typst "currently does not generate CSS stylesheets". Source: [Typst docs: HTML](https://typst.app/docs/reference/html/)
- Building blocks: `html.elem` (raw element with Typst content), `html.frame` (lays content out as in paged export and embeds it as inline SVG), `typed` (typed `html.div`, `html.video`, ...). Source: [Typst docs: HTML](https://typst.app/docs/reference/html/)
- A summarizer of the same page reported that page layout, headers, footers and colour styling are not exported and output is always a standalone file (fragment export planned). Treat as consistent with "no CSS / semantic only", but I did not get a verbatim quote for the headers/footers part. Source: [Typst docs: HTML](https://typst.app/docs/reference/html/)
- Tracking issue #5512: developed iteratively; focus on "generating semantic HTML with no CSS". Element table marks complete: bibliography, lists, citations, emph, figures, footnotes, headings, links, outline, paragraphs, quotes, references, strong, tables, term lists, title, highlight, linebreak, case, raw, smartquote, strike, sub/super, underline, image. Partial: box/block. Not supported: visualize elements (circle, curve, ellipse, line, polygon, rect, square). Planned: fragments, directory output, cross-file links. No production date. Source: [typst/typst#5512](https://github.com/typst/typst/issues/5512)
- 0.14.0 (2025-10-24): typed HTML API (`html.div`, `html.video`, "individually typed attributes"); HTML export gained `image`, `footnote`, `outline`, `bibliography`, `smartquote`, `sub`/`super`, `underline`/`overline`/`strike`, `highlight`; several `html.frame` sizing/nesting fixes. Source: [Changelog 0.14.0](https://typst.app/docs/changelog/0.14.0/)
- 0.15.0 (2026-06-15): equations "automatically exported to MathML"; `box`/`block` aligned with paged behaviour; paragraph grouping revised; `<img>` always gets `width`/`height`; HTML minified by default (`--pretty`); `html.script`/`html.style` take strings only. Verbatim: "The `target` function can now be used without the `html` feature flag (the rest of HTML export remains feature-flagged)". New experimental bundle export (one project emits several HTML/PDF/PNG/SVG files). Source: [Changelog 0.15.0](https://typst.app/docs/changelog/0.15.0/)
  - Conflict note: one summarizer pass of that changelog claimed HTML export is "no longer experimental"; a verbatim re-query returned the sentence above saying it remains feature-flagged, and the 0.15.1 HTML docs page still says experimental. The feature-flagged reading is correct.
- Source: the HTML exporter is `crates/typst-html/src/` (`convert.rs`, `dom.rs`, `encode.rs`, `mathml.rs`, `typed.rs`, `tag.rs`, `introspect.rs`, `css/`, `fragment.rs`). Source: [typst/typst crates/typst-html/src](https://github.com/typst/typst/tree/main/crates/typst-html/src)

### Inferences
- For DOCX, HTML export gives the right shape for flow content (the program is fully evaluated, so custom show rules, counters and headings are resolved), and a template can use `target() == "html"` branches to emit explicit markers (e.g. `html.elem("div", attrs: (data-docx: "callout"))`) for anything the default mapping loses.
- It cannot on its own deliver page headers/footers, page-number fields, `#place`d objects, cell fills or colours; those must come from the paged layout or from template metadata. On 0.14.2, math has no MathML (added in 0.15).

### Gaps
- No verbatim confirmation of how `#place` and `grid` (vs `table`) are rendered in HTML export; #5512 lists only `box`/`block` as partial and shapes as unsupported.
- No published date for HTML export leaving the feature flag.

## 2. `typst query` / `typst eval` and `#metadata`

### Takeaway
A template can drop `#metadata(...)` (inside `context`, so counters are resolved) and a wrapper can pull it out as JSON. In 0.14.2 that is `typst query`; in 0.15 `typst eval` supersedes it with arbitrary expressions (`query(<label>).map(it => it.value)`). This yields structured side data (heading numbers, figure numbers, label targets, page numbers via `here().page()`), not the document body with layout.

### Cited Findings
- `typst eval '<code>' --in <document.typ>`, e.g. `typst eval 'query(<note>)' --in example.typ`; results serialize to JSON (metadata has `func`, `value`, `label`); `.map(it => it.value)`, `.first()`; `--target paged|html`. Source: [Typst docs: query](https://typst.app/docs/reference/introspection/query/)
- 0.15.0: "`typst eval` supersedes `typst query`", "a more general subcommand". Source: [Changelog 0.15.0](https://typst.app/docs/changelog/0.15.0/)
- 0.14.0 made many elements locatable without a label: `par`, `table`, `enum`, `list`, `terms`, `title`, `figure.caption`, `footnote.entry`, `outline.entry` and others, i.e. discoverable with `query()`/`locate()`. Source: [Changelog 0.14.0](https://typst.app/docs/changelog/0.14.0/)
- 0.15.0 adds a `within` selector (elements inside an ancestor). Source: [Changelog 0.15.0](https://typst.app/docs/changelog/0.15.0/)

### Inferences
- A practical 0.14.2-compatible trick: in the template, wrap each heading/figure/table show rule with `context metadata((kind: ..., number: counter(...).display(), page: here().page(), pos: here().position(), label: ...))`, then `typst query main.typ "<docx>" --field value`. That gives resolved counters and page positions to annotate a PDF-derived or HTML-derived DOCX.
- Content values serialize as a nested `func`/`children` tree; this is the evaluated content, not the realized (post show-rule) layout, so it is useful for anchors and numbering, not as a full body source.

### Gaps
- The docs do not state how fully arbitrary `content` (styled, show-rule output) serializes; test on 0.14.2 before relying on it.

## 3. Compiler internals: walking `PagedDocument` frames with semantic tags

### Takeaway
Yes. A Rust tool can call `typst::compile::<PagedDocument>(&world)` and walk each page's `Frame` items: `Group`, `Text`, `Shape`, `Image`, `Link`, and `Tag`. `Tag::Start(Content, flags)` / `Tag::End(Location, ...)` bracket every locatable or "tagged" element in the laid-out frames, so text runs, shapes (fills, strokes) and images can be attributed to the table cell, heading, figure or paragraph that produced them, with the full element (fields such as `rowspan`, `colspan`, `level`) reachable through the Content or the `Introspector`. This is exactly what `typst-pdf` does to build its tagged-PDF structure tree, and headers/footers/backgrounds are explicitly wrapped as artifacts of kind Header/Footer/Background during page layout.

### Cited Findings
- Crates in the workspace: `typst`, `typst-library`, `typst-layout`, `typst-realize`, `typst-eval`, `typst-html`, `typst-pdf`, `typst-svg`, `typst-render`, `typst-syntax`, `typst-kit`, `typst-ide`, `typst-bundle`, `typst-cli`, `typst-macros`, `typst-timing`, `typst-utils`. Source: [typst/typst crates/](https://github.com/typst/typst/tree/main/crates)
- `crates/typst-library/src/layout/frame.rs`: `pub enum FrameItem { Group(GroupItem), Text(TextItem), Shape(Shape, Span), Image(Image, Size, Span), Link(Destination, Size), Tag(Tag) }`; `Frame::items()` yields `(Point, FrameItem)`. Source: [frame.rs](https://github.com/typst/typst/blob/main/crates/typst-library/src/layout/frame.rs)
- `crates/typst-library/src/introspection/tag.rs`: "Marks the start or end of a locatable element." `Tag::Start(Content, TagFlags)` ("The stored element starts here"), `Tag::End(Location, u128, TagFlags)`; `TagFlags { introspectable, tagged }`. Source: [tag.rs](https://github.com/typst/typst/blob/main/crates/typst-library/src/introspection/tag.rs)
- `crates/typst-layout/src/document.rs`: `PagedDocument`; `Page { frame: Frame, bleed, fill, numbering: Option<Numbering>, supplement, number: u64 }`. Source: [document.rs](https://github.com/typst/typst/blob/main/crates/typst-layout/src/document.rs)
- `crates/typst-layout/src/pages/run.rs`: during page layout, `header.artifact(ArtifactKind::Header)`, `footer.artifact(ArtifactKind::Footer)`, `background.artifact(ArtifactKind::Background)`; header and footer are laid out as separate `Option<Frame>` marginals before being composed into the page frame; the page-number marginal is built from `numbering`. Source: [run.rs](https://github.com/typst/typst/blob/main/crates/typst-layout/src/pages/run.rs)
- `crates/typst-pdf/src/tags/` (`mod.rs`, `tree/build.rs`, `context/table.rs`, `context/grid.rs`, `context/figure.rs`, `context/list.rs`, `context/outline.rs`, ...) builds the structure tree from a `PagedDocument` using krilla's tagging API; `tags::init(document, options)` builds a `Tree` when `options.tagged()`, and the frame walker calls `handle_start`/`handle_end` on tags. Source: [typst-pdf/src/tags/mod.rs](https://github.com/typst/typst/blob/main/crates/typst-pdf/src/tags/mod.rs)
- `tree/build.rs`: `HideElem` → artifact Other, `ArtifactElem` → artifact of its kind, `RepeatElem` → Layout artifact; repeated table/grid header and footer cells laid out multiple times are marked `ArtifactType::PaginationOther`. Source: [build.rs](https://github.com/typst/typst/blob/main/crates/typst-pdf/src/tags/tree/build.rs)
- `context/table.rs`: `TableCtx` resolves a `CellGrid`, records per-cell `rowspan`/`colspan`, header kind/scope (`TableCellKind::Header(level, TableHeaderScope::Column)`) and stroke priority (cell stroke vs grid stroke). Source: [table.rs](https://github.com/typst/typst/blob/main/crates/typst-pdf/src/tags/context/table.rs)
- typst-pdf depends on krilla (git rev `7772dbe`). Source: [Cargo.toml](https://github.com/typst/typst/blob/main/Cargo.toml)

### Inferences
- A frame walker could produce: paragraphs (Text items between `ParElem` tags, with fonts/sizes/fills from `TextItem`), headings with level, tables with cell geometry (x/y from accumulated group transforms, sizes from cell frames) and cell fills (`Shape` items inside cell tags), images with drawn size, links, and header/footer content kept apart by the Header/Footer artifact tags. Page-number fields are not preserved as fields: the header/footer is already laid out text ("3"), so a tool must recognize `counter(page).display()` via tags/Content (the realized content is there) or substitute a Word `PAGE` field by convention.
- `#place` content shows up as a positioned group inside the page frame, so its absolute position is known; Word mapping (anchored frame vs inline) is the tool's choice.
- These are internal crate APIs with no stability promise; a tool pins one typst version and must be kept in step with the app's compiler. Building against 0.14.x crates is possible but the tag/artifact code has changed since (0.15 "Fixed tagging order for inline content", more artifact kinds). Source: [Changelog 0.15.0](https://typst.app/docs/changelog/0.15.0/)

### Gaps
- Did not verify whether `ArtifactKind::Header/Footer` wrapping in `pages/run.rs` is identical in the 0.14.2 tag; it was added with tagged PDF in 0.14 per the changelog, but the exact 0.14.2 source was not read.
- No public example of a third-party tool walking `PagedDocument` tags specifically for header/footer separation (typort uses geometry instead, see section 5).

## 4. Tagged PDF from 0.14: does it help PDF→DOCX converters?

### Takeaway
Typst 0.14+ PDFs are tagged by default with a real structure tree (headings, tables with header cells and spans, figures, lists, and header/footer/background artifacts), plus PDF/UA-1. But the common open converter, pdf2docx, ignores the structure tree, so the tags help only a converter that reads them (Acrobat is reported to preserve cross-references, but I found no primary source that it uses tags for DOCX).

### Cited Findings
- 0.14.0: "Typst PDFs are now _tagged_ by default"; PDF/UA-1 support; "PDF/UA-2 is not yet supported, but planned"; `pdf.artifact` to "mark content as not semantically meaningful"; tables support multiple headers. Source: [Changelog 0.14.0](https://typst.app/docs/changelog/0.14.0/)
- 0.15.0: multiple PDF standards at once (e.g. PDF/UA-1 + PDF/A-2a), named destinations for labelled headings, more `pdf.artifact` kinds, "Fixed tagging order for inline content". Source: [Changelog 0.15.0](https://typst.app/docs/changelog/0.15.0/)
- Structure tree mechanics (StructTreeRoot, element types H1, TH, LI, references into content streams). Source: [RemeDocs: PDF tag trees](https://remedocs.com/blog/pdf-tag-trees-guide/); PyMuPDF exposes it only via low-level access. Source: [PyMuPDF discussion #2389](https://github.com/pymupdf/PyMuPDF/discussions/2389)
- A grep of the installed pdf2docx 0.5.13 package in this repo's `.venv-pdf2docx` for `StructTree`, `struct_tree` and `MarkInfo` found no matches (local check, 2026-09-29); pdf2docx's layout reconstruction is geometric. Source: [pdf2docx](https://github.com/ArtifexSoftware/pdf2docx)
- Forum report: PDF→DOCX via Acrobat "successfully preserve[s] cross-references". Source: [Typst Forum: pdf2docx + Pandoc](https://forum.typst.app/t/exporting-to-docx-combining-pdf2docx-and-pandoc/6644)

### Inferences
- The tagged PDF is a cheap, already-produced side channel: a repair pass can read `StructTreeRoot` (e.g. with pikepdf/PyMuPDF xref access) to learn which marked-content IDs are `Artifact /Header`/`/Footer`, which are `TH`/`TD` with `RowSpan`/`ColSpan`, and which are `H1..H6`, then use that instead of geometric guessing when post-processing pdf2docx output. That is a plausible fit for the app's existing `convert.py` pipeline without changing the typst compile.

### Gaps
- No primary source found on whether Adobe Acrobat or Word's own PDF reflow consume the structure tree when exporting to DOCX.

## 5. Existing Typst→DOCX projects and positions

### Takeaway
Upstream Typst has declined native DOCX. The most relevant third-party project is typort (Rust, 2026, Apache-2.0), which embeds typst 0.15.1 and walks the HTML export's tag stream with the introspector, using the paged layout for geometry (image sizes, fonts, page setup, header/footer detection). typlite (tinymist) also writes DOCX from the HTML export. typ2docx (PDF→DOCX plus Pandoc math merge) was archived in September 2026. Pandoc's Typst reader (typst-hs) evaluates only partially.

### Cited Findings
- Issue #190 "Will typst consider to support generating word(.docx) format?" (opened 2023-03-23) is "Closed as not planned". Source: [typst/typst#190](https://github.com/typst/typst/issues/190)
- Discussion #2561: frozolotl (2023-11-02): DOCX "is not well suited for sharing documents and it is difficult to export already fully formatted, laid out and typeset documents to it"; suggests `pandoc main.typ -o main.docx` with the caveat that styling and objects "display differently or get lost entirely"; a 2025-05-22 reply reports pandoc parse errors on a real document; 2026-03-05 reply lists typ2docx, Word opening the PDF, Acrobat. Source: [Discussion #2561](https://github.com/typst/typst/discussions/2561)
- typort: crates.io "Universal Typst to Word (.docx) converter", repo github.com/dianzuan/typort, Apache-2.0, created 2026-05-19, 0.2.0 published 2026-09-01, 134 downloads; split into `typort-core`, `typort-ooxml`, `typort-math`, `typort-presets`. Source: [crates.io API: typort](https://crates.io/api/v1/crates/typort); [lib.rs: typort](https://lib.rs/crates/typort)
  - Claims "compiles your Typst document and generates a Word file directly, no intermediate PDF, no Pandoc, no template required"; `typort input.typ -o output.docx`, `--preset`. Source: [lib.rs: typort](https://lib.rs/crates/typort) (via search snippet; the page timed out on fetch)
  - `typort-core` 0.2.0 depends on `typst`, `typst-html`, `typst-layout`, `typst-library`, `typst-realize`, `typst-render` = 0.15.1. `src/convert/mod.rs`: "Tag-walker based Typst -> OOXML conversion (v2). Walks `HtmlDocument`'s `Tag` sequence. Each `Tag::Start` carries a `Location` that maps via the `Introspector` to the full Content AST"; image sizes come "from the paged frames"; "a drawing body is dropped from the HTML export, so its pixels come from the paged frames" (rasterized). `src/convert/page.rs`: "`PagedDocument` -> page settings, document style, font detection ... Also detects section breaks, headers/footers, and column layouts", with header detection by position ("Use margin * 0.9 as the boundary"). About 10,100 lines in `src/convert/`. Source: [typort-core 0.2.0 crate source](https://crates.io/api/v1/crates/typort-core/0.2.0/download) (downloaded and read locally)
- typlite (tinymist): "Converts a subset of typst to markdown"; outputs `.txt`, `.md`, `.tex`, `.docx`; `context` content rendered as SVG; exposes `sys.inputs.x-target`. Its crate uses `typst-html::HtmlDocument` parsed to an AST and a `docx-rs` writer (`writer/docx`, feature `docx`). Source: [typlite README](https://github.com/Myriad-Dreamin/tinymist/tree/main/crates/typlite), [typlite Cargo.toml](https://github.com/Myriad-Dreamin/tinymist/blob/main/crates/typlite/Cargo.toml)
  - Forum reply: typlite exports DOCX through HTML but turns formulas into images with scaling problems; another user reports typlite HTML export "immediately fails with page settings". Source: [Typst Forum thread](https://forum.typst.app/t/exporting-to-docx-combining-pdf2docx-and-pandoc/6644)
- typ2docx (sghng): compiles to PDF with injected markers, converts via Acrobat / PDFServices / pdf2docx, extracts math with the `typst` + `typst-eval` crates and converts it with Pandoc, then merges `document.xml` by XSLT. Known issues: distorted text in SVG/PDF images, lost spaces around inline math. Archived 2026-09-05; the author recommends Pandoc instead, citing improved Typst support. Source: [sghng/typ2docx](https://github.com/sghng/typ2docx); web front end [typ2docx.sghuang.com](https://typ2docx.sghuang.com/)
- Pandoc Typst reader is built on typst-hs, which has "a parser" and "an evaluator, which evaluates the typst expressions in the AST", "targets v0.15.0 of typst, and offers only partial support". Source: [jgm/typst-hs](https://github.com/jgm/typst-hs)
- Pandoc's Typst writer supports `typst:prop` attributes (the reverse direction). Source: [Pandoc: Typst property output](https://pandoc.org/typst-property-output.html)
- Online converters exist (e.g. lazyconvert), with no stated method. Source: [lazyconvert](https://lazyconvert.com/convert/typst-to-docx/)
- Chinese community FAQ page on converting to Word exists. Source: [Typst 中文社区: convert to word](https://typst-doc-cn.github.io/guide/FAQ/convert_to_word.html)
- A "Markdown export" issue exists upstream (#8674), showing non-PDF export requests continue. Source: [typst/typst#8674](https://github.com/typst/typst/issues/8674)

### Inferences
- typort validates the hybrid architecture (HTML-export tag walk for semantics, `PagedDocument` for geometry). It still guesses headers/footers geometrically rather than reading the `ArtifactKind::Header/Footer` tags in the paged frames, which is an obvious improvement point.
- Any crate-based converter pins a typst version (typort: 0.15.1). Adopting one means either moving the app's CLI to that version or running two compilers, which would break the app's "one compile, both formats" guarantee (the PDF and DOCX could differ).
- typort is young (4 months, 134 downloads, single author); treat as a reference implementation, not a dependency to trust with hostile input.

### Gaps
- Could not fetch typort's GitHub README (lib.rs timed out); feature list (tables with fills, `#place`, grid) is not confirmed beyond the source comments above.
- Found no company selling a Typst→Word product beyond generic online converters.
- Did not read the closing comment on #190 (not shown in the fetched page).
