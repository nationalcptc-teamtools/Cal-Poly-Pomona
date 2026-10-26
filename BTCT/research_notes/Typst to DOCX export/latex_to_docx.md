# LaTeX to DOCX converters: where in the pipeline they convert, and what that costs

Framing used throughout. There are three places a converter can stand:

1. **Source-syntax converters** parse `.tex` text themselves and never run TeX (pandoc, GrindEQ, latex2rtf). LaTeXML is a special case: it re-implements TeX in Perl, so it "evaluates" macros, but only as far as its re-implementation and its per-package bindings go.
2. **In-engine converters** run the real TeX engine on the real source, with hooks that inject structural markers into the output (tex4ht / make4ht). Every macro and class executes, so structure is still known, but the target is a reflowable markup format (ODT), not a page.
3. **Output-side converters** read the final PDF (Word PDF Reflow, Acrobat Export, Aspose.PDF, ABBYY, pdf2docx). The real typesetter ran, so any template "works", but structure has been flattened to positioned glyphs and lines and must be guessed back.

## 1. pandoc (source-syntax, AST-based)

### Takeaway
pandoc parses LaTeX into its own AST and writes DOCX from that; it never runs TeX, so packages and classes are not loaded, visual layout is dropped by design, and Word appearance comes from a reference.docx plus `custom-style` hooks. It gives the cleanest editable Word output (real Heading styles, native numbering fields) and the least visual fidelity to the TeX template.

### Cited Findings
- pandoc's own manual: "Because pandoc's intermediate representation of a document is less expressive than many of the formats it converts between, one should not expect perfect conversions... Pandoc attempts to preserve the structural elements of a document, but not formatting details such as margin size. And some document elements, such as complex tables, may not fit into pandoc's simple document model... conversions from formats more expressive than pandoc's Markdown can be expected to be lossy." ([pandoc MANUAL](https://pandoc.org/MANUAL.html), text verified in [MANUAL.txt](https://raw.githubusercontent.com/jgm/pandoc/main/MANUAL.txt))
- Macros: with the `latex_macros` extension "pandoc will parse LaTeX macro definitions and apply the resulting macros to all LaTeX math and raw LaTeX", e.g. `\newcommand{\tuple}[1]{\langle #1 \rangle}` works in all output formats; macros are not applied inside raw spans/blocks marked with `raw_attribute`. ([pandoc MANUAL, latex_macros](https://pandoc.org/MANUAL.html#extension-latex_macros))
- Packages are not executed: a Feb 2025 report (pandoc 3.6.3) shows `Could not load include file geometry.sty` for every package (datetime, hyperref, fancyhdr, enumitem, parskip) and a DOCX that came out "totally bland" even though pdflatex compiled the same file. ([jgm/pandoc#10617](https://github.com/jgm/pandoc/issues/10617))
- Other reader gaps reported upstream: `\providecommand` ignored ([#3254](https://github.com/jgm/pandoc/issues/3254)), `\part` ignored ([#1905](https://github.com/jgm/pandoc/issues/1905)), `latex_macros` only available on readers, not writers ([#9677](https://github.com/jgm/pandoc/issues/9677)), requests for custom macro files for non-LaTeX output ([#7816](https://github.com/jgm/pandoc/issues/7816)).
- reference.docx: "The contents of the reference docx are ignored, but its stylesheets and document properties (including margins, page size, header, and footer) are used in the new docx." Customisable styles include Normal, Body Text, First Paragraph, Compact, Title, Subtitle, Author, Date, Abstract, Heading 1–9, Block Text, Source Code, Footnote Text, Caption, Table Caption, Image Caption, Figure, TOC Heading, plus character and table styles. ([pandoc MANUAL, --reference-doc](https://pandoc.org/MANUAL.html#option--reference-doc))
- Custom styles: a Div, Span or Table with attribute `custom-style` gets that Word paragraph/character style, "with the exception of elements whose function depends on a style, like headings, code blocks, block quotes, or links"; undefined styles are created inheriting from Normal; already-defined ones are not altered. The manual pairs this with filters (e.g. map all italics to an `Emphasis` character style). ([pandoc MANUAL, Custom Styles](https://pandoc.org/MANUAL.html#custom-styles))
- Numbering: `--number-sections` numbers headings in Docx; `native_numbering` "Enables numbering of figures and tables via counter fields specific to the target format" for odt/docx, and "If this extension is not enabled, tables and figures in these formats will not be numbered." `xrefs_name`/`xrefs_number` emit Word cross-reference fields that only become consistent "once the document has been refreshed." ([pandoc MANUAL](https://pandoc.org/MANUAL.html#extension-native_numbering))
- Lua filters transform the AST between reader and writer ("Transform the document in a similar fashion as JSON filters, but use pandoc's built-in Lua filtering system"). ([pandoc MANUAL](https://pandoc.org/MANUAL.html#option--lua-filter))
- Reverse direction worth knowing: `-f docx+styles` reads Word styles back as `custom-style` attributes, so a styled document can be used as its own reference. ([pandoc MANUAL, Custom Styles](https://pandoc.org/MANUAL.html#custom-styles))

### Inferences
- The pandoc model is "semantic mapping + a Word-side stylesheet": fidelity to the *template* depends entirely on someone hand-building a reference.docx that imitates it. Arbitrary templates are not supported in principle, because template code (class files, fancyhdr, geometry) is never executed.
- For a Typst exporter, the pandoc lesson is that the editable result users like comes from emitting real Word styles, numbering fields and caption fields, not from positioning.

### Gaps
- I did not find an official list of exactly which LaTeX environments/commands the reader handles; the manual does not enumerate them, and the answer lives in the Haskell reader source.

## 2. tex4ht / make4ht (in-engine, then ODT, then LibreOffice to DOCX)

### Takeaway
tex4ht runs the real LaTeX engine with redefined macros that drop output-format "specials" into the DVI, then post-processes the DVI; custom macros and most packages therefore work, but DOCX is not a native target. The route is LaTeX to ODT via make4ht, then LibreOffice converts ODT to DOCX, and page layout (headers, margins, exact spacing) is not carried as page geometry.

### Cited Findings
- Mechanism: "an ordinary (La)TeX run compiles a DVI file from the source first. TeX4ht subsequently processes the DVI file"; it "can leverage existing macro packages and BibTeX extensions without requiring native implementations in the converter itself." Output formats include HTML5, XHTML, MathML, OpenDocument, DocBook, EPUB, TEI, and Word "via the OpenDocument (ODT) intermediary." Maintained by Karl Berry and Michal Hoftich since Eitan Gurari's death in 2009. ([Wikipedia: TeX4ht](https://en.wikipedia.org/wiki/TeX4ht))
- make4ht: "The TeX run produces a special DVI file that contains the code for the desired output format. The produced DVI file is then processed using the tex4ht command, which in conjunction with the t4ht command produces the desired output files." Supported formats listed: "xhtml, html5, odt, tei, docbook" (no docx). ODT notes: no accented filenames; an `odttemplate` filter for styling. ([make4ht README](https://github.com/michal-h21/make4ht)); manual v0.4d dated 2025-04-14 ([make4ht-doc.pdf on CTAN](https://ctan.math.washington.edu/tex-archive/support/make4ht/make4ht-doc.pdf)).
- Hook mechanism: "In order to insert html tags, LaTeX macros are redefined and in the definitions special hooks are inserted"; hooks are declared via `\NewConfigure` in `.4ht` files and filled via `\Configure` in user `.cfg` files; "Basic font styles are inserted by `tex4ht` command during extraction of text from dvi." ([tex4ht tutorial, Hoftich](https://github.com/michal-h21/helpers4ht/wiki/tex4ht-tutorial)); configuration system described in Hoftich's TUG 2021 talk ([slides](https://tug.org/tug2021/assets/pdf/Michal-Hoftich-slides.pdf)).
- Word route per the TeX FAQ: "Convert LaTeX to OpenOffice format, using the tex4ht command oolatex; open the result in OpenOffice or LibreOffice and 'save as' a MS-Word document." ([TeX FAQ: other conversions](https://texfaq.org/FAQ-fmtconv))
- Reported failure in that last hop: users got an ODT that worked in LibreOffice but LibreOffice refused / misbehaved when saving it as DOCX. ([make4ht#43](https://github.com/michal-h21/make4ht/issues/43))

### Inferences
- tex4ht is the closest LaTeX analogue to "evaluate the real typesetter but keep structure": any macro that ultimately calls a configured hook (sectioning, lists, footnotes, tables) comes out structural. Anything that does its work by raw box/glue manipulation with no hook (custom title pages, fancyhdr running heads, TikZ positioning) either becomes flattened text/images or disappears, because the target is flow markup, not a page.
- The Typst analogue would be hooking Typst's introspection (show rules / element tree after layout) rather than the PDF: structure known, macros evaluated. The tex4ht experience says each "element kind" still needs an explicit mapping, like the `.4ht` files.

### Gaps
- I found no quantitative fidelity study of tex4ht ODT/DOCX output. The claim that page geometry (margins, headers/footers) is lost is my inference from the flow-format target; the tutorial summary I fetched did not state it verbatim.

## 3. LaTeXML (re-implemented TeX engine in Perl, to XML)

### Takeaway
LaTeXML emulates TeX in Perl, relying on hand-written `.ltxml` bindings for 400+ packages; unsupported packages are skipped unless `--includestyles` tries the raw `.sty`. It has no DOCX output: its targets are HTML/MathML/SVG, JATS, ePub, TEI via its own XML. About 75% of arXiv papers convert without errors as of 2026.

### Cited Findings
- "The approach is to emulate TeX as far as possible (in Perl), converting the TeX or (LaTeX) document into LaTeXML's XML format"; outputs "HTML of various flavors, with MathML and SVG, or into JATS or ePub"; "there are gaps in fidelity and coverage"; current version 0.8.8. ([LaTeXML home](https://math.nist.gov/~BMiller/LaTeXML/))
- `--includestyles` lets latexml load raw `.sty/.cls/.clo/.cnf`; by default these are ignored unless an `.ltxml` binding exists. ([latexml command docs](https://math.nist.gov/~BMiller/LaTeXML/manual/commands/latexml.html); [Common::Config](https://metacpan.org/pod/LaTeXML::Common::Config))
- arXiv (Feb 2024): "some 25% of papers had conversion errors... Only 3% totally fail conversion"; LaTeXML has special-case implementations for "more than 400 of the most commonly used LaTeX packages", with a long tail (TikZ the major example) unsupported. ([arXiv 2402.08954](https://arxiv.org/html/2402.08954v1))
- arXiv (May 2026): "About 97% of submissions currently produce some HTML; that figure is an availability ceiling rather than a quality claim"; the fraction converting without LaTeXML errors "has slipped to roughly 75%", as venues "adopt new macro packages, and dependencies continue to migrate toward newer LaTeX 3 definitions." ([arXiv 2605.16562](https://arxiv.org/html/2605.16562v1))

### Inferences
- LaTeXML shows the ceiling of the "reimplement the engine" strategy: even a decades-long, well-funded effort sits at ~75% error-free on real-world sources, and the error rate rises as the ecosystem moves. A DOCX path would have to be LaTeXML to HTML/JATS then pandoc, stacking two lossy steps.

### Gaps
- No first-party LaTeXML DOCX writer found; I did not find a documented, maintained LaTeXML to DOCX pipeline.

## 4. PDF-side converters (Word PDF Reflow, Acrobat, Aspose, pdf2docx, ABBYY)

### Takeaway
These all accept output of the real typesetter, so any template "works", but they must recover paragraphs, tables and headers from positioned glyphs. Every vendor exposes the same trade-off as an explicit switch: preserve look (text boxes, absolute placement, poor editability) versus reflow (editable paragraphs, drift in line/page breaks).

### Cited Findings
- Microsoft: "PDF is a fixed file format, which means the file stores the location of text, pictures, and vector graphics on a page, but not necessarily the relationships among them." Elements that do not convert well: tables with cell spacing, page colors and borders, tracked changes, frames, footnotes spanning more than one page, endnotes, audio/video/interactive elements, PDF bookmarks/tags/comments, font effects such as Glow or Shadow. Works best on text-heavy business/legal documents; image-heavy PDFs may become non-editable images. ([Microsoft Support: Opening PDFs in Word](https://support.microsoft.com/en-us/word/opening-pdfs-in-word?CorrelationId=5b841d52-0337-4b5a-8f97-0877d13cd074&ad=US&app=pdfreflow.exe&rs=en-US&ui=en-US&ver=16))
- Aspose.PDF `RecognitionMode`: Textbox "is fast and good for maximally preserving original look of the PDF file, but editability of the resulting document could be limited"; Flow is "Full recognition mode, the engine performs grouping and multi-level analysis to restore the original document author's intent and produce a maximally editable document"; EnhancedFlow is "An alternative Flow mode that supports the recognition of tables." ([Aspose.PDF API reference](https://reference.aspose.com/pdf/net/aspose.pdf/docsaveoptions.recognitionmode/))
- Adobe Acrobat offers the same split: "Retain Flowing Text" versus "Retain Page Layout", the latter "may split the text into different text box groups to retain the original design." ([Adobe community thread](https://community.adobe.com/t5/acrobat-services-api-discussions/exportpdfoperation-word-format-retain-page-layout-and-retain-flowing-text/td-p/12725499)). Users have long complained about text-box output ([Acrobat UserVoice: "Export to MS Word without putting every piece of text in a text box"](https://acrobat.uservoice.com/forums/590923-acrobat-for-windows-and-mac/suggestions/20393680-export-to-ms-word-without-putting-every-piece)).
- The TeX FAQ's verdict on PDF routes: Acrobat Reader or PDF Exchange Editor "will output rather feeble files that Word can read." ([TeX FAQ](https://texfaq.org/FAQ-fmtconv)) (older wording; Acrobat has improved since, so treat as historical.)
- pdf2docx: "extract data from PDF with PyMuPDF, parse layout with rule, and generate docx with python-docx" ([docs](https://pdf2docx.readthedocs.io/en/latest/)). Feature list (v0.5.8 README): page margin, section and 1 or 2 columns, "page header and footer [TODO]", list style [TODO], OCR [TODO], inline and floating images, tables with borders/shading/merged cells/nested tables. Limitations: "Text-based PDF file; Left to right language; Normal reading direction, no word transformation / rotation; Rule-based method can't 100% convert the PDF layout." ([pdf2docx v0.5.8 README](https://raw.githubusercontent.com/ArtifexSoftware/pdf2docx/v0.5.8/README.md)). Status 2026: "pdf2docx is no longer actively maintained by Artifex", relicensed MIT, latest PyPI 0.5.13. ([pdf2docx repo](https://github.com/ArtifexSoftware/pdf2docx); [PyPI](https://pypi.org/project/pdf2docx/))

### Inferences
- PDF-side conversion is the only strategy where "arbitrary template" is truly free, and it is the only one where structure (headings, lists, running headers, TOC) must be inferred and can be guessed wrong silently. The recurring losses across vendors are the same set: headers/footers, tables (especially spaced or borderless), footnotes crossing pages, and line/page-break drift once text reflows in Word's own line breaker with different metrics.
- Because the Typst exporter in this repo is already PDF-side (pdf2docx plus repair passes, text-coverage check), the vendor docs confirm its known pain points are intrinsic to the approach, not implementation bugs.

### Gaps
- No public, independent benchmark comparing Word Reflow, Acrobat, ABBYY and Aspose on the same corpus was found. ABBYY FineReader specifics were not researched in the call budget.

## 5. Commercial and other tools (GrindEQ, latex2rtf, Writer2LaTeX, docx4j)

### Takeaway
GrindEQ is a Windows Word add-in that parses LaTeX itself (not a TeX engine), strong on equations and Word-native numbering; latex2rtf is a stalled subset parser; Writer2LaTeX goes the other way (ODT to LaTeX); docx4j is a Java DOCX library, not a LaTeX converter.

### Cited Findings
- GrindEQ: "This is not a complete LaTeX compiler. Some LaTeX features are disabled in this version, because it focuses mainly on conversion of LaTeX equations." It maps LaTeX sectioning to Word styles (Heading 1, 2...), converts equations to Microsoft Equation, Equation 3.x or MathType, offers "a choice of LaTeX's cross-referencing algorithm or Microsoft Word's cross-referencing fields", supports BibTeX, and "works with Microsoft Word for Windows." ([GrindEQ LaTeX-to-Word](https://grindeq.com/latex-to-word/); [older product page](https://www.grindeq.com/index.php?p=latex2word))
- latex2rtf "converts only a limited subset of LaTeX markup; development stalled" (entry dated 2020-06-23). ([TeX FAQ](https://texfaq.org/FAQ-fmtconv))
- Writer2LaTeX: converters from ODF to LaTeX/BibTeX, XHTML+MathML and EPUB, by Henrik Just; last SourceForge news 2023-06-16 (Writer2xhtml 1.7). ([SourceForge project](https://sourceforge.net/projects/writer2latex/); [news](https://sourceforge.net/p/writer2latex/news/)) It is the reverse direction and not relevant to LaTeX to Word except as the LibreOffice ecosystem around ODT.

### Inferences
- GrindEQ's own disclaimer puts it in the source-syntax camp: arbitrary class files and custom layouts will not be honoured. Its selling point, Word-native equations and cross-reference fields, is the same "native Word objects" lesson as pandoc.

### Gaps
- docx4j: not researched with sources in budget; from general knowledge it is a Java library for building/manipulating OOXML with no LaTeX reader, so it is a possible *writer* backend, not a converter. Unsourced, treat as unverified.
- No academic paper comparing LaTeX to Word fidelity across these tools was found. GrindEQ support for user `\newcommand` is undocumented on its site.

## Summary: which evaluate the real typesetter

| Tool | Where it converts | Runs real TeX? | Arbitrary template | Editability | Visual fidelity |
|---|---|---|---|---|---|
| pandoc | source AST | no | no (packages not loaded, [#10617](https://github.com/jgm/pandoc/issues/10617)) | high (real styles, fields) | low; comes from reference.docx |
| GrindEQ | source parse in Word | no ("not a complete LaTeX compiler") | no | high | medium for math |
| LaTeXML | re-implemented engine | emulated in Perl | ~75% error-free on arXiv (2026) | n/a (no DOCX) | n/a |
| tex4ht/make4ht | inside real engine (DVI specials), ODT, LibreOffice | yes | macros yes; layout-only code not mapped | high via ODT styles | page geometry not preserved (inference) |
| Word Reflow / Acrobat / Aspose / pdf2docx | final PDF | yes (upstream) | yes | trades off against look | high in text-box mode, drifts in flow mode |

### Inferences (overall)
- No LaTeX tool delivers both near-identical visuals and fully editable Word for arbitrary templates. The two properties pull in opposite directions at every layer, and every PDF vendor exposes that as an explicit mode switch.
- The strategy that best combines "any template works" with "structure known" is the in-engine one (tex4ht). For Typst, the equivalent is to read the laid-out document from the compiler (element tree plus frame positions) rather than parse source or reverse-engineer the PDF; a hybrid (structure from the compiler, geometry from the laid-out frames) avoids the structural guessing that makes PDF-side repairs lossy.
