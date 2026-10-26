"""The Typst sources test_convert.py compiles, one per behaviour it pins.

Kept beside the test rather than inside it because they are documents, not
code: each one is a shape that made the converter delete part of a report, and
reading them is how you see what the thresholds in convert.py are for.
"""

# Every page's bottom rows are a table row whose only difference from the row
# above is a number, and digit blanking made them all the same text. Two of
# them landed at the same height and were lifted out as a running footer, so
# `Host-111` left the Word file and `Host-073` became the footer of every
# page. Nothing here may be detected as a band.
TABLE = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 10pt)
= Open ports
#table(
  columns: (auto, auto, 1fr),
  table.header([*Host*], [*Address*], [*Finding*]),
  ..range(1, 121).map(i => (
    [Host-#{ if i < 100 { "0" } }#i],
    [10.0.0.#i],
    [Open port finding number #i],
  )).flatten(),
)
"""

# A real running header with the same first body line under it on every page.
# The line sits about 12 pt below the header, inside the glue that holds the
# lines of one band together, so it was deleted from all four pages and
# pasted into the Word header. The header must be lifted and the body line
# must stay where it is.
FIRST_BODY_LINE = """
#set page(
  paper: "us-letter",
  margin: 1in,
  header: align(left)[Acme Security Assessment],
  footer: align(center)[#context counter(page).display()],
)
#set text(size: 11pt)
#for i in range(4) [
  #lorem(300)
  #pagebreak(weak: true)
]
"""

# Odd and even pages carry different headers. Both cleared the old quorum, so
# every page's Word header read "Acme Security Assessment Contoso Consulting
# Group". Word can express this and this script does not, so the edge has to
# be declined and said out loud.
ODD_EVEN = """
#set page(
  paper: "a4",
  margin: 2cm,
  header: context {
    if calc.odd(counter(page).get().first()) [Acme Security Assessment]
    else [Contoso Consulting Group]
  },
)
#set text(size: 11pt)
#for i in range(4) [
  = Section #(i + 1)
  #lorem(120)
  #pagebreak(weak: true)
]
"""

# The shape the whole feature exists for: a cover with no band, a running
# header and footer with a page number, and a table of contents with dot
# leaders. Both repairs have to run, and nothing may be reported.
REPORT = """
#set page(
  paper: "us-letter",
  margin: (x: 2cm, y: 2.2cm),
  header: context {
    if counter(page).get().first() > 1 [
      #grid(columns: (1fr, 1fr), align(left)[Acme Security Assessment], align(right)[Contoso Ltd])
      #line(length: 100%, stroke: 0.5pt)
    ]
  },
  footer: context {
    if counter(page).get().first() > 1 {
      grid(columns: (1fr, 1fr),
        align(left)[CONFIDENTIAL],
        align(right)[#(counter(page).get().first() - 1)])
    }
  },
)
#set text(size: 11pt)
#align(center + horizon)[#text(size: 28pt)[Acme Security Assessment] \\ Prepared for Contoso]
#pagebreak()
= Table of contents
#for (title, page) in (("Introduction", 3), ("Scope of the engagement", 4),
                       ("Findings and remediation", 5), ("Appendix A: methodology", 6)) [
  #box(width: 100%)[#title #box(width: 1fr, repeat[.]) #page]
]
#pagebreak()
= Introduction
#lorem(120)
#pagebreak()
= Scope of the engagement
#lorem(120)
#pagebreak()
= Findings and remediation
#lorem(120)
#pagebreak()
= Appendix A: methodology
#lorem(120)
"""

# The same, with titles in three scripts. `squash` used to reduce a Cyrillic
# title to the empty string, which matched nothing, and an entry that matched
# nothing was deleted along with the rest of its stretch.
MIXED_SCRIPT_TOC = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 11pt, font: "Libertinus Serif")
= Table of contents
#for (title, page) in (("Introduction", 2), ("Глава первая", 3),
                       ("Κεφάλαιο δύο", 4), ("Conclusions", 5)) [
  #box(width: 100%)[#title #box(width: 1fr, repeat[.]) #page]
]
#pagebreak()
= Introduction
#lorem(60)
#pagebreak()
= Глава первая
#lorem(60)
#pagebreak()
= Κεφάλαιο δύο
#lorem(60)
#pagebreak()
= Conclusions
#lorem(60)
"""

# What a report can put in front of a client who opens the Word file. Only the
# last two may survive into `word/_rels/`.
LINKS = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 11pt)
= Links
- #link("FILE://attacker.example/share/x")[Read the appendix]
- #link("smb://attacker.example/share/y")[Share]
- #link("javascript:alert(1)")[Script]
- #link("ms-msdt:/id PCWDiagnostic")[Diagnostic]
- #link("\\\\\\\\attacker.example\\\\share\\\\z")[UNC]
- #link("https://example.com/ok")[Normal link]
- #link("mailto:team@example.com")[Mail us]
"""

# A running header, a per-page DISTINCT finding title just under it, and a
# repeating full-width rule below the title. The rule is a band decoration, so
# the erased rectangle used to be grown to reach it, and that rectangle is the
# whole page width: all eight titles were deleted, with the text check blind
# to it because it excluded the same rectangle from both sides.
RULE_OVER_TITLES = """
#set page(
  paper: "a4",
  margin: 2cm,
  header: align(left)[Acme Security Assessment],
)
#set text(size: 11pt)
#for i in range(8) [
  #v(2pt)
  #text(size: 13pt, weight: "bold")[Finding #(i + 1): unique title #(i + 1)]
  #v(1pt)
  #line(length: 100%, stroke: 0.6pt)
  #lorem(80)
  #pagebreak(weak: true)
]
"""

# Every page holds one line of text and nothing else, so the gap between the
# candidate and the body cannot be measured anywhere. That used to count as a
# pass, and the one line on each page was lifted into the Word header while
# the text check, left with nothing to compare, reported success.
NOTHING_BUT_A_BAND = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 11pt)
#for i in range(4) [
  Quarterly review of the control set
  #pagebreak(weak: true)
]
"""

# A justified paragraph that hyphenates at a line end, plus a real hyphen at a
# line end. Typst writes its own break hyphens as U+00AD and the real one as
# U+002D, so the first must disappear from the Word file and the second must
# not.
HYPHENS = """
#set page(paper: "a4", margin: (x: 2cm, y: 2cm))
#set text(size: 11pt, lang: "en")
#set par(justify: true)
= Hyphenation
{{OUR_COMPANY}} employed a custom, heuristic risk assessment system to measure
overall criticality, and the likelihood ratings were assigned appropriately by
the assessment team throughout the engagement so that every finding carries a
defensible rating.

Affects a small number of users and results in the disclosure of non-critical
information such as verification that a user exists on the system.
"""

# A code block on a grey panel holding two strings a space would change, and
# the same two shapes in prose where the PDF shows a real gap. The marker
# repair has to fix the prose and leave the command alone: the text check
# squashes whitespace, so a space added inside a command is invisible to it.
CODE_AND_MARKERS = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 11pt)
= Remediation
#block(fill: rgb(235, 235, 235), inset: 10pt, width: 100%)[
  #text(font: "DejaVu Sans Mono", size: 9pt)[
    ./deploy 1.{{X}} \\
    check version1.2.3
  ]
]

Then apply the following, in order:

+ {{X}} must be rebuilt first.
+ version1.2.3 is the baseline.
"""

# Cheap for typst, expensive for the converter: 120,000 one-point rectangles
# a page. It has to be refused before pdf2docx is started.
SHAPES = """
#set page(paper: "a4", margin: 0cm)
#for p in range(2) {
  for i in range(120000) {
    place(
      dx: calc.rem(i, 560) * 1pt,
      dy: calc.rem(i * 7, 800) * 1pt,
      rect(width: 1pt, height: 1pt, fill: rgb(20, 60, 200)),
    )
  }
  pagebreak(weak: true)
}
"""

# Numbers inside Hebrew lines. The right-to-left repair once read a span of
# digits as punctuation and turned it round, so the Word file said "1.4.2",
# "5.0.0.01" and "4202", and the text check, comparing against that same
# reading, called it complete. Set in rtl-mixed's fonts: compile it as a
# corpus document so corpus/fonts is on the font path.
RTL_NUMBERS = """
#set page(paper: "a4", margin: 2cm)
#set text(font: ("Noto Sans", "Noto Sans Hebrew"), size: 10.5pt)
#text(lang: "he")[
  גרסה 2.4.1 חשופה לתקיפה מרחוק.

  השרת בכתובת 10.0.0.5 פגיע.

  הבעיה נמצאה בשנת 2024.
]
"""

# Numbers after Hebrew inside English lines. The bidi algorithm draws a
# number that follows a Hebrew phrase to that phrase's left, and the page
# shows "12 שרת ראשי" whether the source said "שרת ראשי 12" or "12 שרת ראשי",
# so nothing on the page tells the two apart. The repair once took the page's
# order for the reading and wrote "Server 12 שרת ראשי" into Word, and the text
# check, reading the same way, called it complete. Set in rtl-mixed's fonts:
# compile it as a corpus document so corpus/fonts is on the font path.
RTL_AMBIGUOUS_NUMBERS = """
#set page(paper: "a4", margin: 2cm)
#set text(font: ("Noto Sans", "Noto Sans Hebrew"), size: 10.5pt)

Server שרת ראשי 12 and שרת משני 7 were tested.

The policy "מדיניות אבטחה 2024" was reviewed.

We reached the host (שרת 5) and stopped there.
"""

# Arabic-Indic digits in Arabic lines. PyMuPDF hands a number of two
# Arabic-Indic digits back turned round ("١٢" read as "٢١"), and pdf2docx
# writes what it is handed, so a check that reads the page the same way
# agreed with a Word file saying 21 where the PDF says 12. European digits
# in the same lines read the right way round. Set in rtl-arabic's font:
# compile it as a corpus document so corpus/fonts is on the font path.
RTL_ARABIC_DIGITS = """
#set page(paper: "a4", margin: 2cm)
#set text(font: "Noto Naskh Arabic", lang: "ar", size: 12pt)

وجدنا ١٢ جهازًا مصابًا في الشبكة.

تغطي الحسابات المشتركة ٥٠٪ من الخوادم.

فحصنا 34 خادمًا في المجموع.
"""

# A bordered table, then a rounded box holding prose and a shaded code line,
# then a footer in two pieces as the page's last row. pdf2docx reads the
# footer as a borderless table and looks for the block just above it to start
# that table at, but its list holds the page's lines first and its tables
# last, so the "block just above" is the bordered table at the top. The
# borderless table then reaches up to the box, is cut into two columns where
# the footer's pieces sit, and every prose line lost the words that crossed
# the cut, at every rung. The prose must reach the Word file whole.
FOOTER_TABLE_REACH = """
#set page(paper: "a4", margin: 2cm, footer: [CONFIDENTIAL #h(1fr) Page 1 of 1])
#set text(size: 10pt)
#table(columns: (auto, 1fr), [ID], [Finding])
#block(stroke: 0.6pt, radius: 4pt, inset: 10pt, width: 100%)[
  #lorem(60)
  #block(fill: luma(235), inset: 8pt, width: 100%)[`java.lang.NullPointerException`]
]
"""

# A letter: a right-aligned sender's address of three lines, then the
# recipient and the body. The converter writes the address at 13.8 pt where the
# PDF set it at 14.4 pt, and the page's first block is too far off for the
# rhythm pass to trust the page top, so it anchors on the address instead and
# assumes it ends where the PDF's rows do. It ends 1.2 pt away, and every
# block under it was moved by that much, where the converter's own spacing
# had them within 0.3 pt. The rhythm pass must leave such a page alone.
UNEVEN_ANCHOR = """
#set page(paper: "a4", margin: (x: 2.5cm, y: 2cm))
#set text(size: 11pt)
#align(right)[
  Contoso Security Ltd \\
  12 Harbour Street \\
  Bristol BS1 4XX
]
#v(1.5em)
Ms Jane Doe \\
Head of IT \\
Fabrikam Inc.

Dear Ms Doe,

#lorem(60)
"""

# Numbered headings each followed by a paragraph, which the converter writes
# as one block with the heading's line and the paragraph's. It sets that block
# at the paragraph's pitch, which is the PDF's. The rhythm pass gives a block
# one exact height, and the smallest that holds the heading's capitals is taller
# than that pitch, so an assessment's conclusion had its six body lines spread
# 2.7 pt apart each. The rhythm pass must leave such a block as it was written.
HEADING_IN_PARAGRAPH = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 10.5pt)
#set heading(numbering: "1.")
= Scope
#lorem(120)

= Conclusion
#lorem(80)
"""

# An HTTP request in a grey panel, with a blank line before its body, above a
# figure. pdf2docx colours the first three lines itself, as cells of tables of
# their own, and leaves the body line bare. The panel pass found only that
# bare line to paint and shaded it as a stripe of its own, a second grey shape
# beside the converter's, which cost the corpus's rtl-in-shapes 0.0016 of mean.
# A panel the converter has already coloured in part must be left to it.
PANEL_PARTLY_SHADED = """
#set page(paper: "us-letter", margin: 1in)
#set text(font: "Libertinus Serif", size: 11pt)
#show raw: set text(font: "DejaVu Sans Mono")
#show raw.where(block: true): block.with(fill: luma(240), inset: 8pt, radius: 3pt, width: 100%)

```http
POST /ar/products/88/comments HTTP/1.1
Host: shop.example
Content-Type: application/x-www-form-urlencoded

comment=hello world ok<script>alert(1)</script>
```

#figure(
  rect(width: 70%, height: 3cm, fill: luma(230))[#align(center + horizon)[screenshot]],
  caption: [The product page after the payload runs: page after the code runs here],
)
"""

# A heading over a two-line paragraph at the top of the page. The
# converter writes an empty paragraph above the heading, with 23 pt of spacing
# after it, and the heading's own spacing before is 3 pt. Word keeps the
# larger of the two, so the heading sits about 2 pt from the PDF's; the rhythm
# pass measured the move against the 3 pt alone, read 18 pt, decided it had
# not understood where the page starts, and fell back to anchoring on a block
# further down. The first move must be measured against the gap Word draws.
SPACER_ABOVE_HEADING = """
#set page(paper: "us-letter", margin: 1in)
#set text(size: 11pt)
= Stored cross-site scripting in the comment form

The comment field of the storefront accepts markup. The request below
stores a comment that runs script for every visitor who opens the product page.

#lorem(80)
"""

# Justified paragraphs whose first line is indented, as an academic paper sets
# them. Every line but the first starts at the text area's left edge, so the
# alignment pass found those lines as a flush-left run, matched the paragraph
# that holds them, and zeroed its first-line indent: every first line came out
# 9 to 10 pt left of the PDF's. The pass must leave a paragraph whose first line
# is not in the run as the converter wrote it.
INDENTED_FIRST_LINE = """
#set page(paper: "a4", margin: 2cm)
#set text(size: 10.5pt)
#set par(justify: true, first-line-indent: (amount: 1.5em, all: true))
#lorem(70)

#lorem(60)
"""

# An English code line with Arabic inside it, and an English caption ending
# in Arabic. pdf2docx writes each as one run, and the right-to-left repair
# marked every run holding an Arabic letter `w:rtl`, which tells Word the whole
# run reads right to left: the payload came out as
# "<script>alert(1)</script>بالعالم مرحبا=comment". Only a run with no
# left-to-right letter may be marked. Set in rtl-in-shapes' fonts: compile it
# as a corpus document so corpus/fonts is on the font path.
RTL_IN_CODE = """
#set page(paper: "a4", margin: 2cm)
#set text(font: ("Libertinus Serif", "Noto Naskh Arabic"), size: 11pt)
#show raw: set text(font: ("DejaVu Sans Mono", "Noto Naskh Arabic"))
#show raw.where(block: true): block.with(fill: luma(240), inset: 8pt, width: 100%)
```http
comment=مرحبا بالعالم<script>alert(1)</script>
```
The product page after the payload runs: #text(lang: "ar")[صفحة المنتج بعد تنفيذ الشيفرة]
"""

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

# The reference report's band shape: a rule under the header and a grey strip
# the full width of the page behind the footer, both drawn inside typst's
# Header and Footer artifacts. Removing the artifacts removes them from the
# PDF too, so the tagged path has to carry them into the Word header and
# footer as the heuristic did.
TAGGED_DECORATED = """
#set page(
  paper: "us-letter", margin: (x: 54pt, y: 72pt),
  header: context { if counter(page).get().first() > 1 {
    block(width: 100%, inset: (bottom: 3pt), stroke: (bottom: 1pt + rgb("#1d2439")))[Acme Security Assessment #h(1fr) Contoso Ltd]
  } },
  footer-descent: 0pt,
  footer: context { if counter(page).get().first() > 1 {
    place(bottom + left, dx: -54pt, rect(width: 612pt, height: 22pt, fill: luma(243), stroke: none))
    place(bottom, dy: -5pt, block(width: 100%, text(size: 9pt)[CONFIDENTIAL #h(1fr) #counter(page).display()]))
  } },
)
#set text(size: 11pt)
#align(center + horizon, text(24pt)[Acme Security Assessment])
#for i in range(4) [
  #pagebreak()
  = Section #(i + 1)
  #lorem(250)
]
"""

# A footer, and a body line with the footer's text as the first line of every
# page. A deep bottom margin puts the footer farther from the bottom edge than
# the body line is from the top, so choosing the removed copy by "nearest a
# page edge" took the body line for the band: a running header the PDF never
# had, and the footer left in the body. The removed copy is the one no row of
# the stripped page still sits on.
TAGGED_FOOTER_TEXT_IN_BODY = """
#set page(paper: "us-letter", margin: (top: 20pt, bottom: 120pt, x: 72pt), footer: [CONFIDENTIAL])
#set text(size: 11pt)
CONFIDENTIAL

#lorem(300)
#pagebreak()
CONFIDENTIAL

#lorem(300)
"""

# The report title is both the running header and the first heading of the
# body. Only the header copy may be lifted; the heading stays in the body.
TAGGED_TITLE_IN_BODY = """
#set page(paper: "a4", margin: 2cm, header: [Quarterly Status Report], footer: context [#counter(page).display()])
#set text(size: 11pt)
= Quarterly Status Report
#lorem(500)
"""

# A header artifact on one page of five, and a page number on every page. One
# page's artifact is not a running band: Word would repeat it on every page.
TAGGED_ONE_PAGE_HEADER = """
#set page(paper: "us-letter", margin: 1in,
  header: context { if counter(page).get().first() == 3 [Draft notice for page three] },
  footer: context [#align(center)[#counter(page).display()]])
#set text(size: 11pt)
#for i in range(5) [ = Section #(i + 1)
#lorem(350)
#pagebreak(weak: true) ]
"""

# A running header on every page, and one more line marked as a header
# artifact at the top of page three's body. That line appears on one page of
# the band's four, so it is not part of the band and must stay in the body.
TAGGED_ARTIFACT_IN_BODY = """
#set page(paper: "us-letter", margin: 1in,
  header: [Quarterly Status Report #h(1fr) Blue Harbor],
  footer: context [#align(center)[#counter(page).display()]])
#set text(size: 11pt)
#for i in range(4) [
#if i == 2 { pdf.artifact(kind: "header")[Placeholder note set apart on page three] }
= Section #(i + 1)
#lorem(350)
#pagebreak(weak: true) ]
"""

# The thesis shape: a page number on every page, and a running header that
# starts on page two. The first page gets the footer and no header.
TAGGED_LATE_HEADER = """
#set page(paper: "us-letter", margin: 1in,
  header: context { if counter(page).get().first() > 1 [Appendix material #h(1fr) Blue Harbor] },
  footer: context [#align(center)[#counter(page).display()]])
#set text(size: 11pt)
#for i in range(4) [ = Section #(i + 1)
#lorem(350)
#pagebreak(weak: true) ]
"""

# A tagged header on a report that turns one page sideways. It sits in the
# same place on every page, so the tags describe it as a running band, but
# the page sizes differ: it stays in the body, and the declines say so
# rather than naming the tags.
TAGGED_MIXED_SIZES = """
#set page(paper: "us-letter", margin: 1in,
  header: [Quarterly Status Report #h(1fr) Blue Harbor])
#set text(size: 11pt)
= Overview
#lorem(300)
#set page(flipped: true)
= Wide table
#lorem(200)
#set page(flipped: false)
= Details
#lorem(300)
"""

# A running header that names the chapter: its text changes in place from
# page to page, under a page number that does not. The first chapter's first
# page has no header at all, which is how typst's own templates leave it.
TAGGED_CHAPTER_HEADER = """
#set page(paper: "us-letter", margin: 1in,
  header: context {
    let before = query(heading.where(level: 1).before(here()))
    if before.len() > 0 [Status Report | #before.last().body]
  },
  footer: context [#align(center)[#counter(page).display()]])
#set text(size: 11pt)
#for name in ("Alpha", "Beta", "Gamma", "Delta") [
  #heading(level: 1)[#name chapter]
  #lorem(900)
  #pagebreak(weak: true)
]
"""

# A footer that swaps its two halves on odd and even pages, the way a bound
# report mirrors them. The words are the same and their order is not.
TAGGED_ODD_EVEN_FOOTER = """
#set page(paper: "us-letter", margin: 1in,
  footer: context {
    let n = counter(page).get().first()
    if calc.odd(n) [Page #n #h(1fr) CONFIDENTIAL] else [CONFIDENTIAL #h(1fr) Page #n]
  })
#set text(size: 11pt)
#for i in range(5) [ = Section #(i + 1)
#lorem(350)
#pagebreak(weak: true) ]
"""

# The page number alone, on the right of odd pages and on the left of even
# ones. Digits are blanked when rows are grouped, so before the group was
# keyed by where the row sits these read as one footer and every Word page
# got the number on the right.
TAGGED_MIRRORED_NUMBER = """
#set page(paper: "us-letter", margin: 1in,
  header: [Acme Pentest #h(1fr) Internal],
  footer: context {
    let n = counter(page).display("1")
    if calc.odd(here().page()) { align(right, n) } else { align(left, n) }
  })
#set text(size: 11pt)
#for i in range(4) [ = Section #(i + 1)
#lorem(300)
#pagebreak(weak: true) ]
"""

# Header and page number on every page of a report that turns one page
# sideways. The sideways page's band is its own: wider, and lower on the page.
TAGGED_LANDSCAPE_BAND = """
#set page(paper: "us-letter", margin: 1in,
  header: [Quarterly Status Report #h(1fr) Blue Harbor],
  footer: context [#align(center)[#counter(page).display()]])
#set text(size: 11pt)
= Overview
#lorem(300)
#set page(flipped: true)
= Wide table
#lorem(200)
#set page(flipped: false)
= Details
#lorem(300)
"""

# A tagged document with a dot-leader list that is not a table of contents
# (a price list). Without a TOC element in the tag tree nothing is rebuilt.
DOT_LEADERS_NOT_TOC = """
#set page(paper: "a4", margin: 2cm)
= Price list
#for (item, price) in (("Consulting day", "900"), ("Report review", "400"), ("Retest", "650")) [
  #item #box(width: 1fr, repeat[.]) #price \
]
#lorem(200)
"""

# A real #outline: the tag tree carries a TOC element, so the contents page is rebuilt.
OUTLINE_TOC = """
#set page(paper: "a4", margin: 2cm)
#set heading(numbering: "1.")
#outline()
#for i in range(24) [
  #pagebreak(weak: true)
  = Section heading number #(i + 1)
  #lorem(40)
]
"""

# A table too tall for one page inside a figure. Typst will not split a
# figure, so it sets the rows that do not fit on top of one another at the
# foot of the page, and says nothing. That text is in the PDF and cannot be
# read there, and pdf2docx keeps none of it with every pass off, so climbing
# down the ladder only threw away the header and footer for nothing. The file
# kept is the top rung, and the warning says the PDF is unreadable there.
STACKED_TABLE_FIGURE = """
#set page(paper: "us-letter", margin: 1in,
  header: [Acme Security Assessment #h(1fr) Contoso Ltd],
  footer: context align(center)[#counter(page).display()])
#set text(size: 11pt)
= Summary
#lorem(300)
#pagebreak()
#figure(
  table(columns: (1fr, 1fr),
    [*Finding*], [*Remediation*],
    ..range(1, 71).map(i => ([Finding number #i], [Remediation step for finding #i])).flatten(),
  ),
  caption: [Every finding],
)
#pagebreak()
= Details
#lorem(300)
"""

# A screenshot in a figure frame, as the CPTC template draws one: the image is
# scaled to the frame's width and clipped to its height, so the PDF draws
# 255 pt of picture and shows 158. pdf2docx floats the whole picture behind
# the text and reads the frame as an empty grey cell over it; the export has
# to crop the picture to the frame and put it inside.
FRAMED_FIGURE = """
#set page(paper: "us-letter", margin: 1in,
  header: [Acme Security Assessment #h(1fr) Contoso Ltd],
  footer: context align(center)[#counter(page).display()])
#set text(size: 11pt)
= Evidence
#lorem(40)
#figure(
  block(width: 100%, height: 158pt, fill: luma(245), stroke: 1pt + luma(180), clip: true,
    image("shot.png", width: 100%)),
  caption: [The service banner, as captured],
)
#lorem(60)
#figure(
  block(width: 100%, height: 158pt, fill: luma(245), stroke: 1pt + luma(180), clip: true,
    image("shot.png", width: 100%)),
  caption: [A second capture],
)
#lorem(30)
"""

# A token too long to break: typst lets the line run into the right margin,
# and pdf2docx keeps only what lies inside its page box (84 of 96
# characters), which sent a whole report down the ladder for twelve. The
# missing end is put back from the PDF's own text.
CUT_TOKEN = """
#set page(paper: "us-letter", margin: 1in,
  header: [Acme Security Assessment #h(1fr) Contoso Ltd],
  footer: context align(center)[#counter(page).display()])
#set text(size: 11pt)
#show raw.where(block: true): block.with(fill: luma(236), inset: 8pt, width: 100%)
= Evidence
#lorem(30)
```bash
$ wget -q https://10.10.5.198/downloads/releases/ff4629fd845fa1cd176399ea65b7059171fff6b3030246c47d407a174ed4463d7e431f0a7bac4fc2769d97834453b40f/package.tar.gz
[+] saved 1 file
```
#lorem(30)
"""
