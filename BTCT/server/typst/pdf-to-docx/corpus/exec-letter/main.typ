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
