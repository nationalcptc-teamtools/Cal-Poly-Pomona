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
