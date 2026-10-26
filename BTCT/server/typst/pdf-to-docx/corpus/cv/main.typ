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
