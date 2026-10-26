#set page(
  paper: "a4",
  margin: (x: 2cm, top: 2.6cm, bottom: 2.2cm),
  header: [
    #set text(8pt, fill: luma(110))
    Northwind Labs #h(1fr) Web Application Assessment
    #v(-0.5em)
    #line(length: 100%, stroke: 0.4pt + luma(160))
  ],
  footer: context [
    #set text(8pt, fill: luma(110))
    CONFIDENTIAL #h(1fr) Page #counter(page).display("1 of 1", both: true)
  ],
)
#set text(font: "Noto Sans", size: 10pt)
#set heading(numbering: "1.")
#show heading.where(level: 1): set text(fill: rgb("#0b3d91"))
#show raw.where(block: true): block.with(fill: luma(245), inset: 8pt, radius: 3pt, width: 100%)

#let severity-colour = (
  Critical: rgb("#6a1b9a"),
  High: rgb("#c62828"),
  Medium: rgb("#ef6c00"),
  Low: rgb("#2e7d32"),
)

#let finding(id, title, severity, cvss, body) = block(
  breakable: false,
  stroke: 0.6pt + luma(200),
  radius: 4pt,
  width: 100%,
  clip: true,
)[
  #block(fill: severity-colour.at(severity), inset: 8pt, width: 100%, spacing: 0pt)[
    #text(fill: white, weight: "bold")[#id #h(0.6em) #title #h(1fr) #severity (CVSS #cvss)]
  ]
  #block(inset: 10pt, spacing: 0pt)[#body]
]

= Summary of findings

#table(
  columns: (auto, 1fr, auto),
  fill: (_, row) => if row == 0 { luma(230) },
  table.header([*ID*], [*Finding*], [*Severity*]),
  [NW-01], [SQL injection in the order search], text(fill: severity-colour.Critical)[*Critical*],
  [NW-02], [Session token not rotated at login], text(fill: severity-colour.High)[*High*],
  [NW-03], [Verbose errors disclose stack traces], text(fill: severity-colour.Medium)[*Medium*],
  [NW-04], [Missing security headers], text(fill: severity-colour.Low)[*Low*],
)

= Findings

#finding("NW-01", "SQL injection in the order search", "Critical", "9.8")[
  The `q` parameter of `/orders/search` is concatenated into a SQL query.
  A single quote returns a database error and a boolean payload changes the
  number of rows returned.

  ```http
  GET /orders/search?q=1'%20OR%20'1'='1 HTTP/1.1
  Host: shop.northwind.example
  ```

  *Affected hosts*
  #table(columns: (auto, auto), [shop.northwind.example], [10.20.0.15],
    [shop-staging.northwind.example], [10.20.8.15])

  *Recommendation.* Use parameterised queries for every database call.
]

#v(0.8em)
#finding("NW-02", "Session token not rotated at login", "High", "7.5")[
  The `SESSION` cookie issued before authentication stays valid afterwards,
  so an attacker who plants a token can ride the victim's session.
  #lorem(40)

  *Recommendation.* Issue a new session identifier at every privilege change.
]

#v(0.8em)
#finding("NW-03", "Verbose errors disclose stack traces", "Medium", "5.3")[
  #lorem(60)
  ```text
  java.lang.NullPointerException
      at com.northwind.orders.SearchController.search(SearchController.java:88)
  ```
]

#v(0.8em)
#finding("NW-04", "Missing security headers", "Low", "3.1")[
  #lorem(50)
]
