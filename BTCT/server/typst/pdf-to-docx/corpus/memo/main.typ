#set page(paper: "us-letter", margin: 1in)
#set text(font: "Libertinus Serif", size: 11pt)
#set par(justify: true)

#align(center, text(16pt, weight: "bold")[MEMORANDUM])
#v(0.8em)
#grid(
  columns: (auto, 1fr),
  column-gutter: 1em,
  row-gutter: 0.6em,
  [*To:*], [All engineering staff],
  [*From:*], [Office of the CISO],
  [*Date:*], [29 September 2026],
  [*Subject:*], [Rotation of shared service credentials],
)
#v(0.4em)
#line(length: 100%, stroke: 0.6pt)

Following the internal assessment completed last month, every shared service
account in the build and deployment pipeline will have its credentials rotated
before the end of the quarter. The assessment found four accounts whose
passwords had not changed since they were created, and two of those were
readable by any member of the engineering group.

The rotation happens in three waves. The first covers the accounts used by the
continuous integration runners and starts on Monday. The second covers the
deployment keys held in the configuration repository. The third covers the
monitoring and backup agents, which need a maintenance window because the
agents restart when their credentials change.

#lorem(120)

Questions about the schedule go to the security team's queue rather than to
individual engineers, so that every answer is recorded once and can be found
again.

#lorem(90)
