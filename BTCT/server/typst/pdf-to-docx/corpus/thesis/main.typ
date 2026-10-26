#set page(
  paper: "a4",
  margin: (inside: 3cm, outside: 2cm, y: 2.5cm),
  numbering: "1",
  header: context {
    if counter(page).get().first() > 1 {
      set text(9pt)
      emph[Chapter 3. Fuzzing stateful protocols]
      h(1fr)
      counter(page).display()
    }
  },
)
#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true, first-line-indent: 1.2em)
#set heading(numbering: "1.1")
#set math.equation(numbering: "(1)")
#show figure.where(kind: table): set figure.caption(position: top)

#outline(depth: 2)
#pagebreak()
#counter(heading).update(2)

= Fuzzing stateful protocols

== Background
Random testing of programs has a long history: the first large study fed
random input to UNIX utilities and crashed a quarter of them @miller1990.
Whitebox approaches later used symbolic execution to reach deeper states
@godefroid2008.#footnote[Symbolic execution tracks inputs as formulas rather
than values, so a solver can pick the next input.] Network protocols add a
difficulty neither addresses: the server's response depends on every message
before it @pham2020.

A useful measure of how much a fuzzer has explored is the entropy of the
states it reached, where $p_i$ is the fraction of inputs that ended in state
$i$:

$ H = - sum_(i=1)^n p_i log_2 p_i $ <eq:entropy>

As @eq:entropy shows, a fuzzer that keeps reaching one state scores zero
however many inputs it sends.#footnote[This is the measure used in the
evaluation in Section 3.3.]

#figure(
  rect(width: 80%, height: 4cm, fill: luma(230), stroke: 0.6pt)[
    #align(center + horizon)[INIT #sym.arrow.r AUTH #sym.arrow.r READY #sym.arrow.r CLOSED]
  ],
  caption: [The four states of the target protocol.],
) <fig:states>

== Method
@fig:states shows the states the harness tracks. #lorem(110)

#figure(
  table(
    columns: 3,
    align: (left, right, right),
    table.header([*Fuzzer*], [*States*], [*Crashes*]),
    [Random], [2], [0],
    [AFLNet], [4], [3],
    [This work], [4], [7],
  ),
  caption: [States reached and crashes found in 24 hours.],
) <tab:results>

== Results
@tab:results summarises the runs. #lorem(140)

$ "coverage"(t) = 1 - e^(-lambda t) $

#lorem(100)

#bibliography("refs.bib")
