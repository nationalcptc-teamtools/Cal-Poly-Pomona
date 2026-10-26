#set page(paper: "a4", margin: 2cm)
#set text(font: "Libertinus Serif", size: 11pt)
#set heading(numbering: "1.")
#let thm-counter = counter("thm")
#let env(kind, fill, bar) = body => {
  thm-counter.step()
  block(fill: fill, stroke: (left: 3pt + bar), inset: 10pt, width: 100%, radius: 2pt)[
    *#kind #context thm-counter.display().* #body
  ]
}
#let definition = env("Definition", rgb("#f3fbef"), rgb("#3a8a2e"))
#let theorem = env("Theorem", rgb("#eef4ff"), rgb("#2b5cb8"))
#let remark = env("Remark", rgb("#fff6e5"), rgb("#c77700"))

= Lecture 4: Hash functions

#definition[
  A hash function is a map $H: {0,1}^* -> {0,1}^n$ that is cheap to compute
  for any input.
]

Three properties are usually asked of a cryptographic hash function:

+ *Preimage resistance.* Given $y$, finding $x$ with $H(x) = y$ is hard.
+ *Second preimage resistance.* Given $x$, finding $x' != x$ with
  $H(x') = H(x)$ is hard.
  - This is weaker than collision resistance.
  - It is what a file checksum relies on.
+ *Collision resistance.* Finding any pair $x != x'$ with $H(x) = H(x')$
  is hard.

#theorem[
  If $H$ is collision resistant then it is second preimage resistant.
]

#remark[
  The converse fails: a function can resist second preimages and still have
  collisions that are easy to find.
]

#lorem(90)

= Lecture 5: The birthday bound

#theorem[
  Among $q$ uniformly random values in a set of size $N$, a collision occurs
  with probability at least $1 - e^(-q(q-1) slash 2N)$.
]

#lorem(120)

#definition[
  The *work factor* of an attack is the expected number of evaluations of $H$
  it needs.
]

#lorem(80)
