// Does this report reach for a Typst package?
//
// `#import "@preview/cetz:0.2.2"` makes the typst CLI fetch from
// packages.typst.org, from whatever network the relay's host sits in, and
// cache it under the user data directory. Server export refuses those and
// points at the browser, which has its own registry story.
//
// The match is on the quoted spec ANYWHERE in the source, not on an #import
// statement, because the statement is not the only way to reach the same
// loader: `#let p = "@preview/x:1.0"` then `#import p`, `#{ import "..." }`
// and `#import("...")` all work, and all were measured to fetch. The cost is
// that a report merely quoting such a string in prose is refused too. That
// is the right way round: the refusal names the browser export, while a miss
// would mean network traffic from the relay's host, and the message says
// "imports or mentions" so nobody hunts for an import that is not there.
//
// Pure: no fs, so src/test covers it through the .d.mts beside this file.
const PACKAGE_SPEC = /"(@(?:preview|local)\/[^"\n]{1,120})"/;

/** The first package spec in the source, without its quotes, or null. */
export function findPackageSpec(source) {
  const m = PACKAGE_SPEC.exec(String(source ?? ''));
  return m ? m[1] : null;
}
