#!/usr/bin/env python3
"""Checks for scorecard_rules.py. Run: <venv>/python -I -B test_scorecard_rules.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scorecard_rules as rules  # noqa: E402


def row(full_ssim, raw_ssim, pdf_pages=None, full_pages=None, raw_pages=None,
        full_seconds=1.0, raw_seconds=1.0, fell_back=False, missing=0, reference=False):
    pdf_pages = pdf_pages if pdf_pages is not None else len(full_ssim)
    return {
        "name": "doc",
        "isReference": reference,
        "pdfPages": pdf_pages,
        "full": {"wordPages": full_pages if full_pages is not None else len(full_ssim), "ssim": full_ssim,
                 "seconds": full_seconds,
                 "result": {"textCheck": {"missing": missing, "fellBack": fell_back}}},
        "raw": {"wordPages": raw_pages if raw_pages is not None else len(raw_ssim), "ssim": raw_ssim,
                "seconds": raw_seconds,
                "result": {"textCheck": {"missing": 0, "fellBack": False}}},
    }


def expect(violations, prefix, label):
    ok = any(v.startswith(prefix) for v in violations)
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", label, violations))
    return ok


def expect_none(violations, label):
    ok = not violations
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", label, violations))
    return ok


def expect_true(ok, label):
    print("%-5s %s" % ("ok" if ok else "FAIL", label))
    return ok


def main():
    passed = True
    passed &= expect_none(rules.evaluate(row([0.95, 0.93], [0.90, 0.91])), "better than raw passes")
    passed &= expect_none(rules.evaluate(row([0.899, 0.91], [0.90, 0.91])), "inside the mean tolerance passes")
    passed &= expect(rules.evaluate(row([0.80, 0.80], [0.90, 0.90])), "3:", "a worse mean is rule 3")
    passed &= expect(rules.evaluate(row([0.99, 0.87], [0.90, 0.90])), "4:", "one page 0.03 worse is rule 4")
    passed &= expect(rules.evaluate(row([0.95], [0.90], fell_back=True)), "1:", "a fallback is rule 1")
    passed &= expect(rules.evaluate(row([0.95], [0.90], missing=2)), "1:", "missing text is rule 1")
    # Rule 2: full lands further from the PDF's page count than raw does.
    passed &= expect(rules.evaluate(row([0.9, 0.9, 0.9], [0.9, 0.9], pdf_pages=2, full_pages=3, raw_pages=2)),
                     "2:", "test_rules_page_count_worse is rule 2")
    passed &= expect_none(rules.evaluate(row([0.9, 0.9], [0.9, 0.9, 0.9], pdf_pages=2, full_pages=2, raw_pages=3)),
                          "test_rules_page_count_better passes")
    # Pages are only paired where both sides have one: a three-page full
    # against a two-page raw compares two pages and does not index past raw.
    passed &= expect_none(rules.evaluate(row([0.9, 0.9, 0.1], [0.9, 0.9], pdf_pages=3, full_pages=3, raw_pages=2)),
                          "test_rules_page_count_unpaired_page_is_not_scored")
    passed &= expect(rules.evaluate(row([0.90], [0.80], reference=True)), "5:", "the reference below its floor is rule 5")
    passed &= expect_none(rules.evaluate(row([0.92], [0.80], reference=True)), "the reference above its floor passes")
    passed &= expect(rules.evaluate(row([0.95], [0.90], full_seconds=9.0, raw_seconds=3.0)), "6:",
                     "full slower than twice raw plus 2 s is rule 6")
    passed &= expect(rules.evaluate({"name": "doc", "error": "typst failed"}), "error:", "an errored row reports it")

    # Rule 1 with a named reason (corpus.EXPECTED_FAILURES): no violation, and
    # the verdict prints the reason. Rules 2 to 6 still apply to the row.
    named = row([0.95], [0.90], fell_back=True, missing=3)
    named["namedReason"] = "RTL: table cells lose letters"
    passed &= expect_none(rules.evaluate(named), "a fallback with a named reason is no violation")
    verdict = rules.verdict(named, rules.evaluate(named))
    ok = verdict == "named: RTL: table cells lose letters"
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", "a named fallback prints its reason as the verdict", verdict))
    passed &= ok
    named_worse = row([0.80], [0.90], fell_back=True)
    named_worse["namedReason"] = "known"
    passed &= expect(rules.evaluate(named_worse), "3:", "a named row still meets rule 3")
    named_slow = row([0.95], [0.90], fell_back=True, full_seconds=9.0, raw_seconds=3.0)
    named_slow["namedReason"] = "known"
    passed &= expect(rules.evaluate(named_slow), "6:", "a named row still meets rule 6")
    named_ref = row([0.90], [0.80], fell_back=True, reference=True)
    named_ref["namedReason"] = "known"
    passed &= expect(rules.evaluate(named_ref), "5:", "a named row still meets rule 5")
    clean_named = row([0.95], [0.90])
    clean_named["namedReason"] = "known"
    ok = rules.verdict(clean_named, rules.evaluate(clean_named)) == "pass"
    print("%-5s %s" % ("ok" if ok else "FAIL", "a named row at the top rung is a plain pass"))
    passed &= ok
    ok = rules.verdict(named_worse, rules.evaluate(named_worse)).startswith("3:")
    print("%-5s %s" % ("ok" if ok else "FAIL", "a named row with another violation shows the violation"))
    passed &= ok
    ok = rules.verdict(row([0.95], [0.90]), []) == "pass"
    print("%-5s %s" % ("ok" if ok else "FAIL", "an unnamed clean row is a pass"))
    passed &= ok
    passed &= scorecard_checks()
    return 0 if passed else 1


def scorecard_checks():
    """scorecard.py's plumbing that needs no Word: stale scores, bad rows, cells."""
    import tempfile
    import scorecard

    passed = True
    out = tempfile.mkdtemp(prefix="btct-rules-")
    with open(os.path.join(out, "doc-full-scores.json"), "w", encoding="utf-8") as handle:
        handle.write('{"scores": [{"ssim": 0.99}]}')
    real_run = scorecard.subprocess.run
    scorecard.subprocess.run = lambda *a, **k: None  # a compare that writes nothing
    try:
        try:
            got = scorecard.score("a.pdf", "b.pdf", out, "doc-full")
            ok = False
        except OSError:
            got, ok = "OSError", True
    finally:
        scorecard.subprocess.run = real_run
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", "a stale scores file is not read as this run's", got))
    passed &= ok

    real = (scorecard.corpus.documents, scorecard.corpus.compile_document, scorecard.score_document)
    scorecard.corpus.documents = lambda: [("doc", "plain", out)]
    scorecard.corpus.compile_document = lambda source, pdf: None
    def malformed(*args):
        raise KeyError("scores")
    scorecard.score_document = malformed
    try:
        try:
            code = scorecard.main(["scorecard.py", "--out", out])
            with open(os.path.join(out, "scorecard.json"), encoding="utf-8") as handle:
                import json
                rows = json.load(handle)
            ok = code == 1 and rows[0].get("error")
        except KeyError as err:
            ok, rows = False, repr(err)
    finally:
        scorecard.corpus.documents, scorecard.corpus.compile_document, scorecard.score_document = real
    print("%-5s %s -- %s" % ("ok" if ok else "FAIL", "a malformed scores file becomes an error row", rows))
    passed &= bool(ok)

    got = scorecard.table([{"name": "doc", "category": "plain", "error": "a | b\n  c", "violations": ["error"]}], 0.002)
    ok = "error: a / b c |" in got
    print("%-5s %s -- %r" % ("ok" if ok else "FAIL", "error text is one clean table cell", got.splitlines()[-1]))
    passed &= ok
    # The three stress measurements (reported numbers, not rules).
    passed &= expect_true(rules.blank_pages([[(10, 740, 200, 760)], [(10, 100, 500, 600)]], 792) == 1,
                          "blank_pages counts a footer-only page")
    passed &= expect_true(rules.blank_pages([[]], 792) == 1, "blank_pages counts an empty page")
    pages = [[(56, 300, 500, 400), (56, 790, 541, 800)], [(56, 300, 545, 400), (56, 30, 541, 40)]]
    edges = rules.body_right_edges(pages, 842)
    passed &= expect_true(edges == [500, 545], "body_right_edges leaves out header and footer boxes: %s" % edges)
    passed &= expect_true(rules.ink_past_margin(edges, 538.6) == 1, "only the body overhang is counted past the margin")
    passed &= expect_true(rules.body_right_edges([[(56, 790, 541, 800)]], 842) == [],
                          "a page with only a footer gives no body edge")
    passed &= expect_true(rules.ink_past_margin([530.0, 560.5, 559.0], 557.0) == 1,
                          "ink_past_margin counts pages beyond the edge plus 2 pt")
    passed &= expect_true(rules.band_in_body(["ACME Security Assessment"], "intro ACME Security Assessment body"),
                          "band_in_body finds header text in the body")
    passed &= expect_true(not rules.band_in_body(["ACME Security Assessment"], "intro body"),
                          "band_in_body is false when absent")
    passed &= expect_true(not rules.band_in_body(["12"], "page 12 of the body"),
                          "band_in_body ignores band pieces shorter than 4 squashed characters")
    return passed


if __name__ == "__main__":
    sys.exit(main())
