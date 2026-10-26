"""The rule a converter change meets before it is committed (spec, section 2).

Pure: a row in, a list of violations out, each starting with the rule's
number so a table can sort and a test can match on it. An empty list passes.

A row may carry "namedReason" (scorecard.py sets it from
corpus.EXPECTED_FAILURES). Rule 1 then names the reason instead of failing
the row, and verdict() prints it; rules 2 to 6 apply as for any row.
"""

import re

# Widened only if scorecard.py --noise measures Word's run-to-run noise above
# it; the value in use is written at the top of SCORECARD.md.
MEAN_TOLERANCE = 0.002
PAGE_TOLERANCE = 0.02
REFERENCE_FLOOR = 0.9146
TIME_FACTOR = 2.0
TIME_SLACK_SECONDS = 2.0


def blank_pages(ink_boxes, page_height, edge_fraction=0.12):
    """Pages whose ink lies only in the top or bottom edge_fraction of the page."""
    top, bottom = page_height * edge_fraction, page_height * (1 - edge_fraction)
    return sum(1 for boxes in ink_boxes if all(y1 <= top or y0 >= bottom for (_x0, y0, _x1, y1) in boxes))


def ink_past_margin(ink_right_edges, content_right, slack=2.0):
    """Pages whose rightmost ink passes the PDF's right content edge by more than slack points."""
    return sum(1 for right in ink_right_edges if right > content_right + slack)


def body_right_edges(ink_boxes, page_height, edge_fraction=0.12):
    """Rightmost ink of each page's body, ignoring boxes wholly in the top or bottom edge_fraction
    (the running header and footer). A page with no body ink gives no entry."""
    top, bottom = page_height * edge_fraction, page_height * (1 - edge_fraction)
    edges = []
    for boxes in ink_boxes:
        body = [x1 for (_x0, y0, x1, y1) in boxes if not (y1 <= top or y0 >= bottom)]
        if body:
            edges.append(max(body))
    return edges


def _squash(text):
    return re.sub(r"\s+", "", text).casefold()


def band_in_body(band_texts, body_text):
    """Whether any running-band text (4+ squashed characters) appears in the body text."""
    body = _squash(body_text)
    return any(len(_squash(t)) >= 4 and _squash(t) in body for t in band_texts)


def mean(values):
    return sum(values) / len(values) if values else 0.0


def evaluate(row, tolerance=MEAN_TOLERANCE, reference_floor=REFERENCE_FLOOR):
    if row.get("error"):
        return ["error: %s" % row["error"]]
    full, raw = row["full"], row["raw"]
    violations = []
    text = full["result"]["textCheck"]
    if (text["fellBack"] or text["missing"]) and not row.get("namedReason"):
        violations.append("1: not at the top rung (%d missing, fell back %s)" % (text["missing"], text["fellBack"]))
    pdf = row["pdfPages"]
    if abs(full["wordPages"] - pdf) > abs(raw["wordPages"] - pdf):
        violations.append("2: %d Word pages against the PDF's %d (raw: %d)" % (full["wordPages"], pdf, raw["wordPages"]))
    # Only pages both sides have are paired, for the mean as for the pages.
    paired = min(len(full["ssim"]), len(raw["ssim"]))
    full_mean, raw_mean = mean(full["ssim"][:paired]), mean(raw["ssim"][:paired])
    if full_mean < raw_mean - tolerance:
        violations.append("3: mean %.4f against raw %.4f" % (full_mean, raw_mean))
    for index, (a, b) in enumerate(zip(full["ssim"], raw["ssim"])):
        if a < b - PAGE_TOLERANCE:
            violations.append("4: page %d at %.4f against raw %.4f" % (index + 1, a, b))
    if row.get("isReference") and mean(full["ssim"]) < reference_floor:
        violations.append("5: reference mean %.4f below %.4f" % (mean(full["ssim"]), reference_floor))
    if full["seconds"] > TIME_FACTOR * raw["seconds"] + TIME_SLACK_SECONDS:
        violations.append("6: %.1f s against raw %.1f s" % (full["seconds"], raw["seconds"]))
    return violations


def fell_short(row):
    """True when the full conversion missed the top rung (rule 1's test)."""
    if row.get("error"):
        return False
    text = row["full"]["result"]["textCheck"]
    return bool(text["fellBack"] or text["missing"])


def verdict(row, violations):
    """The table's verdict: the violations, else a named reason, else pass."""
    if violations:
        return "; ".join(violations)
    if row.get("namedReason") and fell_short(row):
        return "named: %s" % row["namedReason"]
    return "pass"
