"""Measure a Word export against the typst PDF it came from, by defect class.

    <venv>/python -I -B check_word.py <typst.pdf> <word-render.pdf> <out-dir> <name>

The Word render is the .docx printed to PDF by Word itself (render_word.ps1).
A developer tool for the fix-and-measure loop (the converter brain's methods note, if the brain is present): it
pairs every Word page with the PDF page that holds the same text, then
reports one gate per defect class. Writes <out-dir>/<name>.json and a
side-by-side PNG of the three worst pages.

Gates (each printed PASS or FAIL):
  pages      Word page count equals the PDF's
  blank      no Word page is empty between the header rule and the footer strip
  images     no picture reaches into the running header; no body line is drawn over a picture
  fills      every filled rectangle of the PDF (panels, cells, frames) has a match in Word
  margin     no body line ends more than 2.5 pt past the PDF's right content edge
  pictures   every raster picture of the PDF has a Word picture of its visible size
  rendered   every body line of the PDF is drawn somewhere in the Word render (a line a row of exact height clips is not)
  code       every code line (monospace in the PDF) starts within 2.5 pt of where the PDF starts it
  drift      no page's last body line sits more than 10 pt from where the PDF has it
  spaces     every code line keeps the PDF's spaces between its words (the text check squashes them away)
SSIM per page is reported (median, worst), not gated.
"""
import json
import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import numpy as np  # noqa: E402
import pymupdf  # noqa: E402

import compare_pages  # noqa: E402
import convert  # noqa: E402

HEADER_BOTTOM = 56.0
FOOTER_TOP = 768.0
# How far right of the text area's left edge a line may start and still have
# its start measured: a centred line starts wherever its width puts it.
LEFT_SIDE_PT = 80.0


def body_text_rows(page, banded=True):
    rows = []
    for block in page.get_text("dict")["blocks"]:
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            x0, y0, x1, y1 = line["bbox"]
            if banded and (y0 < HEADER_BOTTOM or y1 > FOOTER_TOP):
                continue
            # A line set at an angle is a stamp or a watermark; Word's PDF
            # export draws a turned text box as outlines, so neither side's
            # text can be compared, and no gate here is about rotation.
            direction = line.get("dir", (1.0, 0.0))
            if abs(direction[1]) > 0.01:
                continue
            text = "".join(span["text"] for span in line["spans"]).strip()
            if text:
                base = max((span["origin"][1] for span in line["spans"]), default=y1)
                # The line's ink ends at its last glyph; a trailing space
                # before a manual break widens the box without any ink.
                ink_x1 = x1
                for span in reversed(line["spans"]):
                    stripped = span["text"].rstrip()
                    if stripped:
                        trailing = len(span["text"]) - len(stripped)
                        if trailing and len(span["text"]):
                            ink_x1 = span["bbox"][2] - (span["bbox"][2] - span["bbox"][0]) * trailing / len(span["text"])
                        else:
                            ink_x1 = span["bbox"][2]
                        break
                # Where the first glyph starts: Word draws a line's leading
                # spaces inside its span, typst does not (an indented JSON
                # line read 9 pt left by its box and is not).
                first = next((span for span in line["spans"] if span["text"].strip()), None)
                ink_x0 = ink_left(first) if first is not None else x0
                rows.append({"text": text, "x0": x0, "x1": ink_x1, "y0": y0, "y1": y1, "base": base, "inkX0": ink_x0})
    return rows




def rendered_key(text):
    """A line's comparable text for the rendered gate (`compare_squash` without underscores)."""
    return convert.compare_squash(text).replace("_", "")


def ink_left(span):
    """Where a span's first glyph starts: Word draws leading spaces as part of the span, typst does not."""
    text = span["text"]
    lead = len(text) - len(text.lstrip())
    if not lead or not text.strip():
        return span["bbox"][0]
    return span["bbox"][0] + (span["bbox"][2] - span["bbox"][0]) * lead / len(text)

def code_rows(page, any_font):
    """Lines set in a monospace face (any face on the Word side, matched by text), with their left edge."""
    out = []
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            spans = [s for s in line["spans"] if s["text"].strip()]
            if not spans or (not any_font and not all("mono" in s["font"].lower() for s in spans)):
                continue
            key = convert.compare_squash("".join(s["text"] for s in line["spans"]))
            if len(key) >= 6:
                # "words" keeps the spaces between words, collapsed: typst draws
                # the space between two highlighted tokens as a span of its own,
                # and a span of only a space is still part of the line. Zero-width
                # characters are typst's break opportunities (a CVSS vector), not text.
                words = re.sub(r"\s+", " ", re.sub("[\u00ad\u200b-\u200d\u2060\ufeff]", "",
                                                   "".join(s["text"] for s in line["spans"]).replace("\u00a0", " "))).strip()
                out.append({"key": key, "x0": ink_left(spans[0]), "text": "".join(s["text"] for s in spans).strip(),
                            "words": words})
    return out

def tokens(rows):
    return set(convert.compare_squash(" ".join(r["text"] for r in rows)).split()) or {
        tok for r in rows for tok in convert.compare_squash(r["text"])[i:i + 6].split() for i in range(0, len(convert.compare_squash(r["text"])), 6)}


def shingles(rows):
    text = convert.compare_squash(" ".join(r["text"] for r in rows))
    return {text[i:i + 8] for i in range(0, max(1, len(text) - 7))}


def dice(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return 2.0 * len(a & b) / (len(a) + len(b))


def has_ink(page):
    if body_text_rows(page):
        return True
    for info in page.get_image_info():
        x0, y0, x1, y1 = info["bbox"]
        if y1 > HEADER_BOTTOM and y0 < FOOTER_TOP:
            return True
    for drawing in page.get_drawings():
        r = drawing["rect"]
        if r.y1 > HEADER_BOTTOM + 2 and r.y0 < FOOTER_TOP - 2 and r.width > 2 and r.height > 2:
            return True
    return False


def fills(page):
    out = []
    for drawing in page.get_drawings():
        fill = drawing.get("fill")
        r = drawing["rect"]
        if fill is None or r.width < 40 or r.height < 12:
            continue
        if r.width > page.rect.width - 2 and r.height > page.rect.height - 2:
            continue  # the cover
        if r.y0 < HEADER_BOTTOM or r.y1 > FOOTER_TOP:
            continue  # the bands
        out.append({"x0": r.x0, "y0": r.y0, "x1": r.x1, "y1": r.y1, "w": r.width, "h": r.height,
                    "fill": tuple(round(c * 255) for c in fill[:3])})
    return out


def covered_by_image(f, boxes):
    """A PDF fill that a Word picture covers (a chart's wedge, a frame under its picture)."""
    area = f["w"] * f["h"]
    for b in boxes:
        ix = min(b.x1, f["x1"]) - max(b.x0, f["x0"])
        iy = min(b.y1, f["y1"]) - max(b.y0, f["y0"])
        if ix > 0 and iy > 0 and ix * iy >= 0.9 * area:
            return True
    return False


def match_fills(pdf_fills, word_fills, word_images=()):
    unmatched = []
    free = list(word_fills)
    for f in pdf_fills:
        if covered_by_image(f, word_images):
            continue
        hit = None
        for i, w in enumerate(free):
            # Width within a bar's worth: a panel's grey cell is the PDF's
            # rectangle less the accent bar that is a cell of its own.
            if (abs(w["w"] - f["w"]) <= 12.0 and abs(w["h"] - f["h"]) <= 2.5
                    and all(abs(a - b) <= 10 for a, b in zip(w["fill"], f["fill"]))):
                hit = i
                break
        if hit is None:
            unmatched.append(f)
        else:
            free.pop(hit)
    return unmatched


def images(page):
    return [pymupdf.Rect(info["bbox"]) for info in page.get_image_info()]


def main(argv):
    pdf_path, word_path, out_dir, name = argv[1:5]
    os.makedirs(out_dir, exist_ok=True)
    pdf, word = pymupdf.open(pdf_path), pymupdf.open(word_path)
    content_left, content_right = convert.content_bounds(pdf)
    pdf_rows = [body_text_rows(p) for p in pdf]
    pdf_sh = [shingles(r) for r in pdf_rows]
    result = {"name": name, "pdfPages": pdf.page_count, "wordPages": word.page_count,
              "contentRight": round(content_right, 1)}

    # Pair every Word page with a PDF page by text.
    pairs = []
    offset = 0
    for i in range(word.page_count):
        rows = body_text_rows(word[i])
        sh = shingles(rows)
        guess = min(max(0, i + offset), pdf.page_count - 1)
        best, best_d = guess, -1.0
        for j in range(max(0, guess - 4), min(pdf.page_count, guess + 5)):
            d = dice(sh, pdf_sh[j])
            if d > best_d:
                best, best_d = j, d
        if best_d < 0.3 and not rows:
            best = None
        else:
            offset = best - i
        pairs.append({"word": i + 1, "pdf": None if best is None else best + 1, "dice": round(best_d, 3)})

    blanks = [i + 1 for i in range(word.page_count) if i > 0 and not has_ink(word[i])]
    result["blankPages"] = blanks

    # Pictures: only Word pictures that are a raster image of the PDF (by
    # size); the converter renders vector art as pictures too, and a chevron
    # graphic's box covers text in the PDF as well.
    raster = [(p["visible"].width, p["visible"].height) for p in convert.pdf_pictures(pdf)]
    raster += [(p["rect"].width, p["rect"].height) for p in convert.pdf_pictures(pdf)]
    above = []
    over = []
    for i in range(1, word.page_count):
        page = word[i]
        boxes = [b for b in images(page)
                 if any(abs(b.width - w) <= 3 and abs(b.height - h) <= 3 for w, h in raster)]
        for b in boxes:
            if b.y0 < HEADER_BOTTOM - 2 and b.y1 > HEADER_BOTTOM:
                above.append({"page": i + 1, "top": round(b.y0, 1)})
        rows = body_text_rows(page)
        for b in boxes:
            for r in rows:
                if len(r["text"]) <= 2:
                    continue  # a chart's numerals are text in the PDF too
                ix = min(b.x1, r["x1"]) - max(b.x0, r["x0"])
                iy = min(b.y1, r["y1"]) - max(b.y0, r["y0"])
                if ix > 10 and iy > 2:
                    over.append({"page": i + 1, "text": r["text"][:50]})
                    break
    result["imagesAboveHeader"] = above
    result["textOverImages"] = over

    # Every picture the PDF draws has a Word picture of its visible size:
    # pdf2docx keeps them all, and a pass of the converter that moves blocks
    # can lose one without any gate above noticing.
    wanted = [(p["page"] + 1, p["visible"].width, p["visible"].height, p["rect"]) for p in convert.pdf_pictures(pdf)]
    found = []
    for i in range(word.page_count):
        found.extend((b.width, b.height) for b in images(word[i]))
    missing = []
    for page_number, w, h, rect in wanted:
        hit = next((f for f in found if abs(f[0] - w) <= 3 and abs(f[1] - h) <= 3), None)
        if hit is None:
            missing.append({"pdfPage": page_number, "rect": [round(x, 1) for x in rect]})
        else:
            found.remove(hit)
    result["missingPictures"] = missing

    # Every body line of the PDF is drawn in the Word render. The text check
    # reads the Word file, and a row of exact height clips what does not fit
    # without a trace in it: a resource list lost its last link that way.
    # Underscores are left out on both sides: Word's PDF export maps a subset
    # font's "_" to a space, so "invoice_id" reads back as "invoice id".
    # The Word side is read whole: the bands are cut on the PDF side, and a
    # body line Word draws a few points lower (a footnote on an A4 page) is
    # past a cut made for the PDF's Letter-sized footer, though it is drawn.
    page_text = ["".join(rendered_key(r["text"]) for r in body_text_rows(word[i], banded=False))
                 for i in range(word.page_count)]
    whole_text = "".join(page_text)
    unrendered = []
    for j, rows in enumerate(pdf_rows):
        # The Word pages this PDF page's lines may be drawn on: its pair and the neighbours.
        paired = [pair["word"] - 1 for pair in pairs if pair["pdf"] == j + 1]
        near = set()
        for w in paired:
            near.update(k for k in (w - 1, w, w + 1) if 0 <= k < word.page_count)
        near_text = "".join(page_text[k] for k in sorted(near))
        for r in rows:
            key = rendered_key(r["text"])
            if len(key) < 8:
                continue
            # Joined without separators, so a line Word wrapped elsewhere is
            # still found; only text that was never drawn is missing.
            # A line typst ran off the page is cut at the page edge by both
            # renders, a character or two apart, so most of it is enough.
            probe = key[:max(8, int(len(key) * 0.9))] if len(key) > 40 else key
            if probe not in near_text and probe not in whole_text:
                unrendered.append({"pdfPage": j + 1, "text": r["text"][:50]})
    result["unrendered"] = {"count": len(unrendered), "examples": unrendered[:8]}

    # Every code line starts where the PDF starts it: a listing's indented
    # rows lost their spaces to a hanging indent, and a continuation panel
    # whose rows were all indented stood 22 pt right of the others.
    misplaced = []
    respaced = []
    code_total = 0
    for pair in pairs:
        if pair["pdf"] is None:
            continue
        prows = code_rows(pdf[pair["pdf"] - 1], False)
        taken = set()
        for r in code_rows(word[pair["word"] - 1], True):
            k = next((k for k, p in enumerate(prows) if k not in taken and p["key"] == r["key"]), None)
            if k is None:
                continue
            taken.add(k)
            code_total += 1
            if r["words"] != prows[k]["words"]:
                respaced.append({"page": pair["word"], "pdf": prows[k]["words"][:60], "word": r["words"][:60]})
            dx = r["x0"] - prows[k]["x0"]
            if abs(dx) > 2.5:
                misplaced.append({"page": pair["word"], "dx": round(dx, 1), "text": r["text"][:40]})
    result["codeIndent"] = {"total": code_total, "off": len(misplaced), "examples": misplaced[:8]}
    result["codeSpaces"] = {"total": code_total, "changed": len(respaced), "examples": respaced[:8]}

    # Where prose lines start: reported, not gated. A list item's wrapped
    # lines stood under its marker, 14 pt left of the PDF's, in every report,
    # and no gate saw it. Lines on the left side of the text area only, each
    # matched by its whole text to the one Word line on its page that has it.
    starts_off = []
    starts_total = 0
    for pair in pairs:
        if pair["pdf"] is None:
            continue
        by_key = {}
        for r in body_text_rows(word[pair["word"] - 1]):
            by_key.setdefault(rendered_key(r["text"]), []).append(r)
        for p in body_text_rows(pdf[pair["pdf"] - 1]):
            key = rendered_key(p["text"])
            if p["x0"] > content_left + LEFT_SIDE_PT or len(key) < 5 or len(by_key.get(key, ())) != 1:
                continue
            starts_total += 1
            dx = by_key[key][0]["inkX0"] - p["inkX0"]
            if abs(dx) > 2.5:
                starts_off.append({"page": pair["word"], "dx": round(dx, 1), "text": p["text"][:40]})
    result["lineStarts"] = {"measured": starts_total, "off": len(starts_off), "examples": starts_off[:8]}

    # Filled rectangles.
    unmatched = []
    total = 0
    for pair in pairs:
        if pair["pdf"] is None:
            continue
        pf = fills(pdf[pair["pdf"] - 1])
        wf = fills(word[pair["word"] - 1])
        total += len(pf)
        for f in match_fills(pf, wf, images(word[pair["word"] - 1])):
            unmatched.append({"pdfPage": pair["pdf"], "wordPage": pair["word"], "w": round(f["w"], 1),
                              "h": round(f["h"], 1), "fill": f["fill"], "y0": round(f["y0"], 1)})
    result["fills"] = {"total": total, "unmatched": len(unmatched), "examples": unmatched[:12]}

    # Lines past the right margin, and drift of the last body line.
    past = []
    drifts = []
    for pair in pairs:
        if pair["pdf"] is None:
            continue
        wrows = body_text_rows(word[pair["word"] - 1])
        prows = pdf_rows[pair["pdf"] - 1]
        # A line the PDF itself runs past the column (a token typst could
        # not break) is allowed the same in Word.
        pdf_edge = {}
        for p in prows:
            key = convert.compare_squash(p["text"])[:24]
            if len(key) >= 8:
                pdf_edge[key] = max(pdf_edge.get(key, 0.0), p["x1"])
        # A page set the other way round (a landscape appendix in a portrait
        # report) has its own column; the document's is the wrong yardstick.
        page_right = content_right
        if abs(pdf[pair["pdf"] - 1].rect.width - pdf[0].rect.width) > 1.0 and prows:
            page_right = max(p["x1"] for p in prows)
        for r in wrows:
            key = convert.compare_squash(r["text"])[:24]
            limit = max(page_right, pdf_edge.get(key, 0.0)) + 2.5
            if r["x1"] > limit:
                past.append({"page": pair["word"], "over": round(r["x1"] - content_right, 1), "text": r["text"][:40]})
        if wrows and prows:
            last = wrows[-1]
            key = convert.compare_squash(last["text"])[:24]
            same = [p for p in prows if convert.compare_squash(p["text"])[:24] == key]
            if same and len(key) >= 8:
                # The PDF row nearest the Word row's own height: a listing
                # repeats its first words, and the last of them is not the
                # one Word drew here.
                nearest = min(same, key=lambda p: abs(p["base"] - last["base"]))
                # A match further than this is another line with the same
                # start (Word's render can split a listing row into its
                # columns, and a column's text recurs on the page).
                if abs(last["base"] - nearest["base"]) <= 100:
                    drifts.append({"page": pair["word"], "drift": round(last["base"] - nearest["base"], 2)})
    result["pastMargin"] = {"count": len(past), "max": max([p["over"] for p in past], default=0.0),
                            "examples": sorted(past, key=lambda p: -p["over"])[:8]}
    big = [d for d in drifts if abs(d["drift"]) > 10]
    result["drift"] = {"measured": len(drifts), "over10": big,
                       "median": round(statistics.median([abs(d["drift"]) for d in drifts]), 2) if drifts else None}

    # SSIM.
    scale = compare_pages.RENDER_DPI / 72.0
    scores = []
    for pair in pairs:
        if pair["pdf"] is None:
            continue
        a = compare_pages.render(pdf[pair["pdf"] - 1], scale)
        b = compare_pages.fit(compare_pages.render(word[pair["word"] - 1], scale), a.shape)
        scores.append({"word": pair["word"], "pdf": pair["pdf"], "ssim": round(compare_pages.ssim(a, b), 4)})
    scores_sorted = sorted(scores, key=lambda s: s["ssim"])
    result["ssim"] = {"median": round(statistics.median([s["ssim"] for s in scores]), 4) if scores else None,
                      "worst": scores_sorted[:10]}
    # Side by side of the three worst.
    for s in scores_sorted[:3]:
        a = compare_pages.render(word[s["word"] - 1], 60 / 72.0, colour=True)
        b = compare_pages.render(pdf[s["pdf"] - 1], 60 / 72.0, colour=True)
        h = max(a.shape[0], b.shape[0])
        sheet = np.full((h, a.shape[1] + b.shape[1] + 10, 3), 255, dtype=np.uint8)
        sheet[:a.shape[0], :a.shape[1]] = a
        sheet[:b.shape[0], a.shape[1] + 10:] = b
        compare_pages.save_png(sheet, os.path.join(out_dir, "%s-w%03d-p%03d.png" % (name, s["word"], s["pdf"])))

    gates = {
        "pages": word.page_count == pdf.page_count,
        "blank": not blanks,
        "images": not above and not over,
        "pictures": not missing,
        "rendered": not unrendered,
        "code": not misplaced,
        "fills": total == 0 or len(unmatched) <= max(0, int(0.02 * total)),
        "margin": not past,
        "drift": not big,
        "spaces": not respaced,
    }
    result["gates"] = gates
    with open(os.path.join(out_dir, name + ".json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1)
    print("%s: Word %d / PDF %d pages; blank %s; images above header %d, text over images %d, pictures missing %d, lines unrendered %d, code lines off %d/%d, respaced %d; "
          "fills unmatched %d/%d; past margin %d (max %.1f); drift>10 %d of %d (median %s); ssim median %s worst %s"
          % (name, word.page_count, pdf.page_count, blanks, len(above), len(over), len(missing), len(unrendered), len(misplaced), code_total, len(respaced), len(unmatched), total,
             len(past), result["pastMargin"]["max"], len(big), len(drifts), result["drift"]["median"],
             result["ssim"]["median"], [(s["word"], s["ssim"]) for s in scores_sorted[:3]]))
    for gate, ok in gates.items():
        print("  %-7s %s" % (gate, "PASS" if ok else "FAIL"))
    return 0 if all(gates.values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
