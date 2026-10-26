#!/usr/bin/env python3
"""Score two PDFs page against page and draw contact sheets of the pairs.

    compare_pages.py <reference.pdf> <candidate.pdf> <out-dir> [label]

A developer tool for `compare.ps1`, not part of the server and not part of
`bun run test`. It needs pymupdf and numpy, which the converter's virtualenv
already has.

Three numbers per page, because one was not enough to steer by:

- **mad**: one minus the mean absolute difference of the two pages rendered
  greyscale. It is the old score, kept so earlier runs still compare, and it
  is nearly blind to a missing header: a band of white where there should be
  text is a small fraction of a page's pixels.
- **ssim**: structural similarity over 8 pixel windows. A local miss drives it
  down where the mean does not, which is what makes it the one to watch.
- **offset**: how far the page's ink has moved, in points, as the difference
  between the two ink bounding boxes (dx, dy) and their sizes (dw, dh). This
  is what catches a picture placed at the wrong scale, which looks almost
  right until the boxes are measured.

Every page also gets an **overlay**: the reference's ink in red, the
candidate's in blue, ink they share in near black. On a page that matches, the
overlay is black text on white; every red or blue pixel is a difference, and
that is the acceptance test rather than any of the numbers.
"""

import json
import os
import sys

import numpy as np
import pymupdf

RENDER_DPI = 100
SCORE_WIDTH = 200
SHEET_PAGE_WIDTH = 340
SHEET_COLUMNS = 5
SHEET_GAP = 8
# Below this grey a pixel counts as ink. Anti-aliased glyph edges run up to
# about 220 on a white page, so this keeps the halo out of the bounding box.
INK_LEVEL = 200
SSIM_WINDOW = 8


def render(page, scale, colour=False):
    matrix = pymupdf.Matrix(scale, scale)
    space = pymupdf.csRGB if colour else pymupdf.csGRAY
    pix = page.get_pixmap(matrix=matrix, colorspace=space, alpha=False)
    array = np.frombuffer(pix.samples, dtype=np.uint8)
    return array.reshape(pix.height, pix.width, 3) if colour else array.reshape(pix.height, pix.width)


def grey(page, width):
    return render(page, width / page.rect.width)


def fit(array, shape):
    """Nearest-neighbour resize, so two pages of different size still compare."""
    if array.shape[:2] == shape:
        return array
    rows = (np.arange(shape[0]) * array.shape[0] // shape[0]).clip(0, array.shape[0] - 1)
    cols = (np.arange(shape[1]) * array.shape[1] // shape[1]).clip(0, array.shape[1] - 1)
    return array[rows][:, cols]


def box_mean(array, window):
    """Mean over every `window` by `window` block, from an integral image."""
    padded = np.zeros((array.shape[0] + 1, array.shape[1] + 1), dtype=np.float64)
    padded[1:, 1:] = array.cumsum(axis=0).cumsum(axis=1)
    rows = np.arange(0, array.shape[0] - window + 1)
    cols = np.arange(0, array.shape[1] - window + 1)
    total = (
        padded[np.ix_(rows + window, cols + window)]
        - padded[np.ix_(rows, cols + window)]
        - padded[np.ix_(rows + window, cols)]
        + padded[np.ix_(rows, cols)]
    )
    return total / (window * window)


def ssim(a, b, window=SSIM_WINDOW):
    """Structural similarity, mean over the whole page. 1.0 is identical."""
    a = a.astype(np.float64) / 255.0
    b = b.astype(np.float64) / 255.0
    if min(a.shape) < window:
        return float(1.0 - np.abs(a - b).mean())
    mu_a, mu_b = box_mean(a, window), box_mean(b, window)
    var_a = np.maximum(box_mean(a * a, window) - mu_a * mu_a, 0.0)
    var_b = np.maximum(box_mean(b * b, window) - mu_b * mu_b, 0.0)
    cov = box_mean(a * b, window) - mu_a * mu_b
    c1, c2 = 0.01 ** 2, 0.03 ** 2
    top = (2 * mu_a * mu_b + c1) * (2 * cov + c2)
    bottom = (mu_a * mu_a + mu_b * mu_b + c1) * (var_a + var_b + c2)
    return float((top / bottom).mean())


def ink_box(array):
    """The bounding box of everything darker than INK_LEVEL, in pixels."""
    mask = array < INK_LEVEL
    if not mask.any():
        return None
    rows = np.flatnonzero(mask.any(axis=1))
    cols = np.flatnonzero(mask.any(axis=0))
    return int(cols[0]), int(rows[0]), int(cols[-1]) + 1, int(rows[-1]) + 1


def offset_of(reference, candidate, scale):
    """How far the ink moved and how much it grew, in points."""
    a, b = ink_box(reference), ink_box(candidate)
    if a is None or b is None:
        return None
    to_pt = 1.0 / scale
    return {
        "dx": round((b[0] - a[0]) * to_pt, 2),
        "dy": round((b[1] - a[1]) * to_pt, 2),
        "dw": round(((b[2] - b[0]) - (a[2] - a[0])) * to_pt, 2),
        "dh": round(((b[3] - b[1]) - (a[3] - a[1])) * to_pt, 2),
    }


def overlay(reference, candidate):
    """Reference ink red, candidate ink blue, shared ink near black."""
    shape = reference.shape
    other = fit(candidate, shape)
    a, b = reference < INK_LEVEL, other < INK_LEVEL
    out = np.full(shape + (3,), 255, dtype=np.uint8)
    out[a & ~b] = (220, 40, 40)
    out[b & ~a] = (40, 80, 220)
    both = a & b
    out[both] = np.stack([other[both] // 3] * 3, axis=-1)
    return out


def score_pages(reference, candidate):
    scores = []
    for index in range(min(reference.page_count, candidate.page_count)):
        page = reference[index]
        scale = RENDER_DPI / 72.0
        a = render(page, scale)
        b = fit(render(candidate[index], scale), a.shape)
        small_a = grey(page, SCORE_WIDTH)
        small_b = fit(grey(candidate[index], SCORE_WIDTH), small_a.shape)
        scores.append({
            "page": index + 1,
            "mad": round(1.0 - float(np.abs(small_a.astype(np.int16) - small_b.astype(np.int16)).mean()) / 255.0, 4),
            "ssim": round(ssim(a, b), 4),
            "offset": offset_of(a, b, scale),
        })
    return scores


def save_png(array, path):
    height, width = array.shape[:2]
    pix = pymupdf.Pixmap(pymupdf.csRGB, width, height, bytes(array.tobytes()), 0)
    pix.save(path)


def write_sheet(reference, candidate, indexes, path):
    """One PNG: reference pages, the candidates beneath, the overlays below."""
    scale = SHEET_PAGE_WIDTH
    tops = [render(reference[i], scale / reference[i].rect.width, colour=True) for i in indexes]
    bottoms = [render(candidate[i], scale / candidate[i].rect.width, colour=True) for i in indexes]
    diffs = []
    for i in indexes:
        a = render(reference[i], scale / reference[i].rect.width)
        b = render(candidate[i], scale / candidate[i].rect.width)
        diffs.append(overlay(a, b))
    rows = [tops, bottoms, diffs]
    heights = [max(a.shape[0] for a in row) for row in rows]
    height = sum(heights) + SHEET_GAP * (len(rows) + 1)
    width = len(indexes) * (SHEET_PAGE_WIDTH + SHEET_GAP) + SHEET_GAP
    sheet = np.full((height, width, 3), 150, dtype=np.uint8)
    y = SHEET_GAP
    for row, band in zip(rows, heights):
        for order, tile in enumerate(row):
            x = SHEET_GAP + order * (SHEET_PAGE_WIDTH + SHEET_GAP)
            sheet[y : y + tile.shape[0], x : x + tile.shape[1]] = tile
        y += band + SHEET_GAP
    save_png(sheet, path)


def main(argv):
    if len(argv) < 4:
        print("usage: compare_pages.py <reference.pdf> <candidate.pdf> <out-dir> [label]", file=sys.stderr)
        return 2
    reference = pymupdf.open(argv[1])
    candidate = pymupdf.open(argv[2])
    out_dir = argv[3]
    label = argv[4] if len(argv) > 4 else "sheet"
    os.makedirs(out_dir, exist_ok=True)

    scores = score_pages(reference, candidate)
    print("pages: reference %d, candidate %d" % (reference.page_count, candidate.page_count))
    print("page    mad    ssim   dx     dy     dw     dh")
    for row in scores:
        o = row["offset"] or {}
        print("%4d  %.4f  %.4f  %6s %6s %6s %6s" % (
            row["page"], row["mad"], row["ssim"],
            o.get("dx", "-"), o.get("dy", "-"), o.get("dw", "-"), o.get("dh", "-")))
    if scores:
        mads = sorted(r["mad"] for r in scores)
        ssims = sorted(r["ssim"] for r in scores)
        worst = min(scores, key=lambda r: r["ssim"])
        shifted = [r for r in scores if r["offset"] and max(abs(r["offset"][k]) for k in ("dx", "dy")) > 2.0]
        print("mad   worst %.4f  median %.4f" % (mads[0], mads[len(mads) // 2]))
        print("ssim  worst %.4f (page %d)  median %.4f  mean %.4f"
              % (ssims[0], worst["page"], ssims[len(ssims) // 2], sum(ssims) / len(ssims)))
        print("pages whose ink moved more than 2 pt: %d %s"
              % (len(shifted), [r["page"] for r in shifted][:12]))

    sheets = []
    shared = list(range(min(reference.page_count, candidate.page_count)))
    for start in range(0, len(shared), SHEET_COLUMNS):
        chunk = shared[start : start + SHEET_COLUMNS]
        path = os.path.join(out_dir, "%s-%02d.png" % (label, start // SHEET_COLUMNS + 1))
        write_sheet(reference, candidate, chunk, path)
        sheets.append(path)
    if len(shared) > SHEET_COLUMNS:
        worst_pages = [r["page"] - 1 for r in sorted(scores, key=lambda r: r["ssim"])[:SHEET_COLUMNS]]
        path = os.path.join(out_dir, "%s-worst.png" % label)
        write_sheet(reference, candidate, sorted(worst_pages), path)
        sheets.append(path)

    with open(os.path.join(out_dir, "%s-scores.json" % label), "w", encoding="utf-8") as handle:
        json.dump({
            "referencePages": reference.page_count,
            "candidatePages": candidate.page_count,
            "scores": scores,
            "sheets": sheets,
        }, handle, indent=1)
    print("sheets: " + ", ".join(sheets))
    same = reference.page_count == candidate.page_count
    reference.close()
    candidate.close()
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
