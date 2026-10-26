#!/usr/bin/env python3
"""Score the Word export on the corpus: full converter against raw pdf2docx.

    <venv>/python -I -B scorecard.py [--out DIR] [--only a,b] [--skip PASSES]
        [--noise] [--reference-pdf FILE --reference-fonts DIR]
        [--stress [--cptc-template DIR]]

A developer tool. Needs typst on PATH and Microsoft Word; never runs in Docker
and is not part of any test suite. For each document: compile once, convert
twice (full, and --raw), render both through Word, score both against the PDF
with compare_pages.py, then apply scorecard_rules.evaluate. Writes
scorecard.json and scorecard.md into --out (default: a new temp folder) and
prints the table. A document listed in corpus.EXPECTED_FAILURES carries its
reason into the row, so missing the top rung is printed as "named: <reason>"
rather than failing rule 1; rules 2 to 6 still apply to it. Exit 0 when no
row has a violation.

--stress builds the six documents of stress.py under <out>/stress-src (the
CPTC ones from --cptc-template) and scores them instead of the corpus, unless
--only names corpus documents too. Every row also reports blankPages,
bandInBody, inkPastMargin and wordSeconds for the full side: numbers, not rules.

--skip is passed to the full conversion only, to try a document with one pass
off. --noise renders every raw file twice and reports how far Word's own
rendering moves the mean, which is what the tolerance must exceed.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus  # noqa: E402
import scorecard_rules  # noqa: E402
import stress  # noqa: E402
import tagged  # noqa: E402

RENDER = os.path.join(HERE, "render_word.ps1")
CONVERT = os.path.join(HERE, "convert.py")
COMPARE = os.path.join(HERE, "compare_pages.py")
# The trailing argv export.mjs gives convert.py: round((CONVERT_TIMEOUT_MS 120000 - CONVERT_BUDGET_MARGIN_MS 15000) / 1000).
# Only the stress jobs run under it, so the corpus numbers stay comparable with older runs.
SERVER_BUDGET_SECONDS = 105


def run_convert(pdf, docx, fonts, extra, budget=None):
    result_path = docx + ".json"
    args = [sys.executable, "-I", "-B", CONVERT] + ["--fonts=%s" % d for d in fonts] + extra + [pdf, docx, result_path]
    if budget is not None:
        args.append(str(budget))
    started = time.monotonic()
    proc = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
    seconds = time.monotonic() - started
    with open(result_path, encoding="utf-8") as handle:
        result = json.load(handle)
    if proc.returncode != 0 or not result.get("ok"):
        raise RuntimeError("convert.py: %s" % (result.get("message") or proc.stderr[-300:]))
    return result, seconds


def render(docx, pdf):
    proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", RENDER,
                           "-Docx", docx, "-Pdf", pdf], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("Word render failed: %s" % (proc.stderr or proc.stdout)[-300:])
    for line in proc.stdout.splitlines():
        if line.startswith("pages:"):
            return int(line.split(":", 1)[1])
    raise RuntimeError("Word render printed no page count")


def score(reference_pdf, candidate_pdf, out_dir, label):
    # A reused --out holds the last run's scores under the same name; remove
    # them first so a compare that writes nothing cannot be read as a result.
    scores = os.path.join(out_dir, "%s-scores.json" % label)
    if os.path.exists(scores):
        os.remove(scores)
    subprocess.run([sys.executable, "-I", "-B", COMPARE, reference_pdf, candidate_pdf, out_dir, label],
                   capture_output=True, text=True)
    with open(scores, encoding="utf-8") as handle:
        data = json.load(handle)
    return [page["ssim"] for page in data["scores"]]


def compile_folder(folder, pdf_path, extra_fonts=()):
    """Compile folder/main.typ with the folder as the typst root (stress sources)."""
    args = ["typst", "compile", "--root", folder, "--ignore-system-fonts", "-j", "1"]
    for directory in list(corpus.font_dirs()) + [d for d in extra_fonts if os.path.isdir(d)]:
        args += ["--font-path", directory]
    args += [os.path.join(folder, "main.typ"), pdf_path]
    subprocess.run(args, check=True, capture_output=True, text=True, encoding="utf-8")


def ink_of_page(page):
    """Boxes of everything drawn on the page: text blocks, images, and drawn rectangles.

    A rectangle covering nearly the whole page is a background fill, not ink.
    """
    page_area = page.rect.width * page.rect.height
    boxes = [tuple(block[:4]) for block in page.get_text("blocks") if str(block[4]).strip() or block[6] == 1]
    boxes += [tuple(info["bbox"]) for info in page.get_image_info()]
    for drawing in page.get_drawings():
        rect = drawing["rect"]
        if rect.width * rect.height < 0.9 * page_area:
            boxes.append((rect.x0, rect.y0, rect.x1, rect.y1))
    return boxes


def measure_stress(source_pdf, rendered_pdf, docx):
    """blankPages, inkPastMargin and bandInBody for one converted document."""
    import pymupdf
    import convert

    with pymupdf.open(source_pdf) as source:
        content_right = convert.content_bounds(source)[1]
    with pymupdf.open(rendered_pdf) as doc:
        boxes = [ink_of_page(page) for page in doc]
        height = doc[0].rect.height if doc.page_count else 0.0
    rights = scorecard_rules.body_right_edges(boxes, height)
    body = convert.docx_text(docx, body_only=True)
    return {"blankPages": scorecard_rules.blank_pages(boxes, height),
            "inkPastMargin": scorecard_rules.ink_past_margin(rights, content_right),
            "bandInBody": scorecard_rules.band_in_body(tagged.band_texts(source_pdf), body)}


def side(name, mode, pdf, fonts, extra, out_dir, measure=False, budget=None):
    docx = os.path.join(out_dir, "%s-%s.docx" % (name, mode))
    rendered = os.path.join(out_dir, "%s-%s.word.pdf" % (name, mode))
    result, seconds = run_convert(pdf, docx, fonts, extra, budget)
    started = time.monotonic()
    word_pages = render(docx, rendered)
    word_seconds = time.monotonic() - started
    ssim = score(pdf, rendered, out_dir, "%s-%s" % (name, mode))
    data = {"wordPages": word_pages, "ssim": ssim, "seconds": seconds, "wordSeconds": word_seconds,
            "result": result, "rendered": rendered, "docx": docx}
    if measure:
        data.update(measure_stress(pdf, rendered, docx))
    return data


def score_document(name, category, pdf, fonts, skip, out_dir, is_reference=False):
    import pymupdf

    with pymupdf.open(pdf) as doc:
        pdf_pages = doc.page_count
    full_extra = ["--skip=%s" % skip] if skip else []
    row = {"name": name, "category": category, "isReference": is_reference, "pdfPages": pdf_pages,
           "namedReason": None if is_reference else corpus.EXPECTED_FAILURES.get(name),
           "full": side(name, "full", pdf, fonts, full_extra, out_dir, measure=True,
                        budget=SERVER_BUDGET_SECONDS if category == "stress" else None),
           "raw": side(name, "raw", pdf, fonts, ["--raw"], out_dir)}
    row["violations"] = scorecard_rules.evaluate(row)
    return row


def mean(values):
    return scorecard_rules.mean(values)


def cell(text):
    """One markdown table cell: whitespace folded, no column separators."""
    return " ".join(str(text).split()).replace("|", "/")


def table(rows, tolerance):
    lines = [
        "Mean tolerance in use: %.4f. Numbers come from this machine's Word; a record, not a CI gate." % tolerance,
        "",
        "| document | category | PDF pages | Word full / raw | mean full / raw | worst full / raw "
        "| seconds full / raw | blank | band in body | past margin | word s | declined | verdict |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        if row.get("error"):
            lines.append("| %s | %s | | | | | | | | | | | error: %s |" % (row["name"], row.get("category", ""), cell(row["error"])))
            continue
        full, raw = row["full"], row["raw"]
        declined = ", ".join("%s %d" % (k, v) for k, v in sorted(full["result"].get("declined", {}).items())) or "none"
        verdict = cell(scorecard_rules.verdict(row, row["violations"]))
        lines.append("| %s | %s | %d | %d / %d | %.4f / %.4f | %.4f / %.4f | %.1f / %.1f | %s | %s | %s | %s | %s | %s |" % (
            row["name"], row["category"], row["pdfPages"], full["wordPages"], raw["wordPages"],
            mean(full["ssim"]), mean(raw["ssim"]), min(full["ssim"] or [0]), min(raw["ssim"] or [0]),
            full["seconds"], raw["seconds"], full.get("blankPages", ""), full.get("bandInBody", ""),
            full.get("inkPastMargin", ""), ("%.1f" % full["wordSeconds"]) if "wordSeconds" in full else "",
            declined, verdict))
    return "\n".join(lines) + "\n"


def parse(argv):
    opts = {"out": None, "only": None, "skip": "", "noise": False, "reference_pdf": None, "reference_fonts": None,
            "stress": False, "cptc_template": None}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--noise":
            opts["noise"] = True
        elif arg == "--stress":
            opts["stress"] = True
        elif arg in ("--out", "--only", "--skip", "--reference-pdf", "--reference-fonts", "--cptc-template") \
                and i + 1 < len(argv):
            opts[arg[2:].replace("-", "_")] = argv[i + 1]
            i += 1
        else:
            raise SystemExit("unknown argument %s" % arg)
        i += 1
    return opts


def main(argv):
    opts = parse(argv)
    out_dir = opts["out"] or tempfile.mkdtemp(prefix="btct-scorecard-")
    os.makedirs(out_dir, exist_ok=True)
    only = set(opts["only"].split(",")) if opts["only"] else None
    if opts["stress"] and not only:
        jobs = []
    else:
        jobs = [(n, c, s, corpus.font_dirs(), False) for n, c, s in corpus.documents() if not only or n in only]
    if opts["stress"]:
        built = stress.build_all(os.path.join(out_dir, "stress-src"), opts["cptc_template"])
        for name, folder in built:
            if not only or name in only:
                jobs.append((name, "stress", folder, corpus.font_dirs() + [os.path.join(folder, "fonts")], False))
    if opts["reference_pdf"] and (not only or "reference" in only):
        fonts = [opts["reference_fonts"]] + corpus.font_dirs() if opts["reference_fonts"] else corpus.font_dirs()
        jobs.append(("reference", "reference", opts["reference_pdf"], fonts, True))

    rows = []
    for name, category, source, fonts, is_reference in jobs:
        print("... %s" % name, flush=True)
        try:
            if is_reference:
                pdf = source
            else:
                pdf = os.path.join(out_dir, name + ".pdf")
                if category == "stress":
                    compile_folder(source, pdf, [os.path.join(source, "fonts")])
                else:
                    corpus.compile_document(source, pdf)
            if opts["noise"]:
                first = side(name, "raw", pdf, fonts, ["--raw"], out_dir)
                again = os.path.join(out_dir, "%s-raw-again.word.pdf" % name)
                render(first["docx"], again)
                second = score(pdf, again, out_dir, "%s-raw-again" % name)
                rows.append({"name": name, "noise": abs(mean(first["ssim"]) - mean(second))})
                continue
            rows.append(score_document(name, category, pdf, fonts, opts["skip"], out_dir, is_reference))
        except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError, KeyError) as err:
            message = getattr(err, "stderr", None) or str(err)
            rows.append({"name": name, "category": category, "error": str(message)[:200], "violations": ["error"]})

    if opts["noise"]:
        worst = max((r.get("noise", 0.0) for r in rows), default=0.0)
        for r in rows:
            print("%-16s %s" % (r["name"], ("noise %.5f" % r["noise"]) if "noise" in r else r.get("error")))
        print("worst noise %.5f (tolerance %.4f)" % (worst, scorecard_rules.MEAN_TOLERANCE))
        return 0
    with open(os.path.join(out_dir, "scorecard.json"), "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=1)
    text = table(rows, scorecard_rules.MEAN_TOLERANCE)
    with open(os.path.join(out_dir, "scorecard.md"), "w", encoding="utf-8") as handle:
        handle.write(text)
    print(text)
    print("written to %s" % out_dir)
    return 0 if all(not r.get("violations") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
