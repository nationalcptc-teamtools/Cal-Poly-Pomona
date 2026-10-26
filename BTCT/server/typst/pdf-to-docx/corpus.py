"""The corpus the Word export is scored on, beyond the reference report.

Each entry is a folder under corpus/ with a main.typ. The documents are
compiled the way the server compiles a report (--root on the folder, system
fonts ignored, one job), with corpus/fonts and the report fonts the client
build ships. test_convert.py converts every one of them without Word;
scorecard.py also renders them through Word and scores them.

A document that is known to fail a Word-free check at the moment is listed in
EXPECTED_FAILURES with the reason. The tier fails both when an unlisted
document fails and when a listed one passes, so the list only ever shrinks
on purpose.
"""

import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))

# name -> category. Every name must have corpus/<name>/main.typ.
DOCUMENTS = {
    "memo": "plain",
    "letter": "plain",
    "cv": "plain",
    "ieee": "academic",
    "thesis": "academic",
    "notes": "academic",
    "findings": "pentest",
    "assessment": "pentest",
    "exec-letter": "pentest",
    "rtl-arabic": "rtl",
    "rtl-mixed": "rtl",
    "rtl-in-shapes": "rtl",
}

# name -> why it fails a Word-free check today. Filled in from the baseline
# run in this task, emptied by the triage tasks.
EXPECTED_FAILURES = {
    "ieee": ("15 sections for 2 PDF pages: pdf2docx writes a continuous or next-column section "
             "break every time its two-column detection changes its mind down a page, so the "
             "section count is no measure of pages here (Word draws 2 pages, as the PDF has)"),
    "rtl-mixed": ("RTL: pdf2docx cuts one Hebrew line into pieces around its English terms, which "
                  "sends it to the last rung, where lines pdf2docx wrote in page order may not be "
                  "reordered"),
}


def font_dirs():
    """corpus/fonts, then the report fonts the client build ships."""
    dirs = [os.path.join(CORPUS, "fonts")]
    for candidate in (os.path.join(REPO, "dist", "fonts"), os.path.join(REPO, "public", "fonts")):
        if os.path.isdir(candidate):
            dirs.append(candidate)
            break
    return [d for d in dirs if os.path.isdir(d)]


def documents():
    """[(name, category, source_dir)], in DOCUMENTS order."""
    return [(name, category, os.path.join(CORPUS, name)) for name, category in DOCUMENTS.items()]


def compile_document(source_dir, pdf_path):
    args = ["typst", "compile", "--root", source_dir, "--ignore-system-fonts", "-j", "1"]
    for directory in font_dirs():
        args += ["--font-path", directory]
    args += [os.path.join(source_dir, "main.typ"), pdf_path]
    subprocess.run(args, check=True, capture_output=True, text=True, encoding="utf-8")
