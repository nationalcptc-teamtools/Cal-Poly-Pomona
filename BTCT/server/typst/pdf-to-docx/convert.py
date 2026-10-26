#!/usr/bin/env python3
"""Turn a finished PDF into a Word file that looks like it.

    convert.py <in.pdf> <out.docx> <result.json>

The server compiles the report to PDF with typst and then runs this script on
the result, so the Word file can never disagree with the PDF: redactions are
already baked in, figure numbering is whatever typst evaluated, and the page
breaks are the ones the reader saw.

pdf2docx does the page-to-paragraph work. Two things it gets wrong on a real
report are repaired here, and both repairs are written against page geometry
rather than against any one template:

1. A running header or footer is ordinary page content to pdf2docx, so it
   becomes a paragraph in the body. Word then re-flows it, every page grows by
   the height of its footer, and a 23-page report comes out at 44. So the
   repeating bands are found, removed from the PDF before the conversion, and
   put back afterwards as real Word headers and footers.
2. A table of contents whose entries end in dot leaders confuses the line
   grouping: entries merge, and page numbers land next to the wrong title.
   The entries are read out of the PDF instead and written back as one clean
   paragraph each, with a dot-leader tab stop.

Nothing here knows what a report is. A PDF with no running band and no table
of contents goes through both steps untouched.
"""

import os

# One thread for the numeric libraries, set before anything loads them. numpy's
# OpenBLAS and OpenCV size their thread pools to the CPUs the kernel reports,
# which in a container is the host's, not the cgroup's quota: on a 24-core
# host `import cv2` started 47 threads and mapped 4.4 GB of address space for
# 41 MB of memory, and under `cap_address_space`'s 3 GB that import is a
# segfault, not a MemoryError. With one thread it maps 275 MB. The box this
# runs on has one or two cores, so the threads bought nothing anyway.
for _threads in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[_threads] = "1"

import bisect  # noqa: E402
import contextlib  # noqa: E402
import copy  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import math  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
import unicodedata  # noqa: E402
import zipfile  # noqa: E402
from collections import Counter  # noqa: E402
from statistics import median  # noqa: E402
from xml.etree import ElementTree  # noqa: E402

import pymupdf  # noqa: E402
from docx import Document  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING, WD_TAB_ALIGNMENT, WD_TAB_LEADER  # noqa: E402
from docx.oxml import OxmlElement, parse_xml  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from docx.shared import Pt, RGBColor  # noqa: E402
from docx.text.paragraph import Paragraph  # noqa: E402

# Isolated mode drops the script's own directory from the import path, and
# the server runs this with -I, so the sibling module is found by hand.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fonts  # noqa: E402
import tagged  # noqa: E402

# ── thresholds ────────────────────────────────────────────────────────────
# A band has to live near a page edge. 12% of US Letter is 95 pt, which is
# more than any running header sensibly occupies and still clear of the first
# body line even on a page that opens with a large heading.
BAND_ZONE_FRACTION = 0.12
# Two rows are the same row when their normalized text matches and their top
# edges are within this many points. Typst puts a running header on the same
# baseline every time; the tolerance is for generators that round per page.
BAND_Y_TOLERANCE_PT = 2.0
# Share of the pages that have anything at all in that zone. Below this it is
# body content that happens to repeat, not a band. A cover page with nothing
# up there is not counted either way.
BAND_REPEAT_FRACTION = 0.60
# How far a Word section's paper may differ from its PDF page's before the
# section is not taken for that page. Sections are written in twentieths of a
# point and A4 is 595.28 by 841.89; a sideways page is 250 pt away.
SECTION_SIZE_SLACK_PT = 2.0
# A rule under a header or a filled strip behind a footer joins the band when
# it repeats and sits within this distance of the repeating text.
BAND_GLUE_PT = 30.0
# Lines of one band sit next to each other, so a repeating row this many row
# heights clear of the band is body content that happens to repeat, such as a
# page-opening heading whose only change is its number. Without this the
# heading would be stripped out of the document.
BAND_LINE_GLUE = 1.6
# A running band is separated from the body by a margin, and body text is not.
# The candidate must clear the nearest body row by at least this fraction of
# the body's own line pitch. Measured on five documents (the ratio is the
# candidate's gap to the nearest body row over the median body line pitch):
#
#   a real running header, 23-page report      1.03     keep
#   a real footer, same report                14.13     keep
#   a real page-number footer, letter/1in     25.67     keep
#   a repeated FIRST BODY LINE under a header  0.13     drop
#   a repeated table header and data row       0.31     drop
#   alternating headers plus body lines        0.13     drop
#
# 0.5 sits in the empty middle: twice the worst false positive, half the
# tightest true one. Without it the repeated first body line of every page is
# deleted from the document and pasted into the Word header.
BAND_SEPARATION_RATIO = 0.5
# The gap above has to be measurable on more than this many of the band's
# pages. A page whose only text is the candidate cannot be measured, and a
# document made of those was accepted by default: every page's one body line
# was lifted into the Word header and the text check, having nothing left to
# compare, called it clean.
BAND_SEPARATION_MIN_PAGES = 2
# Room left around a band rectangle when it is removed, so a glyph that
# overhangs its reported box does not survive as a sliver.
BAND_PAD_PT = 1.0
# How far a row's left edge may move between a page and the same page with
# its Header and Footer artifacts removed and still be the same row. Nothing
# should move at all; this only absorbs rounding.
TAGGED_X_TOLERANCE_PT = 1.0
# A horizontal gap this wide starts a new column within one row: it is what
# separates a left header piece from a right one, and a section number from
# the title beside it. Narrower than this is ordinary inter-word space.
COLUMN_GAP_PT = 4.0
# How far a column's edge may sit from the text area's edge and still count
# as flush with it.
ALIGN_TOLERANCE_PT = 6.0

# A dot leader is this many dots or more, optionally spaced. Four would match
# an ellipsis followed by a full stop; six is past anything punctuation does.
LEADER_MIN_DOTS = 6
# Dot-leader paragraphs this far apart in the converted document still belong
# to the same table of contents: pdf2docx sometimes leaves a stray fragment
# between two entries.
TOC_RUN_GAP = 2
# Fewer than this in one stretch is a coincidence, not a table of contents.
TOC_RUN_MIN = 3
# Ceiling on the blank space carried over before an entry, so one bad reading
# cannot push the list onto another page.
TOC_MAX_SPACE_BEFORE_PT = 24.0

# ── the decoration pdf2docx drops ─────────────────────────────────────────
# A filled rectangle survives the conversion when it becomes a table cell and
# is discarded otherwise. These separate the shapes worth putting back from
# the ones that are already handled, and every number is from the reference
# report: its table cells are 17.6 pt tall around an 11.6 pt line (ratio 1.5),
# its code panels 46.2 pt around three of them (4.2), its accent bar 7.2 pt
# wide, and its chart legend's swatches 9 pt squares 6 pt left of their label.
PANEL_MIN_WIDTH_PT = 40.0
PANEL_MIN_HEIGHT_PT = 12.0
PANEL_PADDING_RATIO = 1.6
BAR_MAX_WIDTH_PT = 12.0
# A filled rectangle is a table cell's when another touches it in its column
# within this much (a row of cells shares its edges); a code panel stands
# further from the next one than this.
GRID_TOUCH_PT = 2.0
# How far apart, per channel in 0 to 1, two fills may be and still be the
# same colour: pdf2docx rounds a fill once, PyMuPDF reads it another way.
FILL_MATCH_TOLERANCE = 0.06
# Word's own left and right cell margin, which pdf2docx's style inherits.
DEFAULT_CELL_MARGIN_PT = 5.4
# A floated picture is the PDF's when its page position and size agree within
# this; a figure frame cell is the picture's when its row and cell agree with
# the visible part within this. The frame's stroke is inset half a point.
PICTURE_FIT_PT = 1.5
FRAME_FIT_PT = 2.5
# How many PDF pictures may be passed over to find the one a drawing is.
PICTURE_LOOKAHEAD = 4
# How many blocks after a floated picture's paragraph its frame may stand.
FRAME_SEARCH_BLOCKS = 80
# The frame's stroke sits this far outside the clip that bounds the picture.
FRAME_STROKE_INSET_PT = 0.5
# How far a panel table may hang into the left margin.
TABLE_HANG_PT = 36.0
# A page whose header pushed its content down by less than this is not worth
# a warning; a point or two is within what Word's own rounding moves.
HEADER_SHAVE_WARN_PT = 3.0
# How much taller than the paragraphs it replaces a panel table may be.
PANEL_GROW_PT = 80.0
# How many paragraphs ahead a panel's rows are looked for when the pages
# of the paragraphs are not known.
PANEL_SEARCH_WINDOW = 80
PANEL_MIN_SIDE_PT = 3.0
# The line height of the empty paragraph that keeps two tables apart. Word
# measures spacing in twentieths of a point and will not take a line of none,
# so this is the smallest box it will draw, and it draws nothing in it.
SPACER_LINE_PT = 0.05
# A drawing this thin and this wide is a rule rather than a filled shape. The
# reference report's heaviest rule is 1.5 pt.
RULE_MAX_THICKNESS_PT = 2.5
# How far a table may be moved onto the rules the PDF drew for it. The
# converter's own placement is out by up to 1.27 pt on the reference report,
# so this is three times the worst of that, and the report's closest two
# rules are 17.6 pt apart, so there is no second candidate inside it.
TABLE_TOP_PT = 4.0
# How far a rule's end may sit from the table's own edge and still be that
# table's rule. A stroke's round cap reaches past the corner it is drawn to,
# which on the reference report is 0.33 pt.
TABLE_EDGE_PT = 3.0
# How close a row boundary has to be to a PDF edge to count as landing on it.
# The converter's rows land within 0.2 pt of the PDF's across a whole table,
# so this is loose enough for that and far tighter than the 17.6 pt between
# two of the report's rules.
TABLE_FIT_PT = 0.5
# How closely a table's own height has to match a rectangle the PDF drew
# before the two are taken to be the same box. Both numbers come from the same
# strokes, so they agree to the twentieth of a point the converter rounds a
# row height to; this is room for that and for a stroke's own width.
TABLE_BOX_PT = 1.5
# How far a table may be moved onto such a rectangle. A box the converter met
# is placed through the spacing of everything above it, and on the reference
# report that comes to under 4 pt; more than this and the two are not the same
# object however well their sides agree.
TABLE_BOX_MOVE_PT = 8.0
# How far a table may be moved onto the rectangle the PDF drew for its first
# row alone. A grid's header row is filled where the rest of it is only ruled,
# and that one box, matched on its left edge, its right edge and its height,
# says where the table's top is as surely as a box round the whole: a host
# table under a code panel stood 21 pt below its PDF place, the converter's
# flow having added the panel's spacers up, and nothing above could say so.
# pdf2docx draws each line of a code panel as a one-row table and a spacer,
# about 1 pt a line taller than the PDF, and three panels on one page put the
# table 21 pt low in the flow the pass keeps a table in; Word shows the same
# 21.0 pt on the file with the panels left as the converter wrote them, and
# 1.9 pt once the panels are rebuilt, so it is this pass that put it back.
# The row's cells are joined first (`joined_row_fills`): typst fills each
# cell on its own, so a header over two columns is two rectangles.
TABLE_HEADER_MOVE_PT = 36.0
# The automatic line a paragraph written for a picture carries, 240 twips,
# which is what `twips_of` reads it as in points.
PICTURE_SINGLE_LINE_PT = 12.0
# How far two fill colours may differ, channel by channel, and still be one
# fill. The cells of a header row read back as 0.2627 and 0.2628 from the same
# `fill:`, so this is room for the rounding in the content stream, and far
# below the 0.58 between a panel's accent bar and its body.
FILL_SAME_RGB = 0.02
# How many of a table's boundaries have to land on the PDF's edges before the
# fit is believed. Two is a coincidence between any two rules; three means
# the distance between them agrees as well, which one stray rule cannot fake.
TABLE_FIT_MIN = 3
SWATCH_MAX_SIDE_PT = 14.0
SWATCH_TEXT_GAP_PT = 10.0
# How many characters either side of a run boundary identify it. Eight is
# enough to be unambiguous on a report and short enough to survive the
# converter splitting a run somewhere else.
PAIR_WINDOW = 8
# Families whose name says the text is code. A space inserted into a command
# is a change to the report, not a repair, so the marker-space pass stays out
# of anything wearing one of these.
MONOSPACE = re.compile(r"mono|courier|consol|menlo|inconsolata|source ?code", re.IGNORECASE)
# A justified paragraph reaches the right edge on every line but its last.
# Three lines is the shortest run where that means anything: two lines both
# reaching the edge is also what a centred pair looks like.
JUSTIFY_MIN_LINES = 2
JUSTIFY_EDGE_PT = 3.0
# How far the ends of one justified paragraph's lines spread: measured over
# 52 pages of a 69-page report they stay within 0.4 pt of each other, while
# the ragged lines of a finding card fell within 3 pt of their longest often
# enough to be read as justified, and then a tab wrapped and left an empty line.
JUSTIFY_SPREAD_PT = 1.0
# A run of lines may start this far in from the text's left edge (a list
# three levels deep), and a list item's first line may stand this far left
# of its other lines (its marker's hanging indent).
INDENTED_RUN_MAX_PT = 90.0
HANGING_INDENT_MAX_PT = 30.0
JUSTIFY_LINE_GAP_PT = 6.0
# The widest first-line indent: a line starting further in than this, just
# above a flush-left run, is a centred or right-hand line, not the first line
# of the run's paragraph. Three ems of 12 pt text.
FIRST_LINE_INDENT_MAX_PT = 36.0
# Slack added to a paragraph whose lines are broken where the PDF broke them.
# Word and typst measure a justified line a fraction differently, and a line
# that fills the column exactly in the PDF wraps twice here without it.
LINE_FIT_RELIEF_PT = 4.0
LINE_FIT_MAX_RELIEF_PT = 12.0
# A line that ends this far short of the column was not stretched by typst,
# so Word must not stretch it either (a tab before its break stops that).
SHORT_LINE_PT = 6.0
# Twips a character by which the runs of a broken paragraph are condensed,
# measured through Word on Poppins 11 pt (see `condense_runs`).
CONDENSE_RAGGED_TWIPS = 1
CONDENSE_JUSTIFIED_TWIPS = 2
# Word's line width over typst's for the same ragged text (0.74% measured on
# Poppins 11 pt), and how much typst shrank a space on a justified line.
WORD_WIDTH_EXCESS = 0.012
SPACE_SHRINK_PT = 1.0

# ── where Word puts a line, so a block can be placed without rendering ────
# With `w:lineRule="exact"` and a line height of L, Word puts the baseline
# exactly 0.8 x L below the top of the line box, whatever the font and
# whatever the point size. Measured over 30 cases (six sizes from 8 to 18 pt,
# five line heights each from 1.0 to 2.0 em, one per page so nothing above
# could contribute): every one landed on 0.8 x L within 0.10 pt, which is the
# 1/600 inch Word rounds to when it writes a PDF. The same probe showed that
# space before is dropped at the top of a page.
#
# The gap between two paragraphs is the LARGER of the spacing after the first
# and the spacing before the second, not their sum. Twelve cases, one per
# page, both values stated and neither inherited: every one came out on the
# larger of the two within 0.12 pt, including 12 pt after against 4 pt before
# and 5 pt after against 20 pt before. An earlier round wrote the opposite
# down, from cases where one of the two was zero and the two rules agree.
# Those three facts are the whole layout model the vertical pass needs, and
# none of them is about this report.
EXACT_BASELINE_RATIO = 0.8
# How far ahead of the cursor a block may look for its first PDF row. The
# converter writes a stray empty paragraph here and there; it never re-orders
# a page.
RHYTHM_LOOKAHEAD = 6
# PDF rows one converted paragraph may hold. A paragraph broken at the PDF's
# own line ends holds one row per line, and the report's longest is 8.
RHYTHM_MAX_ROWS = 16
# Spacing is not rewritten for less than this. Word rounds a paragraph's
# spacing to twentieths of a point and its own output to 0.12 pt, so a
# correction smaller than this is noise being written into the file.
RHYTHM_TOLERANCE_PT = 0.25

# The passes a developer may turn off with --skip, to find which one a
# regression comes from without editing code. Font naming and embedding are
# not here: they are guarantees, not layout. The server never passes --skip.
SKIPPABLE = ("bands", "toc", "panels", "swatches", "align", "pictures", "line-breaks",
             "text-repair", "hyphens", "pitch-cut", "rhythm", "rtl", "page-start", "columns", "rotated",
             "page-fills", "margin-notes", "hanging", "labels")
# Room left between the last block a section places and the bottom margin. A
# correction that would not clear it is abandoned for that section rather than
# risk pushing a block onto the next page.
RHYTHM_BOTTOM_GUARD_PT = 6.0
# A PDF page's first line is trusted as a prefix of a longer paragraph only when it is
# this many squashed characters long; a shorter line must be the whole paragraph.
PAGE_START_PREFIX = 40
# How deep a table may be nested and still be placed against the PDF. The
# reference report's finding card is a table of tables two levels down; past
# that the converter is describing a drawing rather than a layout.
RHYTHM_NESTING = 4
# How far the first block of a page may be moved before the model is taken to
# have misread the page. Measured against the converter's own layout, the
# reference report's pages start within 1.6 pt of where the model says they
# do; a page that disagrees by more than a line of text has something on it
# this pass does not understand (a floating table, a frame), and there the
# first block keeps its place and only the rhythm below it is corrected.
RHYTHM_ABSOLUTE_LIMIT_PT = 12.0
# The offset a page's first paragraph asks for, in spacing before, that is
# moved into the section's top margin before the rhythm walk runs. One line:
# below it the first block is where pdf2docx's margin put it, which is the
# case the walk's model was measured on (pages start within 1.6 pt of it).
# Above it the converter had no margin to spend, which is what a cover does
# to it: a full-bleed band makes the content's bounding box the whole page, so
# pdf2docx writes margins of 0 and carries the 82.7 pt between the page's top
# and its first line as that line's spacing before. Word honours it (measured
# on design-b1's cover, and on a section starting at any top margin: before
# of 40, 100 and 200 pt drew 39.6, 99.6 and 199.7 pt below the margin).
LEAD_FOLD_MIN_PT = RHYTHM_ABSOLUTE_LIMIT_PT
# How much bigger than a block's own leading a gap between two of its
# baselines has to be before it is read as the space between two blocks the
# converter wrote as one. A typesetter sets one paragraph at one leading and
# the baselines in a PDF are exact, so there is nothing to absorb here but
# Word's own 1/600 inch rounding; the smallest real change on the reference
# report is 0.85 pt, between a sub-heading's line and the body under it.
PITCH_SPLIT_PT = 0.5
# Two cell edges are the same edge when they are this close. The converter
# writes a cell's width to a twentieth of a point, so the left edges of a
# merged cell and its continuation agree to well inside this.
CELL_EDGE_PT = 0.5
# Two pieces of text a cell draws on one line share a baseline exactly, so
# this only has to cover a generator that rounds each piece on its own. A
# cell's real lines are a whole line pitch apart, which on the smallest text
# a report sets is 8 pt, so there is no second candidate anywhere near it.
SAME_LINE_PT = 1.0
# How far a cell's corrected content may reach past the bottom Word clips an
# exact row at before the whole table is given back. A row's height and the
# boxes inside it are both rounded to a twentieth of a point, and a cell the
# converter already filled to the brim stays full, so the tolerance has to
# cover that rounding and nothing more.
CELL_CLIP_PT = 1.0
# The names Word has had for a cell's left and right inner margins. The
# converter writes the newer pair.
CELL_MARGIN_NAMES = {
    "top": ("w:top",),
    "bottom": ("w:bottom",),
    "left": ("w:start", "w:left"),
    "right": ("w:end", "w:right"),
}
# English Metric Units, which is what a drawing in a Word file is measured in.
EMU_PER_PT = 12700

# ── what the converter will not take on ───────────────────────────────────
# Three bounds, all of them measured rather than guessed. The reference
# report's worst page holds 62 drawings in a 294 kB instruction stream, so
# every one of these has at least a seven times margin over a real report,
# while three A4 pages of 120,000 one-point rectangles (2.1 MB, 2.5 s out of
# typst) are refused in 0.08 s instead of costing the converter 35.9 s and
# 651 MB of RSS. Each refusal reads like the other server export limits and
# sends the operator to the PDF, which has none of these problems.
# What the fidelity passes and the text check cost, as multiples of the
# repairs that must run before them. Measured on three documents; see
# `affordable`.
FIDELITY_COST_RATIO = 1.0
CHECK_COST_RATIO = 3.0
# Kept back from the font-conversion allowance for writing the package. The
# reference report's Word file is 2.6 MB and rewriting it with its font parts
# took 0.4 s, so four times that leaves room for a document several times its
# size without letting a redrawn font be the reason nothing is delivered.
FONT_WRITE_RESERVE_S = 1.6
MAX_PAGES = 300
MAX_PAGE_CONTENT_BYTES = 3_000_000
MAX_PAGE_DRAWINGS = 10_000
# And a budget for the whole document, because the page bound misses the shape
# that really costs: 60 pages of 9,000 drawings clears every per-page test and
# still takes the converter 50.5 s and 403 MB. The reference report draws 479
# shapes across its 23 pages, so 150,000 is over 300 times a real report and
# still refuses that document at its 17th page, before the converter starts.
MAX_DOCUMENT_DRAWINGS = 150_000
# Address space for this process on Linux. PyMuPDF and OpenCV map far more
# than they touch, so this is well above the RSS it is meant to bound; it is
# a backstop that turns a runaway conversion into a MemoryError and a 422
# rather than a cgroup kill of the process that is also the Yjs relay.
ADDRESS_SPACE_LIMIT_BYTES = 3 * 1024 * 1024 * 1024

# Schemes a Word file may hand to the reader's shell. Everything else is
# removed from the PDF before the converter sees it: `FILE://host/share/x`
# resolves as UNC and leaks credentials, and `javascript:` and `ms-msdt:` are
# the same class of problem.
SAFE_LINK_SCHEMES = ("http", "https", "mailto")
LINK_SCHEME = re.compile(r"^\s*([A-Za-z][A-Za-z0-9+.\-]*)\s*:")

# What a typesetter leaves where it broke a word. It is invisible to a reader
# of the PDF, which prints a hyphen for it, and visible to a reader of a Word
# file, which prints it as a hyphen in the middle of a line.
SOFT_HYPHEN = "\u00ad"
# What a chart legend's swatch is drawn as when it comes back as a character.
# A text font often has no glyph for it, so the face it is set in is chosen
# rather than inherited.
FILLED_SQUARE = "\u25a0"
# Invisible characters a typesetter puts around a page number.
INVISIBLE = "⁠​‌‍﻿"
DIGITS = re.compile(r"\d+")
LEADER = re.compile(r"(?:\.[ \t ]*){%d,}" % LEADER_MIN_DOTS)
TOC_LINE = re.compile(
    r"^(?P<title>.*?\S)[ \t ]*(?:\.[ \t ]*){%d,}[%s ]*(?P<page>\d{1,4})$"
    % (LEADER_MIN_DOTS, INVISIBLE)
)
BOLD_FLAG = 1 << 4
SUBSET_PREFIX = re.compile(r"^[A-Z]{6}\+")
FONT_STYLE_SUFFIX = re.compile(
    r"[-,_]?(?:bold|italic|oblique|regular|book|light|medium|semibold|demibold"
    r"|black|heavy|thin|roman|mt|ps)$",
    re.IGNORECASE,
)


class ConvertError(Exception):
    """A failure with a message short enough to show an operator."""


# ── reading the page ──────────────────────────────────────────────────────


def normalize(text):
    """Collapse whitespace and blank out digit runs.

    Two pages of a running header differ only in the page number, so the page
    number has to stop being part of the identity before the two compare
    equal.
    """
    return DIGITS.sub("#", " ".join(text.split()))


def pdf_base_name(pdf_font_name):
    """`ABCDEF+Poppins-Bold` to `Poppins-Bold`: the face, as the PDF names it.

    A PDF writes a font's PostScript name behind a subset prefix. That name
    identifies one face and no other, which is what makes it the key to the
    font file the report was set in, and through that to the family name Word
    will look the face up by.
    """
    name = SUBSET_PREFIX.sub("", str(pdf_font_name or "")).split(",")[0].strip()
    return name or None


def font_family(pdf_font_name):
    """`ABCDEF+Poppins-Bold` to `Poppins`, a family read off the name alone.

    A guess, and only used where nothing better is available: when no font
    file was staged, the style suffix is the one clue the PDF gives about
    which part of the name is the family.
    """
    name = SUBSET_PREFIX.sub("", str(pdf_font_name or "")).split(",")[0]
    while True:
        shorter = FONT_STYLE_SUFFIX.sub("", name)
        if shorter == name or not shorter:
            break
        name = shorter
    return name.strip(" -_") or None


def truncate(text, limit):
    """`text` cut to `limit` characters, the last one an ellipsis when it was."""
    out = " ".join(str(text).split())
    return out if len(out) <= limit else out[: limit - 1] + "…"


def rgb_of(color_int):
    value = int(color_int or 0)
    return RGBColor((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)


# The logical reading: the default flags for a text dictionary, with the
# made-up spaces between glyphs that sit apart turned off.
LOGICAL_TEXT_FLAGS = pymupdf.TEXTFLAGS_DICT | pymupdf.TEXT_INHIBIT_SPACES


def strong_direction(text):
    """(right-to-left, left-to-right) counts of the characters that have one.

    Digits, punctuation and spaces have no strong direction and are not
    counted.
    """
    rtl = ltr = 0
    for ch in text:
        kind = unicodedata.bidirectional(ch)
        if kind in ("R", "AL"):
            rtl += 1
        elif kind == "L":
            ltr += 1
    return rtl, ltr


# Bidi classes that are only spaces, separators and punctuation. A span made
# of nothing else may be turned round when it is read right to left; digits
# (EN, AN) are deliberately absent.
NEUTRAL_BIDI = frozenset(("WS", "ON", "CS", "ES", "ET", "S", "B"))


def has_number(text):
    """Does this text hold a digit, European or Arabic-Indic?"""
    return any(unicodedata.bidirectional(ch) in ("EN", "AN") for ch in text)


def has_rtl(text):
    """Does this text hold any right-to-left letter at all?"""
    return strong_direction(text)[0] > 0


def is_rtl(text):
    """Is this line right-to-left, by a majority of its strong characters?

    One Hebrew phrase quoted in an English sentence leaves it left-to-right,
    and English terms inside a Hebrew sentence leave it right-to-left.
    Digits, punctuation and spaces have no strong direction and do not vote.
    """
    rtl, ltr = strong_direction(text)
    return rtl > 0 and rtl >= ltr


def ambiguous_number(text):
    """Is this a left-to-right line with a number right beside right-to-left words?

    The bidi algorithm draws a number that follows a Hebrew or Arabic phrase
    in an English line to that phrase's left, so the page shows "12 שרת" for
    both "שרת 12" and "12 שרת": the typed order cannot be read off the page,
    and any reading of it is a guess. Spaces and punctuation between the two
    do not separate them. A right-to-left line is not ambiguous this way, nor
    is a number that only English touches.
    """
    if is_rtl(text):
        return False
    strong = []
    for ch in text:
        kind = unicodedata.bidirectional(ch)
        if kind in ("R", "AL"):
            strong.append("R")
        elif kind in ("EN", "AN"):
            strong.append("N")
        elif kind == "L":
            strong.append("L")
    return any({a, b} == {"R", "N"} for a, b in zip(strong, strong[1:]))


def span_text_in_order(span):
    """A span's text from its characters, with each number's digits read as drawn.

    A number reads left to right wherever it stands, but PyMuPDF gives a
    span's characters in the order the PDF draws them, and a PDF that draws
    right-to-left text glyph by glyph from the right draws Arabic-Indic
    digits that way too: typst's "١٢" comes back "٢١". So each unbroken run
    of digits is put in the order of the glyphs' left edges. A run already in
    that order, as European digits are, is unchanged.
    """
    chars = span["chars"]
    out = []
    index = 0
    while index < len(chars):
        if unicodedata.bidirectional(chars[index]["c"]) not in ("EN", "AN"):
            out.append(chars[index]["c"])
            index += 1
            continue
        end = index
        while end < len(chars) and unicodedata.bidirectional(chars[end]["c"]) in ("EN", "AN"):
            end += 1
        out.extend(c["c"] for c in sorted(chars[index:end], key=lambda c: c["bbox"][0]))
        index = end
    return "".join(out)


def bidi_order(parts, rtl_line):
    """A line's spans, given left to right as the page shows them, in reading order.

    PyMuPDF gives each span's characters in reading order already, and the
    spans of a line left to right. That is the reading order for English and
    the reverse of it for Hebrew or Arabic, so the spans that run against the
    line's direction are turned round: in a right-to-left line the whole
    sequence is reversed and each run of English in it put back the right
    way, and in a left-to-right line each run of right-to-left spans is
    reversed where it stands. A run takes in the spaces and punctuation
    between two of its own spans, never the ones at its edges. A span of
    nothing but spaces and punctuation has no direction of its own, so
    PyMuPDF gives it in page order, and where it is read right to left its
    characters are turned round too: ", " before a Hebrew word shows as " ,".
    Digits are not punctuation: a number always reads left to right, so in a
    right-to-left line a span holding one is a left-to-right run like English,
    and its characters are never turned ("2.4.1" stays "2.4.1"). This is the
    two-level case of the Unicode algorithm, which is all a line of a report
    holds.
    """
    kinds = []
    for text in parts:
        rtl, ltr = strong_direction(text)
        if rtl > ltr:
            kinds.append("R")
        elif ltr or (rtl_line and has_number(text)):
            kinds.append("L")
        else:
            kinds.append("N")
    against = "L" if rtl_line else "R"
    groups = []
    index = 0
    while index < len(parts):
        if kinds[index] != against:
            groups.append((False, parts[index:index + 1]))
            index += 1
            continue
        end = index
        probe = index + 1
        while probe < len(parts) and kinds[probe] != ("R" if against == "L" else "L"):
            if kinds[probe] == against:
                end = probe
            probe += 1
        groups.append((True, parts[index:end + 1]))
        index = end + 1

    def turned(part):
        return part[::-1] if all(unicodedata.bidirectional(ch) in NEUTRAL_BIDI for ch in part) else part

    if rtl_line:
        return [part if run else turned(part) for run, group in reversed(groups) for part in group]
    return [turned(part) if run else part
            for run, group in groups for part in (reversed(group) if run else group)]


def page_rows(page, logical=False, blocks=None):
    """One entry per visual row, each split into columns.

    PyMuPDF reports the left and right halves of a running header as two lines
    of one block, and a table-of-contents number as a line of its own beside
    its title. Both are one row to a reader, so rows on the same baseline of
    the same block are joined, and then split again wherever a gap wider than
    ordinary word spacing appears. That split is the column structure both
    repairs below are built on.

    `logical=True` is the reading the text check wants for right-to-left
    text, and nothing else asks for it. The default reading lays a column's
    spans out left to right, as the page shows them, and makes up a space
    wherever two glyphs sit apart; for Arabic, set one glyph at a time, that
    puts spaces inside words. The logical reading keeps only the space glyphs
    the PDF really has and reads each column's spans in reading order
    (`bidi_order`), and each number's digits in the order they are drawn
    (`span_text_in_order`). Its rows are the default reading's rows, so a row
    keeps its `row_id`; its columns are cut only at gaps no space glyph fills.

    `blocks` is the page's `get_text("dict")` blocks when the caller has
    already read them, since reading the page is most of what this costs. They
    are only read here, never changed, so they can be shared.
    """
    raw = []
    if blocks is None or logical:
        blocks = (page.get_text("rawdict", flags=LOGICAL_TEXT_FLAGS) if logical else page.get_text("dict"))["blocks"]
    for block in blocks:
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            if logical:
                for span in line.get("spans", []):
                    span["text"] = span_text_in_order(span)
                # Space glyphs are text here. A line of nothing else is not a
                # row, as it is not in the default reading.
                spans = [s for s in line.get("spans", []) if s.get("text", "")]
                if not any(s["text"].strip() for s in spans):
                    spans = []
            else:
                spans = [s for s in line.get("spans", []) if s.get("text", "").strip()]
            if spans:
                raw.append({"y0": line["bbox"][1], "y1": line["bbox"][3], "block": id(block), "spans": spans})
    raw.sort(key=lambda r: (round(r["y0"], 1), r["spans"][0]["bbox"][0]))

    joined = []
    for row in raw:
        previous = joined[-1] if joined else None
        if (
            previous is not None
            and previous["block"] == row["block"]
            and abs(previous["y0"] - row["y0"]) <= BAND_Y_TOLERANCE_PT
        ):
            previous["spans"].extend(row["spans"])
            previous["y1"] = max(previous["y1"], row["y1"])
            continue
        joined.append(dict(row))

    out = []
    for row in joined:
        spans = sorted(row["spans"], key=lambda s: s["bbox"][0])
        if logical:
            # Blank spans at either end of the row are not between two
            # words, and would move the row's left edge.
            while spans and not spans[0]["text"].strip():
                spans.pop(0)
            while spans and not spans[-1]["text"].strip():
                spans.pop()
        rtl_row = logical and is_rtl("".join(s["text"] for s in spans))
        columns = []
        for span in spans:
            x0, x1 = span["bbox"][0], span["bbox"][2]
            if logical and not span["text"].strip():
                # A space glyph is text in the logical reading, and it closes
                # the gap it sits in: a space between two words set in a
                # fallback font is wider than the gap that cuts a column.
                if columns:
                    columns[-1]["parts"].append(span["text"])
                    columns[-1]["x1"] = max(columns[-1]["x1"], x1)
                continue
            if columns and x0 - columns[-1]["x1"] <= COLUMN_GAP_PT:
                column = columns[-1]
                if logical:
                    column["parts"].append(span["text"])
                    column["x1"] = max(column["x1"], x1)
                    column["y0"] = min(column["y0"], span["bbox"][1])
                    column["y1"] = max(column["y1"], span["bbox"][3])
                    continue
                joiner = " " if x0 - column["x1"] > 0.8 and not column["text"].endswith(" ") else ""
                column["text"] += joiner + span["text"]
                column["x1"] = max(column["x1"], x1)
                column["y0"] = min(column["y0"], span["bbox"][1])
                column["y1"] = max(column["y1"], span["bbox"][3])
                continue
            columns.append(
                {
                    "x0": x0,
                    "x1": x1,
                    # The column's own box, which is not the row's: a row that
                    # holds an eight point label beside a sixteen point
                    # heading is as tall as the heading, and a box measured
                    # from that would never shrink to fit the label.
                    "y0": span["bbox"][1],
                    "y1": span["bbox"][3],
                    "text": span["text"],
                    "font": font_family(span["font"]),
                    # The face itself, kept beside the guess at its family so
                    # a staged font file can name it the way Word resolves it.
                    "psname": pdf_base_name(span["font"]),
                    "size": span["size"],
                    "bold": bool(span["flags"] & BOLD_FLAG),
                    "color": span["color"],
                    # Where the glyphs actually sit on the line. Word positions
                    # a line by its baseline, so the vertical pass compares
                    # baselines rather than the bounding boxes above them.
                    "base": span["origin"][1],
                    "advance": (x1 - x0) / len(span["text"]) if span["text"] else 0.0,
                }
            )
            if logical:
                columns[-1]["parts"] = [span["text"]]
        for column in columns:
            if logical:
                column["text"] = "".join(bidi_order(column.pop("parts"), rtl_row))
            # A code line's span can start with its own indent as space
            # glyphs, so its box starts at the panel's edge while the line's
            # first letter stands further in: the ink is where it starts.
            lead = len(column["text"]) - len(column["text"].lstrip())
            column["inkX0"] = column["x0"] + lead * column.get("advance", 0.0)
            column.pop("advance", None)
            column["text"] = column["text"].strip()
        columns = [c for c in columns if c["text"]]
        if not columns:
            continue
        out.append(
            {
                "y0": row["y0"],
                "y1": row["y1"],
                "x0": columns[0]["x0"],
                "inkX0": columns[0]["inkX0"],
                "x1": columns[-1]["x1"],
                "base": median(sorted(c["base"] for c in columns)),
                "columns": columns,
                "text": " ".join(c["text"] for c in columns),
            }
        )
    return out


# ── step 1: find the repeating bands ──────────────────────────────────────


def in_zone(page, edge, y0, y1):
    height = page.rect.height
    if edge == "top":
        return y1 <= height * BAND_ZONE_FRACTION
    return y0 >= height * (1.0 - BAND_ZONE_FRACTION)


def band_quorum(populated):
    """How many pages a group must appear on before it can be a band.

    The old rule was `max(2, round(n x 0.6))`, which on a four-page document
    is two pages: enough for two rows of a long table that happen to land at
    the same height to be read as a running band and deleted. So the floor is
    three, and a document too short for a fraction to mean anything has to
    carry the band on every page it could, bar one: a cover or a divider may
    have something else up there, and nothing else may.
    """
    if populated <= 3:
        return max(2, populated - 1)
    return max(3, math.ceil(populated * BAND_REPEAT_FRACTION))


def row_id(index, row):
    return (index, round(row["y0"], 1), round(row["x0"], 1))


def alternating_at_edge(groups, edge, quorum):
    """Two different texts taking turns at the outermost position, or None.

    An odd-and-even running header is two groups that never share a page. Word
    can express that (`w:evenAndOddHeaders` plus a second header part) and this
    script does not, so the honest answer is to leave that edge in the body
    rather than concatenate both texts into one header, which is what happened
    before: every page carried "Acme Security Assessment Contoso Consulting
    Group".
    """
    if len(groups) < 2:
        return None
    key = (lambda rows: min(r["y0"] for _, r in rows)) if edge == "top" else (lambda rows: -max(r["y1"] for _, r in rows))
    extreme = min(key(rows) for rows in groups)
    outermost = [rows for rows in groups if abs(key(rows) - extreme) <= BAND_Y_TOLERANCE_PT * 2]
    if len(outermost) < 2:
        return None
    pages = [{index for index, _ in rows} for rows in outermost]
    for i, first in enumerate(pages):
        for second in pages[i + 1 :]:
            if not (first & second) and len(first | second) >= quorum:
                return ("the running %s alternates between two texts, which Word cannot repeat "
                        "from one definition" % ("header" if edge == "top" else "footer"))
    return None


def separation(doc, cluster, edge):
    """How far the cluster sits from the body, as a multiple of the body's pitch.

    Returns `(gap, pitch, pages)`: the medians over the pages that carry the
    cluster, and how many pages could be measured at all. A page whose only
    text is the candidate contributes nothing, and a document made of those
    used to be accepted by default, which lifted every page's one body line
    into the header.
    """
    members = {row_id(index, row) for rows in cluster for index, row in rows}
    gaps, pitches = [], []
    for index in sorted({index for rows in cluster for index, _ in rows}):
        rows = page_rows(doc[index])
        mine = [r for r in rows if row_id(index, r) in members]
        rest = [r for r in rows if row_id(index, r) not in members]
        if not mine or not rest:
            continue
        if edge == "top":
            gaps.append(min(r["y0"] for r in rest) - max(r["y1"] for r in mine))
        else:
            gaps.append(min(r["y0"] for r in mine) - max(r["y1"] for r in rest))
        tops = sorted(r["y0"] for r in rest)
        steps = [b - a for a, b in zip(tops, tops[1:]) if 0 < b - a < 100]
        if steps:
            pitches.append(median(steps))
    if not gaps:
        return 0.0, None, 0
    return median(gaps), (median(pitches) if pitches else None), len(gaps)


def is_outermost(doc, cluster, edge):
    """Nothing else may be printed outside the band on a page that carries it."""
    members = {row_id(index, row) for rows in cluster for index, row in rows}
    for index in sorted({index for rows in cluster for index, _ in rows}):
        rows = page_rows(doc[index])
        mine = [r for r in rows if row_id(index, r) in members]
        rest = [r for r in rows if row_id(index, r) not in members]
        if not mine:
            continue
        if edge == "top" and any(r["y0"] < min(m["y0"] for m in mine) - 1.0 for r in rest):
            return False
        if edge == "bottom" and any(r["y1"] > max(m["y1"] for m in mine) + 1.0 for r in rest):
            return False
    return True


def covers_a_stranger(doc, pages, members, top, bottom):
    """Would erasing this rectangle take a row that is not part of the band?"""
    for index in pages:
        for row in page_rows(doc[index]):
            if row_id(index, row) in members:
                continue
            if row["y0"] >= top - BAND_PAD_PT and row["y1"] <= bottom + BAND_PAD_PT:
                return True
    return False


def detect_band(doc, edge):
    """The repeating header or footer of this document.

    Returns `(band, reason)`: a band and None, or None and a sentence saying
    why this edge was left in the body, or None and None when there was simply
    nothing repeating there.

    Rows in the edge zone are grouped by their normalized text and their
    rounded top edge, and a group has to survive four tests before it can be
    lifted out of the document. Each one exists because it caught real content
    being deleted:

    1. Quorum (`band_quorum`), so two rows of a long table cannot be a band.
    2. Stable digits (`describe_columns`), so a column whose number changes
       from page to page and is not the page number is body content.
    3. Separation (`BAND_SEPARATION_RATIO`), so a repeated first body line
       sitting one line under the header stays in the body.
    4. Outermost, so a band candidate with something printed beyond it is not
       a band at all.
    """
    per_page = {}
    populated = []
    for index in range(doc.page_count):
        page = doc[index]
        rows = [r for r in page_rows(page) if in_zone(page, edge, r["y0"], r["y1"])]
        per_page[index] = rows
        if rows:
            populated.append(index)
    if len(populated) < 2:
        return None, None

    groups = {}
    for index in populated:
        seen = set()
        for row in per_page[index]:
            key = (normalize(row["text"]), round(row["y0"] / BAND_Y_TOLERANCE_PT))
            if key in seen:  # one page cannot vote twice for the same row
                continue
            seen.add(key)
            groups.setdefault(key, []).append((index, row))

    quorum = band_quorum(len(populated))
    alternation = alternating_at_edge(list(groups.values()), edge, quorum)
    if alternation:
        return None, alternation

    name = "header" if edge == "top" else "footer"
    keep = []
    rejected = None
    for rows in groups.values():
        if len(rows) < quorum:
            continue
        if len(populated) <= 3:
            # With so few pages the quorum allows one exception, and it has to
            # be a cover-like first page rather than any page that happens to
            # lack the row.
            absent = [i for i in populated if i not in {index for index, _ in rows}]
            if absent and absent != [populated[0]]:
                continue
        if describe_columns(rows) is None:  # test 2, reported by the describer
            rejected = ("the %s's number changes from page to page and is not a page number" % name)
            continue
        keep.append(rows)

    cluster = edge_cluster(keep, edge)
    # Test 3. The cluster is grown from the page edge inwards, so when it does
    # not clear the body the innermost group is the one that does not belong:
    # drop it and measure again, which is how a genuine header survives having
    # a repeated first body line stuck to it.
    while cluster:
        gap, pitch, measured = separation(doc, cluster, edge)
        if measured <= BAND_SEPARATION_MIN_PAGES:
            # Nothing to measure against on almost every page. That used to
            # count as a pass, and then a document whose only body line is the
            # candidate had that line lifted into the header with the text
            # check reporting "0 lines, 0 missing" as success.
            rejected = ("the %s could not be told apart from the body on enough pages" % name)
            cluster = []
            break
        if gap > 0 and (pitch is None or gap >= BAND_SEPARATION_RATIO * pitch):
            break
        rejected = ("the %s sits too close to the first line of the page to lift safely" % name
                    if edge == "top"
                    else "the footer sits too close to the last line of the page to lift safely")
        cluster = cluster[:-1]
    if not cluster:
        return None, rejected
    if not is_outermost(doc, cluster, edge):  # test 4
        return None, ("something else is printed outside the repeating %s on some pages" % name)

    repeating = cluster
    pages = sorted({index for rows in repeating for index, _ in rows})
    text_top = min(row["y0"] for rows in repeating for _, row in rows)
    text_bottom = max(row["y1"] for rows in repeating for _, row in rows)
    top, bottom = text_top, text_bottom

    # A rule under a header or a strip behind a footer is part of the band,
    # and swallowing it grows the rectangle that gets erased. That rectangle
    # is the whole page width, so growing it past the band's own text can take
    # body content with it: a per-page finding title at y 60 to 72 under a
    # header, with a repeating full-width rule at y 72.4, had all eight titles
    # erased. So the enlargement is offered and then checked, and a rectangle
    # that would cover a row which is not a band member is not taken.
    members = {row_id(index, row) for rows in repeating for index, row in rows}
    wanted_top, wanted_bottom, rule_under, strip_behind, strip_full_width, strip_span, strip_y = band_decorations(
        doc, repeating_drawings(doc, pages, edge), pages, edge, text_top, text_bottom)
    if covers_a_stranger(doc, pages, members, wanted_top, wanted_bottom):
        # The decoration stays in the body. That is a cosmetic price (the rule
        # under the header is drawn twice, once by Word and once by the page
        # it was left on) against deleting a finding.
        rule_under = None
        strip_behind = None
        strip_full_width = False
        strip_span = None
        strip_y = None
    else:
        top, bottom = wanted_top, wanted_bottom

    columns = []
    for rows in sorted(repeating, key=lambda rows: rows[0][1]["x0"]):
        columns.extend(describe_columns(rows))
    return {
        "edge": edge,
        "pages": pages,
        "top": top,
        "bottom": bottom,
        "text_top": text_top,
        "text_bottom": text_bottom,
        "columns": columns,
        "rule_under": rule_under,
        "strip_behind": strip_behind,
        "strip_full_width": strip_full_width,
        "strip_span": strip_span,
        "strip_y": strip_y,
        # The rows this band is made of, so the text check can leave out
        # exactly those and nothing else.
        "members": members,
        "source": "heuristic",
    }, None


def band_decorations(doc, drawings, pages, edge, text_top, text_bottom):
    """The rule under a band and the strip behind it, from its repeating drawings.

    Returns `(top, bottom, rule_under, strip_behind, strip_full_width,
    strip_span, strip_y)`: the band's extent grown to take in every drawing within
    `BAND_GLUE_PT` of it, and what Word should draw for them.
    """
    wanted_top, wanted_bottom = text_top, text_bottom
    rule_under = None
    strip_behind = None
    strip_full_width = False
    strip_span = None
    strip_y = None
    widest_strip = 0.0
    for drawing in drawings:
        rect = drawing["rect"]
        if rect.y0 > wanted_bottom + BAND_GLUE_PT or rect.y1 < wanted_top - BAND_GLUE_PT:
            continue
        wanted_top = min(wanted_top, rect.y0)
        wanted_bottom = max(wanted_bottom, rect.y1)
        if drawing.get("fill") is not None and rect.height > 1.0 and rect.width >= widest_strip:
            # The widest fill is the strip. A progress bar draws a second fill
            # over its track, the width of the page's share of the document, and
            # on a paper size with a single page (a sideways page) both count as
            # repeating: the last one won and b2's page 42 was shaded in the
            # bar's teal over 87% of its width instead of the track's grey.
            widest_strip = rect.width
            strip_behind = tuple(drawing["fill"])
            strip_full_width = rect.width >= doc[pages[0]].rect.width - 2.0
            strip_span = (rect.x0, rect.x1)
            strip_y = (rect.y0, rect.y1)
        elif edge == "top" and rect.y0 >= text_bottom - 1.0:
            # Where the rule starts and stops, and how heavy it is, so Word
            # draws the same line rather than one that runs to the margin.
            rule_under = {
                "x0": rect.x0,
                "x1": rect.x1,
                "width": max(rect.height, drawing.get("width") or 0.0),
                "color": drawing.get("color") if drawing.get("color") is not None else drawing.get("fill"),
            }
    return wanted_top, wanted_bottom, rule_under, strip_behind, strip_full_width, strip_span, strip_y


def drawing_key(drawing):
    rect = drawing["rect"]
    return (drawing.get("type"), round(rect.x0, 1), round(rect.y0, 1), round(rect.x1, 1), round(rect.y1, 1))


def tagged_members(rows_before, rows_after):
    """The rows of one page that are gone once its Header and Footer artifacts are.

    Removing an artifact block does not move the text around it, so every row
    of the stripped page is matched, one for one, to a row of the original
    with the same text in the same place (top within `BAND_Y_TOLERANCE_PT`,
    left edge within `TAGGED_X_TOLERANCE_PT`). The rows of the original left
    unmatched are the ones the artifacts drew. Matching on place as well as
    text is what keeps a body line that reads like the band in the body, at
    whichever edge it sits.

    None when a row of the stripped page matches nothing in the original:
    removing the artifacts changed some other row, so the two readings
    cannot be compared row for row.

    The original's rows are bucketed by text, so a stripped row is compared
    only with the rows that read the same, not with the whole page.
    """
    by_text = {}
    for order, candidate in enumerate(rows_before):
        by_text.setdefault(candidate["text"], []).append(order)
    matched = set()
    for row in rows_after:
        bucket = by_text.get(row["text"], [])
        match = next((slot for slot, order in enumerate(bucket)
                      if abs(rows_before[order]["y0"] - row["y0"]) <= BAND_Y_TOLERANCE_PT
                      and abs(rows_before[order]["x0"] - row["x0"]) <= TAGGED_X_TOLERANCE_PT), None)
        if match is None:
            return None
        matched.add(bucket.pop(match))
    return [candidate for order, candidate in enumerate(rows_before) if order not in matched]


def has_stray_group(groups):
    """A row that fills a place on only some of the pages that carry a band of its size.

    `groups` maps `(page size, text, y, third)` to the `(page, row)` pairs that read
    that way. A header that changes from page to page (the chapter's title,
    odd and even pages) is several groups in one place on pages that never
    share one, and together they fill that place on every page of their size
    that has a band: that is one slot with several variants, and each
    section is given its own. A group in a place nothing else fills is
    something else marked as a header or footer, a note set at the top of one
    page's body, and Word would give it to a whole section as a header.

    Sizes are separate because a sideways page has its band somewhere else.
    """
    by_size = {}
    for key, rows in groups.items():
        by_size.setdefault(key[0], []).append(rows)
    for rows_of_size in by_size.values():
        spans = [(min(r["y0"] for _, r in rows), max(r["y1"] for _, r in rows), {index for index, _ in rows})
                 for rows in rows_of_size]
        everywhere = set().union(*(pages for _, _, pages in spans))
        parent = list(range(len(spans)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for i, (top, bottom, pages) in enumerate(spans):
            for j in range(i + 1, len(spans)):
                other_top, other_bottom, other_pages = spans[j]
                if top < other_bottom and other_top < bottom and not pages & other_pages:
                    parent[find(i)] = find(j)
        filled = {}
        for i, (_, _, pages) in enumerate(spans):
            filled.setdefault(find(i), set()).update(pages)
        if any(pages != everywhere for pages in filled.values()):
            return True
    return False


def page_size(page):
    """A page's size to a tenth of a point: what makes two pages the same paper."""
    return (round(page.rect.width, 1), round(page.rect.height, 1))


def detect_tagged_bands(doc, declined, marked=None):
    """The running header and footer typst marked as such, or None to use the heuristic.

    typst wraps its running header and footer in `/Artifact` marked content
    with `/Subtype /Header` and `/Subtype /Footer`. Removing those blocks from
    every page (`tagged.stripped_copy`) and reading each page's rows before
    and after says exactly which rows they drew: a band member is a row that
    is gone from the stripped page, and nothing else is. Returns `(bands,
    counts)`, the bands in the shape `detect_band` returns plus `"source":
    "tagged"`, and the blocks removed per page.

    None means "use the heuristic", and it comes back for an untagged PDF, a
    tagged one with no Header or Footer artifact, and every case where the
    tags cannot be trusted to name only the band (`bands-tagged-inconsistent`):
    a content stream that does not balance, a stripped page whose rows are
    not a subset of the original's, or a removed row sitting between two body
    rows, where a running band cannot be. A band whose text changes in place
    from page to page (the chapter's title, odd and even pages) comes back as
    one band per text, each with the pages it is on, and Word is given them
    one section at a time (`apply_bands`). A digit that changes and is not
    the page number is not a band (`bands-tagged-varies`).
    A band the tags do not describe as running is left to the heuristic too
    (`bands-tagged-partial`): a row in a place the rest of the pages of its
    paper size leave empty, or a band on one page of a longer document.
    An exception anywhere in reading the tags is `bands-tagged-inconsistent`
    as well: a tagged PDF that converted before the tags were read must
    still convert.

    `marked` is `tagged.is_tagged(doc)` when the caller has read it already.
    `bands-tagged` is not counted here: the caller counts it once the bands
    have survived every later check.
    """
    try:
        if marked is None:
            marked = tagged.is_tagged(doc)
        if not marked:
            return None
        made = tagged.stripped_copy(doc)
    except Exception:  # noqa: BLE001 - a PDF the tags cannot be read from goes to the heuristic
        made = None
    if made is None:
        declined["bands-tagged-inconsistent"] += 1
        return None
    copy, counts = made
    try:
        bands = read_tagged_bands(doc, copy, counts, declined)
    except Exception:  # noqa: BLE001 - a tagged PDF that exported before must still export
        declined["bands-tagged-inconsistent"] += 1
        return None
    finally:
        copy.close()
    if not bands:
        return None
    lifted = band_subtypes(bands)
    if lifted != TAGGED_SUBTYPES:
        # An edge was declined, so its artifacts stay in the page. The counts
        # the caller compares its second copy with are those of the copy that
        # removes only what is lifted.
        try:
            only = tagged.stripped_copy(doc, lifted)
        except Exception:  # noqa: BLE001 - a PDF the tags cannot be cut again goes to the heuristic
            only = None
        if only is None:
            declined["bands-tagged-inconsistent"] += 1
            return None
        only[0].close()
        counts = only[1]
    return bands, counts


TAGGED_SUBTYPES = ("Header", "Footer")


def band_subtypes(bands):
    """The artifact subtypes the bands lift: Header for a top band, Footer for a bottom one."""
    return tuple(name for name, edge in zip(TAGGED_SUBTYPES, ("top", "bottom"))
                 if any(band["edge"] == edge for band in bands))


def read_tagged_bands(doc, copy, counts, declined):
    """The work of `detect_tagged_bands` on its stripped copy: the bands, or None.

    Any exception is the caller's to turn into a decline, so nothing here
    catches one.
    """
    if not any(counts.values()):
        return None
    edges = {"top": [], "bottom": []}
    # The drawings each stripped page still has, so a band's decoration
    # is taken only from what the artifacts drew.
    kept_drawings = {}
    for index in range(doc.page_count):
        if not counts.get(index):
            continue
        kept_drawings[index] = {drawing_key(d) for d in copy[index].get_drawings()}
        rows = page_rows(doc[index])
        height = doc[index].rect.height
        members = tagged_members(rows, page_rows(copy[index]))
        if members is None:
            declined["bands-tagged-inconsistent"] += 1
            return None
        chosen = {id(row) for row in members}
        body = [row for row in rows if id(row) not in chosen]
        if body:
            first = min(row["y0"] for row in body)
            last = max(row["y1"] for row in body)
        for row in members:
            if body:
                above, below = row["y1"] <= first, row["y0"] >= last
            else:
                # A page with nothing but its band: the band is whichever
                # half of the page it sits in.
                above = row["y1"] <= height / 2
                below = not above and row["y0"] >= height / 2
            if above:
                edges["top"].append((index, row))
            elif below:
                edges["bottom"].append((index, row))
            else:
                declined["bands-tagged-inconsistent"] += 1
                return None

    bands = []
    sizes = {index: page_size(doc[index]) for index in range(doc.page_count)}
    # The text area of each paper size, read once: the thirds the groups are
    # keyed by and each band's own content bounds are both measured on it.
    areas = {size: content_bounds(doc, [index for index in range(doc.page_count) if sizes[index] == size])
             for size in set(sizes.values())}
    for edge in ("top", "bottom"):
        members = edges[edge]
        if not members:
            continue
        pages = sorted({index for index, _ in members})
        # A band on one page of a longer document is not a running one. An edge
        # that is only that is declined by itself: a chapter title that is on
        # one page's header declined the page-number footer beside it too, and
        # the heuristic that took over left the title in the body. (An edge
        # with a running band AND a stray row, below, still sends the whole
        # document to the heuristic, which can read the running band alone.)
        if len(pages) == 1 and doc.page_count > 1:
            declined["bands-tagged-partial"] += 1
            continue
        groups = {}
        for index, row in members:
            # The third of the text area the row sits in is part of the key: a
            # number on the right of odd pages and on the left of even ones
            # read as one group, and every Word footer put it on the right.
            # Digits are blanked in the text, so only a row that moved is
            # split from its twin; `has_stray_group` joins the pieces that are
            # in one place on pages that never share one.
            key = (sizes[index], normalize(row["text"]), round(row["y0"] / BAND_Y_TOLERANCE_PT),
                   band_third(row, areas[sizes[index]]))
            groups.setdefault(key, []).append((index, row))
        # A running band fills its place on every page of its size that has
        # one. The text in that place may change from page to page (the
        # chapter's title, odd and even pages): each such text is a variant,
        # given to the sections of its own pages below. A row that fills a
        # place nothing else does is something else marked as a header or
        # footer, and Word would give it to a whole section.
        if has_stray_group(groups):
            declined["bands-tagged-partial"] += 1
            return None
        described = describe_groups(groups)
        if described is None:
            declined["bands-tagged-varies"] += 1
            return None
        # The pages that show exactly the same rows, in the same place on the
        # same paper, share one band; a page that differs gets its own.
        shown = {}
        for key, rows in groups.items():
            for index, row in rows:
                shown.setdefault(index, []).append((row["y0"], row["x0"], key))
        variants = {}
        for index in pages:
            variants.setdefault(tuple(key for _, _, key in sorted(shown[index])), []).append(index)
        # The rule under the header and the strip behind the footer, read the
        # way `detect_band` reads them but only from drawings the artifacts
        # held: one still on a stripped band page is body content. Nothing is
        # erased by rectangle here, so there is no stranger to cover. Read per
        # paper size, since a sideways page draws them somewhere else, and a
        # size with one page vouches for its own drawings.
        drawn_by_size = {}
        for size in {sizes[index] for index in pages}:
            of_size = [index for index in pages if sizes[index] == size]
            drawn_by_size[size] = [d for d in repeating_drawings(doc, of_size, edge, minimum=min(2, len(of_size)))
                                   if not any(drawing_key(d) in kept_drawings[index] for index in of_size)]
        for keys, variant_pages in sorted(variants.items(), key=lambda item: item[1][0]):
            size = sizes[variant_pages[0]]
            mine = [(index, row) for index, row in members if sizes[index] == size and index in set(variant_pages)]
            columns = []
            for key in sorted(keys, key=lambda key: groups[key][0][1]["x0"]):
                columns.extend(described[key])
            text_top = min(row["y0"] for _, row in mine)
            text_bottom = max(row["y1"] for _, row in mine)
            _, _, rule_under, strip_behind, strip_full_width, strip_span, strip_y = band_decorations(
                doc, drawn_by_size[size], variant_pages, edge, text_top, text_bottom)
            left, right = areas[size]
            bands.append({
                "edge": edge,
                "pages": variant_pages,
                "top": text_top - BAND_PAD_PT,
                "bottom": text_bottom + BAND_PAD_PT,
                "text_top": text_top,
                "text_bottom": text_bottom,
                "columns": columns,
                "rule_under": rule_under,
                "strip_behind": strip_behind,
                "strip_full_width": strip_full_width,
                "strip_span": strip_span,
                "strip_y": strip_y,
                "members": {row_id(index, row) for index, row in mine},
                "source": "tagged",
                # The paper this band was read on, and where that paper's text
                # area sits: a sideways page is not the portrait page's size.
                "page_size": size,
                "content": (left, right),
            })
    if not bands:
        return None  # the artifacts drew no text, so there is no band to lift
    return bands


def band_third(row, area):
    """Which third of the text area (0 left, 1 middle, 2 right) a row's middle is in."""
    left, right = area
    middle = (row["x0"] + row["x1"]) / 2.0
    return min(2, max(0, int(3.0 * (middle - left) / max(right - left, 1.0))))


def describe_groups(groups):
    """The columns of every group `(size, text, y, third)` of one edge, or None.

    Digits are blanked in the text, so a group holds the same row on every
    page it is on and `describe_columns` can tell the page number from any
    other number. A group seen on one page only cannot say that for itself;
    it takes the offset the same text showed on other pages, and with none
    its digits are written as they are printed.
    """
    described = {}
    alone = []
    for key, rows in groups.items():
        if len({index for index, _ in rows}) < 2:
            alone.append(key)
            continue
        columns = describe_columns(rows)
        if columns is None:
            return None
        described[key] = columns
    for key in alone:
        offsets = {column["page_offset"] for other, columns in described.items() if other[1] == key[1]
                   for column in columns if column["page_offset"] is not None}
        columns = describe_columns(groups[key], offsets.pop() if len(offsets) == 1 else None)
        if columns is None:
            return None
        described[key] = columns
    return described


def edge_cluster(groups, edge):
    """Keep only the repeating rows that sit together at the page edge.

    A running band is the outermost thing on its page. Body content can repeat
    too, and on a report where every page opens with a heading of the same
    shape it repeats inside the edge zone, so proximity to the edge is what
    separates the two.
    """
    if not groups:
        return []
    bounds = {id(rows): (min(r["y0"] for _, r in rows), max(r["y1"] for _, r in rows)) for rows in groups}
    ordered = sorted(groups, key=lambda rows: bounds[id(rows)][0 if edge == "top" else 1], reverse=edge != "top")
    kept = [ordered[0]]
    top, bottom = bounds[id(ordered[0])]
    for rows in ordered[1:]:
        low, high = bounds[id(rows)]
        glue = BAND_LINE_GLUE * max(bottom - top, high - low, 1.0)
        if low <= bottom + glue and high >= top - glue:
            kept.append(rows)
            top, bottom = min(top, low), max(bottom, high)
    return kept


def repeating_drawings(doc, pages, edge, minimum=2):
    """Vector drawings that appear, identically placed, on most band pages.

    `minimum` is how many pages must show one. The tagged path lowers it to
    the page count of a size that has a single page: its drawings are known to
    be the artifacts' own, so repeating is not what vouches for them.
    """
    groups = {}
    for index in pages:
        page = doc[index]
        seen = set()
        for drawing in page.get_drawings():
            rect = drawing["rect"]
            if not in_zone(page, edge, rect.y0, rect.y1):
                continue
            key = (drawing.get("type"), round(rect.x0, 1), round(rect.y0, 1), round(rect.x1, 1), round(rect.y1, 1))
            if key in seen:
                continue
            seen.add(key)
            groups.setdefault(key, []).append(drawing)
    need = max(minimum, int(round(len(pages) * BAND_REPEAT_FRACTION)))
    return [drawings[0] for drawings in groups.values() if len(drawings) >= need]


def describe_columns(rows, hint=None):
    """Turn one repeating row into columns Word can lay out, or None.

    Every occurrence has the same shape once digits are blanked out, so the
    digit runs line up slot by slot across pages. A slot whose value rises by
    one per page is the page number, and the difference between the printed
    number and the page index is kept so Word can start counting there.

    None means this is not a band. It comes back when a column holds a number
    that changes from page to page and is not the page number: `Host-073 |
    10.0.0.73 | Open port finding number 73` normalizes to the same text as
    every other row of that table, and deleting it as a running footer removes
    a real finding from the report. Digit blanking is what makes a page number
    stop mattering, so anything else it blanks has to be accounted for.

    `hint` is the page offset the same text showed on other pages, for a row
    seen on one page only: a single printed number cannot say whether it is
    the page number, but it can agree with an offset the other pages found.
    """
    counts = {len(row["columns"]) for _, row in rows}
    if len(counts) != 1:
        # Shapes disagree; the safe reading is one column spanning the row.
        merged = [
            (
                index,
                {
                    "x0": row["x0"],
                    "x1": row["x1"],
                    "text": row["text"],
                    "font": row["columns"][0]["font"],
                    "psname": row["columns"][0]["psname"],
                    "size": row["columns"][0]["size"],
                    "bold": row["columns"][0]["bold"],
                    "color": row["columns"][0]["color"],
                    "base": row["base"],
                },
            )
            for index, row in rows
        ]
        one = describe_one_column(merged, hint)
        return None if one is None else [one]
    width = counts.pop()
    described = [describe_one_column([(index, row["columns"][i]) for index, row in rows], hint) for i in range(width)]
    return None if any(column is None for column in described) else described


def describe_one_column(cells, hint=None):
    """One column of a band, or None when its numbers say it is not one."""
    first = cells[0][1]
    numbers = [list(DIGITS.finditer(cell["text"])) for _, cell in cells]
    if len({len(n) for n in numbers}) != 1:
        return None  # a different count of numbers per page is not one band row
    slots = len(numbers[0])
    page_slot = None
    page_offset = None
    for slot in range(slots):
        offsets = {int(m[slot].group()) - index for (index, _), m in zip(cells, numbers)}
        if len(offsets) == 1 and (len(cells) > 1 or hint in offsets):
            page_slot, page_offset = slot, offsets.pop()
            break
    for slot in range(slots):
        if slot == page_slot:
            continue
        if len({m[slot].group() for m in numbers}) != 1:
            return None  # a number that changes and is not the page number

    parts = []
    if page_slot is None:
        parts.append({"kind": "text", "text": first["text"]})
    else:
        match = numbers[0][page_slot]
        parts.append({"kind": "text", "text": first["text"][: match.start()]})
        parts.append({"kind": "page"})
        parts.append({"kind": "text", "text": first["text"][match.end() :]})
    return {
        "x0": min(cell["x0"] for _, cell in cells),
        "x1": max(cell["x1"] for _, cell in cells),
        "parts": [p for p in parts if p["kind"] != "text" or p["text"]],
        "font": first["font"],
        "psname": first.get("psname"),
        "size": first["size"],
        "bold": first["bold"],
        "color": first["color"],
        "page_offset": page_offset,
        # Where the glyphs sit, which Word needs when the band's line is taller
        # than its text (`raise_band_text`).
        "base": median(sorted(cell["base"] for _, cell in cells if cell.get("base") is not None))
        if any(cell.get("base") is not None for _, cell in cells) else None,
    }


def uniform_page_size(doc):
    """The page size every page shares, or None when they differ.

    The band geometry is one set of numbers for the whole document (a footer
    distance measured from the first page's height, a text area from the
    median of every page's own edges), which is wrong the moment a report
    turns a page sideways for a wide table. Rather than carry per-section
    geometry for a case no report here has, a mixed document keeps its bands
    in the body and is told so.
    """
    sizes = {(round(doc[i].rect.width, 1), round(doc[i].rect.height, 1)) for i in range(doc.page_count)}
    return sizes.pop() if len(sizes) == 1 else None


def drop_unsafe_pdf_links(doc):
    """Remove link annotations whose address Word would hand to the shell.

    pdf2docx copies a PDF link annotation into the Word file as an external
    relationship, and Word follows it. `FILE://host/share/x` resolves as UNC
    and leaks the reader's credentials to whoever owns that host; `smb://`,
    `javascript:` and `ms-msdt:` are the same class of problem. A report is
    attacker-influenced text, so the set of schemes that reach a client's
    machine is decided here and not by what the report asked for.

    Internal jumps (a table-of-contents link to another page) are not URI
    annotations and are left alone. A Launch action goes whatever it names:
    typst turns `#link("\\\\\\\\host\\\\share\\\\x")` into one of those rather
    than a URI, and a report has no business asking a reader's machine to open
    a file.
    """
    removed = 0
    for index in range(doc.page_count):
        page = doc[index]
        doomed = []
        for link in page.get_links():
            kind = link.get("kind")
            if kind == pymupdf.LINK_LAUNCH:
                doomed.append(link)
                continue
            if kind != pymupdf.LINK_URI:
                continue
            match = LINK_SCHEME.match(str(link.get("uri") or ""))
            if (match.group(1).lower() if match else "") not in SAFE_LINK_SCHEMES:
                doomed.append(link)
        for link in doomed:
            page.delete_link(link)
            removed += 1
    return removed


def unsafe_docx_targets(path):
    """External relationship targets in the Word file that should not be there.

    The belt to the braces above: the annotations were removed from the PDF
    before the converter saw it, so this should always come back empty. If it
    ever does not, something put an address into a client-facing file that
    this script did not vet, and the conversion fails rather than shipping it.
    """
    bad = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".rels"):
                continue
            for rel in ElementTree.fromstring(archive.read(name)):
                if rel.get("TargetMode") != "External":
                    continue
                target = rel.get("Target") or ""
                match = LINK_SCHEME.match(target)
                if (match.group(1).lower() if match else "") not in SAFE_LINK_SCHEMES:
                    bad.append(target)
    return bad


def refuse_oversized(doc):
    """Stop a report the converter would spend minutes and gigabytes on.

    pdf2docx walks every vector drawing on a page and builds Python objects
    for the ones it keeps, so cost follows the drawing count rather than the
    file size, and neither the output cap nor the image pixel budget sees it.
    Measured on this machine, three A4 pages of 120,000 one-point rectangles:
    typst wrote them in 2.5 s into 2.1 MB, and the converter took 35.9 s and
    651 MB; at 150 pages it ran past the two-minute timeout. Counting them
    first costs a few milliseconds (see MAX_PAGE_DRAWINGS).
    """
    if doc.page_count > MAX_PAGES:
        raise ConvertError(
            "this report is %d pages, more than the %d the Word converter will take. Export the PDF instead."
            % (doc.page_count, MAX_PAGES)
        )
    total = 0
    for index in range(doc.page_count):
        page = doc[index]
        # The page's own instruction stream first, because reading its length
        # costs nothing: 0.08 s for the whole 120,000-shape document against
        # 2.0 s to count its drawings, and 0.002 s on the reference report.
        if len(page.read_contents()) > MAX_PAGE_CONTENT_BYTES:
            raise ConvertError(
                "page %d of this report is too complex for the Word converter. Export the PDF instead."
                % (index + 1)
            )
        # Then the count itself. get_cdrawings returns plain values rather
        # than Point and Rect objects, which is what makes it cheap enough to
        # run on every page: 0.028 s across the 23-page reference report.
        count = len(page.get_cdrawings())
        if count > MAX_PAGE_DRAWINGS:
            raise ConvertError(
                "page %d of this report draws %d shapes, more than the %d the Word converter will take. "
                "Export the PDF instead." % (index + 1, count, MAX_PAGE_DRAWINGS)
            )
        total += count
        # And the whole document, because the per-page bound misses the shape
        # that actually costs: 60 pages of 9,000 drawings clears every page
        # test and still takes the converter most of a minute. The loop stops
        # at the first page that puts the total over, so a long dense document
        # is refused without counting the rest of it.
        if total > MAX_DOCUMENT_DRAWINGS:
            raise ConvertError(
                "this report draws more than %d shapes, more than the Word converter will take. "
                "Export the PDF instead." % MAX_DOCUMENT_DRAWINGS
            )


def strip_bands(doc, bands):
    """Erase the band rectangles, in place, on the pages that carry them.

    A redaction annotation with no fill removes the text and the line art it
    covers and leaves everything else alone. Images are excluded outright: a
    figure that reaches into the zone is body content, not a band.
    """
    for band in bands:
        for index in band["pages"]:
            page = doc[index]
            page.add_redact_annot(
                pymupdf.Rect(page.rect.x0, band["top"] - BAND_PAD_PT, page.rect.x1, band["bottom"] + BAND_PAD_PT),
                cross_out=False,
            )
    for index in sorted({i for band in bands for i in band["pages"]}):
        doc[index].apply_redactions(
            images=pymupdf.PDF_REDACT_IMAGE_NONE,
            graphics=pymupdf.PDF_REDACT_LINE_ART_REMOVE_IF_COVERED,
            text=pymupdf.PDF_REDACT_TEXT_REMOVE,
        )


# ── step 2: read the table of contents out of the PDF ─────────────────────


def content_bounds(doc, pages=None):
    """The left and right edges of the page's text area, in PDF points.

    The median of each page's own extremes, so one full-bleed cover or one
    figure that runs into the margin does not move the reference the bands and
    the table of contents are positioned against. `pages` limits it to the
    pages of one size, which a band on a sideways page is positioned against.
    """
    lefts, rights = [], []
    for index in (range(doc.page_count) if pages is None else pages):
        rows = page_rows(doc[index])
        if not rows:
            continue
        lefts.append(min(row["x0"] for row in rows))
        rights.append(max(row["x1"] for row in rows))
    if not lefts:
        return 0.0, doc[0 if pages is None else pages[0]].rect.width
    return median(lefts), median(rights)


def leader_spacing(page):
    """How much wider than its own advance each leader glyph is set, by row.

    Word repeats a leader glyph at the font's advance for it and nothing else,
    which on the reference report puts its dots 3.1 pt apart where typst put
    them at 4.8: the list reads as a rule rather than a leader. The difference
    is measured here, per row, from the PDF's own glyph positions, and added
    to the tab run as character spacing. A leader the typesetter set solid
    measures zero and nothing is added.
    """
    out = {}
    for block in page.get_text("rawdict")["blocks"]:
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            chars = [c for span in line.get("spans", []) for c in span.get("chars", [])]
            pitches, advances = [], []
            for index, char in enumerate(chars[:-1]):
                if char["c"] != ".":
                    continue
                advances.append(chars[index + 1]["origin"][0] - char["origin"][0])
                following = next((c for c in chars[index + 1:] if c["c"] == "."), None)
                if following is not None:
                    pitches.append(following["origin"][0] - char["origin"][0])
            if len(pitches) >= LEADER_MIN_DOTS:
                # Medians, because the run starts at the full stop of a section
                # number and that one pitch is the width of the title.
                out[round(line["bbox"][1], 1)] = max(0.0, median(sorted(pitches)) - median(sorted(advances)))
    return out


def spacing_for_row(extras, row):
    """The leader spacing measured for this row, or zero."""
    for top, extra in extras.items():
        if abs(top - row["y0"]) <= BAND_Y_TOLERANCE_PT:
            return extra
    return 0.0


def detect_toc(doc, bands):
    """Rows that read "title, dot leader, page number", in reading order."""
    entries = []
    for index in range(doc.page_count):
        # A tagged band is a band on its own pages only: a sideways page's
        # footer sits where a portrait page has body text.
        spans = [(b["top"] - BAND_PAD_PT, b["bottom"] + BAND_PAD_PT) for b in bands
                 if b.get("source") != "tagged" or index in b["pages"]]
        rows = [
            r
            for r in page_rows(doc[index])
            if not any(r["y0"] >= top and r["y1"] <= bottom for top, bottom in spans)
        ]
        extras = None
        previous = None
        for row in rows:
            match = TOC_LINE.match(row["text"].strip())
            segments = title_segments(row) if match else None
            if not segments:
                previous = row
                continue
            if extras is None:
                extras = leader_spacing(doc[index])
            entries.append(
                {
                    "page_index": index,
                    "y0": row["y0"],
                    "x0": row["x0"],
                    # Distance from whatever sits above, which is how much air
                    # the first entry of a list needs under its heading.
                    "gap_before": (row["y0"] - previous["y1"]) if previous else 0.0,
                    "title": " ".join(s["text"] for s in segments),
                    "segments": segments,
                    "number": match.group("page"),
                    "font": segments[0]["font"],
                    "psname": segments[0].get("psname"),
                    "size": segments[0]["size"],
                    "bold": segments[0]["bold"],
                    "color": segments[0]["color"],
                    "leader_extra": spacing_for_row(extras, row),
                }
            )
            previous = row
    return entries


def title_segments(row):
    """The columns before the dot leader, with their offsets from the row's left."""
    segments = []
    for column in row["columns"]:
        text = column["text"]
        match = LEADER.search(text)
        if match:
            text = text[: match.start()]
        text = text.strip(" " + INVISIBLE)
        if text:
            segments.append(
                {
                    "offset": round(column["x0"] - row["x0"], 1),
                    "text": text,
                    "font": column["font"],
                    "psname": column.get("psname"),
                    "size": column["size"],
                    "bold": column["bold"],
                    "color": column["color"],
                }
            )
        if match:
            break
    return segments


def toc_line_pitch(entries):
    """Median distance between consecutive entries on one page."""
    gaps = [
        b["y0"] - a["y0"]
        for a, b in zip(entries, entries[1:])
        if a["page_index"] == b["page_index"] and b["y0"] > a["y0"]
    ]
    return median(gaps) if gaps else None


# ── step 3: write the bands back as Word headers and footers ──────────────


# WordprocessingML validates child order, and Word refuses to open a file
# that gets it wrong ("the file appears to be corrupted") rather than
# ignoring the element. python-docx orders the properties it knows about;
# these are the two sequences this script adds to itself.
PPR_ORDER = (
    "w:pStyle w:keepNext w:keepLines w:pageBreakBefore w:framePr w:widowControl w:numPr"
    " w:suppressLineNumbers w:pBdr w:shd w:tabs w:suppressAutoHyphens w:kinsoku w:wordWrap"
    " w:overflowPunct w:topLinePunct w:autoSpaceDE w:autoSpaceDN w:bidi w:adjustRightInd"
    " w:snapToGrid w:spacing w:ind w:contextualSpacing w:mirrorIndents w:suppressOverlap w:jc"
    " w:textDirection w:textAlignment w:textboxTightWrap w:outlineLvl w:divId w:cnfStyle"
    " w:rPr w:sectPr w:pPrChange"
).split()
SECTPR_ORDER = (
    "w:headerReference w:footerReference w:footnotePr w:endnotePr w:type w:pgSz w:pgMar"
    " w:paperSrc w:pgBorders w:lnNumType w:pgNumType w:cols w:formProt w:vAlign w:noEndnote"
    " w:titlePg w:textDirection w:bidi w:rtlGutter w:docGrid w:printerSettings w:sectPrChange"
).split()
RPR_ORDER = (
    "w:rStyle w:rFonts w:b w:bCs w:i w:iCs w:caps w:smallCaps w:strike w:dstrike w:outline"
    " w:shadow w:emboss w:imprint w:noProof w:snapToGrid w:vanish w:webHidden w:color"
    " w:spacing w:w w:kern w:position w:sz w:szCs w:highlight w:u w:effect w:bdr w:shd"
    " w:fitText w:vertAlign w:rtl w:cs w:em w:lang w:eastAsianLayout w:specVanish w:oMath"
).split()
# What makes a run something a reader sees. A run of none of these is a
# bookmark or a comment anchor and has no font to get wrong.
RUN_CONTENT = ("w:t", "w:tab", "w:br", "w:sym", "w:noBreakHyphen", "w:softHyphen",
               "w:fldChar", "w:instrText", "w:drawing", "w:pict", "w:object")


def insert_ordered(parent, node, order):
    """Put `node` where the schema's sequence says it belongs."""
    tags = [qn(name) for name in order]
    position = tags.index(node.tag)
    for child in parent:
        if child.tag in tags and tags.index(child.tag) > position:
            child.addprevious(node)
            return
    parent.append(node)


def set_page_numbering_start(section, start):
    """`w:pgNumType w:start`, so Word prints the numbers the PDF printed."""
    element = section._sectPr
    for existing in element.findall(qn("w:pgNumType")):
        element.remove(existing)
    node = OxmlElement("w:pgNumType")
    node.set(qn("w:start"), str(start))
    insert_ordered(element, node, SECTPR_ORDER)


# The longest run of non-digits allowed between a page number and the total
# that follows it ("Page 3 of 42", "3 / 42", "3 von 42", "Seite 3 | 42").
TOTAL_CONNECTOR_MAX = 8
TOTAL_SEPARATOR = re.compile(r"\s*[/|:\u00b7\u2013-]\s*")


def is_total_connector(connector):
    """Does this read as the "of" between a page number and the total, and as nothing else?

    A separator ("/", "|", "-"), or a short function word: up to three lower
    case letters ("of", "de", "von", "sur") or two capitals ("OF", "DE").
    Length alone let "| Team " (exactly TOTAL_CONNECTOR_MAX) through, so
    "Page 3 | Team 3" on a three-page report became `Page {PAGE} | Team
    {NUMPAGES}` with nothing to say so, and a footer's "Rev 2" on a short
    appendix is a three-letter word that is a label, not a connector: its
    capital is what tells it from "von". Static text that happens to equal the
    last page's number must stay text.
    """
    if TOTAL_SEPARATOR.fullmatch(connector):
        return True
    words = connector.split()
    if not 1 <= len(words) <= 2 or not all(word.isalpha() for word in words):
        return False
    if len(words) == 2:
        # "out of", "de la": two short function words, in lower case.
        return all(word.islower() and len(word) <= 3 for word in words)
    word = words[0]
    # "of", "von", "sur"; "OF", "DE"; a capital "Of" or "De". "Rev" and "Team" are labels.
    return ((word.islower() and len(word) <= 3) or (word.isupper() and len(word) <= 2)
            or (word.istitle() and len(word) <= 2))
LAST_PAGE_BOOKMARK = "_btct_last_page"


def printed_page_numbers(bands):
    """{PDF page index: the number the PDF printed there}, for pages whose band holds a page number."""
    printed = {}
    for band in bands:
        for column in band["columns"]:
            offset = column.get("page_offset")
            if offset is None:
                continue
            for page in band["pages"]:
                printed[page] = page + offset
    return printed


def page_number_starts(printed):
    """{PDF page index: start} for the pages where Word's count has to be restarted.

    Word numbers a document 1, 2, 3 from its first page and carries on. The PDF
    can print 1, 2, 1, 2 (a body that restarts after the front matter), so the
    count is walked page by page and a start is written on the first page
    whose printed number is not where the running count would put it. A start
    below 0 is not one Word offers, so it is left out here and
    `word_page_numbers` shows the page as one the file cannot give.
    """
    starts = {}
    shift = 1  # Word's number minus the page index; the first page is 1
    for page in sorted(printed):
        if printed[page] - page != shift and printed[page] >= 0:
            starts[page] = printed[page]
            shift = printed[page] - page
    return starts


def word_page_numbers(document, groups):
    """What Word prints on each PDF page given the starts in the section properties."""
    numbers = []
    current = 0
    for members in groups:
        node = document.sections[members[0]]._sectPr.find(qn("w:pgNumType"))
        start = node.get(qn("w:start")) if node is not None else None
        current = int(start) if start is not None else current + 1
        numbers.append(current)
    return numbers


def total_page_field(printed, page_count, starts):
    """The field that stands for the document's last printed number, or None.

    NUMPAGES counts the pages of the file, which is the last printed number
    only when numbering never restarts and begins at 1 on the first page.
    Otherwise a PAGEREF to a bookmark on the last page gives the number Word
    prints there, restarts included. The number is read off the last page that
    carries one and carried forward over the pages after it.
    """
    if not printed:
        return None
    seen = max(printed)
    last = printed[seen] + (page_count - 1 - seen)
    if not starts and last == page_count and printed[seen] == seen + 1:
        return {"instruction": " NUMPAGES ", "result": str(last), "last": last, "bookmark": False}
    return {"instruction": " PAGEREF %s " % LAST_PAGE_BOOKMARK, "result": str(last), "last": last, "bookmark": True}


def split_total_parts(parts, last):
    """A column's parts with the constant total after its page number made a field.

    `Page {PAGE} of 42` is read as text, page, text; when the number at the
    head of the text after the page equals the last page's printed number it
    is that total, and static digits there go wrong the moment the page count
    does. Returns (parts, whether one was changed).
    """
    out = []
    changed = False
    wanted = str(last)
    for position, part in enumerate(parts):
        previous = parts[position - 1] if position else None
        if part["kind"] == "text" and previous is not None and previous["kind"] == "page":
            match = re.match(r"(\D{1,%d})(\d+)(?!\d)" % TOTAL_CONNECTOR_MAX, part["text"])
            if match and match.group(2) == wanted and is_total_connector(match.group(1)):
                out.append({"kind": "text", "text": match.group(1)})
                out.append({"kind": "total"})
                rest = part["text"][match.end():]
                if rest:
                    out.append({"kind": "text", "text": rest})
                changed = True
                continue
        out.append(part)
    return out, changed


def add_last_page_bookmark(document, name=LAST_PAGE_BOOKMARK):
    """A hidden bookmark at the end of the body, for a PAGEREF to name the last page."""
    body = document.element.body
    if any(node.get(qn("w:name")) == name for node in body.iter(qn("w:bookmarkStart"))):
        return
    last = None
    for element in body.iter(qn("w:p")):
        if not any(ancestor.tag == qn("w:txbxContent") for ancestor in element.iterancestors()):
            last = element
    if last is None:
        return
    taken = [int(node.get(qn("w:id"))) for node in body.iter(qn("w:bookmarkStart"))
             if (node.get(qn("w:id")) or "").isdigit()]
    ident = str(max(taken, default=0) + 1)
    start = OxmlElement("w:bookmarkStart")
    start.set(qn("w:id"), ident)
    start.set(qn("w:name"), name)
    end = OxmlElement("w:bookmarkEnd")
    end.set(qn("w:id"), ident)
    last.append(start)
    last.append(end)


def add_total_field(paragraph, instruction, result):
    """A field with its last result kept, so the number shows even where Word does not refresh it."""
    runs = []
    for kind, text in (("begin", None), ("code", instruction), ("separate", None), ("result", result), ("end", None)):
        run = OxmlElement("w:r")
        if kind == "code":
            node = OxmlElement("w:instrText")
            node.set(qn("xml:space"), "preserve")
            node.text = text
            run.append(node)
        elif kind == "result":
            node = OxmlElement("w:t")
            node.text = text
            run.append(node)
        else:
            node = OxmlElement("w:fldChar")
            node.set(qn("w:fldCharType"), kind)
            run.append(node)
        paragraph._p.append(run)
        runs.append(run)
    return runs


def add_page_field(paragraph):
    """A real PAGE field, so Word numbers the pages itself. Returns its runs."""
    runs = []
    for kind, text in (("begin", None), (None, " PAGE "), ("end", None)):
        run = OxmlElement("w:r")
        if kind:
            char = OxmlElement("w:fldChar")
            char.set(qn("w:fldCharType"), kind)
            run.append(char)
        else:
            instruction = OxmlElement("w:instrText")
            instruction.set(qn("xml:space"), "preserve")
            instruction.text = text
            run.append(instruction)
        paragraph._p.append(run)
        runs.append(run)
    return runs


def style_run(run, look):
    if look["font"]:
        run.font.name = look["font"]  # sets w:ascii and w:hAnsi
        table = run._element.get_or_add_rPr().get_or_add_rFonts()
        for attribute in ("w:cs", "w:eastAsia"):
            table.set(qn(attribute), look["font"])
    run.font.size = Pt(round(look["size"], 1))
    run.font.bold = look["bold"]
    # Only when a font file said which face this is. Read off the PDF alone
    # there is no italic flag to trust, and writing one either way would
    # decide something this does not know.
    if look.get("italic") is not None:
        run.font.italic = look["italic"]
    run.font.color.rgb = rgb_of(look["color"])


def style_field(paragraph, elements, look):
    """Give a field's runs the same look, which python-docx cannot reach."""
    template = paragraph.add_run("")
    style_run(template, look)
    rpr = template._element.find(qn("w:rPr"))
    for element in elements:
        if rpr is not None:
            element.insert(0, copy.deepcopy(rpr))
    paragraph._p.remove(template._element)


def shade_paragraph(paragraph, fill):
    node = OxmlElement("w:shd")
    node.set(qn("w:val"), "clear")
    node.set(qn("w:color"), "auto")
    node.set(qn("w:fill"), "%02X%02X%02X" % tuple(max(0, min(255, int(round(c * 255)))) for c in fill[:3]))
    insert_ordered(paragraph._p.get_or_add_pPr(), node, PPR_ORDER)


def border_eighths(width):
    """A stroke width in points as Word wants it: eighths of a point, 2 to 96."""
    return str(max(2, min(96, int(round((width or 0.0) * 8)) or 6)))


def underline_paragraph(paragraph, rule):
    """The rule under a running header, as heavy and as dark as the PDF's."""
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), border_eighths(rule.get("width") if isinstance(rule, dict) else None))
    bottom.set(qn("w:space"), "1")
    colour = rule.get("color") if isinstance(rule, dict) else None
    bottom.set(qn("w:color"), hex_of(colour) if colour is not None else "auto")
    borders.append(bottom)
    insert_ordered(paragraph._p.get_or_add_pPr(), borders, PPR_ORDER)


def alignment_of(column, left, right):
    """Left, centre or right, from where the column sits in the text area."""
    centre = (left + right) / 2.0
    if abs(column["x0"] - left) <= ALIGN_TOLERANCE_PT:
        return "left"
    if abs(column["x1"] - right) <= ALIGN_TOLERANCE_PT:
        return "right"
    if abs((column["x0"] + column["x1"]) / 2.0 - centre) <= ALIGN_TOLERANCE_PT * 2:
        return "centre"
    return "left" if column["x0"] - left < right - column["x1"] else "right"


def band_height(band):
    """How tall the band's own line is, with room for a border under it."""
    text = max(band["text_bottom"] - band["text_top"], 1.0)
    tallest = max((column["size"] for column in band["columns"]), default=10.0)
    return max(text, tallest * 1.15)


BAND_LINE_SHARE = 0.6
"""How far apart, as a share of a column's size, two baselines of a band may be and still be one line."""
HEADER_BAR_SPAN = 0.5
"""The least share of the text area's width a header's fill must span to be a bar behind it (b2's 13 pt logo box is none)."""


def header_bar(band, content_left, content_right):
    """`(top, bottom)` of the filled bar a running header's text sits on, or None.

    `band_decorations` keeps the widest fill near the band as its strip, and
    only a footer's was ever drawn: a2's header is white text on a purple bar
    the width of the text area, and in Word it was white on white on every
    page. A bar is a fill at least `HEADER_BAR_SPAN` of the text area wide
    that holds the band's text from top to bottom, under a header with no
    rule of its own.
    """
    if band["edge"] != "top" or not band.get("strip_behind") or not band.get("strip_y") or not band.get("strip_span"):
        return None
    if band.get("rule_under"):
        return None
    span = band["strip_span"][1] - band["strip_span"][0]
    if span < HEADER_BAR_SPAN * max(1.0, content_right - content_left):
        return None
    top, bottom = band["strip_y"]
    if top > band["text_top"] + 0.5 or bottom < band["text_bottom"] - 0.5:
        return None
    return top, bottom


def strip_to_edge(band, page_height):
    """The height of a footer strip that runs down to the page's edge, or None.

    Word shades a paragraph over its own line box and nothing else, and sets a
    footer `footer_distance` above the edge. A strip drawn to the bottom of the
    page therefore came out as a band as tall as the text with white above and
    below it. When the PDF's strip reaches the edge, the footer is given no
    distance and a line as tall as the strip instead.
    """
    if band["edge"] != "bottom" or not band.get("strip_behind") or not band.get("strip_y"):
        return None
    top, bottom = band["strip_y"]
    if bottom < page_height - 1.0 or bottom - top <= band_height(band):
        return None
    return page_height - top


def raise_band_text(paragraph, band, line_top, line):
    """Lift the band's runs so their baseline is the PDF's, in an exact line of `line` points.

    Word sets the baseline of an exact line at `EXACT_BASELINE_RATIO` of its
    height below its top, which in a line as tall as the strip is lower than
    the PDF's: 3.7 pt on the CPTC footer. `w:position` moves the text and not
    the line, so the strip keeps its size.
    """
    bases = [column["base"] for column in band["columns"] if column.get("base") is not None]
    if not bases:
        return
    lift = line_top + EXACT_BASELINE_RATIO * line - median(sorted(bases))
    half_points = int(round(lift * 2))
    if half_points <= 0:
        return
    for run in paragraph._p.iter(qn("w:r")):
        properties = run.find(qn("w:rPr"))
        if properties is None:
            properties = OxmlElement("w:rPr")
            run.insert(0, properties)
        position = OxmlElement("w:position")
        position.set(qn("w:val"), str(half_points))
        insert_ordered(properties, position, RPR_ORDER)


def band_paint_span(band, left_margin, right_edge):
    """Where the band's own rule or strip runs, or None when it has neither.

    Word draws both of those as paragraph decoration, between the paragraph's
    indents, so this is what the indents have to be: the PDF's rule stops
    short of the right margin on the reference report, and a border run to the
    indent instead was 3 to 7 pt too wide on every page.
    """
    if band["edge"] == "top" and isinstance(band.get("rule_under"), dict):
        return band["rule_under"]["x0"], band["rule_under"]["x1"]
    if band["edge"] == "top" and band.get("bar"):
        if band.get("strip_full_width"):
            return 0.0, left_margin + right_edge
        return band.get("strip_span")
    if band["edge"] == "bottom" and band["strip_behind"]:
        if band.get("strip_full_width"):
            return 0.0, left_margin + right_edge
        return band.get("strip_span")
    return None


def fill_band_paragraph(paragraph, band, left_margin, right_margin, content_left, content_right, page_height=None,
                        page_width=None):
    """One paragraph holding the band's left, centre and right columns.

    Tab stops and indents are measured from the section's own left margin,
    which pdf2docx sets per page, so the band lands on the same column as the
    body however the margins came out.
    """
    clear_paragraph(paragraph)
    fmt = paragraph.paragraph_format
    fmt.space_before = Pt(0)
    fmt.space_after = Pt(0)
    fmt.line_spacing_rule = WD_LINE_SPACING.EXACTLY
    edge_strip = strip_to_edge(band, page_height) if page_height else None
    bar = header_bar(band, content_left, content_right)
    band["bar"] = bar
    if bar:
        # The line is as tall as the bar, since Word shades a paragraph over
        # its own line box, and the text is lifted to the PDF's baseline in it.
        edge_strip = None
        fmt.line_spacing = Pt(round(bar[1] - bar[0], 1))
    else:
        fmt.line_spacing = Pt(round(edge_strip or band_height(band), 1))
    slots = {"left": [], "centre": [], "right": []}
    for column in band["columns"]:
        slots[alignment_of(column, content_left, content_right)].append(column)
    # Where each slot's text starts and stops comes from the columns the PDF
    # drew, and from the text area only for a slot with nothing in it: on a
    # sideways page the median text area is that of a single page and was 49 pt
    # off the band's own left edge, and a header that follows a logo starts
    # 31 pt right of the margin.
    text_left = min((c["x0"] for c in slots["left"]), default=content_left)
    text_right = max((c["x1"] for c in slots["right"]), default=content_right)
    text_centre = ((min(c["x0"] for c in slots["centre"]) + max(c["x1"] for c in slots["centre"])) / 2.0
                   if slots["centre"] else (content_left + content_right) / 2.0)
    indent = text_left - left_margin
    # Word draws a rule or a filled strip between the paragraph's indents, so
    # when the band has one the indents are the PDF's own: a strip that runs
    # to the page edges pushes the paragraph out into the margins, a rule that
    # stops short of the margin pulls the right indent in. An extra tab stop
    # then puts the text back where the text area starts, because the text
    # does not move with the decoration: the first line's own indent does that.
    # (A leading tab to a left stop at the text's start was the way this was
    # done, and Word does not take a stop that is at, or left of, the position
    # the tab starts from: on b2 the first tab went to the centre stop, which
    # centred the left text and pushed the page number 25 to 205 pt past the
    # margin on 13 of 48 pages. A first-line indent has no such stop to miss.)
    # Word measures a right indent from the section's right margin, which
    # pdf2docx set from the page's widest ink, not from the text column: on
    # the CPTC header that is 42 pt in from the edge, and an indent counted
    # from the column's edge plus that margin pulled the rule under the
    # header in by 38 pt, so it stopped under "Harbor".
    right_edge = (page_width - right_margin) if page_width else content_right + max(0.0, right_margin)
    span = band_paint_span(band, left_margin, right_edge)
    if span:
        fmt.left_indent = Pt(round(span[0] - left_margin, 1))
        fmt.right_indent = Pt(round(right_edge - span[1], 1))
        first_line = round(max(0.0, text_left - span[0]), 1)
        if first_line:
            fmt.first_line_indent = Pt(first_line)
    else:
        fmt.left_indent = Pt(round(indent, 1))
        fmt.right_indent = Pt(0)
    reset_tab_stops(paragraph)
    centre = text_centre - left_margin
    right = text_right - left_margin
    fmt.tab_stops.add_tab_stop(Pt(round(max(1.0, centre), 1)), WD_TAB_ALIGNMENT.CENTER, WD_TAB_LEADER.SPACES)
    fmt.tab_stops.add_tab_stop(Pt(round(max(2.0, right), 1)), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.SPACES)

    stack = band_stack(band, content_left, content_right, page_height)
    grouped = band_lines(band["columns"], lambda column: alignment_of(column, content_left, content_right))
    if stack:
        lines, pitch = stack
        # One line per baseline, at the PDF's pitch between them.
        fmt.line_spacing = Pt(round(pitch, 1))
        if fmt.first_line_indent and fmt.first_line_indent.pt > 0:
            # Only the first line takes the first-line indent: the lines after
            # a break start at the left indent, which is the strip's or rule's
            # edge, so each of them tabs to where the text starts. The stop is
            # where the first line starts, to the twip, so that line's own
            # first tab passes over it (Word takes no stop at its position).
            start = Pt((fmt.left_indent.twips + fmt.first_line_indent.twips) / 20.0)
            fmt.tab_stops.add_tab_stop(start, WD_TAB_ALIGNMENT.LEFT, WD_TAB_LEADER.SPACES)
            lead = True
        else:
            lead = False
    else:
        lines, lead = [(None, list(band["columns"]))], False
    for number, (_, members) in enumerate(lines):
        if number:
            paragraph.add_run().add_break()
            if lead:
                paragraph.add_run("\t")
        for order, name in enumerate(("left", "centre", "right")):
            if order:
                paragraph.add_run("\t")
            # Several columns of one slot on one line are written in reading
            # order (top to bottom, then left to right) with a space between,
            # never run together in the order of their left edges.
            mine = [column for column in slots[name] if any(column is member for member in members)]
            mine.sort(key=lambda column: (reading_line(column, grouped), column["x0"]))
            for place, column in enumerate(mine):
                if place:
                    paragraph.add_run(" ")
                for part in column["parts"]:
                    if part["kind"] == "page":
                        style_field(paragraph, add_page_field(paragraph), column)
                    elif part["kind"] == "total":
                        style_field(paragraph, add_total_field(paragraph, part["instruction"], part["result"]), column)
                    else:
                        style_run(paragraph.add_run(part["text"]), column)

    if band["edge"] == "top" and band["rule_under"]:
        underline_paragraph(paragraph, band["rule_under"])
    if bar:
        shade_paragraph(paragraph, band["strip_behind"])
        raise_band_text(paragraph, band, bar[0], bar[1] - bar[0])
    if band["edge"] == "bottom" and band["strip_behind"]:
        shade_paragraph(paragraph, band["strip_behind"])
    if edge_strip:
        line = round(edge_strip, 1)
        raise_band_text(paragraph, band, page_height - line, line)


def reading_line(column, lines):
    """Which of a band's lines a column reads on, for ordering one slot's columns."""
    return next(number for number, (_, members) in enumerate(lines) if any(column is m for m in members))


def is_page_only(column):
    """Whether a band column holds a page number or a total and no words."""
    return all(part["kind"] in ("page", "total") for part in column["parts"])


def band_lines(columns, slot_of=None):
    """A band's columns as `(base, members)` lines, top to bottom: one per line the band's text stands on.

    A footer can stack its text: a2's "CONFIDENTIAL" over "INTERNAL USE
    ONLY", centred, with the page number between them at the right. Written
    as one line, the two centred labels ran together in the order of their
    left edges ("INTERNAL USE ONLYCONFIDENTIAL"). The lines are the stack's:
    those of the slot (left, centre, right, from `slot_of`) that has the most
    of them, read from words, never from a page number, since grouping from
    the top let a "Page 3" between the two labels take the lower one into its
    line. Every other column stands on the nearest of those lines (a page
    number or "Page 3" beside a two-line block, a title centred beside it),
    or, beyond the stack's first or last line by more than `BAND_LINE_SHARE`
    of its size, on a line of its own. `base` is the baseline of the stack's
    own words on that line, so the pitch is the stack's. Every column is in
    exactly one line: moving a line into another after the fact dropped a
    page number that had joined the line that moved.
    """
    placed = sorted((column for column in columns if column.get("base") is not None), key=lambda c: c["base"])
    if not placed or len(placed) != len(columns):
        return [(None, list(columns))]

    def grouped(cols):
        lines = []
        for column in cols:
            if lines and column["base"] - lines[-1][0] <= BAND_LINE_SHARE * (column.get("size") or 10.0):
                lines[-1][1].append(column)
            else:
                lines.append((column["base"], [column]))
        return [(median(sorted(c["base"] for c in members)), members) for _, members in lines]

    words = [column for column in placed if not is_page_only(column)] or placed
    by_slot = {}
    for column in words:
        by_slot.setdefault(slot_of(column) if slot_of else None, []).append(column)
    stack = max((grouped(cols) for cols in by_slot.values()), key=len)
    if len(stack) < 2:
        stack = grouped(words)
    first, last = stack[0][0], stack[-1][0]
    lines = [(base, []) for base, _ in stack]
    outside = []
    for column in placed:
        reach = BAND_LINE_SHARE * (column.get("size") or 10.0)
        if column["base"] < first - reach or column["base"] > last + reach:
            outside.append(column)
            continue
        nearest = min(range(len(lines)), key=lambda i: abs(column["base"] - lines[i][0]))
        lines[nearest][1].append(column)
    lines = sorted([line for line in lines if line[1]] + grouped(outside), key=lambda line: line[0])
    return lines if len(lines) > 1 else [(None, list(columns))]


def stacks_apart(lines):
    """Whether a band's lines stand at least their tallest type apart, so that each can be a line of its own.

    Each line is written at the pitch between them, exactly, and Word clips
    the glyphs of an exact line shorter than its type. Baselines closer than
    that (an 18 pt title beside a 7 pt block, lines set tighter than their
    type) are not a stack, and stay on one line.
    """
    tallest = max((column.get("size") or 0.0) for _, members in lines for column in members)
    return band_pitch(lines) >= tallest


def band_pitch(lines):
    """The distance between the baselines of a stacked band's lines: the smallest gap between neighbours.

    Every line is given it, so it is what the type must fit, and the band
    never stands taller than the PDF's: the median of an uneven stack's gaps
    put its second line 4.4 pt low and pushed the body down by as much.
    """
    bases = [base for base, _ in lines if base is not None]
    gaps = sorted(b - a for a, b in zip(bases, bases[1:]))
    return gaps[0] if gaps else 0.0


def band_stack(band, content_left, content_right, page_height=None):
    """`(lines, pitch)` when the band is written one line per baseline, else None.

    `fill_band_paragraph` writes it and `apply_bands` places it, so both ask
    here. A header bar or a strip to the page's edge keeps one line, lifted
    to the PDF's baseline by `raise_band_text`.
    """
    if header_bar(band, content_left, content_right) or (page_height and strip_to_edge(band, page_height)):
        return None
    lines = band_lines(band["columns"], lambda column: alignment_of(column, content_left, content_right))
    if len(lines) < 2 or not stacks_apart(lines):
        return None
    return lines, band_pitch(lines)


def stack_box(stack):
    """`(top, height)` of a stacked band's paragraph, so its baselines land on the PDF's.

    Word sets an exact line's baseline at `EXACT_BASELINE_RATIO` of its height,
    so a paragraph placed at the band's `text_top` put a stacked header's
    baselines 3.8 pt low and, with its rule, pushed the body down 1.6 pt.
    """
    lines, pitch = stack
    top = lines[0][0] - EXACT_BASELINE_RATIO * pitch
    return top, len(lines) * pitch


def clear_paragraph(paragraph):
    for run in list(paragraph.runs):
        run._element.getparent().remove(run._element)


def reset_tab_stops(paragraph):
    """Drop the paragraph's own tab stops and cancel the ones it inherits.

    Word merges a style's tab stops with the paragraph's rather than letting
    the paragraph replace them, and the built-in Header and Footer styles come
    with a centre and a right stop for one-inch margins. Leaving them in place
    sends the first tab to the style's centre stop and the right-hand piece of
    a running header lands in the middle of the page.
    """
    stops = paragraph.paragraph_format.tab_stops
    stops.clear_all()
    positions = []
    style = paragraph.style
    seen = set()
    while style is not None and id(style) not in seen:
        seen.add(id(style))
        positions.extend(stop.position for stop in style.paragraph_format.tab_stops)
        style = style.base_style
    for position in sorted(set(positions)):
        stops.add_tab_stop(position, WD_TAB_ALIGNMENT.CLEAR)


def section_blocks(body):
    """The top-level elements of each section, in order."""
    groups = [[]]
    for child in body:
        if child.tag == qn("w:sectPr"):
            continue
        groups[-1].append(child)
        properties = child.find(qn("w:pPr")) if child.tag == qn("w:p") else None
        if properties is not None and properties.find(qn("w:sectPr")) is not None:
            groups.append([])
    if groups and not groups[-1]:
        groups.pop()
    return groups


def section_break_of(element):
    """The `w:sectPr` an element carries: a paragraph's own, or the body's, or None."""
    if element.tag == qn("w:sectPr"):
        return element
    if element.tag != qn("w:p"):
        return None
    properties = element.find(qn("w:pPr"))
    return properties.find(qn("w:sectPr")) if properties is not None else None


def section_starts_page(section):
    """Does the section these properties describe begin on a new page?"""
    kind = section.find(qn("w:type"))
    return kind is None or kind.get(qn("w:val")) in (None, "nextPage", "oddPage", "evenPage")


def page_ends(body):
    """The elements after which Word begins a new page, in order.

    Elements, not ids: lxml hands out a proxy object only while something
    holds it, so an id taken from one walk of the body does not name the
    same element on the next.

    A section break lives in the last paragraph of its section and says how
    that section begins, so a page ends at the break whose next section
    starts a page, and at the body's own. pdf2docx writes one section per
    page and then two more inside a page that holds pictures side by side
    (a continuous section of two columns and a next-column one), so a count
    of sections is not a count of pages: the document with such a figure had
    no paragraph given a page, and its text was matched by a cursor that
    ran away on repeated prose.
    """
    holders = [(child, section) for child in body for section in [section_break_of(child)] if section is not None]
    ends = []
    for index, (holder, _) in enumerate(holders):
        if index + 1 >= len(holders) or section_starts_page(holders[index + 1][1]):
            ends.append(holder)
    return ends


def page_sections(document):
    """The section each page begins with, in page order."""
    return [section for section in document.sections if section_starts_page(section._sectPr)]


def page_blocks(body):
    """The top-level elements of each page, in order."""
    holders = page_ends(body)
    ends = {id(holder) for holder in holders}
    groups = [[]]
    for child in body:
        if child.tag == qn("w:sectPr"):
            continue
        groups[-1].append(child)
        if id(child) in ends:
            groups.append([])
    if groups and not groups[-1]:
        groups.pop()
    return groups


def shave_leading_space(blocks, amount):
    """Take `amount` points of blank space off the top of a section.

    Word reserves max(top margin, header distance + header height) before the
    body starts, and pdf2docx sets a top margin that assumed no header at all.
    Without this the whole page slides down by the height of the header, and a
    full page spills onto a second one. The space comes off the first
    paragraph's own spacing, which is the blank run-up pdf2docx writes to put
    the first line where the PDF had it.
    """
    left = amount
    for block in blocks:
        if left <= 0.01 or block.tag != qn("w:p"):
            break
        fmt = Paragraph(block, None).paragraph_format
        for name in ("space_after", "space_before"):
            value = getattr(fmt, name)
            if value is None:
                continue
            take = min(value.pt, left)
            setattr(fmt, name, Pt(round(value.pt - take, 1)))
            left -= take
        spacing = fmt.line_spacing  # a Length when exact, a bare float when a multiple
        if left > 0.01 and hasattr(spacing, "pt"):
            take = min(max(0.0, spacing.pt - 1.0), left)
            fmt.line_spacing = Pt(round(spacing.pt - take, 1))
            left -= take
        break  # only the run-up before the first real content is ours to take
    return left


def bands_need_pages(bands):
    """Tagged bands that Word can give only a section at a time.

    The header and footer on different sets of pages, or an edge with more
    than one text (the chapter's title, odd and even pages, a sideways page's
    own geometry): Word repeats one definition until the next section says
    otherwise, so without a section per PDF page the bands cannot be put back
    as the PDF has them.
    """
    edges = [band for band in bands if band.get("source") == "tagged"]
    if len({band["edge"] for band in edges}) < len(edges):
        return True
    return len(edges) == 2 and set(edges[0]["pages"]) != set(edges[1]["pages"])


def sections_by_page(document, page_sizes):
    """The Word sections of each PDF page, in order, or None when they cannot be told.

    pdf2docx writes one section per page, and more inside a page it lays out
    in columns (two pictures side by side, two cards across): a continuous
    section and a next-column one, which begin no page (`page_ends`). So the
    section count is not the page count (a2 has 54 sections for 42 pages),
    and a chapter's header given by count would land on the wrong pages. A
    page begins at each section that starts one, and the map holds only when
    that gives exactly the PDF's page count and, once a report turns a page
    sideways, every section is the paper size of the page it is on.
    `page_sizes` entries may be None where the size is not known.
    """
    groups = []
    for index, section in enumerate(document.sections):
        if index == 0 or section_starts_page(section._sectPr):
            groups.append([])
        groups[-1].append(index)
    if len(groups) != len(page_sizes):
        return None
    if len(set(page_sizes)) > 1:
        sections = document.sections
        for members, size in zip(groups, page_sizes):
            for index in members:
                width, height = sections[index].page_width, sections[index].page_height
                if width is None or height is None:
                    return None
                if abs(width.pt - size[0]) > SECTION_SIZE_SLACK_PT or abs(height.pt - size[1]) > SECTION_SIZE_SLACK_PT:
                    return None
    return groups


def footer_refers_to_missing_bookmark(document, name=LAST_PAGE_BOOKMARK):
    """Does a header or footer hold `PAGEREF <name>` while no bookmark of that name is in the body?"""
    held = {node.get(qn("w:name")) for node in document.element.body.iter(qn("w:bookmarkStart"))}
    if name in held:
        return False
    for section in document.sections:
        for part in ("header", "footer", "first_page_header", "first_page_footer"):
            holder = getattr(section, part)
            if holder.is_linked_to_previous:
                continue
            for node in holder._element.iter(qn("w:instrText")):
                if name in (node.text or ""):
                    return True
    return False


def band_text_gaps(document, bands, groups):
    """The tagged bands whose text is not in the header or footer of their own sections.

    The text check leaves a band's rows out of the body on both sides, so
    nothing else says that the words of a chapter's header reached the
    sections of that chapter's pages. Each page of each band is looked up in
    the header or footer of the section it begins in (`groups`, from
    `sections_by_page`), and a page whose text is not there is named, which
    sends the conversion to the fallback.
    """
    sections = document.sections
    gaps = []
    for band in bands:
        if band.get("source") != "tagged":
            continue
        name = "header" if band["edge"] == "top" else "footer"
        wanted = [compare_squash(part["text"]) for column in band["columns"] for part in column["parts"]
                  if part["kind"] == "text"]
        for page in band["pages"]:
            holder = getattr(sections[groups[page][0]], name)
            have = compare_squash(" ".join(paragraph.text for paragraph in holder.paragraphs))
            if any(text and text not in have for text in wanted):
                gaps.append("(the running %s of PDF page %d is not in its Word section)" % (name, page + 1))
                break
    # A footer's "of 42" is a PAGEREF to a bookmark `apply_bands` put on the
    # body's last paragraph, and the passes that run after it can drop or copy
    # that paragraph. The band rows are outside the text check, so a footer
    # that refers to a bookmark nothing holds would print "Error! Bookmark not
    # defined." on every page without anything saying so. `band_text_gaps` runs
    # after `decorate_document`, on the document the file is saved from, so
    # this sees what every pass left.
    if footer_refers_to_missing_bookmark(document):
        gaps.append("(a footer counts the pages with a reference to %s, and the body has no such bookmark)"
                    % LAST_PAGE_BOOKMARK)
    # The text check leaves a band's rows out, so a page number that Word
    # would count differently from the PDF (a restart nothing wrote) is
    # silent unless the starts in the section properties are read back.
    printed = printed_page_numbers(bands)
    if printed:
        have_numbers = word_page_numbers(document, groups)
        for page, number in sorted(printed.items()):
            if page < len(have_numbers) and have_numbers[page] != number:
                gaps.append("(PDF page %d prints page number %d and its Word section would print %d)"
                            % (page + 1, number, have_numbers[page]))
                break
    return gaps


def apply_bands(document, bands, page_height, content_left, content_right, page_count, page_sizes=None):
    """Put the bands back as real Word headers and footers.

    pdf2docx writes one section per PDF page with that page's own margins, so
    when the counts line up each section is given the band its page carried
    and the cover keeps its empty header. Otherwise every section gets the
    band and the first page is excluded with "different first page".

    A tagged band knows its own pages, so with a section per page the header
    and the footer are each given only where the PDF has that one: a page
    with a page number and no header gets the footer alone, and a page whose
    header text differs from its neighbours' (the chapter's title) gets the
    variant of its own, read against its own paper size. Without a section
    per page there is no way to say that, and `bands_need_pages` refuses the
    bands before this is called. `page_sizes` is each PDF page's size, which
    is what makes the section per page a checked fact on a report with
    sideways pages (`sections_follow_pages`).
    """
    offsets = [c["page_offset"] for b in bands for c in b["columns"] if c["page_offset"] is not None]
    printed = printed_page_numbers(bands)
    restarts = page_number_starts(printed)
    total = total_page_field(printed, page_count, restarts)
    if total:
        # "Page 3 of 42": the 42 becomes a field that follows the document.
        rebuilt = []
        for band in bands:
            columns = []
            used = False
            for column in band["columns"]:
                parts, changed = split_total_parts(column["parts"], total["last"])
                used = used or changed
                columns.append(dict(column, parts=[dict(part, **total) if part["kind"] == "total" else part
                                                   for part in parts]) if changed else column)
            rebuilt.append(dict(band, columns=columns) if used else band)
            if used and total["bookmark"]:
                add_last_page_bookmark(document)
        bands = rebuilt
    band_pages = {index for band in bands for index in band["pages"]}
    edge_bands = {part: [b for b in bands if b["edge"] == edge] for part, edge in (("header", "top"), ("footer", "bottom"))}
    # Per edge, the pages a tagged band is on (a heuristic band's pages are the
    # document's), and which band is on which page.
    edge_pages = {}
    on_page = {}
    for part, found in edge_bands.items():
        tagged_edge = bool(found) and found[0].get("source") == "tagged"
        edge_pages[part] = {index for band in found for index in band["pages"]} if tagged_edge else band_pages
        on_page[part] = {}
        for band in found:
            for index in (band["pages"] if tagged_edge else band_pages):
                on_page[part].setdefault(index, band)
    sections = document.sections
    groups = sections_by_page(document, page_sizes or [None] * page_count)
    per_page = groups is not None
    page_of = {}
    leads = set()
    for page, members in enumerate(groups or []):
        leads.add(members[0])
        for index in members:
            page_of[index] = page
    # Word's count is restarted on the lead section of each page the PDF
    # restarts at (the first page keeps its explicit 1 as it always had).
    lead_start = {}
    if per_page and printed:
        lead_start = {groups[page][0]: value for page, value in restarts.items() if page < len(groups)}
        lead_start.setdefault(groups[0][0], 1)

    def paper(band):
        """The page height and text area a band was read against."""
        height = band["page_size"][1] if band.get("page_size") else page_height
        left, right = band["content"] if band.get("content") else (content_left, content_right)
        return height, left, right
    blocks = section_blocks(document.element.body)
    warnings = []
    unshaved = 0.0
    unshaved_pages = 0

    for index, section in enumerate(sections):
        # One band per edge unless the sections are the pages: then the band of
        # this page's own variant, or none for a page that has no such band.
        page = page_of.get(index, index)
        header_band = on_page["header"].get(page) if per_page else next(iter(edge_bands["header"]), None)
        footer_band = on_page["footer"].get(page) if per_page else next(iter(edge_bands["footer"]), None)
        bare_part = {part: per_page and page not in pages for part, pages in edge_pages.items()}
        first_page_bare = not per_page and index == 0 and 0 not in band_pages
        section.different_first_page_header_footer = first_page_bare
        if first_page_bare:
            section.first_page_header.is_linked_to_previous = False
            section.first_page_footer.is_linked_to_previous = False
        left_margin = section.left_margin.pt
        right_margin = section.right_margin.pt
        for part, band in (("header", header_band), ("footer", footer_band)):
            holder = getattr(section, part)
            bare = bare_part[part]
            if per_page and index not in leads:
                # The rest of a page laid out in columns takes its first
                # section's definition: the page is given one header.
                holder.is_linked_to_previous = True
                continue
            if bare and index == 0:
                # Nothing precedes the first section, so linking is the same
                # as having no header at all, and it costs the page no space.
                holder.is_linked_to_previous = True
                continue
            holder.is_linked_to_previous = False
            clear_paragraph(holder.paragraphs[0])
            if band is not None and not bare:
                paper_height, band_left, band_right = paper(band)
                fill_band_paragraph(holder.paragraphs[0], band, left_margin, right_margin, band_left, band_right,
                                    paper_height, page_width=section.page_width.pt)
                continue
            # An empty definition still reserves its distance plus a line, and
            # with the margins pdf2docx writes that is enough to push a full
            # page onto a second one. Flatten it instead of leaving defaults.
            fmt = holder.paragraphs[0].paragraph_format
            fmt.space_before = Pt(0)
            fmt.space_after = Pt(0)
            fmt.line_spacing_rule = WD_LINE_SPACING.EXACTLY
            fmt.line_spacing = Pt(1)
            setattr(section, part + "_distance", Pt(0))

        if header_band and not bare_part["header"]:
            bar = header_bar(header_band, *paper(header_band)[1:])
            if bar:
                # The header starts where its bar does, and is the bar.
                height = bar[1] - bar[0]
                reserved = bar[1]
                section.header_distance = Pt(round(bar[0], 1))
            else:
                stack = band_stack(header_band, *paper(header_band)[1:], paper(header_band)[0])
                top, line = stack_box(stack) if stack else (header_band["text_top"], band_height(header_band))
                top = max(0.0, top)
                height = line + (4.0 if header_band["rule_under"] else 2.0)
                reserved = top + height
                section.header_distance = Pt(round(top, 1))
            if reserved > section.top_margin.pt and section_starts_page(section._sectPr):
                delta = reserved - section.top_margin.pt
                section.top_margin = Pt(round(reserved, 1))
                if index < len(blocks):
                    left = shave_leading_space(blocks[index], delta)
                    if left > 1.0:
                        unshaved_pages += 1
                    unshaved = max(unshaved, left)
        if footer_band and not bare_part["footer"]:
            paper_height = paper(footer_band)[0]
            edge_strip = strip_to_edge(footer_band, paper_height)
            stack = band_stack(footer_band, *paper(footer_band)[1:], paper_height)
            height = round(edge_strip, 1) if edge_strip else (stack_box(stack)[1] if stack else band_height(footer_band)) + 2.0
            # A strip drawn to the page's edge is the footer's whole box, so
            # the footer starts at the edge; anything above it shows as white.
            bottom = sum(stack_box(stack)) if stack else footer_band["text_bottom"]
            distance = 0.0 if edge_strip else max(0.0, paper_height - bottom)
            if distance + height > section.bottom_margin.pt:
                distance = max(0.0, section.bottom_margin.pt - height)
            section.footer_distance = Pt(round(distance, 1))
            if distance + height > section.bottom_margin.pt:
                section.bottom_margin = Pt(round(distance + height, 1))
        if index in lead_start:
            set_page_numbering_start(section, lead_start[index])
        elif offsets and index == 0 and not per_page:
            # Without a section per page there is one count for the document.
            # A start below 0 is not one Word offers, so it is held at 0.
            set_page_numbering_start(section, max(0, offsets[0]))
            if offsets[0] < 0:
                warnings.append("The PDF's page numbers start %d pages before the first page; "
                                "Word cannot count from there, so they differ." % -offsets[0])

    # The worst page, not a sum over pages: a report whose every page opens
    # with a table had nothing to shave on any of them, and the sum of sixty
    # pages' point and a half read as a 93 pt fault that no page had.
    if unshaved > HEADER_SHAVE_WARN_PT:
        warnings.append(
            "The running header did not fit in the margin the converter chose on %d page(s), "
            "so their content sits up to %d pt lower than in the PDF." % (unshaved_pages, round(unshaved))
        )
    return warnings


# ── step 4: write the table of contents back ──────────────────────────────


def body_paragraphs(document):
    """Every `w:p` in the body, in document order, tables included.

    Walking the object model instead would visit a merged cell once per grid
    column it spans, and the same paragraph would then be deleted twice.
    """
    return list(document.element.body.iter(qn("w:p")))


def paragraph_text(element):
    return "".join(node.text or "" for node in element.iter(qn("w:t")))


def leader_runs(paragraphs):
    """Stretches of dot-leader paragraphs that could be a table of contents.

    A stretch is counted in leader lines, not paragraphs: pdf2docx joins a
    whole page of contents lines into one paragraph with a line break between
    them (a1's page 3 is one paragraph holding 49 leaders), and counting
    paragraphs dropped that stretch as a coincidence.
    """
    runs = []
    weight = {}
    for index, element in enumerate(paragraphs):
        lines = len(LEADER.findall(paragraph_text(element)))
        if not lines:
            continue
        weight[index] = lines
        if runs and index - runs[-1][-1] <= TOC_RUN_GAP + 1:
            runs[-1].append(index)
        else:
            runs.append([index])
    return [run for run in runs if sum(weight[i] for i in run) >= TOC_RUN_MIN]


def removal_unit(body, element):
    """What has to go for one converted entry to disappear cleanly.

    A paragraph sitting directly in the body is its own unit. One inside a
    table is removed with its whole row: the number and the title of an entry
    land in different cells of the same row, and emptying a cell instead
    leaves a table Word will not open.
    """
    unit = element
    node = element.getparent()
    while node is not None and node is not body:
        if node.tag == qn("w:tr"):
            unit = node
        node = node.getparent()
    return unit


def toc_units(body, region):
    """What has to go for each paragraph of a stretch, once each, in reading order."""
    units = []
    for element in region:
        unit = removal_unit(body, element)
        if unit not in units:
            units.append(unit)
    return units


def toc_unit_losses(units, region, known):
    """What removing these units would delete besides the entries: (pictures, words).

    The entries are rewritten as paragraphs of their own, so a unit that is a
    table row goes whole, and whatever shares the row goes with it. A typst
    `grid(columns: (1fr, 3cm), outline(), image("logo.png"))` is one row of
    two cells for pdf2docx, and the logo went with the entries: 0 drawings
    against 1 with the pass skipped, with nothing in the text check to see it.
    `pictures` counts the drawings, pictures and objects anywhere in a unit.
    `words` lists the paragraphs a unit holds that are outside the stretch and
    that no entry accounts for: a page number in the next cell is accounted for
    and has no letter to lose, a heading or a caption in the next cell is
    neither. `known` is the set of squashed texts the entries own that the
    stretch's own letters did not hold (`toc_accounting`'s `unfound`), and a
    paragraph is accounted for only when its whole text is one of them. Never
    a test against the stretch's letters: a side card reading "Scope" beside
    an outline with an entry "1.1 Scope" is a substring of them, and was
    deleted with its row (c4), with `missing: 0` since the entry still said it.
    """
    pictures = sum(1 for unit in units for tag in ("w:drawing", "w:pict", "w:object") for _ in unit.iter(qn(tag)))
    words = []
    for unit in units:
        for paragraph in unit.iter(qn("w:p")):
            if any(paragraph is element for element in region):
                continue
            text = squash(paragraph_text(paragraph))
            if any(char.isalpha() for char in text) and text not in known:
                words.append(paragraph_text(paragraph).strip())
    return pictures, words


def top_level_block(body, element):
    node = element
    while node is not None and node.getparent() is not body:
        node = node.getparent()
    return node


def section_index_of(body, block):
    """Which section a top-level block belongs to."""
    index = 0
    for child in body:
        if child is block:
            return index
        if child.tag == qn("w:p"):
            properties = child.find(qn("w:pPr"))
            if properties is not None and properties.find(qn("w:sectPr")) is not None:
                index += 1
    return index


def squash(text):
    """A title reduced to the characters that identify it, in any script.

    `[^0-9a-z]` reduced every Cyrillic, Greek and CJK title to the empty
    string, which matched nothing, and an entry that matched nothing used to
    be deleted along with the rest of its stretch.
    """
    return re.sub(r"[\W_]+", "", text.casefold(), flags=re.UNICODE)


def toc_letters(region):
    """A stretch's text squashed, with where each kept character came from.

    The owner of a character is (paragraph position in the region, offset in
    that paragraph's text), so a piece of the squashed text can be cut out of
    the paragraph it came from again.
    """
    letters, owner = [], []
    for position, element in enumerate(region):
        for offset, char in enumerate(paragraph_text(element)):
            for kept in squash(char):
                letters.append(kept)
                owner.append((position, offset))
    return "".join(letters), owner


def toc_accounting(letters, entries, unfound=None):
    """Which characters of a stretch its entries account for, and where each begins.

    The entries are taken in reading order, each from the first copy at or
    after the one before, so a title that occurs twice is taken from the right
    place. An entry is its whole line when that is in the stretch, else its
    columns one by one: the converter parts a figure's label from its caption.
    A page number is taken from the characters right after its title; one that
    is not there is taken from the first unclaimed copy anywhere, since the
    converter sometimes puts it in a cell that is read later.

    `unfound`, when given, collects the squashed texts the stretch's letters
    do not hold: an entry's title when no part of it was found, the segments
    that were not, and a page number that was not. Those are the only texts
    a paragraph beside the stretch may carry and still be that entry's.

    A title or segment that ends in a digit is never taken from the front of
    another entry's that runs on in digits: with "Figure 1" in the cell beside
    the stretch, its label was taken from "Figure 10" in the stretch, so the
    real label beside it was owned by nobody and the whole rebuild declined
    (b1's contents page stayed one run-on paragraph). A copy followed by the
    entry's own page number is that entry's, since the stretch is glued:
    "Phase 1" on page 11 reads "phase111", which is not "Phase 11".
    """
    used = bytearray(len(letters))
    starts = []
    owed = []
    cursor = 0
    texts = set()
    for entry in entries:
        texts.add(squash(entry["title"]))
        texts.update(squash(segment["text"]) for segment in entry["segments"])
    longer = {}

    def runs_on(needle, at, follow=""):
        """Is the copy of `needle` at `at` the start of another entry's text that continues with a digit?"""
        if needle not in texts or not needle[-1].isdigit():
            return False
        if follow and letters.startswith(needle + follow, at):
            return False
        if needle not in longer:
            longer[needle] = [other for other in texts
                              if len(other) > len(needle) and other.startswith(needle) and other[len(needle)].isdigit()]
        return any(letters.startswith(other, at) for other in longer[needle])

    def take(needle, floor, follow=""):
        if not needle:
            return None
        for begin in (floor, 0):
            at = letters.find(needle, begin)
            while at >= 0 and (any(used[at:at + len(needle)]) or runs_on(needle, at, follow)):
                at = letters.find(needle, at + 1)
            if at >= 0:
                used[at:at + len(needle)] = b"\x01" * len(needle)
                return at
        return None

    for entry in entries:
        whole = squash(entry["title"])
        start = take(whole, cursor, squash(entry["number"]))
        end = None if start is None else start + len(whole)
        if start is None:
            for segment in entry["segments"]:
                needle = squash(segment["text"])
                at = take(needle, cursor)
                if at is not None:
                    start = at if start is None else min(start, at)
                    end = at + len(needle) if end is None else max(end, at + len(needle))
                elif needle and unfound is not None:
                    unfound.append(needle)
            if end is None and whole and unfound is not None:
                unfound.append(whole)
        starts.append(start)
        if end is None:
            owed.append(squash(entry["number"]))
            continue
        cursor = max(cursor, end)
        number = squash(entry["number"])
        if number and letters.startswith(number, end) and not any(used[end:end + len(number)]):
            used[end:end + len(number)] = b"\x01" * len(number)
            cursor = max(cursor, end + len(number))
        else:
            owed.append(number)
    for number in owed:
        if take(number, 0) is None and number and unfound is not None:
            unfound.append(number)
    return used, starts


def toc_trim(element, first, last):
    """A copy of one paragraph holding only its text from `first` to `last`.

    Formatting stays, since the copy is the paragraph itself with the words
    outside the range taken out: the heading glued to the first entry of a
    merged contents page keeps its own font and size. A picture or shape
    anchored in the paragraph would be doubled or lost, so such a paragraph
    cannot be copied (None), and so cannot a piece that comes out empty.
    """
    if any(element.find(".//" + qn(tag)) is not None for tag in ("w:drawing", "w:pict", "w:object")):
        return None
    clone = copy.deepcopy(element)
    properties = clone.find(qn("w:pPr"))
    if properties is not None:
        for node in properties.findall(qn("w:sectPr")):
            properties.remove(node)
    offset = 0
    for node in list(clone.iter(qn("w:t"))):
        text = node.text or ""
        low, high = max(first - offset, 0), min(last - offset, len(text))
        offset += len(text)
        if high > low:
            node.text = text[low:high]
            node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        else:
            node.getparent().remove(node)
    # What a run held besides its text (a tab before the page number, a line
    # break) belongs to the entries, not to the words kept.
    for run in list(clone.iter(qn("w:r"))):
        if run.find(".//" + qn("w:t")) is None:
            run.getparent().remove(run)
    return clone if paragraph_text(clone).strip() else None


def toc_leftovers(body, region, letters, owner, used):
    """The text in a stretch that no entry accounts for, a paragraph per piece.

    A heading such as "List of figures" sits between two lists, or is glued to
    the first entry of a merged page ("Contents Notice of confidentiality"),
    and replacing the stretch used to delete it with the entries. A piece
    counts only if it holds a letter: what is left of a page number or a
    label after the entries took their part is digits, and keeping that would
    put a stray number in the list. None when a piece cannot be copied.
    """
    kept = []
    count = len(letters)
    k = 0
    while k < count:
        if used[k]:
            k += 1
            continue
        position = owner[k][0]
        j = k
        while j + 1 < count and not used[j + 1] and owner[j + 1][0] == position:
            j += 1
        if any(char.isalpha() for char in letters[k:j + 1]):
            element = toc_trim(region[position], owner[k][1], owner[j][1] + 1)
            if element is None:
                return None
            block = top_level_block(body, region[position])
            kept.append({"element": element, "key": k,
                         "section": section_index_of(body, block) if block is not None else 0})
        k = j + 1
    return kept


def toc_order(group, mine, starts, pieces):
    """A group's entries with the kept pieces slotted in where the stretch had them."""
    where = {id(entry): starts[number] for number, entry in enumerate(mine)}
    ordered = []
    waiting = sorted(pieces, key=lambda piece: piece["key"])
    last = -1
    for entry in group:
        key = where.get(id(entry))
        last = key if key is not None else last
        while waiting and waiting[0]["key"] < last:
            ordered.append(waiting.pop(0))
        ordered.append(entry)
    ordered.extend(waiting)
    return ordered


def write_toc_entry(paragraph, entry, indent, right_stop, pitch, space_before):
    """One entry: indent, title, dot leader, page number.

    Tab stop positions are measured from the section's left margin, the same
    reference as the indent, so every entry's page number lines up at the
    right edge of the text area whatever its level.
    """
    fmt = paragraph.paragraph_format
    fmt.left_indent = Pt(round(indent, 1))
    fmt.right_indent = Pt(0)
    fmt.first_line_indent = Pt(0)
    fmt.space_after = Pt(0)
    # Never negative: the first entry after the contents page's own break
    # measured 0.6 pt above where its pitch puts it, and python-docx refuses
    # a negative spacing, which failed the export of every report whose
    # contents ran to a second page.
    fmt.space_before = Pt(round(max(0.0, space_before), 1))
    if pitch:
        fmt.line_spacing_rule = WD_LINE_SPACING.EXACTLY
        fmt.line_spacing = Pt(round(pitch, 1))
    reset_tab_stops(paragraph)
    for segment in entry["segments"][1:]:
        if segment["offset"] > COLUMN_GAP_PT:
            fmt.tab_stops.add_tab_stop(
                Pt(round(indent + segment["offset"], 1)), WD_TAB_ALIGNMENT.LEFT, WD_TAB_LEADER.SPACES
            )
    fmt.tab_stops.add_tab_stop(Pt(round(max(indent + 1.0, right_stop), 1)), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)

    for order, segment in enumerate(entry["segments"]):
        if order:
            style_run(paragraph.add_run("\t" if segment["offset"] > COLUMN_GAP_PT else " "), segment)
        style_run(paragraph.add_run(segment["text"]), segment)
    last = entry["segments"][-1]
    tab = paragraph.add_run("\t")
    style_run(tab, last)
    extra = entry.get("leader_extra") or 0.0
    if extra > 0.05:
        # Word draws the leader in the formatting of the run that holds the
        # tab, character spacing included, so this is what sets the pitch.
        node = OxmlElement("w:spacing")
        node.set(qn("w:val"), str(int(round(extra * 20))))
        tab._element.get_or_add_rPr().append(node)
    style_run(paragraph.add_run(entry["number"]), last)


def rebuild_toc(document, entries, content_left, content_right, declined=None, page_groups=None):
    """Replace the converted dot-leader paragraphs with one clean line each.

    Entries are matched to a stretch of dot-leader paragraphs by their title
    text, so a table of contents split over two pages still lands in the right
    place and a stray dot leader elsewhere in the document is left alone. The
    replacements are written at the body level even when the converter put the
    original inside a table, because a table cell would clip the dot leader at
    its own width rather than at the page's.

    Only what the entries account for is replaced. A heading the stretch
    holds ("List of figures" between two lists, "Contents" glued to the first
    entry of a merged page) is kept as a paragraph of its own where it stood,
    and a stretch holding text that cannot be kept that way is left as the
    converter wrote it. Every decline is counted in `declined`.

    `page_groups` is `sections_by_page`'s map (the Word sections of each PDF
    page): a stretch's page is the page its section belongs to, not the
    section's own index, which is larger wherever an earlier page laid out
    pictures in columns (a2 has 54 sections for 42 pages).
    """
    def decline(counter):
        if declined is not None:
            declined[counter] += 1

    if not entries:
        return 0, []
    body = document.element.body
    paragraphs = body_paragraphs(document)
    runs = leader_runs(paragraphs)
    if not runs:
        decline("toc-not-found")
        return 0, ["The table of contents could not be found in the converted file, so it was left as it was."]

    pitch = toc_line_pitch(entries)
    haystacks = [squash("".join(paragraph_text(paragraphs[i]) for i in range(run[0], run[-1] + 1))) for run in runs]
    # The page each stretch is on, from its first paragraph's section, so an
    # entry is matched to the stretch on its own page first: a contents list
    # repeats titles ("Timeline Detail BRAVO" is 10.2 and 10.3), and the
    # first stretch to contain a title was taking the second page's entries.
    page_of_section = {member: page for page, members in enumerate(page_groups or ()) for member in members}
    stretch_pages = []
    for run in runs:
        block = top_level_block(body, paragraphs[run[0]])
        at = section_index_of(body, block) if block is not None else None
        stretch_pages.append(page_of_section.get(at, at))
    assigned = {index: [] for index in range(len(runs))}
    missed = 0
    for entry in entries:
        # The whole line first. Failing that, the title without its section
        # number: the converter sometimes leaves the number in the row above
        # the stretch this scan started at, and then only the words match.
        needles = [squash(entry["title"]), squash(entry["segments"][-1]["text"])]
        order = sorted(range(len(haystacks)), key=lambda i: (stretch_pages[i] != entry.get("page_index"), i))
        for index in order:
            if any(needle and needle in haystacks[index] for needle in needles):
                assigned[index].append(entry)
                break
        else:
            missed += 1
    if missed:
        # All or nothing. Replacing a stretch deletes every paragraph in it,
        # including the ones an unmatched entry came from, so a rebuild that
        # cannot account for every entry would quietly drop the ones it could
        # not place. The list the converter wrote is ugly and complete, which
        # is the better of the two.
        decline("toc-unmatched")
        return 0, [
            "The table of contents was left as the converter wrote it: %d of %d entries could not be "
            "matched to it." % (missed, len(entries))
        ]

    # What each stretch holds besides its entries, worked out for every stretch
    # before any is touched: one that cannot be kept apart declines them all.
    plans = {}
    for index, run in enumerate(runs):
        if not assigned[index]:
            continue
        region = [paragraphs[position] for position in range(run[0], run[-1] + 1)]
        letters, owner = toc_letters(region)
        unfound = []
        used, starts = toc_accounting(letters, assigned[index], unfound)
        pieces = toc_leftovers(body, region, letters, owner, used)
        if pieces is None:
            decline("toc-uncovered")
            return 0, [
                "The table of contents was left as the converter wrote it: its page holds text that is not "
                "an entry and could not be kept apart."
            ]
        units = toc_units(body, region)
        pictures, words = toc_unit_losses(units, region, set(unfound))
        if pictures or words:
            decline("toc-uncovered")
            # The converter's row is as tall as the PDF's lines, and its dot
            # leaders are typed dots that wrap in a cell narrower than the
            # page: a row of exact height then clips its last entry (p16 lost
            # "4. Appendix", measured in a Word render). The entries are kept
            # as written, so the row is let grow to hold them.
            for unit in units:
                height = unit.find(qn("w:trPr") + "/" + qn("w:trHeight")) if unit.tag == qn("w:tr") else None
                if height is not None and height.get(qn("w:hRule")) == "exact":
                    height.set(qn("w:hRule"), "atLeast")
            return 0, [
                "The table of contents was left as the converter wrote it: removing its entries would also delete "
                "%s that shares their table row or paragraph." % (
                    "%d picture(s)" % pictures if pictures else "%d paragraph(s) of text" % len(words))
            ]
        plans[index] = (starts, pieces)

    written = 0
    for index, run in enumerate(runs):
        mine = assigned[index]
        if not mine:
            continue
        starts, pieces = plans[index]
        region = [paragraphs[position] for position in range(run[0], run[-1] + 1)]
        units = toc_units(body, region)
        block = top_level_block(body, units[0])
        if block is None:
            continue
        # The entries go back where their block sits: before it when the block
        # opened with one of them, after it when something else did (a page
        # heading the converter swept into the same table).
        opener = next((child for child in block if child.tag in (qn("w:tr"), qn("w:p"))), None)
        before = block is units[0] or opener is units[0]
        section = document.sections[min(section_index_of(body, block), len(document.sections) - 1)]
        left_margin = section.left_margin.pt
        right_stop = max(1.0, content_right - left_margin)

        # A list that runs over two pages is one stretch to the converter but
        # two sections in its file, one per page. The entries of each PDF
        # page go into that page's section, before the first of the stretch's
        # own blocks there; put all of them into the first section, they
        # would overrun it by the two or three entries the PDF's page break
        # moved, and Word would make a page of its own for those.
        by_page = []
        for entry in mine:
            if not by_page or by_page[-1][0] != entry["page_index"]:
                by_page.append((entry["page_index"], []))
            by_page[-1][1].append(entry)
        sections_of_units = []
        for unit in units:
            index_of = section_index_of(body, top_level_block(body, unit))
            if not sections_of_units or sections_of_units[-1][0] != index_of:
                sections_of_units.append((index_of, unit))
        split = len(by_page) > 1 and len(sections_of_units) == len(by_page)
        groups = [(top_level_block(body, unit), entries, index) for (index, unit), (_, entries)
                  in zip(sections_of_units, by_page)] if split else [(block, mine, None)]

        # A kept piece goes with the group of its own page when the stretch
        # is split over pages, else with the one group.
        homes = [[] for _ in groups]
        for piece in pieces:
            home = 0 if len(groups) == 1 else min(
                range(len(groups)), key=lambda number: abs((groups[number][2] or 0) - piece["section"]))
            homes[home].append(piece)

        for (group_block, group, _), own in zip(groups, homes):
            made = []
            previous = None
            for item in toc_order(group, mine, starts, own):
                if "element" in item:
                    made.append(item["element"])
                    # The entry under a heading is spaced from the heading, as in the PDF.
                    previous = None
                    continue
                entry = item
                element = OxmlElement("w:p")
                made.append(element)
                indent = max(0.0, entry["x0"] - left_margin)
                if previous is None:
                    space = entry["gap_before"]
                elif pitch and previous["page_index"] == entry["page_index"]:
                    space = max(0.0, (entry["y0"] - previous["y0"]) - pitch)
                else:
                    space = 0.0
                write_toc_entry(
                    Paragraph(element, document), entry, indent, right_stop, pitch, min(TOC_MAX_SPACE_BEFORE_PT, space)
                )
                previous = entry
                written += 1
            group_opener = next((child for child in group_block if child.tag in (qn("w:tr"), qn("w:p"))), None)
            group_before = before if group_block is block else (
                group_block in units or group_opener is not None and any(group_opener is u for u in units))
            target = group_block
            for element in made:
                if group_before:
                    target.addprevious(element)
                else:
                    target.addnext(element)
                    target = element
        parents = []
        for unit in units:
            parent = unit.getparent()
            if parent is None:
                continue
            if section_break_of(unit) is not None:
                # The paragraph that ends a page's section is in the stretch
                # when a list runs over a page break, and it is not an entry:
                # deleting it merged two sections and left the document one
                # page-starting section short of the PDF's pages. It stays,
                # emptied, where it ended its section; trim_section_tails
                # shrinks it to one point later.
                for child in list(unit):
                    if child.tag != qn("w:pPr"):
                        unit.remove(child)
                continue
            parent.remove(unit)
            parents.append(parent)
        # A table whose rows were all entries is gone with them: Word will not
        # open a table with no row, and the heading rows that used to keep one
        # alive are now paragraphs of their own.
        for table in [group_block for group_block, _, _ in groups] + parents:
            if table.tag == qn("w:tbl") and not table.findall(qn("w:tr")) and table.getparent() is not None:
                table.getparent().remove(table)

    return written, []


# ── step 5: the decoration pdf2docx leaves behind ─────────────────────────
#
# It keeps a filled rectangle when it becomes a table cell and drops it
# otherwise, so a code block's grey panel, the darker bar down its left edge
# and a chart legend's colour squares all arrive as text on white paper. None
# of that changes what the document says, and all of it is what makes a report
# look like the PDF, so the rectangles are read out of the PDF and put back as
# paragraph shading, a paragraph border and a coloured glyph.


def hex_of(fill):
    return "%02X%02X%02X" % tuple(max(0, min(255, int(round(c * 255)))) for c in tuple(fill)[:3])


def find_decoration(doc, bands):
    """Filled rectangles the converter will drop, and the text they belong to.

    A panel is a filled rectangle with room around the text inside it. A table
    cell is a filled rectangle the text exactly fills, and pdf2docx already
    handles those, so the ratio of the rectangle's height to the tallest row
    inside it is what separates them: the reference report's cells come out at
    1.5 and its code panels at 4.2.

    A swatch is a small filled square sitting just left of a text row, which is
    how a chart legend is drawn.
    """
    member_rows = set()
    for band in bands:
        member_rows |= band.get("members") or set()
    panels, swatches = [], []
    for index in range(doc.page_count):
        page = doc[index]
        rows = [r for r in page_rows(page) if row_id(index, r) not in member_rows]
        # A table cell has neighbours: another filled rectangle sharing its
        # top and bottom (the rest of the row) or its left and right (the rest
        # of the column). A panel stands on its own. This is what separates
        # the two, because size does not: a risk matrix's cells are as tall as
        # a code block and painting one of those onto a paragraph puts a red
        # bar through a sentence. The accent bar is excluded from the test,
        # since it shares its panel's top and bottom by construction.
        wide = [d for d in page.get_drawings()
                if d.get("fill") is not None and d["rect"].width > BAR_MAX_WIDTH_PT]
        for drawing in page.get_drawings():
            fill = drawing.get("fill")
            if fill is None:
                continue
            rect = drawing["rect"]
            if PANEL_MIN_SIDE_PT <= rect.width <= SWATCH_MAX_SIDE_PT and rect.height <= SWATCH_MAX_SIDE_PT:
                # The label is the column that starts just to its right, not
                # the row: a legend puts four swatches on one line and only
                # the first of them would ever sit at the row's own left edge.
                for row in rows:
                    if row["y0"] >= rect.y1 or row["y1"] <= rect.y0:
                        continue
                    label = next((c for c in row["columns"] if 0 <= c["x0"] - rect.x1 <= SWATCH_TEXT_GAP_PT), None)
                    if label:
                        swatches.append({"fill": tuple(fill), "row": row, "label": label["text"]})
                        break
                continue
            if rect.width < PANEL_MIN_WIDTH_PT or rect.height < PANEL_MIN_HEIGHT_PT:
                continue
            if has_grid_neighbour(rect, wide):
                continue  # a table cell, which pdf2docx colours itself
            inside = [r for r in rows if r["y0"] >= rect.y0 - 1 and r["y1"] <= rect.y1 + 1
                      and r["x0"] >= rect.x0 - 1 and r["x1"] <= rect.x1 + 1]
            if not inside:
                continue
            tallest = max(r["y1"] - r["y0"] for r in inside)
            if len(inside) < 2 and rect.height < PANEL_PADDING_RATIO * tallest:
                continue  # text that exactly fills its box is a cell too
            panels.append({"fill": tuple(fill), "rows": inside, "rect": rect, "page": index, "bar": None})
    # A narrow filled rectangle hugging a panel's left edge is the accent bar.
    for index in range(doc.page_count):
        for drawing in doc[index].get_drawings():
            fill = drawing.get("fill")
            rect = drawing["rect"]
            if fill is None or rect.width > BAR_MAX_WIDTH_PT:
                continue
            for panel in panels:
                if panel["page"] != index or panel["bar"] is not None:
                    continue
                if abs(rect.x1 - panel["rect"].x0) <= 1.5 and abs(rect.y0 - panel["rect"].y0) <= 2.0:
                    # How far the bar stands off the text it runs beside. Word
                    # draws a paragraph border at the indent unless it is told
                    # otherwise, and the indent is where the text starts, so
                    # without this the bar sits inside the panel against the
                    # code rather than down the panel's own edge.
                    inset = min(row["x0"] for row in panel["rows"]) - rect.x1
                    panel["bar"] = {"fill": tuple(fill), "width": rect.width, "space": max(0.0, inset)}
    return panels, swatches


def has_grid_neighbour(rect, others):
    """Another filled rectangle beside this one in its row, or touching it in its column.

    A table cell has a row-mate beside it, or a column-mate whose top or
    bottom meets its own. Two code panels on one page share a column too,
    since both run the full width of the text, but a paragraph or two stands
    between them: on a 69-page report 69 of its 80 panels were refused for
    each other that way and came out on white. So a column-mate counts only
    when it touches, within `GRID_TOUCH_PT`.
    """
    for other in others:
        box = other["rect"]
        if abs(box.y0 - rect.y0) < 0.5 and abs(box.y1 - rect.y1) < 0.5 and abs(box.x0 - rect.x0) > 0.5:
            return True
        if (abs(box.x0 - rect.x0) < 0.5 and abs(box.x1 - rect.x1) < 0.5 and abs(box.y0 - rect.y0) > 0.5
                and (abs(box.y0 - rect.y1) <= GRID_TOUCH_PT or abs(box.y1 - rect.y0) <= GRID_TOUCH_PT)):
            return True
    return False


def fill_of_hex(value):
    """A Word fill such as "ECECEC" as (r, g, b) in 0 to 1, or None for none."""
    value = (value or "auto").strip().lstrip("#").lower()
    if value in ("auto", "", "ffffff") or len(value) != 6:
        return None
    try:
        return tuple(int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    except ValueError:
        return None


def fills_close(a, b, tolerance=FILL_MATCH_TOLERANCE):
    return a is not None and b is not None and all(abs(x - y) <= tolerance for x, y in zip(a[:3], b[:3]))


def cell_fill(cell):
    properties = cell.find(qn("w:tcPr"))
    node = properties.find(qn("w:shd")) if properties is not None else None
    return fill_of_hex(node.get(qn("w:fill"))) if node is not None else None


def paragraph_fill(element):
    properties = element.find(qn("w:pPr"))
    node = properties.find(qn("w:shd")) if properties is not None else None
    return fill_of_hex(node.get(qn("w:fill"))) if node is not None else None


def blank_or_short(element):
    """A paragraph the comparison has nothing to say about: empty, or a rule of dashes."""
    return element.tag == qn("w:p") and len(compare_squash(paragraph_text(element))) < COMPARE_MIN_CHARS


def wrapper_table(element, members):
    """The table pdf2docx wrapped this line of a panel in, or None.

    pdf2docx writes a code block's lines as tables of their own when the
    panel's bar reads to it as a rule: twelve lines become twelve tables with
    a 1 pt paragraph between each, sometimes with the bar as a narrow cell
    beside the text, sometimes two lines to a cell. The exact rows tile the
    PDF's rectangle, the spacers do not, and nothing can shade the whole. A
    table is such a wrapper when every paragraph with text in it is one of
    the panel's (`members`) or a rule of dashes, and all of them stand in one
    column of it.
    """
    cell = element.getparent()
    if cell is None or cell.tag != qn("w:tc"):
        return None
    row = cell.getparent()
    table = row.getparent() if row is not None else None
    if row is None or row.tag != qn("w:tr") or table is None or table.tag != qn("w:tbl"):
        return None
    column = None
    for tr in table.findall(qn("w:tr")):
        for index, tc in enumerate(tr.findall(qn("w:tc"))):
            for child in tc:
                if child.tag == qn("w:tbl"):
                    return None
                if child.tag != qn("w:p") or blank_spacer(child):
                    continue
                if any(child is m for m in members):
                    if column is None:
                        column = index
                    elif column != index:
                        return None
                elif not blank_or_short(child):
                    return None
    return table


def wrapper_text_column(table, members):
    """The index of the column that holds the panel's lines, and its left margin in points."""
    for tr in table.findall(qn("w:tr")):
        for index, tc in enumerate(tr.findall(qn("w:tc"))):
            if any(any(child is m for m in members) for child in tc if child.tag == qn("w:p")):
                return index
    return 0


def column_offset(table, column):
    """How far the start of `column` is from the table's left edge: the widths of the cells before it."""
    offset = 0.0
    grid = table.find(qn("w:tblGrid"))
    widths = [twips_of(node.get(qn("w:w"))) or 0.0 for node in grid.findall(qn("w:gridCol"))] if grid is not None else []
    for index in range(min(column, len(widths))):
        offset += widths[index]
    return offset


def wrapper_row_height(row):
    """A wrapper row's exact height in points, or None when Word is free to size it."""
    properties = row.find(qn("w:trPr"))
    node = properties.find(qn("w:trHeight")) if properties is not None else None
    if node is None or node.get(qn("w:hRule")) != "exact":
        return None
    return twips_of(node.get(qn("w:val")))


def table_row_height(table):
    """The exact height of a table whose rows are all exact, in points, or None."""
    heights = [wrapper_row_height(row) for row in table.findall(qn("w:tr"))]
    if not heights or any(height is None for height in heights):
        return None
    return sum(heights)


def wrapper_table_indent(table, column=0):
    """A table's indent plus the cells before `column` plus that cell's left margin, in points."""
    properties = table.find(qn("w:tblPr"))
    node = properties.find(qn("w:tblInd")) if properties is not None else None
    indent = (twips_of(node.get(qn("w:w"))) if node is not None else None) or 0.0
    indent += column_offset(table, column)
    cells = table.find(qn("w:tr")).findall(qn("w:tc"))
    cell = cells[min(column, len(cells) - 1)]
    cell_properties = cell.find(qn("w:tcPr"))
    margin = cell_properties.find(qn("w:tcMar")) if cell_properties is not None else None
    left = None
    if margin is not None:
        for name in ("w:start", "w:left"):
            side = margin.find(qn(name))
            if side is not None:
                left = twips_of(side.get(qn("w:w")))
                break
    return indent + (DEFAULT_CELL_MARGIN_PT if left is None else left)


def set_left_indent(element, points):
    properties = element.get_or_add_pPr()
    node = properties.find(qn("w:ind"))
    if node is None:
        node = OxmlElement("w:ind")
        insert_ordered(properties, node, PPR_ORDER)
    for name in ("w:start", "w:left"):
        if node.get(qn(name)) is not None or name == "w:left":
            node.set(qn(name), twips_attribute(max(0.0, points)))


def split_joined_code(elements, panel):
    """Break a paragraph that holds several of the panel's lines where the PDF broke them.

    pdf2docx joins consecutive lines of tool output into one paragraph when
    they fill the width, and Word then wraps that paragraph at the column,
    in the middle of a line, inside a cell of exact height that clips what
    does not fit. Each such paragraph gets a manual break at every one of the
    PDF's line ends, in the order the rows have. Returns how many breaks.
    """
    rows = [(row, compare_squash(row["text"])) for row in panel["rows"]]
    comparable = [(index, squashed) for index, (_, squashed) in enumerate(rows) if len(squashed) >= COMPARE_MIN_CHARS]
    added = split_glued_tail(elements, panel)
    for element in elements:
        text = compare_squash(paragraph_text(element))
        held = []
        cursor = 0
        for index, squashed in comparable:
            at = text.find(squashed, cursor)
            if at < 0:
                continue
            held.append((index, squashed))
            cursor = at + len(squashed)
        if len(held) < 2:
            continue
        # Only a paragraph that is exactly those rows in a row, nothing between.
        joined = "".join(squashed for _, squashed in held)
        if not text.endswith(joined):
            continue
        skip = len(text) - len(joined)
        # A rule of dashes under a listing's header squashes to nothing, so
        # the comparison has no end of it to cut at and its break was never
        # written: the rule and the row under it came out as one line. The
        # cuts are taken from the paragraph's own text instead, at the end
        # of every row from the first held to the last whatever it is made
        # of, and the comparison decides only when a row is not found there.
        first, last = held[0][0], held[-1][0]
        # The same is true at the other end. A rule of dashes squashes to
        # nothing, so it is never held either, and when the page breaks right
        # under it the paragraph ENDS with it: no held row follows, the range
        # stopped at the header above, and the header and the rule came out as
        # one line ("Sharename Type Comment--------- ---- -------"). In data-b
        # that was 1 of 54 such listings, the only one whose rule was the last
        # row on its page. The range runs on over every punctuation-only row
        # that the paragraph's text closes with.
        while (
            last + 1 < len(rows)
            and not rows[last + 1][1]
            and raw_row_ends(element, [rows[k][0] for k in range(first, last + 2)], to_end=True) is not None
        ):
            last += 1
        # A short first row (a prompt, "ok", a brace) proves nothing to the
        # comparison and is never held, but it is in the paragraph, and the
        # break pdf2docx put after it is about to be removed: the range
        # reaches back over every row the paragraph's own text starts with.
        while first > 0 and raw_row_ends(element, [rows[k][0] for k in range(first - 1, last + 1)]) is not None:
            first -= 1
        cuts = raw_row_ends(element, [rows[k][0] for k in range(first, last + 1)])
        # pdf2docx breaks some of the lines and joins others (a Python
        # block's "with" line and the indented call under it came out as
        # one), so its breaks are removed and every PDF line end is written.
        remove_wrapping_breaks(element)
        if cuts is not None:
            added += split_paragraph_at(element, [], raw_cuts=cuts)
        else:
            added += split_paragraph_at(element, [squashed for _, squashed in held], skip)
    return added


def remove_wrapping_breaks(element):
    """Take every line break out of a paragraph, and the runs left holding nothing else."""
    for run in list(element.iter(qn("w:r"))):
        breaks = [br for br in run.findall(qn("w:br")) if (br.get(qn("w:type")) or "textWrapping") == "textWrapping"]
        for br in breaks:
            run.remove(br)
        if breaks and run.find(qn("w:t")) is None and run.find(qn("w:tab")) is None:
            run.getparent().remove(run)


def raw_row_ends(element, rows, to_end=False):
    """Where each row's text ends in the paragraph's own text, or None when one is not there.

    The rows are matched in order with any whitespace between their words,
    because pdf2docx keeps a listing's spaces in some lines and turns them
    into tabs or an indent in others. The last row's end is not a cut. With
    `to_end` the last row must also be the last thing in the paragraph.
    """
    runs = [node for node in element.iter(qn("w:r")) if node.find(qn("w:t")) is not None]
    raw = "".join(node.find(qn("w:t")).text or "" for node in runs)
    cursor = 0
    ends = []
    for row in rows:
        words = row["text"].split()
        if not words:
            return None
        found = re.compile(r"\s*".join(re.escape(word) for word in words)).search(raw, cursor)
        if found is None or found.end() <= cursor:
            return None
        ends.append(found.end())
        cursor = found.end()
    if to_end and raw[cursor:].strip():
        return None
    return ends[:-1]


def glued_tail(key, squashed):
    """Which rows a code line carries, or None: `(first, tail)` row indices.

    `key` is the line's squashed text and `squashed` every row of the panel in
    order. The line must start with a row long enough to be compared and then
    read as nothing but the short rows that follow it in the panel.
    """
    for first, row in enumerate(squashed):
        if len(row) < COMPARE_MIN_CHARS or len(key) <= len(row) or not key.startswith(row):
            continue
        rest = key[len(row):]
        tail = []
        used = 0
        for index in range(first + 1, len(squashed)):
            short = squashed[index]
            if not short or len(short) >= COMPARE_MIN_CHARS or not rest.startswith(short, used):
                break
            tail.append(index)
            used += len(short)
            if used == len(rest):
                return first, tail
    return None


def split_glued_tail(elements, panel):
    """Put a short row pdf2docx left on the end of a code line back on a line of its own.

    A closing brace under a long JSON value came out as `"notes": "..." }`:
    the row is too short to be compared, so `split_joined_code` never cuts
    for it, and its breaks are only written for a paragraph that is exactly
    its comparable rows with nothing between them (a `},` row between two
    values fails that). Left joined, Word drew the brace after the value, and
    the row that stands at the panel's left edge, which is what pdf2docx
    indented the whole paragraph by, was not one `restore_leading_spaces`
    could see: it took the paragraph's block edge from the rows it did match
    (pdf2docx keeps one of the two spaces before a nested "}," and starts its
    box there) and put every line of the block one character (5.9 pt) left of
    the PDF, on two of the twelve stress reports. A break goes after the row
    that comes first and after each short row but the last. Returns how many.
    """
    rows = panel["rows"]
    squashed = [compare_squash(row["text"]) for row in rows]
    added = 0
    for element in elements:
        cuts = []
        offset = 0
        pieces = []
        unusual = False
        for run in element.iter(qn("w:r")):
            texts = run.findall(qn("w:t"))
            if len(texts) > 1:
                unusual = True
                break
            if texts:
                pieces.append((offset, texts[0].text or ""))
                offset += len(texts[0].text or "")
            if any((br.get(qn("w:type")) or "textWrapping") == "textWrapping" for br in run.findall(qn("w:br"))):
                pieces.append((offset, None))
        if unusual:
            continue
        lines = [[]]
        for start, text in pieces:
            if text is None:
                lines.append([])
            else:
                lines[-1].append((start, text))
        for line in lines:
            if not line:
                continue
            text = "".join(piece for _, piece in line)
            found = glued_tail(compare_squash(text), squashed)
            if found is None:
                continue
            first, tail = found
            cursor = 0
            ends = []
            for index in [first] + tail:
                words = rows[index]["text"].split()
                match = re.compile(r"\s*" + r"\s*".join(re.escape(word) for word in words)).match(text, cursor) if words else None
                if match is None:
                    ends = []
                    break
                ends.append(match.end())
                cursor = match.end()
            cuts.extend(line[0][0] + end for end in ends[:-1])
        if cuts:
            added += split_paragraph_at(element, [], raw_cuts=sorted(cuts))
    return added


def restore_leading_spaces(elements, panel):
    """Give each code line back the spaces pdf2docx turned into an indent.

    Tool output lines up its columns with spaces, and the PDF has them as
    spaces; pdf2docx writes a line that starts with spaces at an indent
    instead, so the line looks right and pastes wrong, and for a paragraph
    of several lines it writes the indent of all but the first as a hanging
    indent. Every line, the ones after a break included, gets the number of
    spaces that is its distance from the panel's left text edge over the
    width of one character, and the paragraph's indent goes back to the
    panel's, with no hanging or first-line indent left.
    """
    rows = [row for row in panel["rows"] if len(compare_squash(row["text"])) >= COMPARE_MIN_CHARS]
    if not rows:
        return 0
    left = panel_text_left(panel)
    # Measured from the letters: a row's box starts at its first space glyph
    # when its span drew its own indent, which made "- stdout" 8.1 pt a
    # character in a 5.42 pt face.
    advances = sorted((row["x1"] - ink_x0(row)) / len(row["text"].rstrip())
                      for row in rows if row["x1"] > ink_x0(row) and len(row["text"].rstrip()) >= 4)
    if not advances:
        return 0
    # One advance for the whole panel: it is one monospace face, and a short
    # row's own width over its length is the least reliable measure of it.
    advance = advances[len(advances) // 2]
    short_rows = [row for row in panel["rows"] if row not in rows]
    restored = 0
    used = set()
    for element in elements:
        lines = code_line_nodes(element)
        if not lines:
            continue
        held = []
        first_unmatched = False
        for number, nodes in enumerate(lines):
            text = "".join(node.text or "" for node in nodes)
            key = compare_squash(text)
            if not key:
                continue
            have = len(text) - len(text.lstrip(" "))
            row = next((r for r in rows if id(r) not in used and key.startswith(compare_squash(r["text"]))), None)
            if row is None:
                row = next((r for r in short_rows if id(r) not in used and key == compare_squash(r["text"])), None)
            if row is None:
                if number == 0:
                    first_unmatched = True
                continue
            used.add(id(row))
            offset = ink_x0(row) - left
            # Where pdf2docx's text for this line starts: at its letters, or
            # at the spaces before them when it kept those as text.
            held.append((row, offset - have * advance))
            wanted = max(0, int(round(offset / advance)))
            tabs = leading_tabs(nodes)
            # pdf2docx writes a nested line's indent as tab characters, which
            # Word takes to its half-inch stops: a YAML key four spaces in
            # stood 47 pt right of where the PDF has it. They go, and the
            # spaces the PDF has take their place.
            for tab in tabs:
                tab.getparent().remove(tab)
            if have == wanted and not tabs:
                continue
            # The line's own leading spaces are replaced by the PDF's count,
            # across however many runs pdf2docx split them over.
            strip = have
            for node in nodes:
                raw = node.text or ""
                take = min(strip, len(raw) - len(raw.lstrip(" ")))
                node.text = raw[take:]
                strip -= take
                if strip <= 0 or node.text:
                    break
            target = next((node for node in nodes if node.text), nodes[0])
            target.text = " " * wanted + (target.text or "")
            target.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            restored += 1
        if not held:
            continue
        # pdf2docx indents a paragraph at the left edge of its whole text
        # block, the leftmost of its lines' boxes (a box starts at its first
        # space glyph when the line drew its indent), and writes a first line
        # that stands apart as a first-line or hanging indent. The rows this
        # paragraph holds are the panel's from its first matched row to its
        # last, and a first line too short to match ("{") is the row before.
        order = panel["rows"]
        indices = sorted(order.index(row) for row, _ in held)
        first_index = indices[0] - (1 if first_unmatched and indices[0] > 0 else 0)
        span = order[first_index:indices[-1] + 1]
        starts = [start for _, start in held]
        starts += [ink_x0(row) - left for row in span if not any(row is kept for kept, _ in held)]
        block_offset = min(starts)
        # The spaces carry every line's indent now, so the paragraph's own
        # indent is the panel's text edge for all of them, with no hanging
        # or first-line indent left: the panel cell dropped a listing's
        # hanging indent (its rows lost 22 pt) and, left in place, it pushed
        # the first line in by the same amount.
        properties = element.find(qn("w:pPr"))
        node = properties.find(qn("w:ind")) if properties is not None else None
        block_left = paragraph_indent(element)
        if node is not None:
            hanging = twips_of(node.get(qn("w:hanging"))) or 0.0
            first = twips_of(node.get(qn("w:firstLine"))) or 0.0
            block_left += min(0.0, first - hanging)
            for name in ("w:hanging", "w:firstLine"):
                if node.get(qn(name)) is not None:
                    del node.attrib[qn(name)]
        set_left_indent(element, max(0.0, block_left - block_offset))
    return restored


def leading_tabs(nodes):
    """The `w:tab` elements before a line's first letter, found from its first text node's run backwards."""
    if not nodes:
        return []
    first = next((node for node in nodes if (node.text or "").strip()), None)
    if first is None:
        return []
    found = []
    run = first.getparent()
    paragraph = run.getparent()
    while paragraph is not None and paragraph.tag != qn("w:p"):
        paragraph = paragraph.getparent()
    if paragraph is None:
        return []
    for item in paragraph.iter(qn("w:t"), qn("w:tab"), qn("w:br")):
        if item is first:
            break
        if item.tag == qn("w:tab") and item.getparent().tag != qn("w:r"):
            # A tab STOP, `w:pPr/w:tabs/w:tab`, is the same element name as
            # the tab character and comes before every letter of the
            # paragraph. Counted as a leading tab it was removed with them,
            # and the tab after a heading's number (the "6.1.2" of a finding's
            # title) fell to Word's own stops, 9 pt right of the PDF's, so the
            # title's first line wrapped one word early and its fourth line
            # was cut off by the banner's exact height.
            continue
        if item.tag == qn("w:br"):
            found = []
        elif item.tag == qn("w:tab"):
            found.append(item)
        elif (item.text or "").strip():
            found = []
    return found


def code_line_nodes(element):
    """The `w:t` nodes of each line of a paragraph, lines split at its text-wrapping breaks."""
    lines = [[]]
    for run in element.iter(qn("w:r")):
        for child in run:
            if child.tag == qn("w:t"):
                lines[-1].append(child)
            elif child.tag == qn("w:br") and (child.get(qn("w:type")) or "textWrapping") == "textWrapping":
                lines.append([])
    return [nodes for nodes in lines if nodes]


def gather_panel_blocks(elements, panel):
    """The blocks a panel's paragraphs sit in, as one clean run, or None.

    Each paragraph is a block of its own, or the one-cell table pdf2docx
    wrapped it in when that cell is bare or carries the panel's own colour
    (pdf2docx colours the cells it recognised, and a cell in the panel's
    grey is the panel). A paragraph or cell in any other colour is something
    else's, and the panel is left alone. Every block must have one parent,
    and between the first and the last only blank spacers may stand.

    Returns `(run, occupied)`: the parent's children from the first block to
    the last, spacers included, and the height they take up in the flow,
    which is what a panel table may replace without the page gaining a line.
    """
    blocks = []
    for element in elements:
        own = paragraph_fill(element)
        if own is not None and not fills_close(own, panel["fill"]):
            return None
        table = wrapper_table(element, elements)
        if table is not None:
            fill = cell_fill(element.getparent())
            if fill is not None and not fills_close(fill, panel["fill"]) and not (
                    panel.get("bar") and fills_close(fill, panel["bar"]["fill"])):
                return None
            if not any(table is block for block in blocks):
                blocks.append(table)
        else:
            blocks.append(element)
    parent = blocks[0].getparent()
    if parent is None or any(block.getparent() is not parent for block in blocks):
        return None
    order = list(parent)
    start, end = order.index(blocks[0]), order.index(blocks[-1])
    if start > end:
        return None
    run = order[start:end + 1]
    occupied = 0.0
    last_after = 0.0
    for node in run:
        if any(node is block for block in blocks):
            if node.tag == qn("w:tbl"):
                height = table_row_height(node)
                if height is None:
                    return None
                occupied += height
                last_after = 0.0
            else:
                metrics = paragraph_metrics(node)
                if metrics is None:
                    return None
                occupied += metrics["before"] + metrics["lines"] * metrics["line"]
                last_after = metrics["after"]
        elif blank_spacer(node):
            occupied += paragraph_metrics(node)["line"]
        elif blank_or_short(node) and paragraph_metrics(node) is not None:
            # A rule of dashes between two lines: a row of the panel that the
            # comparison could not name, so it was never matched.
            metrics = paragraph_metrics(node)
            occupied += metrics["before"] + metrics["lines"] * metrics["line"]
            last_after = metrics["after"]
        elif node.tag == qn("w:tbl") and wrapper_table(next((p for p in node.iter(qn("w:p")) if not blank_spacer(p)), node), elements) is node \
                and table_row_height(node) is not None:
            occupied += table_row_height(node)
            last_after = 0.0
        else:
            return None
    return run, occupied + last_after


def unwrap_panel_blocks(run):
    """Turn a run of blocks into consecutive paragraphs, keeping every line's pitch.

    A paragraph wrapped in a one-cell table of exact height h sat at that
    table's top, and the next line's top was h below it. On its own the
    paragraph is only its line box, so whatever of h its lines did not use
    goes into the spacing before the paragraph that follows, which keeps the
    baselines where the rows had them even before the vertical pass runs.
    The table's indent and the cell's left margin go into the paragraph's
    own indent, so the text keeps its x. Spacers are removed. Returns the
    paragraphs, in order, and the height of the rows that stayed tables.
    """
    elements = []
    carry = 0.0
    kept_height = 0.0
    for node in list(run):
        if node.tag == qn("w:tbl"):
            texts = [p for p in node.iter(qn("w:p")) if not blank_spacer(p)]
            column = wrapper_text_column(node, texts)
            shift = wrapper_table_indent(node, column)
            kept = []
            tail = node
            for row in node.findall(qn("w:tr")):
                height = wrapper_row_height(row) or 0.0
                cells = row.findall(qn("w:tc"))
                cell = cells[min(column, len(cells) - 1)]
                if (any(cell_has_content(other) for other in cells if other is not cell)
                        or any(True for _ in cell.iter(qn("w:drawing")))
                        or any(child.tag == qn("w:tbl") for child in cell)):
                    # pdf2docx put two screenshots side by side in a row of
                    # the same table as the panel's last line, and one alone
                    # in the column's own cell. The row is not the panel's:
                    # it stays, as a table of its own, where removing the
                    # table with the lines lost three pictures of an 86-page
                    # report.
                    kept.append(row)
                    continue
                paragraphs = [child for child in cell if child.tag == qn("w:p") and not blank_spacer(child)]
                used = 0.0
                for paragraph in paragraphs:
                    metrics = paragraph_metrics(paragraph) or {"before": 0.0, "line": 0.0, "lines": 1}
                    before = metrics["before"] + carry
                    carry = 0.0
                    set_spacing(paragraph, before=before)
                    used += before + metrics["lines"] * metrics["line"]
                    set_left_indent(paragraph, paragraph_indent(paragraph) + shift)
                    shift_tab_stops(paragraph, shift)
                    if kept:
                        # A line under a kept row follows it, as the PDF has it.
                        tail.addnext(paragraph)
                        tail = paragraph
                    else:
                        node.addprevious(paragraph)
                    elements.append(paragraph)
                carry += max(0.0, height - used)
            if kept:
                for row in node.findall(qn("w:tr")):
                    if not any(row is keep for keep in kept):
                        node.remove(row)
                kept_height += sum(wrapper_row_height(row) or 0.0 for row in kept)
                carry = 0.0
            else:
                node.getparent().remove(node)
        elif blank_spacer(node):
            carry += paragraph_metrics(node)["line"]
            node.getparent().remove(node)
        else:
            if carry:
                metrics = paragraph_metrics(node)
                set_spacing(node, before=(metrics["before"] if metrics else 0.0) + carry)
                carry = 0.0
            elements.append(node)
    return elements, kept_height


def cell_has_content(cell):
    """Text, a picture or a table inside a cell."""
    return (any((node.text or "").strip() for node in cell.iter(qn("w:t")))
            or any(True for _ in cell.iter(qn("w:drawing")))
            or any(child.tag == qn("w:tbl") for child in cell))


def ink_x0(row):
    """Where a row's first letter stands, past any indent its span drew as space glyphs."""
    return row.get("inkX0", row["x0"])


def panel_text_left(panel):
    """Where a panel's text column starts on the page: its settled edge, else its leftmost row."""
    return panel.get("textLeft", min(ink_x0(row) for row in panel["rows"]))


def settle_panel_text_left(panels):
    """Give each panel the text edge its document's panels share when its own rows are all indented.

    A listing that runs onto a new page continues there in a panel of its
    own whose every row starts four spaces in, so its leftmost row is not its
    text edge: taken for one, the panel table stood 22 pt right of every other
    panel in its finding card and ran 12 pt past the card's right edge, and
    its rows lost their four spaces. Most panels have a row at their edge, so
    the padding they share (the most common distance from the panel's left
    edge to its leftmost row) is the edge; a panel whose leftmost row stands
    a whole number of characters further in than that is given it. Returns
    how many panels were settled.
    """
    paddings = Counter()
    for panel in panels:
        if panel["rows"]:
            paddings[round(min(ink_x0(row) for row in panel["rows"]) - panel["rect"].x0, 1)] += 1
    if not paddings:
        return 0
    common, seen = paddings.most_common(1)[0]
    if seen < 2:
        return 0
    settled = 0
    for panel in panels:
        rows = [row for row in panel["rows"] if len(row["text"].rstrip()) >= 4 and row["x1"] > ink_x0(row)]
        if not rows:
            continue
        advance = sorted((row["x1"] - ink_x0(row)) / len(row["text"].rstrip()) for row in rows)[len(rows) // 2]
        extra = min(ink_x0(row) for row in panel["rows"]) - panel["rect"].x0 - common
        if advance <= 0 or extra < advance - PANEL_EDGE_FIT_PT:
            continue
        characters = round(extra / advance)
        if characters < 1 or abs(extra - characters * advance) > PANEL_EDGE_FIT_PT:
            continue
        panel["textLeft"] = panel["rect"].x0 + common
        if panel.get("bar"):
            panel["bar"]["space"] = max(0.0, panel["textLeft"] - panel["rect"].x0 - panel["bar"]["width"])
        settled += 1
    return settled


# How far a panel's leftmost row may be from a whole number of characters past
# the common padding and still be read as indented by that many.
PANEL_EDGE_FIT_PT = 1.0


def panel_padding(panel):
    """The room the PDF leaves between a panel's edges and the text inside it.

    The right one cannot be measured when no line reaches the right edge,
    which on a code panel is every line, so the left padding stands in for
    it: a panel is padded the same on both sides or the text would not start
    where it does.
    """
    rows = panel["rows"]
    rect = panel["rect"]
    return (max(0.0, panel_text_left(panel) - rect.x0),
            max(0.0, min(row["y0"] for row in rows) - rect.y0),
            max(0.0, rect.y1 - max(row["y1"] for row in rows)))


def paragraph_indent(element):
    """How far a paragraph is indented from whatever contains it, in points."""
    properties = element.find(qn("w:pPr"))
    node = properties.find(qn("w:ind")) if properties is not None else None
    if node is None:
        return 0.0
    for name in ("w:start", "w:left"):
        value = twips_of(node.get(qn(name)))
        if value is not None:
            return value
    return 0.0


def shift_tab_stops(element, points):
    """Move every tab stop of a paragraph by `points`, dropping one that would fall before the text area.

    A stop is measured from the left edge of the paragraph's container, not
    from its indent. When the converter moves a paragraph into another
    container and carries its x across as an indent or a cell margin, the
    stops have to move by the same amount or a tab lands where the old
    container's edge would have put it.
    """
    properties = element.find(qn("w:pPr"))
    stops = properties.find(qn("w:tabs")) if properties is not None else None
    if stops is None or not points:
        return
    for stop in list(stops):
        place = twips_of(stop.get(qn("w:pos")))
        if place is None:
            continue
        moved = place + points
        if moved <= 0:
            stops.remove(stop)
        else:
            stop.set(qn("w:pos"), twips_attribute(moved))


def strip_paragraph_frame(element):
    """Drop a paragraph's own indent, fill and borders.

    They were the panel before this, and the cell is the panel now: leaving
    them in indents the code a second time and paints a second rectangle
    inside the first.
    """
    properties = element.get_or_add_pPr()
    for name in ("w:ind", "w:shd", "w:pBdr"):
        for node in properties.findall(qn(name)):
            properties.remove(node)


def pushed_alignment(element):
    """Whether pdf2docx centred or right-aligned a paragraph (not a right-to-left one, where right means start)."""
    properties = element.find(qn("w:pPr"))
    if properties is None or properties.find(qn("w:bidi")) is not None:
        return False
    node = properties.find(qn("w:jc"))
    return node is not None and node.get(qn("w:val")) in ("center", "right", "end")


# How far a row's middle (or right end) may be from the panel's own middle (or
# right padding) and still be read as centred (or right-aligned) there. A
# character of code is 4.5 pt; typst centres to a fraction of a point.
PANEL_ALIGN_FIT_PT = 3.0


def panel_rows_of(paragraph, panel):
    """The panel's rows whose text this paragraph holds (a row too short to prove anything must equal it)."""
    text = compare_squash(paragraph_text(paragraph))
    found = []
    for row in panel["rows"]:
        key = compare_squash(row["text"])
        if key and (key == text or (len(key) >= COMPARE_MIN_CHARS and key in text)):
            found.append(row)
    return found


def row_aligned_in_panel(row, panel):
    """Whether the PDF itself centres this row in its panel's text area, or sets it against the right padding.

    The text area runs from the panel's text edge to the same padding
    short of the right edge (the left padding stands in for the right one,
    which no code line reaches). A row that starts at the edge, or stands
    further in with no symmetry (an indented line of code), is not aligned:
    it is only where its spaces put it.
    """
    rect = panel["rect"]
    edge = panel_text_left(panel)
    bar = (panel["bar"] or {}).get("width") or 0.0
    right = rect.x1 - max(0.0, edge - rect.x0 - bar)
    start, end = ink_x0(row), row.get("x1", ink_x0(row))
    if start - edge <= PANEL_ALIGN_FIT_PT:
        return False
    return (abs((start + end) / 2.0 - (edge + right) / 2.0) <= PANEL_ALIGN_FIT_PT
            or abs(end - right) <= PANEL_ALIGN_FIT_PT)


def drifted_alignment(element, panel):
    """Whether pdf2docx centred or right-aligned a code line that the PDF sets at its panel's text edge or indents.

    A code line starts at its panel's text edge in the PDF (leading spaces
    are text, restored as such), so a line pdf2docx aligned any other way is
    a short line it read as sitting in the middle or at the right of its
    block: in design-b1 the first line of a terminal window (centred, its
    indent 10 pt short of the others') and a wrapped tail such as
    "(signing:False)" (right-aligned), 26 lines of the 473 in all that Word
    drew up to 230 pt right of the PDF's. A line the PDF itself centres (a
    title in a shaded box) keeps the alignment, and so does one whose row
    cannot be found, since nothing says it is wrong.
    """
    if not pushed_alignment(element):
        return False
    rows = panel_rows_of(element, panel)
    return bool(rows) and not all(row_aligned_in_panel(row, panel) for row in rows)


def twips_attribute(value):
    return str(int(round(value * 20)))


def keep_paragraph_around(table):
    """A table needs a paragraph either side of it.

    Two tables that touch are one table to Word, and a cell or a body that
    ends in a table is not a file Word will open.
    """
    for neighbour, place in ((table.getprevious(), table.addprevious),
                             (table.getnext(), table.addnext)):
        if neighbour is None or neighbour.tag != qn("w:p"):
            spacer = OxmlElement("w:p")
            set_spacing(spacer, before=0.0, after=0.0, line=SPACER_LINE_PT)
            place(spacer)


def panel_cell(width, fill, margins=None):
    """One cell of a panel table: a width, a colour and its inner margins."""
    cell = OxmlElement("w:tc")
    settings = OxmlElement("w:tcPr")
    node = OxmlElement("w:tcW")
    node.set(qn("w:w"), twips_attribute(width))
    node.set(qn("w:type"), "dxa")
    settings.append(node)
    shade = OxmlElement("w:shd")
    shade.set(qn("w:val"), "clear")
    shade.set(qn("w:color"), "auto")
    shade.set(qn("w:fill"), hex_of(fill))
    settings.append(shade)
    inner = OxmlElement("w:tcMar")
    # Top and bottom stay at nothing on purpose. A cell's fill covers the
    # whole cell, spacing and all, so the panel's padding above and below the
    # code is the spacing the vertical pass writes; and Word grows an exact
    # row by the bottom margin it is given, which measured 4.7 pt of panel
    # that the PDF does not have.
    for name, value in (("w:top", 0.0), ("w:start", margins or 0.0),
                        ("w:bottom", 0.0), ("w:end", margins or 0.0)):
        node = OxmlElement(name)
        node.set(qn("w:w"), twips_attribute(value))
        node.set(qn("w:type"), "dxa")
        inner.append(node)
    settings.append(inner)
    cell.append(settings)
    return cell


def build_panel_table(panel, elements, occupied=None):
    """Put a panel's paragraphs inside a table shaped like the panel.

    Word fills a shaded paragraph between its indents and over its line boxes
    only, never over its spacing, measured on five cases. So no paragraph can
    carry a panel's padding: the grey hugs the text on all four sides while
    the PDF leaves room above it, below it and to the left. A table can, and
    it can carry the accent bar as well, as a narrow cell of its own in the
    bar's colour, which is how PyMuPDF reads that panel out of the PDF too. A
    cell's fill covers everything inside the cell, so the padding is whatever
    spacing the code ends up with.

    The code does not move, and the left edge of whatever contains the panel
    does not have to be known for that, which is what defeated the earlier
    attempt on a panel inside a finding card. The indent the converter gave
    the code is spent on the table's indent, the bar's cell and the text
    cell's left margin, and those three add up to the same number.

    Returns `(table, top, was_height)`, or None when the panel cannot be
    placed confidently, in which case the caller shades the paragraphs the
    way it used to. `occupied` is the height the paragraphs took up before,
    when the caller knows it better (they were rows of exact height); else
    it is added up from their spacing.
    """
    parent = elements[0].getparent()
    if parent is None or any(node.getparent() is not parent for node in elements):
        return None
    order = list(parent)
    start = order.index(elements[0])
    if order[start:start + len(elements)] != elements:
        return None   # something else of the page's is in among them
    metrics = [paragraph_metrics(node) for node in elements]
    if any(item is None for item in metrics):
        return None
    rect = panel["rect"]
    left, top, bottom = panel_padding(panel)
    bar = panel["bar"] or {}
    width = bar.get("width") or 0.0
    height = rect.y1 - rect.y0
    inside = rect.x1 - rect.x0
    # The table replaces the paragraphs in the flow, so it may not be taller
    # than they were or a page could gain a line and the document a page.
    if occupied is None:
        occupied = sum(item["before"] + item["lines"] * item["line"] for item in metrics) + metrics[-1]["after"]
    # pdf2docx joins the lines of a block it reads as one paragraph, so the
    # paragraphs can read a few lines shorter than the rectangle; the table
    # is the PDF's own height, which is what the page was laid out for.
    if height <= 0 or inside <= left or height > occupied + PANEL_GROW_PT:
        return None
    # Word takes a negative table indent (the table hangs into the margin),
    # which is what pdf2docx's smaller indent asks for; only an indent that
    # would put the panel's bar off the page is refused.
    # The first paragraph pdf2docx left aligned gives the indent: a centred
    # or right-aligned one carries the indent of the window it was centred or
    # pushed right in, 10 pt short of the code's own (design-b1's terminal
    # windows, whose first line pdf2docx centred), so the table, its text
    # and the whole panel stood that far left.
    anchor = next((node for node in elements if not pushed_alignment(node) and paragraph_text(node).strip()),
                  elements[0])
    inset = paragraph_indent(anchor) - (width + left)
    if inset < -TABLE_HANG_PT:
        return None

    table = OxmlElement("w:tbl")
    properties = OxmlElement("w:tblPr")
    # Word (compatibility mode 14, which this file declares) puts a body
    # table's EDGE the first cell's left margin before tblInd, so the TEXT stands at
    # tblInd whatever the margin is. A panel with an accent bar has the bar's
    # cell, which has no margin, first, so its edge is tblInd; one without a
    # bar has its text cell first and needs the margin added back or the whole
    # panel stands that far left. Measured on a numbered listing (12.0 pt,
    # the text cell's margin), then on every bar-less panel of design-b1 and
    # design-b2, a terminal window with no accent bar: 10.0 pt and 9.0 pt left
    # of the PDF's, panel edge and text alike. Only for a table that stands in
    # the body: the nine bar-less panels of design-a2 that stand in a table's
    # cell were drawn where tblInd says, and with the margin added they stood
    # 8.9 pt right of the PDF's.
    edge = inset + (left if width <= 0 and parent.tag == qn("w:body") else 0.0)
    for name, attributes in (("w:tblW", {"w:w": twips_attribute(width + inside), "w:type": "dxa"}),
                             ("w:tblInd", {"w:w": twips_attribute(edge), "w:type": "dxa"}),
                             ("w:tblLayout", {"w:type": "fixed"})):
        node = OxmlElement(name)
        for key, value in attributes.items():
            node.set(qn(key), value)
        properties.append(node)
    table.append(properties)
    grid = OxmlElement("w:tblGrid")
    for column in ([width, inside] if width > 0 else [inside]):
        node = OxmlElement("w:gridCol")
        node.set(qn("w:w"), twips_attribute(column))
        grid.append(node)
    table.append(grid)

    row = OxmlElement("w:tr")
    span = OxmlElement("w:trHeight")
    span.set(qn("w:hRule"), "exact")
    span.set(qn("w:val"), twips_attribute(height))
    holder = OxmlElement("w:trPr")
    holder.append(span)
    row.append(holder)
    if width > 0:
        stripe = panel_cell(width, bar["fill"])
        empty = OxmlElement("w:p")
        set_spacing(empty, before=0.0, after=0.0, line=SPACER_LINE_PT)
        stripe.append(empty)
        row.append(stripe)
    cell = panel_cell(inside, panel["fill"], left)
    row.append(cell)
    table.append(row)

    elements[0].addprevious(table)
    for node in elements:
        cell.append(node)
        # The cell's text area starts where the paragraph's indent edge was.
        shift_tab_stops(node, -paragraph_indent(node))
        strip_paragraph_frame(node)
        if drifted_alignment(node, panel):
            # Code is left-aligned in the PDF; in the cell a right-aligned
            # line would run to the cell's right edge.
            node.get_or_add_pPr().find(qn("w:jc")).set(qn("w:val"), "left")
    keep_paragraph_around(table)
    # The top edge the PDF drew, and the height the paragraphs used to take
    # up. The vertical pass needs both: the first to put the panel where the
    # PDF has it, the second so that everything under it keeps the place the
    # converter gave it rather than rising by the difference.
    return table, rect.y0, occupied


def paragraph_pages(document, page_count):
    """Which page each paragraph of the body is on, by id, or None.

    pdf2docx writes one section per page, with the break in the last
    paragraph of each. When the sections add up to the PDF's pages, every
    paragraph (those inside tables included) can be given its page, which is
    what keeps a text match on one page: the same command appears in every
    finding of a report, and a search that may run ahead to the next page
    lands on the wrong copy and never comes back.
    """
    body = document.element.body
    holders = page_ends(body)
    ends = {id(holder) for holder in holders}
    pages = {}
    page = 0
    for child in body:
        if child.tag == qn("w:p"):
            pages[id(child)] = page
        else:
            for paragraph in child.iter(qn("w:p")):
                pages[id(paragraph)] = page
        if id(child) in ends:
            page += 1
    return pages if page_count and page == page_count else None


def split_line_numbers(panel):
    """The panel as its code alone when every row belongs to a numbered listing, else None.

    Typst draws a numbered listing as two columns, and pdf2docx writes it as
    a table of two cells: the numbers in one paragraph, the code in the
    other. The panel's rows read "1 $ nmap ..." with the number glued on, so
    no row was ever found in a paragraph and the four numbered panels of a
    42-page report stayed pdf2docx's table, 25 pt narrower than the PDF's
    rectangle with the gutter a cell of its own. The rows of the returned
    copy are the code columns, which is what the paragraphs hold; `gutter`
    carries the numbers and where the column stands. Only a panel whose rows
    start with a number, counting up by one, in the same font as the code
    beside it: a numbered list of prose does not.

    Two kinds of row have no code column and still belong. A blank code line
    is a row with its number alone (an HTTP request has one between its
    headers and its body), and a line typst wrapped continues on a row with no
    number at all, which starts at the block's edge, left of the code column,
    because the number is a box inside the first line. A listing with either
    came back None before and stayed two or three of pdf2docx's tables, with
    the body of a request standing beside the wrong number. `gutter["lines"]`
    has one entry per line the PDF draws, in order: its number (None for a
    continuation), whether the line is blank and, for a continuation, whether
    it starts at the code column (`atCode`). A number-only row is not in
    the returned rows, since it has no text to find; a continuation is, and
    `gutter["continued"]` names those row objects.

    Where a continuation starts says how the numbers were drawn. A number in
    a box inside the first line (a `show raw.line` rule) leaves the wrapped
    rest at the block's edge, left of the code column. A number in a column
    of its own (a `grid`) leaves it in the code column: numbers2.typ measured
    the ink at 100.75 against a code column at 100.7 and a gutter at 88.1, and
    the fold wrote such a line at the paragraph's edge, 12.6 pt left of the
    PDF's, under the numbers.
    """
    rows = panel["rows"]
    if len(rows) < 3:
        return None

    def starts_with_number(columns):
        return bool(columns) and re.fullmatch(r"[0-9]{1,6}", columns[0]["text"]) is not None

    def numbered(row):
        columns = row.get("columns") or []
        return len(columns) >= 2 and starts_with_number(columns)

    with_code = [row for row in rows if numbered(row)]
    if len(with_code) < 2 or not numbered(rows[0]):
        return None
    if any(row["columns"][0]["font"] != row["columns"][1]["font"] for row in with_code):
        return None
    code_left = min(row["columns"][1]["inkX0"] for row in with_code)
    numbers, code, lines, continued, values = [], [], [], [], []
    for row in rows:
        columns = row.get("columns") or []
        if numbered(row):
            number = int(columns[0]["text"])
            if values and number != values[-1] + 1:
                return None
            values.append(number)
            numbers.append(columns[0])
            rest = columns[1:]
            code.append(dict(row, columns=rest, text=" ".join(c["text"] for c in rest),
                             x0=rest[0]["x0"], inkX0=rest[0]["inkX0"]))
            lines.append({"number": columns[0]["text"], "blank": False})
        elif len(columns) == 1 and starts_with_number(columns) and columns[0]["x1"] < code_left:
            # A number alone in the gutter is a blank code line, and only
            # the next number counts as one.
            number = int(columns[0]["text"])
            if not values or number != values[-1] + 1:
                return None
            values.append(number)
            numbers.append(columns[0])
            lines.append({"number": columns[0]["text"], "blank": True})
        elif values and ink_x0(row) <= code_left + 1.0:
            code.append(row)
            continued.append(row)
            lines.append({"number": None, "blank": False, "atCode": ink_x0(row) >= code_left - 1.0})
        else:
            return None
    gutter = {"numbers": [column["text"] for column in numbers],
              "lines": lines,
              "continued": continued,
              "left": min(column["x0"] for column in numbers),
              "right": max(column["x1"] for column in numbers),
              "codeLeft": code_left,
              "reach": min((ink_x0(row) for row in continued), default=None)}
    if gutter["right"] >= code_left:
        return None
    return dict(panel, rows=code, gutter=gutter)


def listing_blocks(found):
    """The body-level blocks a numbered listing was written as, sorted into its numbers and its code.

    pdf2docx makes a table of a number cell and a code cell, and starts a new
    table where the listing has a blank line or a wrapped one: the request
    "headers, blank line, body" came out as two tables, and a wrapped curl
    line as three, one of them a single cell and one a row of code alone
    above rows of a number beside its code. So the listing is every block
    from the first table the panel's rows were found in to the last, which
    may hold only tables and spacers (and body paragraphs the rows matched),
    each row of them one cell of code or a cell of numbers then a cell of
    code.

    Returns `(run, side, code)`, or None when the blocks are anything else.
    `run` is the body's children from the first block to the last, `side`
    the number paragraphs in order and `code` the code paragraphs in order,
    each with the distance its cell's text edge stood from the body's margin
    (the table's indent, the number cell before it and its own left margin).
    """
    tops = []
    for element in found:
        top = element
        while top.getparent() is not None and top.getparent().tag != qn("w:body"):
            top = top.getparent()
        if top.getparent() is None:
            return None
        if not any(top is seen for seen in tops):
            tops.append(top)
    body = tops[0].getparent()
    if any(top.getparent() is not body for top in tops):
        return None
    order = list(body)
    indices = sorted(order.index(top) for top in tops)
    run = order[indices[0]:indices[-1] + 1]
    side, code = [], []
    for block in run:
        if block.tag == qn("w:p"):
            if blank_spacer(block):
                continue
            if not any(block is element for element in found):
                return None
            code.append((block, 0.0))
            continue
        if block.tag != qn("w:tbl"):
            return None
        properties = block.find(qn("w:tblPr"))
        node = properties.find(qn("w:tblInd")) if properties is not None else None
        indent = (twips_of(node.get(qn("w:w"))) if node is not None else None) or 0.0
        for row in block.findall(qn("w:tr")):
            cells = row.findall(qn("w:tc"))
            if len(cells) not in (1, 2) or any(child.tag == qn("w:tbl") for cell in cells for child in cell):
                return None
            shift = indent
            for index, cell in enumerate(cells):
                widths = cell.find(qn("w:tcPr"))
                width = widths.find(qn("w:tcW")) if widths is not None else None
                if width is None or twips_of(width.get(qn("w:w"))) is None:
                    return None
                paragraphs = [child for child in cell if child.tag == qn("w:p") and not blank_spacer(child)]
                if len(cells) == 2 and index == 0:
                    shift += twips_of(width.get(qn("w:w")))
                    side.extend(paragraphs)
                    continue
                margin = None
                spacing = widths.find(qn("w:tcMar"))
                for name in ("w:start", "w:left"):
                    side_margin = spacing.find(qn(name)) if spacing is not None else None
                    if side_margin is not None:
                        margin = twips_of(side_margin.get(qn("w:w")))
                        break
                code.extend((paragraph, shift + (DEFAULT_CELL_MARGIN_PT if margin is None else margin))
                            for paragraph in paragraphs)
    return (run, side, code) if code and side else None


def fold_line_numbers(found, panel):
    """Move a numbered listing's code out of pdf2docx's tables, each line carrying its number.

    The listing is one or more tables of `[numbers | code]` rows (see
    `listing_blocks`). Every code paragraph is copied, given the indent its
    cell and table gave it, split at the PDF's line ends and given its spaces
    back like any other code, and the copies are joined into one paragraph,
    the lines in the order the PDF has them. Then every line that has a
    number starts with a tab, that number (the runs pdf2docx wrote, so the
    colour and size are the PDF's) and a tab: a right stop where the numbers
    end, a left stop where the code begins, both measured from the PDF's own
    columns. A blank code line is the same line with nothing after the second
    tab, and a continuation is the code alone, at the paragraph's own edge,
    which is where the PDF starts it when the numbers were boxes inside the
    first line; when they were a column of their own the PDF starts it at the
    code column, so the line begins with two tabs (the first runs to the right
    stop, over nothing, the second to the code's stop). The paragraph is then
    a plain code paragraph and the panel table is built round it like any
    other, one cell the size of the rectangle with the border.

    Lines are paired with the PDF's rows by position, and the count is made
    before anything is built, on copies: the numbers that were read must be
    the PDF's, the code must have exactly the PDF's lines that have text, and
    the cells must be what `listing_blocks` expects, or the answer is None
    and the document is exactly as it was found. Otherwise the new paragraph
    stands where the first table stood, the tables are gone, and it is
    returned.
    """
    gutter = panel["gutter"]
    parts = listing_blocks(found)
    if parts is None:
        return None
    run, side, code = parts
    marks, numbers = [], []
    for paragraph in side:
        for line in code_line_nodes(paragraph):
            marks.append("".join(node.text or "" for node in line).strip())
            # The numbers' runs, with the trailing space pdf2docx leaves after
            # each taken off: the right stop would otherwise end the number a
            # space before the PDF's.
            runs = []
            for text_node in line:
                piece = copy.deepcopy(text_node.getparent())
                for inner in piece.findall(qn("w:t")):
                    inner.text = (inner.text or "").strip()
                if piece.find(qn("w:t")).text:
                    runs.append(piece)
            numbers.append(runs)
    if marks != gutter["numbers"] or any(not runs for runs in numbers):
        return None
    # The work is done on copies from here, so a refusal leaves the document alone.
    text_left = panel["textLeft"] if "textLeft" in panel else gutter["codeLeft"]
    pieces = []
    for paragraph, shift in code:
        piece = copy.deepcopy(paragraph)
        set_left_indent(piece, paragraph_indent(piece) + shift)
        shift_tab_stops(piece, shift)
        pieces.append(piece)
    # The helpers measure a line's spaces from the code column, so a
    # continuation, which starts left of it, is not one of their rows.
    carried = [row for row in panel["rows"] if not any(row is kept for kept in gutter["continued"])]
    local = dict(panel, rows=carried, textLeft=text_left)
    split_joined_code(pieces, local)
    restore_leading_spaces(pieces, local)
    lines, breaks, owners = [], [], []
    for piece in pieces:
        current = []
        for item in piece.findall(qn("w:r")):
            stop = item.find(qn("w:br"))
            if stop is not None and (item.find(qn("w:t")) is not None or item.find(qn("w:tab")) is not None):
                return None
            if stop is not None and (stop.get(qn("w:type")) or "textWrapping") == "textWrapping":
                lines.append(current)
                breaks.append(item)
                owners.append(piece)
                current = []
            else:
                current.append(item)
        if current:
            lines.append(current)
            breaks.append(None)
            owners.append(piece)
    if (any(not any(item.find(qn("w:t")) is not None for item in line) for line in lines)
            or len(lines) != sum(len(code_line_nodes(piece)) for piece in pieces)
            or len(lines) != sum(1 for entry in gutter["lines"] if not entry["blank"])):
        return None
    base = pieces[0]
    left = paragraph_indent(base)
    start = left - (text_left - gutter["left"])
    if gutter.get("reach") is not None:
        start = min(start, left - (text_left - gutter["reach"]))
    if start < 0.0:
        return None

    def tab_run(like):
        item = OxmlElement("w:r")
        format_node = like.find(qn("w:rPr"))
        if format_node is not None:
            item.append(copy.deepcopy(format_node))
        item.append(OxmlElement("w:tab"))
        return item

    template = next((item for item in breaks if item is not None), None)
    built = []
    at = 0
    counted = 0
    for entry in gutter["lines"]:
        if entry["blank"]:
            first = numbers[counted][0]
            built.append(([tab_run(first)] + numbers[counted] + [tab_run(first)], None))
            counted += 1
            continue
        line, owner = lines[at], owners[at]
        if entry["number"] is not None:
            # Lines that carry a number all stand in cells at the same edge.
            if abs(paragraph_indent(owner) - left) > 1.5:
                return None
            place = next(i for i, item in enumerate(line)
                         if item.find(qn("w:t")) is not None or item.find(qn("w:tab")) is not None)
            first = numbers[counted][0]
            line = line[:place] + [tab_run(first)] + numbers[counted] + [tab_run(first)] + line[place:]
            counted += 1
        elif entry.get("atCode"):
            place = next(i for i, item in enumerate(line)
                         if item.find(qn("w:t")) is not None or item.find(qn("w:tab")) is not None)
            first = line[place]
            line = line[:place] + [tab_run(first), tab_run(first)] + line[place:]
        built.append((line, breaks[at]))
        at += 1
    if counted != len(numbers):
        return None
    for piece in pieces:
        for item in piece.findall(qn("w:r")):
            piece.remove(item)
    for position, (line, stop) in enumerate(built):
        for item in line:
            base.append(item)
        if stop is None and position < len(built) - 1:
            if template is not None:
                stop = copy.deepcopy(template)
            else:
                stop = OxmlElement("w:r")
                format_node = line[0].find(qn("w:rPr"))
                if format_node is not None:
                    stop.append(copy.deepcopy(format_node))
                stop.append(OxmlElement("w:br"))
        if stop is not None:
            base.append(stop)
    properties = base.get_or_add_pPr()
    stops = properties.find(qn("w:tabs"))
    if stops is None:
        stops = OxmlElement("w:tabs")
        insert_ordered(properties, stops, PPR_ORDER)
    for kind, place in (("right", left - (text_left - gutter["right"])), ("left", left)):
        stop = OxmlElement("w:tab")
        stop.set(qn("w:val"), kind)
        stop.set(qn("w:pos"), twips_attribute(place))
        stops.append(stop)
    # Word reads a paragraph's stops in the order written and a stop out of
    # order is lost: pdf2docx's own stops for a listing's indented lines
    # (776 and 882 twips) sat ahead of the two new ones, so the first tab of
    # every line went to 776 and the whole listing stood 38.6 pt right of its
    # rectangle's text edge, numbers and code alike.
    for node in sorted(stops.findall(qn("w:tab")), key=lambda tab: twips_of(tab.get(qn("w:pos"))) or 0.0):
        stops.append(node)
    set_left_indent(base, start)
    # The tables' exact rows are what the listing used to take up in the flow,
    # and what a panel table the PDF's height may replace.
    height = 0.0
    for block in run:
        if block.tag == qn("w:tbl"):
            heights = [wrapper_row_height(row) for row in block.findall(qn("w:tr"))]
            if any(item is None for item in heights):
                height = None
                break
            height += sum(heights)
        elif blank_spacer(block):
            spacer = paragraph_metrics(block)
            height += spacer["before"] + spacer["lines"] * spacer["line"] + spacer["after"]
        else:
            height = None
            break
    metrics = paragraph_metrics(base)
    if height and metrics:
        set_spacing(base, after=max(0.0, height - metrics["before"] - metrics["lines"] * metrics["line"]))
    run[0].addprevious(base)
    for block in run:
        block.getparent().remove(block)
    panel["textLeft"] = min(gutter["left"], gutter["reach"]) if gutter.get("reach") is not None else gutter["left"]
    return base


def shade_run_of_paragraphs(document, panels, plain=False, declined=None, page_count=None):
    """Shade the paragraphs a panel's text ended up in, and draw its bar.

    Matching is by text, in document order: the same code block appears on
    every finding page of a report, so "the only paragraph that contains this
    line" is the wrong question. The panels are walked in page order against a
    cursor into the paragraphs, which pairs the nth occurrence with the nth
    panel. A row that matches nothing ahead of the cursor is skipped. A
    paragraph
    that already carries a fill, or sits in a table cell that does, is left
    alone: pdf2docx colours the cells it recognised and a second fill would
    fight with it. It does not colour a code block, even though it does put
    one in a cell, which is why "is it in a table" is the wrong question and
    "does it already have a colour" is the right one.

    Returns `(painted, anchors)`: the paragraphs a panel holds, and the panel
    tables this built with the page coordinate each one's top edge has in the
    PDF, which is better than any flow the vertical pass could work out for
    them.

    `plain` shades the paragraphs where they stand and builds no table at all,
    which is what the rung below the fallback asks for: it is the level where
    nothing this file does may move a paragraph out of the place the converter
    wrote it.
    """
    body = document.element.body
    # Every paragraph, including the ones that already have a colour: a panel
    # the converter did handle still has to consume its place in the order, or
    # the cursor runs ahead and the next panel is painted onto the wrong text.
    paragraphs = body_paragraphs(document)
    squashed = [compare_squash(paragraph_text(p)) for p in paragraphs]
    pages = paragraph_pages(document, page_count)
    on_page = [pages.get(id(p)) for p in paragraphs] if pages is not None else None
    painted = []
    anchors = []
    cursor = 0
    used = set()
    folded = set()
    # A panel read as a numbered listing is the code columns alone, with the
    # numbers in `gutter`; the panel as it was read stays here, for the case
    # that the fold refuses (below).
    unsplit = {}
    cut = []
    for panel in panels:
        split = split_line_numbers(panel)
        if split is not None:
            unsplit[id(split)] = panel
        cut.append(split or panel)
    panels = cut
    settle_panel_text_left(panels)
    work = sorted(panels, key=lambda p: (p["page"], p["rect"].y0))
    position_in_work = 0
    while position_in_work < len(work):
        panel = work[position_in_work]
        position_in_work += 1
        cursor_before = cursor
        # A row is looked for on the panel's own page when the pages are
        # known, among the paragraphs no panel has taken yet; the order the
        # converter writes a page's blocks in is not the PDF's (a card's
        # nested tables come out where the card does), so no cursor runs
        # through a page. Without the pages, a window ahead of a cursor.
        if on_page is not None:
            candidates = [i for i in range(len(squashed)) if on_page[i] == panel["page"] and i not in used]
        else:
            candidates = [i for i in range(cursor, min(len(squashed), cursor + PANEL_SEARCH_WINDOW)) if i not in used]
        hit_rows = []
        def match_rows(candidates):
            matched = []
            hit_rows.clear()
            start = None
            for number, row in enumerate(panel["rows"]):
                needle = compare_squash(row["text"])
                if len(needle) < COMPARE_MIN_CHARS:
                    continue
                # The first row fixes where the panel begins; the rest are
                # looked for after it, so a line two panels share (a table
                # header) is taken from this one and not from one further on.
                holders = [i for i in candidates if (start is None or i >= start) and needle in squashed[i]]
                # The panel's first row fixes where it begins, so a paragraph
                # that starts with it is the panel's first line and one that
                # only quotes it (a sentence before the block that names its
                # first command) is not: the quote took the anchor, the real
                # first line was never matched and the panel stayed
                # pdf2docx's staircase of tables.
                position = next((i for i in holders if start is None and squashed[i].startswith(needle)),
                                holders[0] if holders else None)
                if position is not None:
                    matched.append(position)
                    hit_rows.append(number)
                    if start is None:
                        start = position
            return matched

        matched = match_rows(candidates)
        if not matched and on_page is None:
            # Nothing within the window: the paragraphs are further on, and
            # a cursor that never moves would leave every later panel white.
            matched = match_rows([i for i in range(cursor, len(squashed)) if i not in used])
        if not matched:
            if declined is not None:
                declined["panels-unmatched"] += 1
            continue
        # The short rows at the panel's edges (a "{" above the first line, a
        # "}" under the last) are no match of their own, since a row that
        # short proves nothing anywhere in a report, but the PDF has them in
        # the panel. Left out they stay loose paragraphs above and below a
        # table as tall as the whole rectangle: the table, an exact row
        # replacing 7 lines of the 9 it was drawn round, pushed the "}" 42 pt
        # down and everything under it 31 pt.
        framing = short_edge_rows(panel, hit_rows, matched, paragraphs, squashed, on_page, used)
        stray = None if plain else stray_tail_row(panel, hit_rows, matched, framing, paragraphs, squashed, on_page, used)
        if stray is not None:
            # The panel's closing row is the first line of the step's text
            # cell under it. It moves out, to stand after the panel's last
            # block, and the cell keeps the rest of its text. The lists are
            # read again from the document, and the indices the loop holds
            # follow the elements they named.
            tail = paragraphs[stray]
            last = paragraphs[max(list(matched) + list(framing))]
            block = wrapper_table(last, [paragraphs[i] for i in list(matched) + list(framing)]) or last
            tail.getparent().remove(tail)
            block.addnext(tail)
            kept = [[paragraphs[i] for i in group] for group in (sorted(used), matched, framing)]
            paragraphs = body_paragraphs(document)
            squashed = [compare_squash(paragraph_text(p)) for p in paragraphs]
            pages = paragraph_pages(document, page_count)
            on_page = [pages.get(id(p)) for p in paragraphs] if pages is not None else None
            where = {id(element): number for number, element in enumerate(paragraphs)}
            used = {where[id(element)] for element in kept[0]}
            matched = [where[id(element)] for element in kept[1]]
            framing = [where[id(element)] for element in kept[2]] + [where[id(tail)]]
            if declined is not None:
                declined["panels-stray-tail"] += 1
        used.update(matched)
        used.update(framing)
        cursor = max(matched + framing) + 1
        found = [paragraphs[position] for position in sorted(set(matched) | set(framing))]
        if panel.get("gutter"):
            # A numbered listing is rebuilt only from the table pdf2docx made
            # of it, which is a change to the document; on the rung that moves
            # nothing, or when the cells are not what it expects, the panel is
            # left as it was found, which is what not matching it did.
            joined = None if plain else fold_line_numbers(found, panel)
            if joined is None:
                # Nothing about a panel says it is code: steps, years or ports
                # in a prose font beside their numbers pass every test that
                # split_line_numbers has, and a fold that cannot be made
                # (pdf2docx's cells are not a number cell and a code cell)
                # used to leave the callout unbuilt and unfilled, where the
                # ordinary path builds it (steps.typ: 2 callouts unbuilt, 1
                # with the gutter limited to monospace). So the panel goes
                # through the ordinary path as it was read, numbers and all,
                # which is what it did before the gutter existed.
                original = unsplit.get(id(panel))
                if original is not None:
                    used.difference_update(matched)
                    used.difference_update(framing)
                    cursor = cursor_before
                    work.insert(position_in_work, original)
                    continue
                if declined is not None:
                    declined["panels-unmatched"] += 1
                continue
            found = [joined]
            folded.add(id(joined))
        if plain:
            # Nothing moves on this rung, so a line the converter coloured
            # itself keeps its colour and the rest are shaded where they are.
            wanted = [element for element in found if not already_shaded(body, element)]
            if not wanted:
                continue
            if len(wanted) < len(found):
                if declined is not None:
                    declined["panels-partial"] += 1
                continue
        else:
            # The lines may be paragraphs, or each the sole content of a
            # one-cell table pdf2docx made (bare, or in the panel's own grey),
            # with its spacers between. Taken apart they are one run of
            # paragraphs again and the panel table can hold them all. A line
            # in any other colour is something the converter recognised as
            # its own, and painting around it would draw a second grey shape
            # beside it: an HTTP request whose first three lines pdf2docx had
            # shaded got its last line shaded again as a stripe of its own.
            gathered = gather_panel_blocks(found, panel)
            if gathered is None and framing:
                # The edge rows are an addition: a stranger between one of
                # them and the panel's lines (a picture's paragraph, which
                # has no text to step over) is the old state of things.
                loose = {id(paragraphs[position]) for position in framing}
                found = [element for element in found if id(element) not in loose]
                used.difference_update(framing)
                framing = []
                gathered = gather_panel_blocks(found, panel)
            if gathered is None:
                if declined is not None:
                    declined["panels-partial"] += 1
                continue
            run, occupied = gathered
            rect = panel["rect"]
            comparable = sum(1 for row in panel["rows"] if len(compare_squash(row["text"])) >= COMPARE_MIN_CHARS)
            declared = sum((paragraph_metrics(element) or {"lines": 1})["lines"] for element in found)
            comparable += len(framing)
            if len(matched) + len(framing) == comparable and declared < comparable:
                # Every row of the panel is in these paragraphs, so the page
                # already holds all of it: pdf2docx joined some rows into one
                # paragraph line and the file declares fewer lines than Word
                # draws. Taken for too tall, a 20-row listing in a finding
                # card stayed a shaded paragraph with pdf2docx's 194 pt right
                # indent, and the panel under it was pushed out of the card's
                # exact row and hidden (page 94 of a 286-page report).
                # The flow they took up is what Word draws: a line for every
                # row of the panel, at the paragraphs' own height. The
                # rectangle's height alone leaves out the spacing under the
                # last line, which is what the block below sits after, so a
                # figure under a 6-row listing the file declared as 4 lines
                # was placed 18.1 pt too high (shape-a, page 25).
                pitch = (paragraph_metrics(found[-1]) or {"line": 0.0})["line"]
                occupied = max(occupied + max(0, len(panel["rows"]) - declared) * pitch, rect.y1 - rect.y0)
            if rect.y1 - rect.y0 > occupied + PANEL_GROW_PT:
                # Taller than what it would replace: the page could gain a
                # line. Left as it is, like any panel the builder refuses.
                wanted = [element for element in found if not already_shaded(body, element)]
                if not wanted:
                    continue
            else:
                wanted, kept_height = unwrap_panel_blocks(run)
                if not wanted:
                    # Every row held something beside the panel's line (a
                    # "Capture" tag in a cell next to its picture), so the
                    # rows all stayed tables and there is nothing to rebuild.
                    if declined is not None:
                        declined["panels-partial"] += 1
                    continue
                # A numbered listing's lines were split and given their spaces
                # when its numbers went in, and the numbers are in the text now.
                loose = [element for element in wanted if id(element) not in folded]
                split_joined_code(loose, panel)
                restore_leading_spaces(loose, panel)
                built = build_panel_table(panel, wanted, occupied - kept_height)
                if built is not None:
                    anchors.append(built)
                    painted.extend(wanted)
                    continue
        for element in wanted:
            paragraph = Paragraph(element, document)
            shade_paragraph(paragraph, panel["fill"])
            if panel["bar"]:
                left_border(paragraph, panel["bar"])
            painted.append(element)
    return painted, anchors


def short_edge_rows(panel, hit_rows, matched, paragraphs, squashed, on_page, used):
    """Positions of the paragraphs that hold the short rows around a panel's matched ones.

    The rows the comparison could not use (under COMPARE_MIN_CHARS) are left
    out of every match, and the ones in the middle of a panel are harmless:
    the run of blocks the table replaces passes over a short paragraph
    between two matched ones. The ones at the two ends are not, because the
    run starts at the first matched paragraph and ends at the last. A short
    row there is taken when the paragraph next to the run, with blanks
    stepped over, is that very row's text (equal, not merely containing it),
    is on the panel's page and is nobody's yet. The walk stops at the first
    row that does not fit, so it never reaches past a line it could not
    name. A row that squashes to nothing (a rule of dashes) is stepped over
    on the row side only.
    """
    if not matched or len(matched) != len(hit_rows):
        return []
    rows = panel["rows"]
    taken = set(matched)
    framing = []
    for step, edge, stop in ((-1, min(hit_rows), -1), (1, max(hit_rows), len(rows))):
        position = min(matched) if step < 0 else max(matched)
        for number in range(edge + step, stop, step):
            key = compare_squash(rows[number]["text"])
            if len(key) >= COMPARE_MIN_CHARS:
                break
            if not key:
                continue
            index = position + step
            while (0 <= index < len(paragraphs) and not squashed[index]
                   and not any(True for _ in paragraphs[index].iter(qn("w:drawing")))):
                index += step
            if (not 0 <= index < len(paragraphs) or index in used or index in taken
                    or squashed[index] != key
                    or (on_page is not None and on_page[index] != panel["page"])):
                break
            framing.append(index)
            taken.add(index)
            position = index
    return framing


def stray_tail_row(panel, hit_rows, matched, framing, paragraphs, squashed, on_page, used):
    """Position of a panel's closing short row that pdf2docx put in the table of the block after it.

    The last row of a code block ("}") is too short for the comparison, so
    `short_edge_rows` takes it only when it is the next paragraph. On two
    thirds of a finding report's pages the next paragraph is the number
    badge of the step under the panel, because pdf2docx made the "}" the
    first line of that step's text cell, and the cell's reading order puts
    the badge in front of it. The panel was built without its last line and
    the "}" stayed in the step, 11.5 pt of text above it, which is the 10.5
    to 13 pt every one of those steps came out late by (b2 pages 13, 18, 26
    and 34, measured).

    Only that shape is taken: the very next paragraph with text is shorter
    than the comparison can name, the one after it is the row's text (equal),
    it is the first thing in its table cell, that cell is another cell of the
    row the short one stands in, it is on the panel's page and it is nobody's.
    """
    rows = panel["rows"]
    if not matched or len(matched) != len(hit_rows) or len(rows) - 1 <= max(hit_rows):
        return None
    wanted = compare_squash(rows[-1]["text"])
    if not wanted or len(wanted) >= COMPARE_MIN_CHARS:
        return None
    last = max(list(matched) + list(framing))
    if squashed[last] == wanted:
        return None
    index = last + 1
    while index < len(paragraphs) and not squashed[index] and not any(True for _ in paragraphs[index].iter(qn("w:drawing"))):
        index += 1
    if index >= len(paragraphs) or not 0 < len(squashed[index]) < COMPARE_MIN_CHARS or squashed[index] == wanted:
        return None
    badge = paragraphs[index]
    stray = index + 1
    while stray < len(paragraphs) and not squashed[stray] and not any(True for _ in paragraphs[stray].iter(qn("w:drawing"))):
        stray += 1
    if stray >= len(paragraphs) or squashed[stray] != wanted or stray in used or stray in framing or stray in matched:
        return None
    if on_page is not None and on_page[stray] != panel["page"]:
        return None
    cell, home = paragraphs[stray].getparent(), badge.getparent()
    if cell is None or cell.tag != qn("w:tc") or home is None or home.tag != qn("w:tc") or cell is home:
        return None
    texts = [p for p in cell if p.tag == qn("w:p")]
    if cell.getparent() is not home.getparent() or len(texts) < 2 or texts[0] is not paragraphs[stray]:
        return None
    return stray


def already_shaded(body, element):
    """Does this paragraph, or the cell holding it, already carry a fill?"""
    node = element
    while node is not None and node is not body:
        properties = node.find(qn("w:pPr")) if node.tag == qn("w:p") else node.find(qn("w:tcPr"))
        if properties is not None:
            fill = properties.find(qn("w:shd"))
            if fill is not None and (fill.get(qn("w:fill")) or "auto").lower() not in ("auto", "ffffff", ""):
                return True
        node = node.getparent()
    return False


def left_border(paragraph, bar):
    node = OxmlElement("w:pBdr")
    left = OxmlElement("w:left")
    left.set(qn("w:val"), "single")
    # Eighths of a point, and Word refuses anything above 48.
    left.set(qn("w:sz"), str(max(4, min(48, int(round(bar["width"] * 8))))))
    # Points, and Word takes 0 to 31 of them.
    left.set(qn("w:space"), str(max(0, min(31, int(round(bar.get("space") or 0.0))))))
    left.set(qn("w:color"), hex_of(bar["fill"]))
    node.append(left)
    properties = paragraph._p.get_or_add_pPr()
    for existing in properties.findall(qn("w:pBdr")):
        properties.remove(existing)
    insert_ordered(properties, node, PPR_ORDER)


def restore_swatches(document, swatches, face=None):
    """Put a chart legend's colour squares back as coloured glyphs.

    pdf2docx drops a small filled square that is not part of a table, so the
    legend arrives as four words with nothing to tell them apart. A filled
    square character in the swatch's colour, in the run the label starts,
    reads the same at the size a legend is printed at.

    The square is a character the report's own text font may well not have,
    and a font Word picks for a missing glyph is a font this file does not
    carry. `face` is one it does, chosen for having the glyph.
    """
    body = document.element.body
    paragraphs = body_paragraphs(document)
    squashed = [compare_squash(paragraph_text(p)) for p in paragraphs]
    by_row = {}
    for swatch in swatches:
        by_row.setdefault(id(swatch["row"]), []).append(swatch)
    added = 0
    for group in by_row.values():
        labels = [compare_squash(s["label"]) for s in group]
        if not all(labels):
            continue
        runs = None
        # The whole legend in one paragraph, run by run.
        for element, text in zip(paragraphs, squashed):
            if all(label in text for label in labels):
                paragraph = Paragraph(element, document)
                found = [next((r._element for r in paragraph.runs
                               if compare_squash(r.text).startswith(label)), None) for label in labels]
                if all(run is not None for run in found):
                    runs = found
                break
        # Or one paragraph per label, in order, which is how the converter
        # writes a legend it has read as a column of cells.
        if runs is None:
            window = matching_sequence(paragraphs, squashed, labels)
            if window is None:
                continue
            if any(already_shaded(body, element) for element in window):
                continue  # the converter kept this cell's colour already
            runs = [element.find(qn("w:r")) for element in window]
            if any(run is None for run in runs):
                continue
        for swatch, target in zip(group, runs):
            target.addprevious(colour_square(target, swatch["fill"], face))
            added += 1
    return added


def matching_sequence(paragraphs, squashed, labels):
    """The first run of paragraphs whose texts are exactly these labels, in order."""
    filled = [i for i, text in enumerate(squashed) if text]
    for start in range(len(filled) - len(labels) + 1):
        window = filled[start : start + len(labels)]
        if [squashed[i] for i in window] == labels:
            return [paragraphs[i] for i in window]
    return None


def colour_square(sibling, fill, face=None):
    """A run holding a filled square in `fill`, styled like its neighbour.

    It keeps the neighbour's size, so the line it joins is no taller than it
    was, and takes `face` when one was found: a font this file carries that
    has the character, rather than whichever font the reader's Word reaches
    for when the text font turns out not to.
    """
    mark = copy.deepcopy(sibling if sibling.tag == qn("w:r") else OxmlElement("w:r"))
    if mark.tag != qn("w:r"):
        mark = OxmlElement("w:r")
    for child in list(mark):
        if child.tag != qn("w:rPr"):
            mark.remove(child)
    properties = mark.find(qn("w:rPr"))
    if properties is None:
        properties = OxmlElement("w:rPr")
        mark.insert(0, properties)
    for existing in properties.findall(qn("w:color")):
        properties.remove(existing)
    colour = OxmlElement("w:color")
    colour.set(qn("w:val"), hex_of(fill))
    insert_ordered(properties, colour, RPR_ORDER)
    if face:
        table = properties.find(qn("w:rFonts"))
        if table is None:
            table = OxmlElement("w:rFonts")
            insert_ordered(properties, table, RPR_ORDER)
        for attribute in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
            table.set(qn(attribute), face["family"])
        set_flag(properties, "w:b", face["bold"])
        set_flag(properties, "w:i", face["italic"])
    text = OxmlElement("w:t")
    text.set(qn("xml:space"), "preserve")
    text.text = FILLED_SQUARE + " "
    mark.append(text)
    return mark


def page_clips(page):
    """Every clip rectangle the page's content sets, from PyMuPDF's extended drawings."""
    out = []
    try:
        items = page.get_drawings(extended=True)
    except Exception:  # noqa: BLE001 - a page whose drawings cannot be read has no clips to offer
        return out
    for item in items:
        if item.get("type") == "clip" and item.get("scissor") is not None:
            rect = pymupdf.Rect(item["scissor"])
            if not rect.is_empty and rect.width > 1 and rect.height > 1:
                out.append(rect)
    return out


def pdf_pictures(doc):
    """Every raster image the PDF places, with where it sits and what shows.

    A cover usually bleeds off the page, so the rectangle it was drawn at and
    the part of it a reader sees are two different things, and Word only has
    the second: an inline picture starts at the text origin and cannot hang
    over the page edge.

    A screenshot in a figure is the same thing on a smaller scale: typst
    draws the whole image and clips it to the figure's frame, so a 255 pt
    picture shows 158 pt of itself. The clip is in the page's drawing
    commands (`page_clips`), and what shows is the image's rectangle cut by
    the largest clip that cuts it. A clip that holds the whole image cuts
    nothing and is ignored, and a page with no clip leaves the image as the
    page edge leaves it.
    """
    out = []
    for index in range(doc.page_count):
        page = doc[index]
        clips = None
        fills = None
        for info in page.get_image_info():
            rect = pymupdf.Rect(info["bbox"])
            if rect.width <= 0 or rect.height <= 0:
                continue
            visible = rect & page.rect
            if clips is None:
                clips = page_clips(page)
            best = None
            for clip in clips:
                cut = rect & clip
                if cut.is_empty or cut.width < 1 or cut.height < 1 or cut.get_area() >= visible.get_area() - 0.5:
                    continue
                if best is None or cut.get_area() > best.get_area():
                    best = cut
            if best is not None:
                visible = best & page.rect
            if visible.is_empty:
                continue
            # A filled rectangle the size of what shows is the figure's
            # frame; pdf2docx writes that as an empty cell, which is where
            # the picture belongs. A picture with no frame has no cell to go
            # into and is placed by its position instead.
            if fills is None:
                fills = [d["rect"] for d in page.get_drawings() if d.get("fill") is not None]
            framed = any(abs(r.x0 - visible.x0) <= FRAME_FIT_PT and abs(r.y0 - visible.y0) <= FRAME_FIT_PT
                         and abs(r.x1 - visible.x1) <= FRAME_FIT_PT and abs(r.y1 - visible.y1) <= FRAME_FIT_PT
                         for r in fills)
            out.append({"page": index, "rect": rect, "visible": visible, "framed": framed,
                        "clipped": best is not None})
    return out


def drawing_box(node):
    """Where a `wp:anchor` sits on its page, as a Rect in points, or None.

    Only an anchor positioned against the page in both directions says
    where it is; one placed against a paragraph or a column depends on the
    flow and is left alone.
    """
    out = {}
    for axis, name in (("x", "wp:positionH"), ("y", "wp:positionV")):
        position = node.find(qn(name))
        offset = position.find(qn("wp:posOffset")) if position is not None else None
        if position is None or position.get("relativeFrom") != "page" or offset is None:
            return None
        try:
            out[axis] = int(offset.text or "0") / EMU_PER_PT
        except ValueError:
            return None
    extent = node.find(qn("wp:extent"))
    if extent is None:
        return None
    try:
        width, height = int(extent.get("cx")) / EMU_PER_PT, int(extent.get("cy")) / EMU_PER_PT
    except (TypeError, ValueError):
        return None
    return pymupdf.Rect(out["x"], out["y"], out["x"] + width, out["y"] + height)


def set_drawing_size(node, visible):
    width = int(round(visible.width * EMU_PER_PT))
    height = int(round(visible.height * EMU_PER_PT))
    for child in [node.find(qn("wp:extent"))] + list(node.iter(qn("a:ext"))):
        if child is not None:
            child.set("cx", str(width))
            child.set("cy", str(height))


def crop_drawing(node, rect, visible):
    """Crop the picture to `visible` with `a:srcRect`; the drawn rectangle was `rect`."""
    crop = {
        "l": (visible.x0 - rect.x0) / rect.width,
        "t": (visible.y0 - rect.y0) / rect.height,
        "r": (rect.x1 - visible.x1) / rect.width,
        "b": (rect.y1 - visible.y1) / rect.height,
    }
    fill = next(node.iter(qn("pic:blipFill")), None)
    if fill is None or not any(value > 0.0005 for value in crop.values()):
        return
    for existing in fill.findall(qn("a:srcRect")):
        fill.remove(existing)
    source = OxmlElement("a:srcRect")
    for side, value in crop.items():
        if value > 0.0005:
            # Thousandths of a percent of the source image's side.
            source.set(side, str(int(round(value * 100000))))
    blip = fill.find(qn("a:blip"))
    (blip.addnext(source) if blip is not None else fill.append(source))


def empty_frame_cell(table, visible, used):
    """A bare cell of this table the size of `visible`, not yet used, or None.

    A figure on its own is a one-cell table; two figures side by side are
    two cells of one row, each the size of its own picture.
    """
    for row in table.findall(qn("w:tr")):
        height = wrapper_row_height(row)
        if height is None or abs(height - visible.height) > FRAME_FIT_PT:
            continue
        for cell in row.findall(qn("w:tc")):
            if id(cell) in used:
                continue
            properties = cell.find(qn("w:tcPr"))
            size = properties.find(qn("w:tcW")) if properties is not None else None
            width = twips_of(size.get(qn("w:w"))) if size is not None else None
            if width is None or abs(width - visible.width) > FRAME_FIT_PT:
                continue
            if any(child.tag == qn("w:tbl") for child in cell):
                continue
            if any(child.tag == qn("w:p") and (any((t.text or "").strip() for t in child.iter(qn("w:t")))
                                                or any(True for _ in child.iter(qn("w:drawing"))))
                   for child in cell):
                continue
            return cell
    return None


def empty_frame_after(paragraph, visible, used):
    """A bare one-cell table the size of `visible` in the blocks after `paragraph`, or None.

    pdf2docx reads a figure's frame (a filled, stroked block) as a table of
    one empty cell with the frame's fill and exact height, and floats the
    picture behind it. The cell is where the picture belongs. For a figure
    inside a finding card the frame sits in the card's table while the
    picture's paragraph stands before the card, so the following blocks are
    searched inside as well, in document order, and a frame that already
    holds a picture (`used`) is passed over. pdf2docx puts the picture's
    paragraph where the hidden top of the image begins, which after a code
    block is a dozen one-line tables before the frame, and a second figure's
    paragraph can come before the first one's frame, so the search runs on
    through other pictures' paragraphs: pictures and frames both follow the
    page's reading order, so the first unused frame is this picture's. Only
    a picture the PDF frames (`framed`) is looked for at all.
    """
    node = paragraph.getnext()
    for _ in range(FRAME_SEARCH_BLOCKS):
        if node is None:
            return None
        if node.tag == qn("w:tbl"):
            for table in node.iter(qn("w:tbl")):
                cell = empty_frame_cell(table, visible, used)
                if cell is not None:
                    used.add(id(cell))
                    return cell
        node = node.getnext()
    return None


def inline_into_frame(run, anchor, cell, visible):
    """Move a floated picture into its frame cell as an inline picture of the frame's size."""
    inline = OxmlElement("wp:inline")
    for name in ("distT", "distB", "distL", "distR"):
        inline.set(name, "0")
    for child in list(anchor):
        if child.tag in (qn("wp:simplePos"), qn("wp:positionH"), qn("wp:positionV"), qn("wp:wrapNone"),
                         qn("wp:wrapSquare"), qn("wp:wrapTight"), qn("wp:wrapThrough"), qn("wp:wrapTopAndBottom")):
            continue
        inline.append(child)
    drawing = anchor.getparent()
    drawing.replace(anchor, inline)
    properties = cell.find(qn("w:tcPr"))
    if properties is None:
        properties = OxmlElement("w:tcPr")
        cell.insert(0, properties)
    margins = properties.find(qn("w:tcMar"))
    if margins is None:
        margins = OxmlElement("w:tcMar")
        properties.append(margins)
    for name in ("w:top", "w:start", "w:bottom", "w:end"):
        side = margins.find(qn(name))
        if side is None:
            side = OxmlElement(name)
            margins.append(side)
        side.set(qn("w:w"), "0")
        side.set(qn("w:type"), "dxa")
    host = next((child for child in cell if child.tag == qn("w:p")), None)
    if host is None:
        host = OxmlElement("w:p")
        cell.append(host)
    # An inline picture stands on the baseline like a glyph. In an exact line
    # the baseline is 0.8 of the line down, so a picture as tall as the line
    # rises 30 pt above the cell (measured); a single auto line grows to the
    # picture, and a 1 pt font leaves next to no descent under it.
    set_spacing(host, before=0.0, after=0.0)
    spacing = host.get_or_add_pPr().find(qn("w:spacing"))
    spacing.set(qn("w:line"), "240")
    spacing.set(qn("w:lineRule"), "auto")
    set_left_indent(host, 0.0)
    host_properties = host.get_or_add_pPr()
    for name in ("w:jc",):
        for node in host_properties.findall(qn(name)):
            host_properties.remove(node)
    run_properties = run.find(qn("w:rPr"))
    if run_properties is None:
        run_properties = OxmlElement("w:rPr")
        run.insert(0, run_properties)
    for name in ("w:sz", "w:szCs"):
        size = run_properties.find(qn(name))
        if size is None:
            size = OxmlElement(name)
            insert_ordered(run_properties, size, RPR_ORDER)
        size.set(qn("w:val"), "2")
    host.append(run)


def bare_cells(body):
    """Every empty cell of an exact-height row in the body, in document order, with its size."""
    out = []
    for table in body.iter(qn("w:tbl")):
        for row in table.findall(qn("w:tr")):
            height = wrapper_row_height(row)
            if height is None:
                continue
            for cell in row.findall(qn("w:tc")):
                if any(child.tag == qn("w:tbl") for child in cell):
                    continue
                if any(child.tag == qn("w:p") and (any((t.text or "").strip() for t in child.iter(qn("w:t")))
                                                    or any(True for _ in child.iter(qn("w:drawing"))))
                       for child in cell):
                    continue
                properties = cell.find(qn("w:tcPr"))
                size = properties.find(qn("w:tcW")) if properties is not None else None
                width = twips_of(size.get(qn("w:w"))) if size is not None else None
                if width is None:
                    continue
                out.append((cell, width, height))
    return out


def pair_frames(body, pictures):
    """Which bare cell each framed picture goes into, by id of the picture, or none.

    The frames pdf2docx writes and the pictures the PDF draws follow the same
    reading order, so within one size of frame the k-th picture takes the
    k-th cell. Pairing by order is safe only when the two counts agree; when
    a frame of some size is missing from the file (pdf2docx read it as
    something else) the pictures of that size are left to their positions,
    rather than each taking the next picture's frame down the document,
    which is what a search forward from each picture's paragraph did.
    """
    cells = bare_cells(body)
    framed = [p for p in pictures if p.get("framed")]
    classes = []
    for picture in framed:
        size = (picture["visible"].width, picture["visible"].height)
        for known in classes:
            if abs(known[0] - size[0]) <= FRAME_FIT_PT and abs(known[1] - size[1]) <= FRAME_FIT_PT:
                break
        else:
            classes.append(size)
    paired = {}
    for size in classes:
        mine = [p for p in framed if abs(p["visible"].width - size[0]) <= FRAME_FIT_PT
                and abs(p["visible"].height - size[1]) <= FRAME_FIT_PT]
        slots = [cell for cell, width, height in cells
                 if abs(width - size[0]) <= FRAME_FIT_PT and abs(height - size[1]) <= FRAME_FIT_PT]
        if len(mine) != len(slots):
            continue
        for picture, cell in zip(mine, slots):
            paired[id(picture)] = cell
    return paired


def reserve_clipped_strips(drawing, rect, visible):
    """Give an inline picture's paragraph the strips its figure's frame clips away, as spacing.

    pdf2docx spaced the paragraph from the whole rectangle the image was
    drawn at. Cropped to what the frame shows, the picture then started where
    its unclipped top had been and the caption followed 13 pt early (page 13
    of a 69-page report). The strips go back as space before and after, so
    the paragraph takes up the rectangle and the picture sits where the frame
    is. A cover's bleed over the page edge is not a strip and reserves nothing.
    """
    run = drawing.getparent()
    paragraph = run.getparent() if run is not None else None
    if paragraph is None or paragraph.tag != qn("w:p"):
        return
    if any(a.tag == qn("w:tc") for a in paragraph.iterancestors()):
        # In a cell of exact height the strips would only push the picture
        # down to be clipped; the cell is sized by its own pass.
        return
    top = max(0.0, visible.y0 - rect.y0)
    bottom = max(0.0, rect.y1 - visible.y1)
    if top < 0.5 and bottom < 0.5:
        return
    properties = paragraph.find(qn("w:pPr"))
    spacing = properties.find(qn("w:spacing")) if properties is not None else None
    before = (twips_of(spacing.get(qn("w:before"))) if spacing is not None else None) or 0.0
    after = (twips_of(spacing.get(qn("w:after"))) if spacing is not None else None) or 0.0
    set_spacing(paragraph, before=before + top, after=after + bottom)


# How far apart two pictures' tops may be and still be one row of pictures:
# typst sets a grid's cells on one top line (`align: top`), to the rounding of
# the PDF.
SIDE_PICTURE_TOP_PT = 2.0


def inline_picture_size(run):
    """(width, height) in points of the inline picture a run holds, or None."""
    node = run.find(qn("w:drawing") + "/" + qn("wp:inline"))
    extent = node.find(qn("wp:extent")) if node is not None else None
    try:
        return int(extent.get("cx")) / EMU_PER_PT, int(extent.get("cy")) / EMU_PER_PT
    except (TypeError, ValueError, AttributeError):
        return None


def rejoin_side_pictures(document, pictures, declined=None):
    """Put a picture pdf2docx set on a caption's line back beside the picture it stands next to.

    Two screenshots side by side, each with a caption under it, are one row of
    pictures in the PDF, top-aligned. When the right one is taller its lower
    part reaches down beside the left one's caption, and pdf2docx, which builds
    lines from what overlaps vertically, writes the left picture as a paragraph
    of its own and then the caption, a tab and the right picture as one line:
    in Word that line is as tall as the right picture and stands under the left
    one, so the figure took about twice its height, the paragraph after it was
    drawn over a picture and the captions were clipped (design-a2's two-picture
    figures, PDF 16 and 20). The three-picture figures of the same report came
    out as a table and were right.

    A paragraph that holds text and an inline picture is taken apart when the
    paragraph before it holds nothing but one inline picture, and the PDF has
    the two pictures (matched by size, `PICTURE_FIT_PT`) on one page with their
    tops within `SIDE_PICTURE_TOP_PT` and side by side: the picture, and the tab
    before it, move to that paragraph, after or before its picture as the PDF
    has them, with a left tab stop where the second picture starts; the caption
    keeps its own line. Pictures of the same sizes recur (two figures of the
    same pair of screenshot sizes), so a pair is taken on the paragraph's own
    page (`page_blocks`), or, where pages cannot be told, the first pair not
    yet used in document order. Returns how many were moved.
    """
    body = document.element.body
    page_of = {}
    for index, blocks in enumerate(page_blocks(body)):
        for block in blocks:
            page_of[block] = index

    def page_of_paragraph(paragraph):
        node = paragraph
        while node is not None and node.getparent() is not body:
            node = node.getparent()
        return page_of.get(node)

    used = []
    moved = 0
    for paragraph in list(body.iter(qn("w:p"))):
        runs = [run for run in paragraph if run.tag == qn("w:r")]
        held = [run for run in runs if inline_picture_size(run) is not None]
        if len(held) != 1 or not paragraph_text(paragraph).strip():
            continue
        partner_paragraph = paragraph.getprevious()
        while partner_paragraph is not None and partner_paragraph.tag == qn("w:p") and blank_spacer(partner_paragraph):
            partner_paragraph = partner_paragraph.getprevious()
        if partner_paragraph is None or partner_paragraph.tag != qn("w:p") or paragraph_text(partner_paragraph).strip():
            continue
        partner_runs = [run for run in partner_paragraph if run.tag == qn("w:r")]
        partner = [run for run in partner_runs if inline_picture_size(run) is not None]
        if len(partner) != 1:
            continue
        mover, staying = held[0], partner[0]
        size_moving, size_staying = inline_picture_size(mover), inline_picture_size(staying)

        def candidates(size):
            return [p for p in pictures
                    if abs(p["visible"].width - size[0]) <= PICTURE_FIT_PT
                    and abs(p["visible"].height - size[1]) <= PICTURE_FIT_PT]

        pairs = [(a, b) for a in candidates(size_staying) for b in candidates(size_moving)
                 if a is not b and a["page"] == b["page"]
                 and abs(a["visible"].y0 - b["visible"].y0) <= SIDE_PICTURE_TOP_PT
                 and (a["visible"].x1 <= b["visible"].x0 or b["visible"].x1 <= a["visible"].x0)]
        page = page_of_paragraph(paragraph)
        if page is not None:
            pairs = [(a, b) for a, b in pairs if a["page"] == page]
        else:
            pairs = [(a, b) for a, b in pairs if not any(a is u or b is u for u in used)][:1]
        if len(pairs) != 1:
            if pairs and declined is not None:
                declined["side-pictures-ambiguous"] += 1
            continue
        used.extend(pairs[0])
        a, b = pairs[0]
        position = runs.index(mover)
        tab = runs[position - 1] if position and runs[position - 1].find(qn("w:tab")) is not None \
            and not "".join(t.text or "" for t in runs[position - 1].iter(qn("w:t"))).strip() else None
        if tab is None:
            tab = OxmlElement("w:r")
            tab.append(OxmlElement("w:tab"))
        else:
            paragraph.remove(tab)
        paragraph.remove(mover)
        # The stop is where the second picture starts, measured from where the
        # first one does, which is where the paragraph's own indent puts it.
        left = paragraph_indent(partner_paragraph)
        if b["visible"].x0 >= a["visible"].x1:
            staying.addnext(tab)
            tab.addnext(mover)
            stop = left + (b["visible"].x0 - a["visible"].x0)
        else:
            staying.addprevious(mover)
            mover.addnext(tab)
            stop = left + (a["visible"].x0 - b["visible"].x0)
        add_left_tab_stop(partner_paragraph, stop)
        moved += 1
    return moved


def add_left_tab_stop(paragraph, position):
    """A left tab stop at `position` points from the paragraph's own margin, kept in order with any it has."""
    properties = paragraph.get_or_add_pPr()
    stops = properties.find(qn("w:tabs"))
    if stops is None:
        stops = OxmlElement("w:tabs")
        insert_ordered(properties, stops, PPR_ORDER)
    node = OxmlElement("w:tab")
    node.set(qn("w:val"), "left")
    node.set(qn("w:pos"), twips_attribute(position))
    stops.append(node)
    for item in sorted(stops.findall(qn("w:tab")), key=lambda tab: twips_of(tab.get(qn("w:pos"))) or 0.0):
        stops.append(item)


def fit_pictures(document, pictures):
    """Give each picture the size, the crop and the place the PDF gave it.

    pdf2docx sizes a picture to the rectangle it was drawn at, which for a
    full-bleed cover is larger than the page: Word then places all 816 pt of
    an 816 pt image from the top of the text area, so the whole page is
    pushed down by the bleed and the bottom is cut off. Cropping the picture
    to the part of it the PDF actually shows, with `a:srcRect`, and sizing it
    to that, puts it exactly where the PDF has it without moving anything
    else on the page.

    A screenshot that overlaps text in the PDF (every one that is clipped by
    its figure's frame does, by the part the frame hides) is floated by
    pdf2docx behind the text at its full, unclipped size, with the frame as
    an empty grey cell painted over it and the caption on top of its lower
    strip; where the figure opens a page the upper strip covers the running
    header. Such a picture is cropped and sized the same way, and then put
    into the frame cell as an inline picture, where the caption follows it
    in the flow. A floated picture with no frame to go into is cropped and
    moved to where its visible part is.

    Pictures are paired with the PDF's in document order, so the drawings
    pdf2docx renders itself from vector art, which the PDF has no image for,
    are passed over when they match nothing. Returns how many were fitted.
    """
    body = document.element.body
    cursor = 0
    fixed = 0
    frames = pair_frames(body, pictures)
    anchors = []
    seen_tables = set()
    for drawing in list(body.iter(qn("w:drawing"))):
        node = drawing.find(qn("wp:inline"))
        anchor = drawing.find(qn("wp:anchor"))
        if node is None and anchor is None:
            continue
        box = drawing_box(anchor) if anchor is not None else None
        extent = (anchor if anchor is not None else node).find(qn("wp:extent"))
        try:
            size = (int(extent.get("cx")) / EMU_PER_PT, int(extent.get("cy")) / EMU_PER_PT)
        except (TypeError, ValueError, AttributeError):
            continue
        match = None
        for ahead in range(cursor, min(len(pictures), cursor + PICTURE_LOOKAHEAD)):
            rect = pictures[ahead]["rect"]
            if box is not None:
                same = (abs(box.x0 - rect.x0) <= PICTURE_FIT_PT and abs(box.y0 - rect.y0) <= PICTURE_FIT_PT
                        and abs(box.width - rect.width) <= PICTURE_FIT_PT and abs(box.height - rect.height) <= PICTURE_FIT_PT)
            else:
                same = abs(size[0] - rect.width) <= PICTURE_FIT_PT and abs(size[1] - rect.height) <= PICTURE_FIT_PT
            if same:
                match = ahead
                break
        if match is None:
            continue
        cursor = match + 1
        picture = pictures[match]
        rect, visible = picture["rect"], picture["visible"]
        target = anchor if anchor is not None else node
        set_drawing_size(target, visible)
        crop_drawing(target, rect, visible)
        if anchor is None and picture.get("clipped"):
            reserve_clipped_strips(drawing, rect, visible)
        if anchor is not None:
            paragraph = drawing.getparent().getparent() if drawing.getparent() is not None else None
            run = drawing.getparent()
            frame = frames.get(id(picture))
            if frame is not None:
                inline_into_frame(run, anchor, frame, visible)
                # The frame's table is placed from the PDF's own top edge by
                # the vertical pass, as a panel is, rather than from the
                # converter's flow, which sat it 12 pt high.
                table = frame.getparent().getparent() if frame.getparent() is not None else None
                if table is not None and table.tag == qn("w:tbl") and id(table) not in seen_tables:
                    seen_tables.add(id(table))
                    height = table_row_height(table) or visible.height
                    anchors.append((table, visible.y0 - FRAME_STROKE_INSET_PT, height))
            else:
                for axis, name in (("x0", "wp:positionH"), ("y0", "wp:positionV")):
                    offset = anchor.find(qn(name)).find(qn("wp:posOffset"))
                    offset.text = str(int(round(getattr(visible, axis) * EMU_PER_PT)))
        fixed += 1
    return fixed, anchors




def page_edge_offsets(page_ends, content_right):
    """How far each page size's text edge sits from `content_right`, by page width in points.

    `page_ends` is `(page width, x1 of the page's widest row)` for every page.
    The document's right edge is the median of those (`content_bounds`), and
    a landscape page in a portrait report ends 245 pt to the right of it: a
    justified paragraph there measured against the document's edge came out
    with a right indent that left a third of the page unused, and two lines
    of ragged text counted as justified because both reached past it.

    The size most pages have keeps the document's edge, offset zero, so that
    nothing about the pages that make up the report moves. Every other size
    gets the edge its own pages share (`run_column` over their widest rows,
    which is the cluster most of them agree on and not a median: on a report
    whose portrait pages end either at 508 or at 542 the median of the two
    kinds is 523, an edge no line has). A document of one size has no offsets.
    """
    sizes = {}
    for width, end in page_ends:
        sizes.setdefault(width, []).append(end)
    if len(sizes) < 2:
        return {}
    dominant = max(sizes, key=lambda width: len(sizes[width]))
    # With as many pages of one size as of another there is no dominant size:
    # the median sits between the two (`centre.typ`: 656.8 for an A4 page that
    # ends at 547.0 and a landscape one at 766.5), and the arbitrary winner
    # kept an edge 110 pt past its text, so its two-line paragraphs read as
    # ragged. Every size then has its own.
    tied = sorted((len(ends) for ends in sizes.values()), reverse=True)[:2]
    return {width: 0.0 if width == dominant and tied[0] != tied[1] else run_column(ends, max(ends)) - content_right
            for width, ends in sizes.items()}


# What typst lets hang past the column: a line that ends in one of these
# stands up to 0.8 of that mark's width beyond the edge (`overhang`, on by
# default). 197 of the lines in 18 pages of the verbose stress report end 2.9 pt
# past the margin, every one of them on a hyphen, and a column read off two of
# them gave every paragraph around it 2.9 pt too much room.
HANGING_MARKS = "-\u2010\u2011\u2012\u2013\u2014.,:;"


def hangs_into_margin(text):
    """Does this line end in a mark typst hangs past the column?"""
    return text.rstrip()[-1:] in tuple(HANGING_MARKS)


# How far a line ending in a hanging mark may stand past the column, in ems of
# its type: typst hangs a full stop or comma 0.8 of the mark's width (about a
# quarter of an em), a hyphen 0.55 of its width, a colon or dash less. 0.3 em
# is the widest of those, and the measured overhang was 2.4 pt on 11 pt text
# (a comma) and 2.9 pt (a hyphen).
HANGING_OVERSHOOT_EM = 0.3
# A line broken after a hyphen or a dash carries no space after it, while one
# broken at a space has the space inside its box (2.75 to 3.1 pt on 11 pt
# Libertinus and Arial), so it ends that much short of its neighbours less its
# own overhang: on `old_c.typ` (Arial) the lines ended at 543.0 (a word), 545.5
# (a comma, which hangs 2.4 and keeps its space), 542.0 (a hyphen) and 542.1
# (an em dash). A space is 0.25 to 0.32 em; this is the short side.
HANGING_SHORT_EM = 0.25


def lines_reaching_edge(run):
    """The lines of a run, its last aside, that end on the edge its justified lines share.

    The edge is where the lines that do not hang end, because a line ending in
    punctuation stands up to `HANGING_OVERSHOOT_EM` past the column and its
    end says nothing about where the column is. Measured against the widest end
    of all the lines, a paragraph whose widest line ended in a comma had one
    line within a point of the edge and the rest 2.4 pt short, so it read as
    ragged: 6 of 26 justified paragraphs in the review's probes. A hanging
    line reaches the column when it ends at it or past it by no more than
    that overhang, but its window is wide (5 pt against the 2 pt a firm line
    has), so a hanging line is counted only when it completes the set: every
    line but the last then reaches the column, as a justified paragraph's
    do. Counted on its own it made a ragged one justified (`dashes.typ`: three
    Libertinus lines ending at 535.2, which hangs, 533.9 and 530.3). When
    every line hangs there is nothing else to measure against, and the
    widest of them stands in.
    """
    solid = [r for r in run if not hangs_into_margin(r["text"])]
    if not solid:
        edge = max(r["x1"] for r in run)
        return [r for r in run[:-1] if abs(r["x1"] - edge) <= JUSTIFY_SPREAD_PT]
    edge = max(r["x1"] for r in solid)
    firm = [r for r in run[:-1] if not hangs_into_margin(r["text"]) and abs(r["x1"] - edge) <= JUSTIFY_SPREAD_PT]
    hung = []
    for r in run[:-1]:
        if hangs_into_margin(r["text"]):
            size = (r.get("columns") or [{}])[-1].get("size") or 0.0
            if -(JUSTIFY_SPREAD_PT + HANGING_SHORT_EM * size) <= r["x1"] - edge <= HANGING_OVERSHOOT_EM * size + JUSTIFY_SPREAD_PT:
                hung.append(r)
    return firm + hung if len(firm) + len(hung) == len(run) - 1 else firm


def run_column(ends, widest):
    """Where a justified run's lines end: the right end the most of them share, reaching for the widest of those.

    Justified lines end on one edge, give or take the last glyph's ink, and
    a line typst could not break (an unbreakable token) ends past it. The
    edge is the cluster of ends within `JUSTIFY_SPREAD_PT` of each other that
    holds the most lines, and its largest member: ink falls short of the
    column by the last glyph's side bearing, never beyond it. A tie goes to
    the cluster further right. No lines to go by is `widest`.
    """
    best = None
    for anchor in ends:
        cluster = [end for end in ends if abs(end - anchor) <= JUSTIFY_SPREAD_PT]
        key = (len(cluster), max(cluster))
        if best is None or key > best[0]:
            best = (key, cluster)
    return max(best[1]) if best else widest


# A paragraph is matched to the run it came from by the squashed text of the
# run's lines: any line at least this long is looked up by its first this many
# characters to find the runs worth a closer look, and a run answers for a
# paragraph only when the one holds the whole of the other (the run's text
# inside the paragraph, or a paragraph of at least RUN_MATCH_MIN_CHARS inside
# the run's). Lines alone are not enough: a report that repeats a sentence on
# several pages in different boxes shares single lines between runs that end
# on different edges, and a first version that scored by lines narrowed five
# paragraphs of one report by 15 pt and they wrapped (a page more, a blank one).
# A paragraph that only overlaps its run, which begins before it or runs on
# into the next paragraph, is measured against the page size's edge as before.
# Twelve characters is long enough that a table's repeated words do not
# collide, and 24 is two short lines or one that fills part of a column.
RUN_GRAM_CHARS = 12
RUN_MATCH_MIN_CHARS = 24
# Runs that hold the same text on pages of the same size agree on a column
# when their ends are within this of each other (the ink of a last glyph).
RUN_COLUMN_AGREE_PT = 1.5


class RunColumns:
    """The right edge each run of flush-left lines had in the PDF, found again from a paragraph's text.

    `column_right_indent` is called with a paragraph and the document's
    right edge, from three places that do not hand it the run the paragraph
    was matched to. The runs of the last `flush_left_runs` are kept here
    instead, indexed by the first characters of their lines, so that a
    paragraph can be given back the column its own lines were set to. A
    paragraph that matches no run, or matches runs that disagree, gets None
    and the caller falls back to the page size's edge.
    """

    def __init__(self):
        self.reset([], None, {})

    def reset(self, runs, content_right, offsets):
        self.runs = runs
        self.joined = ["".join(run["lines"]) for run in runs]
        self.content_right = content_right
        self.offsets = offsets
        self.cache = {}
        self.index = {}
        for number, run in enumerate(runs):
            # A run of two lines or more has a column that means something:
            # a one-line run is a heading or a table cell's text, and its
            # short text turned up inside a long paragraph of another page (a
            # glossary entry's 42 characters inside a body paragraph) and gave
            # that paragraph a half-column indent. Ragged runs are kept so that
            # they can disagree with a justified one that holds the same text.
            if len(run["lines"]) < 2 or len(self.joined[number]) < RUN_MATCH_MIN_CHARS:
                continue
            for line in run["lines"]:
                if len(line) >= RUN_GRAM_CHARS:
                    self.index.setdefault(line[:RUN_GRAM_CHARS], []).append((number, line))

    def page_edge(self, page_width, fallback):
        """The right edge of pages this wide: the document's, moved by what its pages of this size measured."""
        if self.content_right is None:
            return fallback
        return self.content_right + self.offsets.get(round(page_width), 0.0)

    def column_for(self, text, page_width):
        """The column of the run `text` (a paragraph's text) was drawn from, or None when no one run says."""
        key = (text, round(page_width))
        if key in self.cache:
            return self.cache[key]
        if DOT_RUN.search(text):
            # A line with a dot leader is a table of contents entry or a
            # list's: its rows are rebuilt from the PDF's own geometry, and
            # on the TOC page of a 48-page report the column of its rows gave
            # the entries 173 pt of right indent, which wrapped them.
            self.cache[key] = None
            return None
        squashed = compare_squash(text)
        looked = set()
        chosen = []
        for at in range(len(squashed) - RUN_GRAM_CHARS + 1):
            for number, line in self.index.get(squashed[at:at + RUN_GRAM_CHARS], ()):
                if number in looked or not squashed.startswith(line, at):
                    continue
                looked.add(number)
                joined = self.joined[number]
                if joined in squashed or (len(squashed) >= RUN_MATCH_MIN_CHARS and squashed in joined):
                    chosen.append(number)
        answer = None
        if chosen:
            same_size = [number for number in chosen if abs(self.runs[number]["pageWidth"] - round(page_width)) <= 2]
            held = same_size or chosen
            ends = sorted(self.runs[number]["column"] for number in held if self.runs[number]["column"] is not None)
            # Every run that holds this text has to be justified, to have a
            # column its lines can be read for, and to end on the same edge:
            # a ragged one has no column, and one that is ragged beside a
            # justified one says the text is laid out both ways.
            if (len(ends) == len(held) and all(self.runs[number]["justified"] for number in held)
                    and ends[-1] - ends[0] <= RUN_COLUMN_AGREE_PT):
                answer = ends[len(ends) // 2]
        self.cache[key] = answer
        return answer


RUN_COLUMNS = RunColumns()


# How many rows must stand on one x0 for it to be a page's own left edge. A
# paragraph is at least a heading and a line, a figure caption is one row, and
# three is the fewest that no stray label or margin note makes up.
PAGE_EDGE_MIN_ROWS = 3


def page_text_left(rows, content_left):
    """Where this page's text starts, when that is not where the document's does.

    `content_left` is one number for the whole document, the median of the
    pages' own leftmost rows. A report with mirrored margins (inside 1.25 in,
    outside 0.75 in) has two left edges, 90 and 54 pt on `mirror.typ`: the
    pages on the document's edge got their repairs, and a page 36 pt left of
    it had no row that was at the edge or indented from it, so it formed no
    run and came out of the converter with no breaks, `jc=left` and a stray
    right indent. With an even page count the median is the midpoint, 72, and
    neither kind of page is on it. A page that has rows on the document's edge
    keeps it. One that has none, and has `PAGE_EDGE_MIN_ROWS` rows on an x0 to
    the left of it, takes the leftmost such x0. Only to the left: a page
    whose text starts further in already forms runs, as indented ones (up to
    `INDENTED_RUN_MAX_PT`), and a continued listing's panel is such a page.
    """
    if any(abs(row["x0"] - content_left) <= JUSTIFY_EDGE_PT for row in rows):
        return content_left
    starts = sorted(row["x0"] for row in rows if row["x0"] < content_left - JUSTIFY_EDGE_PT)
    for start in starts:
        if sum(1 for other in starts if abs(other - start) <= JUSTIFY_EDGE_PT) >= PAGE_EDGE_MIN_ROWS:
            return start
    return content_left


def flush_left_runs(doc, bands, content_left, content_right):
    """Runs of consecutive lines that all begin at the text area's left edge.

    pdf2docx reads alignment off one line's geometry at a time, which goes
    wrong two ways in the same paragraph. It misses justification on some
    paragraphs and not others. And a middle line that happens to sit near the
    middle of the column is marked centred, so it renders a few characters in
    from the margin while the PDF has it flush: the reference report's
    "{{OUR_COMPANY}} strongly recommends..." came out with `jc="center"` in
    between two left-aligned lines of its own paragraph.

    The PDF settles both. A line that starts at the left edge is flush left,
    whatever its right end does, and a run of them whose every line but the
    last also reaches the right edge is justified. Three lines is the shortest
    run where that means anything, because two lines that both reach the edge
    is also what a centred pair looks like.
    """
    member_rows = set()
    for band in bands:
        member_rows |= band.get("members") or set()
    found = []
    # (page width, x1 of the page's widest row) for every page, which is what
    # `page_edge_offsets` needs once the pass has been over all of them.
    page_ends = []
    for index in range(doc.page_count):
        every_row = page_rows(doc[index])
        page_width = round(doc[index].rect.width)
        if every_row:
            page_ends.append((page_width, max(r["x1"] for r in every_row)))
        rows = [r for r in every_row if row_id(index, r) not in member_rows]
        page_left = page_text_left(rows, content_left)
        # Every line of the page, runs or not: a one-word last line ("ut.")
        # is no run of its own, and where a paragraph's text goes on after the
        # lines a run holds, it is one of these that the text goes on in.
        page_keys = [key for key in (compare_squash(r["text"]) for r in rows) if key]
        run = []

        def close(run):
            lines = [compare_squash(r["text"]) for r in run]
            if not any(len(line) >= COMPARE_MIN_CHARS for line in lines):
                return
            justified = False
            edge = max(r["x1"] for r in run)
            column = edge
            if len(run) >= 3:
                # Justified prose ends every line but a paragraph's last on
                # one edge. A run may hold two paragraphs now, so the test
                # is that most lines but the last reach the run's own edge,
                # within `JUSTIFY_SPREAD_PT`; ragged prose puts one or two
                # of ten there by chance, never half of them.
                reaching = lines_reaching_edge(run)
                justified = len(reaching) >= 2 and len(reaching) >= 0.5 * (len(run) - 1)
                column = run_column([r["x1"] for r in run[:-1] if not hangs_into_margin(r["text"])], None)
            elif len(run) == JUSTIFY_MIN_LINES:
                # Two lines cannot say by themselves; the first reaching the
                # page's column says it for them. Which column the page has
                # depends on its size, so the answer waits until every page's
                # widest row is known (below).
                justified = None
                column = None if hangs_into_margin(run[0]["text"]) else run[0]["x1"]
            found.append({"lines": lines, "justified": justified, "reach": edge, "firstEnd": run[0]["x1"],
                          # Where the run's justified lines end, which is the
                          # column Word has to be given: a landscape page, a
                          # padded block and one column of two each end
                          # somewhere other than the document's usual edge.
                          "column": column, "pageWidth": page_width,
                          "indentedAbove": indented_above(run[0]), "page": index, "pageKeys": page_keys,
                          # A run that does not start at the text's left edge
                          # keeps whatever indents the converter gave it.
                          "indented": abs(run[0]["x0"] - page_left) > JUSTIFY_EDGE_PT,
                          # A line that stops short of the column: the last of
                          # a paragraph, or one typst broke by hand, which it
                          # does not stretch and so neither may Word.
                          "short": [r["x1"] < edge - SHORT_LINE_PT for r in run],
                          # Each line's ink width and word count, which is
                          # what its condensation is sized from.
                          "widths": [r["x1"] - r["x0"] for r in run],
                          "spaces": [max(0, len(r["text"].split()) - 1) for r in run]})

        def indented_above(first):
            """Is the line just above this run's first its paragraph's
            indented first line? It sits on the next line up, and starts a
            first-line indent in from the edge rather than anywhere else."""
            place = rows.index(first)
            if place == 0:
                return False
            above = rows[place - 1]
            indent = above["x0"] - page_left
            return (JUSTIFY_EDGE_PT < indent <= FIRST_LINE_INDENT_MAX_PT
                    and -JUSTIFY_LINE_GAP_PT <= first["y0"] - above["y1"] <= JUSTIFY_LINE_GAP_PT)

        for row in rows + [None]:
            at_edge = row is not None and abs(row["x0"] - page_left) <= JUSTIFY_EDGE_PT
            # A list item's lines stand at one indent, its marker row a little
            # left of the rest (a hanging indent), and a nested item's deeper;
            # those lines wrap where typst wrapped them too, and a run of them
            # gets the same breaks as a run at the edge. Any indent up to
            # `INDENTED_RUN_MAX_PT` starts a run.
            indented = row is not None and not at_edge and 0 < row["x0"] - page_left <= INDENTED_RUN_MAX_PT
            starts = at_edge or indented
            # Consecutive lines of one paragraph: the next line's top may sit
            # a little above the previous line's bottom, because a line box is
            # taller than the text in it.
            close_enough = run and -JUSTIFY_LINE_GAP_PT <= row["y0"] - run[-1]["y1"] <= JUSTIFY_LINE_GAP_PT if row is not None else False
            same_indent = run and abs(row["x0"] - run[-1]["x0"]) <= JUSTIFY_EDGE_PT if row is not None else False
            hanging = (run and len(run) == 1 and 0 < row["x0"] - run[0]["x0"] <= HANGING_INDENT_MAX_PT) if row is not None else False
            follows = starts and close_enough and (same_indent or hanging)
            if not follows:
                close(run)
                run = [row] if starts else []
            else:
                run.append(row)
            # A short line used to end the run, as the last line of its
            # paragraph. That left every ragged paragraph as runs of one line
            # (nothing to break, so Word re-wrapped them) and every line of a
            # finding card the same, since the card's column is narrower
            # than the page's. A run now ends where the lines stop following
            # each other; one that spans two paragraphs is given to both by
            # `force_line_breaks`.
    offsets = page_edge_offsets(page_ends, content_right)
    for run in found:
        page_edge = content_right + offsets.get(run["pageWidth"], 0.0)
        if run["justified"] is None:
            run["justified"] = run["firstEnd"] >= page_edge - JUSTIFY_EDGE_PT
        # How far the run's longest line reaches past the column the page
        # nominally has. Word measures a line against the indents it is
        # given, and a forced line that is a hair too wide wraps twice: the
        # PDF's own overshoot is what that hair measures.
        run["overshoot"] = run["reach"] - page_edge
    RUN_COLUMNS.reset(found, content_right, offsets)
    return found


def set_run_condensation(run, twips):
    properties = run.find(qn("w:rPr"))
    if properties is None:
        properties = OxmlElement("w:rPr")
        run.insert(0, properties)
    if properties.find(qn("w:spacing")) is not None:
        return
    node = OxmlElement("w:spacing")
    node.set(qn("w:val"), str(-int(twips)))
    insert_ordered(properties, node, RPR_ORDER)


def condense_runs(element, twips):
    """Tighten every run of a paragraph by `twips` a character (`w:spacing` in the run).

    Measured through Word on ten ragged lines of Poppins 11 pt: Word sets
    them 0.74% wider than typst, kerning on or off makes no difference, and
    one twip a character brings them to within 0.15%. A run that already
    carries a spacing (a contents entry's leader) keeps it.
    """
    for run in element.iter(qn("w:r")):
        if run.find(qn("w:t")) is not None:
            set_run_condensation(run, twips)


def condensation_for(width, spaces, chars, justified, short):
    """Twips a character that make a line of the PDF's fit Word's column.

    Word's text is `WORD_WIDTH_EXCESS` wider than typst's, and a line typst
    justified has had its spaces shrunk, by up to `SPACE_SHRINK_PT` each
    (2.47 pt against the font's 2.91 pt, measured), which Word gives back.
    The condensation covers both, plus a point, over the line's characters;
    a line that was not stretched needs only the excess, since nothing but
    its own width is at stake.
    """
    if chars <= 0:
        return CONDENSE_RAGGED_TWIPS
    excess = width * WORD_WIDTH_EXCESS
    if justified and not short:
        excess += spaces * SPACE_SHRINK_PT + 1.0
    return max(CONDENSE_RAGGED_TWIPS, int(math.ceil(excess / chars * 20.0)))


def condense_lines(element, lines, widths, spaces, shorts, justified, skip=0):
    """Condense each line of a broken paragraph by what that line needs.

    The paragraph's runs were split at the line ends, so the runs between
    two breaks are one line, and the line is known from its PDF row. The
    first `skip` squashed characters of the paragraph are text before the
    run (a heading the converter joined to it, with its own break): those
    runs get the ragged value and do not count as lines, or every line's
    value lands one line late and the last full line, given a short line's
    value, wraps.
    """
    specs = []
    for text, width, count, short in zip(lines, widths, spaces, shorts):
        specs.append(condensation_for(width, count, max(1, len(text)), justified, short))
    index = 0
    seen = 0
    started = False
    for run in element.iter(qn("w:r")):
        node = run.find(qn("w:t"))
        if node is not None:
            if seen < skip:
                set_run_condensation(run, CONDENSE_RAGGED_TWIPS)
            else:
                started = True
                set_run_condensation(run, specs[min(index, len(specs) - 1)] if specs else CONDENSE_RAGGED_TWIPS)
            seen += len(compare_squash(node.text or ""))
        if started and any((br.get(qn("w:type")) or "textWrapping") == "textWrapping" for br in run.findall(qn("w:br"))):
            index += 1


def tab_before_breaks_until(element, offset):
    """Put a tab before every break in the first `offset` squashed characters of a paragraph.

    The converter writes a heading and the paragraph under it as one block
    with its own break between; the run of body lines that gets broken here
    starts after that heading, which is a line typst left short, and the
    break before it is the converter's, not this pass's.
    """
    seen = 0
    for run in list(element.iter(qn("w:r"))):
        for child in list(run):
            if child.tag == qn("w:t"):
                seen += len(compare_squash(child.text or ""))
            elif child.tag == qn("w:tab"):
                pass
            elif child.tag == qn("w:br") and (child.get(qn("w:type")) or "textWrapping") == "textWrapping":
                if seen > offset:
                    return
                previous = child.getprevious()
                if previous is None or previous.tag != qn("w:tab"):
                    child.addprevious(OxmlElement("w:tab"))


def tab_before_short_breaks(element, short_lines):
    """Put a tab before each existing break that ends one of `short_lines`.

    Word stretches a justified line that ends in a manual break to the
    margin, unless the line ends in a tab, in which case it is left at its
    width (measured). pdf2docx writes a step title and its paragraph as one
    block with a break between them, and the title came out as four words
    spread across the column.
    """
    runs = [node for node in element.iter(qn("w:r"))]
    text = ""
    for run in runs:
        for child in run:
            if child.tag == qn("w:t"):
                text += child.text or ""
            elif child.tag == qn("w:tab"):
                text += "\t"
            elif child.tag == qn("w:br") and (child.get(qn("w:type")) or "textWrapping") == "textWrapping":
                line = compare_squash(text)
                if line and any(line.endswith(s) or s.endswith(line) for s in short_lines) and not text.endswith("\t"):
                    child.addprevious(OxmlElement("w:tab"))
                text = ""


def paragraph_justified(element):
    properties = element.find(qn("w:pPr"))
    node = properties.find(qn("w:jc")) if properties is not None else None
    return node is not None and node.get(qn("w:val")) in ("both", "distribute")


def column_right_indent(document, element, content_right, column=None):
    """The right indent that ends a justified line at the PDF's column.

    pdf2docx sets each page's right margin to the rightmost ink it found,
    which on a page with a wide table or a glyph's overhang is 8 to 12 pt
    past the text column, and Word stretches a justified line to that edge:
    89 lines of a 69-page report ended up to 11.7 pt past where the PDF's
    did. The indent is the difference, never negative.

    The column is where the paragraph's own run of lines ended in the PDF
    (`column`, or found again from the paragraph's text through
    `RUN_COLUMNS`), not the document's one right edge. Measured against that
    edge, a justified paragraph on a landscape page got an indent of 248 pt
    and every forced line wrapped, a padded block was stretched back to the
    full column, and one column of two to the whole page. A column within
    `SHORT_LINE_PT` of the page's edge is the page's edge: that much is the
    ink of a last glyph, a mark typst hangs into the margin (2.9 pt on the
    verbose stress report) or the edge's own estimate, and moving every
    paragraph by it only moved lines past what the checker allows. Short of
    the edge that window is the overhang a mark can have, `HANGING_OVERSHOOT_EM`
    of the paragraph's type, not the whole 6 pt: a block inset 5 pt from
    the right (`block(inset: (x: 5pt))`, `pad(x: 4pt)`) is a column of its own
    and snapped to the page's, so Word stretched each of its lines up to 5 pt
    past the PDF's. In the stress set no justified run ends between 3.3 and
    6 pt short of the edge, so the narrower window moves none of them. A
    paragraph no run claims is measured against the edge of pages its size,
    and so is one that
    is not justified: a ragged line never stretches, so a column wider than
    its run's costs nothing, and one narrower makes Word wrap what the PDF
    did not.
    """
    if content_right is None:
        return 0.0
    body = document.element.body
    block = top_level_block(body, element)
    if block is None:
        return 0.0
    sections = document.sections
    section = sections[min(section_index_of(body, block), len(sections) - 1)]
    width = section.page_width.pt
    edge = width - section.right_margin.pt
    if column is None and paragraph_justified(element):
        column = RUN_COLUMNS.column_for(paragraph_text(element), width)
    page_column = RUN_COLUMNS.page_edge(width, content_right)
    size = paragraph_font_size(element)
    # The page's column comes from body lines, whose ends carry a trailing
    # space of the body's size; a smaller paragraph's carry a smaller one, so
    # its column reads 0.25 em of the difference short of the page's (an 8 pt
    # disclaimer in an 11 pt report was given a column 2.7 pt narrower than
    # the PDF's). The window is sized from the larger of the two sizes.
    body = body_font_size(document)
    if size is not None and body is not None:
        size = max(size, body)
    short_window = SHORT_LINE_PT if size is None else min(SHORT_LINE_PT, HANGING_OVERSHOOT_EM * size)
    if column is None or -short_window <= column - page_column <= SHORT_LINE_PT:
        column = page_column
    return max(0.0, edge - column)


def body_font_size(document):
    """The font size, in points, that most of the body's text is set in, or None; worked out once per document."""
    cached = getattr(document, "_btct_body_size", False)
    if cached is not False:
        return cached
    weights = {}
    for run in document.element.body.iter(qn("w:r")):
        node = run.find(qn("w:rPr") + "/" + qn("w:sz"))
        text = "".join(t.text or "" for t in run.findall(qn("w:t")))
        if node is None or not text.strip():
            continue
        try:
            size = float(node.get(qn("w:val"))) / 2.0
        except (TypeError, ValueError):
            continue
        weights[size] = weights.get(size, 0) + len(text)
    found = max(weights, key=weights.get) if weights else None
    try:
        document._btct_body_size = found
    except AttributeError:
        pass
    return found


def paragraph_box(document, element):
    """`(container, left, right)` in points: the width the paragraph's cell or section gives it and its indents, or None."""
    body = document.element.body
    properties = element.find(qn("w:pPr"))
    indent = properties.find(qn("w:ind")) if properties is not None else None
    left = (twips_of(indent.get(qn("w:left"))) if indent is not None else None) or 0.0
    right = (twips_of(indent.get(qn("w:right"))) if indent is not None else None) or 0.0
    cell = None
    node = element.getparent()
    while node is not None and node is not body:
        if node.tag == qn("w:tc"):
            cell = node
            break
        node = node.getparent()
    if cell is not None:
        settings = cell.find(qn("w:tcPr"))
        size = settings.find(qn("w:tcW")) if settings is not None else None
        width = twips_of(size.get(qn("w:w"))) if size is not None and size.get(qn("w:type")) == "dxa" else None
        if width is None:
            return None
        width -= cell_text_margin(cell, "left") + cell_text_margin(cell, "right")
    else:
        block = top_level_block(body, element)
        if block is None:
            return None
        sections = document.sections
        section = sections[min(section_index_of(body, block), len(sections) - 1)]
        if section.page_width is None or section.left_margin is None or section.right_margin is None:
            return None
        width = section.page_width.pt - section.left_margin.pt - section.right_margin.pt
    return width, left, right


def cell_text_margin(cell, side):
    """A cell's left or right inner margin as Word will use it: its own, else its table's, else Word's default."""
    holders = []
    properties = cell.find(qn("w:tcPr"))
    if properties is not None and properties.find(qn("w:tcMar")) is not None:
        holders.append(properties.find(qn("w:tcMar")))
    table = next((a for a in cell.iterancestors() if a.tag == qn("w:tbl")), None)
    settings = table.find(qn("w:tblPr")) if table is not None else None
    if settings is not None and settings.find(qn("w:tblCellMar")) is not None:
        holders.append(settings.find(qn("w:tblCellMar")))
    for holder in holders:
        for name in CELL_MARGIN_NAMES[side]:
            found = holder.find(qn(name))
            if found is not None:
                value = twips_of(found.get(qn("w:w")))
                if value is not None:
                    return value
    return DEFAULT_CELL_MARGIN_PT


# The advance of the monospace faces this repo ships, DejaVu Sans Mono's 0.602 em
# among them; Fira Mono, JetBrains Mono and Courier are 0.6.
MONO_ADVANCE_EM = 0.602
# A line typst ran off the page is drawn by Word only as far as its cell's
# right edge: measured through Word on a 9 pt DejaVu Sans Mono token of 98
# characters, the glyphs whose start lies past the cell edge (547.7 pt) were
# never painted, 87 of the 98 showed, and widening the cell moved the cut with
# it (to the page margin, 559.8 pt, when the cell reached past it). A body
# paragraph is not cut. A line only this much wider than the cell is set a
# little tighter so all of it shows; the cell's edge less this is where it ends.
CELL_EDGE_SLACK_PT = 1.0
# The tightening it takes is limited to this share of the glyph advance: a
# monospace glyph's ink is about 0.52 em of its 0.602 em advance, so 15% (0.09
# em) leaves the glyphs touching and no more. A longer line (a 400-character
# token) stays as typst set it, and Word cuts it at the edge.
CODE_SQUEEZE_MAX = 0.15


def let_line_overflow(document, element):
    """A right indent negative enough that a line typst ran off the page is one line in Word too.

    A token with no break in it (a 96-character hash in a URL) ran into the
    margin and off the page in the PDF; the Word file holds it whole once
    `restore_cut_lines` has put its end back, and Word then wrapped the last
    characters round, which made the panel a line taller. Text may hang past
    a cell's edge when the paragraph's right indent is negative by that much,
    so the line runs off the page as the PDF's did. The width is the line's
    characters at the run's own size and the monospace advance, plus what
    Word adds to typst's widths. Inside a cell Word paints a line only as far
    as the cell's own edge (`CELL_EDGE_SLACK_PT`), so a line that is within
    `CODE_SQUEEZE_MAX` of fitting there is set tighter, run by run, to end at
    that edge; one further over keeps typst's spacing and is cut by Word.
    The lines are the paragraph's own, split at its breaks, so the paragraph
    must already have a break at every PDF line end (`overflow_code_rows`).
    Returns whether the indent was written.
    """
    box = paragraph_box(document, element)
    if box is None:
        return False
    container, left, right = box
    lines = [""]
    line_runs = [[]]
    size = None
    for run in element.iter(qn("w:r")):
        properties = run.find(qn("w:rPr"))
        node = properties.find(qn("w:sz")) if properties is not None else None
        value = twips_of(node.get(qn("w:val"))) if node is not None else None
        if value is not None and run.find(qn("w:t")) is not None:
            size = max(size or 0.0, value * 10.0)
        for child in run:
            if child.tag == qn("w:t"):
                lines[-1] += child.text or ""
                if not line_runs[-1] or line_runs[-1][-1] is not run:
                    line_runs[-1].append(run)
            elif child.tag == qn("w:br"):
                lines.append("")
                line_runs.append([])
            elif child.tag == qn("w:tab"):
                lines[-1] += "    "
    if not size or not any(line.strip() for line in lines):
        return False
    advance = MONO_ADVANCE_EM * size
    cell = next((a for a in element.iterancestors() if a.tag == qn("w:tc")), None)
    # How far a line may reach: the cell's own edge, which is its text area
    # and the right margin Word gives the cell beyond it.
    limit = container - left + cell_text_margin(cell, "right") - CELL_EDGE_SLACK_PT if cell is not None else None
    needed = 0.0
    for index, line in enumerate(lines):
        chars = len(line.rstrip())
        width = chars * advance * (1.0 + WORD_WIDTH_EXCESS)
        if limit is not None and chars and width > limit and 1.0 - limit / (chars * advance) <= CODE_SQUEEZE_MAX:
            # Tightened by what it takes for Word's wider text to end at the
            # cell's edge, a twip over rather than under.
            twips = int(math.ceil((width - limit) / chars * 20.0))
            for run in line_runs[index]:
                set_run_condensation(run, twips)
            width = limit
        needed = max(needed, width)
    overflow = needed - (container - left - right)
    if overflow <= 0:
        return False
    Paragraph(element, document).paragraph_format.right_indent = Pt(-round(overflow - right + 2.0, 1))
    return True


def edge_tab_stop(document, element):
    """A right tab stop at the paragraph's right text edge, so a tab before a break reaches it.

    Word takes a tab to the next tab stop, and the default stops are every
    half inch from the margin. A line that ends 6 pt short of its column
    with the next stop past the edge wrapped the tab and the break onto a
    line of their own, and the paragraph gained an empty line (a finding
    card's prose on page 44 of a 69-page report). A stop a point inside the
    edge is always reachable from a line the PDF left short.
    """
    box = paragraph_box(document, element)
    if box is None:
        return
    width, _, right = box
    position = width - right - 1.0
    if position <= 1.0:
        return
    Paragraph(element, document).paragraph_format.tab_stops.add_tab_stop(Pt(round(position, 1)), WD_TAB_ALIGNMENT.RIGHT)


def force_line_breaks(document, runs, shaded, page_count=None, content_right=None):
    """Break each paragraph where the PDF broke it.

    Word's text engine breaks a justified line a word earlier or later than
    typst did, and on a text-heavy page that is the whole of what is left to
    see. The PDF knows where every line ended, so the converter's paragraphs
    are split there with a manual break and left justified: Word justifies a
    line that ends in a manual break, so they still reach both margins.

    What this costs is re-flow. Editing such a paragraph leaves the old breaks
    where they were, and the reader has to delete them (Find and Replace, `^l`
    for a space) to get a paragraph that wraps by itself again. The owner
    asked for the PDF's layout, which is what `--line-breaks=pdf` means.

    Code is never touched: a code block's lines are already separate
    paragraphs and its text must come out byte for byte. Neither is a
    paragraph the PDF wrote as one line, because there is nothing to break.
    """
    paragraphs = body_paragraphs(document)
    squashed = [compare_squash(paragraph_text(p)) for p in paragraphs]
    pages = paragraph_pages(document, page_count)
    on_page = [pages.get(id(p)) for p in paragraphs] if pages is not None else None
    shaded = set(shaded)
    cursor = 0
    broken = 0
    used = set()
    for run in runs:
        count = len(run["lines"])
        # Where a part of a run ends inside a paragraph, the rest of the
        # paragraph has to be a line of this page: these are the lines the
        # page has (none known: nothing to check the rest against).
        known_lines = run.get("pageKeys")
        # Every line is kept, however short: the run's lines are matched
        # joined, end to end, so a short one only makes the match exact, and
        # a paragraph that ends on "in.", "Ut." or "20." needs the break
        # before that line as much as any. Dropped, the word was drawn on
        # the line above and the page ended a line early (pages 53 and 60 of
        # a 69-page report), and a paragraph ending on "20." in the middle
        # of a run ended with text the run did not hold, so nothing in the
        # run was given its breaks (page 17 of a 104-page report).
        kept = [(line, short, width, spaces)
                for line, short, width, spaces in zip(run["lines"], run.get("short") or [False] * count,
                                                      run.get("widths") or [0.0] * count, run.get("spaces") or [0] * count)
                if line]
        lines = [line for line, _, _, _ in kept]
        shorts = [short for _, short, _, _ in kept]
        widths = [width for _, _, width, _ in kept]
        spaces = [spaces for _, _, _, spaces in kept]
        if len(lines) < 2:
            cursor += 1
            continue
        joined = "".join(lines)
        # The run's lines are not always the whole of a paragraph. The
        # converter writes a sub-heading and the paragraph under it as one
        # block, with a break between them, and the run then holds only the
        # body: an exact match misses it, nothing is broken, and Word wraps
        # those lines itself. Five paragraphs of the reference report, and
        # twelve of its lines, were ending up somewhere the PDF never put
        # them for exactly this reason.
        # The run has to be the END of the paragraph, not merely somewhere
        # inside it. A table-of-contents entry contains its own title twice
        # over once the leader is squashed away, and an inside match put a
        # line break in the middle of a row of dots.
        position, skip = None, 0
        if on_page is not None and run.get("page") is not None:
            candidates = [i for i in range(len(squashed)) if on_page[i] == run["page"] and i not in used]
        else:
            candidates = list(range(cursor, len(squashed)))
        for index in candidates:
            if squashed[index].endswith(joined):
                position, skip = index, len(squashed[index]) - len(joined)
                break
        if position is None:
            # Inside a finding card the gap between two paragraphs is less
            # than a line, so the PDF's rows read as one run across both.
            # The run is then given to the paragraphs from its end: the
            # paragraph that ends with the longest tail of it takes those
            # lines, and the rest are looked for in another.
            remaining = list(zip(lines, shorts, widths, spaces))
            while remaining:
                best = None
                inside = None
                for index in candidates:
                    if index in used or DOT_RUN.search(paragraph_text(paragraphs[index])):
                        continue
                    for j in range(0, len(remaining)):
                        tail = "".join(line for line, _, _, _ in remaining[j:])
                        if squashed[index].endswith(tail):
                            # A tie goes to the later paragraph: the run's
                            # tail is the end of the last paragraph it
                            # reaches, and repeated prose let an earlier
                            # paragraph end with the same words by chance
                            # (page 231 of a 286-page report).
                            if best is None or j < best[1] or (j == best[1] and index > best[0]):
                                best = (index, j)
                            break
                        # pdf2docx joins a nested list item to the item above
                        # it, so a run's last lines end inside a paragraph
                        # rather than at its end, and no paragraph ended with
                        # any tail: a bullet and its sub-item took the 13
                        # lines of their run with them (page 17 of a 92-page
                        # report). The longest tail a paragraph holds whole
                        # takes its lines where they stand; the joined
                        # remainder is left to the run it belongs to, and the
                        # paragraph stays open for that run.
                        at = squashed[index].find(tail)
                        if (at >= 0 and known_lines is not None and not begins_a_line(squashed[index][at + len(tail):], known_lines)):
                            # The tail ends inside this paragraph, so the PDF
                            # broke the line there and the rest of the text
                            # starts the next one. A "." that is no line of
                            # the page is no such rest: the bullet "... Sed
                            # do eiusmod." held the first line of "... Sed
                            # do eiusmod tempor.", took its break, and Word
                            # wrapped the full stop onto a line of its own
                            # (page 168 of a 291-page report).
                            continue
                        if at >= 0 and not DOT_RUN.search(paragraph_text(paragraphs[index])):
                            if inside is None or j < inside[1] or (j == inside[1] and index > inside[0]):
                                inside = (index, j, at)
                            break
                if best is None and inside is None:
                    # No paragraph ends with or holds any tail: the run's last
                    # line is one the file has no paragraph for (a table row
                    # the PDF reads as one line across two cells, "TECHNIQUES
                    # MITIGATIONS", which a finding card's gaps let into the
                    # run above it). It is dropped, and the lines above it
                    # get their breaks; a 30-line card lost every one of them
                    # to that row on page 66 of a 175-page report.
                    remaining = remaining[:-1]
                    continue
                ended = best is not None
                if ended:
                    index, j = best
                    used.add(index)
                    part_skip = None
                else:
                    index, j, part_skip = inside
                part = remaining[j:]
                remaining = remaining[:j]
                element = paragraphs[index]
                if is_code(element, shaded):
                    continue
                part_lines = [line for line, _, _, _ in part]
                part_shorts = [short for _, short, _, _ in part]
                part_widths = [width for _, _, width, _ in part]
                part_spaces = [count for _, _, _, count in part]
                if part_skip is None:
                    part_skip = len(squashed[index]) - len("".join(part_lines))
                justified = bool(run.get("justified")) or paragraph_justified(element)
                # A part that ends inside the paragraph (the item pdf2docx
                # joined to it follows) gets a break after its last line too.
                continues = part_skip + len("".join(part_lines)) < len(squashed[index])
                cut_lines = part_lines + ([""] if continues else [])
                cut_shorts = part_shorts + ([False] if continues else [])
                added = split_paragraph_at(element, cut_lines, part_skip, tabs=cut_shorts if justified else None)
                if added:
                    condense_lines(element, part_lines, part_widths, part_spaces, part_shorts, justified, part_skip)
                    if not in_table_single_line(document.element.body, element):
                        indent = column_right_indent(document, element, content_right) if justified else 0.0
                        Paragraph(element, document).paragraph_format.right_indent = Pt(round(indent, 1))
                    if justified and part_skip > 0 and ended:
                        tab_before_breaks_until(element, part_skip)
                    if justified and any(True for _ in element.iter(qn("w:tab"))):
                        edge_tab_stop(document, element)
                broken += added
            cursor += 1
            continue
        used.add(position)
        element = paragraphs[position]
        if is_code(element, shaded):
            cursor = position + 1
            continue
        # A paragraph in a table cell is broken like any other now that its
        # lines are condensed to fit: left to Word, a finding card's prose
        # wrapped to four lines where the PDF had three and the model that
        # places the blocks under it counted the PDF's, so a panel below sat
        # 50 pt too low. The cell's own width is the PDF's, so no indent.
        in_cell = in_table_single_line(document.element.body, element)
        # A run of two lines cannot say whether it was justified, and the
        # converter's own alignment then stands: a justified paragraph with
        # breaks in it gets its short lines a tab and its lines the column.
        justified = bool(run.get("justified")) or paragraph_justified(element)
        if DOT_RUN.search(paragraph_text(element)):
            # A row of dots is deleted by the comparison but not by the text,
            # so a character offset counted in one does not mean the same
            # place in the other, and a break landed in the middle of a table
            # of contents entry's leader. Those lines are rebuilt from the
            # PDF elsewhere and have no business here.
            cursor = position + 1
            continue
        added = split_paragraph_at(element, lines, skip, tabs=shorts if justified else None)
        if added:
            # Word sets these lines a fraction wider than typst, which is
            # enough to wrap the last word round when the line fills the
            # column. The runs are condensed by a twip a character, two for
            # a justified paragraph, so every line fits; Word then stretches
            # a justified line back to the margin, exactly as typst did, and
            # a ragged line is within 0.15% of its width in the PDF. No
            # widening of the column is needed, and none is written, so no
            # line ends past the margin.
            condense_lines(element, lines, widths, spaces, shorts, justified, skip)
            if not in_cell:
                indent = column_right_indent(document, element, content_right) if justified else 0.0
                Paragraph(element, document).paragraph_format.right_indent = Pt(round(indent, 1))
            if justified and skip > 0:
                # The heading the converter joined to this paragraph ends in
                # its own break, and that line was short in the PDF.
                tab_before_breaks_until(element, skip)
            if justified and any(True for _ in element.iter(qn("w:tab"))):
                edge_tab_stop(document, element)
        broken += added
        cursor = position + 1
    return broken


def begins_a_line(rest, page_lines):
    """Is `rest` (squashed text) the start of one of the page's lines, or an empty remainder?

    A line that is a prefix of the rest counts as well, since the rest may
    run over several lines and only the first is looked for.
    """
    return not rest or any(line.startswith(rest) or rest.startswith(line) for line in page_lines)


def break_cell_lines(document, lines, shaded, page_count=None):
    """Break a table cell's paragraph where the PDF's lines in that cell end.

    The line-break pass works from runs of lines at the page's left edge or
    a little in, so a cell in a table's right-hand column is out of its reach;
    pdf2docx joins that cell's lines into one paragraph with a right indent of
    its own guessing, Word wraps it somewhere else, and an exact row clips
    what wrapped: "2. ... dolor. 3. ..." on shape-c lost its third step on
    seven pages. The PDF's lines are read cell by cell (each line's pieces
    are its columns), so a paragraph whose text is exactly some of a page's
    pieces in reading order, two or more of them, gets a break at each piece's
    end and loses its right indent: the cell is the PDF's width already.
    A cell paragraph pdf2docx already broke in some places is finished the
    same way when each of its breaks falls where one of the PDF's lines ends:
    pdf2docx keeps a break only where the line before it stopped short of the
    cell's guess at a right edge, so the labels of design-b1's cover table
    ("Prepared by", "Engagement window", "Report version", "Classification",
    one cell, 86.6 pt for the longest) came out as breaks after "Prepared by"
    and "Report version" only, "Engagement window Report version" ran on as
    one line, and Word wrapped it in the 86.6 pt the right indent left it.
    A break that is not at a line end of the PDF leaves the paragraph alone.
    Only a cell paragraph that is not code, on a known page.
    Returns how many paragraphs were broken.
    """
    # The paragraphs first: the page map is keyed by the id of each element,
    # which names the same element only while something holds it.
    paragraphs = body_paragraphs(document)
    pages = paragraph_pages(document, page_count)
    if pages is None:
        return 0
    shaded = set(shaded)
    by_page = {}
    for order, line in enumerate(lines):
        page = line.get("page")
        if page is None:
            continue
        # A step's number is a piece of its own ("2." beside its text), so
        # every run of a line's neighbouring pieces is a candidate as well.
        keys = [compare_squash(piece) for piece in line.get("pieces") or [line["text"]]]
        for first in range(len(keys)):
            for last in range(first, len(keys)):
                key = "".join(keys[first:last + 1])
                if key:
                    by_page.setdefault(page - 1, []).append((order, key))
    body = document.element.body
    broken = 0
    for element in paragraphs:
        if not in_table_single_line(body, element) or is_code(element, shaded):
            continue
        text = compare_squash(paragraph_text(element))
        if len(text) < 2 * COMPARE_MIN_CHARS or DOT_RUN.search(paragraph_text(element)):
            continue
        own_breaks = break_offsets(element)
        if own_breaks is None:
            continue
        pieces = by_page.get(pages.get(id(element)))
        if not pieces:
            continue
        found = None
        for start, (order, key) in enumerate(pieces):
            if len(key) < COMPARE_MIN_CHARS or not text.startswith(key) or key == text:
                continue
            chain, at, last = [key], len(key), order
            while at < len(text):
                # The next line's longest candidate that continues the text.
                step = None
                for later, later_key in pieces:
                    if later <= last or len(later_key) < COMPARE_MIN_CHARS or not text.startswith(later_key, at):
                        continue
                    if step is None or later < step[0] or (later == step[0] and len(later_key) > len(step[1])):
                        step = (later, later_key)
                if step is None:
                    break
                chain.append(step[1])
                at += len(step[1])
                last = step[0]
            if at == len(text) and len(chain) >= 2:
                ends, total = set(), 0
                for piece in chain[:-1]:
                    total += len(piece)
                    ends.add(total)
                if own_breaks <= ends:
                    found = chain
                    break
        if found is None:
            continue
        added = split_paragraph_at(element, found)
        if added:
            paragraph = Paragraph(element, document)
            paragraph.paragraph_format.right_indent = Pt(0)
            if paragraph.alignment == WD_ALIGN_PARAGRAPH.CENTER:
                # pdf2docx writes a centred cell's indents in pairs (288 and 288
                # twips on `cellc.typ`); dropping one side alone moved the
                # centre by half of what the other kept.
                paragraph.paragraph_format.left_indent = Pt(0)
            broken += 1
    return broken


LIST_MARKER = re.compile(r"(?:\d{1,3}[.)]?|[A-Za-z][.)]|[ivxIVX]{1,4}[.)]|[\u2022\u25cf\u25aa\u25e6\u2023\u2219\u2013\u2014*-])")
"""What a list item's marker may be: a number, a letter or a roman numeral with its stop, or a bullet."""
HANGING_EDGE_PT = 1.5
"""How far a line may start from the marker's or the text's edge and still be on it."""
HANGING_GAP_PT = 13.0
"""The widest gap between a marker and its text on one row: list items measured 4 to 13 pt, a table's next column 18 and more."""
HANGING_GAP_LINES = 2.0
"""The widest gap between a badge's number, a row of its own, and its text, in line heights (b2's measured 15.2 pt)."""
LINE_CHILDREN = ("w:pPr", "w:r", "w:bookmarkStart", "w:bookmarkEnd", "w:proofErr")


def restore_list_hanging(document, lines, shaded=(), page_count=None, declined=None):
    """Give list items the PDF's hanging layout: the text after the marker, and every wrapped line, on one edge.

    typst sets a numbered or bulleted item's marker at the list's edge and its
    text, first line and wrapped lines alike, at an edge of its own 5 to 7 pt
    past the marker. pdf2docx writes the marker and the text with a space
    between them and no hanging indent, and joins consecutive items into one
    paragraph with breaks between their lines, so in Word every wrapped line
    started under the marker (verbose-a's "tempor." at 54.0 against the PDF's
    68.3) and a round step badge had its text drawn over it. No gate saw it:
    the text is all there, and the checker measures where code lines start,
    not prose.

    A paragraph's lines (between its breaks) are matched to the PDF's rows on
    its page, in order and whole; the first must be a marker line: a row whose
    first piece is a marker and whose second starts the text, no more than
    `HANGING_GAP_PT` on (a badge's number, a row of its own, within
    `HANGING_GAP_LINES` line heights). A marker line gets a tab after its
    marker, and a line the PDF starts at its item's text edge gets a tab
    before its first word, with a left tab stop at that edge. Each item keeps
    its own edge ("9." and "10." may differ). A tab pdf2docx already wrote in
    one of those two places stays the only one (a second one went on to the
    next stop, a right stop at the margin). A paragraph with a hanging indent
    is one item already laid out: its wrapped lines stand on the indent, and
    only the marker's space becomes a tab, which Word takes to the indent, when
    the indent is the PDF's gap; a second item in it, or another indent, and
    it is left. A paragraph with a line that matches no row, a line that
    starts anywhere but the marker's or its item's text edge, a marker line on
    another edge, a tab inside a line, a centred or right-aligned paragraph,
    or anything in it but runs is left alone (`hanging-declined`). Code and
    contents lines are never touched. Tabs are whitespace to the text check.
    Returns how many paragraphs were changed.
    """
    # Held before the pages are read: `paragraph_pages` keys by id, and lxml
    # reuses the id of a proxy nobody holds.
    paragraphs = body_paragraphs(document)
    pages = paragraph_pages(document, page_count)
    if pages is None:
        return 0
    shaded = set(shaded)
    rows_of = {}
    for line in lines:
        if line.get("page") is not None and line.get("ends") and line.get("widths"):
            rows_of.setdefault(line["page"] - 1, []).append(line)
    changed = 0
    for element in paragraphs:
        if is_code(element, shaded) or DOT_RUN.search(paragraph_text(element)):
            continue
        if any(ancestor.tag == qn("w:txbxContent") for ancestor in element.iterancestors()):
            continue
        alignment = element.find(qn("w:pPr") + "/" + qn("w:jc"))
        if alignment is not None and alignment.get(qn("w:val")) in ("center", "right", "end"):
            continue
        rows = rows_of.get(pages.get(id(element)))
        if not rows:
            continue
        opening = paragraph_text(element).lstrip()
        head = opening.split(None, 1)[0] if opening.split(None, 1) else ""
        if not LIST_MARKER.fullmatch(head) or len(opening.split(None, 1)) < 2:
            continue
        if any(child.tag not in tuple(qn(tag) for tag in LINE_CHILDREN) for child in element):
            if declined is not None:
                declined["hanging-declined"] += 1
            continue
        # The paragraph's lines: the text nodes and tabs of each, between breaks.
        word_lines, current = [], []
        for run in element.findall(qn("w:r")):
            for node in run:
                if node.tag == qn("w:br"):
                    if (node.get(qn("w:type")) or "textWrapping") != "textWrapping":
                        current = None
                        break
                    word_lines.append(current)
                    current = []
                elif node.tag in (qn("w:t"), qn("w:tab")):
                    current.append(node)
            if current is None:
                break
        if current is None:
            continue
        word_lines.append(current)
        texts = ["".join((node.text or "") if node.tag == qn("w:t") else "\t" for node in nodes) for nodes in word_lines]
        if any(not compare_squash(line) for line in texts):
            continue
        # A tab may stand only where this pass would put one: first in a
        # line, or right after its marker; one before a break (a short line
        # of a justified paragraph) is the line-break pass's.
        inner = []
        for line in texts:
            body_text = line.strip(" \u00a0").rstrip("\t").lstrip("\t")
            parts = body_text.split(None, 1)
            if parts and LIST_MARKER.fullmatch(parts[0].rstrip("\t")) and body_text[len(parts[0]):][:1] == "\t":
                body_text = body_text[len(parts[0]) + 1:]
            inner.append("\t" in body_text)
        if any(inner):
            if declined is not None:
                declined["hanging-declined"] += 1
            continue
        # Each line is a row of the page, in order, with the marker's and the
        # text's edges when it starts an item and where it starts.
        matched, at = [], 0
        for line in texts:
            found = match_list_line(line, rows, at)
            if found is None:
                break
            at = found[0] + 1
            matched.append(found[1:])
        if len(matched) != len(texts):
            continue
        first = matched[0][0]
        if first is None:
            continue
        base = first[0]
        plan, text_edge = [], None
        for nodes, line, (edges, start) in zip(word_lines, texts, matched):
            if edges is not None and abs(edges[0] - base) <= HANGING_EDGE_PT:
                if not LIST_MARKER.fullmatch(line.lstrip().split(None, 1)[0] if line.split() else ""):
                    plan = None
                    break
                text_edge = edges[1]
                plan.append(("marker", nodes, text_edge - base))
            elif abs(start - base) <= HANGING_EDGE_PT:
                plan.append(("plain", nodes, 0.0))
            elif text_edge is not None and abs(start - text_edge) <= HANGING_EDGE_PT:
                plan.append(("wrapped", nodes, text_edge - base))
            else:
                plan = None
                break
        if not plan:
            if declined is not None:
                declined["hanging-declined"] += 1
            continue
        properties = element.find(qn("w:pPr"))
        indent = properties.find(qn("w:ind")) if properties is not None else None
        left = (twips_of(indent.get(qn("w:left"))) if indent is not None else None) or 0.0
        first_line = (twips_of(indent.get(qn("w:firstLine"))) if indent is not None else None) or 0.0
        hanging = (twips_of(indent.get(qn("w:hanging"))) if indent is not None else None) or 0.0
        if first_line:
            continue
        if hanging:
            # One item, laid out by its indent: the marker line starts the
            # paragraph and every other line is a wrapped one on the indent.
            kinds = [kind for kind, _, _ in plan]
            if (kinds[0] != "marker" or any(kind != "wrapped" for kind in kinds[1:])
                    or abs(plan[0][2] - hanging) > HANGING_EDGE_PT):
                if declined is not None:
                    declined["hanging-declined"] += 1
                continue
            if not marker_has_tab(plan[0][1]):
                insert_tab_after_marker(plan[0][1])
                tabs = properties.find(qn("w:tabs"))
                if tabs is not None:
                    # A stop short of the indent would take the tab first.
                    for stop in list(tabs.findall(qn("w:tab"))):
                        position = twips_of(stop.get(qn("w:pos")))
                        if (stop.get(qn("w:val")) or "left") != "right" and position is not None \
                                and left - hanging < position < left - 1.0:
                            tabs.remove(stop)
                changed += 1
            continue
        stops = sorted({round(left + offset, 1) for kind, _, offset in plan if kind != "plain"})
        for kind, nodes, offset in plan:
            if kind == "marker" and not marker_has_tab(nodes):
                insert_tab_after_marker(nodes)
            elif kind == "wrapped" and not starts_with_tab(nodes):
                insert_tab_at_start(nodes)
        tabs = properties.find(qn("w:tabs")) if properties is not None else None
        if tabs is not None:
            for stop in list(tabs.findall(qn("w:tab"))):
                position = twips_of(stop.get(qn("w:pos")))
                if (stop.get(qn("w:val")) or "left") != "right" and position is not None \
                        and left < position < max(stops) + 1.0 and all(abs(position - s) > 1.0 for s in stops):
                    tabs.remove(stop)
        for stop in stops:
            if tabs is None or all(abs((twips_of(t.get(qn("w:pos"))) or -99.0) - stop) > 1.0
                                   for t in tabs.findall(qn("w:tab"))):
                add_left_tab_stop(element, stop)
                tabs = element.find(qn("w:pPr")).find(qn("w:tabs"))
        changed += 1
    return changed


OUTLINE_MARKER = re.compile(r"\d{1,3}(?:\.\d{1,3}){1,5}[.)]?")
"""A multi-level number that opens an outline item ("2.1", "2.2.1.1", "1.2."). `LIST_MARKER` leaves it out, since
`restore_list_hanging` lays out one level of a list and a numbered heading would read as an item there."""

LIST_ROW_BELOW = 0.5
"""How far a row must stand below the one before it, in that row's height, to be the next line and not one beside it.
A list's rows stand a line apart (14 pt for 10.5 pt rows on a2); two cells' rows side by side share a top."""


def starts_list_item(row):
    """Does this PDF row open a list item: a marker or outline number as its first piece and the text close after it?"""
    pieces, ends, widths = row.get("pieces") or [], row.get("ends") or [], row.get("widths") or []
    if len(pieces) < 2 or len(ends) < 2 or len(widths) < 2:
        return False
    head = pieces[0].strip()
    if not (LIST_MARKER.fullmatch(head) or OUTLINE_MARKER.fullmatch(head)):
        return False
    gap = ends[1] - widths[1] - ends[0]
    return 0 <= gap <= HANGING_GAP_PT


def line_texts(element):
    """A paragraph's text between its line breaks, tabs as tabs; None when it holds a break of another kind."""
    texts, current = [], []
    for run in element.iter(qn("w:r")):
        for node in run:
            if node.tag == qn("w:br"):
                if (node.get(qn("w:type")) or "textWrapping") != "textWrapping":
                    return None
                texts.append("".join(current))
                current = []
            elif node.tag == qn("w:t"):
                current.append(node.text or "")
            elif node.tag == qn("w:tab"):
                current.append("\t")
    texts.append("".join(current))
    return texts


def joined_rows(key, keys, rows):
    """`(first, last)`: the one stretch of two or more consecutive rows whose text is this line, whole, or None.

    `key` is the line's squashed text, `keys` the page's rows' squashed texts
    in page order. Each row of the stretch stands below the one before it by
    `LIST_ROW_BELOW` of its height. A line that two stretches could make is
    left alone.
    """
    found = None
    for start in range(len(keys)):
        if not keys[start] or len(keys[start]) >= len(key) or not key.startswith(keys[start]):
            continue
        end, held = start, keys[start]
        while len(held) < len(key) and end + 1 < len(keys) and keys[end + 1]:
            end += 1
            held += keys[end]
        if held != key:
            continue
        if any(rows[index + 1]["y0"] - rows[index]["y0"] < LIST_ROW_BELOW * (rows[index]["y1"] - rows[index]["y0"])
               for index in range(start, end)):
            continue
        if found is not None:
            return None
        found = (start, end)
    return found


def stretched_row(row, ends):
    """Did typst stretch this row to a column's edge, so that it runs on into the next one?

    Typst stretches every row of a justified paragraph but its last to the
    column's edge, and never the last row of a list item. A boxed score at
    the start of the next row ("9.8" with a 5 pt inset is a piece of its
    own) reads as an outline number, and the break and tab put before it
    took the row above out of its paragraph's justification. A row is
    stretched when `PAGE_EDGE_MIN_ROWS` rows of its page, itself included,
    end within `JUSTIFY_SPREAD_PT` of it: a justified paragraph's rows all
    end there, while an outline's or a ragged list's rows end where their
    words do. `ends` are the right ends of the page's rows, sorted.
    """
    end = max(row.get("ends") or [0.0])
    low, high = bisect.bisect_left(ends, end - JUSTIFY_SPREAD_PT), bisect.bisect_right(ends, end + JUSTIFY_SPREAD_PT)
    return high - low >= PAGE_EDGE_MIN_ROWS


def break_before_list_items(document, lines, shaded=(), page_count=None):
    """Break a paragraph's line where the PDF starts a list item on the row below.

    pdf2docx breaks a block's row when it leaves more than a tenth of the
    block's width free, measured against the block's widest row, so the
    widest row never gets a break: when it is a list item's last row, the
    next item runs on after it. a2's outline read "...discovered hosts 3
    Threat modelling", item 3 joined to the deepest item above it. The
    line-break pass gives breaks to runs of rows at one indent, and an
    outline changes indent at every level, so no run held both rows.

    A row whose first piece is a list marker or an outline number ("2.1",
    "2.2.1.1") with the item's text no more than `HANGING_GAP_PT` on
    (`starts_list_item`) starts a line in any layout. A paragraph line that
    is two or more consecutive rows of its page, whole and in order, each
    below the last (`joined_rows`), gets a break before every such row in it.
    A row joined to the one above it without a marker is left: on a2, three
    of the four joins pdf2docx's rule leaves after the line-break pass are
    wraps in a card column narrower than pdf2docx's layout, which Word is
    meant to redo. A justified paragraph gets a tab before each new break,
    as the line-break pass gives its short lines, since Word stretches a
    justified line that ends in a manual break. A marker row after a row
    typst stretched to a column's edge (`stretched_row`) is a wrap like any
    other. Code, contents lines, table
    cells (`break_cell_lines` breaks those at the PDF's pieces), text boxes
    and paragraphs holding anything but runs are left alone. Returns how
    many breaks were inserted.
    """
    # Held before the pages are read: `paragraph_pages` keys by id, and lxml
    # reuses the id of a proxy nobody holds.
    paragraphs = body_paragraphs(document)
    pages = paragraph_pages(document, page_count)
    if pages is None:
        return 0
    shaded = set(shaded)
    rows_of = {}
    for line in lines:
        if line.get("page") is not None and line.get("y0") is not None and line.get("y1") is not None:
            rows_of.setdefault(line["page"] - 1, []).append(line)
    keys_of = {page: [compare_squash(row.get("text") or "") for row in rows] for page, rows in rows_of.items()}
    ends_of = {page: sorted(max(row.get("ends") or [0.0]) for row in rows) for page, rows in rows_of.items()}
    allowed = tuple(qn(tag) for tag in LINE_CHILDREN)
    inserted = 0
    for element in paragraphs:
        page = pages.get(id(element))
        rows = rows_of.get(page)
        if not rows or is_code(element, shaded) or DOT_RUN.search(paragraph_text(element)):
            continue
        if any(ancestor.tag in (qn("w:tc"), qn("w:txbxContent")) for ancestor in element.iterancestors()):
            continue
        if any(child.tag not in allowed for child in element):
            continue
        texts = line_texts(element)
        if texts is None:
            continue
        keys = keys_of[page]
        line_keys = [compare_squash(text) for text in texts]
        whole = compare_squash(paragraph_text(element))
        if "".join(line_keys) != whole:
            continue
        cuts, offset = [], 0
        for key in line_keys:
            found = joined_rows(key, keys, rows) if key else None
            if found is not None:
                at = offset
                for index in range(found[0], found[1]):
                    at += len(keys[index])
                    if starts_list_item(rows[index + 1]) and not stretched_row(rows[index], ends_of[page]):
                        cuts.append(at)
            offset += len(key)
        if not cuts:
            continue
        bounds = [0] + cuts + [len(whole)]
        parts = [whole[start:end] for start, end in zip(bounds, bounds[1:])]
        justified = paragraph_justified(element)
        added = split_paragraph_at(element, parts, tabs=[True] * len(parts) if justified else None)
        if added and justified:
            edge_tab_stop(document, element)
        inserted += added
    return inserted


def marker_edges(row, marker=None):
    """(marker start, text start) of a row whose first piece is a list marker, or None.

    With `marker`, a row of its own holding just the marker (a number typst
    centres in a round badge sits lower than its text, so it is read as a
    row of its own), and `row` the text row beside it.
    """
    pieces, ends, widths = row.get("pieces") or [], row.get("ends") or [], row.get("widths") or []
    height = (row.get("y1") or 0.0) - (row.get("y0") or 0.0)
    if marker is not None:
        if not ends or not marker.get("ends") or not marker.get("widths"):
            return None
        mark_start, mark_end = marker["ends"][0] - marker["widths"][0], marker["ends"][-1]
        text_start = ends[0] - widths[0]
    else:
        if len(pieces) < 2 or len(ends) < 2 or not LIST_MARKER.fullmatch(pieces[0].strip()):
            return None
        mark_start, mark_end, text_start = ends[0] - widths[0], ends[0], ends[1] - widths[1]
    gap = text_start - mark_end
    if gap < 0:
        return None
    if marker is None and gap > HANGING_GAP_PT:
        return None
    if marker is not None and height > 0 and gap > HANGING_GAP_LINES * height:
        return None
    return mark_start, text_start


def match_list_line(line, rows, at):
    """`(row index, marker edges or None, line start)` of the page's row that is this line, from `at` on, or None.

    A line is a row whole; or, when it is a marker and its text, the text's
    row with a row of just the marker on its left that overlaps it in height.
    """
    key = compare_squash(line)
    for index in range(at, len(rows)):
        row = rows[index]
        if compare_squash(row.get("text") or "") == key:
            return index, marker_edges(row), row["ends"][0] - row["widths"][0]
    parts = line.lstrip().split(None, 1)
    if len(parts) < 2 or not LIST_MARKER.fullmatch(parts[0]):
        return None
    rest = compare_squash(parts[1])
    for index in range(at, len(rows)):
        row = rows[index]
        if compare_squash(row.get("text") or "") != rest:
            continue
        for marker in rows:
            if (marker is not row and (marker.get("text") or "").strip() == parts[0]
                    and marker.get("y0") is not None and row.get("y0") is not None
                    and marker["y0"] < row["y1"] and marker["y1"] > row["y0"]):
                edges = marker_edges(row, marker)
                if edges is not None:
                    return index, edges, edges[0]
        return None
    return None


def marker_has_tab(nodes):
    """Does a marker line already have a tab right after its marker?"""
    seen = False
    for node in nodes:
        if node.tag == qn("w:tab"):
            return seen
        value = node.text or ""
        if not value.strip():
            if seen and value:
                return False
            continue
        if seen:
            return False
        stripped = value.strip()
        marker = stripped.split(None, 1)[0]
        if stripped != marker or value.rstrip() != value:
            return False
        seen = True
    return False


def starts_with_tab(nodes):
    """Is a line's first non-empty node a tab, its text standing on a stop already?"""
    for node in nodes:
        if node.tag == qn("w:tab"):
            return True
        if (node.text or "").strip(" \u00a0"):
            return False
    return False


def insert_tab_after_marker(nodes):
    """Replace the space after a line's marker with a tab."""
    texts = [node for node in nodes if node.tag == qn("w:t")]
    for index, node in enumerate(texts):
        value = node.text or ""
        stripped = value.lstrip()
        if not stripped:
            continue
        cut = len(value) - len(stripped) + len(stripped.split(None, 1)[0])
        rest = value[cut:].lstrip(" \u00a0")
        node.text = value[:cut]
        node.set(qn("xml:space"), "preserve")
        tab = OxmlElement("w:tab")
        node.addnext(tab)
        if rest:
            piece = OxmlElement("w:t")
            piece.text = rest
            piece.set(qn("xml:space"), "preserve")
            tab.addnext(piece)
            return
        # The space ran on into the next node: its leading spaces go too.
        for later in texts[index + 1:]:
            trimmed = (later.text or "").lstrip(" \u00a0")
            later.text = trimmed
            later.set(qn("xml:space"), "preserve")
            if trimmed:
                return
        return


def insert_tab_at_start(nodes):
    """Put a tab before a line's first word, taking the spaces before it away."""
    for node in nodes:
        if node.tag != qn("w:t"):
            continue
        value = node.text or ""
        trimmed = value.lstrip(" \u00a0")
        node.text = trimmed
        node.set(qn("xml:space"), "preserve")
        if trimmed:
            node.addprevious(OxmlElement("w:tab"))
            return


RUN_PIECES_MAX = 3
"""The most neighbouring pieces of a PDF row `condense_cell_lines` joins into one key."""
SPLIT_DASH_KEY_CHARS = 12
"""How many comparable characters either side of a moved dash must match the PDF's rows."""


def return_split_dashes(document, lines, shaded=(), page_count=None):
    """Give a dash pdf2docx moved to the start of the next line back to the line the PDF ends with it.

    typst breaks a line after a dash that stands between two words
    ("consecutus? – Laudem"), and pdf2docx sometimes starts the next line
    with the dash, as a paragraph of its own or after a break (which the
    pitch-cut pass only later makes a paragraph), so the dash and its space
    open a line: 8 pt that the PDF's line does not have. In b1's finding card
    that line wrapped, its row of exact height had a line more to hold, and
    the step under it was clipped. The dash goes back only when, on the
    paragraph's page, the PDF has a row that ends with the dash and with the
    text the line above ends with, and a row that starts with this line's
    text after the dash and not with a dash: a list item or a quote's
    attribution (an em dash and "Internal advisory") starts its row with the
    dash and stays, and so does every such dash on a page that also has a row
    starting with the dash and this text. The dash goes back with a space
    before it only when the PDF's row has one ("wireless" and an unspaced em
    dash stays unspaced). Code is left alone. The text check cannot see the
    move, since dashes squash away.
    Returns how many dashes went back.
    """
    paragraphs = body_paragraphs(document)
    pages = paragraph_pages(document, page_count)
    if pages is None:
        return 0
    rows = {}
    for line in lines:
        if line.get("page") is not None:
            rows.setdefault(line["page"] - 1, []).append(line.get("text") or "")
    shaded = set(shaded)
    moved = 0
    for element in paragraphs:
        if is_code(element, shaded):
            continue
        page = rows.get(pages.get(id(element)))
        if not page:
            continue
        lines_of = text_lines(element)
        before = element.getprevious()
        above = None
        if before is not None and before.tag == qn("w:p") and not is_code(before, shaded):
            above = text_lines(before)[-1] or None
        for index, nodes in enumerate(lines_of):
            earlier = lines_of[index - 1] if index else above
            if nodes and earlier and give_back_dash(nodes, earlier, page):
                moved += 1
    return moved


def text_lines(element):
    """A paragraph's lines, each the list of its text nodes holding text, between its line breaks."""
    found = [[]]
    for node in element.iter(qn("w:t"), qn("w:br")):
        if node.tag == qn("w:br"):
            if (node.get(qn("w:type")) or "textWrapping") == "textWrapping":
                found.append([])
        elif node.text:
            found[-1].append(node)
    return found


def give_back_dash(texts, earlier, page):
    """Move the dash that opens the line `texts` to the end of the line `earlier`, when the PDF's rows say so."""
    whole = "".join(node.text for node in texts)
    opening = whole.lstrip()
    if len(opening) < 2 or opening[0] not in DASHES or not opening[1].isspace():
        return False
    head = compare_squash(opening[1:])[:SPLIT_DASH_KEY_CHARS]
    tail = compare_squash("".join(node.text for node in earlier))[-SPLIT_DASH_KEY_CHARS:]
    if len(head) < SPLIT_DASH_KEY_CHARS or len(tail) < SPLIT_DASH_KEY_CHARS:
        return False
    dash = opening[0]
    ending = [row.rstrip() for row in page if row.rstrip().endswith(dash) and compare_squash(row).endswith(tail)]
    starts_with = any(row.lstrip()[:1] not in DASHES and compare_squash(row).startswith(head) for row in page)
    opens_with = any(row.lstrip()[:1] == dash and compare_squash(row).startswith(head) for row in page)
    if not ending or not starts_with or opens_with:
        return False
    spaced = ending[0][:-1].endswith((" ", "\u00a0"))
    # Take the dash and the spaces after it off the front of this line.
    left = len(whole) - len(opening) + 1
    for node in texts:
        if left <= 0:
            break
        taken = min(left, len(node.text))
        node.text = node.text[taken:]
        node.set(qn("xml:space"), "preserve")
        left -= taken
    for node in texts:
        if not node.text:
            continue
        stripped = node.text.lstrip()
        if len(stripped) == len(node.text):
            break
        node.text = stripped
        if stripped:
            break
    last = earlier[-1]
    body_text = last.text if spaced else last.text.rstrip()
    if spaced and not body_text.endswith(" "):
        body_text += " "
    last.text = body_text + dash + " "
    last.set(qn("xml:space"), "preserve")
    return True


def condense_cell_lines(document, lines, shaded, page_count=None):
    """Condense the lines of a table cell's paragraph by what each needs, as body lines are.

    The line-break pass condenses the paragraphs it breaks (`condense_lines`),
    and a cell is out of its reach: a cell paragraph that pdf2docx broke, or
    `break_cell_lines` did, kept Word's own widths, which are wider than
    typst's (`WORD_WIDTH_EXCESS`) and, for justified text, give back the space
    typst shrank. A line that just fits in the PDF then wraps in Word, the
    cell is a line taller, and an exact row clips its last paragraph: design-
    b1's finding sidebar wrapped "laetetur" and lost the first line of its
    reproduction steps on four pages. Each line between two breaks is matched
    to a piece of the PDF's lines on the paragraph's page, which gives its
    width; a paragraph is justified when every line but the last (two at
    least) ends within `JUSTIFY_SPREAD_PT` of its widest, and then those lines
    also get their spaces' shrink back. Only a line that would not fit the
    width its cell gives it in Word (`paragraph_box`: its PDF width with
    Word's excess and, justified, its spaces' shrink, plus a point) is
    condensed, by what it needs for the PDF's width and, when that is small,
    by what it is short of its cell besides: condensing every line made shape-c's tables narrower than the
    PDF's where nothing wrapped (page similarity 0.8228 to 0.8059). A cell
    paragraph of one line is measured the same way: b1's checklist label
    needed 215.3 pt of the 216.7 its cell gives it, wrapped in Word and lost
    its last word to the row's exact height. A line is matched to a piece of
    the PDF's row or to a run of neighbouring pieces, because a numbered
    step's first line is two pieces in the PDF ("1." and its text) and one
    line in Word, and a checklist label (the box's "x" and its text) shares
    its row with the item beside it in the next column.

    A paragraph's own lines decide its justification, with one addition:
    pdf2docx cuts a step's first line from the rest of its paragraph (the
    rest goes after the table), so that line is the last of its Word
    paragraph and was measured as ragged, while in the PDF it is a justified
    line with its spaces shrunk, and Word wrapped its last word over the next
    line (b1's step on PDF 21). A last line whose PDF row has, on the next
    line down, a row ending within `JUSTIFY_SPREAD_PT` of where it ends and
    starting within it of where its text starts, with other text, is
    measured as a full justified line: a right-aligned column ends every row
    at one edge too, and a port list of 58.65 pt in a 63.3 pt cell was
    condensed 6 pt narrower than the PDF's. Only the last line: in a ragged
    paragraph two neighbours end within a point of each other often enough to
    matter (shape-c, above), and every other line has its own paragraph's
    lines to go by.

    A paragraph with a line that matches nothing, one already condensed, one
    whose cell width is not written, and code are left alone. Returns how
    many paragraphs were condensed.
    """
    paragraphs = body_paragraphs(document)
    pages = paragraph_pages(document, page_count)
    if pages is None:
        return 0
    shaded = set(shaded)
    # page -> key -> (width, where it ends or None, the line record, where
    # its last piece's text starts, whether a run of pieces gave it)
    widths = {}
    rows_of = {}

    def remember(page, key, width, end, line, start, joined=False):
        if not key:
            return
        table = widths.setdefault(page - 1, {})
        held = table.get(key)
        if held is None:
            table[key] = (width, end, line, start, joined)
        elif not joined and (held[4] or width > held[0]):
            # A piece's own width beats a run's, and the widest piece wins.
            table[key] = (width, end, line, start, joined)
        elif joined and held[4] and width < held[0]:
            # Among runs the narrowest: a run across a wide gap is the wrong one.
            table[key] = (width, end, line, start, joined)

    for line in lines:
        page = line.get("page")
        if page is None:
            continue
        rows_of.setdefault(page - 1, []).append(line)
        pieces = line.get("pieces") or []
        sizes = line.get("widths") or []
        ends = line.get("ends") or [None] * len(pieces)
        for piece, width, end in zip(pieces, sizes, ends):
            remember(page, compare_squash(piece), width, end, line, None if end is None else end - width)
        if len(sizes) == len(pieces) and all(end is not None for end in ends):
            # Runs of neighbouring pieces no further apart than a list's
            # marker and its text (`HANGING_GAP_PT`): a numbered step's "1."
            # and its text are two pieces, and a checklist label beside another
            # column's item is two of four. A run across a table's gap made a
            # risk matrix's "1" and "2", 115 pt apart, the key "12", and the
            # cells reading "12" were condensed 4.7 pt a digit. At most
            # `RUN_PIECES_MAX` pieces, which every such line is: a row of 40
            # narrow columns took 11 s when every run of it was a key.
            for first in range(len(pieces)):
                for last in range(first + 1, min(len(pieces), first + RUN_PIECES_MAX)):
                    if (ends[last] - sizes[last]) - ends[last - 1] > HANGING_GAP_PT:
                        break
                    remember(page, compare_squash(" ".join(pieces[first:last + 1])),
                             ends[last] - (ends[first] - sizes[first]), ends[last], line, ends[last] - sizes[last],
                             joined=True)

    def runs_on_to_edge(page, line, end, start):
        """Does the PDF row right under `line` start and end where its text does?"""
        if end is None or start is None or line.get("y0") is None or line.get("y1") is None:
            return False
        height = line["y1"] - line["y0"]
        for other in rows_of.get(page, ()):
            if other is line or other.get("y0") is None:
                continue
            if not line["y0"] + 0.5 * height < other["y0"] < line["y1"] + 0.9 * height:
                continue
            if not any(abs(edge - end) <= JUSTIFY_SPREAD_PT for edge in other.get("ends") or ()):
                continue
            starts = [edge - width for edge, width in zip(other.get("ends") or (), other.get("widths") or ())]
            if (starts and abs(min(starts) - start) <= JUSTIFY_SPREAD_PT
                    and compare_squash(other.get("text") or "") != compare_squash(line.get("text") or "")):
                return True
        return False

    body = document.element.body
    condensed = 0
    for element in paragraphs:
        if not in_table_single_line(body, element) or is_code(element, shaded):
            continue
        runs = element.findall(qn("w:r"))
        if any(run.find(qn("w:rPr") + "/" + qn("w:spacing")) is not None for run in runs):
            continue
        texts, current = [], []
        for run in runs:
            for node in run:
                if node.tag == qn("w:t"):
                    current.append(node.text or "")
                elif node.tag == qn("w:tab"):
                    current.append(" ")
                elif node.tag == qn("w:br") and (node.get(qn("w:type")) or "textWrapping") == "textWrapping":
                    texts.append("".join(current))
                    current = []
        texts.append("".join(current))
        table = widths.get(pages.get(id(element)))
        if not table:
            continue
        keys = [compare_squash(line) for line in texts]
        if any(not key for key in keys) or any(key not in table for key in keys):
            continue
        box = paragraph_box(document, element)
        if box is None:
            continue
        line_widths = [table[key][0] for key in keys]
        widest = max(line_widths)
        reaching = [width >= widest - JUSTIFY_SPREAD_PT for width in line_widths[:-1]]
        # Every line but the last, and at least two: a ragged cell with long
        # lines has two of them end within a point of each other often enough
        # that "two reach" over-condensed shape-c's tables (page similarity
        # 0.8228 to 0.8059).
        justified = len(reaching) >= 2 and all(reaching)
        shorts = [not reach for reach in reaching] + [True]
        _width, last_end, last_line, last_start, _joined = table[keys[-1]]
        if runs_on_to_edge(pages.get(id(element)), last_line, last_end, last_start):
            justified = True
            shorts[-1] = False
        room = box[0] - box[1] - box[2]
        spaces = [line.count(" ") for line in texts]
        specs = []
        for key, width, count, short in zip(keys, line_widths, spaces, shorts):
            need = width * (1.0 + WORD_WIDTH_EXCESS) + 1.0
            if justified and not short:
                need += count * SPACE_SHRINK_PT
            if need <= room:
                specs.append(None)
                continue
            spec = condensation_for(width, count, max(1, len(key)), justified, short)
            # What fits the PDF's width is not always what fits the cell (b1's
            # checklist label, condensed to the PDF's width, still ran 0.7 pt
            # past its cell and lost "channel"), so a line that is short of its
            # cell by a little, at most twice Word's excess and a point, is
            # condensed by that as well. The shortfall leaves out the spaces'
            # shrink, which `condensation_for` already gives back, and a larger
            # one is a wrong match or a cell the file measures wrong, not a
            # line to squeeze further.
            shortfall = width * (1.0 + WORD_WIDTH_EXCESS) + 1.0 - room
            if 0.0 < shortfall <= 2.0 * width * WORD_WIDTH_EXCESS + 1.0:
                spec += int(math.ceil(shortfall / max(1, len(key)) * 20.0))
            specs.append(spec)
        if not any(spec is not None for spec in specs):
            continue
        index = 0
        for run in runs:
            if run.find(qn("w:t")) is not None and specs[min(index, len(specs) - 1)] is not None:
                set_run_condensation(run, specs[min(index, len(specs) - 1)])
            if any((br.get(qn("w:type")) or "textWrapping") == "textWrapping" for br in run.findall(qn("w:br"))):
                index += 1
        condensed += 1
    return condensed


def break_offsets(element):
    """Where a paragraph's own line breaks fall, as counts of comparable characters.

    None when a break is a page or column break or sits anywhere but directly
    in the paragraph as a run of its own (`break_runs` has the same rule), so
    a paragraph with something unusual in it is given back untouched.
    """
    holders = break_runs(element)
    if holders is None:
        return None
    offsets, before = set(), 0
    for child in element:
        if child in holders:
            offsets.add(before)
            continue
        for node in child.iter(qn("w:t")):
            before += len(compare_squash(node.text or ""))
    return offsets


def in_table_single_line(body, element):
    """Is this paragraph inside a table cell?

    Breaking inside one changes the row's height, and pdf2docx sized every row
    from the lines it wrote. Measured on the reference report, breaking inside
    cells cost page 9 about 0.07 of structural similarity on its own.
    """
    node = element.getparent()
    while node is not None and node is not body:
        if node.tag == qn("w:tc"):
            return True
        node = node.getparent()
    return False


# How far apart a line's two gaps to the text area's edges may be and still
# be a centred line, before the trailing space is allowed for. typst centres
# from the line's advance, which the PDF's span box reports to within a
# fraction of a point, and a line that is merely indented differs by 40 to
# 300 pt.
CENTRE_TOLERANCE_PT = 2.0
# How far a lone picture's middle may stand from the text area's and still be
# a centred figure (`centre_lone_pictures`).
CENTRE_PICTURE_PT = 6.0
# The opening of a list item (a number or a bullet, then its text), for
# `left_align_cell_list_items`.
# A number must be followed by a letter, so an address (`129.21.249.5`) or a
# section number (`6.3.2`) in a centred cell is not taken for one.
CELL_LIST_ITEM = re.compile(r"(?:\d{1,3}[.)]\s*[^\W\d_]|[\u2022\u25cf\u25aa\u25e6\u2023\u2219]\s*\S|[\u2013*-]\s+\S)")
# A span box of a wrapped line includes the space glyph that ends it, so the
# box reaches one space past the ink on the right and the gaps differ by that
# much: 2.7 pt on the 11 pt Libertinus caption "Figure 3: Credential
# material ..." (gaps 16.6 and 13.9). Charged at the widest common space
# advance, DejaVu Sans' 0.318 em, rounded up, and only on the right.
TRAILING_SPACE_EM = 0.33


class EdgedLine(str):
    """A squashed line that also remembers how the PDF's row began and ended.

    `compare_squash` drops dashes, so "request-" and "request" are one line to
    every comparison here, and a cut counted in squashed characters cannot
    tell whether the PDF ended its line on the dash or began the next one
    with it. Both happen: typst breaks after a hyphen or an en dash, and
    before or after an em dash. The row's own first and last characters
    (spaces stripped) ride along on the string, so `split_paragraph_at` can
    tell. It is a plain `str` to everything else, and a slice or a join of it
    is a plain `str` that has forgotten both.
    """
    first = ""
    last = ""


def row_kind(row, content_left, content_right, page_width):
    """Where a page row sits in the text area: F full, L flush left and short, C centred, O other.

    Centred is the row's two gaps to the text area's edges agreeing within
    `CENTRE_TOLERANCE_PT` (plus the trailing space on the right), or its
    middle standing at the page's. The second reading is for a justified
    document, whose right edge as measured sits 3 to 4 pt out because typst
    lets punctuation hang past it, and so cannot be trusted for the gaps. It
    assumes the page's margins are equal; a page that is not still passes by
    the first. Full is flush left and either reaching the right edge or
    centred, which a centred line that fills the column also is, so it
    proves nothing either way.
    """
    gap_left = row["x0"] - content_left
    gap_right = content_right - row["x1"]
    trailing = TRAILING_SPACE_EM * (row["columns"][-1].get("size") or 0.0)
    middle = (row["x0"] + row["x1"]) / 2.0
    centred = (-CENTRE_TOLERANCE_PT <= gap_left - gap_right <= CENTRE_TOLERANCE_PT + trailing
               or -CENTRE_TOLERANCE_PT / 2.0 <= middle - page_width / 2.0 <= CENTRE_TOLERANCE_PT / 2.0 + trailing / 2.0)
    if gap_left <= JUSTIFY_EDGE_PT:
        return "F" if gap_right <= JUSTIFY_EDGE_PT or centred else "L"
    return "C" if centred else "O"


def row_edges(text):
    """The first and last visible characters of a row's text."""
    shown = "".join(char for char in text if char not in INVISIBLE_CHARS).strip()
    return shown[:1], shown[-1:]


def text_area_edges(pages):
    """{page width: (left, right)} of the text area on pages of each size, from `pages`, a list of (page width, rows).

    The median over a size's pages of each page's own extremes, as
    `content_bounds` takes them, with two differences. It is per page size, so
    a sideways page in a portrait report is not measured against edges its
    own pages do not have (`centre.typ` of the review: one A4 page and one
    landscape page, whose document-wide medians sat at 73.7 and 656.8 pt and
    gave neither page a centred line). And the right edge is that of the
    lines that do not end in a hanging mark, since typst hangs those 2.4 to
    2.9 pt past the column and a gap measured to them is that much short; less
    the space a wrapped line's box carries after its last word (2.75 pt on
    11 pt Libertinus: a one-line centred caption measured 2.8 pt off centre
    against the box's end, and `row_kind` allows 2).
    """
    lefts, rights = {}, {}
    for width, rows in pages:
        if not rows:
            continue
        solid = [r for r in rows if not hangs_into_margin(r["text"])] or rows
        widest = max(solid, key=lambda r: r["x1"])
        lefts.setdefault(round(width), []).append(min(r["x0"] for r in rows))
        rights.setdefault(round(width), []).append(widest["x1"] - TRAILING_SPACE_EM * (widest["columns"][-1].get("size") or 0.0))
    return {width: (median(lefts[width]), median(rights[width])) for width in lefts}


def starts_like_list_item(text):
    """Does this line open with a bullet or a number, as the first line of a list item does?"""
    shown = "".join(char for char in text if char not in INVISIBLE_CHARS).strip()
    if not shown:
        return False
    if re.match(r"\d{1,3}[.)]\s", shown):
        return True
    return not (shown[0].isalnum() or shown[0] in "\"'(‘“[")


def centred_stacks(rows):
    """The indexes of the rows that stand one above another, centred on one axis, in `rows` (a page's rows in reading order).

    A cell's text is centred in the cell, not on the page, so the page's edges
    cannot say which lines are centred. The lines of one centred paragraph
    say it themselves: each is directly below the one before in the same
    column, starts at a different x and shares its middle. Left-aligned
    lines start together, and a list item's wrapped line starts under its
    text, so its first row (the marker) rules it out. The upper line of a
    wrapped paragraph carries the space it broke at inside its box, which
    moves its middle right by up to half a space, so the window is
    asymmetric as `row_kind`'s is.

    Only rows of one column are considered: a row `page_rows` read across
    several cells is a line of none of them.
    """
    flagged = set()
    for index, upper in enumerate(rows):
        if len(upper["columns"]) != 1 or starts_like_list_item(upper["text"]):
            continue
        height = upper["y1"] - upper["y0"]
        best = None
        for later in range(index + 1, len(rows)):
            lower = rows[later]
            if lower["y0"] - upper["y1"] > JUSTIFY_LINE_GAP_PT:
                break
            if len(lower["columns"]) != 1 or lower["y0"] - upper["y0"] < 0.5 * height:
                continue
            overlap = min(upper["x1"], lower["x1"]) - max(upper["x0"], lower["x0"])
            if overlap > 0 and (best is None or overlap > best[0]):
                best = (overlap, later)
        if best is None:
            continue
        lower = rows[best[1]]
        trailing = TRAILING_SPACE_EM * (upper["columns"][-1].get("size") or 0.0)
        shift = (upper["x0"] + upper["x1"]) / 2.0 - (lower["x0"] + lower["x1"]) / 2.0
        if (-CENTRE_TOLERANCE_PT <= shift <= CENTRE_TOLERANCE_PT + trailing / 2.0
                and abs(upper["x0"] - lower["x0"]) > JUSTIFY_EDGE_PT):
            flagged.update((index, best[1]))
    return flagged


def annotate_runs(doc, bands, runs, content_left, content_right):
    """Give each run what its PDF rows know and its squashed lines have lost.

    Two things, both read off the rows the run was made from (a run is a
    contiguous slice of the page's rows, so it is found by its lines):

    - each line becomes an `EdgedLine` carrying its row's first and last
      characters, for the dashes `split_paragraph_at` has to keep on the
      right side of a break;
    - `pageRows`, the page's (key, kind) pairs in reading order, shared by
      every run of the page, for `centred_paragraph`: a run's own x says
      nothing about alignment unless its line starts at the edge.

    A run that cannot be found keeps its plain lines and no `pageRows`, which
    is the behaviour before this existed.
    """
    member_rows = set()
    for band in bands:
        member_rows |= band.get("members") or set()
    by_page = {}
    for run in runs:
        if run.get("page") is not None:
            by_page.setdefault(run["page"], []).append(run)
    page_sets = {index: [r for r in page_rows(doc[index]) if row_id(index, r) not in member_rows] for index in by_page}
    edges = text_area_edges([(doc[index].rect.width, rows) for index, rows in page_sets.items()])
    for index, page_runs in by_page.items():
        rows = page_sets[index]
        keys = [compare_squash(r["text"]) for r in rows]
        width = doc[index].rect.width
        left, right = edges.get(round(width), (content_left, content_right))
        shared = [(key, row_kind(r, left, right, width)) for key, r in zip(keys, rows) if key]
        stacked = centred_stacks(rows)
        at = 0
        for run in page_runs:
            wanted = [str(line) for line in run["lines"]]
            count = len(wanted)
            start = next((s for s in range(at, len(rows) - count + 1) if keys[s:s + count] == wanted), None)
            if start is None:
                continue
            at = start + count
            edged = []
            for line, row in zip(wanted, rows[start:start + count]):
                carried = EdgedLine(line)
                carried.first, carried.last = row_edges(row["text"])
                edged.append(carried)
            run["lines"] = edged
            run["pageRows"] = shared
            run["centredLines"] = [start + number in stacked for number in range(count)]


def centred_paragraph(text, rows):
    """Is a paragraph (its squashed text) made of page rows that are centred or full, one at least centred?

    The paragraph's lines are found by tiling its text with consecutive rows
    of the page; a paragraph the rows cannot tile exactly (a heading joined to
    the text under it, a table row read across its cells) is not decided, and
    the same text tiled in two places has to be centred in both. A flush-left
    line, even the short last line of a justified paragraph, or an indented
    one rules it out.
    """
    if not text or not rows:
        return False
    verdicts = []
    for start, (first_key, _) in enumerate(rows):
        if not text.startswith(first_key):
            continue
        at, kinds = 0, []
        for key, kind in rows[start:]:
            if not text.startswith(key, at):
                break
            at += len(key)
            kinds.append(kind)
            if at == len(text):
                break
        if at == len(text):
            verdicts.append("C" in kinds and set(kinds) <= {"C", "F"})
    return bool(verdicts) and all(verdicts)


def plain_indent(element):
    """Does this paragraph carry no indent of its own and no tab?

    pdf2docx places a centred line it could not centre with indents or a tab,
    and a paragraph written that way is positioned by them: centring it
    would centre it inside the indented area.
    """
    properties = element.find(qn("w:pPr"))
    indent = properties.find(qn("w:ind")) if properties is not None else None
    if indent is not None:
        for name in ("w:left", "w:right", "w:firstLine", "w:hanging", "w:start", "w:end"):
            value = twips_of(indent.get(qn(name)))
            if value is not None and abs(value) > 1.0:
                return False
    return next(element.iter(qn("w:tab")), None) is None


def left_only_indent(element):
    """Is this paragraph positioned by a left (or first-line) indent alone, with no right indent and no tab?"""
    properties = element.find(qn("w:pPr"))
    indent = properties.find(qn("w:ind")) if properties is not None else None
    if indent is None:
        return False
    for name in ("w:right", "w:hanging", "w:end"):
        value = twips_of(indent.get(qn(name)))
        if value is not None and abs(value) > 1.0:
            return False
    return next(element.iter(qn("w:tab")), None) is None


def clear_indent(element):
    """Drop a paragraph's left, right and first-line indents."""
    properties = element.find(qn("w:pPr"))
    indent = properties.find(qn("w:ind")) if properties is not None else None
    if indent is not None:
        properties.remove(indent)


def section_text_widths(body):
    """{id(paragraph): its section's text width in points} for every `w:p` in the body.

    A section's properties sit in the last paragraph of the section (or at the
    end of the body for the last one), so each paragraph takes the next
    `w:sectPr` after it. The cover of a typst report is its own section with
    no margins, so the first section's width is not every page's.
    """
    def width_of(sect):
        size = sect.find(qn("w:pgSz")) if sect is not None else None
        margins = sect.find(qn("w:pgMar")) if sect is not None else None
        page = twips_of(size.get(qn("w:w"))) if size is not None else None
        if page is None:
            return None
        left = (twips_of(margins.get(qn("w:left"))) or 0.0) if margins is not None else 0.0
        right = (twips_of(margins.get(qn("w:right"))) or 0.0) if margins is not None else 0.0
        return page - left - right

    widths = {}
    pending = []
    for element in body.iter(qn("w:p")):
        pending.append(element)
        properties = element.find(qn("w:pPr"))
        sect = properties.find(qn("w:sectPr")) if properties is not None else None
        if sect is not None:
            width = width_of(sect)
            for waiting in pending:
                widths[id(waiting)] = width
            pending = []
    width = width_of(body.find(qn("w:sectPr")))
    for waiting in pending:
        widths[id(waiting)] = width
    return widths


def centre_lone_pictures(document, declined=None):
    """Centre each body paragraph that holds nothing but one inline picture standing in the middle of the text area.

    pdf2docx places a centred figure with a left indent equal to the gap the
    PDF left beside it. That reproduces the page until the picture is resized
    in Word or the margins differ, and then it sits off to the left: a typst
    figure is always centred, so the paragraph says so instead. A picture
    whose middle is not within `CENTRE_PICTURE_PT` of the text area's is left
    where the converter put it.
    """
    body = document.element.body
    widths = section_text_widths(body)
    done = 0
    for element in body.iter(qn("w:p")):
        text_width = widths.get(id(element))
        if not text_width or text_width <= 0 or in_table_single_line(body, element):
            continue
        drawings = list(element.iter(qn("w:drawing")))
        if len(drawings) != 1 or paragraph_text(element).strip():
            continue
        inline = drawings[0].find(qn("wp:inline"))
        extent = inline.find(qn("wp:extent")) if inline is not None else None
        if extent is None:
            continue
        try:
            width = int(extent.get("cx")) / 12700.0
        except (TypeError, ValueError):
            continue
        properties = element.find(qn("w:pPr"))
        indent = properties.find(qn("w:ind")) if properties is not None else None
        left = 0.0
        if indent is not None:
            left = (twips_of(indent.get(qn("w:left"))) or 0.0) + (twips_of(indent.get(qn("w:firstLine"))) or 0.0)
        if abs(left + width / 2.0 - text_width / 2.0) > CENTRE_PICTURE_PT:
            continue
        paragraph = Paragraph(element, document)
        if paragraph.alignment == WD_ALIGN_PARAGRAPH.CENTER and indent is None:
            continue
        clear_indent(element)
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        done += 1
    if declined is not None and done:
        declined["pictures-centred"] += done
    return done


# ── label boxes ───────────────────────────────────────────────────────────
#
# A filled box with one line of text centred in it: an empty screenshot slot
# ("[ Screenshot placeholder ]" in a grey frame) or a tag such as a finding's
# "Rediscovered". pdf2docx writes the first as a one-cell table whose label
# is pushed into place with spacing before and leading spaces, or outside a
# table as a shaded line with no box at all, and the second as a one-cell
# table with square corners. Both are rebuilt from the PDF's own rectangle:
# a square box as a one-cell table of the box's size whose cell centres the
# label, a rounded one as a rounded-rectangle shape holding the text.

# How far a label's middle may stand from its box's and still be centred in it.
LABEL_CENTRE_PT = 3.0
# A box's corners count as rounded from this radius up.
LABEL_ROUND_MIN_PT = 0.75
# How far a box's middle may stand from the page's and still be centred on it.
LABEL_BOX_CENTRE_PT = 6.0
EMU_PER_PT = 12700


def _hex(colour):
    if colour is None:
        return None
    return "".join("%02X" % max(0, min(255, int(round(c * 255)))) for c in colour[:3])


def _corner_radius(drawing):
    """The corner radius of a drawn rectangle: half of what its straight edges fall short of its width by."""
    items = drawing.get("items") or []
    if not any(item[0] == "c" for item in items):
        return 0.0
    rect = drawing["rect"]
    flats = [abs(item[2].x - item[1].x) for item in items if item[0] == "l" and abs(item[2].y - item[1].y) < 0.1]
    if not flats:
        return 0.0
    return max(0.0, (rect.width - max(flats)) / 2.0)


def label_boxes(doc):
    """Every filled box in the PDF holding exactly one line of text centred in it, in page order.

    Each is `{"page", "key", "x0", "y0", "x1", "y1", "lineTop", "fill", "stroke",
    "strokeWidth", "radius", "centred"}`, the rectangle in points, `key` the
    label as `compare_squash` has it, `centred` whether the box stands in the
    middle of its page. A fill and its outline are drawn as two paths, so a
    stroke on the same rectangle is taken as the box's border.
    """
    found = []
    for index in range(doc.page_count):
        page = doc[index]
        drawings = page.get_drawings()
        fills = [d for d in drawings if d.get("fill") is not None and d["rect"].width > 4 and d["rect"].height > 4]
        if not fills:
            continue
        lines = []
        for block in page.get_text("dict").get("blocks", []):
            for line in block.get("lines", []):
                text = "".join(span.get("text", "") for span in line.get("spans", []))
                if text.strip():
                    lines.append((pymupdf.Rect(line["bbox"]), text))
        for drawing in fills:
            rect = drawing["rect"]
            inside = [(box, text) for box, text in lines
                      if box.x0 >= rect.x0 - 1 and box.x1 <= rect.x1 + 1 and box.y0 >= rect.y0 - 1 and box.y1 <= rect.y1 + 1]
            if len(inside) != 1:
                continue
            box, text = inside[0]
            if (abs((box.x0 + box.x1) / 2.0 - (rect.x0 + rect.x1) / 2.0) > LABEL_CENTRE_PT
                    or abs((box.y0 + box.y1) / 2.0 - (rect.y0 + rect.y1) / 2.0) > LABEL_CENTRE_PT):
                continue
            stroke, width = None, 0.0
            if drawing.get("color") is not None and drawing.get("width"):
                stroke, width = drawing["color"], drawing["width"]
            else:
                for other in drawings:
                    edge = other["rect"]
                    if (other.get("color") is not None and other.get("width")
                            and max(abs(edge.x0 - rect.x0), abs(edge.y0 - rect.y0),
                                    abs(edge.x1 - rect.x1), abs(edge.y1 - rect.y1)) < 0.6):
                        stroke, width = other["color"], other["width"]
                        break
            found.append({
                "page": index, "key": compare_squash(text),
                "x0": rect.x0, "y0": rect.y0, "x1": rect.x1, "y1": rect.y1, "lineTop": box.y0,
                "fill": _hex(drawing["fill"]), "stroke": _hex(stroke), "strokeWidth": width or 0.0,
                "radius": _corner_radius(drawing),
                "centred": abs((rect.x0 + rect.x1) / 2.0 - page.rect.width / 2.0) <= LABEL_BOX_CENTRE_PT,
            })
    return found


def _label_candidate(element, body):
    """The label paragraph of a one-cell table, or of a shaded body paragraph, or None."""
    if element.tag == qn("w:tbl"):
        rows = element.findall(qn("w:tr"))
        cells = rows[0].findall(qn("w:tc")) if len(rows) == 1 else []
        if len(cells) != 1:
            return None
        paragraphs = cells[0].findall(qn("w:p"))
        if (len(paragraphs) != 1 or cells[0].find(qn("w:tbl")) is not None
                or next(cells[0].iter(qn("w:drawing")), None) is not None):
            return None
        return paragraphs[0]
    if element.tag == qn("w:p") and not in_table_single_line(body, element):
        properties = element.find(qn("w:pPr"))
        shade = properties.find(qn("w:shd")) if properties is not None else None
        if shade is None or (shade.get(qn("w:fill")) or "auto").lower() in ("auto", "ffffff"):
            return None
        if next(element.iter(qn("w:drawing")), None) is not None:
            return None
        return element
    return None


def _label_runs(paragraph):
    """Copies of a label paragraph's runs, the label's outer spaces trimmed."""
    runs = [copy.deepcopy(run) for run in paragraph.findall(qn("w:r"))]
    texts = [t for run in runs for t in run.iter(qn("w:t"))]
    if texts:
        texts[0].text = (texts[0].text or "").lstrip()
        texts[-1].text = (texts[-1].text or "").rstrip()
    return runs


def _twips(points):
    return str(int(round(points * 20)))


def _label_table(label, runs, indent):
    """A one-cell table the size of the label's box, its label centred in the cell."""
    width, height = label["x1"] - label["x0"], label["y1"] - label["y0"]
    table = OxmlElement("w:tbl")
    properties = OxmlElement("w:tblPr")
    table_width = OxmlElement("w:tblW")
    table_width.set(qn("w:w"), _twips(width))
    table_width.set(qn("w:type"), "dxa")
    properties.append(table_width)
    if label["centred"]:
        justify = OxmlElement("w:jc")
        justify.set(qn("w:val"), "center")
        properties.append(justify)
    elif indent:
        table_indent = OxmlElement("w:tblInd")
        table_indent.set(qn("w:w"), _twips(indent))
        table_indent.set(qn("w:type"), "dxa")
        properties.append(table_indent)
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    properties.append(layout)
    margins = OxmlElement("w:tblCellMar")
    for side in ("top", "left", "bottom", "right"):
        margin = OxmlElement("w:" + side)
        margin.set(qn("w:w"), "0")
        margin.set(qn("w:type"), "dxa")
        margins.append(margin)
    properties.append(margins)
    table.append(properties)
    grid = OxmlElement("w:tblGrid")
    column = OxmlElement("w:gridCol")
    column.set(qn("w:w"), _twips(width))
    grid.append(column)
    table.append(grid)
    row = OxmlElement("w:tr")
    row_properties = OxmlElement("w:trPr")
    row_height = OxmlElement("w:trHeight")
    row_height.set(qn("w:val"), _twips(height))
    row_height.set(qn("w:hRule"), "exact")
    row_properties.append(row_height)
    row.append(row_properties)
    cell = OxmlElement("w:tc")
    cell_properties = OxmlElement("w:tcPr")
    cell_width = OxmlElement("w:tcW")
    cell_width.set(qn("w:w"), _twips(width))
    cell_width.set(qn("w:type"), "dxa")
    cell_properties.append(cell_width)
    borders = OxmlElement("w:tcBorders")
    for side in ("top", "left", "bottom", "right"):
        border = OxmlElement("w:" + side)
        if label["stroke"] and label["strokeWidth"] > 0:
            border.set(qn("w:val"), "single")
            border.set(qn("w:sz"), str(max(2, int(round(label["strokeWidth"] * 8)))))
            border.set(qn("w:color"), label["stroke"])
        else:
            border.set(qn("w:val"), "nil")
        borders.append(border)
    cell_properties.append(borders)
    shade = OxmlElement("w:shd")
    shade.set(qn("w:val"), "clear")
    shade.set(qn("w:color"), "auto")
    shade.set(qn("w:fill"), label["fill"])
    cell_properties.append(shade)
    align = OxmlElement("w:vAlign")
    align.set(qn("w:val"), "center")
    cell_properties.append(align)
    cell.append(cell_properties)
    cell.append(_label_paragraph(runs))
    row.append(cell)
    table.append(row)
    return table


def _label_paragraph(runs, justify="center", indent=0.0):
    paragraph = OxmlElement("w:p")
    properties = OxmlElement("w:pPr")
    spacing = OxmlElement("w:spacing")
    spacing.set(qn("w:before"), "0")
    spacing.set(qn("w:after"), "0")
    spacing.set(qn("w:line"), "240")
    spacing.set(qn("w:lineRule"), "auto")
    properties.append(spacing)
    if indent:
        ind = OxmlElement("w:ind")
        ind.set(qn("w:left"), _twips(indent))
        properties.append(ind)
    jc = OxmlElement("w:jc")
    jc.set(qn("w:val"), justify)
    properties.append(jc)
    paragraph.append(properties)
    for run in runs:
        paragraph.append(run)
    return paragraph


def _rounded_label(label, runs, shape_id, indent):
    """A paragraph holding a rounded-rectangle shape the size of the label's box, the text centred in it."""
    width, height = label["x1"] - label["x0"], label["y1"] - label["y0"]
    cx, cy = int(round(width * EMU_PER_PT)), int(round(height * EMU_PER_PT))
    adjust = int(round(min(50000, label["radius"] / max(min(width, height), 0.1) * 100000)))
    outline = ""
    half = 0
    if label["stroke"] and label["strokeWidth"] > 0:
        outline = ('<a:ln w="%d"><a:solidFill><a:srgbClr val="%s"/></a:solidFill></a:ln>'
                   % (int(round(label["strokeWidth"] * EMU_PER_PT)), label["stroke"]))
        half = int(round(label["strokeWidth"] * EMU_PER_PT / 2.0))
    else:
        outline = "<a:ln><a:noFill/></a:ln>"
    xml = (
        '<w:r %s><mc:AlternateContent><mc:Choice Requires="wps"><w:drawing>'
        '<wp:inline distT="0" distB="0" distL="0" distR="0">'
        '<wp:extent cx="%d" cy="%d"/><wp:effectExtent l="%d" t="%d" r="%d" b="%d"/>'
        '<wp:docPr id="%d" name="Label %d"/><wp:cNvGraphicFramePr/>'
        '<a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">'
        '<wps:wsp><wps:cNvSpPr/><wps:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="%d" cy="%d"/></a:xfrm>'
        '<a:prstGeom prst="roundRect"><a:avLst><a:gd name="adj" fmla="val %d"/></a:avLst></a:prstGeom>'
        '<a:solidFill><a:srgbClr val="%s"/></a:solidFill>%s</wps:spPr>'
        '<wps:txbx><w:txbxContent/></wps:txbx>'
        '<wps:bodyPr rot="0" vert="horz" wrap="none" lIns="0" tIns="0" rIns="0" bIns="0" anchor="ctr" anchorCtr="0">'
        '<a:noAutofit/></wps:bodyPr></wps:wsp></a:graphicData></a:graphic></wp:inline>'
        '</w:drawing></mc:Choice></mc:AlternateContent></w:r>'
        % (LABEL_NAMESPACES, cx, cy, half, half, half, half, shape_id, shape_id, cx, cy, adjust, label["fill"], outline)
    )
    run = parse_xml(xml)
    run.find(".//" + qn("w:txbxContent")).append(_label_paragraph(runs))
    return _label_paragraph([run], justify="left", indent=indent)


LABEL_NAMESPACES = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
    'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
    'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"'
)


def _spacer(points):
    """An empty paragraph exactly `points` tall."""
    paragraph = OxmlElement("w:p")
    properties = OxmlElement("w:pPr")
    spacing = OxmlElement("w:spacing")
    spacing.set(qn("w:before"), "0")
    spacing.set(qn("w:after"), "0")
    spacing.set(qn("w:line"), _twips(max(points, 1.0)))
    spacing.set(qn("w:lineRule"), "exact")
    properties.append(spacing)
    paragraph.append(properties)
    return paragraph


def rebuild_label_boxes(document, labels, content_left, declined=None):
    """Write each label box (`label_boxes`) as the PDF draws it.

    The Word side is found by its label, in document order against the PDF's
    page order, among the one-cell tables and the shaded body paragraphs; one
    whose label no box has is left as it was. A square box becomes a one-cell
    table of the box's size with its fill and border, centred on the page
    when the box is, its label centred by the cell (`w:vAlign`) rather than
    pushed down by spacing, which not every editor honours at the top of a
    cell. A rounded box becomes a rounded-rectangle shape, since a Word cell
    cannot round its corners. A shaded body paragraph keeps the gap above its
    box as a spacer, so nothing under it moves.
    """
    if not labels:
        return 0
    body = document.element.body
    queues = {}
    for label in labels:
        queues.setdefault(label["key"], []).append(label)
    used = {key: 0 for key in queues}
    ids = [int(node.get("id")) for node in body.iter(qn("wp:docPr")) if (node.get("id") or "").isdigit()]
    next_id = max(ids, default=0) + 1000
    done = 0
    for element in list(body.iter(qn("w:tbl"), qn("w:p"))):
        if element.getparent() is None:
            continue
        paragraph = _label_candidate(element, body)
        if paragraph is None:
            continue
        key = compare_squash(paragraph_text(paragraph))
        queue = queues.get(key)
        if not key or not queue or used[key] >= len(queue):
            continue
        label = queue[used[key]]
        used[key] += 1
        runs = _label_runs(paragraph)
        if element.tag == qn("w:tbl"):
            table_properties = element.find(qn("w:tblPr"))
            table_indent = table_properties.find(qn("w:tblInd")) if table_properties is not None else None
            indent = (twips_of(table_indent.get(qn("w:w"))) or 0.0) if table_indent is not None else 0.0
            gap = 0.0
        else:
            spacing = paragraph.find(qn("w:pPr") + "/" + qn("w:spacing"))
            before = (twips_of(spacing.get(qn("w:before"))) or 0.0) if spacing is not None else 0.0
            indent = max(0.0, label["x0"] - content_left) if content_left is not None else 0.0
            gap = before - (label["lineTop"] - label["y0"])
        if label["radius"] >= LABEL_ROUND_MIN_PT:
            replacement = [_rounded_label(label, runs, next_id, indent)]
            next_id += 1
        else:
            replacement = [_label_table(label, runs, indent)]
            if gap > 1.0:
                replacement.insert(0, _spacer(gap))
            # Two tables in a row are one table to Word.
            following = element.getnext()
            if following is not None and following.tag == qn("w:tbl"):
                replacement.append(_spacer(1.0))
            preceding = element.getprevious()
            if (replacement[0].tag == qn("w:tbl") and preceding is not None and preceding.tag == qn("w:tbl")):
                replacement.insert(0, _spacer(1.0))
        parent = element.getparent()
        at = parent.index(element)
        parent.remove(element)
        for offset, node in enumerate(replacement):
            parent.insert(at + offset, node)
        # A cell must end with a paragraph.
        if parent.tag == qn("w:tc") and parent[-1].tag != qn("w:p"):
            parent.append(_spacer(1.0))
        done += 1
    if declined is not None and done:
        declined["labels-rebuilt"] += done
    return done


def left_align_cell_list_items(document, declined=None):
    """Set a list item a cell centred back to the left.

    A one-line item that nearly fills its cell has two equal gaps, so the
    converter reads it as centred; a list never is, and the remediation steps
    of a finding came out with one item centred under a left-aligned one.
    """
    body = document.element.body
    done = 0
    for element in body.iter(qn("w:p")):
        if not in_table_single_line(body, element):
            continue
        paragraph = Paragraph(element, document)
        if paragraph.alignment != WD_ALIGN_PARAGRAPH.CENTER:
            continue
        shown = "".join(char for char in paragraph_text(element) if char not in INVISIBLE_CHARS).strip()
        if not CELL_LIST_ITEM.match(shown):
            continue
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
        done += 1
    if declined is not None and done:
        declined["list-items-left"] += done
    return done


def line_end_offset(text, cut, last, hyphen=True):
    """Where in `text` the PDF's line really ends, given `cut`, the offset just after its last comparable character.

    Returns `(offset, matched)`. What follows `cut` up to the next comparable
    character is dropped by `compare_squash` (spaces, dashes, invisible
    marks), so the squashed count cannot say whether the line ended before or
    after it. `last` is the row's own last character: a dash there means the
    line ended on the dash, so the offset goes past the first dash of the
    dropped stretch (typst breaks after a hyphen or en dash, and an em dash
    can end a line or start one). Without it (`None`, a plain string) the
    dash stays where the count put it, which is what every caller did before
    the rows were read: a table cell's lines are cut without condensation,
    and the 3 to 4 pt of a hyphen moved onto the end of a line that has 4.7 pt
    to spare made Word wrap "non-" onto a line of its own (page 5 of
    verbose-a, shape-a and shape-c, the line "critical information such as
    ...") where the hyphen at the start of the next line fitted. Spaces after
    the end of the line belong to it, where Word does not count them against
    the column.

    A soft hyphen right at the cut goes with the line too (unless `hyphen` is
    false, for a line whose end was matched already): typst puts one in the
    text only where it broke a word, and the count cannot see it. Left to open
    the next line, it kept pdf2docx's own break after it from being found, a
    second break went in before it, and every word typst hyphenated in b1's
    glossary left an empty line in its entry (two lines over the page). Every
    cutter takes it, or a cell's second pass, with plain lines, cut before a
    hyphen the first had cut after and made the same empty line.
    """
    end = cut
    matched = False
    if hyphen and cut < len(text) and text[cut] == SOFT_HYPHEN:
        end = cut + 1
        matched = True
    elif last and last in DASHES:
        at = cut
        while at < len(text) and (text[at].isspace() or text[at] in INVISIBLE_CHARS):
            at += 1
        if at < len(text) and text[at] in DASHES:
            end = at + 1
            matched = True
    while end < len(text) and text[end].isspace():
        end += 1
    return end, matched


def next_text_run(node):
    """The first run after `node`, in the paragraph's order, that holds text, or None.

    Looked for inside a hyperlink or outside one. A run with a break or a tab
    in it ends the search: that is a line end already, and text past it is
    not what this line's end is next to.
    """
    paragraph = node.getparent()
    while paragraph is not None and paragraph.tag != qn("w:p"):
        paragraph = paragraph.getparent()
    if paragraph is None:
        return None
    runs = list(paragraph.iter(qn("w:r")))
    try:
        place = runs.index(node)
    except ValueError:
        return None
    for later in runs[place + 1:]:
        if later.find(qn("w:br")) is not None or later.find(qn("w:tab")) is not None:
            return None
        piece = later.find(qn("w:t"))
        if piece is not None and (piece.text or ""):
            return later, piece
    return None


def split_paragraph_at(element, lines, skip=0, tabs=None, raw_cuts=None):
    """Insert `w:br` at each of the PDF's line ends, splitting runs if need be.

    `raw_cuts` are offsets into the paragraph's own text (its runs' `w:t`
    joined) rather than counts of comparable characters, for a code paragraph
    whose lines were matched byte for byte.

    Landing a break only where a run boundary happens to fall is worse than
    not breaking at all: the paragraph then carries some of the PDF's line
    ends and lets Word choose the rest, and the two disagree. Measured on the
    reference report, that took three pages down by up to 0.23 structural
    similarity. So a break that falls inside a run splits it.

    `tabs`, one flag per line, puts a tab before the break that ends that
    line: Word stretches a justified line ending in a manual break to the
    margin unless a tab ends it, and a line typst left short must stay so.
    """
    runs = [node for node in element.iter(qn("w:r")) if node.find(qn("w:t")) is not None]
    if not runs:
        return 0
    if raw_cuts is not None:
        wanted = [cut for cut in raw_cuts if cut > 0]
    else:
        wanted = []
        total = skip
        for line in lines[:-1]:
            total += len(line)
            wanted.append(total)
    total_cuts = len(wanted)

    seen = 0
    inserted = 0
    queue = list(runs)
    while queue and wanted:
        node = queue.pop(0)
        text = node.find(qn("w:t"))
        raw = text.text or ""
        length = len(raw) if raw_cuts is not None else len(compare_squash(raw))
        if wanted[0] > seen + length:
            seen += length
            continue
        if raw_cuts is not None:
            cut = wanted[0] - seen
            if cut <= 0:
                # A cut at this run's start is one the run before took.
                wanted.pop(0)
                queue.insert(0, node)
                continue
        else:
            cut = raw_offset_for(raw, wanted[0] - seen)
            if cut is None:
                seen += length
                continue
        # The space between the last word of this line and the first of the
        # next belongs to the end of this line, where Word does not count it
        # against the column, rather than to the start of the next, where it
        # is a real character that makes the line a space wider than the PDF
        # made it and can send its last word round again. So does a dash the
        # PDF's line ended on, which the squashed count has dropped: cutting
        # at the count put "-forgery" and the dash of a page range at the
        # start of a line.
        matched = True
        last = ""
        if raw_cuts is not None:
            while cut < len(raw) and raw[cut].isspace():
                cut += 1
        else:
            popped = total_cuts - len(wanted)
            last = getattr(lines[popped], "last", None) if popped < len(lines) else None
            cut, matched = line_end_offset(raw, cut, last)
        if raw_cuts is None and cut >= len(raw):
            # The line ends where this run does, and the characters that
            # belong to its end (the space before a link, a dash opening a
            # bold run) are the first of the next run's text: the break went
            # between them and the next line opened with a space. They move
            # back across the boundary; the break stays where it was. The
            # dash may be further than the next run: a list item that is only
            # a dash is three runs, a bullet, a space and the dash, and the
            # space run went across while the dash, one run on, stayed to
            # open the next line (the bullet alone, and the dash under it).
            # A run that went across whole and was only space asks the one
            # after it.
            neighbour = next_text_run(node)
            ends_on_dash = not matched and bool(last) and last in DASHES
            while neighbour is not None:
                piece = neighbour[1]
                lead, found = line_end_offset(piece.text, 0, "" if matched else last, not matched)
                if not lead:
                    break
                raw += piece.text[:lead]
                text.text = raw
                text.set(qn("xml:space"), "preserve")
                piece.text = piece.text[lead:]
                piece.set(qn("xml:space"), "preserve")
                cut = len(raw)
                if found or piece.text or not ends_on_dash:
                    break
                neighbour = next_text_run(node)
        following = node.getnext()
        holder = node
        while following is None and holder.getparent() is not None and holder.getparent().tag != qn("w:p"):
            # The run ends a hyperlink (a resource link in a list), which
            # pdf2docx wraps in a run of its own, and the converter's break
            # stands after that wrapper: a second break inside the link gave
            # every list an empty line and the row clipped its last link.
            holder = holder.getparent()
            following = holder.getnext()
        while (following is not None and following.tag == qn("w:r") and following.find(qn("w:br")) is None
               and following.find(qn("w:tab")) is None and following.find(qn("w:t")) is not None
               and not (following.find(qn("w:t")).text or "")):
            # Runs the boundary move above emptied: the converter's break is
            # the next thing past them.
            following = following.getnext()
        if (cut >= len(raw) and following is not None and following.tag == qn("w:r")
                and following.find(qn("w:br")) is not None and following.find(qn("w:t")) is None):
            # The converter already broke the line here (a heading and the
            # paragraph under it come as one block with a break between);
            # a second break would be an empty line. The break is kept, and
            # given its tab if the line was short.
            if tabs and inserted < len(tabs) and tabs[inserted] and following.find(qn("w:tab")) is None:
                following.find(qn("w:br")).addprevious(OxmlElement("w:tab"))
            inserted += 1
            wanted.pop(0)
            seen += length
            continue
        if cut < len(raw):
            tail = copy.deepcopy(node)
            spare = tail.find(qn("w:t"))
            spare.text = raw[cut:]
            spare.set(qn("xml:space"), "preserve")
            text.text = raw[:cut]
            text.set(qn("xml:space"), "preserve")
            node.addnext(tail)
            queue.insert(0, tail)
        # Its own run, so the break carries no text formatting of its own.
        holder = OxmlElement("w:r")
        if tabs and inserted < len(tabs) and tabs[inserted]:
            holder.append(OxmlElement("w:tab"))
        holder.append(OxmlElement("w:br"))
        node.addnext(holder)
        inserted += 1
        wanted.pop(0)
        seen += cut if raw_cuts is not None else len(compare_squash(raw[:cut]))
    return inserted


def raw_offset_for(text, squashed_count):
    """Where in `text` the first `squashed_count` comparable characters end."""
    for cut in range(1, len(text) + 1):
        if len(compare_squash(text[:cut])) >= squashed_count:
            return cut
    return None


def align_paragraphs(document, runs, declined=None, page_count=None, content_right=None):
    """Give each flush-left line the alignment and indent the PDF gave it.

    Every line of a run starts at the same x in the PDF, so none of them may
    carry a first-line or hanging indent and none of them may be centred or
    right-aligned. The lines of a justified run are justified except the last,
    which is how Word writes a justified paragraph too.

    That holds only for a paragraph whose first line is in the run. An academic
    paper indents each paragraph's first line, so the run is its other lines
    and the paragraph holding them starts before the run does; zeroing its
    indent moved every first line 9 to 10 pt left of the PDF's. A paragraph
    that starts before its run, where the PDF's line just above the run is
    indented by no more than `FIRST_LINE_INDENT_MAX_PT`, is left as the
    converter wrote it, counted as `align-earlier-line`. Only that shape: a
    heading the converter joined to the paragraph under it also starts before
    the run, and there the pass helps.
    """
    paragraphs = body_paragraphs(document)
    squashed = [compare_squash(paragraph_text(p)) for p in paragraphs]
    pages = paragraph_pages(document, page_count)
    on_page = [pages.get(id(p)) for p in paragraphs] if pages is not None else None
    cursor = 0
    done = 0
    centred = {}
    # The lines of a centred stack (`centred_stacks`) by page: what keeps a
    # centred cell's paragraph centred below.
    stacked = {}
    for run in runs:
        for line, flag in zip(run["lines"], run.get("centredLines") or []):
            if flag and len(line) >= COMPARE_MIN_CHARS:
                stacked.setdefault(run.get("page"), set()).add(str(line))
    for run in runs:
        first = True
        shorts = [line for line, short in zip(run["lines"], run.get("short") or []) if short and len(line) >= COMPARE_MIN_CHARS]
        for order, needle in enumerate(run["lines"]):
            if len(needle) < COMPARE_MIN_CHARS:
                first = False
                continue
            if on_page is not None and run.get("page") is not None:
                position = next((i for i in range(cursor, len(squashed)) if on_page[i] == run["page"] and needle in squashed[i]), None)
            else:
                position = next((i for i in range(cursor, len(squashed)) if needle in squashed[i]), None)
            if position is None:
                first = False
                continue
            if first and order == 0 and run.get("indentedAbove") and not squashed[position].startswith(needle):
                if declined is not None:
                    declined["align-earlier-line"] += 1
                cursor = position
                break
            first = False
            paragraph = Paragraph(paragraphs[position], document)
            if run.get("pageRows") is not None:
                # A line that starts short of the page's edge says nothing
                # about its alignment from where it starts: a centred
                # caption and an indented line both do. The PDF's own rows
                # say, so a paragraph whose lines are all centred (or full
                # width, which a centred line that fills the column also is)
                # keeps the alignment pdf2docx read from the whole block,
                # and gets one when it read none. Forcing it left moved every
                # caption wider than the column minus 180 pt, and the centred
                # last line of a wrapped paragraph, to the margin.
                key = (position, run.get("page"))
                if key not in centred:
                    in_cell = in_table_single_line(document.element.body, paragraphs[position])
                    centred[key] = (not in_cell and centred_paragraph(squashed[position], run["pageRows"]))
                    # A cell's lines are centred in the cell, which the page's
                    # edges cannot say, so the cell is judged by its own lines
                    # (`centred_stacks`) and only to keep a centre the converter
                    # read from the cell's geometry: the pass used to set a
                    # wrapped, centred cell flush left whenever one of its
                    # lines stood at the table's edge (`cellc.typ` of the
                    # review: raw `center`, full `left`), and the engagement
                    # timeline's and the risk scale's cells came out off-centre.
                    if (in_cell and paragraph.alignment == WD_ALIGN_PARAGRAPH.CENTER
                            and any(line in squashed[position] for line in stacked.get(run.get("page"), ()))):
                        centred[key] = True
                    if centred[key] and declined is not None:
                        declined["align-centred"] += 1
                if centred[key]:
                    if paragraph.alignment != WD_ALIGN_PARAGRAPH.CENTER:
                        if plain_indent(paragraphs[position]):
                            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        elif left_only_indent(paragraphs[position]):
                            # pdf2docx placed the centred line with a left
                            # indent, which holds only while Word's line is
                            # exactly as wide as the PDF's. A figure caption
                            # in another font, or edited, drifted off centre
                            # and read as left-aligned. The rows prove it is
                            # centred on the text area, so centre it there.
                            clear_indent(paragraphs[position])
                            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    if "".join(run["lines"]) in squashed[position]:
                        # Full lines in a row read as justified; these are
                        # centred, so no right indent and no tab before a
                        # short line is wanted.
                        run["justified"] = False
                    cursor = position
                    done += 1
                    continue
            if run.get("indented") and len(run["lines"]) == 1 and in_table_single_line(document.element.body, paragraphs[position]):
                # One line in a cell, starting short of the page's edge: its
                # x says nothing about its alignment, because a centred date
                # or risk label starts within the same reach of the margin
                # as an indented line does. The converter read the cell's
                # own geometry and centred it, and that stands; forcing it
                # left set the engagement timeline's dates and the risk
                # matrix's labels flush against their cells' left edges.
                cursor = position
                done += 1
                continue
            last = order == len(run["lines"]) - 1
            # Word never stretches a paragraph's last line, so the paragraph
            # is justified whole; only a paragraph that holds nothing but
            # the run's last line (the converter sometimes writes one on its
            # own) is left ragged. Setting "left" for the last line used to
            # win over "justify" for the lines before it, since they are all
            # one paragraph, and every justified paragraph came out ragged.
            alone = last and squashed[position] == needle
            paragraph.alignment = (WD_ALIGN_PARAGRAPH.JUSTIFY if run["justified"] and not alone
                                   else WD_ALIGN_PARAGRAPH.LEFT)
            if not run.get("indented"):
                # A hanging indent pulls the first line out to the edge the
                # run is on, which is where this line is when it starts the
                # paragraph, and a list item's marker always is: its wrapped
                # lines stand on the text's edge, 13 pt in, though the run
                # takes them too. Zeroing it set the marker 13 pt right of the
                # PDF's.
                hanging = paragraph.paragraph_format.first_line_indent
                opening = paragraph_text(paragraphs[position]).lstrip().split(None, 1)
                item = len(opening) == 2 and LIST_MARKER.fullmatch(opening[0]) is not None
                if not (hanging is not None and hanging < 0 and (item or squashed[position].startswith(needle))):
                    paragraph.paragraph_format.first_line_indent = Pt(0)
            if run["justified"] and shorts:
                tab_before_short_breaks(paragraphs[position], shorts)
            if run["justified"] and not in_table_single_line(document.element.body, paragraphs[position]):
                # Word stretches the justified lines to the section's right
                # margin, which pdf2docx measured from the page's widest ink;
                # the PDF's column is where they must end.
                indent = column_right_indent(document, paragraphs[position], content_right)
                paragraph.paragraph_format.right_indent = Pt(round(indent, 1))
            # Not position + 1: the converter often writes several of these
            # lines as one paragraph, and that paragraph has to stay available
            # to the rest of the run.
            cursor = position
            done += 1
        cursor += 1
    return done


# ── step 6: the vertical rhythm ───────────────────────────────────────────
#
# pdf2docx reads each block's own geometry off the PDF and then writes a
# spacing that does not reproduce it, because it does not model what Word will
# do with the line height it wrote next to it. The errors are small and they
# all point the same way, so they add up: on the reference report the two inks
# agree at the top of a page and are 8 to 14 pt apart by the bottom.
#
# Three of them, measured on the reference report:
#
# 1. The exact line height is the converter's own guess at the font's line
#    box, not the distance the PDF put between two lines. A paragraph the PDF
#    set at a 17.0 pt pitch came out at 19.6 pt, so every line after it sat
#    2.6 pt lower than the last.
# 2. A paragraph's spacing before is measured from the previous row's ink,
#    while Word measures from the previous line box, which is taller.
# 3. The converter writes the same gap twice, as the spacing after one
#    paragraph and again as the spacing before the next. Word keeps the larger
#    of the two, so the gap is right until one of the passes here wants the
#    second block higher: lowering its spacing before then changes nothing
#    until the block above gives its spacing after back.
#
# The repair is one walk per page. Every block's first baseline is known from
# the PDF, and where Word will draw it is known from the layout model above,
# so the spacing between two blocks is whatever makes the second land on its
# own baseline. Nothing here knows what a report is: the target comes from the
# PDF's own text rows and the correction from the file's own line heights.


def twips_of(value):
    """One of Word's twentieths of a point, as points.

    `float`, not `int`: the schema says these attributes are integers and the
    converter writes several of them with a decimal point ("0.0" for a table
    indent, "12.0" for a border width). Word reads them, so this has to as
    well, and an `int` here threw the value away.
    """
    try:
        return float(value) / 20.0
    except (TypeError, ValueError):
        return None


def paragraph_metrics(element):
    """Spacing and exact line height, in points, or None when it does not say.

    Only a paragraph that carries its own exact line height can be modelled: a
    value inherited from a style is not in this file's hands, and a line that
    Word is free to size is not a length this pass can add up.
    """
    properties = element.find(qn("w:pPr"))
    spacing = properties.find(qn("w:spacing")) if properties is not None else None
    if spacing is None or spacing.get(qn("w:lineRule")) != "exact":
        return None
    line = twips_of(spacing.get(qn("w:line")))
    if not line or line <= 0:
        return None
    return {
        "before": twips_of(spacing.get(qn("w:before"))) or 0.0,
        "after": twips_of(spacing.get(qn("w:after"))) or 0.0,
        "line": line,
        "lines": 1 + sum(1 for node in element.iter(qn("w:br"))
                         if (node.get(qn("w:type")) or "textWrapping") == "textWrapping"),
    }


def picture_line(element):
    """`(before, height, after)` of a paragraph that holds one inline picture and nothing else.

    None for anything else. The picture pass writes such a paragraph with a
    single automatic line, so Word sizes the line to the picture and
    `paragraph_metrics` rightly declines it: its height is not a line height
    this file wrote. It is still a length the walk can add up, the picture's
    own, and a walk that gave up at the first one left everything under a
    picture where the converter's flow had put it. On shape-f a finding
    card's code panel stood 8 pt too close to the paragraph above it, the
    table under the panel 10 pt too close to the panel, and the picture
    itself 5 pt low, because the panel above it had been rebuilt shorter.
    """
    properties = element.find(qn("w:pPr"))
    spacing = properties.find(qn("w:spacing")) if properties is not None else None
    if (spacing is None or spacing.get(qn("w:lineRule")) != "auto"
            or twips_of(spacing.get(qn("w:line"))) != PICTURE_SINGLE_LINE_PT):
        return None
    if any((node.text or "").strip() for node in element.iter(qn("w:t"))):
        return None
    if next(element.iter(qn("w:br")), None) is not None or next(element.iter(qn("w:tab")), None) is not None:
        return None
    drawings = list(element.iter(qn("w:drawing")))
    if len(drawings) != 1 or drawings[0].find(qn("wp:inline")) is None:
        return None
    height = drawing_height(drawings[0])
    if height <= 0:
        return None
    return (twips_of(spacing.get(qn("w:before"))) or 0.0, height,
            twips_of(spacing.get(qn("w:after"))) or 0.0)


def set_spacing(element, before=None, after=None, line=None):
    properties = element.get_or_add_pPr()
    spacing = properties.find(qn("w:spacing"))
    if spacing is None:
        spacing = OxmlElement("w:spacing")
        insert_ordered(properties, spacing, PPR_ORDER)
    if before is not None:
        spacing.set(qn("w:before"), str(int(round(max(0.0, before) * 20))))
    if after is not None:
        spacing.set(qn("w:after"), str(int(round(max(0.0, after) * 20))))
    if line is not None:
        spacing.set(qn("w:line"), str(int(round(line * 20))))
        spacing.set(qn("w:lineRule"), "exact")


def cell_border(cell, side):
    """How wide one of a cell's own borders is, in points, 0 when it has none."""
    properties = cell.find(qn("w:tcPr"))
    borders = properties.find(qn("w:tcBorders")) if properties is not None else None
    node = borders.find(qn("w:" + side)) if borders is not None else None
    if node is None or (node.get(qn("w:val")) or "none") in ("none", "nil"):
        return 0.0
    # Eighths of a point, and the converter writes this one as "12.0", which
    # the schema does not allow and Word reads anyway. Parsing it as an
    # integer threw the width away, and every page whose first block was a
    # bordered heading table then placed everything under it 1.5 pt too low.
    try:
        return float(node.get(qn("w:sz"))) / 8.0
    except (TypeError, ValueError):
        return 0.0


def last_row_border(row):
    """The bottom border Word draws under a table's last row, in points.

    It is drawn below the row rather than inside it, so the table stands that
    much taller than the heights its rows declare.
    """
    return max((cell_border(cell, "bottom") for cell in row.findall(qn("w:tc"))), default=0.0)


def cell_margin(cell, side):
    """One of a cell's inner margins, in points.

    `w:start` and `w:end` are what the converter writes for the left and the
    right of a cell; `w:left` and `w:right` are the older names for the same
    two, and both are read. A margin the cell does not state is Word's own
    default for the Normal Table style, which is none at the top.
    """
    properties = cell.find(qn("w:tcPr"))
    node = properties.find(qn("w:tcMar")) if properties is not None else None
    if node is None:
        return 0.0
    for name in CELL_MARGIN_NAMES[side]:
        found = node.find(qn(name))
        if found is not None:
            value = twips_of(found.get(qn("w:w")))
            if value is not None:
                return value
    return 0.0


def cell_content_top(cell, row_top):
    """Where the first line box inside a cell starts, measured on the page.

    Word insets a cell's content by the cell's own top border as well as by
    its top margin. Measured over 151 cells of the reference report's Word
    render: with the border term 148 of them land within 0.2 pt of where this
    says and the median residual is 0.02 pt; without it the median is 0.74,
    which is the rule the report draws across the top of a card.
    """
    return row_top + cell_border(cell, "top") + cell_margin(cell, "top")


def cell_content_left(box):
    """Where a nested table inside a cell starts, measured on the page."""
    return box["x0"] + cell_margin(box["cell"], "left")


def table_indent(element):
    """How far a table is pushed in from whatever contains it, in points."""
    properties = element.find(qn("w:tblPr"))
    node = properties.find(qn("w:tblInd")) if properties is not None else None
    return (twips_of(node.get(qn("w:w"))) or 0.0) if node is not None else 0.0


def row_height(row):
    """A row's declared height in points, or None when Word is free to size it.

    A row Word sizes from its contents is not a length this pass can add up,
    and it is also a row that can grow, which is how a page count changes.
    """
    properties = row.find(qn("w:trPr"))
    height = properties.find(qn("w:trHeight")) if properties is not None else None
    if height is None or (height.get(qn("w:hRule")) or "atLeast") != "exact":
        return None
    return twips_of(height.get(qn("w:val")))


def table_grid(element, top, left):
    """Every cell of a table as a rectangle on the page, or None.

    The grid is the PDF's own: the converter reads a table's rules off the
    page and writes them back as row heights and cell widths, so anchoring
    them at the table's top left corner puts each cell where the PDF drew it.
    A cell's width is read from `w:tcW` rather than from `w:tblGrid`, because
    the grid a fixed-layout table declares does not always add up and the
    cell widths always do; a cell spanning several grid columns carries the
    whole span in its own width, so `w:gridSpan` needs no arithmetic here.
    """
    rows = []
    y = top
    start = left + table_indent(element)
    for row in element.findall(qn("w:tr")):
        span = row_height(row)
        if span is None:
            return None
        x = start
        cells = []
        for cell in row.findall(qn("w:tc")):
            properties = cell.find(qn("w:tcPr"))
            node = properties.find(qn("w:tcW")) if properties is not None else None
            width = twips_of(node.get(qn("w:w"))) if node is not None else None
            if width is None:
                return None
            merge = properties.find(qn("w:vMerge")) if properties is not None else None
            cells.append({
                "cell": cell,
                "x0": x,
                "x1": x + width,
                "merge": (merge.get(qn("w:val")) or "continue") if merge is not None else None,
            })
            x += width
        rows.append({"y0": y, "y1": y + span, "cells": cells})
        y += span
    return rows


def merged_bottom(rows, index, box):
    """How far down a cell reaches, following a vertical merge."""
    bottom = rows[index]["y1"]
    if box["merge"] != "restart":
        return bottom
    for later in rows[index + 1:]:
        joined = next((c for c in later["cells"]
                       if abs(c["x0"] - box["x0"]) < CELL_EDGE_PT and c["merge"] == "continue"), None)
        if joined is None:
            break
        bottom = later["y1"]
    return bottom


def row_bands(rows, lines):
    """Each row's share of the page's text lines, by where the line's centre is.

    One pass over the lines rather than one per cell, so a table of a
    thousand rows costs what a table of ten does per row.
    """
    ordered = sorted(lines, key=lambda line: line["y0"] + line["y1"])
    bands = []
    cursor = 0
    for row in rows:
        while cursor < len(ordered) and (ordered[cursor]["y0"] + ordered[cursor]["y1"]) / 2.0 < row["y0"]:
            cursor += 1
        start = cursor
        while cursor < len(ordered) and (ordered[cursor]["y0"] + ordered[cursor]["y1"]) / 2.0 <= row["y1"]:
            cursor += 1
        bands.append(ordered[start:cursor])
    return bands


def lines_in_cell(bands, first, last, box):
    """The text lines of these row bands whose centre falls inside this cell."""
    out = []
    for band in bands[first:last + 1]:
        for line in band:
            if box["x0"] <= (line["x0"] + line["x1"]) / 2.0 <= box["x1"]:
                out.append(line)
    return out


def merged_lines(lines):
    """The text of one cell, with everything on a baseline read as one line.

    A page's rows are split into columns so that two cells of the same table
    row can be told apart, and inside one cell those pieces are a single line
    again: a list marker and the text beside it are two columns of one row,
    and reading them as two lines puts the paragraph half a line height too
    high, which is what happened to every numbered remediation step.
    """
    out = []
    for line in sorted(lines, key=lambda item: (round(item["base"], 2), item["x0"])):
        last = out[-1] if out else None
        if last is not None and abs(last["base"] - line["base"]) <= SAME_LINE_PT:
            last["key"] += line["key"]
            last["x1"] = max(last["x1"], line["x1"])
            last["y0"] = min(last["y0"], line["y0"])
            last["y1"] = max(last["y1"], line["y1"])
            continue
        out.append(dict(line))
    return out


def text_columns(rows):
    """Every text line of a page as an item of its own.

    A row of a table reads across its columns, and each of those columns is
    in a different cell, so the column rather than the row is the piece that
    can be paired with one.
    """
    out = []
    for row in rows:
        for column in row["columns"]:
            out.append({
                "x0": column["x0"],
                "x1": column["x1"],
                "y0": column["y0"],
                "y1": column["y1"],
                "base": column["base"],
                "key": compare_squash(column["text"]),
            })
    return out


def table_metrics(element):
    """A table's height and where its first line of text sits inside it.

    Every row has to declare an exact height. One that does not is sized by
    Word from its contents, and a block placed under a guess is worse than a
    block left where the converter put it.
    """
    rows = element.findall(qn("w:tr"))
    if not rows:
        return None
    total = 0.0
    for row in rows:
        value = row_height(row)
        if value is None:
            return None
        total += value
    insides = [offset for offset in (first_baseline(cell, RHYTHM_NESTING)
                                     for cell in rows[0].findall(qn("w:tc"))) if offset is not None]
    # The row's own first line of text, which is the row the PDF matched, so
    # the topmost of the cells rather than the first one: a card's leftmost
    # cell often opens with a spacer thinner than its neighbour's text.
    return {"height": total + last_row_border(rows[-1]), "inside": min(insides) if insides else None}


def first_baseline(cell, depth):
    """How far below its row's top a cell's first line of text is drawn.

    The same walk as a page, inside a table cell, and with the two rules a
    cell has of its own: Word insets the content by the cell's top border and
    its top margin, and it does not drop the first paragraph's spacing before
    the way it does at the top of a page. None when anything on the way cannot
    be measured, which is how a card the converter built out of boxes declines
    to be an anchor.
    """
    if depth <= 0:
        return None
    cursor = cell_content_top(cell, 0.0)
    pending = 0.0
    for block in cell:
        if block.tag == qn("w:p"):
            metrics = paragraph_metrics(block)
            if metrics is None:
                return None
            if compare_squash(paragraph_text(block)):
                return cursor + max(pending, metrics["before"]) + EXACT_BASELINE_RATIO * metrics["line"]
            cursor += max(pending, metrics["before"]) + metrics["lines"] * metrics["line"]
            pending = metrics["after"]
        elif block.tag == qn("w:tbl"):
            rows = block.findall(qn("w:tr"))
            if not rows:
                return None
            inner = None
            for nested in rows[0].findall(qn("w:tc")):
                offset = first_baseline(nested, depth - 1)
                if offset is not None:
                    inner = offset if inner is None else min(inner, offset)
            if inner is None:
                return None
            return cursor + pending + inner
    return None


def block_key(element):
    return compare_squash(paragraph_text(element))


def fitted_rows(edges, bounds, offset):
    """How many of a table's row boundaries land on a PDF edge, moved by `offset`."""
    hits = 0
    for value in bounds:
        wanted = value + offset
        position = bisect.bisect_left(edges, wanted)
        if any(abs(candidate - wanted) <= TABLE_FIT_PT
               for candidate in edges[max(0, position - 1):position + 1]):
            hits += 1
    return hits


def table_top_offset(edges, table, left, modelled):
    """How far a table has to move for its rules to land on the PDF's.

    The converter reaches a table through the spacing of everything above it,
    so a table carries whatever error those blocks came to: on the reference
    report they come out up to 1.3 pt below the rules the PDF drew for them.

    The correction is not read off one rule. A page has other rules near a
    table and the wrong one moves it further away, which is what an earlier
    round measured and took out. It is the offset that lines up the most of
    the table's own row boundaries with the edges the PDF drew across the
    same span, and a boundary count is not something one stray rule can fake:
    the offsets worth trying are the few a nearby edge suggests for the top
    boundary, and a table keeps its place unless one of them fits more of its
    rows than staying still does.
    """
    rows = table_grid(table, modelled, left)
    if rows is None or len(rows) < TABLE_FIT_MIN or not rows[0]["cells"]:
        return 0.0
    start, end = rows[0]["cells"][0]["x0"], rows[0]["cells"][-1]["x1"]
    near = sorted(edge["y"] for edge in edges
                  if abs(edge["x0"] - start) <= TABLE_EDGE_PT and abs(edge["x1"] - end) <= TABLE_EDGE_PT)
    if not near:
        return 0.0
    bounds = [rows[0]["y0"]] + [row["y1"] for row in rows]
    best, score = 0.0, fitted_rows(near, bounds, 0.0)
    for edge in near:
        offset = edge - bounds[0]
        # Upwards only. Every error the converter's spacing makes points the
        # same way, which is why two inks that agree at the top of a page are
        # 8 to 14 pt apart by the bottom of it, so a table is drawn below
        # where the PDF has it and never above. An edge further down is
        # another rule, or the fill Word paints under a cell's top border,
        # and moving a table onto one of those took four pages backwards.
        if not -TABLE_TOP_PT <= offset <= -RHYTHM_TOLERANCE_PT:
            continue
        count = fitted_rows(near, bounds, offset)
        if count > score:
            best, score = offset, count
    return best if score >= TABLE_FIT_MIN else 0.0


def page_boxes(doc):
    """Every rectangle the PDF draws that is a container rather than a rule.

    A converter that meets a drawn box writes a table the size of the box, so
    a table whose width and height are one of these rectangles IS that
    rectangle, and the PDF knows where its top edge goes.

    A filled row is drawn one rectangle per cell, so a header over two
    columns is two boxes that each fall short of the table's width on one
    side, and matched against the table they never agree on both. The cells
    of one row that touch and share a fill are the same box, and are listed
    as one beside their parts (`joined_row_fills`).
    """
    pages = []
    for index in range(doc.page_count):
        found, fills = [], []
        for drawing in doc[index].get_drawings():
            rect = drawing["rect"]
            if rect.height <= RULE_MAX_THICKNESS_PT or rect.width <= RULE_MAX_THICKNESS_PT:
                continue
            box = {"x0": rect.x0, "x1": rect.x1, "y0": rect.y0, "height": rect.height}
            if rect.width >= PANEL_MIN_WIDTH_PT:
                found.append(box)
            if drawing.get("fill") is not None:
                fills.append((tuple(drawing["fill"]), box))
        found.extend(joined_row_fills(fills))
        pages.append(found)
    return pages


def joined_row_fills(fills):
    """One box for each run of touching, equally filled cells of a row.

    `fills` is `(colour, box)` for every filled rectangle of a page. Cells
    count as one row when they start at the same height, are the same height
    and end where the next begins, and are the same colour: the header row of
    a two-column grid on shape-b and shape-f is 108 and 396 pt wide, and the
    table is 504. A run of one is not listed, since it is its own box
    already; one narrower than a panel is dropped like any other.

    The colour has to agree because a panel is a coloured bar beside a grey
    body that touch in the same way, and the pair is not a table's header.
    """
    ordered = sorted(fills, key=lambda item: (round(item[1]["y0"], 1), round(item[1]["height"], 1), item[1]["x0"]))
    joined = []
    run = []

    def same_run(first, second):
        return (all(abs(a - b) <= FILL_SAME_RGB for a, b in zip(first[0], second[0]))
                and abs(first[1]["y0"] - second[1]["y0"]) <= TABLE_FIT_PT
                and abs(first[1]["height"] - second[1]["height"]) <= TABLE_FIT_PT
                and abs(first[1]["x1"] - second[1]["x0"]) <= TABLE_FIT_PT)

    def flush():
        if len(run) >= 2 and run[-1][1]["x1"] - run[0][1]["x0"] >= PANEL_MIN_WIDTH_PT:
            joined.append({"x0": run[0][1]["x0"], "x1": run[-1][1]["x1"],
                           "y0": run[0][1]["y0"], "height": run[0][1]["height"]})

    for item in ordered:
        if run and not same_run(run[-1], item):
            flush()
            run = []
        run.append(item)
    flush()
    return joined


def table_box_offset(boxes, table, left, modelled, baselines=None):
    """How far a table has to move to sit on the rectangle the PDF drew for it.

    Three of the four sides have to agree before this is believed: the left
    edge, the right edge and the height. A table that is a page's rectangle in
    all three is that rectangle, and where the PDF puts its top is better
    evidence than the spacing of every block above it added up, which is how
    the reference report's network diagram came out 3.8 pt high.

    It moves in either direction, unlike the fit against a page's rules, and
    it can afford to: a box says where its own top is, while a rule only says
    that something lines up there and the wrong one lines up too. Two
    rectangles that fit and disagree about the offset are no evidence at all,
    so the table keeps its place.

    A rectangle of the right size is not yet the table's own. With typst's
    default insets a one-line finding bar is exactly as tall as a table's
    header row, and a bar 34 pt above a correctly placed table was taken for
    its header and pulled the table up onto it. So a box counts only when the
    PDF's own text for this table's first row stands inside it, `baselines`
    being where `first_row_baselines` found that text: a bar has its own words
    in it and the table's are 34 pt away. Without any (the first row's words
    were not found on the page) the first row alone is no evidence at all, and
    only a box round the whole table is believed, as before.
    """
    rows = table_grid(table, modelled, left)
    if rows is None or not rows or not rows[0]["cells"]:
        return 0.0
    if baselines:
        boxes = [box for box in boxes
                 if any(box["y0"] - TABLE_FIT_PT <= base <= box["y0"] + box["height"] + TABLE_FIT_PT
                        for base in baselines)]
    x0, x1 = rows[0]["cells"][0]["x0"], rows[0]["cells"][-1]["x1"]
    height = rows[-1]["y1"] - rows[0]["y0"]
    first = rows[0]["y1"] - rows[0]["y0"]
    whole = [box["y0"] - modelled for box in boxes
             if abs(box["x0"] - x0) <= TABLE_EDGE_PT
             and abs(box["x1"] - x1) <= TABLE_EDGE_PT
             and abs(box["height"] - height) <= TABLE_BOX_PT]
    header = [box["y0"] - modelled for box in boxes
              if baselines
              and abs(box["x0"] - x0) <= TABLE_EDGE_PT
              and abs(box["x1"] - x1) <= TABLE_EDGE_PT
              and abs(box["height"] - first) <= TABLE_BOX_PT]
    # A box standing where the table already is, round the whole or its
    # first row, says the table is right: evidence, not noise, and without
    # it a one-line panel 30 pt above moved a table that was in its place.
    if any(abs(offset) < RHYTHM_TOLERANCE_PT for offset in whole + header):
        return 0.0
    found = [offset for offset in whole if RHYTHM_TOLERANCE_PT <= abs(offset) <= TABLE_BOX_MOVE_PT]
    if found and max(found) - min(found) <= TABLE_FIT_PT:
        return found[0]
    # The first row alone moves a table upwards only, as the fit against the
    # rules does: the converter's errors all put a table below its place.
    header = [offset for offset in header if -TABLE_HEADER_MOVE_PT <= offset <= -RHYTHM_TOLERANCE_PT]
    if not header or max(header) - min(header) > TABLE_FIT_PT:
        return 0.0
    return header[0]


def first_row_baselines(table, left, lines):
    """Where the PDF has the words that open this table's first row.

    A cell's first paragraph starts with the text of the PDF line it begins
    with, and that line stands in the cell's own columns, so a line with that
    text in that column is the cell's. Found by text and column rather than
    by pairing the table's whole text with the page's rows, which fails for a
    table whose cell holds several lines beside a cell that holds one: the
    PDF reads those across, the converter down.
    """
    grid = table_grid(table, 0.0, left)
    if not grid or not grid[0]["cells"]:
        return []
    row_height = grid[0]["y1"] - grid[0]["y0"]
    # Per cell, the baselines of the lines that open its text. A key shorter
    # than `COMPARE_MIN_CHARS` opens anything ("1" above "10.0.0.5"), and a
    # cell whose own text is that short has nothing to be found by.
    per_cell = []
    for box in grid[0]["cells"]:
        words = next((key for key in (compare_squash(paragraph_text(node))
                                      for node in box["cell"].findall(qn("w:p"))) if key), "")
        if len(words) < COMPARE_MIN_CHARS:
            continue
        per_cell.append([line["base"] for line in lines
                         if len(line["key"]) >= COMPARE_MIN_CHARS and words.startswith(line["key"])
                         and box["x0"] - TABLE_EDGE_PT <= line["x0"] and line["x1"] <= box["x1"] + TABLE_EDGE_PT])
    # A line in the cell's column that opens the cell's text may still be a
    # label above the table ("Critical" over a table whose first cell starts
    # "Critical"), which in the cell's column is indistinguishable from the
    # cell's own first line. The header row's cells share a row, so a
    # baseline counts when the first row's other cells have a line of theirs
    # within the row's height: a bar's text has no such neighbour in the
    # next cell. A first row with one cell that can be found has no other to
    # ask, and keeps what it found.
    need = min(2, len(per_cell))
    found = []
    for hits in per_cell:
        for base in hits:
            if sum(1 for other in per_cell if any(abs(b - base) <= row_height for b in other)) >= need:
                found.append(base)
    return found


def known_panel(anchors, element):
    """`(top, was_height)` for a table the decoration pass built, else None.

    A panel table is placed from the rectangle the PDF drew, which is exact,
    rather than from the flow the converter's own spacing adds up to, and it
    still counts as the paragraphs it replaced in that flow, so the blocks
    under it keep the place the converter gave them.
    """
    for table, top, height in anchors:
        if table is element:
            return top, height
    return None


def cut_cell_pitches(cell, ordered, seams):
    """Cut this cell's paragraphs where the PDF changed the leading inside them.

    The same cut the top level gets, on the lines geometry has already dropped
    into this cell, and run before the cell is walked rather than during it, so
    the walk sees the pieces and never a paragraph changing under it. That is
    what makes it possible here at all: a cell's rows are only known once the
    grid has been anchored, which happens in the middle of the page's walk.

    A finding card writes a sub-heading and the paragraph under it as one
    block, four times over, at 13.48 pt inside a pair and 18.05 pt between two
    of them. Three of its seven lines sit 2.3 pt low however the one line
    height is chosen.

    `splittable` is asked without the shaded set, which it uses only to know
    code from prose. Nothing is lost: a code block's runs all name a monospace
    family, which is the other half of that test, and its lines are separate
    paragraphs anyway, so there is no break to turn into anything.
    """
    placed = 0
    for block in list(cell):
        if block.tag == qn("w:tbl"):
            # Whatever is left in `ordered` belongs to the nested table.
            break
        if block.tag != qn("w:p"):
            continue
        metrics = paragraph_metrics(block)
        if metrics is None:
            break
        key = block_key(block)
        span = consume_rows(ordered, placed, key) if len(key) >= COMPARE_MIN_CHARS else None
        if span is None:
            continue
        placed = span[1]
        mine = ordered[span[0]:span[1]]
        cuts = pitch_cuts(mine)
        if not cuts or not splittable(block, ()):
            continue
        holders = break_runs(block)
        if holders is None or len(holders) != len(mine) - 1:
            continue
        seams.extend(cut_paragraph(block, [holders[cut - 1] for cut in cuts]))


def align_table_cells(table, top, left, lines, anchors=(), depth=RHYTHM_NESTING, seams=None):
    """Put the text inside a table on the baselines the PDF has for it.

    Returns `(moved, undo)`, and an empty undo means nothing was written.

    The table itself does not move and no row changes height, so no rule
    moves and no page can grow. What moves is the text inside each cell, and
    on the reference report that was 2.3 pt low in a data table's rows and
    4.4 pt low by the middle of a finding card.

    Rows and cells are paired with the PDF by geometry, not by reading order,
    which is what defeated the earlier attempts: the PDF reads a row across
    its columns and the converter writes it down one column and then the
    next, so the two texts never join in the same order. A table's row
    heights and cell widths are the PDF's own rules, because the converter
    read them off the page, so anchoring the grid at the table's top left
    corner puts every cell back where the PDF drew it, and a text line
    belongs to the cell its centre falls in.
    """
    rows = table_grid(table, top, left)
    if rows is None:
        return 0, []
    bands = row_bands(rows, lines)
    undo = []
    moved = 0
    for index, row in enumerate(rows):
        for box in row["cells"]:
            if box["merge"] == "continue":
                continue   # an empty continuation of the cell above it
            bottom = merged_bottom(rows, index, box)
            last = index
            while last + 1 < len(rows) and rows[last + 1]["y1"] <= bottom:
                last += 1
            found, fits = place_cell(box, row["y0"], bottom,
                                     lines_in_cell(bands, index, last, box), undo, anchors, depth,
                                     seams)
            if not fits:
                # A correction that would push a cell's last line past the
                # bottom edge Word clips an exact row at would lose text
                # rather than move it, so the whole table goes back.
                restore(undo)
                return 0, []
            moved += found
    return moved, undo


def place_cell(box, row_top, bottom, lines, undo, anchors, depth, seams=None):
    """Walk one cell's blocks, correcting the spacing between them.

    The same walk as a page, with three differences. A cell does not drop its
    first paragraph's spacing before. Its lines are read in the order the PDF
    drew them, by baseline, rather than in the order the converter wrote
    them. And a cell cannot grow: its row has an exact height, so anything
    past the bottom is clipped rather than pushed onto the next page, which
    is what `fits` reports.
    """
    ordered = merged_lines(lines)
    if seams is not None:
        cut_cell_pitches(box["cell"], ordered, seams)
    cursor = was = cell_content_top(box["cell"], row_top)
    pending = was_pending = 0.0
    placed = moved = 0
    above = None
    lost = False
    for block in box["cell"]:
        if block.tag == qn("w:p"):
            metrics = paragraph_metrics(block)
            picture = picture_line(block) if metrics is None and not lost else None
            if picture is not None:
                # A lone inline picture is a length the walk can add up, the
                # picture's own, so it is counted rather than lost. It is not
                # placed against a text row, but it is kept where the
                # converter had it, as a table is: its spacing before is what
                # it was less whatever the corrections above have added
                # since, and what follows is measured from the bottom of it.
                gap = was + max(was_pending, picture[0]) - cursor
                if gap < pending and pending > 0 and above is not None:
                    keep_spacing(undo, *above)
                    set_spacing(above[0], after=0.0)
                    pending = 0.0
                gap = max(0.0, gap)
                if abs(gap - picture[0]) >= RHYTHM_TOLERANCE_PT:
                    undo.append((block, picture[0], picture[2], None))
                    set_spacing(block, before=gap)
                    moved += 1
                cursor += max(pending, gap) + picture[1]
                pending = picture[2]
                was += max(was_pending, picture[0]) + picture[1]
                was_pending = picture[2]
                above = None
                continue
            if metrics is None:
                # A paragraph Word sizes itself that is not a lone picture:
                # where it ends is not a length to add up, so the
                # walk has no position until a block it can pair with the PDF
                # turns up. Giving the cell up here left a panel built under
                # a screenshot where pdf2docx's spacing put it, 7.9 pt above
                # the rectangle with its bottom 18.8 pt short of the figure
                # below (shape-a, page 25).
                lost = True
                above = None
                pending = was_pending = 0.0
                continue
            key = block_key(block)
            if len(key) >= COMPARE_MIN_CHARS:
                span = consume_rows(ordered, placed, key)
            elif key:
                # A line too short to pair on anywhere in a report ("{", "}",
                # "ok") still pairs with the very next line the cell has left,
                # when that line is the same text: nothing else is a candidate
                # for it, and left unpaired it keeps the spacing pdf2docx gave
                # it, which for a panel's first line is the gap above the whole
                # block. The next line then had to shrink to make up for it,
                # and a "{" stood 8.0 pt low with the line under it squeezed
                # (page 61 of an 86-page report).
                span = consume_rows(ordered, placed, key, lookahead=0)
            else:
                span = None
            if lost:
                # Anchor on the first block that is the PDF's own rows and
                # keeps the converter's height, which is the relative mode a
                # page uses when its first block is unmodelled: that block
                # stays and everything under it is measured from it.
                if span is None:
                    continue
                mine = ordered[span[0]:span[1]]
                count = max(metrics["lines"], len(mine))
                if len(mine) >= 2 and (len(mine) - 1) * abs(row_pitch(mine) - metrics["line"]) >= RHYTHM_TOLERANCE_PT:
                    continue
                placed = span[1]
                cursor = was = first_baseline_target(mine, metrics["line"]) - EXACT_BASELINE_RATIO * metrics["line"]
                cursor += count * metrics["line"]
                was += count * metrics["line"]
                pending = was_pending = metrics["after"]
                above = (block, metrics)
                lost = False
                continue
            if span is None and key:
                span = sole_pairing(box["cell"], ordered, placed)
            gap, line, count = metrics["before"], metrics["line"], metrics["lines"]
            if span is not None:
                placed = span[1]
                mine = ordered[span[0]:span[1]]
                line, floor = wanted_line_height(mine, metrics["line"])
                if has_own_shape(block):
                    line, floor = metrics["line"], metrics["line"]
                count = max(metrics["lines"], len(mine))
                target = first_baseline_target(mine, line)
                gap = target - EXACT_BASELINE_RATIO * line - cursor
                if gap < pending and pending > 0 and above is not None:
                    keep_spacing(undo, *above)
                    set_spacing(above[0], after=0.0)
                    pending = 0.0
                if gap < 0 and line > floor:
                    room = count - EXACT_BASELINE_RATIO
                    if room > 0:
                        line = max(floor, line + gap / room)
                        target = first_baseline_target(mine, line)
                        gap = target - EXACT_BASELINE_RATIO * line - cursor
                gap = max(0.0, gap)
                keep_spacing(undo, block, metrics)
                set_spacing(block, before=gap, line=line)
                if (abs(gap - metrics["before"]) >= RHYTHM_TOLERANCE_PT
                        or abs(line - metrics["line"]) >= RHYTHM_TOLERANCE_PT):
                    moved += 1
            cursor += max(pending, gap) + count * line
            pending = metrics["after"]
            was += max(was_pending, metrics["before"]) + count * metrics["line"]
            was_pending = metrics["after"]
            above = (block, metrics)
        elif block.tag == qn("w:tbl"):
            inner = table_metrics(block)
            if inner is None:
                return moved, True
            if lost:
                continue
            known = known_panel(anchors, block)
            if above is not None:
                # A nested table keeps the place the converter gave it, for
                # the reason a top-level one does: its rules are the PDF's
                # already. What moves is the gap above it, which takes up
                # whatever the corrections above have added or removed. A
                # panel this pass built is the exception: its top edge is in
                # the PDF and does not have to inherit the flow's error.
                step = max(0.0, (was + was_pending if known is None else known[0]) - cursor)
                keep_spacing(undo, *above)
                set_spacing(above[0], after=step)
                pending = step
            if depth > 0:
                found, deeper = align_table_cells(block, cursor + pending, cell_content_left(box),
                                                  lines, anchors, depth - 1, seams)
                moved += found
                undo.extend(deeper)
            cursor += pending + inner["height"]
            pending = 0.0
            was += was_pending + (inner["height"] if known is None else known[1])
            was_pending = 0.0
            above = None
    # The bottom of the last line box, not of the spacing under it: Word
    # clips an exact row, and spacing that falls off the end of a cell costs
    # nothing while a line that does is a line the reader never sees. Room
    # for the rounding in the heights themselves, because the converter
    # writes them to a twentieth of a point and a cell that was already full
    # stays full.
    return moved, cursor <= max(bottom, was) + CELL_CLIP_PT


def sole_pairing(cell, ordered, placed):
    """`(start, end)` for a cell whose one line of text is beyond doubt.

    A cell's lines are chosen by geometry rather than by reading, so a cell
    holding exactly one paragraph with text in it, with exactly one line
    dropped into it and nothing placed yet, has nothing to match: the two are
    each other's.

    It is the only way to place such a cell when its text is too short to pair
    on. The number of a numbered heading is written in a cell of its own and
    squashes to "2", which occurs all over a report and is evidence of
    nothing, so the pairing declined and the number kept the line height the
    converter gave it. On the reference report that is 25.2 pt against the
    23.65 the title beside it has, and Word drew the two 1.25 pt apart where
    the PDF has them on one baseline, on eight of its pages.
    """
    if placed or len(ordered) != 1:
        return None
    found = 0
    for block in cell:
        if block.tag == qn("w:tbl"):
            return None
        if block.tag == qn("w:p") and compare_squash(paragraph_text(block)):
            found += 1
    return (0, 1) if found == 1 else None


def keep_spacing(undo, block, metrics):
    undo.append((block, metrics["before"], metrics["after"], metrics["line"]))


def consume_rows(rows, cursor, key, lookahead=RHYTHM_LOOKAHEAD):
    """`(start, end)` of the PDF rows whose text joins to `key`, or None.

    A converted block holds whole PDF rows and never a piece of one, so the
    match is exact on the squashed text. Starting a little ahead of the cursor
    is allowed, because the converter writes the occasional empty paragraph
    that no row of the page corresponds to.
    """
    for start in range(cursor, min(len(rows), cursor + lookahead + 1)):
        joined = ""
        for end in range(start, min(len(rows), start + RHYTHM_MAX_ROWS)):
            joined += rows[end]["key"]
            if joined == key:
                return start, end + 1
            if not key.startswith(joined):
                break
    return None


def wanted_line_height(rows, current):
    """The exact line height for this block, and the smallest it may become.

    Several rows give their own pitch, which is the distance the PDF put
    between them and the one number that makes a broken paragraph read like
    the page it came from. A single row has no pitch of its own, so the
    converter's height is kept.

    The floor is what stops a box being shrunk into the text it holds. Word
    clips an exact line box at the top, and the baseline sits at 0.8 of it, so
    a box shorter than the row's own ascent over 0.8 cuts the capitals off.
    Descenders are not part of it: every ordinary leading puts them past the
    bottom of their box and into the next line's, which is why a 15.4 pt box
    round a 3.8 pt descender is what the converter writes and what the page
    looks right with.
    """
    floor = 1.0
    for row in rows:
        floor = max(floor, max(0.0, row["base"] - row["y0"]) / EXACT_BASELINE_RATIO)
    if len(rows) >= 2:
        pitch = row_pitch(rows)
        if pitch > 0:
            return max(pitch, floor), floor
    return current, min(floor, current)


def row_pitch(rows):
    """The median distance between consecutive baselines of these rows."""
    return median(sorted(b["base"] - a["base"] for a, b in zip(rows, rows[1:])))


def first_baseline_target(rows, line):
    """Where a block's first baseline goes if its lines are to straddle the PDF's."""
    return median(sorted(row["base"] - order * line for order, row in enumerate(rows)))


def page_edges(doc):
    """Every horizontal edge the PDF draws, page by page.

    A rule counts once, at its centre, and a filled rectangle twice, at its
    top and at its bottom: a table drawn with banded rows has no stroke
    between two of them and the band's own edge is the rule. These are what a
    table's row boundaries are fitted against, because the converter reaches
    a table through the spacing of everything above it and that spacing
    carries whatever error those blocks came to.
    """
    pages = []
    for index in range(doc.page_count):
        found = []
        for drawing in doc[index].get_drawings():
            rect = drawing["rect"]
            if rect.width < PANEL_MIN_WIDTH_PT:
                continue
            if rect.height <= RULE_MAX_THICKNESS_PT:
                found.append({"y": (rect.y0 + rect.y1) / 2.0, "x0": rect.x0, "x1": rect.x1})
        pages.append(found)
    return pages


def page_anchor_rows(doc, bands):
    """Every page's text rows, band members dropped, each with its own key."""
    members = set()
    for band in bands:
        members |= band.get("members") or set()
    pages = []
    for index in range(doc.page_count):
        rows = []
        for row in page_rows(doc[index]):
            if row_id(index, row) in members:
                continue
            entry = dict(row)
            entry["key"] = compare_squash(row["text"])
            rows.append(entry)
        pages.append(rows)
    return pages


def has_own_shape(element):
    """Does this paragraph paint something whose size the reader would notice?

    A shaded panel and a bordered block are drawn to the line box, so shrinking
    the box to buy back a point of spacing would shrink the grey rectangle with
    it. Those keep the height the shape pass gave them.
    """
    properties = element.find(qn("w:pPr"))
    if properties is None:
        return False
    return properties.find(qn("w:shd")) is not None or properties.find(qn("w:pBdr")) is not None


class PageWalk:
    """One page's blocks, placed against the baselines the PDF has for them.

    `cursor` is where the next block's box would start with no spacing at all,
    and `pending` is the spacing after the last paragraph, which is still a
    knob until the next block is placed: the gap between two blocks is written
    once, either as the second one's spacing before or, when the second one is
    a table and has none, as the first one's spacing after. `was` and
    `was_pending` are the same walk over the values the converter wrote, which
    is how the page knows whether a correction made it taller.
    """

    def __init__(self, top):
        self.cursor = self.was = top
        self.pending = self.was_pending = 0.0
        self.undo = []
        self.changed = 0
        self.placed = 0
        self.drift = None
        self.last_lines = 1
        self.above = None
        # Set when a block with text in it found no rows to stand on. The
        # cursor counts such a block as the converter declared it (one line
        # for a paragraph Word wraps into three), so from there on it is
        # behind the page by the lines it left out, and a gap taken from the
        # PDF's absolute position less that cursor is too wide by exactly
        # them. Cleared by the next block the rows do match.
        self.lost = False

    def keep(self, block, metrics):
        self.undo.append((block, metrics["before"], metrics["after"], metrics["line"]))

    def flow(self, lead, height, after, was_lead, was_height, was_after, lines=1):
        self.last_lines = lines
        self.cursor += max(self.pending, lead) + height
        self.pending = after
        self.was += max(self.was_pending, was_lead) + was_height
        self.was_pending = was_after


def place_page(section, blocks, rows, lines, page_height, absolute, anchors=(), edges=(), boxes=(),
               seams=None, declined=None):
    """Walk one page's blocks, correcting the spacing between them.

    Returns `(undo, changed, fits, drift)`: what to restore, how many blocks
    were really moved, whether the page still ends above its bottom margin,
    and how far the first block had to move, which is what decides whether the
    model understood where this page starts.

    `rows` is the page's text read as whole lines, which is what a top-level
    block holds; `lines` is the same text read column by column, which is
    what a table cell holds.
    """
    # Word reserves the top margin for the body and drops a paragraph's
    # spacing before at the top of a page, so the first block starts there
    # whatever it asks for.
    walk = PageWalk(section.top_margin.pt) if absolute else None
    for order, block in enumerate(blocks):
        if block.tag == qn("w:p"):
            metrics = paragraph_metrics(block)
            if metrics is None:
                picture = picture_line(block) if walk is not None else None
                if picture is None:
                    break
                lead = 0.0 if order == 0 else picture[0]
                gap = lead
                if order:
                    # Kept where the converter had it, as a table is: what
                    # the corrections above have added since comes off the
                    # spacing before it.
                    gap = walk.was + max(walk.was_pending, lead) - walk.cursor
                    if gap < walk.pending and walk.pending > 0 and walk.above is not None:
                        walk.keep(*walk.above)
                        set_spacing(walk.above[0], after=0.0)
                        walk.pending = 0.0
                    gap = max(0.0, gap)
                    if abs(gap - lead) >= RHYTHM_TOLERANCE_PT:
                        walk.undo.append((block, lead, picture[2], None))
                        set_spacing(block, before=gap)
                        walk.changed += 1
                walk.flow(gap, picture[1], picture[2], lead, picture[1], picture[2])
                walk.above = None
                continue
            lead = 0.0 if order == 0 else metrics["before"]
            key = block_key(block)
            span = consume_rows(rows, walk.placed if walk else 0, key) if len(key) >= COMPARE_MIN_CHARS else None
            if span is None:
                if walk:
                    walk.lost = walk.lost or len(key) >= COMPARE_MIN_CHARS
                    walk.flow(lead, metrics["lines"] * metrics["line"], metrics["after"],
                              lead, metrics["lines"] * metrics["line"], metrics["after"],
                              metrics["lines"])
                    walk.above = (block, metrics)
                continue
            mine = rows[span[0]:span[1]]
            line, floor = wanted_line_height(mine, metrics["line"])
            if has_own_shape(block):
                line, floor = metrics["line"], metrics["line"]
            # How many lines Word will draw, which is how many the PDF drew:
            # counting the manual breaks alone misses a paragraph the
            # converter left whole and Word wraps by itself, and a block
            # placed under that count lands a line high, which is what used to
            # push a page over.
            count = max(metrics["lines"], len(mine))
            if (walk is not None and len(mine) >= 2
                    and floor > row_pitch(mine) + RHYTHM_TOLERANCE_PT
                    and abs(metrics["line"] - row_pitch(mine)) < RHYTHM_TOLERANCE_PT):
                # One of its rows is too tall for the PDF's pitch, a heading
                # the converter joined to the paragraph under it, while the
                # converter's own height is already that pitch. One exact
                # height for every line would be the heading's, and a
                # conclusion under a 14 pt heading had its six body lines
                # spread 2.7 pt apart each, where the converter's height had
                # them on the PDF's. The block keeps what the converter wrote,
                # and the walk carries on under it. The reference report's
                # sub-headings over one line are the same shape with a
                # converter height off the pitch, and there the walk helps.
                if declined is not None:
                    declined["rhythm-tall-row"] += 1
                walk.placed = span[1]
                walk.flow(lead, count * metrics["line"], metrics["after"],
                          lead, count * metrics["line"], metrics["after"], count)
                walk.above = (block, metrics)
                continue
            # Where the block's first baseline has to land. A block of several
            # lines gets one line height for all of them, so pinning its first
            # line to the PDF leaves the rest to drift: the reference report
            # writes a sub-heading and the paragraph under it as one block,
            # and the gap below the heading is wider than the gap between two
            # body lines. Straddling instead, so the residuals fall either
            # side of zero, halves the worst of them.
            target = first_baseline_target(mine, line)
            if walk is None:
                # Relative mode: this block stays where the converter put it
                # and everything below is measured from here.
                if (count - 1) * abs(line - metrics["line"]) >= RHYTHM_TOLERANCE_PT:
                    # Its lines keep the converter's height, not the PDF's
                    # pitch, so where it ends is not where the PDF's rows say.
                    # A right-aligned address block of three lines at 13.8 pt
                    # in a letter set at 14.4 pt ended 1.2 pt from where this
                    # walk assumed, and every block under it moved by that
                    # much, where the converter's own spacing had them within
                    # 0.3 pt. The page keeps the converter's spacing.
                    if declined is not None:
                        declined["rhythm-uneven-anchor"] += 1
                    return [], 0, True, 0.0
                walk = PageWalk(target - EXACT_BASELINE_RATIO * metrics["line"])
                walk.placed = span[1]
                walk.drift = 0.0
                walk.flow(0.0, count * metrics["line"], metrics["after"],
                          0.0, count * metrics["line"], metrics["after"], count)
                walk.above = (block, metrics)
                continue
            walk.placed = span[1]
            gap = target - EXACT_BASELINE_RATIO * line - walk.cursor
            if walk.lost:
                walk.lost = False
                if order and gap - lead > RHYTHM_TOLERANCE_PT:
                    # The rows are found again, but the cursor is still behind
                    # by the lines it never counted, so this gap is too wide by
                    # them (a 66 pt jump under a card on one measured page).
                    # The block keeps the converter's own spacing and the walk
                    # carries on from where the PDF says the block stands.
                    if declined is not None:
                        declined["rhythm-lost-walk"] += 1
                    behind = gap - max(walk.pending, lead)
                    gap = lead
                    walk.cursor += behind
                    walk.was += behind
            if gap < walk.pending and walk.pending > 0 and walk.above is not None:
                # Word takes the larger of the spacing after the block above
                # and the spacing before this one, not their sum, so as long as
                # the one above is the larger, writing this one changes
                # nothing. It has to give its spacing back first.
                walk.keep(*walk.above)
                set_spacing(walk.above[0], after=0.0)
                walk.pending = 0.0
            if gap < 0 and line > floor:
                # Still no room for the box the converter asked for. A shorter
                # one gives back its height less the part above the baseline,
                # down to the smallest box that holds this text's own ascent.
                room = count - EXACT_BASELINE_RATIO
                if room > 0:
                    line = max(floor, line + gap / room)
                    target = first_baseline_target(mine, line)
                    gap = target - EXACT_BASELINE_RATIO * line - walk.cursor
            if span[1] >= len(rows) and gap > walk.pending:
                # The last block with text on the page, and its gap is the
                # page's slack: a footnote carries the whole distance down to
                # the bottom as its spacing before (93.6 pt on one measured
                # page), so a line or two of drift anywhere above it, in the
                # Word that draws it, pushes the note past the margin and onto
                # a page of its own. Its bottom stays inside the guard the
                # page's own fit test uses, and the gap gives up the rest.
                # Only for a block that sticks out by less than its own height:
                # a row far past the margin is a page the model has not
                # understood, and that page is refused below.
                over = (walk.cursor + gap + count * line
                        - (page_height - section.bottom_margin.pt - RHYTHM_BOTTOM_GUARD_PT))
                if RHYTHM_TOLERANCE_PT < over <= count * line:
                    if declined is not None:
                        declined["rhythm-last-block-capped"] += 1
                    gap = max(walk.pending, gap - over)
            gap = 0.0 if order == 0 else max(0.0, gap)
            if walk.drift is None:
                # How far the first block really moves: Word draws the larger
                # of two touching spacings, before and after this change, so
                # an empty paragraph the converter wrote above the page's first
                # heading, with its spacing after, is part of the gap. Measured
                # against this block's spacing before alone, a heading 2 pt off
                # read as 18 pt, and the page fell back to anchoring on a block
                # further down whose place in Word is a guess.
                walk.drift = max(walk.pending, gap) - max(walk.was_pending, lead)
            walk.keep(block, metrics)
            set_spacing(block, before=gap, line=line)
            if abs(gap - lead) >= RHYTHM_TOLERANCE_PT or abs(line - metrics["line"]) >= RHYTHM_TOLERANCE_PT:
                walk.changed += 1
            walk.flow(gap, count * line, metrics["after"],
                      lead, count * metrics["line"], metrics["after"], count)
            walk.above = (block, metrics)
            continue
        if block.tag == qn("w:tbl"):
            metrics = table_metrics(block)
            if metrics is None:
                break
            key = block_key(block)
            span = consume_rows(rows, walk.placed if walk else 0, key) if len(key) >= COMPARE_MIN_CHARS else None
            if walk is None:
                if span is None or metrics["inside"] is None:
                    continue
                # A table anchors a page too: the numbered heading that opens
                # a section arrives as a one-row table.
                walk = PageWalk(rows[span[0]]["base"] - metrics["inside"])
                walk.placed = span[1]
                walk.drift = 0.0
                walk.flow(0.0, metrics["height"], 0.0, 0.0, metrics["height"], 0.0)
                continue
            if span is not None:
                walk.placed = span[1]
                walk.lost = False
            previous = blocks[order - 1] if order else None
            earlier = paragraph_metrics(previous) if previous is not None and previous.tag == qn("w:p") else None
            # A table keeps the place the converter gave it. It reads a
            # table's top off the PDF's own grid lines and sizes the rows from
            # them, so its rules already land on the PDF's; a target taken
            # from the text inside the first row would move the whole grid to
            # put one baseline right, and the reference report's finding cards
            # lost a point of similarity each when that was tried. What does
            # move is the gap above it, which takes up whatever the
            # corrections above have added or removed.
            known = known_panel(anchors, block)
            wanted = walk.was + walk.was_pending if known is None else known[0]
            if known is None:
                # The rectangle the PDF drew for this table first, because it
                # says where the top goes rather than only that something
                # lines up there; the fit against the page's rules otherwise.
                shift = table_box_offset(boxes, block, section.left_margin.pt, wanted,
                                         first_row_baselines(block, section.left_margin.pt, lines))
                wanted += shift or table_top_offset(edges, block, section.left_margin.pt, wanted)
            if earlier is not None:
                gap = max(0.0, wanted - walk.cursor)
                if walk.drift is None:
                    walk.drift = gap - walk.pending
                if walk.lost and gap - walk.pending > RHYTHM_TOLERANCE_PT:
                    # A block above found no rows, so the cursor is behind the
                    # page by the lines it never counted and a wider gap here
                    # only pays for them. The spacing stays as written.
                    if declined is not None:
                        declined["rhythm-lost-walk"] += 1
                    gap = walk.pending
                else:
                    walk.keep(previous, earlier)
                    set_spacing(previous, after=gap)
                    if abs(gap - walk.pending) >= RHYTHM_TOLERANCE_PT:
                        walk.changed += 1
                    walk.pending = gap
            found, table_undo = align_table_cells(block, walk.cursor + walk.pending,
                                                  section.left_margin.pt, lines, anchors,
                                                  RHYTHM_NESTING, seams)
            walk.changed += found
            walk.undo.extend(table_undo)
            walk.flow(0.0, metrics["height"], 0.0, 0.0,
                      metrics["height"] if known is None else known[1], 0.0)
            walk.above = None
            continue
        break
    if walk is None:
        return [], 0, True, 0.0
    end = walk.cursor + walk.pending
    fits = (end <= walk.was + walk.was_pending + RHYTHM_TOLERANCE_PT
            or end <= page_height - section.bottom_margin.pt - RHYTHM_BOTTOM_GUARD_PT + RHYTHM_TOLERANCE_PT)
    return walk.undo, walk.changed, fits, walk.drift or 0.0


def restore(undo):
    for block, before, after, line in reversed(undo):
        set_spacing(block, before=before, after=after, line=line)


def pitch_cuts(rows):
    """Where a block's own baselines say the converter joined two blocks.

    The smallest distance between two of a block's baselines is the leading
    the typesetter set it at. A bigger one is the space a report puts between
    a sub-heading and the paragraph under it, or between two entries of a
    list, and the converter writes both of those as one paragraph with a line
    break in it. One exact line height cannot serve two leadings, so the wider
    gaps are where the paragraph has to become two.

    Returns the row indexes a paragraph break belongs before, and an empty
    list when every gap is the same, which is every ordinary paragraph. Two
    rows have a single gap and no second one to read it against, so they are
    never cut: there is no evidence which of the two kinds of gap it is.
    """
    gaps = [later["base"] - earlier["base"] for earlier, later in zip(rows, rows[1:])]
    if len(gaps) < 2:
        return []
    leading = min(gaps)
    return [index + 1 for index, gap in enumerate(gaps) if gap > leading + PITCH_SPLIT_PT]


def break_runs(element):
    """The runs holding this paragraph's own line breaks, in order.

    None when any break sits somewhere a paragraph boundary cannot replace it
    one for one: a page break, a break inside a hyperlink or a field, or a
    break sharing its run with text. Both the converter and this file's own
    line-break pass write a break as a run of its own directly in the
    paragraph, so the ordinary case is the one that is handled and anything
    else gives the paragraph back untouched.
    """
    holders = []
    for node in element.iter(qn("w:br")):
        if (node.get(qn("w:type")) or "textWrapping") != "textWrapping":
            return None
        run = node.getparent()
        if run is None or run.tag != qn("w:r") or run.getparent() is not element:
            return None
        if any(child is not node and child.tag != qn("w:rPr") for child in run):
            return None
        holders.append(run)
    return holders


def splittable(element, shaded):
    """May this paragraph be cut in two without changing what it says?

    Four kinds are refused rather than risked: one that paints its own shape
    would paint it twice, a numbered one would take a second number, code has
    to come out byte for byte, and a table-of-contents line is rebuilt from
    the PDF elsewhere. So is one holding a drawing, which is where the picture
    pass put it.
    """
    if has_own_shape(element) or is_code(element, shaded):
        return False
    properties = element.find(qn("w:pPr"))
    if properties is not None and properties.find(qn("w:numPr")) is not None:
        return False
    if properties is not None and properties.find(qn("w:sectPr")) is not None:
        # A section break lives in the properties of the paragraph it ends, so
        # cutting that paragraph is cutting a section boundary. `cut_paragraph`
        # carries the break to the last piece and would be correct on its own;
        # a paragraph that decides where a page's margins and its header start
        # is still not worth a point of leading.
        return False
    if next(element.iter(qn("w:drawing")), None) is not None:
        return False
    return not DOT_RUN.search(paragraph_text(element))


def cut_paragraph(element, holders):
    """Turn the given line breaks into paragraph breaks.

    Returns the seams, `(head, tail, holder)` in the order they were made, so
    the change can be taken back exactly: the break run is kept rather than
    dropped, and putting it back where it was and moving the tail's content in
    after it gives back the paragraph it came from.

    The spacing is shared out so the pieces are together the height the one
    paragraph was: the first keeps the spacing before, the last keeps the
    spacing after, the seams get none, and every piece keeps the line height.
    A paragraph that is cut and then never placed is therefore exactly as many
    points tall as the one it replaced, which is what stops a cut from pushing
    a line onto the next page.
    """
    metrics = paragraph_metrics(element)
    if metrics is None:
        return []
    seams = []
    head = element
    for holder in holders:
        moving, found = [], False
        for child in head:
            if child is holder:
                found = True
            elif found:
                moving.append(child)
        if not found:
            break
        tail = OxmlElement("w:p")
        properties = head.find(qn("w:pPr"))
        if properties is not None:
            copied = copy.deepcopy(properties)
            # Never copied: a section break ends its section AT the paragraph
            # holding it, so one on every piece is three section breaks where
            # the document had one, and two of them in the wrong place.
            for node in copied.findall(qn("w:sectPr")):
                copied.remove(node)
            tail.append(copied)
        for child in moving:
            tail.append(child)
        head.remove(holder)
        head.addnext(tail)
        seams.append((head, tail, holder))
        head = tail
    if not seams:
        return []
    carry_section(element, seams[-1][1])
    set_spacing(element, after=0.0)
    for _, tail, _ in seams[:-1]:
        set_spacing(tail, before=0.0, after=0.0)
    set_spacing(seams[-1][1], before=0.0, after=metrics["after"])
    return seams


def carry_section(source, target):
    """Move a section break from one paragraph's properties to another's.

    The piece of a cut paragraph that keeps the original properties is the
    first one, and a `w:sectPr` there would end the section at the wrong
    paragraph: it ends its section AT the paragraph holding it, and where this
    paragraph ended is the last piece. Joining the cut back up moves it the
    other way, which is why this takes a direction rather than assuming one.
    """
    properties = source.find(qn("w:pPr"))
    node = properties.find(qn("w:sectPr")) if properties is not None else None
    if node is None:
        return False
    properties.remove(node)
    insert_ordered(target.get_or_add_pPr(), node, PPR_ORDER)
    return True


def rejoin_paragraph(head, tail, holder):
    """Put one cut of a paragraph back, exactly as it was."""
    metrics = paragraph_metrics(tail)
    # The cut moved a section break to the last piece, so joining back up has
    # to bring it home, or the document loses the break altogether.
    carry_section(tail, head)
    head.append(holder)
    for child in list(tail):
        if child.tag != qn("w:pPr"):
            head.append(child)
    parent = tail.getparent()
    if parent is not None:
        parent.remove(tail)
    if metrics is not None:
        set_spacing(head, after=metrics["after"])


def split_pitch_changes(document, pages, shaded=()):
    """Cut a paragraph in two where the PDF changed its leading inside it.

    The converter writes a sub-heading and the paragraph under it as one block
    with a line break between them, and a Word paragraph has one exact line
    height for all of its lines. Whichever height that one number takes, the
    lines set at the other leading walk away from the page they came from: on
    the reference report the body under a sub-heading finishes 2.4 to 7.3 pt
    below where the PDF has it, which is the largest thing left on four of its
    pages, and the heading itself is dragged up to meet it.

    The cut adds nothing and deletes nothing. A line break becomes a paragraph
    break, which the text check, the reader and a copy out of Word all read
    the same way, and the spacing is shared out so the pieces are as tall
    together as the paragraph was. What the pieces are worth is the layout
    pass after this one, which can now give each of them the line height its
    own lines were set at, so a piece that pass does not reach is joined back
    up rather than left with no space above it.

    The blocks are paired with the PDF's rows the way `place_page` pairs them,
    and the walk stops where that one stops, so the two agree about which rows
    belong to which block.
    """
    sections = page_blocks(document.element.body)
    if len(sections) != len(pages):
        return []
    shaded = set(shaded)
    seams = []
    for index, blocks in enumerate(sections):
        rows = pages[index]
        if not rows:
            continue
        placed = 0
        for block in blocks:
            if block.tag == qn("w:p"):
                if paragraph_metrics(block) is None:
                    break
            elif block.tag == qn("w:tbl"):
                if table_metrics(block) is None:
                    break
            else:
                break
            key = block_key(block)
            span = consume_rows(rows, placed, key) if len(key) >= COMPARE_MIN_CHARS else None
            if span is None:
                continue
            placed = span[1]
            if block.tag != qn("w:p"):
                continue
            mine = rows[span[0]:span[1]]
            cuts = pitch_cuts(mine)
            if not cuts or not splittable(block, shaded):
                continue
            holders = break_runs(block)
            if holders is None or len(holders) != len(mine) - 1:
                # One break per line end, or these breaks are not the PDF's
                # line ends and a cut would fall somewhere it never broke.
                continue
            seams.extend(cut_paragraph(block, [holders[cut - 1] for cut in cuts]))
    return seams


def rejoin_unplaced(seams, written):
    """Join back up every cut piece the layout pass did not go on to place.

    A piece that was placed carries the spacing the PDF asks for above it. One
    that was not carries none, because none is what keeps a cut from making
    the document taller, and two paragraphs with nothing between them read a
    line tighter than the report printed. Joining it back up gives the reader
    the paragraph the converter wrote, which is where this round started.
    """
    joined = 0
    for head, tail, holder in reversed(seams):
        if id(tail) in written:
            continue
        rejoin_paragraph(head, tail, holder)
        joined += 1
    return joined


def fold_leading_space_into_margin(document):
    """Make the offset of a page's first line the page's top margin.

    The rhythm walk starts every page at its top margin and takes the first
    block to stand there, so it writes the first paragraph's spacing before as
    0 and measures every gap below from a cursor that has not counted it. That
    holds on a page whose margin pdf2docx took from the first line. On a page
    that begins with a full-bleed shape the margin is 0 and the first line's
    distance from the page's top is that paragraph's spacing before, so the
    walk wrote 0 over it: on design-b1's cover the kicker "PENETRATION TEST
    REPORT" stood at the top edge instead of 82.7 pt down, and because the
    walk's two models both lost the same offset the gap above the meta table
    came out as 0 and its orange rule sat under the subtitle, 36 pt above
    where the PDF draws it.

    The spacing becomes margin: the page's body then starts where its first
    line is and the walk's premise is true. The layout Word draws is the
    same as with the spacing, which is why the converter's own file was right
    here. A section that has a header (or follows one, which it inherits) is
    left alone, since Word starts its body below the header whatever the
    margin says and the two would no longer be equal.
    Returns how many pages were changed.
    """
    body = document.element.body
    sections = page_sections(document)
    pages = page_blocks(body)
    if len(sections) != len(pages):
        return 0
    changed = 0
    header_above = False
    for section, blocks in zip(sections, pages):
        if section._sectPr.find(qn("w:headerReference")) is not None:
            header_above = True
        if header_above or not blocks or blocks[0].tag != qn("w:p"):
            continue
        metrics = paragraph_metrics(blocks[0])
        if metrics is None or metrics["before"] < LEAD_FOLD_MIN_PT:
            continue
        section.top_margin = Pt(section.top_margin.pt + metrics["before"])
        set_spacing(blocks[0], before=0.0)
        changed += 1
    return changed


def align_vertical_rhythm(document, pages, page_height, anchors=(), rules=(), seams=(), boxes=(),
                          declined=None):
    """Put every block's first line on the baseline the PDF gave it.

    One walk per section, because the converter writes one section per PDF
    page. Every block's spacing becomes whatever puts the next block's first
    baseline where the PDF has it, given the line heights this file declares,
    and a block whose height the file does not state ends the walk for that
    page. Two things are refused rather than risked: a page whose first block
    would move further than a line, which means the model has not understood
    where this page starts, and a page that would end below its bottom margin,
    which is how a page count changes.
    """
    body = document.element.body
    sections = page_blocks(body)
    starts = page_sections(document)
    if len(sections) != len(pages) or len(sections) != len(starts):
        rejoin_unplaced(seams, set())
        return 0
    # The cuts this pass makes inside a table cell join the ones the pre-pass
    # made at the top level, so a piece that is never placed is joined back up
    # wherever it was cut.
    made = list(seams)
    moved = 0
    written = set()
    for index, blocks in enumerate(sections):
        rows = pages[index]
        if not rows:
            continue
        section = starts[index]
        lines = text_columns(rows)
        edges = rules[index] if index < len(rules) else ()
        drawn = boxes[index] if index < len(boxes) else ()
        # A walk counts what it declined, and only the walk the page keeps
        # reports it.
        tried = Counter()
        undo, changed, fits, drift = place_page(section, blocks, rows, lines, page_height,
                                                True, anchors, edges, drawn, made, tried)
        if not fits or abs(drift) > RHYTHM_ABSOLUTE_LIMIT_PT:
            restore(undo)
            tried = Counter()
            undo, changed, fits, _ = place_page(section, blocks, rows, lines, page_height,
                                                False, anchors, edges, drawn, made, tried)
            if not fits:
                restore(undo)
                undo, changed = [], 0
                tried = Counter()
        if declined is not None:
            declined.update(tried)
        # What is left in `undo` is what this page kept, which is the only
        # thing that says a cut paragraph was really given its spacing back.
        written.update(id(block) for block, _, _, _ in undo)
        moved += changed
    rejoin_unplaced(made, written)
    return moved


# ── step 7: the text the converter ran together ───────────────────────────


def typed_soft_hyphens(doc, bands):
    """Soft hyphens the author typed, rather than the ones typst broke lines at.

    A break hyphen is the last character of its line. One anywhere else was in
    the report's own text, is invisible to a reader, and is removed with the
    rest, so the export says how many.
    """
    member_rows = set()
    for band in bands:
        member_rows |= band.get("members") or set()
    typed = 0
    for index in range(doc.page_count):
        for row in page_rows(doc[index]):
            if row_id(index, row) in member_rows:
                continue
            for column in row["columns"]:
                text = column["text"]
                typed += text.count("­") - (1 if text.endswith("­") else 0)
    return max(0, typed)


def broken_words(doc, bands):
    """Boundaries where the typesetter broke a word across two lines.

    It marks the break with a soft hyphen, which is invisible to a reader of
    the PDF because the PDF prints a hyphen for it, and visible to a reader of
    a Word file because Word prints it in the middle of a line. So every one
    of them is removed, and where the Word file breaks the line in the same
    place a real hyphen goes back: without it the page reads "em ployed".
    """
    members = set()
    for band in bands:
        members |= band.get("members") or set()
    pairs = set()
    for index in range(doc.page_count):
        rows = [r for r in page_rows(doc[index]) if row_id(index, r) not in members]
        for left, right in zip(rows, rows[1:]):
            if not left["text"].rstrip().endswith(SOFT_HYPHEN):
                continue
            pairs.add((compare_squash(left["text"])[-PAIR_WINDOW:],
                       compare_squash(right["text"])[:PAIR_WINDOW]))
    return {pair for pair in pairs if pair[0] and pair[1]}


def restore_break_hyphens(document, broken, shaded=()):
    """Put the hyphen back at every line end where the PDF broke a word.

    A line ends at a manual break or at the end of a paragraph, and the
    converter writes most of the PDF's lines as paragraphs of their own, so
    both count. The pair of words either side of the break identifies it, the
    same way the space repair identifies a run boundary, so a hyphen is never
    added anywhere the PDF did not break a word.
    """
    if not broken:
        return 0
    shaded = set(shaded)
    stream = []
    for element in body_paragraphs(document):
        if is_code(element, shaded):
            stream.append(None)
            continue
        for node in element.iter():
            if node.tag == qn("w:t"):
                stream.append(node)
            elif node.tag in (qn("w:br"), qn("w:cr")):
                stream.append(None)
        stream.append(None)
    added = 0
    for index, item in enumerate(stream):
        if item is not None:
            continue
        last, before = None, ""
        for back in range(index - 1, -1, -1):
            if stream[back] is None:
                break
            # A run emptied by the passes before (a soft hyphen that had a run
            # of its own) is no line end to put the hyphen on.
            if last is None and (stream[back].text or ""):
                last = stream[back]
            before = (stream[back].text or "") + before
            if len(compare_squash(before)) >= PAIR_WINDOW:
                break
        after = ""
        for ahead in range(index + 1, len(stream)):
            if stream[ahead] is None:
                break
            after += stream[ahead].text or ""
            if len(compare_squash(after)) >= PAIR_WINDOW:
                break
        if last is None or not (last.text or ""):
            continue
        key = (compare_squash(before)[-PAIR_WINDOW:], compare_squash(after)[:PAIR_WINDOW])
        if key in broken and not last.text.rstrip().endswith("-"):
            last.text = last.text + "-"
            last.set(qn("xml:space"), "preserve")
            added += 1
    return added


def spaced_pairs(doc):
    """Boundaries where the PDF put a gap and the converter may not.

    pdf2docx writes one run per PDF span and drops the space between two of
    them, so a numbered step arrives as "1.{{REMEDIATION STEP}}". The PDF
    knows there was a gap there, so the pairs are collected here and matched
    against the converter's run boundaries afterwards.
    """
    pairs = set()
    for index in range(doc.page_count):
        for row in page_rows(doc[index]):
            for left, right in zip(row["columns"], row["columns"][1:]):
                pairs.add((compare_squash(left["text"])[-PAIR_WINDOW:],
                           compare_squash(right["text"])[:PAIR_WINDOW]))
            # Within a column the row builder already inserted the space, so
            # the pair is taken from the text it produced.
            for column in row["columns"]:
                text = column["text"]
                for position, char in enumerate(text):
                    if char == " " and position and position + 1 < len(text):
                        pairs.add((compare_squash(text[:position])[-PAIR_WINDOW:],
                                   compare_squash(text[position + 1:])[:PAIR_WINDOW]))
    return {pair for pair in pairs if pair[0] and pair[1]}


def is_code(element, shaded):
    """Is this paragraph code, where a space is a change and not a repair?

    Two signals, either of which is enough: the shape pass painted it as a
    panel (a code block is the thing that comes out of the converter as bare
    text on white paper), or every run in it names a monospace family.
    """
    if element in shaded:
        return True
    fonts = [f.get(qn("w:ascii")) or "" for f in element.iter(qn("w:rFonts"))]
    return bool(fonts) and all(MONOSPACE.search(name) for name in fonts)


def adjacent_text(element):
    """Pairs of text nodes with nothing between them a reader would see.

    A tab or a line break already separates two pieces of text, and a table of
    contents is written as "number, tab, title": adding a space there as well
    pushed every title in the reference report's list 2.9 pt, one space, to
    the right of where the PDF has it. Walking the `w:t` nodes alone cannot
    see that, because the tab is not one of them.
    """
    pairs = []
    previous = None
    for node in element.iter():
        if node.tag in (qn("w:tab"), qn("w:br"), qn("w:cr")):
            previous = None
            continue
        if node.tag != qn("w:t"):
            continue
        if previous is not None:
            pairs.append((previous, node))
        previous = node
    return pairs


def repair_text(document, pairs, shaded=()):
    """Drop soft hyphens, and put back a space the converter ran together.

    A soft hyphen is where the typesetter broke a word, not a character of the
    document, and Word prints it: the reference report showed "em-ployed",
    "likeli-hood" and "appro-priate" in the middle of a line. Real hyphens are
    U+002D and are left alone, which is why this does not use pdf2docx's own
    `delete_end_line_hyphen`: that would turn "non-critical" into
    "noncritical". Every soft hyphen goes, including one an author typed on
    purpose and including one inside a code block; `typed_soft_hyphens` counts
    those separately so the export can say it happened.

    The space repair is kept away from code. The text check squashes
    whitespace, so a space added inside a command would be invisible to it,
    and `1.{{X}}` or `version1.2.3` in a shell line must come out byte for
    byte as the report wrote it.
    """
    shaded = set(shaded)
    removed, spaced = 0, 0
    for element in body_paragraphs(document):
        nodes = [n for n in element.iter(qn("w:t"))]
        for node in nodes:
            if node.text and "­" in node.text:
                removed += node.text.count("­")
                node.text = node.text.replace("­", "")
                node.set(qn("xml:space"), "preserve")
        if is_code(element, shaded):
            continue
        for left, right in adjacent_text(element):
            if not left.text or not right.text:
                continue
            if left.text[-1].isspace() or right.text[0].isspace():
                continue
            key = (compare_squash(left.text)[-PAIR_WINDOW:], compare_squash(right.text)[:PAIR_WINDOW])
            if key[0] and key[1] and key in pairs:
                right.text = " " + right.text
                right.set(qn("xml:space"), "preserve")
                spaced += 1
    return removed, spaced


# ── step 8: the font names Word resolves with ─────────────────────────────


def name_looks(value, plan):
    """Give every look read off the PDF the family Word resolves it to.

    The bands and the table of contents are read as PDF spans and written as
    Word runs, so each one carries the name the PDF used. Here that name
    becomes the family in the font file's own name table, with the two flags
    the file states, which is the only pair Word will match a face on.
    """
    if isinstance(value, dict):
        face = fonts.resolve_pdf_font(plan, value.get("psname"))
        if face:
            value["font"] = face["family"]
            value["bold"] = face["bold"]
            value["italic"] = face["italic"]
        for item in value.values():
            name_looks(item, plan)
    elif isinstance(value, (list, tuple)):
        for item in value:
            name_looks(item, plan)


def run_parts(document):
    """The body and every header and footer, as XML roots."""
    roots = [document.element.body]
    for part in document.part.package.iter_parts():
        element = getattr(part, "element", None)
        if element is not None and element.tag in (qn("w:hdr"), qn("w:ftr")):
            roots.append(element)
    return roots


def flag_of(properties, tag):
    """Whether a run property is on, reading Word's several ways of saying no."""
    node = properties.find(qn(tag)) if properties is not None else None
    if node is None:
        return False
    return (node.get(qn("w:val")) or "true").lower() not in ("0", "false", "off")


def set_flag(properties, tag, value):
    """`w:b` or `w:i` said out loud, on or off, where the schema wants it."""
    node = properties.find(qn(tag))
    if node is None:
        node = OxmlElement(tag)
        insert_ordered(properties, node, RPR_ORDER)
    node.set(qn("w:val"), "1" if value else "0")


def named_font(run):
    """The family a run asks for by name, or None when it asks for nothing."""
    properties = run.find(qn("w:rPr"))
    table = properties.find(qn("w:rFonts")) if properties is not None else None
    return table.get(qn("w:ascii")) if table is not None else None


def draws(run):
    """Does this run put anything on the page?"""
    return any(run.find(qn(tag)) is not None for tag in RUN_CONTENT)


def name_runs(document, plan):
    """Name every run by the family Word resolves, with the flags to match.

    The converter labels a run with whatever the PDF called the face, and the
    PDF calls it by its PostScript name. Word matches on the legacy family
    instead, so a run asking for `DejaVuSansMono` never reaches the file
    called `DejaVu Sans Mono`, embedded in the same document or not, and Word
    substitutes without saying so.

    The flags come from the same file. A face whose subfamily is Bold is the
    family plus `w:b`; a face whose subfamily is Regular is the family with
    `w:b` cleared, however heavy its name reads, because a weight Word does
    not keep per family has a family of its own and asking for bold on top of
    it paints a fake weight over a face that already had one.
    """
    named = 0
    for root in run_parts(document):
        for run in root.iter(qn("w:r")):
            current = named_font(run)
            if not current:
                continue
            properties = run.find(qn("w:rPr"))
            face = fonts.resolve(plan, current, flag_of(properties, "w:b"), flag_of(properties, "w:i"))
            if not face:
                continue
            table = properties.find(qn("w:rFonts"))
            for attribute in ("w:ascii", "w:hAnsi", "w:cs"):
                table.set(qn(attribute), face["family"])
            if table.get(qn("w:eastAsia")) is not None:
                table.set(qn("w:eastAsia"), face["family"])
            # A theme name would be consulted before the one just written.
            for attribute in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
                if table.get(qn(attribute)) is not None:
                    del table.attrib[qn(attribute)]
            set_flag(properties, "w:b", face["bold"])
            set_flag(properties, "w:i", face["italic"])
            named += 1
    return named


def take_font(properties, donor):
    """Copy the font and size across, leaving everything else alone."""
    for tag in ("w:rFonts", "w:sz", "w:szCs"):
        node = donor.find(qn(tag))
        if node is not None and properties.find(qn(tag)) is None:
            insert_ordered(properties, copy.deepcopy(node), RPR_ORDER)


def fill_bare_runs(document):
    """Anything in a paragraph that names no font takes the text's.

    pdf2docx writes a tab as a run with no properties at all, a few more
    arrive the same way, and no paragraph gets properties for its own
    paragraph mark. Word sets all of those in the document default, which on
    a file built from python-docx's template is an 11 pt serif nothing else
    on the page uses. None of them draws anything a reader would call a
    glyph, but Word writes the mark out as a space when it makes a PDF, so
    the finished file is set in a font it does not carry and cannot be shown
    to use only the fonts it does.

    Each one takes the font and size of the text beside it: a run from the
    run after it, else the one before; a paragraph mark from the last run of
    its own paragraph, which is the formatting Word itself would give a mark
    typed there; and the mark of a paragraph with no text at all from the
    nearest paragraph that has some. That last one is the only place this
    could move something, because an empty paragraph's height is its mark's,
    and it was measured before it was written: over the reference report, 22
    of them, every page scored to four decimal places exactly as it had.
    """
    filled = 0
    for root in run_parts(document):
        paragraphs = list(root.iter(qn("w:p")))
        donors = []
        for paragraph in paragraphs:
            runs = list(paragraph.iter(qn("w:r")))
            named = [run for run in runs if named_font(run)]
            donors.append(named[-1].find(qn("w:rPr")) if named else None)
            if not named:
                continue
            for index, run in enumerate(runs):
                if named_font(run) or not draws(run):
                    continue
                source = next((r for r in runs[index + 1:] if named_font(r)), None)
                if source is None:
                    source = next(r for r in reversed(runs[:index]) if named_font(r))
                properties = run.find(qn("w:rPr"))
                if properties is None:
                    properties = OxmlElement("w:rPr")
                    run.insert(0, properties)
                take_font(properties, source.find(qn("w:rPr")))
                filled += 1
        for position, paragraph in enumerate(paragraphs):
            donor = donors[position]
            if donor is None:
                donor = next((d for d in reversed(donors[:position]) if d is not None), None)
            if donor is None:
                donor = next((d for d in donors[position + 1:] if d is not None), None)
            if donor is None:
                continue
            mark = paragraph.get_or_add_pPr()
            properties = mark.find(qn("w:rPr"))
            if properties is None:
                properties = OxmlElement("w:rPr")
                insert_ordered(mark, properties, PPR_ORDER)
            if properties.find(qn("w:rFonts")) is None:
                take_font(properties, donor)
                filled += 1
    return filled


# ── the safety net: did the Word file keep the PDF's text? ────────────────
#
# Every repair above deletes something from the document and writes something
# back, and a heuristic that deletes the wrong thing is the one failure nobody
# would notice: the Word file still looks like a report. So the two texts are
# compared afterwards, and a conversion that lost any of the PDF's words is
# thrown away and done again with the repairs off.

# Characters a typesetter leaves in the text layer that no reader sees.
INVISIBLE_FOR_COMPARE = dict.fromkeys(
    ord(c) for c in "­​‌‍⁠﻿‎‏"
)
INVISIBLE_CHARS = frozenset(chr(code) for code in INVISIBLE_FOR_COMPARE)
# Three dots or more is a leader, not words. The PDF writes them as characters
# and Word draws them from a tab stop, so neither side may count them.
DOT_RUN = re.compile(r"(?:\.[ \t ]*){3,}")
# Whitespace, hyphens and dashes: everything a re-flow may add, drop or move.
DASHES = "".join(chr(c) for c in (0x2D, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2212))
SQUASH_DROP = re.compile("[\\s%s]+" % re.escape(DASHES), re.UNICODE)
HAS_ALNUM = re.compile(r"\w", re.UNICODE)
# A piece of text shorter than this proves nothing: "1." and "LOW" occur all
# over a report, so finding one somewhere does not mean this one survived, and
# not finding it would be noise.
COMPARE_MIN_CHARS = 4
# A line pdf2docx cut at the page's edge is put back when a paragraph ends
# with its first part: at least this many characters of a line at least
# this long, so a short line that merely starts like another is not touched.
CUT_LINE_MIN_CHARS = 40
CUT_LINE_HEAD_CHARS = 24
CUT_LINE_KEPT_FRACTION = 0.6
# A line whose right end is within this of the page's edge ran into the margin.
CUT_EDGE_PT = 20.0
# Two pieces of text that share more than this much of the smaller one's box
# are drawn on top of each other, and neither can be read on the page. Lines
# set tighter than their glyph boxes overlap their neighbours by a sixth at
# most; a typst table too tall for an unbreakable figure stacks its overflow
# rows exactly on one another.
OVERPRINT_FRACTION = 0.5


W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
W_T = W_NS + "t"
BREAKS = (W_NS + "tab", W_NS + "br", W_NS + "p")


def compare_squash(text):
    """One block of text, flattened into the form both sides are compared in.

    Everything that a re-flow is allowed to change goes: whitespace of any
    kind, hyphens and dashes, dot leaders, and the invisible characters a
    typesetter leaves behind. What is left is the letters and digits in order,
    which is what has to survive the conversion.

    Whitespace has to go rather than be collapsed, because the two sides
    disagree about it constantly and none of it is content: the PDF prints
    "1. {{RECOMMENDATION}}" as two pieces on one line and the converter writes
    one run reading "1.{{RECOMMENDATION}}"; a word broken across two PDF lines
    comes back with the hyphen kept, dropped or turned into a space.
    """
    out = unicodedata.normalize("NFKC", text).translate(INVISIBLE_FOR_COMPARE)
    out = DOT_RUN.sub("", out)
    return SQUASH_DROP.sub("", out).casefold()


def compare_words(text):
    """A right-to-left line for the comparison: its words squashed, one space apart.

    compare_squash drops whitespace because a re-flow may move it, and that is
    exactly what hid pdf2docx running a Hebrew line together: with the spaces
    gone on both sides, a line with none left compares equal. For a
    right-to-left line the word boundaries are content, so they are kept.
    """
    return " ".join(w for w in (compare_squash(part) for part in text.split()) if w)


def body_lines(doc, bands):
    """The PDF's text for the comparison: one entry per line, with its pieces.

    A band's text is expected once per page in the PDF and once per section in
    the Word file, and those two counts have nothing to do with each other, so
    the comparison drops it on both sides instead of trying to reconcile them.
    Pages that do not carry the band keep every line.

    Each line also carries its columns, because they are the pieces that are
    really contiguous on the page. A row of a two-column table reads
    "TECHNIQUES MITIGATIONS" across the page and the converter writes the
    cells down one column and then the other, which is a re-ordering rather
    than a loss, and only the columns survive it.

    What is left out is the band's own MEMBER ROWS, never "everything inside
    the rectangle the band erases". Those are two different things: the
    rectangle is grown to swallow a rule or a strip, and excluding by
    rectangle hid from this check exactly the rows that growing it deleted.
    Anything else the erase removes is now reported as missing, which is what
    sends the conversion to the fallback.

    A row with any right-to-left letter in it is taken from the logical
    reading (`page_rows(page, logical=True)`) instead: in reading order and
    with only the spaces the PDF really has. Read left to right, a Hebrew
    line compares equal to a Word file whose words run backwards, and the
    spaces PyMuPDF makes up inside Arabic words would be demanded of a Word
    file that has the words right. Every other row is read as before.

    Except a left-to-right row with a number beside its right-to-left words
    (`ambiguous_number`): the page does not say which side of them the number
    was typed on, so no reading of that row is better than a guess. It keeps
    the default reading and is marked `ambiguous`, which is what tells the
    right-to-left repair to leave it alone.

    Every line also says which page it is on and whether the page draws it on
    top of other text (`overprinted`), so a loss can be told apart from text
    that could not be read in the PDF either.
    """
    members = set()
    for band in bands:
        members |= band.get("members") or set()
    lines = []
    for index in range(doc.page_count):
        reading = None
        blocks = doc[index].get_text("dict")["blocks"]
        stacked = overprinted_boxes(doc[index], blocks)
        for row in page_rows(doc[index], blocks=blocks):
            if row_id(index, row) in members:
                continue
            ambiguous = ambiguous_number(row["text"])
            if has_rtl(row["text"]) and not ambiguous:
                if reading is None:
                    reading = {row_id(index, r): r for r in page_rows(doc[index], logical=True)}
                row = reading.get(row_id(index, row), row)
            lines.append({"text": row["text"], "pieces": [c["text"] for c in row["columns"]],
                          "widths": [c["x1"] - c["x0"] for c in row["columns"]],
                          "ends": [c["x1"] for c in row["columns"]],
                          "y0": row["y0"], "y1": row["y1"],
                          "ambiguous": ambiguous, "page": index + 1,
                          # Does the line run into the page's right margin? A
                          # token typst could not break does, and pdf2docx
                          # cuts it there (`restore_cut_lines`).
                          "cut": row["x1"] > doc[index].rect.width - CUT_EDGE_PT,
                          "overprinted": any(box_within(box, column) for box in stacked
                                             for column in row["columns"])})
    return lines


def overprinted_boxes(page, blocks=None):
    """The boxes of every piece of text the page draws on top of different text.

    Typst does not split a figure across pages, so a table too tall for one
    page inside a `#figure` has its overflow rows set on top of one another at
    the foot of the page, with no warning. Their text is in the PDF and
    cannot be read there, and pdf2docx, reading the same pile, keeps none of
    it, so the text check reports it missing at every rung. Two spans with
    the same text are left out, because drawing a word twice in one place is
    how some writers fake bold.

    The test is glyph by glyph, not box by box: PyMuPDF gives an Arabic span
    set one glyph at a time a box as wide as its whole line, with the line's
    other spans inside it, and those boxes overlap completely on a page that
    reads perfectly well. Two spans overprint when most glyphs of the shorter
    one sit on a glyph of the other. Combining marks are not counted, since
    they sit on a letter by design. Reading the glyphs costs as much as reading
    the page again, so it is done only on a page where two spans' boxes
    already cover each other (`blocks`, the page's `get_text("dict")` blocks):
    an Arabic page or a pile like the one above, never an ordinary one.
    """
    if blocks is None:
        blocks = page.get_text("dict")["blocks"]
    boxes = sorted(((span["bbox"], span["text"].strip()) for block in blocks if block.get("type") == 0
                    for line in block.get("lines", []) for span in line.get("spans", [])
                    if span.get("text", "").strip()), key=lambda item: item[0][1])
    suspect = False
    for i, (box, text) in enumerate(boxes):
        for other, other_text in boxes[i + 1:]:
            if other[1] >= box[3]:
                break
            if text != other_text and overlap_share(box, other) > OVERPRINT_FRACTION:
                suspect = True
                break
        if suspect:
            break
    if not suspect:
        return []
    spans = []
    for block in page.get_text("rawdict")["blocks"]:
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                glyphs = [c["bbox"] for c in span.get("chars", [])
                          if c["c"].strip() and not unicodedata.combining(c["c"])
                          and c["bbox"][2] > c["bbox"][0] and c["bbox"][3] > c["bbox"][1]]
                if glyphs:
                    text = "".join(c["c"] for c in span["chars"]).strip()
                    spans.append({"bbox": span["bbox"], "glyphs": glyphs, "text": text})
    spans.sort(key=lambda span: span["bbox"][1])
    out = {}
    for i, first in enumerate(spans):
        for second in spans[i + 1:]:
            if second["bbox"][1] >= first["bbox"][3]:
                break
            if first["text"] == second["text"] or not boxes_meet(first["bbox"], second["bbox"]):
                continue
            shorter, longer = sorted((first, second), key=lambda span: len(span["glyphs"]))
            covered = sum(1 for glyph in shorter["glyphs"]
                          if any(overlap_share(glyph, other) > OVERPRINT_FRACTION for other in longer["glyphs"]))
            if covered > OVERPRINT_FRACTION * len(shorter["glyphs"]):
                out[id(first)] = first["bbox"]
                out[id(second)] = second["bbox"]
    return list(out.values())


def boxes_meet(a, b):
    return min(a[2], b[2]) > max(a[0], b[0]) and min(a[3], b[3]) > max(a[1], b[1])


def overlap_share(a, b):
    """How much of the smaller of two boxes the other one covers, from 0 to 1."""
    width = min(a[2], b[2]) - max(a[0], b[0])
    height = min(a[3], b[3]) - max(a[1], b[1])
    if width <= 0 or height <= 0:
        return 0.0
    smaller = min((a[2] - a[0]) * (a[3] - a[1]), (b[2] - b[0]) * (b[3] - b[1]))
    return width * height / smaller if smaller > 0 else 0.0


def box_within(box, column, slack=0.5):
    """Does a span's box sit inside a column's box?"""
    x0, y0, x1, y1 = box
    return (x0 >= column["x0"] - slack and x1 <= column["x1"] + slack
            and y0 >= column["y0"] - slack and y1 <= column["y1"] + slack)


def docx_text(path, body_only):
    """Every word in the Word file, as one string.

    `body_only` leaves out `header*.xml` and `footer*.xml`, which is what the
    comparison wants when the bands were lifted into them. Everything else is
    read straight off the XML rather than through python-docx, so table cells,
    text boxes and anything else carrying a `w:t` is counted without having to
    know where it sits.
    """
    parts = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.startswith("word/") or not name.endswith(".xml"):
                continue
            leaf = name[len("word/"):]
            if body_only and (leaf.startswith("header") or leaf.startswith("footer")):
                continue
            if not (leaf == "document.xml" or leaf.startswith(("header", "footer", "footnotes", "endnotes"))):
                continue
            tree = ElementTree.fromstring(archive.read(name))
            for node in tree.iter():
                if node.tag == W_T and node.text:
                    parts.append(node.text)
                elif node.tag in BREAKS:
                    parts.append("\n")
    return "".join(parts)


def code_row_cuts(element, rows, anchor):
    """Where the PDF's lines end inside a code paragraph, or None unless they are all of its text.

    `rows` are one page's lines in reading order and `anchor` the index of one
    known to be in the paragraph. The rows on either side are matched
    outwards, each directly against the last with only whitespace between,
    until one is not there. The result is the paragraph's own text offset of
    every row end but the last, and only when the rows found are the whole of
    the paragraph: a break written into part of it would leave the rest to run
    past the cell on a line of its own, which is what a negative right indent
    does to a line nothing breaks.
    """
    nodes = [node for node in element.iter(qn("w:r")) if node.find(qn("w:t")) is not None]
    raw = "".join(node.find(qn("w:t")).text or "" for node in nodes)

    def words(row):
        return r"\s*".join(re.escape(word) for word in row["text"].split())

    if not words(rows[anchor]):
        return None
    found = re.search(words(rows[anchor]), raw)
    if found is None:
        return None
    start, end = found.start(), found.end()
    ends = [end]
    for index in range(anchor + 1, len(rows)):
        if not words(rows[index]):
            continue
        after = re.compile(r"\s*" + words(rows[index])).match(raw, end)
        if after is None:
            break
        end = after.end()
        ends.append(end)
    for index in range(anchor - 1, -1, -1):
        if not words(rows[index]):
            continue
        before = re.compile("(" + words(rows[index]) + r")\s*$").search(raw, 0, start)
        if before is None:
            break
        start = before.start()
        ends.insert(0, before.end(1))
    if raw[:start].strip() or raw[end:].strip():
        return None
    return ends[:-1]


def overflow_code_rows(document, element, rows, anchor):
    """Give a code paragraph a break at every PDF line end, then let its long line run past the cell.

    The negative right indent that lets a token typst ran off the page stay on
    one line applies to every line of the paragraph, so a paragraph pdf2docx
    wrapped by itself (its lines joined with a space, the way it writes a
    block whose lines fill the width) came out as one line running off the
    page: the appendix panel on page 60 of a 66-page stress report held eleven
    lines, six of them long enough, and Word set them as four, the last three
    of them past the margin and unread. The panel's own pass could not break
    them, because a line pdf2docx had cut was not yet in the paragraph whole
    for it to find. Returns whether the paragraph's lines were all found and
    the indent written.
    """
    cuts = code_row_cuts(element, rows, anchor)
    if cuts is None:
        return False
    if cuts:
        remove_wrapping_breaks(element)
        split_paragraph_at(element, [], raw_cuts=cuts)
    return let_line_overflow(document, element)


def restore_cut_lines(document, lines, shaded=()):
    """Put back the end of a line pdf2docx cut at the page's edge.

    typst cannot break a token with no break in it (a 96-character hash in
    a URL), so it lets the line run into the right margin, and pdf2docx keeps
    only what lies inside its page box: 84 of the 96 characters survived, and
    the text check sent the whole report down the ladder for the twelve. A
    paragraph whose text ends with the first part of such a line gets the
    rest appended to its last run, so the Word file holds the token whole;
    Word then wraps it at the column, which the PDF could not. Returns how
    many lines were completed.

    A line pdf2docx kept whole that still runs past its cell (a token that ends
    a hair inside the page box) is not counted, because nothing was put back,
    but its code paragraph gets the same breaks and indent (`overflow_code_rows`).
    """
    paragraphs = body_paragraphs(document)
    texts = [paragraph_text(p) for p in paragraphs]
    squashed = [compare_squash(t) for t in texts]
    restored = 0
    page_rows = {}
    for line in lines:
        page_rows.setdefault(line.get("page"), []).append(line)
    for line in lines:
        if not line.get("cut"):
            continue
        # The line's place among its page's, which is what the paragraph's own
        # breaks are worked out from (`overflow_code_rows`).
        rows = page_rows[line.get("page")]
        anchor = next(i for i, row in enumerate(rows) if row is line)
        pieces = line["pieces"] or [line["text"]]
        for piece in pieces:
            whole = compare_squash(piece)
            if len(whole) < CUT_LINE_MIN_CHARS:
                continue
            holders = [i for i, s in enumerate(squashed) if whole in s]
            if holders:
                # pdf2docx kept the line whole: its glyphs end a hair inside
                # the page box (611.2 pt of a 612 pt page), so nothing was cut,
                # and the line is still wider than its cell. Word wrapped the
                # last characters of such a token round, a line of one letter
                # that pushed the page 12 pt down.
                for index in holders:
                    if is_code(paragraphs[index], shaded):
                        overflow_code_rows(document, paragraphs[index], rows, anchor)
                continue
            head = whole[:CUT_LINE_HEAD_CHARS]
            for index, s in enumerate(squashed):
                at = s.find(head)
                if at < 0:
                    continue
                # How much of the piece the paragraph carries from there. A
                # shorter token that merely begins like it (a 40-character
                # hash against a 96-character one) matches less than most of
                # it and is somebody else's line.
                count = 0
                while count < len(whole) and at + count < len(s) and s[at + count] == whole[count]:
                    count += 1
                if count < max(CUT_LINE_HEAD_CHARS, int(CUT_LINE_KEPT_FRACTION * len(whole))) or count >= len(whole):
                    continue
                # The rest of the raw text, from where the kept characters end.
                raw = piece.strip()
                seen = 0
                tail = ""
                for position, char in enumerate(raw):
                    if compare_squash(char):
                        seen += 1
                    if seen == count:
                        tail = raw[position + 1:]
                        break
                if not tail.strip():
                    continue
                if not insert_text_at(paragraphs[index], at + count, tail):
                    continue
                squashed[index] = s[:at + count] + compare_squash(tail) + s[at + count:]
                if is_code(paragraphs[index], shaded):
                    # Prose keeps its column: a negative indent is a paragraph
                    # property and would widen every justified line of it.
                    if not overflow_code_rows(document, paragraphs[index], rows, anchor):
                        let_line_overflow(document, paragraphs[index])
                restored += 1
                break
    return restored


def insert_text_at(element, offset, tail):
    """Insert `tail` into a paragraph's text where `offset` squashed characters end."""
    seen = 0
    for run in element.iter(qn("w:r")):
        node = run.find(qn("w:t"))
        if node is None:
            continue
        raw = node.text or ""
        length = len(compare_squash(raw))
        if offset > seen + length:
            seen += length
            continue
        cut = raw_offset_for(raw, offset - seen)
        if cut is None:
            return False
        node.text = raw[:cut] + tail + raw[cut:]
        node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        return True
    return False


def missing_from_docx(pdf_lines, docx_body_text):
    """PDF lines the Word file does not contain, in order. Empty is the pass.

    A piece of a line is present when its squashed characters appear, in order
    and unbroken, somewhere in the Word file's squashed text. Deleting a line
    is exactly what breaks that: its letters stop being next to each other.
    A piece shorter than COMPARE_MIN_CHARS is not evidence either way, because
    "1." and "LOW" appear all over a report, so it is not looked for.

    Three readings were tried, and the numbers are from the reference report,
    which loses nothing and therefore has to come back clean. Counting words
    reported 62 lines missing, every one a short token such as "1." whose count
    differs because the converter merged two table cells. Matching runs of
    words reported 38, every one a place where the converter's run boundaries
    fall inside text the PDF had spaced differently. Squashed characters per
    line reported 8, all of them two-column table rows the converter writes
    one column at a time. Squashed characters per column report 0, and still
    catch every deletion the tests below make.

    A right-to-left piece of two words or more is also looked for word by
    word (`compare_words`), against the Word text with its whitespace
    collapsed rather than removed. Squashing is blind to a line run together,
    and pdf2docx runs Hebrew and Arabic lines together wherever the space
    between two words was set in another font. Only right-to-left pieces take
    this second test, so a left-to-right line is compared exactly as before.
    """
    haystack = compare_squash(docx_body_text)
    spaced = compare_words(docx_body_text)
    # Presence is not enough: three identical rows of a table against one in
    # the Word file is two rows lost, and a substring test calls it a pass. So
    # each distinct piece has to occur at least as often as the PDF prints it.
    # Occurrences are counted without overlap, which is the reading that
    # matches "how many times does the page show this".
    wanted = Counter()
    wanted_words = Counter()
    for line in pdf_lines:
        for piece in (line["pieces"] or [line["text"]]):
            squashed = compare_squash(piece)
            if len(squashed) >= COMPARE_MIN_CHARS:
                wanted[squashed] += 1
                if takes_word_test(piece):
                    wanted_words[compare_words(piece)] += 1
    have = {piece: haystack.count(piece) for piece in wanted}
    have_words = {piece: spaced.count(piece) for piece in wanted_words}

    missing = []
    for line in pdf_lines:
        raw_pieces = line["pieces"] or [line["text"]]
        pieces = [compare_squash(piece) for piece in raw_pieces]
        looked_for = [p for p in pieces if len(p) >= COMPARE_MIN_CHARS]
        word_pieces = [compare_words(piece) for piece in raw_pieces
                       if len(compare_squash(piece)) >= COMPARE_MIN_CHARS and takes_word_test(piece)]
        if (any(have.get(p, 0) < wanted[p] for p in looked_for)
                or any(have_words.get(p, 0) < wanted_words[p] for p in word_pieces)):
            missing.append(line["text"])
    return missing


def takes_word_test(piece):
    """Is this piece right-to-left with at least one word boundary to keep?"""
    return is_rtl(piece) and len(piece.split()) >= 2


# ── right-to-left text ────────────────────────────────────────────────────
#
# pdf2docx writes a Hebrew or Arabic line as one run per PDF span, in the
# order the spans sit on the page rather than the order they are read in, and
# it drops a span that holds nothing but a space. Typst sets the space between
# two Hebrew words in the document's main font when the Hebrew comes from a
# fallback font, so that space is a span of its own and is lost, and the
# words run together. Where Arabic is set one glyph at a time, PyMuPDF's own
# made-up spaces land inside words instead. Both are repaired here from the
# PDF's logical reading (`page_rows(page, logical=True)`), which is what the
# text check compares against.


def respace(run_texts, pdf_text):
    """The runs of one paragraph with the PDF line's word spaces, and only those.

    The visible characters of the runs have to be the visible characters of
    the PDF line, in the same order; only whitespace is rewritten. Between
    two characters the runs get a space exactly where the PDF has one: a
    missing one is written at the end of the run the word before ends in, so
    no run's formatting is stretched over a new word, and one the PDF does not
    have is taken out. Whitespace before the first character and after the
    last belongs to whatever sits next to the line and is kept. Returns None
    when the characters differ, which is a different line or a re-ordered one,
    and guessing would write spaces into the wrong words.
    """
    def visible(ch):
        return not ch.isspace() and ch not in INVISIBLE_CHARS

    joined = "".join(run_texts)
    owner = [index for index, text in enumerate(run_texts) for _ in text]
    units = [p for p, ch in enumerate(joined) if visible(ch)]
    wanted = []
    gap = None
    for ch in pdf_text:
        if ch.isspace():
            if wanted and gap is None:
                gap = ch
            continue
        if ch in INVISIBLE_CHARS:
            continue
        wanted.append((ch, gap))
        gap = None
    if [joined[p] for p in units] != [ch for ch, _ in wanted]:
        return None
    if not units:
        return list(run_texts)
    first, last = units[0], units[-1]
    unit_at = {p: k for k, p in enumerate(units)}
    out = [[] for _ in run_texts]
    for position, ch in enumerate(joined):
        run = owner[position]
        if ch.isspace() and first < position < last:
            continue
        k = unit_at.get(position)
        if k:
            space = wanted[k][1]
            if space is not None:
                out[owner[units[k - 1]]].append(" " if space in "\r\n\t" else space)
        out[run].append(ch)
    return ["".join(chars) for chars in out]


def direction_chunks(text, rtl_line):
    """A line cut into its right-to-left and left-to-right stretches, in order.

    Spaces and punctuation go with their neighbours when both run the same
    way and with the line's own direction when they sit between the two, so
    the quotes around a Hebrew title in an English sentence stay English.
    Digits count as left-to-right, since a number reads that way wherever it
    stands, so "2.4.1" in a Hebrew line is a stretch of its own.
    """
    kinds = []
    for ch in text:
        kind = unicodedata.bidirectional(ch)
        kinds.append("R" if kind in ("R", "AL") else ("L" if kind in LTR_TOKEN_BIDI else None))
    base = "R" if rtl_line else "L"
    resolved = []
    for index, kind in enumerate(kinds):
        if kind:
            resolved.append(kind)
            continue
        before = next((k for k in reversed(kinds[:index]) if k), None)
        after = next((k for k in kinds[index + 1:] if k), None)
        resolved.append(before if before and before == after else base)
    chunks = []
    for ch, kind in zip(text, resolved):
        if chunks and chunks[-1][0] == kind:
            chunks[-1] = (kind, chunks[-1][1] + ch)
        else:
            chunks.append((kind, ch))
    return chunks


def letters_key(text):
    """The letters of a piece of text regardless of their order."""
    return "".join(sorted(compare_squash(text)))


def plain_text_run(run):
    """The `w:t` of a run that holds its properties and one piece of text only."""
    children = [child for child in run if child.tag != qn("w:rPr")]
    if len(children) == 1 and children[0].tag == W_T:
        return children[0]
    return None


def run_look(run):
    """A run's formatting, as text that compares equal when the formatting does."""
    properties = run.find(qn("w:rPr"))
    return "" if properties is None else str(properties.xml)


# A run marked right-to-left is set in its complex-script size and weight,
# which pdf2docx never writes: Word would fall back to the style's.
CS_TWINS = (("w:sz", "w:szCs"), ("w:b", "w:bCs"), ("w:i", "w:iCs"))


def mark_run_rtl(run):
    """`w:rtl` on a run, with the complex-script twins of its size, bold and italic."""
    properties = run.find(qn("w:rPr"))
    if properties is None:
        properties = OxmlElement("w:rPr")
        run.insert(0, properties)
    for plain, twin in CS_TWINS:
        source = properties.find(qn(plain))
        if source is not None and properties.find(qn(twin)) is None:
            node = OxmlElement(twin)
            for key, value in source.attrib.items():
                node.set(key, value)
            insert_ordered(properties, node, RPR_ORDER)
    if properties.find(qn("w:rtl")) is None:
        insert_ordered(properties, OxmlElement("w:rtl"), RPR_ORDER)


# pdf2docx places a paragraph with left and right indents and an alignment
# read off the page. Word reads both from the paragraph's own start in a
# `w:bidi` paragraph, so they are turned round with it.
MIRRORED_JC = {"left": "right", "right": "left", "start": "end", "end": "start"}


def mark_paragraph_rtl(paragraph):
    """`w:bidi` on a paragraph, with its indents and alignment mirrored to match."""
    properties = paragraph.find(qn("w:pPr"))
    if properties is None:
        properties = OxmlElement("w:pPr")
        paragraph.insert(0, properties)
    if properties.find(qn("w:bidi")) is not None:
        return
    insert_ordered(properties, OxmlElement("w:bidi"), PPR_ORDER)
    indent = properties.find(qn("w:ind"))
    if indent is not None:
        left, right = indent.get(qn("w:left")), indent.get(qn("w:right"))
        for key, value in ((qn("w:left"), right), (qn("w:right"), left)):
            if value is None:
                indent.attrib.pop(key, None)
            else:
                indent.set(key, value)
    align = properties.find(qn("w:jc"))
    if align is not None:
        value = align.get(qn("w:val"))
        align.set(qn("w:val"), MIRRORED_JC.get(value, value))


def rtl_windows(paragraph, by_letters):
    """Stretches of plain runs in a paragraph that hold exactly one PDF piece's letters.

    Each is (runs, piece). A stretch never crosses a break, a tab, a picture
    or a hyperlink boundary; it starts at the first run it can and is as
    short as it can be.
    """
    segments, current, parent = [], [], None
    for run in paragraph.iter(qn("w:r")):
        node = plain_text_run(run)
        if node is None or (current and run.getparent() is not parent):
            if current:
                segments.append(current)
            current = []
        if node is not None:
            current.append(run)
            parent = run.getparent()
    if current:
        segments.append(current)
    longest = max((len(key) for key in by_letters), default=0)
    found = []
    for runs in segments:
        texts = [plain_text_run(run).text or "" for run in runs]
        start = 0
        while start < len(runs):
            letters = ""
            for end in range(start, len(runs)):
                letters += compare_squash(texts[end])
                if len(letters) > longest:
                    break
                window = "".join(texts[start:end + 1])
                pieces = by_letters.get("".join(sorted(letters)))
                if pieces and has_rtl(window) and compare_squash(texts[start]):
                    found.append((runs[start:end + 1], pieces))
                    start = end
                    break
            start += 1
    return found


LTR_TOKEN_BIDI = frozenset(("L", "EN", "AN"))
LTR_TOKEN_JOINERS = frozenset(("CS", "ES", "ET"))


def ltr_tokens(text):
    """The words and numbers in a text that read left to right, each whole.

    A token is a stretch of Latin letters and digits, with the dots, dashes
    and slashes between two of them: "10.0.0.5", "CVE-2026-1234", "SQL".
    """
    tokens, current, pending = [], "", ""
    for ch in text:
        kind = unicodedata.bidirectional(ch)
        if kind in LTR_TOKEN_BIDI:
            current += pending + ch
            pending = ""
        elif kind in LTR_TOKEN_JOINERS and current and not pending and not ch.isspace():
            pending = ch
        else:
            if current:
                tokens.append(current)
            current, pending = "", ""
    if current:
        tokens.append(current)
    return tokens


def reorder_is_safe(texts, piece):
    """May a stretch of runs be rewritten as the piece, in a different order?

    Only when nothing but whole stretches move: the runs and the piece hold
    exactly the same characters, dashes and invisibles included, and every
    English word and every number is the same, unbroken, on both sides. A
    rewrite that passed only the squashed comparison could otherwise drop a
    dash, or write "2.4.1" as "1.4.2" and confirm it against its own
    reference.
    """
    joined = "".join(texts)
    if Counter(ch for ch in joined if not ch.isspace()) != Counter(ch for ch in piece if not ch.isspace()):
        return False
    have = Counter(token for text in texts for token in ltr_tokens(text))
    return have == Counter(ltr_tokens(piece))


def rewrite_window(runs, piece, declined, reorder=True):
    """Give one stretch of runs the PDF piece's text. True when it was rewritten.

    When the runs already hold the piece's characters in order, only their
    whitespace changes and every run keeps its own formatting. When pdf2docx
    wrote them in page order, the piece is written back in reading order, one
    run per right-to-left or left-to-right stretch, each formatted like the
    runs that held that stretch's letters; if those runs disagree about their
    formatting the stretch is left as it is, because there is no telling
    which word was which. `reorder=False` allows the whitespace rewrite only,
    for the last rung, which must not restructure anything.
    """
    nodes = [plain_text_run(run) for run in runs]
    texts = [node.text or "" for node in nodes]
    rebuilt = respace(texts, piece)
    if rebuilt is not None:
        for run, node, value in zip(runs, nodes, rebuilt):
            node.text = value
            node.set(qn("xml:space"), "preserve")
            rtl, ltr = strong_direction(value)
            if rtl and ltr:
                # `w:rtl` lays the whole run out right to left, English
                # included: an English code line holding an Arabic greeting
                # came out as "<script>alert(1)</script>بالعالم مرحبا=comment".
                # Unmarked, Word's own bidi algorithm orders it as the PDF did.
                declined["rtl-mixed-run"] += 1
            elif rtl:
                mark_run_rtl(run)
        return True
    if not reorder:
        declined["rtl-reorder-plain-rung"] += 1
        return False
    if not reorder_is_safe(texts, piece):
        declined["rtl-reorder"] += 1
        return False
    sources = {}
    for run, text in zip(runs, texts):
        rtl, ltr = strong_direction(text)
        for kind, count in (("R", rtl), ("L", ltr or has_number(text))):
            if count:
                sources.setdefault(kind, []).append(run)
    chunks = direction_chunks(piece, is_rtl(piece))
    for kind in {kind for kind, _ in chunks}:
        looks = {run_look(run) for run in sources.get(kind, [])}
        if len(looks) != 1:
            declined["rtl-reorder"] += 1
            return False
    lead = texts[0][: len(texts[0]) - len(texts[0].lstrip())]
    trail = texts[-1][len(texts[-1].rstrip()):]
    anchor = runs[0]
    for index, (kind, value) in enumerate(chunks):
        run = copy.deepcopy(sources[kind][0])
        node = plain_text_run(run)
        if index == 0:
            value = lead + value
        if index == len(chunks) - 1:
            value = value + trail
        node.text = value
        node.set(qn("xml:space"), "preserve")
        if kind == "R":
            mark_run_rtl(run)
        anchor.addprevious(run)
    for run in runs:
        run.getparent().remove(run)
    return True


def restore_rtl(document, rtl_pieces, declined, reorder=True, ambiguous=()):
    """Put right-to-left text back in reading order with its word spaces, and mark it.

    `rtl_pieces` is the PDF's logical reading of every piece that holds a
    right-to-left letter. A stretch of runs holding exactly one piece's
    letters is rewritten to that piece (`rewrite_window`), its right-to-left
    runs get `w:rtl`, and a paragraph that reads right to left gets `w:bidi`.
    Runs that hold no whole piece are left alone, never guessed at: pdf2docx
    sometimes cuts a line into pieces and writes them apart, and a stretch
    that is not a whole piece has nothing to be checked against. A paragraph
    with right-to-left text and nothing rewritten is counted as declined.
    `reorder=False` is the last rung's: whitespace only, no run is moved,
    cloned or deleted, and no paragraph is marked or has its indent or
    alignment turned round; its runs are still marked `w:rtl`.
    `ambiguous` holds the pieces of left-to-right lines whose numbers could
    sit on either side of their right-to-left words (`ambiguous_number`):
    each is declined by name and never looked for, so pdf2docx's text stands
    and the text check judges it. Returns the number of stretches rewritten.
    """
    for _ in ambiguous:
        declined["rtl-ambiguous-number"] += 1
    by_letters = {}
    for piece in rtl_pieces:
        key = letters_key(piece)
        if key:
            by_letters.setdefault(key, set()).add(piece.strip())
    # Two different pieces with the same letters would need a guess.
    by_letters = {key: next(iter(pieces)) for key, pieces in by_letters.items() if len(pieces) == 1}
    repaired = 0
    for paragraph in body_paragraphs(document):
        if not has_rtl(paragraph_text(paragraph)):
            continue
        rewrote = 0
        for runs, piece in rtl_windows(paragraph, by_letters):
            if rewrite_window(runs, piece, declined, reorder):
                rewrote += 1
        if not rewrote:
            declined["rtl-respace"] += 1
            continue
        repaired += rewrote
        # The mark moves the paragraph: Word reads its indents and alignment
        # from the other edge, so they are mirrored with it. The last rung
        # moves nothing, so it leaves the paragraph's properties alone.
        if reorder and is_rtl(paragraph_text(paragraph)):
            mark_paragraph_rtl(paragraph)
    return repaired


# ── the run ───────────────────────────────────────────────────────────────


def stream_tables_in_page_order(original, declined=None):
    """pdf2docx's borderless-table step, with the page's blocks in page order.

    For each borderless table it finds, pdf2docx takes the table's top edge
    from "the block just above it", found by walking the page's blocks until
    one starts below the table. That walk assumes the list runs top to bottom,
    and it does not: the page's lines come first and the bordered tables it
    has already built are appended after them. So for a footer in two pieces,
    which pdf2docx reads as a borderless table, the block just above was
    whichever bordered table came last in the list, however far up the page.
    The borderless table then reached up to the nearest box border, was cut
    into two columns where the footer's pieces sit, and every prose line in
    between lost the words that crossed the cut (the corpus findings report
    lost nine lines, at every rung). Sorting the blocks first gives the walk
    the order it was written for.

    It applies on every rung, the last one included. A pdf2docx whose blocks
    no longer sort this way (a renamed attribute, a bbox that is not a pair of
    numbers) gets its own step unchanged, as if nothing were patched, and
    each such call is counted in `declined` as `page-order-fallthrough`, so a
    pdf2docx upgrade that turns the fix off shows in result.json.
    """
    def stream_tables(self, *args, **kwargs):
        blocks = getattr(self, "_blocks", None)
        in_order = False
        if blocks is not None:
            try:
                blocks.reset(sorted(blocks, key=lambda block: (block.bbox.y0, block.bbox.x0)))
                in_order = True
            except (AttributeError, TypeError):
                pass
        if not in_order and declined is not None:
            declined["page-order-fallthrough"] += 1
        restore = carry_cells_across_rows(self, declined)
        try:
            return original(self, *args, **kwargs)
        finally:
            restore()
    return stream_tables


def same_char(own, near):
    """Is `own` the character `near` (the very object, or a copy pdf2docx made of it)?

    A cell that holds a span's whole box is given a deep copy of it
    (`TextSpan.intersects` returns `self.copy()`), so its characters are new
    objects and an identity test finds no carrier for a character left out next
    to them: it was counted `orphan-chars-unplaced` and lost (round-3 wrappers
    review, finding 4). A copy has the same character and the same box.
    """
    if own is near:
        return True
    try:
        return own.c == near.c and tuple(own.bbox) == tuple(near.bbox)
    except (AttributeError, TypeError):
        return False


def in_column_of(char, cell):
    """May a character left out of a cut line join `cell`: does it stand inside that cell's column?

    PyMuPDF can read one line across two cells, and when the second cell's
    characters are cut by sliver rows they used to be put after the first
    cell's last one, in the neighbour's column, which the squashed text check
    passes (round-3 wrappers review, finding 5). Such a character is left out
    instead, so the check names it and the ladder runs. The test is the
    column, not a distance: the text of two cells can stand an em apart (two
    5 pt insets at 10 pt), and two zero-width letters of a ligature as far as
    a letter apart; a letter's centre is in its own cell either way.
    """
    middle = (char.bbox.x0 + char.bbox.x1) / 2.0
    return cell.bbox.x0 - ORPHAN_COLUMN_SLACK_PT <= middle <= cell.bbox.x1 + ORPHAN_COLUMN_SLACK_PT


# Rounding room at a cell's side, where a glyph's box can stand a fraction past
# the edge pdf2docx gave the cell.
ORPHAN_COLUMN_SLACK_PT = 1.0


def straddling_lines_keep_their_chars(original, declined=None):
    """pdf2docx's hand-over of a table's text lines to its cells, with no character left behind.

    A line goes to the cell that holds at least 0.75 of it, and otherwise is
    cut up character by character: a character goes to a cell that holds half
    of the smaller of the two boxes, and a character no cell holds half of goes
    nowhere, with no trace in the result. That happens whenever the grid of a
    borderless table puts a row edge through the middle of a line, which it
    does when two things side by side have different baselines (a card beside
    a table of striped rows: the card's value line, 10.6 pt high, met edges at
    141.0, 146.3 and 151.0, and each cell held under half of it, so the line
    was gone). It also happens to a zero-width character wherever the line is
    cut at all: a `fi` ligature reads as an `f` and an `i` with no width, the
    cell test needs an intersection of positive area, and "infinitum" came out
    "infnitum". Design-b2 lost 26 lines this way once its running header was
    taken out of the page, because the header had been giving the table a
    different grid.

    The characters nobody took are given back after the original has run: a
    line no cell took at all goes whole to the cell it overlaps most, and a
    character left out of a line that was cut goes after the character before
    it (before the next one, for the first), in the cell and the run that
    character went to. It is the same text in the same order, and it never
    takes a character from a cell that had it. A pdf2docx whose cells or
    lines no longer look like this gets its own hand-over untouched, counted
    in `declined` as `orphan-chars-fallthrough`.
    """
    try:
        from pdf2docx.common import constants
        from pdf2docx.text.Line import Line
        from pdf2docx.text.TextSpan import TextSpan
    except ImportError:  # pragma: no cover - a pdf2docx that lays its text out some other way
        return original

    def holds(cell, span, char):
        """Does the original hand-over give this character to this cell?"""
        if cell.bbox.contains(span.bbox):
            return True
        if not cell.bbox.intersects(span.bbox):
            return False
        return bool(char.get_main_bbox(cell.bbox, constants.FACTOR_A_HALF))

    def holder(cell, char):
        """The span of a line in `cell` that carries this very character, or None."""
        for block in cell.blocks:
            for span in getattr(block, "spans", ()):
                if any(same_char(own, char) for own in span.chars):
                    return span
        return None

    def give_back(table, line):
        cells = [cell for row in table._rows for cell in row if cell and cell.bbox.intersects(line.bbox)]
        if not cells or any(cell.contains(line, threshold=constants.FACTOR_MAJOR) for cell in cells):
            return
        placed = []  # per character, in order: its cell, or None
        for span in line.spans:
            if not isinstance(span, TextSpan):
                continue
            for char in span.chars:
                placed.append((span, char, next((cell for cell in cells if holds(cell, span, char)), None)))
        if all(cell is not None for _, _, cell in placed):
            return
        if all(cell is None for _, _, cell in placed):
            # Nothing of it went anywhere: the whole line, to the cell it overlaps most.
            best = max(cells, key=lambda cell: (cell.bbox & line.bbox).get_area())
            best.blocks.append(line.copy())
            return
        for index, (span, char, cell) in enumerate(placed):
            if cell is not None:
                continue
            before = [item for item in placed[:index] if item[2] is not None]
            after = [item for item in placed[index + 1:] if item[2] is not None]
            if before:
                _, near, home = before[-1]
                after_it = True
            else:
                _, near, home = after[0]
                after_it = False
            if not in_column_of(char, home):
                if declined is not None:
                    declined["orphan-chars-other-column"] += 1
                continue
            carrier = holder(home, near)
            if carrier is None:
                if declined is not None:
                    declined["orphan-chars-unplaced"] += 1
                continue
            at = next(i for i, own in enumerate(carrier.chars) if same_char(own, near))
            carrier.chars.insert(at + 1 if after_it else at, char)
            carrier.union_bbox(char)
            # The next character left out follows this one: `ffi` is an `f`
            # and two zero-width characters, and each belongs after the last.
            placed[index] = (span, char, home)

    def assign_blocks(self, blocks):
        original(self, blocks)
        try:
            for block in blocks:
                if isinstance(block, Line):
                    give_back(self, block)
        except (AttributeError, TypeError, ValueError, StopIteration):
            if declined is not None:
                declined["orphan-chars-fallthrough"] += 1
        try:
            lines_keep_one_cell(self)
        except (AttributeError, TypeError, ValueError, IndexError):
            if declined is not None:
                declined["split-cells-fallthrough"] += 1
    return assign_blocks


SPLIT_LINE_PT = 1.0
# Across an edge the grid draws a rule on, a line must reach this far into the
# empty cell before the two become one: a tight ruled cell's line box overflows
# by its ascender and descender, 1.4 to 1.5 pt (the round-3 review's probes),
# while the card lines a stripe's edges cut on design-b2 reached 2.1, 4.0 and
# 5.6 pt.
SPLIT_RULED_LINE_PT = 2.0
"""How far a line may reach past its cell into an empty neighbour before the two are one cell.

Measured on design-b2's quick-facts card: a line box is 9.5 to 10.6 pt high and
the lines stand 9.3 to 9.9 pt apart, so a line reaches 0.3 to 0.8 pt into its
neighbours with no harm (a cell is allowed that much), while a table edge
through the middle of a line puts 2.1, 4.0 and 5.6 pt of it in the cell
beside. One point sits between the two groups."""


def lines_keep_one_cell(table):
    """Merge a cell with the empty cell its text reaches into, so a line sits in one cell.

    A borderless table's grid has every row edge of every column in it, so a
    card beside a table of striped rows is cut at the stripes' edges as well
    as at its own: on design-b2 the card's `T1190` line (10.6 pt high) stands
    in a 5.3 pt row, with a 4.7 pt empty row under it, then `OWNER`. Word
    clips an exact row at its edge (the lines above it came out with their
    lower halves cut) and `relax_overfull_rows` lets a row it cannot clip grow
    (the table grew 7.5 pt, 12.8 at its foot), on four pages of that report.
    The PDF has no such rows. The card's own rows are the ones its lines make,
    and a line stands whole in one of them.

    A cell whose text reaches more than `SPLIT_LINE_PT` into the cell above or
    below is merged with it when that cell is empty, has the same width and
    fill, and is not already part of a taller one; a cell that holds a line of
    its own is never merged, and the merge is repeated while the text still
    reaches out. The merged cell keeps the top edge of the upper cell and the
    bottom edge of the lower one, since the rule between them is the stripes'
    and was never the card's. Cells with a column span merge the same way,
    and only with a cell of the same span.
    """
    from pdf2docx.table.Cell import Cell
    rows = table._rows
    count = len(rows)
    if not count:
        return

    def usable(cell):
        return bool(cell) and cell.merged_cells[0] >= 1

    def joins(cell, other, reach):
        if not usable(other) or len(other.blocks):
            return False
        if other.merged_cells[1] != cell.merged_cells[1] or other.bg_color != cell.bg_color:
            return False
        # Across a rule only for a real cut: in a ruled table's tight cell a
        # line box reaches 1.4 to 1.5 pt into the empty cell beside it (its
        # ascender and descender), and a merge took away the rule between two
        # hosts' rows. The grid can draw a neighbour's rule across a card's
        # column too (design-b2), where the card's lines were cut 2.1 to 5.6 pt.
        upper, lower = (other, cell) if other.bbox.y1 <= cell.bbox.y0 + 0.5 else (cell, other)
        ruled = (upper.border_width[2] or 0) > 0 or (lower.border_width[0] or 0) > 0
        if ruled and reach < SPLIT_RULED_LINE_PT:
            return False
        return abs(other.bbox.x0 - cell.bbox.x0) < 0.5 and abs(other.bbox.x1 - cell.bbox.x1) < 0.5

    def fuse(upper, lower, target):
        """Make `target` (one of the two) stand for both; the other becomes a placeholder."""
        n_rows = upper.merged_cells[0] + lower.merged_cells[0]
        widths = (upper.border_width[0], upper.border_width[1], lower.border_width[2], upper.border_width[3])
        colours = (upper.border_color[0], upper.border_color[1], lower.border_color[2], upper.border_color[3])
        box = upper.bbox | lower.bbox
        if target is lower:
            for block in list(lower.blocks):
                upper.blocks.append(block)
            target = upper
        target.merged_cells = (n_rows, upper.merged_cells[1])
        target.border_width, target.border_color = widths, colours
        target.update_bbox(box)

    for j in range(table.num_cols):
        i = 0
        while i < count:
            cell = rows[i][j]
            if not usable(cell) or not len(cell.blocks):
                i += 1
                continue
            top = min(block.bbox.y0 for block in cell.blocks)
            bottom = max(block.bbox.y1 for block in cell.blocks)
            while i > 0 and cell.bbox.y0 - top > SPLIT_LINE_PT:
                above = rows[i - 1][j]
                if not joins(cell, above, cell.bbox.y0 - top) or abs(above.bbox.y1 - cell.bbox.y0) > 0.5:
                    break
                fuse(above, cell, cell)
                rows[i]._cells._instances[j] = Cell()
                cell = above
                i -= 1
            while True:
                below_at = i + cell.merged_cells[0]
                if below_at >= count or bottom - cell.bbox.y1 <= SPLIT_LINE_PT:
                    break
                below = rows[below_at][j]
                if not joins(cell, below, bottom - cell.bbox.y1) or abs(below.bbox.y0 - cell.bbox.y1) > 0.5:
                    break
                fuse(cell, below, cell)
                rows[below_at]._cells._instances[j] = Cell()
            i += cell.merged_cells[0]


CELL_EDGE_GAP = 0.5
"""How far apart two filled rectangles' touching edges may sit, in points.

pdf2docx's own merge treats rectangles as touching within half a point
(`TINY_DIST`), and typst draws neighbouring cells' fills from the same
coordinate, so the measured gap on the reference reports is 0.0 to 0.1."""


def spans_keep_inner_blanks(original, text_span, image_span, declined=None):
    """pdf2docx's span restore, keeping a blank span that sits between text.

    Typst draws the space between two differently coloured tokens as a span
    of its own that holds only the space (the CPTC listing `[001] [-] foxtrot`
    comes out of PyMuPDF as `[001]`, ` `, `[`, `-`, `]`, ` foxtrot`). pdf2docx
    sets any span whose text is blank and that carries no underline or
    highlight to None as it restores a line, so the space is gone before any
    pass here runs: `[001][-] foxtrot`, `defprobe(host, port):`,
    `kali@pt~/hfg$nmap`. Raw pdf2docx does the same, so the ladder cannot
    help, and the text check squashes whitespace, so it never noticed. Measured
    on the stress reports before this: 72 of 880 code lines in shape-b, 7 in
    shape-f, 10 in design a2, 14 in b1, 16 in b2.

    A blank span is kept when a span that holds text (or a picture) comes
    before it in the same line and another comes after it. A leading or
    trailing blank span is dropped as before, so `restore_leading_spaces` and
    the line's own strip see what they always saw, and a blank span with a
    style is kept as pdf2docx keeps it. A pdf2docx whose spans no longer
    build this way (a renamed class, a raw span it cannot read) gets its own
    method unchanged, counted in `declined` as `spaces-fallthrough`, so an
    upgrade that turns the fix off shows in result.json.
    """
    def restore(self, raws):
        try:
            built = [image_span(raw) if "image" in raw else text_span(raw) for raw in raws]
            holds = [not isinstance(span, text_span) or bool(span.text.strip()) for span in built]
            first = holds.index(True) if True in holds else len(built)
            last = len(built) - 1 - holds[::-1].index(True) if True in holds else -1
            kept = []
            for index, span in enumerate(built):
                blank = isinstance(span, text_span) and not span.text.strip() and not span.style
                kept.append(None if blank and not first < index < last else span)
        except (AttributeError, TypeError, KeyError, ValueError):
            if declined is not None:
                declined["spaces-fallthrough"] += 1
            return original(self, raws)
        for span in kept:
            self.append(span)
        return self
    return restore


def lines_reach_their_tab_stop(original, minor_dist, declined=None):
    """pdf2docx's tab-stop step, with each line's offset rounded the way its stop was.

    pdf2docx places the lines of a block it cannot align (an outline whose
    items stand at five indents) with tabs: a left stop at every line's
    offset from the block's edge, rounded to 0.1 pt, and before each line as
    many tabs as there are stops at or left of its offset. That offset was
    compared unrounded, and pdf2docx's edges are themselves rounded to 0.1 pt,
    so their difference can miss a stop by a float's hair: a2's level-two
    items stood 81.3 - 65.5 = 15.799999999999997 pt in, short of their own
    stop at 15.8, were given no tab and started at the level-one edge, while
    the deeper levels happened to round up. Measured over the loop's
    documents: 105 lines of a2, 57 of a1, 25 of b2, 10 of verbose-a (its
    wrapped "tempor." at 68.3). Here the offset is rounded as the stops were,
    so a line always reaches its own stop.

    Once every line reaches its stop, a second fault shows: items of one
    level whose markers start 0.1 to 0.3 pt apart ("a." at 88.3, "b." at 88.1
    on a1, the glyphs' side bearings) are two stops that far apart, and a line
    that crosses both takes a tab for a 0.2 pt step, which Word draws 3.6 to
    3.9 pt wide (three "a." lines of a1 moved from inside the 2.5 pt tolerance
    to +3.6..+3.9). Stops closer together than `minor_dist` (pdf2docx's own
    "small distance", 1 pt) are therefore one stop, the lowest. On a1 that
    leaves 22 lines off the PDF's start where raw pdf2docx has 29 and the
    stops alone 26. Nothing else differs from pdf2docx's step. A block that
    cannot be read this way gets pdf2docx's own method, counted in `declined`
    as `tabs-fallthrough`.
    """
    def parse_tab_stop(self, line_separate_threshold):
        try:
            block = self.parent
            idx0, idx1 = (0, 2) if block.is_horizontal_text else (3, 1)
            lines = list(self._instances)
            left = block.bbox[idx0]
            offsets = {round(abs(line.bbox[idx0] - left), 1) for line in lines}
        except (AttributeError, TypeError, KeyError, IndexError, ValueError):
            if declined is not None:
                declined["tabs-fallthrough"] += 1
            return original(self, line_separate_threshold)
        stops = []
        for offset in sorted(offset for offset in offsets if offset >= minor_dist):
            if not stops or offset - stops[-1] >= minor_dist:
                stops.append(offset)
        block.tab_stops = stops
        if not stops:
            return None

        def tab_position(position):
            offset = round(position - left, 1)
            return sum(1 for stop in stops if offset >= stop)

        ref = left
        for index, line in enumerate(lines):
            if line.bbox[idx0] - ref > line_separate_threshold:
                line.tab_stop = tab_position(line.bbox[idx0]) - tab_position(ref)
            if index == len(lines) - 1:
                break
            ref = line.bbox[idx1] if line.in_same_row(lines[index + 1]) else left
        return None
    return parse_tab_stop


CELL_EDGE_GAP = 0.5
"""How far apart two filled rectangles' touching edges may sit, in points.

pdf2docx's own merge treats rectangles as touching within half a point
(`TINY_DIST`), and typst draws neighbouring cells' fills from the same
coordinate, so the measured gap on the reference reports is 0.0 to 0.1."""


def touching_cells(rects):
    """Pairs of boxes that meet side by side: [(left, right, top, bottom)].

    `rects` are (x0, y0, x1, y1) boxes in pdf2docx's page coordinates. One box
    ends where another begins (within CELL_EDGE_GAP) and the two share part of
    their height (`top` to `bottom`): that is the boundary between two cells
    of one row.
    """
    # A box can only meet one that starts within half a point of where it ends,
    # so boxes are filed by where they start and each looks in three files. A
    # long report has tables of hundreds of cells, and comparing every pair is
    # the quadratic cost this avoids.
    starts = {}
    for box in rects:
        starts.setdefault(int(box[0] // CELL_EDGE_GAP), []).append(box)
    pairs = []
    for left in rects:
        key = int(left[2] // CELL_EDGE_GAP)
        for file in (key - 1, key, key + 1):
            for right in starts.get(file, ()):
                if left is right or abs(left[2] - right[0]) > CELL_EDGE_GAP:
                    continue
                top, bottom = max(left[1], right[1]), min(left[3], right[3])
                if bottom - top >= 1.0:
                    pairs.append((left, right, top, bottom))
    return pairs


def abutting_fill_edges(rects):
    """Cell edges a row of filled rectangles proves: [{x, rows, low, high}] by x.

    Each touching pair (`touching_cells`) votes for the x where it meets.
    Rows are counted by pair, so a column of ten stripes votes ten times for
    the edge they share.
    """
    clusters = []
    for x, top, bottom in sorted(((left[2] + right[0]) / 2.0, top, bottom)
                                 for left, right, top, bottom in touching_cells(rects)):
        if clusters and x - clusters[-1]["x"] <= CELL_EDGE_GAP:
            near = clusters[-1]
            near["rows"] += 1
            near["low"], near["high"] = min(near["low"], top), max(near["high"], bottom)
        else:
            clusters.append({"x": x, "rows": 1, "low": top, "high": bottom})
    return clusters


def row_cell_boxes(rects):
    """Filled boxes that are one cell of a row of cells: [(x0, y0, x1, y1)].

    A cell of a table drawn with fills meets a neighbour side by side
    (`touching_cells`) and has the neighbour's top and bottom, since typst
    sizes every cell of a row to the row. A callout beside a sidebar meets its
    neighbour too, but is rarely the same height, which is what keeps it out.
    """
    cells = []
    seen = set()
    for left, right, _, _ in touching_cells(rects):
        if abs(left[1] - right[1]) > CELL_EDGE_GAP or abs(left[3] - right[3]) > CELL_EDGE_GAP:
            continue
        for box in (left, right):
            if box not in seen:
                seen.add(box)
                cells.append(box)
    return cells + unfilled_row_cells(cells)


def unfilled_row_cells(cells):
    """The cells of a row with no fill of its own, proven by the filled rows around it.

    The usual stripe is `fill: (_, y) => if calc.odd(y) { grey }`, so every
    other row has no rectangle at all and a line break in one of its cells
    would prove nothing. Its cells are still bounded: in each column the cell
    above ends where the row begins and the cell below begins where it ends,
    both with the column's own edges. A gap between two cells of one column
    that the same rows of at least two columns share is one row of cells with
    no fill, and its boxes are returned.
    """
    columns = []
    for box in sorted(cells):
        for column in columns:
            if abs(column[0][0] - box[0]) <= CELL_EDGE_GAP and abs(column[0][2] - box[2]) <= CELL_EDGE_GAP:
                column.append(box)
                break
        else:
            columns.append([box])
    rows = {}
    for index, column in enumerate(columns):
        column.sort(key=lambda box: box[1])
        for above, below in zip(column, column[1:]):
            if below[1] - above[3] > CELL_EDGE_GAP:
                rows.setdefault((round(above[3] * 2), round(below[1] * 2)), {})[index] = (
                    above[0], above[3], above[2], below[1])
    found = []
    for gap in rows.values():
        if len(gap) >= 2:
            found.extend(gap.values())
    return found


def rows_continuing_cells(rows, cells):
    """Indexes of the one-block rows that carry on a cell of the row above.

    `rows` is one list of block boxes per row of text, top to bottom, and
    `cells` the boxes of `row_cell_boxes`. A row is a continuation when it has
    one block, the row above is part of a table and one cell box holds the new
    block together with one of the blocks above (`sits_under`: on its edge or
    centre, a line gap below): the second line of a cell that wraps or has a
    line break in it. A paragraph between two tables of the same columns lies
    in the gap `unfilled_row_cells` takes for a row of cells, and used to be
    carried into the table above, which joined the two tables into one (a
    3 + 4 + 3 column run of notes became one table of twelve rows). A row is
    part of a table when two or
    more of its blocks each sit in a cell, or when it is a continuation
    itself. One block in a cell is not enough: a card with a narrow accent bar
    beside it makes a pair of equal-height boxes too, and its first line of
    text sits in the card alone.
    """
    def inside(box, cell):
        return (cell[0] - CELL_EDGE_GAP <= box[0] and cell[1] - CELL_EDGE_GAP <= box[1]
                and box[2] <= cell[2] + CELL_EDGE_GAP and box[3] <= cell[3] + CELL_EDGE_GAP)

    carried = set()
    for index in range(1, len(rows)):
        if len(rows[index]) != 1:
            continue
        above = rows[index - 1]
        if (index - 1) not in carried and sum(any(inside(box, cell) for cell in cells) for box in above) < 2:
            continue
        for cell in cells:
            if inside(rows[index][0], cell) and any(
                    inside(box, cell) and sits_under(rows[index][0], box) for box in above):
                carried.add(index)
                break
    return carried


CARRY_ALIGN_PT = 1.0
"""How far off a line's left edge, centre or right edge may be from the line above it in one cell.

Typst sets every line of a cell on one edge (or one centre), so the lines of
a wrapped cell agree to the rounding of the PDF, 0.0 to 0.1 pt in the striped
reports. A paragraph between two tables stands on the column's own edge, which
is the cell's inset (5 pt in typst's default) left of the cell's text."""

CARRY_GAP_RATIO = 1.5
"""The most a line may stand below the one above it, as a fraction of its own height, and still be its cell's next line.

Two lines of one cell stand 0 to 1.5 pt apart (the boxes touch), a paragraph
break inside a cell about half a line (6.5 pt of 13.6 at 10 pt) and up to 0.92
of one under `par(spacing: 1.8em)`, so the gap cannot tell a cell's next
paragraph from a note between two tables (0.9 of a line): it only refuses a
line well below, and the edge test does the rest."""


def sits_under(block, above):
    """Is `block` the next line of the cell `above` is in: not left of its text, within a line and a half below it?

    A paragraph between two tables of the same columns stands on the column's
    own edge, a cell's inset left of the text in the cell above (56.7 against
    61.7 on the review's probe), and that is the one shape refused: a cell's
    next line may be right-aligned, centred or indented under the line above
    (a reference, a score, a nested list), which an alignment test split into
    a second table with the line between them as body text.
    """
    if block[0] < above[0] - CARRY_ALIGN_PT:
        return False
    return block[1] - above[3] <= CARRY_GAP_RATIO * (block[3] - block[1])


def carry_cells_across_rows(layout, declined=None):
    """Makes pdf2docx's row walk keep a cell's second line in the table.

    `Blocks.collect_stream_lines` closes the table it is gathering at every
    row that has a single block, because one block per row is how it
    recognises flowing text. The second line of a cell with a line break in it
    is such a row, so the table was cut between a cell's two lines: the first
    line stayed in the table, the second began another one if the fill behind
    it was not white (the check that lets a shaded row stay in a table
    excludes white on purpose) and fell out into the body if it was. On a
    striped host table the second service then sat in a paragraph between two
    tables, and with a row span it landed in the next host's row. The fills
    say the two lines share a cell, so the row walk is told so: the rows
    `rows_continuing_cells` names report that they are not flow layout.

    Installs the marking on `layout`'s blocks for the duration of one
    `stream_tables` call and returns the function that takes it off again. A
    pdf2docx whose objects no longer answer to these names gets its own walk,
    counted in `declined` as `cell-rows-fallthrough`.
    """
    try:
        blocks = layout._blocks
        rects = []
        for fill in layout._shapes.table_fillings:
            parts = getattr(fill, "_btct_parts", None)
            rects.extend(parts if parts else [tuple(fill.bbox)])
        cells = row_cell_boxes(rects)
        real = blocks.group_by_rows
    except (AttributeError, TypeError, ValueError):
        if declined is not None:
            declined["cell-rows-fallthrough"] += 1
        return lambda: None
    if not cells:
        return lambda: None

    def group_by_rows(*args, **kwargs):
        rows = real(*args, **kwargs)
        try:
            boxes = [[tuple(block.bbox) for block in row] for row in rows]
            for index in rows_continuing_cells(boxes, cells):
                rows[index].is_flow_layout = lambda *a, **k: False
        except (AttributeError, TypeError, ValueError):
            if declined is not None:
                declined["cell-rows-fallthrough"] += 1
        return rows

    blocks.group_by_rows = group_by_rows

    def restore():
        blocks.__dict__.pop("group_by_rows", None)
    return restore


def borders_follow_cell_edges(original_finalize, original_by_strokes, declined=None):
    """pdf2docx's borderless-table borders, placed on the PDF's cell edges.

    A stream table has no ruled lines, so pdf2docx puts each vertical border
    in the gap between two columns of text: first at an edge the page's filled
    rectangles prove, failing that at the middle of the gap. The first never
    happens for cells filled row by row, because `Shapes._merge_shapes` has
    already fused a row of same-coloured cells into one rectangle across the
    table, and a rectangle that spans the table proves no inner edge. The
    borders then sit mid-gap: on the reference report's host index the fourth
    column came out 133 pt wide against the PDF's 174.6 and the fifth 78
    against 34.3, so every zebra stripe Word drew was the wrong width (281 of
    773 fills unmatched on a report whose running header was already out of
    the table).

    The merge now keeps the boxes it fused (`merged_fills_keep_parts`). Just
    before pdf2docx lets the page's fills place borders (its second use of
    `_finalize_by_strokes`, after explicit ruled lines have had theirs), each
    vertical border that is still free takes the edge between two touching
    cells that falls inside its gap and is voted for by the most rows. A gap
    with no such edge is left to pdf2docx, so a table with no filled cells, or
    cells that do not touch, comes out exactly as before.

    The same cells answer a second question. A cell of two lines has a gap
    between them, and pdf2docx reads a gap between two lines of one column as
    a row boundary, so the stripe was cut in two rows and Word shaded each
    half (a 116 pt cell of 26.8 pt came out as 13.1 and 13.7). When a cell
    that touches its neighbour contains the whole gap, that border becomes a
    reference line only: the lines stay together in one cell and the other
    cells of the row span both.
    """
    def finalize(self, strokes, fills):
        self._btct_edge_state = [strokes, fills, False]
        try:
            return original_finalize(self, strokes, fills)
        finally:
            self._btct_edge_state = None

    def by_strokes(self, strokes):
        state = getattr(self, "_btct_edge_state", None)
        if state is not None and not state[2] and strokes is not state[0]:
            state[2] = True
            try:
                place_borders_on_cell_edges(self, state[1])
            except (AttributeError, TypeError, ValueError):
                if declined is not None:
                    declined["cell-edges-fallthrough"] += 1
        return original_by_strokes(self, strokes)

    return finalize, by_strokes


def place_borders_on_cell_edges(borders, fills):
    """Pin each free inner vertical border to the busiest cell edge in its gap,
    and stop a row border from cutting a cell the fills prove is one box."""
    rects = []
    for fill in fills:
        parts = getattr(fill, "_btct_parts", None)
        rects.extend(parts if parts else [tuple(fill.bbox)])
    pairs = touching_cells(rects)
    if not pairs:
        return
    clusters = abutting_fill_edges(rects)
    cells = {box for left, right, _, _ in pairs for box in (left, right)}
    has_right = {left for left, _, _, _ in pairs}
    has_left = {right for _, right, _, _ in pairs}
    for border in list(borders._instances):
        if border.finalized and border.border_type in ("VL", "VR"):
            continue
        if border.border_type in ("VL", "VR"):
            # The table's own side: the edge most rows of cells end on. A band
            # that runs to the page edge above the table is one row, and the
            # first fill pdf2docx met used to decide, which made the last
            # column of a glossary 439 pt wide instead of 266.
            left_side = border.border_type == "VL"
            votes = {}
            for box in rects:
                if box in (has_left if left_side else has_right):
                    continue
                x = box[0] if left_side else box[2]
                if border.is_valid(x):
                    key = round(x / CELL_EDGE_GAP)
                    votes.setdefault(key, []).append(x)
            ranked = sorted(votes.values(), key=len, reverse=True)
            if ranked and len(ranked[0]) >= 2 and (len(ranked) == 1 or len(ranked[0]) > len(ranked[1])):
                border.finalize_by_value(sum(ranked[0]) / len(ranked[0]))
            continue
        if border.finalized or border.border_type not in ("VI", "HI"):
            continue
        first, second = border.get_boundary_borders()
        if first is None or second is None:
            continue
        if border.is_vertical:
            reach = (first.LRange, second.URange)
            best = None
            for edge in clusters:
                if not border.is_valid(edge["x"]) or edge["high"] < reach[0] or edge["low"] > reach[1]:
                    continue
                if best is None or edge["rows"] > best["rows"]:
                    best = edge
            if best is not None:
                border.finalize_by_value(best["x"])
        elif not border.is_reference and any(
                box[1] - CELL_EDGE_GAP <= border.LRange and border.URange <= box[3] + CELL_EDGE_GAP
                and box[0] - CELL_EDGE_GAP <= first.URange and second.LRange <= box[2] + CELL_EDGE_GAP
                for box in cells):
            # The gap between two lines of text lies inside one cell of a row
            # of cells, so it is a line break in that cell and not a row.
            border.is_reference = True


def merged_fills_keep_parts(original):
    """`Shapes._merge_shapes`, remembering the rectangles it fused.

    Each shape that comes out of the merge and stands for two or more of the
    page's rectangles carries their boxes in `_btct_parts`, copied before the
    merge moves the first one's box. Nothing else about the merge changes.
    """
    def merge(shapes):
        sources = []
        for shape in shapes:
            try:
                if not shape.is_determined:
                    sources.append((shape.color, tuple(shape.bbox)))
            except AttributeError:
                sources = []
                break
        merged = original(shapes)
        for shape in merged:
            try:
                box, color = tuple(shape.bbox), shape.color
            except AttributeError:
                continue
            parts = [part for tint, part in sources
                     if tint == color and part[0] >= box[0] - CELL_EDGE_GAP and part[1] >= box[1] - CELL_EDGE_GAP
                     and part[2] <= box[2] + CELL_EDGE_GAP and part[3] <= box[3] + CELL_EDGE_GAP]
            if len(parts) > 1:
                shape._btct_parts = parts
        return merged
    return staticmethod(merge)


def run_pdf2docx(source, target, plan=None, raw=False, declined=None):
    """pdf2docx, with its own chatter kept off both streams.

    It logs a line per page on the root logger, which it configures itself at
    import time, and it prints the input path while doing so. Neither belongs
    in a server's output, so the level is lowered after the import and stdout
    is pointed at stderr for the call in case anything prints directly.

    It is also told what each face is, when a font file was staged for it.
    Its own answer is the family name in the PDF's embedded copy, found by
    asking whether one name contains the other, and both halves of that go
    wrong on a real report: a reader hands a font name back out of a 24 byte
    field, and a name cut short there stops matching exactly and starts
    matching by containment, so `BtctProbeSansSemiBold-Regular` comes back as
    the family below it. That family is the one Word would then paint a fake
    bold over. Only the name is replaced here; the line height pdf2docx
    measured for the face it chose is left exactly as it was, so nothing on
    the page moves.

    Its borderless-table step also gets its blocks in page order
    (`stream_tables_in_page_order`), and its span restore keeps the blank
    span between two tokens of a line (`spans_keep_inner_blanks`), and its
    hand-over of a table's lines to cells leaves no character out
    (`straddling_lines_keep_their_chars`), and its tab stops count a line's
    own stop as reached (`lines_reach_their_tab_stop`), except for `raw`,
    which is pdf2docx as shipped and the baseline everything else is
    measured against.
    """
    from pdf2docx import Converter
    try:
        from pdf2docx.font.Fonts import Fonts
    except ImportError:  # pragma: no cover - a pdf2docx that names spans some other way
        Fonts = None
    try:
        from pdf2docx.table.TablesConstructor import TablesConstructor
    except ImportError:  # pragma: no cover - a pdf2docx that builds tables some other way
        TablesConstructor = None
    try:
        from pdf2docx.shape.Shapes import Shapes
        from pdf2docx.table.Border import Borders
    except ImportError:  # pragma: no cover - a pdf2docx that places borders some other way
        Shapes = Borders = None
    try:
        from pdf2docx.text.Spans import Spans
        from pdf2docx.text.TextSpan import TextSpan
        from pdf2docx.image.ImageSpan import ImageSpan
    except ImportError:  # pragma: no cover - a pdf2docx that restores spans some other way
        Spans = TextSpan = ImageSpan = None
    try:
        from pdf2docx.table.TableBlock import TableBlock
    except ImportError:  # pragma: no cover - a pdf2docx that hands text to cells some other way
        TableBlock = None
    try:
        from pdf2docx.text.Lines import Lines
        from pdf2docx.common import constants as pdf2docx_constants
    except ImportError:  # pragma: no cover - a pdf2docx that places a block's lines some other way
        Lines = pdf2docx_constants = None

    logging.getLogger().setLevel(logging.ERROR)
    original = Fonts.get if Fonts is not None else None
    original_stream = getattr(TablesConstructor, "stream_tables", None)
    original_restore = getattr(Spans, "restore", None)
    original_assign = getattr(TableBlock, "assign_blocks", None)
    original_tab_stop = getattr(Lines, "parse_tab_stop", None)
    original_merge = Shapes.__dict__.get("_merge_shapes") if Shapes is not None else None
    original_finalize = getattr(Borders, "finalize", None)
    original_by_strokes = getattr(Borders, "_finalize_by_strokes", None)
    follow_cells = (not raw and original_merge is not None and original_finalize is not None
                    and original_by_strokes is not None)

    def named(self, font_name):
        found = original(self, font_name)
        face = fonts.resolve_pdf_font(plan, pdf_base_name(font_name))
        if face is None or not hasattr(found, "_replace"):
            return found
        return found._replace(name=face["family"])

    converter = Converter(source)
    try:
        if original is not None and plan:
            Fonts.get = named
        if original_stream is not None and not raw:
            TablesConstructor.stream_tables = stream_tables_in_page_order(original_stream, declined)
        if original_restore is not None and not raw:
            Spans.restore = spans_keep_inner_blanks(original_restore, TextSpan, ImageSpan, declined)
        if original_assign is not None and not raw:
            TableBlock.assign_blocks = straddling_lines_keep_their_chars(original_assign, declined)
        if original_tab_stop is not None and not raw:
            Lines.parse_tab_stop = lines_reach_their_tab_stop(original_tab_stop, pdf2docx_constants.MINOR_DIST,
                                                              declined)
        if follow_cells:
            Shapes._merge_shapes = merged_fills_keep_parts(original_merge.__func__)
            Borders.finalize, Borders._finalize_by_strokes = borders_follow_cell_edges(
                original_finalize, original_by_strokes, declined)
        with contextlib.redirect_stdout(sys.stderr):
            converter.convert(target)
    finally:
        if original is not None:
            Fonts.get = original
        if original_stream is not None:
            TablesConstructor.stream_tables = original_stream
        if original_restore is not None:
            Spans.restore = original_restore
        if original_assign is not None:
            TableBlock.assign_blocks = original_assign
        if original_tab_stop is not None:
            Lines.parse_tab_stop = original_tab_stop
        if follow_cells:
            Shapes._merge_shapes = original_merge
            Borders.finalize, Borders._finalize_by_strokes = original_finalize, original_by_strokes
        converter.close()


CROWDED_OUT = ("This report is large, so the Word file skips the final layout pass and may sit a "
               "little differently from the PDF.")
PLAIN_LAYOUT = ("Text was missing from the Word file until the layout passes were turned off, so it "
                "carries the converter's own spacing and panels and will sit differently from the PDF.")


def top_level(element, body):
    """The child of `body` that holds `element` (or is it)."""
    while element.getparent() is not body:
        element = element.getparent()
    return element


def starts_a_page(paragraph, anchor):
    """Does Word already begin a page somewhere between `anchor` and this paragraph?

    Both are children of the body, `anchor` first. pdf2docx carries a section
    break in the last paragraph of a section, in its own `w:pPr/w:sectPr`,
    and puts spacers and anchored drawings ahead of a page's first line, so
    the question is asked of everything between the previous page's first line
    and this one rather than of the paragraph just above. A section starts a
    new page unless it says otherwise. A page break that is already there
    counts too.
    """
    element = anchor
    while element is not None and element is not paragraph:
        ppr = element.find(qn("w:pPr")) if element.tag == qn("w:p") else None
        if ppr is not None:
            section = ppr.find(qn("w:sectPr"))
            if section is not None:
                kind = section.find(qn("w:type"))
                if kind is None or kind.get(qn("w:val")) in (None, "nextPage", "oddPage", "evenPage"):
                    return True
            before = ppr.find(qn("w:pageBreakBefore"))
            if element is not anchor and before is not None and before.get(qn("w:val")) not in ("0", "false", "off"):
                return True
        # The anchor's own break is what started its page, not this one.
        if element is not anchor and any(br.get(qn("w:type")) == "page" for br in element.iter(qn("w:br"))):
            return True
        element = element.getnext()
    ppr = paragraph.find(qn("w:pPr"))
    if ppr is not None:
        before = ppr.find(qn("w:pageBreakBefore"))
        if before is not None and before.get(qn("w:val")) not in ("0", "false", "off"):
            return True
    first_run = paragraph.find(qn("w:r"))
    br = None if first_run is None else first_run.find(qn("w:br"))
    return br is not None and br.get(qn("w:type")) == "page"


def word_page_sections(document):
    """How many sections of the body begin a new page."""
    body = document.element.body
    count = 0
    for section in list(body.iter(qn("w:sectPr"))):
        if section.getparent() is not body and section.getparent().tag != qn("w:pPr"):
            continue
        kind = section.find(qn("w:type"))
        if kind is None or kind.get(qn("w:val")) in (None, "nextPage", "oddPage", "evenPage"):
            count += 1
    return count


# The paragraph that carries a section break, and the padding before it.
TAIL_LINE_PT = 1.0
TAIL_SPACER_MAX_PT = 1.05


def blank_spacer(element):
    """An empty paragraph with an exact line of about a point or less."""
    if element.tag != qn("w:p"):
        return False
    if any((node.text or "").strip() for node in element.iter(qn("w:t"))):
        return False
    if any(True for _ in element.iter(qn("w:drawing"))) or any(True for _ in element.iter(qn("w:br"))):
        return False
    metrics = paragraph_metrics(element)
    return metrics is not None and metrics["line"] <= TAIL_SPACER_MAX_PT


# Word's single line spacing, as a multiple of the font size, for a paragraph
# whose line height the file leaves automatic. Fonts differ (1.15 to 1.25 for
# the report faces measured); the low end, because an estimate too short only
# leaves an exact row as it was.
AUTO_LINE_EM = 1.15
# An inline picture stands on the baseline, so its line is the picture plus the
# descent of the paragraph's font below it.
AUTO_DESCENT_EM = 0.22
# The font size assumed for a paragraph that holds only a picture and names no size.
AUTO_FONT_PT = 10.0


def automatic_paragraph_metrics(paragraph):
    """The metrics of a paragraph whose line height is automatic: lines as written, each as tall as its tallest thing.

    `paragraph_metrics` declines such a paragraph, and `cell_content_height`
    then declined the whole cell, so a row holding a picture or a plain
    caption was never measured and an exact row clipped what followed the
    picture with no trace in the file (design-a2: a figure's caption under
    two screenshots side by side). The first line is as tall as the tallest
    inline picture or `AUTO_LINE_EM` of the largest font, every further line
    (one per line break written) as tall as the font. None for a paragraph
    with no size to read and no picture.
    """
    properties = paragraph.find(qn("w:pPr"))
    spacing = properties.find(qn("w:spacing")) if properties is not None else None
    if spacing is not None and spacing.get(qn("w:lineRule")) in ("exact", "atLeast"):
        return None
    before = twips_of(spacing.get(qn("w:before"))) if spacing is not None else None
    after = twips_of(spacing.get(qn("w:after"))) if spacing is not None else None
    sizes = []
    for size in paragraph.iter(qn("w:sz")):
        try:
            sizes.append(float(size.get(qn("w:val"))) / 2.0)
        except (TypeError, ValueError):
            pass
    pictures = [inline_picture_size(run)[1] for run in paragraph.findall(qn("w:r"))
                if inline_picture_size(run) is not None]
    if not sizes and not pictures:
        return None
    size = max(sizes) if sizes else AUTO_FONT_PT
    font = AUTO_LINE_EM * size
    breaks = sum(1 for node in paragraph.iter(qn("w:br"))
                 if (node.get(qn("w:type")) or "textWrapping") == "textWrapping")
    first = max([font] + [height + AUTO_DESCENT_EM * size for height in pictures])
    return {"before": before or 0.0, "after": after or 0.0, "line": first, "lines": 1,
            "extra": breaks * font, "estimated": True}


def cell_content_height(cell, estimated=None):
    """What a cell's blocks add up to in points, or None when the file does not say.

    `estimated`, a list when given, gets True appended when a paragraph's
    height had to be estimated (`automatic_paragraph_metrics`).
    """
    total = cell_margin(cell, "top") + cell_margin(cell, "bottom")
    pending = 0.0
    for child in cell:
        if child.tag == qn("w:p"):
            metrics = paragraph_metrics(child)
            if metrics is None:
                metrics = automatic_paragraph_metrics(child)
                if metrics is not None and estimated is not None:
                    estimated.append(True)
            if metrics is None:
                return None
            total += max(pending, metrics["before"]) + metrics["lines"] * metrics["line"] + metrics.get("extra", 0.0)
            pending = metrics["after"]
        elif child.tag == qn("w:tbl"):
            metrics = table_metrics(child)
            if metrics is None:
                return None
            total += pending + metrics["height"]
            pending = 0.0
    # The spacing after the last block is not content: nothing has to show
    # there, and the panel pass leaves the panel's bottom padding in it.
    return total


# A nested table with nothing in it is a decoration's trace (a sidebar's fill,
# a band) when it is this tall and more than `EMPTY_TABLE_RATIO` times the
# tallest thing beside it in its row.
EMPTY_TABLE_MIN_PT = 100.0
EMPTY_TABLE_RATIO = 2.0


def drop_tall_empty_tables(document):
    """Remove a nested table that holds no text and no picture and is far taller than its row's content.

    A page-height fill beside the text column (design-a1's grey comment
    sidebar, 810.8 pt) comes out of pdf2docx as a second column of the table
    the finding's heading is in, holding a nested table of that height and
    nothing else; Word grows the heading's row to hold it, so the heading
    stood alone on a page and the next page was empty (two extra pages per
    finding). The table draws a fill and nothing a reader needs; the fill
    pass (`restore_page_fills`) draws a page's large plain fills behind the
    text where nothing is printed on them. A table with any text, picture or
    object in it is never removed, nor one that is not much taller than the
    content beside it. Returns how many were removed.
    """
    body = document.element.body
    removed = 0
    for table in list(body.iter(qn("w:tbl"))):
        cell = table.getparent()
        if cell is None or cell.tag != qn("w:tc"):
            continue
        if "".join(node.text or "" for node in table.iter(qn("w:t"))).strip():
            continue
        if any(True for tag in ("w:drawing", "w:pict", "w:object") for _ in table.iter(qn(tag))):
            continue
        metrics = table_metrics(table)
        if metrics is None or metrics["height"] < EMPTY_TABLE_MIN_PT:
            continue
        # A drawn border is a box a reader may need (a signature field, an
        # evidence placeholder), not a fill's trace.
        if any((side.get(qn("w:val")) or "nil") not in ("nil", "none")
               for borders in table.iter(qn("w:tblBorders"), qn("w:tcBorders")) for side in borders):
            continue
        row = cell.getparent()
        beside = [cell_content_height(other) for other in row.findall(qn("w:tc")) if other is not cell]
        beside = [height for height in beside if height is not None]
        if not beside or metrics["height"] <= EMPTY_TABLE_RATIO * max(beside):
            continue
        cell.remove(table)
        if cell.find(qn("w:p")) is None:
            cell.append(OxmlElement("w:p"))
        removed += 1
    return removed


def relax_overfull_rows(document):
    """Let a row of exact height grow when the file says its content is taller.

    pdf2docx sizes every row from the PDF and Word clips what an exact row
    cannot hold, without a trace in the file: a resource list lost its last
    link, a finding card its last line. Where the spacing and line heights
    this file declares add up to more than the row, the row becomes "at
    least" that tall, so the page may drift by the difference but no text
    is hidden. A row whose content the file cannot measure is left alone.
    Returns how many rows were relaxed.
    """
    relaxed = 0
    for row in document.element.body.iter(qn("w:tr")):
        properties = row.find(qn("w:trPr"))
        height = properties.find(qn("w:trHeight")) if properties is not None else None
        if height is None or height.get(qn("w:hRule")) != "exact":
            continue
        limit = twips_of(height.get(qn("w:val")))
        if limit is None:
            continue
        tallest = None
        estimated = []
        for cell in row.findall(qn("w:tc")):
            settings = cell.find(qn("w:tcPr"))
            if settings is not None and settings.find(qn("w:vMerge")) is not None:
                # Its content spans the rows below as well; measured against
                # this row alone it would grow the row by the whole span.
                continue
            content = cell_content_height(cell, estimated)
            if content is None:
                tallest = None
                break
            tallest = content if tallest is None else max(tallest, content)
        # A height estimated from automatic lines is a low estimate (the
        # smallest single spacing of the faces measured), so any real
        # overshoot of it is Word's too: design-a2's figure row measured 1.9 pt
        # over and clipped its caption.
        allowance = ROW_OVERFULL_ESTIMATED_PT if estimated else ROW_OVERFULL_PT
        if tallest is not None and tallest > limit + allowance:
            height.set(qn("w:hRule"), "atLeast")
            relaxed += 1
    return relaxed


# How much taller than its exact row a cell's declared content may be before
# the row is let grow. The last line's box reaches below its glyphs by the
# descent, which an exact row may cut without hiding a letter: a 3-line
# code panel declares 1.9 pt more than its row and shows every line.
ROW_OVERFULL_PT = 4.0
# The same for a row whose content was partly estimated from automatic lines.
ROW_OVERFULL_ESTIMATED_PT = 1.0


def trim_section_tails(document):
    """Make the paragraph that carries each section break as short as Word allows.

    pdf2docx ends every page with up to eleven 0.7 pt padding paragraphs
    ("never put a table at the end of a page") and then the empty paragraph
    that python-docx's `add_section` makes to hold the `w:sectPr`. That last
    one has no spacing of its own, so it inherits the document default: a
    1.15 line of the run's font plus 10 pt after, 20 to 26 pt the PDF does not
    have. When a page has drifted near its bottom that tail is what falls off,
    and Word makes a page that holds nothing but a header and a footer: every
    empty page measured on six verbose reports was this tail.

    Each break paragraph gets a 1 pt exact line, no spacing and a 1 pt font,
    and the empty padding before it goes, back to the last block that holds
    something. The walk stops at a table, so a spacer that keeps two tables
    apart is never removed. Returns how many paragraphs were removed.
    """
    body = document.element.body
    removed = 0
    for paragraph in list(body.iterchildren(qn("w:p"))):
        properties = paragraph.find(qn("w:pPr"))
        if properties is None or properties.find(qn("w:sectPr")) is None:
            continue
        if any((node.text or "").strip() for node in paragraph.iter(qn("w:t"))):
            continue
        set_spacing(paragraph, before=0.0, after=0.0, line=TAIL_LINE_PT)
        run_properties = properties.find(qn("w:rPr"))
        if run_properties is None:
            run_properties = OxmlElement("w:rPr")
            insert_ordered(properties, run_properties, PPR_ORDER)
        for name in ("w:sz", "w:szCs"):
            size = run_properties.find(qn(name))
            if size is None:
                size = OxmlElement(name)
                insert_ordered(run_properties, size, RPR_ORDER)
            size.set(qn("w:val"), "2")
        node = paragraph.getprevious()
        while node is not None and blank_spacer(node):
            previous = node.getprevious()
            body.remove(node)
            removed += 1
            node = previous
    return removed


def ensure_page_starts(document, page_first_lines, declined=None, pages=None):
    """Put a page break before each PDF page's first line where Word would not start a page.

    pdf2docx writes one section per page, so this is usually a no-op; it
    matters where two pages were merged into one section. Only a paragraph
    that is the whole line, or a line long enough that its opening is not
    likely to be repeated, is trusted: a heading and its contents entry begin
    with the same words, and cutting the page at the entry would split the
    contents page. A line that cannot be found that way, is one of several
    paragraphs that begin alike, or sits inside a table cell where a break
    cannot go, is counted as `page-start-unfound` and left alone.

    When `pages` is given and the body already has that many page-starting
    sections, nothing is matched at all: a text match can be wrong, and a break
    put inside a page is invisible in the result.
    """
    body = document.element.body
    if pages is not None and word_page_sections(document) >= pages:
        return 0
    paragraphs = body_paragraphs(document)
    cursor, inserted = 0, 0
    anchor = next(iter(body), None)
    for wanted in page_first_lines:
        if not wanted or anchor is None:
            continue
        texts = {}
        for k in range(cursor, len(paragraphs)):
            squashed = compare_squash(paragraph_text(paragraphs[k]))
            if squashed == wanted or (len(wanted) >= PAGE_START_PREFIX and squashed.startswith(wanted[:PAGE_START_PREFIX])):
                texts[k] = squashed
        found = None
        if len(texts) == 1:
            found = next(iter(texts))
        elif texts:
            exact = [k for k, squashed in texts.items() if squashed == wanted]
            if len(exact) == 1:
                found = exact[0]
        if found is None or paragraphs[found].getparent() is not body:
            if declined is not None:
                declined["page-start-unfound"] += 1
            if found is not None:
                cursor = found + 1
                anchor = top_level(paragraphs[found], body)
            continue
        cursor = found + 1
        p = paragraphs[found]
        if p.getprevious() is not None and not starts_a_page(p, anchor):
            run = p.makeelement(qn("w:r"), {})
            run.append(run.makeelement(qn("w:br"), {qn("w:type"): "page"}))
            ppr = p.find(qn("w:pPr"))
            p.insert(0 if ppr is None else list(p).index(ppr) + 1, run)
            inserted += 1
        anchor = p
    return inserted


def column_region(body):
    """The first run of pdf2docx column sections that holds only pictures, or None.

    Returns `(opener, columns, holders, closer, widths, height)`: the
    paragraph whose section break precedes the columns (None at the start of
    the document), one list of top-level blocks per column, the paragraphs
    carrying each column's section break, the element whose break closes the
    page after them (a paragraph's or the body's own), the columns' widths in
    points and the tallest picture's height.
    """
    children = list(body)
    opener = None
    start = 0
    index = 0
    while index < len(children):
        child = children[index]
        section = section_break_of(child)
        if section is None:
            index += 1
            continue
        cols = section.find(qn("w:cols"))
        kind = section.find(qn("w:type"))
        try:
            count = int(cols.get(qn("w:num")) or 1) if cols is not None else 1
        except ValueError:
            count = 0
        if child.tag == qn("w:p") and kind is not None and kind.get(qn("w:val")) == "continuous" and count >= 2:
            columns = [children[start:index]]
            holders = [child]
            cursor = index + 1
            last = index
            while len(columns) < count:
                look = next((k for k in range(cursor, len(children)) if section_break_of(children[k]) is not None), None)
                if look is None:
                    break
                more = section_break_of(children[look])
                more_kind = more.find(qn("w:type"))
                more_cols = more.find(qn("w:cols"))
                if (children[look].tag != qn("w:p") or more_kind is None or more_kind.get(qn("w:val")) != "nextColumn"
                        or more_cols is None or more_cols.get(qn("w:num")) != cols.get(qn("w:num"))):
                    break
                columns.append(children[cursor:look])
                holders.append(children[look])
                cursor = look + 1
                last = look
            closer = next((children[k] for k in range(last + 1, len(children)) if section_break_of(children[k]) is not None), None)
            widths = column_widths(section, count)
            height = max((sum(drawing_height(node) for block in blocks for node in block.iter(qn("w:drawing")))
                          for blocks in columns), default=0.0)
            if (len(columns) == count and closer is not None and widths is not None and height > 0
                    and column_count(section_break_of(closer)) <= 1
                    and all(pictures_only(blocks) for blocks in columns)
                    and not any(paragraph_has_content(holder) for holder in holders)):
                return opener, columns, holders, closer, widths, height
        if child.tag == qn("w:p"):
            opener = child
        start = index + 1
        index += 1
    return None


def column_count(section):
    """How many columns a section's properties declare."""
    cols = section.find(qn("w:cols"))
    try:
        return int(cols.get(qn("w:num")) or 1) if cols is not None else 1
    except ValueError:
        return 1


def spacing_pt(element, name):
    """A paragraph's own spacing before or after in points, 0 when it states none."""
    properties = element.find(qn("w:pPr")) if element.tag == qn("w:p") else None
    spacing = properties.find(qn("w:spacing")) if properties is not None else None
    return (twips_of(spacing.get(qn(name))) if spacing is not None else None) or 0.0


def column_widths(section, count):
    """Each column's width in points, from the section's own columns or shared out evenly."""
    cols = section.find(qn("w:cols"))
    widths = []
    for col in (cols.findall(qn("w:col")) if cols is not None else []):
        value = twips_of(col.get(qn("w:w")))
        if value is None:
            widths = []
            break
        widths.append(value)
    if len(widths) == count:
        return widths
    size = section.find(qn("w:pgSz"))
    margins = section.find(qn("w:pgMar"))
    page = twips_of(size.get(qn("w:w"))) if size is not None else None
    left = twips_of(margins.get(qn("w:left"))) if margins is not None else None
    right = twips_of(margins.get(qn("w:right"))) if margins is not None else None
    space = (twips_of(cols.get(qn("w:space"))) if cols is not None else None) or 0.0
    if page is None or left is None or right is None:
        return None
    total = page - left - right - space * (count - 1)
    return [total / count] * count if total > 0 else None


def drawing_height(drawing):
    """A drawing's height in points, 0 when it does not say."""
    node = drawing.find(qn("wp:inline"))
    if node is None:
        node = drawing.find(qn("wp:anchor"))
    extent = node.find(qn("wp:extent")) if node is not None else None
    try:
        return int(extent.get("cy")) / EMU_PER_PT
    except (TypeError, ValueError, AttributeError):
        return 0.0


def paragraph_has_content(element):
    return (any((node.text or "").strip() for node in element.iter(qn("w:t")))
            or any(True for _ in element.iter(qn("w:drawing"))))


def pictures_only(blocks):
    """Paragraphs that hold pictures or nothing, and no table."""
    return all(block.tag == qn("w:p") and not any((node.text or "").strip() for node in block.iter(qn("w:t")))
               for block in blocks)


def paragraph_font_size(element):
    """The largest size its text runs declare, in points, or None."""
    sizes = []
    for run in element.iter(qn("w:r")):
        if run.find(qn("w:t")) is None:
            continue
        properties = run.find(qn("w:rPr"))
        size = properties.find(qn("w:sz")) if properties is not None else None
        value = twips_of(size.get(qn("w:val"))) if size is not None else None
        if value is not None:
            sizes.append(value * 10.0)
    return max(sizes) if sizes else None


def repair_thin_line(paragraph):
    """A text paragraph whose exact line is thinner than its own type gets its neighbour's line.

    pdf2docx wrote the caption under two pictures side by side with a 1 pt
    line, which drew it over the pictures' lower edge. The line is taken
    from the next paragraph at the same size that states a plausible one, so
    the value is the converter's own for that type.
    """
    metrics = paragraph_metrics(paragraph)
    size = paragraph_font_size(paragraph)
    if metrics is None or size is None or metrics["line"] >= 0.8 * size:
        return False
    for following in paragraph.itersiblings(qn("w:p")):
        other = paragraph_metrics(following)
        if other is not None and paragraph_font_size(following) == size and other["line"] >= 0.8 * size:
            set_spacing(paragraph, line=other["line"])
            return True
    set_spacing(paragraph, line=1.4 * size)
    return True


def fold_column_sections(document):
    """Turn each run of pdf2docx column sections that holds only pictures into one table row.

    Two screenshots side by side come out of pdf2docx as three sections on
    their page: a continuous section of two columns holding the first
    picture, a next-column section holding the second, and a continuous one
    for the rest of the page. Word lays that out as the PDF has it, and
    everything else here then went wrong, because the passes counted
    sections to find pages: no paragraph of such a document was given a
    page, its text was matched by a cursor that ran away on repeated prose,
    the vertical pass refused the whole document, and a tagged header could
    not be given its pages. The columns become one borderless table row, a
    cell per column at the column's width and the row as tall as its tallest
    picture, and the page is one section again, carrying the page's closing
    section properties with the opening section's start. Columns that hold
    anything but pictures are left as they are. Returns how many rows were made.
    """
    body = document.element.body
    folded = 0
    while True:
        region = column_region(body)
        if region is None:
            return folded
        opener, columns, holders, closer, widths, height = region
        # pdf2docx writes the gap below the pictures as spacing after the
        # last paragraph before the break, or on the break's own paragraph
        # when that one is a picture; both go with the fold, so the gap is
        # carried to the first paragraph after the row.
        gap = max([spacing_pt(holder, "w:after") for holder in holders]
                  + [spacing_pt(blocks[-1], "w:after") for blocks in columns if blocks], default=0.0)
        table = OxmlElement("w:tbl")
        properties = OxmlElement("w:tblPr")
        for name, attributes in (("w:tblW", {"w:w": twips_attribute(sum(widths)), "w:type": "dxa"}),
                                 ("w:tblInd", {"w:w": "0", "w:type": "dxa"}),
                                 ("w:tblLayout", {"w:type": "fixed"})):
            node = OxmlElement(name)
            for key, value in attributes.items():
                node.set(qn(key), value)
            properties.append(node)
        margins = OxmlElement("w:tblCellMar")
        for side in ("w:top", "w:start", "w:bottom", "w:end"):
            node = OxmlElement(side)
            node.set(qn("w:w"), "0")
            node.set(qn("w:type"), "dxa")
            margins.append(node)
        properties.append(margins)
        mark = OxmlElement("w:tblDescription")
        mark.set(qn("w:val"), COLUMN_TABLE_MARK)
        properties.append(mark)
        table.append(properties)
        grid = OxmlElement("w:tblGrid")
        for width in widths:
            node = OxmlElement("w:gridCol")
            node.set(qn("w:w"), twips_attribute(width))
            grid.append(node)
        table.append(grid)
        row = OxmlElement("w:tr")
        span = OxmlElement("w:trHeight")
        span.set(qn("w:hRule"), "exact")
        span.set(qn("w:val"), twips_attribute(height))
        holder = OxmlElement("w:trPr")
        holder.append(span)
        row.append(holder)
        anchor = columns[0][0] if columns[0] else holders[0]
        anchor.addprevious(table)
        for width, blocks in zip(widths, columns):
            cell = OxmlElement("w:tc")
            settings = OxmlElement("w:tcPr")
            node = OxmlElement("w:tcW")
            node.set(qn("w:w"), twips_attribute(width))
            node.set(qn("w:type"), "dxa")
            settings.append(node)
            cell.append(settings)
            for block in blocks:
                cell.append(block)
                if any(True for _ in block.iter(qn("w:drawing"))):
                    picture_host(block)
            if not any(child.tag == qn("w:p") for child in cell):
                cell.append(OxmlElement("w:p"))
            row.append(cell)
        table.append(row)
        closing = section_break_of(closer)
        opening = section_break_of(opener) if opener is not None else None
        for stub in holders:
            body.remove(stub)
        # A paragraph already standing after the row is the next page's, the
        # blank run-up pdf2docx wrote for its header line, so the page's break
        # goes straight after the row. Behind that paragraph, as it was
        # written first, it took the run-up over to the page that ends here and
        # left the next page opening on its first line of text, a figure's
        # caption, whose 16.7 pt line the header's margin then shaved to 1 pt
        # (shave_leading_space takes the line of a first paragraph when it has
        # no spacing to give), so Word clipped the caption away.
        keep_paragraph_around(table)
        if section_starts_page(closing) and opening is not None:
            # The columns end their page: nothing of it follows them, so the
            # break after them begins the next page (the running footer that
            # was the rest of the page went with the bands). The page's own
            # break moves from before the row to after it; merging it into
            # the closer, as below, joined two pages into one section and
            # took the page map from a 77-page report.
            opening.getparent().remove(opening)
            if not paragraph_has_content(opener):
                body.remove(opener)
            stub = OxmlElement("w:p")
            set_spacing(stub, before=0.0, after=0.0, line=SPACER_LINE_PT)
            insert_ordered(stub.get_or_add_pPr(), opening, PPR_ORDER)
            # Right after the row: the paragraph after it is the next page's
            # first, and a break after that one pulled it back onto this page.
            table.addnext(stub)
        else:
            # The page's one section: the closing break's properties, started
            # the way the opening section started.
            kind = closing.find(qn("w:type"))
            if kind is not None:
                closing.remove(kind)
            wanted = opening.find(qn("w:type")) if opening is not None else None
            if wanted is not None:
                insert_ordered(closing, copy.deepcopy(wanted), SECTPR_ORDER)
            if opening is not None:
                opening.getparent().remove(opening)
                if not paragraph_has_content(opener):
                    body.remove(opener)
        following = table.getnext()
        while following is not None and following.tag == qn("w:p") and not paragraph_has_content(following):
            following = following.getnext()
        if following is not None and following.tag == qn("w:p"):
            repair_thin_line(following)
            if gap > spacing_pt(following, "w:before"):
                set_spacing(following, before=gap)
        folded += 1


# The description a folded picture row carries, so it can be found again.
COLUMN_TABLE_MARK = "btct-columns"


def resize_column_rows(document):
    """Size each folded picture row to its tallest column again, once the pictures are cropped.

    The fold runs before the picture pass, which crops a picture to what its
    frame shows and sizes it to that; a row kept at the uncropped height
    would stand taller than its pictures. Returns how many rows changed.
    """
    changed = 0
    for table in document.element.body.iter(qn("w:tbl")):
        properties = table.find(qn("w:tblPr"))
        mark = properties.find(qn("w:tblDescription")) if properties is not None else None
        if mark is None or mark.get(qn("w:val")) != COLUMN_TABLE_MARK:
            continue
        for row in table.findall(qn("w:tr")):
            height = max((sum(drawing_height(node) for node in cell.iter(qn("w:drawing"))) for cell in row.findall(qn("w:tc"))),
                         default=0.0)
            holder = row.find(qn("w:trPr"))
            span = holder.find(qn("w:trHeight")) if holder is not None else None
            if span is not None and height > 0 and span.get(qn("w:val")) != twips_attribute(height):
                span.set(qn("w:val"), twips_attribute(height))
                changed += 1
    return changed


def strip_column_marks(document):
    """Remove the description that names a folded picture row: it is this file's own
    bookkeeping, and Word and screen readers take a table description for alt text."""
    removed = 0
    for table in document.element.body.iter(qn("w:tbl")):
        properties = table.find(qn("w:tblPr"))
        mark = properties.find(qn("w:tblDescription")) if properties is not None else None
        if mark is not None and mark.get(qn("w:val")) == COLUMN_TABLE_MARK:
            properties.remove(mark)
            removed += 1
    return removed


def picture_host(paragraph):
    """A paragraph that holds a picture and nothing else: no spacing, one auto line, a 1 pt font.

    An inline picture stands on the baseline like a glyph; a single auto
    line grows to it and a 1 pt font leaves next to no descent under it,
    which is what `inline_into_frame` measured for a frame cell.
    """
    set_spacing(paragraph, before=0.0, after=0.0)
    spacing = paragraph.get_or_add_pPr().find(qn("w:spacing"))
    spacing.set(qn("w:line"), "240")
    spacing.set(qn("w:lineRule"), "auto")
    for run in paragraph.findall(qn("w:r")):
        if run.find(qn("w:drawing")) is None:
            continue
        run_properties = run.find(qn("w:rPr"))
        if run_properties is None:
            run_properties = OxmlElement("w:rPr")
            run.insert(0, run_properties)
        for name in ("w:sz", "w:szCs"):
            size = run_properties.find(qn(name))
            if size is None:
                size = OxmlElement(name)
                insert_ordered(run_properties, size, RPR_ORDER)
            size.set(qn("w:val"), "2")


# ── text pdf2docx cannot carry: lines that are neither upright nor a quarter turn ──
#
# pdf2docx writes a line only when its writing direction is exactly (1, 0) or
# exactly (0, -1) (`Line.text_direction`), and drops every other line without
# a word. A diagonal "DRAFT" or "CONFIDENTIAL" watermark, a stamp set at four
# degrees on a cover, a ribbon at 45 degrees: none of them reaches the Word
# file on any rung, `--raw` included, and invariant 18 does not let a recurring
# loss be forgiven, so the check sent every such report to the bottom of the
# ladder (two of the design-b reports, one line each, on their first page).
#
# The line is written back after every other pass has finished, as a DrawingML
# text box anchored to its page, turned by the line's own angle about the
# centre of the line's box, set in the line's font and colour, with no fill and
# no outline. Nothing is moved or deleted for it: an anchored shape takes no
# room in the text, and it is added after every pass that reads paragraphs, so
# none of them reads its paragraph as a row of the PDF.

# Word writes this as the z-order of the first floating object on a page.
BOX_FIRST_HEIGHT = 251658240
EMU_PER_PT = 12700
# Room the box gets beyond the text: a quarter of the line's length plus this
# many type sizes along it, this many across it. The text is centred in the box
# both ways, so spare room moves nothing, and Word clips what a fixed box is
# too small for (a Word line is taller than the PDF's glyph cell in some fonts)
# and wraps what is wider than the box (a font the reader lacks is substituted
# in silence). The box cannot be told not to wrap: with `wrap="none"` Word sets
# the line from the box's left edge whatever the paragraph says, and measured
# on a 14 pt stamp that put it 15 pt left of the PDF's. Word's own "fit text"
# (`w:fitText`) was tried to reproduce a tracked line's length and set the 14 pt
# stamp 9% too long, so the line keeps the font's natural width, centred; a
# tracked 82 pt watermark comes out 7 to 10% shorter than the PDF's.
BOX_PAD_EM = 2.0
BOX_WIDEN = 1.25
# A trace span is the same text as a dictionary span when its first glyph
# starts within this of where the dictionary says the span's origin is.
TRACE_MATCH_PT = 1.0
BOX_XML = (
    '<w:r xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
    ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
    ' xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"><w:drawing>'
    '<wp:anchor distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="{height}"'
    ' behindDoc="{behind}" locked="0" layoutInCell="0" allowOverlap="1"><wp:simplePos x="0" y="0"/>'
    '<wp:positionH relativeFrom="page"><wp:posOffset>{left}</wp:posOffset></wp:positionH>'
    '<wp:positionV relativeFrom="page"><wp:posOffset>{top}</wp:posOffset></wp:positionV>'
    '<wp:extent cx="{width}" cy="{tall}"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapNone/>'
    '<wp:docPr id="{id}" name="Rotated text {id}"/><wp:cNvGraphicFramePr/>'
    '<a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">'
    '<wps:wsp><wps:cNvSpPr txBox="1"/><wps:spPr><a:xfrm rot="{turn}"><a:off x="0" y="0"/>'
    '<a:ext cx="{width}" cy="{tall}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
    '<a:noFill/><a:ln><a:noFill/></a:ln></wps:spPr><wps:txbx><w:txbxContent/></wps:txbx>'
    '<wps:bodyPr rot="0" vert="horz" wrap="square" lIns="0" tIns="0" rIns="0" bIns="0" anchor="ctr"'
    ' anchorCtr="0"><a:noAutofit/></wps:bodyPr></wps:wsp></a:graphicData></a:graphic></wp:anchor>'
    '</w:drawing></w:r>'
)


# A filled rectangle with no text on it is written back as a shape when it is
# big enough to be part of the page's design rather than a rule or a swatch:
# it spans this much of the page's height or width (a side band, a stripe, a
# header bar), or covers this much of its area (a full-bleed block). Measured
# on design-b1's cover: the maroon band is 100% of the page's height and the
# gold stripe beside it too; a table cell, a heading's number block and a
# panel are under 10% of either. pdf2docx writes none of these, since a shape
# with no text over it is neither a cell's shading nor a border, and the
# converter's own file for that cover had a white page where the band stands.
FILL_BAND_SPAN = 0.8
# How close to the page's side a band must reach to be one the page bleeds.
FILL_EDGE_PT = 1.0
FILL_BLOCK_AREA = 0.15
FILL_XML = (
    '<w:r xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
    ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
    ' xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"><w:drawing>'
    '<wp:anchor distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="{height}"'
    ' behindDoc="1" locked="0" layoutInCell="0" allowOverlap="1"><wp:simplePos x="0" y="0"/>'
    '<wp:positionH relativeFrom="page"><wp:posOffset>{left}</wp:posOffset></wp:positionH>'
    '<wp:positionV relativeFrom="page"><wp:posOffset>{top}</wp:posOffset></wp:positionV>'
    '<wp:extent cx="{width}" cy="{tall}"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapNone/>'
    '<wp:docPr id="{id}" name="Page fill {id}"/><wp:cNvGraphicFramePr/>'
    '<a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">'
    '<wps:wsp><wps:cNvSpPr/><wps:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{width}" cy="{tall}"/></a:xfrm>'
    '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:solidFill><a:srgbClr val="{rgb}"/></a:solidFill>'
    '<a:ln><a:noFill/></a:ln></wps:spPr><wps:bodyPr rot="0" vert="horz" wrap="square" lIns="0" tIns="0"'
    ' rIns="0" bIns="0" anchor="t" anchorCtr="0"><a:noAutofit/></wps:bodyPr></wps:wsp></a:graphicData>'
    '</a:graphic></wp:anchor></w:drawing></w:r>'
)


def page_fills(doc, members=None):
    """The big filled rectangles with nothing printed on them, one list per page.

    Each entry is `{"x0", "y0", "x1", "y1", "rgb"}` in points, cut to the page
    and with a fill's opacity blended onto white like a watermark's. A drawing
    counts only when it is one plain rectangle with a fill and no outline, is
    not white, and is a band or a block by `FILL_BAND_SPAN` and
    `FILL_BLOCK_AREA`; a block must also have no word's centre inside it
    (text over a fill is shaded by the converter's own passes, and a second
    copy would only be a duplicate), while a band is drawn with its text on
    it. A page turned by /Rotate is left alone.
    """
    pages = []
    for index in range(doc.page_count):
        page = doc[index]
        found = []
        pages.append(found)
        if page.rotation:
            continue
        bounds = page.rect
        centres = [((w[0] + w[2]) / 2, (w[1] + w[3]) / 2) for w in page.get_text("words")]
        # The running header's and footer's own rows: a strip that carries
        # one of them is the band's, which `apply_bands` already draws in the
        # Word header or footer (a second copy behind the body put 149 strips
        # into a 69-page report).
        band_centres = [((row["x0"] + row["x1"]) / 2, (row["y0"] + row["y1"]) / 2)
                        for row in page_rows(page) if members and row_id(index, row) in members]
        for drawing in page.get_drawings():
            items = drawing.get("items") or []
            fill = drawing.get("fill")
            if fill is None or drawing.get("color") is not None or len(items) != 1 or items[0][0] != "re":
                continue
            rect = pymupdf.Rect(drawing["rect"]) & bounds
            if rect.is_empty or min(rect.width, rect.height) <= RULE_MAX_THICKNESS_PT:
                continue
            band = rect.height >= FILL_BAND_SPAN * bounds.height or rect.width >= FILL_BAND_SPAN * bounds.width
            block = rect.width * rect.height >= FILL_BLOCK_AREA * bounds.width * bounds.height
            if not (band or block):
                continue
            # A band carries text more often than not (a chapter's title in
            # white on a dark full-bleed strip, a sidebar holding comments),
            # and without the band that text is white on white: design-b2's
            # chapter titles were invisible. The converter's own shading never
            # spans a page, so the band is drawn behind the text whatever is
            # printed on it; a block with text on it is still left to the
            # passes that shade text.
            # Only a band that reaches the page's edge is drawn over its text:
            # a full-bleed strip across the page, or a full-height one at a
            # side. A code panel or a table's header row spans 82% of a
            # Letter page and carries text too, and is shaded by the
            # converter's own passes; a second copy at the PDF's place stands
            # apart from it wherever Word's page drifts.
            bleed = ((rect.x0 <= FILL_EDGE_PT and rect.x1 >= bounds.width - FILL_EDGE_PT)
                     or (rect.height >= FILL_BAND_SPAN * bounds.height
                         and (rect.x0 <= FILL_EDGE_PT or rect.x1 >= bounds.width - FILL_EDGE_PT)))
            if not bleed and any(rect.x0 <= x <= rect.x1 and rect.y0 <= y <= rect.y1 for x, y in centres):
                continue
            if any(rect.x0 <= x <= rect.x1 and rect.y0 <= y <= rect.y1 for x, y in band_centres):
                continue
            opacity = drawing.get("fill_opacity")
            value = (round(fill[0] * 255) << 16) | (round(fill[1] * 255) << 8) | round(fill[2] * 255)
            value = blend_with_white(value, 1.0 if opacity is None else opacity)
            if value == 0xFFFFFF:
                continue
            found.append({"x0": rect.x0, "y0": rect.y0, "x1": rect.x1, "y1": rect.y1, "rgb": "%06X" % value})
    return pages


def restore_page_fills(document, pages, declined):
    """Write each page's plain fills back as shapes behind its text. Returns how many.

    Page-relative and behind the text, anchored in the first paragraph of the
    page's own blocks like the rotated lines, which is all a shape that is
    positioned against the page needs. Run last, with the rotated lines: the
    passes read the body's paragraphs as the page's lines.
    """
    sections = page_blocks(document.element.body)
    shape_id = max((int(node.get("id")) for root in run_parts(document)
                    for node in root.iter(qn("wp:docPr")) if (node.get("id") or "").isdigit()), default=0)
    written = 0
    for index, fills in enumerate(pages):
        if not fills:
            continue
        if index >= len(sections):
            declined["page-fills-no-page"] += 1
            continue
        blocks = sections[index]
        holder = next((block for block in blocks if block.tag == qn("w:p")), None)
        if holder is None:
            holder = next((p for block in blocks for p in block.iter(qn("w:p"))), None)
        if holder is None:
            declined["page-fills-no-paragraph"] += 1
            continue
        properties = holder.find(qn("w:pPr"))
        source = next((r.find(qn("w:rPr")) for r in holder.findall(qn("w:r")) if named_font(r)), None)
        if source is None and properties is not None:
            source = properties.find(qn("w:rPr"))
        # In the PDF's drawing order, each run after the one before it, and
        # each shape a higher `relativeHeight` than the last: what is drawn
        # later lies over what was drawn first.
        previous = None
        for fill in fills:
            shape_id += 1
            run = parse_xml(FILL_XML.format(
                height=BOX_FIRST_HEIGHT + shape_id, id=shape_id, rgb=fill["rgb"],
                left=round(fill["x0"] * EMU_PER_PT), top=round(fill["y0"] * EMU_PER_PT),
                width=round((fill["x1"] - fill["x0"]) * EMU_PER_PT),
                tall=round((fill["y1"] - fill["y0"]) * EMU_PER_PT)))
            if previous is not None:
                previous.addnext(run)
            elif properties is None:
                holder.insert(0, run)
            else:
                properties.addnext(run)
            previous = run
            if source is not None:
                carried = OxmlElement("w:rPr")
                run.insert(0, carried)
                take_font(carried, source)
            written += 1
    return written


def carried_by_pdf2docx(direction):
    """Does pdf2docx write a line with this writing direction? The same test it makes."""
    return direction[0] == 1.0 or direction[1] == -1.0


def blend_with_white(color, opacity):
    """A colour as it shows on a white page when drawn at `opacity`, as an int.

    Word sets a run's transparency only through an extension other readers
    ignore, and a watermark drawn at 9% would show at full strength in them.
    On the white page a report is printed on the two are the same colour, and
    this one is the same in every reader.
    """
    value = int(color or 0)
    if opacity >= 1.0:
        return value
    mixed = [round(255 - opacity * (255 - ((value >> shift) & 0xFF))) for shift in (16, 8, 0)]
    return (mixed[0] << 16) | (mixed[1] << 8) | mixed[2]


def xml_safe(text):
    """`text` without the control characters an XML document cannot hold."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cc")


def traced_span(tilted, origin):
    """The text trace's span whose first glyph sits at `origin`, or None."""
    nearest = min(tilted, key=lambda t: math.dist(t["chars"][0][2], origin), default=None)
    if nearest is not None and math.dist(nearest["chars"][0][2], origin) <= TRACE_MATCH_PT:
        return nearest
    return None


def rotated_lines(doc):
    """The PDF's lines pdf2docx drops for their direction, with what a text box needs.

    Each entry has its page index, angle (degrees, clockwise on the page,
    which is what DrawingML turns by), the centre of its box, its length
    along the line, the height of its glyph cell, its spans' looks and
    `behind`: whether the PDF draws it before any upright text of its page,
    which is how a watermark is laid under a page and a stamp is not.

    The box PyMuPDF reports for a tilted line is the bounds of the tilted
    rectangle, so with the cell height known the length is solved from
    whichever side of it is longer (the other side is then reproduced to
    0.1 pt on a 4 degree stamp and a 45 degree ribbon). The centre of those
    bounds is the centre of the rectangle, which is what Word turns about.

    A span's opacity and its place in the drawing order are not in the text
    dictionary, so they come from the text trace, matched by where the span's
    first glyph sits. A drawn break hyphen reads as a soft hyphen; in a box
    that cannot wrap it is a hyphen. A page turned by /Rotate is left alone (a
    typst report never has one) and what is left alone is reported missing.
    """
    flags = pymupdf.TEXTFLAGS_DICT & ~pymupdf.TEXT_PRESERVE_IMAGES
    out = []
    for index in range(doc.page_count):
        page = doc[index]
        if page.rotation:
            continue
        found = []
        for block in page.get_text("dict", flags=flags)["blocks"]:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                spans = [s for s in line.get("spans", []) if s.get("text")]
                if not carried_by_pdf2docx(line["dir"]) and "".join(s["text"] for s in spans).strip():
                    found.append((line, spans))
        if not found:
            continue
        tilted, first_upright = [], None
        try:
            trace = [span for span in page.get_texttrace() if span.get("chars")]
        except Exception:  # noqa: BLE001 - opacity and order are refinements, never a reason to fail the export
            trace = []
        for span in trace:
            if carried_by_pdf2docx(span["dir"]):
                first_upright = span["seqno"] if first_upright is None else min(first_upright, span["seqno"])
            else:
                tilted.append(span)
        for line, spans in found:
            dx, dy = line["dir"]
            looks, seqs = [], []
            for span in spans:
                match = traced_span(tilted, span["origin"])
                seqs.append(match["seqno"] if match else None)
                looks.append({"text": xml_safe(span["text"].replace(SOFT_HYPHEN, "-")), "font": font_family(span["font"]),
                              "psname": pdf_base_name(span["font"]), "size": span["size"],
                              "bold": bool(span["flags"] & BOLD_FLAG),
                              "color": blend_with_white(span["color"], match["opacity"] if match else 1.0),
                              "ascender": span.get("ascender", 0.9), "descender": span.get("descender", -0.2)})
            if not "".join(look["text"] for look in looks).strip():
                continue
            cell = max(look["size"] * (look["ascender"] - look["descender"]) for look in looks)
            x0, y0, x1, y1 = line["bbox"]
            cos, sin = abs(dx), abs(dy)
            length = (x1 - x0 - cell * sin) / cos if cos >= sin else (y1 - y0 - cell * cos) / sin
            if not (length > 0 and cell > 0):
                continue
            known = [s for s in seqs if s is not None]
            out.append({"page": index, "angle": math.degrees(math.atan2(dy, dx)),
                        "cx": (x0 + x1) / 2, "cy": (y0 + y1) / 2, "length": length, "cell": cell,
                        "spans": looks,
                        "behind": first_upright is None or (bool(known) and min(known) < first_upright)})
    return out


# How far outside its page's text column a row must start (or end) to be a
# note in the margin rather than text that runs a little past the column: a
# hanging full stop is under 3 pt, and design-a1's comments stand 24.8 pt out.
MARGIN_NOTE_GAP_PT = 6.0
# Two rows are one note when they start on one edge, this close, and the gap
# between them is at most a line.
MARGIN_NOTE_EDGE_PT = 3.0
NOTE_XML = BOX_XML.replace('anchor="ctr"', 'anchor="t"').replace('name="Rotated text {id}"', 'name="Margin note {id}"')


def margin_note_groups(rows, left, right):
    """The page's rows that lie wholly outside its text column, grouped into notes, top to bottom."""
    outside = sorted((row for row in rows
                      if row["x0"] >= right + MARGIN_NOTE_GAP_PT or row["x1"] <= left - MARGIN_NOTE_GAP_PT),
                     key=lambda row: row["y0"])
    groups = []
    for row in outside:
        last = groups[-1][-1] if groups else None
        if (last is not None and abs(row["x0"] - last["x0"]) <= MARGIN_NOTE_EDGE_PT
                and row["y0"] - last["y1"] <= (last["y1"] - last["y0"])):
            groups[-1].append(row)
        else:
            groups.append([row])
    return groups


def float_margin_notes(document, anchors, page_widths, declined=None):
    """Lift a note set in the page's margin out of the flow, into a text box where the PDF has it.

    typst `place`s a margin note beside the text column, where it takes no
    room; pdf2docx reads it as one more block and writes it into the flow,
    usually as a table of its own under the paragraph it stands beside, so
    every note pushed the rest of its page down by its own height: design-a1's
    review comments (24.8 pt right of the column) added two Word pages each,
    split a finding from its severity band and ran 130.8 pt past the margin.
    A page's rows that lie wholly outside its own text column
    (`text_area_edges`, per paper size, so a landscape page's body is not
    margin), on one edge and a line apart, are one note; the paragraph whose
    text is exactly that note's, on that page and not in a box already, goes
    into an anchored text box at the note's PDF rectangle (in front of the
    text, as the PDF draws it), and the table that held it goes when nothing
    else in it has text. The text check reads text in boxes, so a note that is
    moved wrong is still found. Returns how many notes were moved.
    """
    body = document.element.body
    edges = text_area_edges([(page_widths[index], rows) for index, rows in enumerate(anchors)
                             if index < len(page_widths)])
    pages = page_blocks(body)
    if len(pages) != len(anchors):
        return 0
    page_of = {}
    for index, blocks in enumerate(pages):
        for block in blocks:
            page_of[block] = index
    shape_id = max((int(node.get("id")) for root in run_parts(document)
                    for node in root.iter(qn("wp:docPr")) if (node.get("id") or "").isdigit()), default=0)
    paragraphs = body_paragraphs(document)
    moved = 0
    for index, rows in enumerate(anchors):
        if index >= len(page_widths) or round(page_widths[index]) not in edges:
            continue
        left, right = edges[round(page_widths[index])]
        for group in margin_note_groups(rows, left, right):
            key = "".join(row["key"] for row in group)
            if len(key) < COMPARE_MIN_CHARS:
                continue
            found = []
            for element in paragraphs:
                if compare_squash(paragraph_text(element)) != key:
                    continue
                if any(ancestor.tag == qn("w:txbxContent") for ancestor in element.iterancestors()):
                    continue
                top = top_level_block(body, element)
                if page_of.get(top) == index:
                    found.append((element, top))
            if len(found) != 1:
                if found and declined is not None:
                    declined["margin-notes-ambiguous"] += 1
                continue
            element, top = found[0]
            # A note with a fill of its own (a review comment's box, a
            # severity pill) keeps it: a fill on the paragraph goes with the
            # paragraph, and its cell's fill becomes the box's, or the note
            # would be white text on nothing (declining such notes put
            # design-a1's two comments back in the flow, four pages over).
            # A table that holds a picture as well would take the picture
            # with it, and is declined.
            cell = element.getparent()
            cell_fill = None
            if cell is not None and cell.tag == qn("w:tc"):
                shading = cell.find(qn("w:tcPr") + "/" + qn("w:shd"))
                value = (shading.get(qn("w:fill")) or "auto").upper() if shading is not None else "AUTO"
                if re.fullmatch(r"[0-9A-F]{6}", value) and value != "FFFFFF":
                    cell_fill = (shading, value)
            if top.tag == qn("w:tbl") and any(True for tag in ("w:drawing", "w:pict", "w:object") for _ in top.iter(qn(tag))):
                if declined is not None:
                    declined["margin-notes-picture"] += 1
                continue
            holder = next((block for block in pages[index] if block.tag == qn("w:p") and block is not top), None)
            if holder is None:
                if declined is not None:
                    declined["margin-notes-no-anchor"] += 1
                continue
            x0 = min(row["x0"] for row in group)
            y0 = min(row["y0"] for row in group)
            x1 = max(row["x1"] for row in group)
            y1 = max(row["y1"] for row in group)
            em = max((row["y1"] - row["y0"]) for row in group)
            shape_id += 1
            run = parse_xml(NOTE_XML.format(
                height=BOX_FIRST_HEIGHT + shape_id, behind=0, id=shape_id,
                left=round(x0 * EMU_PER_PT), top=round(y0 * EMU_PER_PT),
                width=round(((x1 - x0) * BOX_WIDEN + em) * EMU_PER_PT),
                tall=round(((y1 - y0) + em) * EMU_PER_PT), turn=0))
            note = copy.deepcopy(element)
            properties = note.get_or_add_pPr()
            for tag in ("w:ind", "w:framePr", "w:pageBreakBefore", "w:keepNext"):
                for node in properties.findall(qn(tag)):
                    properties.remove(node)
            spacing = properties.find(qn("w:spacing"))
            if spacing is not None:
                spacing.set(qn("w:before"), "0")
                spacing.set(qn("w:after"), "0")
            next(run.iter(qn("w:txbxContent"))).append(note)
            if cell_fill is not None:
                fill = parse_xml('<a:solidFill xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                                 '<a:srgbClr val="%s"/></a:solidFill>' % cell_fill[1])
                shape = next(run.iter("{http://schemas.microsoft.com/office/word/2010/wordprocessingShape}spPr"))
                empty = shape.find("{http://schemas.openxmlformats.org/drawingml/2006/main}noFill")
                empty.addprevious(fill)
                shape.remove(empty)
            # The note leaves the flow: its paragraph goes, and the table it
            # was the only text of goes with it (a cell keeps one paragraph,
            # and an emptied cell its fill no longer).
            if top.tag == qn("w:tbl") and compare_squash("".join(paragraph_text(p) for p in top.iter(qn("w:p")))) == key:
                body.remove(top)
            elif element.getparent().tag == qn("w:tc") and len(element.getparent().findall(qn("w:p"))) == 1:
                for child in list(element):
                    if child.tag != qn("w:pPr"):
                        element.remove(child)
                if cell_fill is not None:
                    cell_fill[0].getparent().remove(cell_fill[0])
            else:
                element.getparent().remove(element)
            insert_ordered_run(holder, run)
            moved += 1
    return moved


def insert_ordered_run(paragraph, run):
    """Put a run first in a paragraph, after its properties."""
    properties = paragraph.find(qn("w:pPr"))
    if properties is None:
        paragraph.insert(0, run)
    else:
        properties.addnext(run)


def text_box_run(line, shape_id):
    """A run holding the anchored text box for one rotated line.

    The frame is placed before it is turned, and Word turns it about its
    centre, so the frame's centre is the line's centre whatever the angle.
    """
    em = max(look["size"] for look in line["spans"])
    width = line["length"] * BOX_WIDEN + BOX_PAD_EM * em
    tall = line["cell"] + BOX_PAD_EM * em
    run = parse_xml(BOX_XML.format(
        height=BOX_FIRST_HEIGHT + shape_id, behind=1 if line["behind"] else 0, id=shape_id,
        left=round((line["cx"] - width / 2) * EMU_PER_PT), top=round((line["cy"] - tall / 2) * EMU_PER_PT),
        width=round(width * EMU_PER_PT), tall=round(tall * EMU_PER_PT),
        turn=int(round(line["angle"] * 60000)) % 21600000))
    paragraph = Paragraph(OxmlElement("w:p"), None)
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.space_after = Pt(0)
    for look in line["spans"]:
        style_run(paragraph.add_run(look["text"]), look)
    # The paragraph mark in the font of its text, as `fill_bare_runs` gives
    # every other one, so Word has no default-font mark to write out.
    mark = OxmlElement("w:rPr")
    take_font(mark, paragraph.runs[-1]._r.find(qn("w:rPr")))
    paragraph._p.get_or_add_pPr().append(mark)
    next(run.iter(qn("w:txbxContent"))).append(paragraph._p)
    return run


def add_tail_pages(document, pages, lines, page_rows_of):
    """Give the pages after the file's last one a paragraph each, while the PDF has nothing upright on them.

    pdf2docx writes no block for a page that holds only text it drops (a
    closing page with one tilted "END OF REPORT" and no drawing), so
    `page_blocks` has no group for it and the line had no page to sit on:
    `rotated-no-page` on every rung, a named loss, and the whole report
    dropped to the plain rung. The paragraph is a one point stub at the end
    of the body, before its own section properties, and it begins the page
    itself when the body's section does not (`section_starts_page`). A page
    is made only when every row the PDF has on it is one of the rotated lines
    (`page_rows_of[page]` holds nothing else, compared as the multiset of
    characters, since a tilted line's row and its line are cut alike but not
    always in the same order): then the converter had nothing to write for
    it, and a page it lost upright text from stays a decline. Appends the new
    groups to `pages`.
    """
    body = document.element.body
    final = body.find(qn("w:sectPr"))
    if final is None or page_rows_of is None or not lines:
        return
    first = len(pages)
    for page in range(first, max(line["page"] for line in lines) + 1):
        if page >= len(page_rows_of):
            return
        tilted = sorted("".join(compare_squash("".join(span["text"] for span in line["spans"]))
                                for line in lines if line["page"] == page))
        if sorted("".join(row["key"] for row in page_rows_of[page])) != tilted:
            return
        paragraph = OxmlElement("w:p")
        properties = OxmlElement("w:pPr")
        # `pages` grows with every stub, so `page > len(pages)` was never true
        # and two trailing pages shared one Word page (r1: 3 PDF pages, 2 in
        # Word); only the first stub may lean on the final section's own break.
        if page > first or not section_starts_page(final):
            properties.append(OxmlElement("w:pageBreakBefore"))
        spacing = OxmlElement("w:spacing")
        for name, value in (("before", "0"), ("after", "0"), ("line", "20"), ("lineRule", "exact")):
            spacing.set(qn("w:" + name), value)
        properties.append(spacing)
        paragraph.append(properties)
        final.addprevious(paragraph)
        pages.append([paragraph])


def restore_rotated_lines(document, lines, declined, page_rows_of=None):
    """Write every rotated line of the PDF back as a text box on its page. Returns how many.

    The box is anchored in the first paragraph of the page's own blocks (a
    page-relative shape only has to be on the right page), after every other
    pass, because a paragraph inside a text box is a `w:p` in the body and
    the passes read the body's paragraphs as the page's lines. A page the
    file has no paragraph on, or no page for, is declined by name, and its
    lines are left to the text check to report; a page after the file's last
    that the PDF holds only these lines on gets a page of its own first
    (`add_tail_pages`; `page_rows_of` is each PDF page's upright rows).
    """
    pages = page_blocks(document.element.body)
    add_tail_pages(document, pages, lines, page_rows_of)
    shape_id = max((int(node.get("id")) for root in run_parts(document)
                    for node in root.iter(qn("wp:docPr")) if (node.get("id") or "").isdigit()), default=0)
    written = 0
    for line in lines:
        if line["page"] >= len(pages):
            declined["rotated-no-page"] += 1
            continue
        blocks = pages[line["page"]]
        holder = next((block for block in blocks if block.tag == qn("w:p")), None)
        if holder is None:
            holder = next((p for block in blocks for p in block.iter(qn("w:p"))), None)
        if holder is None:
            declined["rotated-no-paragraph"] += 1
            continue
        try:
            run = text_box_run(line, shape_id + 1)
        except Exception:  # noqa: BLE001 - a box that cannot be written is reported by the text check
            declined["rotated-unwritable"] += 1
            continue
        shape_id += 1
        properties = holder.find(qn("w:pPr"))
        if properties is None:
            holder.insert(0, run)
        else:
            properties.addnext(run)
        # The run that carries the shape takes the font of the text beside it,
        # else of the paragraph mark, like every other run that draws without
        # text (`fill_bare_runs`).
        source = next((r.find(qn("w:rPr")) for r in holder.findall(qn("w:r")) if named_font(r)), None)
        if source is None and properties is not None:
            source = properties.find(qn("w:rPr"))
        if source is not None:
            carried = OxmlElement("w:rPr")
            run.insert(0, carried)
            take_font(carried, source)
        written += 1
    return written


# A drawn tick box is a small empty square: no side of it longer than this.
# Measured on the corpus's checklists and the CPTC designs, 6 to 7 pt; 12 pt
# leaves room for a 10 pt body size and is still smaller than any bordered
# 1x1 table that holds a value, an icon or a label.
CHECK_BOX_MAX_PT = 12.0


def box_table_size(table):
    """`(width, height)` in points of a tick box pdf2docx wrote as a table, else None.

    The box is a bordered 1x1 table with nothing in it: no text, no picture,
    no nested table, borders on at least three sides. A 1x1 table that holds
    anything is somebody's cell and is left alone.
    """
    rows = table.findall(qn("w:tr"))
    if len(rows) != 1:
        return None
    cells = rows[0].findall(qn("w:tc"))
    if len(cells) != 1:
        return None
    cell = cells[0]
    if "".join(cell.itertext()).strip():
        return None
    if any(True for _ in cell.iter(qn("w:tbl"), qn("w:drawing"), qn("w:pict"), qn("w:object"))):
        return None
    # A filled box is a legend's swatch: its colour is what it says.
    shading = cell.find(qn("w:tcPr") + "/" + qn("w:shd"))
    if shading is not None and (shading.get(qn("w:fill")) or "auto").upper() not in ("AUTO", "FFFFFF"):
        return None
    borders = cell.find(qn("w:tcPr") + "/" + qn("w:tcBorders"))
    if borders is None:
        return None
    drawn = [side for side in borders if (side.get(qn("w:val")) or "nil") not in ("nil", "none")]
    if len(drawn) < 3:
        return None
    width = cell.find(qn("w:tcPr") + "/" + qn("w:tcW"))
    height = rows[0].find(qn("w:trPr") + "/" + qn("w:trHeight"))
    try:
        wide = float(width.get(qn("w:w"))) / 20.0
        tall = float(height.get(qn("w:val"))) / 20.0
    except (AttributeError, TypeError, ValueError):
        return None
    if not (0 < wide <= CHECK_BOX_MAX_PT and 0 < tall <= CHECK_BOX_MAX_PT):
        return None
    return wide, tall, drawn


def fold_checked_boxes(document):
    """Draw a ticked box as a bordered character in its label's own line.

    A box with a mark in it comes out of pdf2docx as a nested 1x1 table, empty,
    followed by a paragraph that holds the mark ("x") and the label: Word
    stacks them, so the box sits ABOVE its text. Each ticked item is about 7 pt
    taller than the PDF's (b1's checklist on PDF 6, 44.6 pt of drift by PDF 7)
    and an exact-height cell clips the lines it can no longer hold. An empty
    box is written as a table cell of its own beside the label and is fine.

    The box becomes a run of the label's paragraph, drawn with a character
    border and fitted to the box's width, so it takes no height of its own.
    The mark, when it is the paragraph's first run, goes inside it; otherwise
    the run holds a no-break space. The spacer paragraph that held the box
    down inside its cell goes with the table: it only existed to place it.
    """
    return fold_checked_boxes_in(document.element.body)


def place_folded_label(label, gap, box_height, mark):
    """Give the label the vertical position the spacer and the box gave it.

    `gap` is where the box's top stood below what was above it: the spacer's
    height, or the spacing after the item above when there was no spacer. In
    the PDF the label is centred on the box (typst `align:
    horizon`), so its baseline stands the box's half height plus 0.3 of the
    label's size below the box's top (the baseline of a line sits 0.8 of the
    line below its top, and the line's centre 0.5). Measured on the probe
    against the PDF's baselines: spacers of 4.2 to 10.7 pt put the label's
    first line within 0.5 pt of the PDF's, a line of exact 15.3 pt included.
    The label's own line height is subtracted because the rhythm pass may
    have set it to push the text down beside the stacked box.
    """
    metrics = paragraph_metrics(label)
    if metrics is None:
        return
    sizes = []
    for run in label.findall(qn("w:r")):
        if run is mark or not any(c.tag == qn("w:t") and (c.text or "").strip() for c in run):
            continue
        size = run.find(qn("w:rPr") + "/" + qn("w:sz"))
        if size is not None:
            try:
                sizes.append(float(size.get(qn("w:val"))) / 2.0)
            except (TypeError, ValueError):
                pass
    size = max(sizes) if sizes else 10.0
    baseline = gap + box_height / 2.0 + (EXACT_BASELINE_RATIO - 0.5) * size
    # The rhythm pass grew the first line's pitch to push it past the stacked
    # box; the paragraph that continues the label shows the pitch the PDF has
    # (probe: 15.3 pt against 10.0 pt, which put the second line 3.4 pt low).
    line = metrics["line"]
    following = label.getnext()
    if following is not None and following.tag == qn("w:p") and paragraph_text(following).strip():
        follow = paragraph_metrics(following)
        if follow is not None and 0 < follow["line"] < line - RHYTHM_TOLERANCE_PT:
            line = follow["line"]
    set_spacing(label, before=max(0.0, baseline - EXACT_BASELINE_RATIO * line), line=line)


def fold_checked_boxes_in(body):
    """`fold_checked_boxes` over one element's tables, and how many it folded."""
    folded = 0
    for table in list(body.iter(qn("w:tbl"))):
        size = box_table_size(table)
        if size is None:
            continue
        label = table.getnext()
        if label is None or label.tag != qn("w:p") or not paragraph_text(label).strip():
            continue
        wide, tall, sides = size
        stroke = max(float(side.get(qn("w:sz")) or 4) for side in sides)
        colour = (sides[0].get(qn("w:color")) or "auto").lstrip("#")
        runs = [r for r in label.findall(qn("w:r")) if any(c.tag in (qn("w:t"), qn("w:tab")) for c in r)]
        if not runs:
            continue
        mark = runs[0]
        mark_text = "".join(t.text or "" for t in mark.iter(qn("w:t")))
        # The mark is a tick or a cross: a glyph, or the letter x that
        # templates type for one (design-b1), never another letter or a
        # digit: a label whose first run is "A " would otherwise become the
        # box with its space stripped ("Afirewall"), which the text check
        # cannot see.
        glyph = mark_text.strip()
        if len(glyph) == 1 and (glyph in "xX" or not glyph.isalnum()):
            box = mark
            for t in box.iter(qn("w:t")):
                t.text = (t.text or "").strip()
                t.set(qn("xml:space"), "preserve")
        else:
            box = copy.deepcopy(mark)
            for child in list(box):
                if child.tag != qn("w:rPr"):
                    box.remove(child)
            text = OxmlElement("w:t")
            text.text = " "
            box.append(text)
            mark.addprevious(box)
        properties = box.find(qn("w:rPr"))
        if properties is None:
            properties = OxmlElement("w:rPr")
            box.insert(0, properties)
        # The box is as wide as `fitText` says; a condensation the label's
        # line was given before the fold would squeeze it as well.
        for tag in ("w:bdr", "w:fitText", "w:spacing"):
            for existing in properties.findall(qn(tag)):
                properties.remove(existing)
        border = OxmlElement("w:bdr")
        border.set(qn("w:val"), "single")
        border.set(qn("w:sz"), str(max(2, min(96, int(round(stroke))))))
        border.set(qn("w:space"), "0")
        border.set(qn("w:color"), colour)
        insert_ordered(properties, border, RPR_ORDER)
        fit = OxmlElement("w:fitText")
        fit.set(qn("w:val"), str(int(round(wide * 20))))
        fit.set(qn("w:id"), str(900000 + folded))
        insert_ordered(properties, fit, RPR_ORDER)
        before = table.getprevious()
        stub = None
        if (before is not None and before.tag == qn("w:p") and not paragraph_text(before).strip()
                and not any(True for _ in before.iter(qn("w:drawing"), qn("w:pict")))):
            above = before.getprevious()
            if above is None or above.tag in (qn("w:tcPr"), qn("w:tblPr")):
                stub = paragraph_metrics(before)
                before.getparent().remove(before)
        if stub is not None:
            place_folded_label(label, stub["before"] + stub["lines"] * stub["line"] + stub["after"], tall, mark)
        elif before is not None and before.tag == qn("w:p") and paragraph_text(before).strip():
            # Items stacked in one cell carry the gap to the next box as the
            # spacing after the item above, and no spacer of their own.
            above = paragraph_metrics(before)
            if above is not None:
                set_spacing(before, after=0.0)
                place_folded_label(label, above["after"], tall, mark)
        table.getparent().remove(table)
        folded += 1
    return folded


def decorate_document(document, look, anchors, started, budget_seconds, repairs, place=True):
    """Everything that makes a converted file look like the PDF it came from.

    Two levels. `place=True` is the whole of it: a run of code becomes a panel
    table, a picture is cropped to the part of it the PDF shows, each
    paragraph is broken where the PDF broke it, and the layout passes put
    blocks, tables and the text inside a cell on the PDF's own baselines.

    `place=False` leaves the structure exactly as the converter wrote it:
    paragraphs are shaded where a panel would have been built, and nothing is
    broken, cropped, cut or moved. That is the rung below the fallback, for a
    document that has lost text with both repairs already off, where the only
    passes left to suspect are the ones that rearrange what the converter
    wrote. It costs the file its resemblance to the PDF and is never the first
    answer.

    Returns `(swatches, warnings)`. `repairs` is what the passes before this
    one cost, which is the only measure of the document's size the budget has.
    """
    warnings = []
    skip = look.get("skip", frozenset())
    started_look = time.monotonic()
    panels = [] if "panels" in skip else look["panels"]
    shaded, panel_tables = shade_run_of_paragraphs(document, panels, plain=not place,
                                                   declined=look["declined"], page_count=len(anchors) or None)
    swatches = [] if "swatches" in skip else look["swatches"]
    squares = restore_swatches(document, swatches, look["face"])
    aligned = [] if "align" in skip else look["aligned"]
    align_paragraphs(document, aligned, declined=look["declined"], page_count=len(anchors) or None,
                     content_right=look.get("contentRight"))
    if "align" not in skip:
        left_align_cell_list_items(document, look["declined"])
    if place and "pictures" not in skip:
        _, frame_anchors = fit_pictures(document, look["pictures"])
        rejoin_side_pictures(document, look["pictures"], look["declined"])
        centre_lone_pictures(document, look["declined"])
    if place and "margin-notes" not in skip and look.get("pageWidths"):
        float_margin_notes(document, anchors, look["pageWidths"], look["declined"])
        panel_tables = list(panel_tables) + frame_anchors
        resize_column_rows(document)
    repairs += time.monotonic() - started_look
    room = affordable(started, budget_seconds, repairs)
    if place and room and look["lineBreaks"] == "pdf" and "line-breaks" not in skip:
        return_split_dashes(document, look.get("lines") or [], shaded, page_count=len(anchors) or None)
        force_line_breaks(document, look["aligned"], shaded, page_count=len(anchors) or None,
                          content_right=look.get("contentRight"))
        break_cell_lines(document, look.get("lines") or [], shaded, page_count=len(anchors) or None)
        # Again: a cell's lines are cut with plain lines, which leave a dash
        # where the count puts it, at the start of the next line.
        return_split_dashes(document, look.get("lines") or [], shaded, page_count=len(anchors) or None)
        condense_cell_lines(document, look.get("lines") or [], shaded, page_count=len(anchors) or None)
        break_before_list_items(document, look.get("lines") or [], shaded, page_count=len(anchors) or None)
        if "hanging" not in skip:
            restore_list_hanging(document, look.get("lines") or [], shaded, page_count=len(anchors) or None,
                                 declined=look["declined"])
    if place and not room:
        warnings.append(CROWDED_OUT)
    # Text, not layout, so it runs at every rung: the fallback's file needs
    # its Hebrew and Arabic words apart as much as the first one does. The
    # last rung restructures nothing, so there it only rewrites whitespace.
    if (look.get("rtl") or look.get("rtlAmbiguous")) and "rtl" not in skip:
        restore_rtl(document, look["rtl"], look["declined"], reorder=place,
                    ambiguous=look.get("rtlAmbiguous", ()))
    if "text-repair" not in skip:
        repair_text(document, look["pairs"], shaded)
        restore_cut_lines(document, look.get("lines") or [], shaded)
    if "hyphens" not in skip:
        restore_break_hyphens(document, look["broken"], shaded)
    # Last, because it reads the spacing and the line count of every block the
    # passes above have finished writing.
    if place and room:
        seams = [] if "pitch-cut" in skip else split_pitch_changes(document, anchors, shaded)
        if "rhythm" not in skip:
            fold_leading_space_into_margin(document)
            align_vertical_rhythm(document, anchors, look["height"], panel_tables, look["rules"],
                                  seams, look["boxes"], declined=look["declined"])
    # After the rhythm pass: it has put each label where the stacked layout
    # (spacer, box, label) needs it, and this pass reads the spacer's height
    # off the result.
    if place:
        fold_checked_boxes(document)
    if place and "labels" not in skip:
        rebuild_label_boxes(document, look.get("labels") or [], look.get("contentLeft"), look["declined"])
    if "page-start" not in skip:
        look["pageBreaks"] = ensure_page_starts(
            document, [page[0]["key"] for page in list(anchors)[1:] if page], look["declined"],
            pages=len(anchors) or None)
    # Every rung, the plain one included: this removes nothing the PDF has
    # and moves nothing, it only stops the converter's own tail from costing
    # a page.
    trim_section_tails(document)
    drop_tall_empty_tables(document)
    relax_overfull_rows(document)
    strip_column_marks(document)
    name_runs(document, look["plan"])
    fill_bare_runs(document)
    # After everything that reads paragraphs, `fill_bare_runs` included: it
    # walks every `w:p` below a paragraph, a text box's too, and an empty
    # paragraph takes its mark's font from the nearest paragraph with text, so
    # an 82 pt watermark made the mark of 41 empty paragraphs 82 pt tall (the
    # pages' first lines, measured). The boxes are named and filled by hand.
    if look.get("rotated") and "rotated" not in skip:
        restore_rotated_lines(document, look["rotated"], look["declined"], page_rows_of=anchors)
    if look.get("plainFills") and "page-fills" not in skip:
        restore_page_fills(document, look["plainFills"], look["declined"])
    return squares, warnings


def redo_plainly(source, part, look, anchors, started, budget_seconds, place):
    """Convert the untouched PDF again and decorate it at the given level.

    The abandoned rung's declines go with its file: `look["declined"]` starts
    again from the counts made before any rung (`look["baseDeclined"]`).
    """
    look["declined"] = Counter(look["baseDeclined"])
    look["pageBreaks"] = 0
    run_pdf2docx(source, part, look["plan"], declined=look["declined"])
    if not os.path.exists(part) or os.path.getsize(part) == 0:
        raise ConvertError("the converter produced no Word file")
    document = Document(part)
    if place and "columns" not in look.get("skip", frozenset()):
        fold_column_sections(document)
    squares, warnings = decorate_document(document, look, anchors, started, budget_seconds,
                                          0.0, place)
    return document, squares, warnings


def set_aside(tried, part, missing, declined, written, bands, squares, warnings, lines, fell_back, look):
    """Keep a rung's file and what it reported before the ladder climbs down from it."""
    path = "%s.rung%d" % (part, len(tried) + 1)
    shutil.copyfile(part, path)
    tried.append({"path": path, "missing": list(missing), "declined": Counter(declined), "written": written,
                  "bands": bands, "squares": squares, "warnings": list(warnings), "lines": lines,
                  "fellBack": fell_back, "pageBreaks": look.get("pageBreaks", 0)})


def better_rung(tried, missing):
    """The highest rung set aside whose only losses are the PDF's own, or None.

    The ladder climbs down because a repair may have deleted text, and a rung
    further down is safer only if it gets some of that text back. A rung is
    put back when every line it lost is text the PDF draws on top of other
    text (`overprinted`) and the last rung lost each of those lines too: that
    text could not be read in the PDF and pdf2docx keeps none of it with every
    pass off, so it was never the repairs' to lose, and the rung above is the
    same text with its header, footer and layout. A line is counted as often
    as it was lost, so a rung that lost a second copy is not taken for one
    that lost the first.

    Losing the same legible lines on every rung is not enough. The passes a
    rung below turns off can cost a document more than they give it: on the
    corpus's rtl-mixed the top rung, put back that way, scored 0.7817 against
    0.7906 for the rung the ladder kept and 0.7903 for raw pdf2docx.
    """
    final = Counter(missing)
    for rung in tried:
        lost = rung["missing"]
        if (lost and not Counter(lost) - final
                and len(overprinted_missing(rung["lines"], lost)) == len(lost)):
            return rung
    return None


def overprinted_missing(lines, missing):
    """The missing lines the PDF draws on top of other text, each as its line."""
    left = Counter(missing)
    out = []
    for line in lines:
        if line.get("overprinted") and left[line["text"]] > 0:
            left[line["text"]] -= 1
            out.append(line)
    return out


def affordable(started, budget, repairs):
    """Is there time left for the passes that only make the file look right?

    The two that grow with the document, breaking each paragraph where the PDF
    broke it and putting every block on its own baseline, are worth their cost
    on a report and not worth a timeout on a monster. What they will cost is
    estimated from what this document has already cost: the repairs that have
    to run whatever happens walk the same paragraphs, so their measured time is
    the size of the document in the only unit that matters here. Measured over
    the reference report, a 23-page prose document and a 25-page table of 1,249
    rows, the two fidelity passes together come to about half of the repairs
    before them and the text check after them to about one and a half times, so
    the reservation below has roughly a two times margin over both.

    The text check and the link check are never part of this decision. They are
    what says the Word file still holds the PDF's words, and a file that has
    not been checked is worth less than one that sits a point out of place.
    """
    if budget is None:
        return True
    return budget - (time.monotonic() - started) > repairs * (FIDELITY_COST_RATIO + CHECK_COST_RATIO)


def font_conversion_allowance(started, budget):
    """The seconds left that redrawing a font's outlines may spend.

    Redrawing one face costs 1.0 to 4.9 seconds, measured over the thirteen
    OpenType faces this repo ships, and a family is four of them, so it is
    the one step here that can be worth several seconds and is still optional:
    without it Word substitutes, which is bad, and past the deadline the
    caller gets nothing at all, which is worse. So it is given what is left
    after the file has been written and a margin kept for writing it, and it
    stops converting when that runs out rather than starting a face it cannot
    finish.
    """
    if budget is None:
        return None
    return max(0.0, budget - (time.monotonic() - started) - FONT_WRITE_RESERVE_S)


def convert(pdf_path, docx_path, budget_seconds=None, line_breaks="pdf", font_dirs=(),
            convert_fonts=True, raw=False, skip=frozenset()):
    """Read the PDF, decide the repairs, convert, and check nothing was lost.

    The two repairs delete part of the document and write something back, and
    a heuristic that deletes the wrong thing would leave a Word file that
    still looks like a report. So the result is compared against the PDF's own
    text, and a conversion that lost any of it is thrown away and done again
    with both repairs off. That second file keeps the bands in the body and
    may run to more pages than the PDF, which is said plainly rather than
    silently traded for a page count.
    """
    warnings = []
    # --raw is every pass off and pdf2docx's own file, with only the font
    # steps that are guarantees kept.
    skip = frozenset(SKIPPABLE) if raw else frozenset(skip)
    # What the passes declined, for the file that is kept. align-rtl is
    # counted once, before any rung, and every rung is built with it; each
    # rung then starts again from that, and --raw, which runs no pass,
    # reports nothing.
    base_declined = Counter()
    tagged_copy = None
    doc = pymupdf.open(pdf_path)
    try:
        if doc.page_count == 0:
            raise ConvertError("the PDF has no pages")
        refuse_oversized(doc)
        pages = doc.page_count
        page_height = doc[0].rect.height
        content_left, content_right = content_bounds(doc)
        removed_links = drop_unsafe_pdf_links(doc)
        if removed_links:
            warnings.append(
                "%d link(s) with unsupported addresses were removed from the Word file." % removed_links
            )
        bands = []
        # Read once: the band step and the contents gate both ask. None when
        # the catalog cannot be read, which each of them treats as it would
        # any other failure to read the tags.
        try:
            marked = tagged.is_tagged(doc)
        except Exception:  # noqa: BLE001 - an unreadable catalog is not a reason to fail the export
            marked = None
        # A tagged PDF names its own header and footer, and that is used
        # before any guess is. The decline counts go in `base_declined`, the
        # counts every rung starts from, because they say which path read
        # the document rather than what one rung did.
        found = None if "bands" in skip else detect_tagged_bands(doc, base_declined, marked)
        if found:
            bands = found[0]
            # The copy the converter reads. It is made again rather than kept
            # from the reading, and it has to remove what the first one did
            # on every page; anything else and the bands stay in the body.
            try:
                lifted = band_subtypes(bands)
                again = tagged.stripped_copy(doc) if lifted == TAGGED_SUBTYPES else tagged.stripped_copy(doc, lifted)
            except Exception:  # noqa: BLE001 - never a reason to fail the export
                again = None
            if again is not None and again[1] == found[1]:
                tagged_copy = again[0]
            else:
                if again is not None:
                    again[0].close()
                bands = []
                base_declined["bands-tagged-restrip"] += 1
                warnings.append(
                    "The running header and footer could not be removed from the PDF a second time, so "
                    "they stay in the page body and the page count may differ from the PDF."
                )
        elif "bands" not in skip:
            for edge, name in (("top", "header"), ("bottom", "footer")):
                band, reason = detect_band(doc, edge)
                if band:
                    bands.append(band)
                elif reason:
                    warnings.append(
                        "The running %s could not be lifted out safely (%s), so it stays in the page body "
                        "and the page count may differ from the PDF." % (name, reason)
                    )
                else:
                    warnings.append(
                        "No repeating %s was found, so the Word file has none and its page count may "
                        "differ from the PDF." % name
                    )
        # A tagged band carries the paper it was read on, so a report with
        # sideways pages keeps them; the heuristic's geometry is one set of
        # numbers for the whole document.
        if bands and uniform_page_size(doc) is None and any(b.get("source") != "tagged" for b in bands):
            bands = []
            base_declined["bands-mixed-sizes"] += 1
            warnings.append(
                "This report mixes page sizes, so the running header and footer stay in the page body "
                "and the page count may differ from the PDF."
            )
        # Which path's bands the file carries, counted only once they have
        # survived every check above.
        if bands:
            base_declined["bands-tagged" if found else "bands-heuristic"] += 1
        elif tagged_copy is not None:
            tagged_copy.close()
            tagged_copy = None
        if "toc" in skip:
            entries = []
        else:
            try:
                # A tagged PDF says where its contents page is; a dot-leader
                # list with no TOC element behind it is a price list, not a
                # table of contents. A tag tree that cannot be read says
                # nothing, and the contents page is looked for as in an
                # untagged PDF.
                toc_untagged = bool(marked) and "/TOC" not in tagged.struct_types(doc)
            except Exception:  # noqa: BLE001 - an unreadable tag tree falls back to detect_toc
                toc_untagged = False
            if toc_untagged:
                entries = []
                base_declined["toc-untagged"] += 1
            else:
                entries = detect_toc(doc, bands)
        band_pages = sorted({index for band in bands for index in band["pages"]})
        page_sizes = [page_size(doc[index]) for index in range(pages)]
        repaired_lines = body_lines(doc, bands)
        plain_lines = body_lines(doc, [])
        # Lines pdf2docx would drop for their direction, read with the rest of
        # the page while the PDF is open and written back as text boxes.
        rotated = []
        if "rotated" not in skip:
            try:
                rotated = rotated_lines(doc)
            except Exception:  # noqa: BLE001 - lines left unwritten are reported by the text check, so never a reason to fail
                base_declined["rotated-unreadable"] += 1
        plain_fills = []
        if "page-fills" not in skip:
            try:
                plain_fills = page_fills(doc, {member for band in bands for member in band.get("members") or ()})
            except Exception:  # noqa: BLE001 - a fill left out is a missing decoration, never a reason to fail the export
                base_declined["page-fills-unreadable"] += 1
        # Read before the bands are erased, so a panel that reaches into the
        # band zone is still described, and kept for the post-processing pass
        # that runs once the converter has produced a file.
        pictures = pdf_pictures(doc)
        anchors = page_anchor_rows(doc, bands)
        rules = page_edges(doc)
        drawn_boxes = page_boxes(doc)
        labels = label_boxes(doc)
        # The fallback keeps the bands in the body, so its pages carry rows
        # this one does not and the targets have to be read again without them.
        plain_anchors = anchors if not bands else page_anchor_rows(doc, [])
        # Read the staged fonts before anything is written, because what the
        # bands and the table of contents are named depends on what the font
        # files call themselves.
        font_plan = fonts.plan(fonts.pdf_faces(doc, pdf_base_name), fonts.collect(font_dirs)) if font_dirs else None
        name_looks(bands, font_plan)
        name_looks(entries, font_plan)
        name_looks(rotated, font_plan)
        swatch_face = fonts.face_for_char(font_plan, ord(FILLED_SQUARE))
        panels, swatches = find_decoration(doc, bands)
        pairs = spaced_pairs(doc)
        broken = broken_words(doc, bands)
        aligned = flush_left_runs(doc, bands, content_left, content_right)
        annotate_runs(doc, bands, aligned, content_left, content_right)
        # The alignment and line-break passes were built on left-to-right
        # paragraphs and have never been measured on anything else, so a
        # right-to-left paragraph is left where the converter put it.
        kept = []
        for run in aligned:
            if any(is_rtl(line) for line in run["lines"]):
                if "align" not in skip:
                    base_declined["align-rtl"] += 1
            else:
                kept.append(run)
        aligned = kept
        rtl_pieces = [piece for line in plain_lines if not line.get("ambiguous")
                      for piece in (line["pieces"] or [line["text"]]) if has_rtl(piece)]
        rtl_ambiguous = [piece for line in plain_lines if line.get("ambiguous")
                         for piece in (line["pieces"] or [line["text"]]) if has_rtl(piece)]
        typed_hyphens = typed_soft_hyphens(doc, bands)
        # Two inputs: the PDF as it stands, for the fallback, and a copy with
        # the bands erased, for the repaired pass. Tagged bands are erased by
        # removing the artifact blocks that drew them, so nothing near them
        # goes too; the rectangle erase is for the heuristic's bands.
        plain_pdf = docx_path + ".plain.pdf"
        doc.save(plain_pdf, garbage=3, deflate=True)
        stripped_pdf = plain_pdf
        if bands:
            stripped_pdf = docx_path + ".stripped.pdf"
            if found:
                tagged_copy.save(stripped_pdf, garbage=3, deflate=True)
            else:
                strip_bands(doc, bands)
                doc.save(stripped_pdf, garbage=3, deflate=True)
    finally:
        if tagged_copy is not None:
            tagged_copy.close()
        doc.close()

    part = docx_path + ".part"
    written = 0
    fell_back = False
    declined = Counter()
    look = {}
    # Each rung the ladder climbs down from, kept so it can be put back if
    # the rungs below it lose the same text (`set_aside`, `better_rung`).
    tried = []
    try:
        started = time.monotonic()
        if raw:
            run_pdf2docx(plain_pdf, part, font_plan, raw=True)
            if not os.path.exists(part) or os.path.getsize(part) == 0:
                raise ConvertError("the converter produced no Word file")
            document = Document(part)
            name_runs(document, font_plan)
            fill_bare_runs(document)
            document.save(part)
            squares = []
            repair_warnings = []
            checked_lines = plain_lines
            missing = missing_from_docx(plain_lines, docx_text(part, body_only=False))
        else:
            declined = Counter(base_declined)
            run_pdf2docx(stripped_pdf, part, font_plan, declined=declined)
            first_pass = time.monotonic() - started
            if not os.path.exists(part) or os.path.getsize(part) == 0:
                raise ConvertError("the converter produced no Word file")
            repair_warnings = []
            document = Document(part)
            repairs = time.monotonic()
            # First, because every pass after it counts sections to find pages.
            if "columns" not in skip:
                fold_column_sections(document)
            written, toc_warnings = rebuild_toc(document, entries, content_left, content_right, declined,
                                                page_groups=sections_by_page(document, page_sizes))
            repair_warnings.extend(toc_warnings)
            # A tagged header and footer on different pages need a Word section
            # per PDF page to be given apart; without one they are not lifted.
            page_map = sections_by_page(document, page_sizes)
            pages_apart = bool(bands) and bands_need_pages(bands) and page_map is None
            if bands and not pages_apart:
                if page_map is None:
                    bare = [i for i in range(1, pages) if i not in band_pages]
                    if bare:
                        repair_warnings.append(
                            "%d page(s) after the first carry no running header or footer in the PDF; "
                            "Word repeats one on every page but the first." % len(bare)
                        )
                repair_warnings.extend(apply_bands(document, bands, page_height, content_left, content_right, pages,
                                                   page_sizes))
            repairs = time.monotonic() - repairs
            look = {"panels": panels, "swatches": swatches, "face": swatch_face, "aligned": aligned, "lines": plain_lines,
                    "contentRight": content_right, "contentLeft": content_left,
                    "pictures": pictures, "pairs": pairs, "broken": broken, "rules": rules,
                    "boxes": drawn_boxes, "labels": labels, "height": page_height, "lineBreaks": line_breaks,
                    "plan": font_plan, "skip": skip, "declined": declined, "baseDeclined": base_declined,
                    "rtl": rtl_pieces, "rtlAmbiguous": rtl_ambiguous, "rotated": rotated,
                    "plainFills": plain_fills, "pageWidths": [size[0] if size else 0.0 for size in page_sizes]}
            squares, look_warnings = decorate_document(document, look, anchors, started,
                                                       budget_seconds, repairs)
            repair_warnings.extend(look_warnings)
            document.save(part)
            missing = missing_from_docx(repaired_lines, docx_text(part, body_only=bool(bands)))
            if bands and not pages_apart and page_map is not None:
                missing = missing + band_text_gaps(document, bands, page_map)
            checked_lines = repaired_lines
            if bands and not repaired_lines:
                # Everything on every page was a band member, so the check had
                # nothing to compare and would otherwise report a clean pass on a
                # document whose whole body was lifted into the header.
                missing = ["(the whole document was read as a running header or footer)"]
            if pages_apart:
                # Counted where every rung starts from, so the file that is
                # kept says why its header and footer stayed in the body.
                base_declined["bands-pages-apart"] += 1
                missing = missing or ["(the header and footer cover different pages and Word has no section per page)"]

            if missing and (bands or written):
                # Doing it again costs about what the first pass cost, and the
                # server kills the child at its own timeout with a message that
                # says nothing useful. Better to stop here and say why.
                if budget_seconds is not None and time.monotonic() - started + first_pass > budget_seconds:
                    raise ConvertError(
                        "The header and footer repair lost text and there was not enough time to convert "
                        "again. Export the PDF instead."
                    )
                # Something the repairs touched is gone. Convert again with both
                # of them off and keep that file instead, whatever it costs in
                # page count: a Word file that reads wrong is recoverable, one
                # that is missing a finding is not.
                set_aside(tried, part, missing, declined, written, bands, squares, repair_warnings,
                          checked_lines, fell_back, look)
                fell_back = True
                repair_warnings = [
                    "The header and footer could not be lifted safely on this report, so the Word file "
                    "keeps them in the page body and its page count may differ from the PDF."
                ]
                document, squares, more = redo_plainly(plain_pdf, part, look, plain_anchors,
                                                       started, budget_seconds, place=True)
                declined = look["declined"]
                repair_warnings.extend(w for w in more if w not in repair_warnings)
                document.save(part)
                written = 0
                bands = []
                checked_lines = plain_lines
                missing = missing_from_docx(plain_lines, docx_text(part, body_only=False))

            if missing and (budget_seconds is None
                            or time.monotonic() - started + first_pass <= budget_seconds):
                # The rung below the fallback. The two repairs are off already and
                # text is still short, so what is left to suspect is the passes
                # that rebuild a run of paragraphs into a panel, crop a picture,
                # break a line where the PDF broke it or move a block, a table or
                # the text inside a cell. Give all of them up too: this file will
                # look less like the PDF than the one it replaces, and it is the
                # closest thing to what the converter itself produced, which is
                # the best place to stand when a finding has gone missing.
                set_aside(tried, part, missing, declined, written, bands, squares, repair_warnings,
                          checked_lines, fell_back, look)
                fell_back = True
                document, squares, more = redo_plainly(plain_pdf, part, look, plain_anchors,
                                                       started, budget_seconds, place=False)
                declined = look["declined"]
                repair_warnings.extend(w for w in more if w not in repair_warnings)
                document.save(part)
                written = 0
                bands = []
                checked_lines = plain_lines
                missing = missing_from_docx(plain_lines, docx_text(part, body_only=False))
                repair_warnings.append(PLAIN_LAYOUT)

            kept = better_rung(tried, missing)
            if kept is not None:
                # Climbing down brought none of the lost text back, so the file
                # it cost is no safer than the one above it, only plainer.
                os.replace(kept["path"], part)
                missing, declined, written, bands = kept["missing"], kept["declined"], kept["written"], kept["bands"]
                squares, repair_warnings, checked_lines = kept["squares"], kept["warnings"], kept["lines"]
                fell_back = kept["fellBack"]
                look["pageBreaks"] = kept["pageBreaks"]

        warnings.extend(repair_warnings)
        if missing:
            # Still short after the fallback: this is the converter itself
            # dropping text, and nothing here can put it back. Name it.
            sample = "; ".join(truncate(line, 60) for line in missing[:2])
            warnings.append(
                "%d line(s) of the PDF could not be found in the Word file, starting with \"%s\". "
                "Compare the two before sending." % (len(missing), sample)
            )
        stacked = overprinted_missing(checked_lines, missing)
        if stacked:
            warnings.append(
                "%d of the missing line(s) are printed on top of other text on PDF page %s, so they "
                "cannot be read in the PDF either. A table too tall for one page inside a figure does "
                "this, because typst will not split a figure; `#show figure: set block(breakable: true)` "
                "lets it continue on the next page."
                % (len(stacked), ", ".join(str(page) for page in sorted({line["page"] for line in stacked})))
            )
        unsafe = unsafe_docx_targets(part)
        if unsafe:
            raise ConvertError(
                "the Word file came out with a link this server does not allow (%s)"
                % truncate(unsafe[0], 60)
            )
        embedded, skipped, redrawn = ([], [], [])
        if font_plan:
            # A report's fonts and its chosen families are attacker-influenced
            # (invariant #18), and by this point the document has already
            # passed the text check and the link check. A bug or a fontTools
            # edge case in the font step must degrade to a warning rather than
            # throw away a finished, checked document.
            try:
                embedded, skipped, redrawn = fonts.embed(
                    part, font_plan, convert_fonts, font_conversion_allowance(started, budget_seconds))
            except Exception:  # noqa: BLE001 - losing the document over a font bug is the worse failure
                embedded, skipped, redrawn = [], [], []
                warnings.append(
                    "Fonts could not be embedded because of an internal error, so on a computer "
                    "without them Word will substitute other fonts."
                )
            else:
                for family, why in skipped:
                    warnings.append(
                        "%s could not be embedded (%s), so on a computer without it Word will substitute "
                        "another font and some lines may wrap twice." % (family, why)
                    )
                if redrawn:
                    warnings.append(
                        "%s had outlines of a kind Word will not carry, so they were redrawn as TrueType "
                        "to go in the file. Every advance width is unchanged, so no line moves."
                        % ", ".join(redrawn)
                    )
        if squares and swatch_face is None:
            warnings.append(
                "A chart legend's colour squares are set in a character none of this report's fonts "
                "has, so Word will choose a font for them."
            )
        os.replace(part, docx_path)
    finally:
        for temporary in [plain_pdf, stripped_pdf] + [rung["path"] for rung in tried]:
            with contextlib.suppress(OSError):
                os.remove(temporary)

    if typed_hyphens:
        warnings.append(
            "%d invisible soft hyphen(s) that were typed into the report were removed." % typed_hyphens
        )
    if written:
        warnings.append("%d table-of-contents entries were rebuilt." % written)
    return {
        "ok": True,
        "pages": pages,
        "headerFooter": {
            "header": any(b["edge"] == "top" for b in bands),
            "footer": any(b["edge"] == "bottom" for b in bands),
            "pagesWithBands": len({index for band in bands for index in band["pages"]}),
        },
        "lineBreaks": line_breaks,
        "fontsEmbedded": embedded,
        "fontsRedrawn": redrawn,
        "tocEntries": written,
        "pageBreaksInserted": look.get("pageBreaks", 0),
        "mode": "raw" if raw else "full",
        "skipped": sorted(skip),
        "declined": dict(declined),
        "textCheck": {"pdfLines": len(checked_lines), "missing": len(missing), "fellBack": fell_back,
                      "overprinted": len(overprinted_missing(checked_lines, missing))},
        "warnings": warnings,
    }


def write_result(path, payload):
    with contextlib.suppress(OSError):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True)


def cap_address_space():
    """Bound this process on Linux, where `resource` exists.

    The relay process is the cgroup's other tenant, so a conversion that runs
    away should be the one that dies, with a message, rather than leaving the
    kernel to choose. The limit is on address space rather than RSS because
    that is what `resource` offers, and PyMuPDF and OpenCV map far more than
    they touch: measured on the 120,000-shape document, 651 MB of RSS against
    a little over 2 GB mapped, which is why the number is 3 GB and not 768 MB.
    Below about 2.5 GB the import of OpenCV itself fails, so a tighter limit
    would refuse every export rather than only the runaway one. That figure
    holds only with the numeric libraries on one thread (the top of this
    file): left to size their pools to a 24-core host, the same import maps
    4.4 GB and dies of SIGSEGV under this limit before converting anything.
    Windows has no `resource` module and relies on the page, shape and size
    bounds instead.

    On the 1 GB box this server is built for the limit is inert: the cgroup
    kills the child long before 3 GB of address space is mapped, and the
    existing "a SIGKILL we did not send is the memory killer" mapping turns
    that into a 422. It earns its place on a larger host, where nothing else
    would stop one export taking the machine.
    """
    try:
        import resource
    except ImportError:
        return False
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    want = ADDRESS_SPACE_LIMIT_BYTES
    if hard != resource.RLIM_INFINITY:
        want = min(want, hard)
    if soft != resource.RLIM_INFINITY and soft <= want:
        return False
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (want, hard))
        return True
    return False


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    # Developer switches, for finding which pass a regression comes from.
    # Read before anything else so a typo is a usage error and nothing runs.
    raw = "--raw" in flags
    skip = set()
    for flag in flags:
        if flag.startswith("--skip="):
            skip |= {name for name in flag.split("=", 1)[1].split(",") if name}
    unknown = sorted(skip - set(SKIPPABLE))
    if unknown:
        print("unknown pass name(s) for --skip: %s (known: %s)" % (", ".join(unknown), ", ".join(SKIPPABLE)),
              file=sys.stderr)
        return 2
    if len(args) not in (3, 4):
        print("usage: convert.py [--line-breaks=pdf|word] [--fonts=DIR] [--no-font-conversion]"
              " [--raw] [--skip=PASS,...] <in.pdf> <out.docx> <result.json> [budget]", file=sys.stderr)
        return 2
    cap_address_space()
    pdf_path, docx_path, result_path = args[0], args[1], args[2]
    # `pdf` reproduces the PDF's own line endings, which is what the report
    # is for; `word` lets Word re-flow, which reads better under editing.
    line_breaks = "pdf"
    for flag in flags:
        if flag.startswith("--line-breaks="):
            line_breaks = "word" if flag.split("=", 1)[1] == "word" else "pdf"
    # Directories holding the report's own fonts and the defaults the
    # browser compiler ships, so the families the PDF names can be found
    # as files and carried into the Word file.
    font_dirs = [flag.split("=", 1)[1] for flag in flags if flag.startswith("--fonts=")]
    # Word carries TrueType outlines only, so a PostScript-outline face is
    # redrawn on the way in. This turns that off, for anyone who would rather
    # ship a font Word substitutes for than one it has redrawn.
    convert_fonts = "--no-font-conversion" not in flags
    # How long the caller will wait, so the decision to convert a second time
    # is made here rather than by a SIGKILL with a generic message.
    budget = None
    if len(args) == 4:
        with contextlib.suppress(ValueError):
            budget = max(1.0, float(args[3]))
    try:
        result = convert(pdf_path, docx_path, budget_seconds=budget, line_breaks=line_breaks,
                         font_dirs=font_dirs, convert_fonts=convert_fonts,
                         raw=raw, skip=frozenset(skip))
    except ConvertError as err:
        write_result(result_path, {"ok": False, "message": str(err)[:300]})
        print(str(err)[:300], file=sys.stderr)
        return 1
    except Exception as err:  # noqa: BLE001 - a short message is all the caller gets
        message = ("%s: %s" % (type(err).__name__, err))[:300]
        write_result(result_path, {"ok": False, "message": message})
        print(message, file=sys.stderr)
        return 1
    write_result(result_path, result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
