#!/usr/bin/env python3
"""Carry the report's fonts into the Word file, so it reads the same anywhere.

A Word file names its fonts and expects the reader's machine to have them.
This one is made from a PDF and, since the owner asked for the PDF's line
endings to be reproduced exactly, a substituted font does not merely look
different: a line that fitted the column becomes one that does not, and the
page re-wraps. So the fonts go in the file.

**Word looks a font up by the name in its own name table, and by nothing
else.** A PDF names a font by its PostScript name, `DejaVuSansMono` or
`Poppins-SemiBold`, and that is not the name Word asks for. Word asks for
name ID 1, the legacy family (`DejaVu Sans Mono`, `Poppins SemiBold`), plus
the bold and italic bits, which the font states in name ID 2. A face declared
under its PostScript name is a face Word never finds, embedded or not, and it
substitutes in silence. So every name written into the document comes from
the font file's own tables: `w:rFonts` on the run, `w:font w:name` in the
table, and the four embed slots under it.

Name ID 2 only ever says Regular, Bold, Italic or Bold Italic, because those
four are all Word keeps per family. A weight outside them, SemiBold say, is a
family of its own: name ID 1 is `Poppins SemiBold` and name ID 2 is
`Regular`. Asking for `Poppins` with the bold bit on gets a different face
with a fake weight painted over it, so that record is read whole rather than
searched: `SemiBold` is not `Bold`, and `BoldItalic` is both. See `style_of`,
where each of those was a bug before it was a rule.

The embedding format is awkward but small. Each font is a part under
`word/fonts/` whose first 32 bytes are XORed with a key taken from the part's
own GUID, the relationship from `word/fontTable.xml` names it under
`w:embedRegular` and friends with that GUID as `w:fontKey`, and
`word/settings.xml` has to say `w:embedTrueTypeFonts`. `w:saveSubsetFonts` is
deliberately left off: the whole font goes in, so the file stays editable
rather than carrying only the glyphs this report happened to use. For the
same reason a family that the report uses at all is carried whole, up to its
four slots, rather than only in the faces the report set text in.

**The font is read before it is carried.** fontTools opens a file and
decompiles a table only when one is asked for, so a font truncated to a third
of itself answers every question about its name and its licence and fails only
when a reader asks it to draw something. So the tables a usable font needs are
required by name and one real outline is decompiled; a file that cannot manage
that is skipped as damaged. The bytes are bounded too, at 15 MB for one face
and 40 MB for the file, because the export as a whole is capped at 100 MB.

**Word carries TrueType outlines and nothing else.** A font whose outlines
are PostScript, the `.otf` flavour, can be written into the package and
declared in the table and Word will still substitute. That is measured, not
assumed: `font_probe.py` made one probe family of each kind out of the same
report, and Word's render came back with the TrueType family and with Calibri
where the other one should have been. It is not a rare case either, because
typst's own default font is one of them, so such a face is **redrawn** on the
way in: every cubic curve is approximated by a quadratic within a thousandth
of an em, and everything a line's width depends on, the advance widths, the
vertical metrics, the kerning and the shaping tables, is left exactly as it
was. Only the side bearings move, and only to the redrawn outline's own left
edge. See `to_truetype`.

**Licences are read, not assumed.** The OS/2 table's `fsType` says what the
foundry allows. 0 is installable, 8 is editable, 4 is preview and print, and
2 is restricted. The first two are embedded and the other two are skipped and
named in a warning, so whoever sends the file knows a reader without the font
will see something else. Preview and print is refused for a reason of its
own: Word honours that bit by opening the document read-only, which takes
away the one thing this export is for.

Redrawing the outlines is a modification, which is a second question and gets
a second answer: the licence name records are read too, and a face is only
redrawn under a licence that is recognised here as allowing it. An
unrecognised licence is refused and named rather than guessed at. The
embedded copy keeps the family name it came with, because that name is the
only thing Word matches on, so this is not a renamed derivative anybody
receives as a font: it is the same face inside one document.
"""

import os
import re
import time
import uuid
import zipfile

CONTENT_TYPES = "[Content_Types].xml"
FONT_TABLE = "word/fontTable.xml"
SETTINGS = "word/settings.xml"
FONT_TABLE_RELS = "word/_rels/fontTable.xml.rels"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
FONT_REL_TYPE = R_NS + "/font"
# OS/2 fsType. Bit 1 means the foundry forbids embedding outright; bit 9 means
# only a bitmap may be embedded, which a Word file cannot do.
FS_RESTRICTED = 0x0002
# Bit 2 means a reader may look at the document and print it and may not edit
# it, and Word honours that by opening the whole document read-only. See
# `embeddable`.
FS_PREVIEW_PRINT = 0x0004
FS_BITMAP_ONLY = 0x0200
# The tables a font needs before Word can lay a line out with it. Outlines are
# in `glyf` or in one of the two CFF flavours; the rest are what a reader has
# to have to map a character to a glyph and to advance the pen. fontTools will
# open a file that has none of them, because it parses a table when it is
# asked for one and not before, which is how a font truncated to a third of
# itself still looks readable until something reads it.
REQUIRED_TABLES = ("cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2")
OUTLINE_TABLES = ("glyf", "CFF ", "CFF2")
# Outlines Word will carry. `w:embedTrueTypeFonts` means what it says: a font
# whose outlines are PostScript rather than quadratic goes into the file, is
# listed in the table, and is ignored, and Word substitutes as if it were not
# there at all. Measured with a probe font nothing could have installed: the
# TrueType family came back in Word's render and the OpenType one came back
# as Calibri. So it is refused with a reason rather than carried in silence.
POSTSCRIPT_OUTLINES = ("CFF ", "CFF2")
# How much font a Word file may carry. The reference report's faces come to
# 1.5 MB, a CJK face runs to 20 MB on its own, and the export as a whole is
# capped at 100 MB, so a single face over 15 MB or a total over 40 MB is a
# report asking for something the reader will not thank it for.
MAX_FONT_BYTES = 15 * 1024 * 1024
MAX_FONT_TOTAL_BYTES = 40 * 1024 * 1024
STYLE_ELEMENTS = {
    (False, False): "w:embedRegular",
    (True, False): "w:embedBold",
    (False, True): "w:embedItalic",
    (True, True): "w:embedBoldItalic",
}
# The name records this reads. 1 and 2 are the legacy family and subfamily,
# which is what Word matches on; 4 and 6 are the full and PostScript names,
# which is how a PDF refers to the same face; 16 and 17 are the typographic
# pair, kept because a font that has them uses 1 and 2 for the Word-shaped
# reading and 16 and 17 for the real one.
NAME_FAMILY, NAME_SUBFAMILY, NAME_FULL = 1, 2, 4
NAME_POSTSCRIPT, NAME_TYPO_FAMILY, NAME_TYPO_SUBFAMILY = 6, 16, 17
# Where a font says what may be done with it. 13 and 14 are the licence and
# its URL, and 0 is the copyright notice, which is where several families put
# the licence instead: New Computer Modern names the GUST Font License in 0
# and has no 13 at all.
NAME_COPYRIGHT, NAME_LICENCE, NAME_LICENCE_URL = 0, 13, 14
NAME_IDS = (NAME_COPYRIGHT, NAME_FAMILY, NAME_SUBFAMILY, NAME_FULL,
            NAME_POSTSCRIPT, NAME_LICENCE, NAME_LICENCE_URL,
            NAME_TYPO_FAMILY, NAME_TYPO_SUBFAMILY)
NOT_A_NAME = re.compile(r"[^0-9a-z]+")
# Characters XML 1.0 cannot carry, in an attribute or in text: the C0 controls
# other than tab, newline and carriage return, the two noncharacters, and a
# surrogate half with no partner. A font's name table is free-form bytes, so
# nothing stops a hostile one from putting these in its family, and Word's
# font table names a family in an attribute (`w:font w:name="..."`): a name
# that reaches it unfiltered leaves fontTable.xml not well-formed, or makes
# python-docx's own writer refuse the string outright when a run names it.
# Built from `chr()` rather than written as literal code points, so this file
# stays plain ASCII instead of carrying the very characters it exists to
# reject.
_XML_NONCHARACTERS = chr(0xFFFE) + chr(0xFFFF)
_XML_SURROGATE_RANGE = chr(0xD800) + "-" + chr(0xDFFF)
XML_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f%s%s]" % (_XML_NONCHARACTERS, _XML_SURROGATE_RANGE))
# The most of a font's own family name that is ever written into a document.
MAX_FAMILY_CHARS = 63
# Licences this recognises well enough to convert a font's outlines under.
# Conversion is a modification, so it is not done on a licence nobody here
# has read: an unrecognised one is refused and named, which is the same
# answer the restricted `fsType` bit gets. The phrases are matched against
# the licence, the licence URL and the copyright notice, with punctuation and
# case removed, so a font that states its licence in any of the three is
# found.
CONVERTIBLE_LICENCES = (
    ("the SIL Open Font License", ("silopenfontlicense", "openfontlicenseorg", "scriptssilorgofl")),
    ("the Apache License 2.0", ("apachelicenseversion20", "apache20", "apachelicense20",
                                "wwwapacheorglicenseslicense20")),
    ("the Bitstream Vera licence", ("bitstreamvera",)),
    ("the GUST Font License", ("gustfontlicense",)),
    ("the Ubuntu Font Licence", ("ubuntufontlicence", "ubuntufontlicense")),
)
# How far a quadratic curve may sit from the cubic it replaces, in em. One
# unit per thousand is what every converter uses and is a twentieth of a pixel
# at 20 pt on a 300 dpi page, so nothing a reader can see moves.
CONVERT_MAX_ERR_EM = 0.001
# How often the glyph loop checks a deadline. Measured at 1,200 to 2,200
# glyphs a second, so a 65,535-glyph CFF face is tens of seconds on its own
# against the caller's much larger budget for the whole conversion; checking
# the clock every 200 glyphs stops within a fraction of a second of the
# deadline and costs nothing worth measuring against the drawing itself.
CONVERT_DEADLINE_CHECK_GLYPHS = 200
# Tables that describe outlines this no longer has, or vouch for bytes this
# has changed.
CONVERT_DROPS = ("CFF ", "CFF2", "VORG", "DSIG")
# Which slot to fall back to when a family has no face for what a run asks
# for: keep the slant and drop the weight first, because a Word file that
# loses an italic reads worse than one that loses a bold.
SLOT_ORDER = ((False, False), (False, True), (True, False), (True, True))


def style_of(subfamily):
    """Bold and italic, read off a legacy subfamily name.

    Name ID 2 is the one field a font uses to say which of Word's four slots
    it fills, and the format allows it four answers: Regular, Bold, Italic
    and Bold Italic, with Book and Oblique in the wild for the first and the
    third. So the whole string is read rather than any word of it. The slant
    is a suffix, and what is left in front of it is the weight, which is bold
    when it is the word `bold` and nothing else.

    Both halves of that are load-bearing, and each was a bug first. A
    substring test makes `SemiBold` bold, and a SemiBold face is a family of
    its own that Word would then paint a fake weight over. Splitting into
    words instead makes `BoldItalic`, which is how New Computer Modern spells
    it, neither bold nor italic, so it takes the regular slot and the real
    regular face never gets carried.
    """
    text = key_of(subfamily)
    italic = False
    for slant in ("italic", "oblique"):
        if text.endswith(slant):
            italic, text = True, text[: -len(slant)]
            break
    return text == "bold", italic


def key_of(name):
    """A font name reduced to what a comparison can use.

    The same face is `DejaVuSansMono` in a PDF, `DejaVu Sans Mono` in its own
    family record and `DejaVu Sans Mono Book` written out in full, so spacing,
    punctuation and case all have to stop counting before the three can be
    recognised as one font.
    """
    return NOT_A_NAME.sub("", str(name or "").lower())


def strip_xml_unsafe(name):
    """A name with the characters XML cannot carry taken out.

    Read once here, in `read_font`, so every later use of a family or
    subfamily, the font table's own `w:name` attribute among them, is already
    safe rather than trusted to escape it correctly on its own.
    """
    return XML_FORBIDDEN.sub("", str(name or ""))


def obfuscate(data, key):
    """Word's font obfuscation: the first 32 bytes XORed with the GUID's bytes.

    The key is the part's GUID written backwards as pairs of hex digits, which
    is the one detail every implementation gets wrong the first time.
    """
    nibbles = bytes.fromhex(key.strip("{}").replace("-", ""))
    mask = bytes(reversed(nibbles))
    head = bytes(b ^ mask[i % 16] for i, b in enumerate(data[:32]))
    return head + data[32:]


def read_font(path):
    """What a font calls itself, and whether it may travel, from its own tables."""
    try:
        from fontTools.ttLib import TTFont
    except ImportError:  # pragma: no cover - fontTools ships with pdf2docx
        return None
    names, fs_type, bold, italic, whole, postscript = {}, 0, False, False, False, False
    try:
        with TTFont(path, lazy=True, fontNumber=0) as font:
            for record in font["name"].names:
                if record.nameID not in NAME_IDS or record.nameID in names:
                    continue
                try:
                    names[record.nameID] = record.toUnicode()
                except Exception:  # noqa: BLE001 - a record we cannot decode is one we skip
                    continue
            os2 = font["OS/2"] if "OS/2" in font else None
            fs_type = int(getattr(os2, "fsType", 0) or 0)
            subfamily = names.get(NAME_SUBFAMILY) or names.get(NAME_TYPO_SUBFAMILY) or ""
            bold, italic = style_of(subfamily)
            if not subfamily and os2 is not None:
                # No subfamily record at all, so the only thing left that says
                # which face this is, is the selection bits.
                bold = bool(os2.fsSelection & 0x20)
                italic = bool(os2.fsSelection & 0x01)
            postscript = "glyf" not in font and any(table in font for table in POSTSCRIPT_OUTLINES)
            whole = (all(table in font for table in REQUIRED_TABLES)
                     and any(table in font for table in OUTLINE_TABLES)
                     # Naming a table is not having it: fontTools decompiles
                     # lazily, so a file cut short answers every question above
                     # and fails only when a glyph is asked for, which in a
                     # Word file happens on the reader's machine.
                     and reads_a_glyph(font))
    except Exception:  # noqa: BLE001 - a font we cannot read at all is one we skip
        pass
    # Stripped of anything XML 1.0 forbids before anything else touches it: a
    # hostile font's family is a string this script writes into an XML
    # attribute later, and nothing upstream of here checks it.
    family = strip_xml_unsafe(names.get(NAME_FAMILY) or names.get(NAME_TYPO_FAMILY) or "").strip()
    # A name table is as long as the font wants it to be, and a family reaches
    # `w:name` in every run this file writes. Word's own limit for a font name
    # is 31 characters and no real face is anywhere near that; cutting at 63
    # leaves a name nobody sensible will notice and keeps a 4 KB one out of
    # every paragraph of the document.
    family = family[:MAX_FAMILY_CHARS]
    if not family:
        # Stripping took the whole name, so this font is as unreadable as one
        # whose name table never had a family to begin with.
        return None
    return {
        "path": path,
        # Name ID 1 and 2: the pair Word resolves a run with.
        "family": family,
        "subfamily": strip_xml_unsafe(names.get(NAME_SUBFAMILY) or "").strip(),
        # Name ID 6 and 4: how the PDF and its reader refer to the same face.
        "postscript": (names.get(NAME_POSTSCRIPT) or "").strip(),
        "full": (names.get(NAME_FULL) or "").strip(),
        # Name ID 16 and 17: the typographic family, when the font has one.
        "typoFamily": (names.get(NAME_TYPO_FAMILY) or "").strip(),
        "typoSubfamily": (names.get(NAME_TYPO_SUBFAMILY) or "").strip(),
        "bold": bold,
        "italic": italic,
        "fsType": fs_type,
        "damaged": not whole,
        "postscriptOutlines": postscript,
        # Name IDs 13, 14 and 0, run together, because a font may state its
        # terms in any of the three.
        "licenceText": " ".join(names.get(name_id, "") for name_id in
                                (NAME_LICENCE, NAME_LICENCE_URL, NAME_COPYRIGHT)).strip(),
    }


def reads_a_glyph(font):
    """Decompile one real outline, so a truncated file cannot pass as whole."""
    order = list(font.getGlyphOrder() or ())
    if not order:
        return False
    glyphs = font["glyf"] if "glyf" in font else None
    if glyphs is not None:
        # The first glyph of a font is `.notdef` and is often empty, so this
        # walks until it finds one with an outline and gives up after a few:
        # a font of nothing but blanks is not one this report is setting text
        # in either.
        for name in order[:64]:
            glyph = glyphs[name]
            glyph.expand(glyphs)
            if getattr(glyph, "numberOfContours", 0):
                return True
        return False
    charstrings = font["CFF "].cff[0].CharStrings if "CFF " in font else font["CFF2"].cff[0].CharStrings
    for name in order[:64]:
        if name in charstrings:
            charstrings[name].decompile()
            return True
    return False


def covers(entry, codepoint):
    """Does this face have a glyph for this character?"""
    try:
        from fontTools.ttLib import TTFont
        with TTFont(entry["path"], lazy=True, fontNumber=0) as font:
            return codepoint in font.getBestCmap()
    except Exception:  # noqa: BLE001 - a font we cannot read has nothing to offer
        return False


def embeddable(entry):
    """May this font travel in a file that is still worth receiving?

    `fsType` has three levels above restricted. Installable and editable are
    both fine. Preview and print is refused, and not on the licence's account:
    Word honours that bit by opening the whole document read-only, so the one
    thing this export exists to hand somebody, a report they can edit, is
    exactly what embedding such a face takes away. Measured on the starter
    report, whose italic is one: Word declined to repaginate it and answered
    `this command is not available` to a request to save it.
    """
    fs = entry["fsType"]
    if fs & FS_BITMAP_ONLY or fs & FS_RESTRICTED:
        return False
    return not (fs & FS_PREVIEW_PRINT)


def licence_of(entry):
    """The licence this font states, when it is one this recognises.

    A font states its terms in prose, so this is a recognition and not a
    reading: a licence nobody here has looked at gets no answer rather than a
    guess. What the answer is used for is narrow. It never decides whether a
    font may be embedded, which is what the `fsType` bits are for. It decides
    only whether this may redraw the outlines on the way in.
    """
    text = key_of(entry.get("licenceText"))
    if not text:
        return None
    for label, phrases in CONVERTIBLE_LICENCES:
        if any(phrase in text for phrase in phrases):
            return label
    return None


def convertible(entry):
    """May this face's outlines be redrawn so that Word can carry them?"""
    return bool(entry.get("postscriptOutlines")) and licence_of(entry) is not None


def carriable(entry, convert_outlines=True):
    """Will this face be in the file and drawn from it, rather than named?"""
    if entry.get("damaged") or not embeddable(entry):
        return False
    if not entry.get("postscriptOutlines"):
        return True
    return bool(convert_outlines) and convertible(entry)


def refusal(entries, convert_outlines=True):
    """Why none of these faces can travel, in the reader's terms."""
    if all(e.get("damaged") for e in entries):
        return "the font file is damaged"
    alive = [e for e in entries if not e.get("damaged")]
    if alive and all(e["fsType"] & FS_PREVIEW_PRINT and not (e["fsType"] & FS_RESTRICTED)
                     and not (e["fsType"] & FS_BITMAP_ONLY) for e in alive):
        return ("its licence lets a reader print the document but not edit it, and Word "
                "opens a document carrying such a font read-only")
    if alive and all(e.get("postscriptOutlines") for e in alive):
        if not convert_outlines:
            return ("its outlines are a kind Word cannot embed, and converting them "
                    "is turned off")
        if not any(convertible(e) for e in alive):
            return ("its outlines are a kind Word cannot embed, and its licence does "
                    "not clearly allow converting them")
        return "there was not enough time left to convert its outlines"
    return "its licence does not allow embedding"


def to_truetype(path, deadline=None):
    """The same face with quadratic outlines, in memory, or None.

    `w:embedTrueTypeFonts` means what it says, so a font whose outlines are
    PostScript is written into the package and ignored. The outlines are the
    only thing Word objects to, and a cubic curve has a quadratic within a
    thousandth of an em of it, so the face is redrawn rather than dropped.

    Everything a line's width depends on is left exactly as it was: the
    advance widths in `hmtx`, the vertical metrics in `hhea` and `OS/2`, and
    the kerning and shaping tables. Only the side bearing moves, and only to
    the redrawn outline's own left edge, which is where the format says it
    has to be. `post` is written as format 2 so the glyph names survive, and
    falls back to format 3 when they will not fit, which is the one case
    where something is lost and it is something no reader draws.

    `deadline` is a monotonic time this stops at rather than finish: one CFF
    face can be 65,535 glyphs, tens of seconds of drawing on its own, and the
    budget check that used to run only before a face started could let one
    face alone run the caller past its own timeout. Checked every
    `CONVERT_DEADLINE_CHECK_GLYPHS` glyphs, including the first, so a deadline
    already passed when this is called returns almost immediately.
    """
    try:
        from fontTools.ttLib import TTFont, newTable
        from fontTools.pens.cu2quPen import Cu2QuPen
        from fontTools.pens.ttGlyphPen import TTGlyphPen
    except ImportError:  # pragma: no cover - fontTools ships with pdf2docx
        return None
    import io

    try:
        font = TTFont(path, fontNumber=0)
    except Exception:  # noqa: BLE001 - a font we cannot read is one we skip
        return None
    try:
        if "glyf" in font or not any(table in font for table in POSTSCRIPT_OUTLINES):
            return None
        if "CFF2" in font or "gvar" in font:
            return None  # a variable font has no single set of outlines to draw
        order = font.getGlyphOrder()
        source = font.getGlyphSet()
        error = CONVERT_MAX_ERR_EM * font["head"].unitsPerEm
        drawn = {}
        for index, name in enumerate(order):
            if (deadline is not None and index % CONVERT_DEADLINE_CHECK_GLYPHS == 0
                    and time.monotonic() > deadline):
                return None
            pen = TTGlyphPen(drawn)
            # Reversed, because TrueType fills the other way round than
            # PostScript does and an unreversed contour comes out hollow.
            source[name].draw(Cu2QuPen(pen, error, reverse_direction=True))
            drawn[name] = pen.glyph()

        glyf = newTable("glyf")
        glyf.glyphOrder = order
        glyf.glyphs = drawn
        font["loca"] = newTable("loca")
        font["glyf"] = glyf
        for table in CONVERT_DROPS:
            if table in font:
                del font[table]
        glyf.compile(font)

        hmtx = font["hmtx"]
        for name, glyph in drawn.items():
            if hasattr(glyph, "xMin"):
                hmtx[name] = (hmtx[name][0], glyph.xMin)  # the advance is untouched

        font["head"].glyphDataFormat = 0
        font["maxp"] = maxp = newTable("maxp")
        maxp.tableVersion = 0x00010000
        maxp.maxZones = 1
        maxp.maxTwilightPoints = 0
        maxp.maxStorage = 0
        maxp.maxFunctionDefs = 0
        maxp.maxInstructionDefs = 0
        maxp.maxStackElements = 0
        maxp.maxSizeOfInstructions = 0
        maxp.maxComponentElements = max(
            [len(g.components) for g in drawn.values() if g.isComposite()] or [0])
        maxp.compile(font)

        post = font["post"]
        post.formatType = 2.0
        post.extraNames = []
        post.mapping = {}
        post.glyphOrder = order
        try:
            post.compile(font)
        except OverflowError:
            post.formatType = 3.0

        font.sfntVersion = "\000\001\000\000"
        out = io.BytesIO()
        font.save(out)
        return out.getvalue()
    except Exception:  # noqa: BLE001 - a face we cannot redraw is one we do not carry
        return None
    finally:
        font.close()


def collect(directories):
    """Every readable font under these directories, in a stable order."""
    found, seen = [], set()
    for directory in directories:
        if not directory or not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not name.lower().endswith((".ttf", ".otf")) or path in seen:
                continue
            seen.add(path)
            entry = read_font(path)
            if entry:
                found.append(entry)
    return found


def face_names(entry):
    """Every name one face answers to, reduced for comparison."""
    written = [entry.get("postscript"), entry.get("full")]
    for family, subfamily in (("family", "subfamily"), ("typoFamily", "typoSubfamily")):
        if entry.get(family) and entry.get(subfamily):
            written.append("%s %s" % (entry[family], entry[subfamily]))
    return [key for key in (key_of(name) for name in written) if key]


def pdf_faces(doc, base_name):
    """The fonts the PDF sets text in, by the name the PDF writes them under."""
    names = set()
    for index in range(doc.page_count):
        for block in doc[index].get_text("dict")["blocks"]:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    name = base_name(span.get("font"))
                    if name:
                        names.add(name)
    return names


def plan(pdf_names, entries):
    """Which staged file each PDF font is, and what Word must be told to get it.

    Matching is on the names the font itself carries, PostScript name first,
    because that is what a PDF writes. What comes back is keyed both ways: by
    family, for the runs a converter has already labelled with one, and by
    face, for the ones still carrying the PDF's own name. Family wins on a
    tie, because a family lookup also reads the run's bold and italic bits and
    a face lookup cannot.
    """
    by_alias = {}
    for entry in entries:
        for alias in face_names(entry):
            by_alias.setdefault(alias, entry)
    faces, missing = {}, []
    for name in sorted(pdf_names):
        key = key_of(name)
        entry = by_alias.get(key)
        if entry is None:
            # A PDF reader hands a font's name back out of a fixed-size
            # field, and PyMuPDF's is 24 bytes, so `DejaVuSansMono-BoldOblique`
            # arrives two characters short of itself. A name that begins
            # exactly one staged face is that face; one that begins two is
            # nobody's and stays missing.
            begun = {id(e): e for alias, e in by_alias.items() if alias.startswith(key)}
            entry = next(iter(begun.values())) if len(begun) == 1 else None
        if entry is None:
            missing.append(name)
        else:
            faces[name] = entry

    # A family the report touches is carried whole, so the Word file stays
    # editable in the face the reader reaches for next.
    families = {entry["family"]: {} for entry in faces.values()}
    for entry in entries:
        slots = families.get(entry["family"])
        if slots is not None:
            slots.setdefault((entry["bold"], entry["italic"]), entry)

    by_family = {key_of(family): family for family in families}
    for family in families:
        # `Poppins SemiBold` says its typographic family is `Poppins`, which
        # is a family in its own right here, so an alias only ever fills a
        # name no real family already answers to.
        for entry in (e for e in entries if e["family"] == family):
            for alias in (entry.get("typoFamily"), family.split("-")[0]):
                if key_of(alias):
                    by_family.setdefault(key_of(alias), family)

    by_face = {}
    for name, entry in faces.items():
        by_face.setdefault(key_of(name), entry)
    for entry in entries:
        if entry["family"] not in families:
            continue
        for alias in face_names(entry):
            if by_face.setdefault(alias, entry) is not entry:
                by_face[alias] = None  # two faces answer to it; it names neither
    by_face = {alias: entry for alias, entry in by_face.items()
               if entry is not None and alias not in by_family}
    return {"faces": faces, "missing": missing, "families": families,
            "byFamily": by_family, "byFace": by_face}


def resolve(plan_, name, bold, italic):
    """The face Word should be asked for, given what a run says now."""
    if not plan_:
        return None
    key = key_of(name)
    family = plan_["byFamily"].get(key)
    if family:
        slots = plan_["families"][family]
        for want in ((bold, italic), (False, italic), (bold, False), (False, False)):
            if want in slots:
                return slots[want]
        return next((slots[k] for k in SLOT_ORDER if k in slots), None)
    return plan_["byFace"].get(key)


def resolve_pdf_font(plan_, pdf_name):
    """The face a PDF font name is, exactly, or None when nothing was staged."""
    if not plan_ or not pdf_name:
        return None
    return plan_["faces"].get(pdf_name)


def face_for_char(plan_, codepoint):
    """A face this Word file will carry that has a glyph for this character.

    A converter that puts a character back on the page has to say what to set
    it in, and the only fonts a reader is certain to have are the ones
    travelling inside the file.
    """
    if not plan_:
        return None
    for family in sorted(plan_["families"]):
        slots = plan_["families"][family]
        for style in SLOT_ORDER:
            entry = slots.get(style)
            if entry and carriable(entry) and covers(entry, codepoint):
                return entry
    return None


def face_bytes(entry, budget):
    """The bytes to carry for this face, redrawn first when they have to be.

    `budget` is a one-element list holding the seconds left for conversion,
    or None for no limit, and it is decremented as faces are converted: a
    report that needs six faces redrawn should not spend the caller's whole
    margin doing it and then be killed before it writes the file. The same
    number becomes `to_truetype`'s deadline, so one face cannot run past the
    margin the budget check only enforced between faces before.

    A face whose conversion raises is treated exactly like one that returns
    None: skipped, with the plain warning `embed` already gives a face it
    could not redraw. `to_truetype` reads a font this server did not choose,
    and a bug or a fontTools edge case in it must not cost the finished
    document.
    """
    if not entry.get("postscriptOutlines"):
        with open(entry["path"], "rb") as handle:
            return handle.read(), False
    if budget[0] is not None and budget[0] <= 0:
        return None, False
    started = time.monotonic()
    deadline = started + budget[0] if budget[0] is not None else None
    try:
        data = to_truetype(entry["path"], deadline=deadline)
    except Exception:  # noqa: BLE001 - a face we cannot redraw safely is one we do not carry
        data = None
    if budget[0] is not None:
        budget[0] -= time.monotonic() - started
    return data, data is not None


def too_big_message(size):
    """The refusal `embed` gives a face over `MAX_FONT_BYTES`, before or after conversion."""
    return "the font file is %d MB, over the %d MB a single face may take" % (
        round(size / (1024 * 1024)), MAX_FONT_BYTES // (1024 * 1024))


def embed(docx_path, plan_, convert_outlines=True, convert_seconds=None):
    """Put the fonts in the file.

    Returns the families carried, the names skipped with a reason each, and
    the families whose outlines had to be redrawn on the way in.
    """
    skipped = [(name, "no font file for it was staged") for name in plan_["missing"]]
    chosen = []
    redrawn = set()
    for family in sorted(plan_["families"]):
        slots = plan_["families"][family]
        entries = [slots[style] for style in SLOT_ORDER if style in slots]
        usable = [e for e in entries if carriable(e, convert_outlines)]
        if not usable:
            skipped.append((family, refusal(entries, convert_outlines)))
            continue
        # A family can be carried in some of its faces and not others, and a
        # missing italic is a substituted italic, so each one says so.
        kept = {id(e) for e in usable}
        for entry in entries:
            if id(entry) not in kept:
                skipped.append(("%s %s" % (family, entry["subfamily"] or "Regular"),
                                refusal([entry], convert_outlines)))
        chosen.append((family, usable))
    if not chosen:
        return [], skipped, sorted(redrawn)

    parts = {}
    table_rows = []
    rels = []
    carried = 0
    embedded = []
    budget = [convert_seconds]
    for family, entries in chosen:
        rows = []
        for entry in entries:
            style = STYLE_ELEMENTS[(entry["bold"], entry["italic"])]
            if any(row.startswith("<" + style) for row in rows):
                continue
            # Checked against the file on disk before anything is spent
            # converting it: a CFF face over the cap would otherwise pay for
            # its own redraw, tens of seconds by the measurement in
            # `to_truetype`, only to be refused once it was already bytes.
            # The redrawn size is checked again below, because a conversion
            # can come out a different size than the file it started from and
            # the running total needs the real number.
            source_size = os.path.getsize(entry["path"])
            if source_size > MAX_FONT_BYTES:
                skipped.append((family, too_big_message(source_size)))
                continue
            data, converted = face_bytes(entry, budget)
            if data is None:
                skipped.append((family, refusal([entry], convert_outlines)
                                if budget[0] is not None and budget[0] <= 0
                                else "its outlines could not be redrawn for Word"))
                continue
            size = len(data)
            if size > MAX_FONT_BYTES:
                skipped.append((family, too_big_message(size)))
                continue
            if carried + size > MAX_FONT_TOTAL_BYTES:
                skipped.append((family, "the Word file already carries the %d MB of fonts it may"
                                % (MAX_FONT_TOTAL_BYTES // (1024 * 1024))))
                continue
            key = "{%s}" % str(uuid.uuid4()).upper()
            rid = "rIdFont%d" % (len(parts) + 1)
            name = "fonts/font%d.odttf" % (len(parts) + 1)
            parts["word/" + name] = obfuscate(data, key)
            carried += size
            rels.append((rid, name))
            rows.append('<%s r:id="%s" w:fontKey="%s" w:subsetted="false"/>' % (style, rid, key))
            if converted:
                redrawn.add(family)
        if rows:
            table_rows.append('<w:font w:name="%s">%s</w:font>' % (escape(family), "".join(rows)))
            embedded.append(family)
    if not table_rows:
        return [], skipped, sorted(redrawn)
    rewrite(docx_path, parts, table_rows, rels)
    return embedded, skipped, sorted(redrawn)


def escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")


def rewrite(docx_path, parts, table_rows, rels):
    """Write the package back with the font parts and the three edits."""
    with zipfile.ZipFile(docx_path) as archive:
        existing = {item.filename: archive.read(item.filename) for item in archive.infolist()}

    types = existing[CONTENT_TYPES].decode("utf-8")
    if "odttf" not in types:
        types = types.replace(
            "</Types>",
            '<Default Extension="odttf" '
            'ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/></Types>',
        )
    existing[CONTENT_TYPES] = types.encode("utf-8")

    table = existing.get(FONT_TABLE, b"").decode("utf-8")
    if not table.strip():
        table = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<w:fonts xmlns:w="%s" xmlns:r="%s"></w:fonts>' % (W_NS, R_NS))
    if 'xmlns:r=' not in table:
        table = table.replace("<w:fonts ", '<w:fonts xmlns:r="%s" ' % R_NS, 1)
    # A family already in the table keeps its own element and gains the
    # embed children, rather than being declared twice.
    for row in table_rows:
        name = re.search(r'w:name="([^"]+)"', row).group(1)
        children = row[row.index(">") + 1 : row.rindex("</w:font>")]
        pattern = re.compile(r'(<w:font w:name="%s"[^>]*>)' % re.escape(name))
        if pattern.search(table):
            table = pattern.sub(lambda m: m.group(1) + children, table, count=1)
        else:
            table = table.replace("</w:fonts>", row + "</w:fonts>")
    existing[FONT_TABLE] = table.encode("utf-8")

    relationships = existing.get(FONT_TABLE_RELS, b"").decode("utf-8")
    if not relationships.strip():
        relationships = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         "</Relationships>")
    added = "".join(
        '<Relationship Id="%s" Type="%s" Target="%s"/>' % (rid, FONT_REL_TYPE, target) for rid, target in rels
    )
    existing[FONT_TABLE_RELS] = relationships.replace("</Relationships>", added + "</Relationships>").encode("utf-8")

    settings = existing.get(SETTINGS, b"").decode("utf-8")
    if "embedTrueTypeFonts" not in settings:
        settings = re.sub(r"(<w:settings[^>]*>)", r"\1<w:embedTrueTypeFonts/>", settings, count=1)
    existing[SETTINGS] = settings.encode("utf-8")
    existing.update(parts)

    with zipfile.ZipFile(docx_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in existing.items():
            archive.writestr(name, data)
