#!/usr/bin/env python3
"""Show that Word sets the Word file in the fonts the file carries.

    <venv>/python -I -B font_probe.py <scratch-folder>

A developer tool, like `compare.ps1`. It is not part of `bun run test`, it
never runs in Docker, and it needs typst on PATH, Microsoft Word, and
`pdffonts` (MiKTeX ships one).

The thing it exists to answer cannot be answered with a real report: this
machine has the report's text font installed, so a Word file that named its
fonts wrongly still came out looking right, and the one font the machine did
not have was the one that came out in Verdana. Installing and uninstalling
fonts to find out is not something a test may do to the machine it runs on.

So the fonts are made instead. Two permissively licensed families from
`public/fonts/` are copied and their name tables rewritten to families nobody
can have installed: `Btct Probe Sans` with all four of Word's faces, `Btct
Probe Sans SemiBold` as a family of its own to exercise the weight Word does
not keep per family, and `Btct Probe Mono`. A one-page report is set in them,
compiled with `--ignore-system-fonts`, converted, rendered back to PDF
through Word, and read with `pdffonts`. Every font in that list must be a
probe family. Word cannot have found one anywhere but inside the file.

Word renames a font it loaded from a document to `___WRD_EMBED_SUB_n` when it
writes a PDF, which is itself the proof: a name like that is a face that came
out of the file rather than off the machine. The face behind it is identified
by its PostScript name, which Word leaves alone.

A fourth family, `Btct Probe Serif`, has PostScript outlines, which Word will
not carry however correctly the file declares it, so the converter redraws
them as quadratics on the way in. The control for that one is the same
document converted again with `--no-font-conversion`: one flag apart, the
same face, and Word substitutes. That is what it did for every such font
before this, and what it would do again if the redrawing broke.

Licences. DejaVu Sans Mono is Bitstream Vera plus public-domain changes; the
Vera licence allows modification and forbids the modified font from carrying
`Bitstream` or `Vera` in its name, which none of these do. Libertinus Serif,
the control, is SIL OFL 1.1, which allows modification and requires the name
to change when it does, which is what this is. Both keep their copyright and
licence name records.
"""

import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_FONTS = os.path.join(HERE, "..", "..", "..", "public", "fonts")
# name IDs that say who owns the font and on what terms. They are copied
# across unchanged; the rest of the table is rewritten.
KEEP_RECORDS = (0, 13, 14)
# The two records every tool reads. A font with only these is a font whose
# family and subfamily cannot be misread.
PLATFORMS = ((3, 1, 0x409), (1, 0, 0))
# Source file, family, subfamily, PostScript name, and the weight to write
# into OS/2 when it has to differ from the source's. Weight 600 is what makes
# typst read `Btct Probe Sans SemiBold` as the semibold member of `Btct Probe
# Sans` rather than as a second bold, which is how a report asks for the case
# this probe exists to cover.
PROBES = (
    ("DejaVuSansMono.ttf", "Btct Probe Sans", "Regular", "BtctProbeSans-Regular", None),
    ("DejaVuSansMono-Bold.ttf", "Btct Probe Sans", "Bold", "BtctProbeSans-Bold", None),
    ("DejaVuSansMono-Oblique.ttf", "Btct Probe Sans", "Italic", "BtctProbeSans-Italic", None),
    ("DejaVuSansMono-BoldOblique.ttf", "Btct Probe Sans", "Bold Italic",
     "BtctProbeSans-BoldItalic", None),
    ("DejaVuSansMono-Bold.ttf", "Btct Probe Sans SemiBold", "Regular",
     "BtctProbeSansSemiBold-Regular", 600),
    ("DejaVuSansMono.ttf", "Btct Probe Mono", "Regular", "BtctProbeMono-Regular", None),
    ("LibertinusSerif-Regular.otf", "Btct Probe Serif", "Regular", "BtctProbeSerif-Regular", None),
)
# The family whose outlines are PostScript, so the one the converter has to
# redraw before Word will carry it.
CONTROL = "Btct Probe Serif"
REPORT = """#set page(width: 8.5in, height: 11in, margin: 1in)
#set text(font: "Btct Probe Sans", size: 11pt)
#show raw: set text(font: "Btct Probe Mono", size: 9pt)

#text(weight: "semibold", size: 18pt)[A heading in the semibold family]

This paragraph is set in the regular face of the probe family, and it runs on
for long enough that a substituted font would break the line somewhere else
than this one does. Here is *a run in bold*, here is _a run in italic_, and
here is *_a run in bold italic_*, so all four of the faces Word keeps under
one family name are asked for on the same page.

#text(weight: "semibold", size: 13pt)[A second semibold line]

The semibold face above is a family of its own as far as Word is concerned.
Word keeps four faces per family and semibold is not one of them, so a file
that asked for the family below it with the bold bit set would be asking for
a different face and getting a painted-on weight over the top of it.

```
nmap -sV -p 443 10.0.0.1 | grep -i "http"
curl -s http://10.0.0.1:8080/ > /dev/null
```

#text(font: "Btct Probe Serif")[%s]
"""
CONTROL_LINE = ("The control is a line in a family whose outlines are PostScript, "
                "which Word declines to carry however the file asks for it.")
REPORT = REPORT % CONTROL_LINE
RENDER = """
$ErrorActionPreference = 'Stop'
$word = $null; $doc = $null
try {
  $word = New-Object -ComObject Word.Application
  $word.Visible = $false
  $word.DisplayAlerts = 0
  $doc = $word.Documents.Open('%(docx)s', $false, $true, $false)
  $doc.Fields.Update() | Out-Null
  $doc.Repaginate()
  Write-Host ('pages=' + $doc.ComputeStatistics(2))
  $doc.SaveAs2('%(pdf)s', 17)
} finally {
  if ($doc) { $doc.Close([ref]0) | Out-Null }
  if ($word) { $word.Quit() | Out-Null }
  foreach ($o in @($doc, $word)) {
    if ($o) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($o) }
  }
  [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
}
"""


def rename_font(source, target, family, subfamily, postscript, weight):
    """Copy a font with a family name nothing on this machine can answer to."""
    from fontTools.ttLib import TTFont

    font = TTFont(source)
    table = font["name"]
    full = family if subfamily == "Regular" else "%s %s" % (family, subfamily)
    table.names = [record for record in table.names if record.nameID in KEEP_RECORDS]
    written = {1: family, 2: subfamily, 3: "%s: probe" % full, 4: full, 6: postscript}
    for name_id, value in written.items():
        for platform, encoding, language in PLATFORMS:
            table.setName(value, name_id, platform, encoding, language)
    if weight is not None:
        # The weight and the selection bits have to agree with the subfamily
        # just written, or a reader sizes the face by one and names it by the
        # other.
        os2 = font["OS/2"]
        os2.usWeightClass = weight
        os2.fsSelection = (os2.fsSelection & ~0x21) | 0x40  # not bold, not italic, regular
        font["head"].macStyle &= ~0x03
    if "CFF " in font:
        # A CFF font says its name twice, and typst reads the second one.
        cff = font["CFF "].cff
        top = cff[cff.fontNames[0]]
        cff.fontNames[0] = postscript
        top.FullName = full
        top.FamilyName = family
    font.save(target)
    font.close()


def build_fonts(out_dir):
    """The probe families, written into a directory of their own."""
    os.makedirs(out_dir, exist_ok=True)
    made = []
    for name, family, subfamily, postscript, weight in PROBES:
        source = os.path.join(REPO_FONTS, name)
        if not os.path.isfile(source):
            raise SystemExit("no source font at %s" % source)
        target = os.path.join(out_dir, postscript + os.path.splitext(name)[1])
        rename_font(source, target, family, subfamily, postscript, weight)
        made.append((target, family, subfamily))
    return made


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit("%s failed (%d)" % (args[0], result.returncode))
    return result.stdout


def word_render(docx, pdf):
    """Word's own opinion of the Word file, as a PDF. Needs Word."""
    if os.path.exists(pdf):
        os.remove(pdf)
    script = RENDER % {"docx": docx.replace("'", "''"), "pdf": pdf.replace("'", "''")}
    out = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    return out.strip()


def read_fonts(pdf):
    """Every font the PDF draws with, named as `pdffonts` names it."""
    if shutil.which("pdffonts") is None:
        raise SystemExit("pdffonts is not on PATH (MiKTeX ships one)")
    listed = []
    for line in run(["pdffonts", pdf]).splitlines()[2:]:
        name = line.split()[0] if line.split() else ""
        if name:
            listed.append(re.sub(r"^[A-Z]{6}\+", "", name))
    return listed


def visible_spans(pdf):
    """Every run of visible text in a PDF, with the font it was drawn in."""
    import pymupdf

    doc = pymupdf.open(pdf)
    out = []
    try:
        for index in range(doc.page_count):
            for block in doc[index].get_text("dict")["blocks"]:
                if block.get("type") != 0:
                    continue
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        if span["text"].strip():
                            out.append((re.sub(r"^[A-Z]{6}\+", "", span["font"]), span["text"]))
    finally:
        doc.close()
    return out


def face_behind(pdf, name):
    """What a font Word renamed on its way out actually is, by PostScript name."""
    import io

    import pymupdf
    from fontTools.ttLib import TTFont

    doc = pymupdf.open(pdf)
    found = None
    try:
        for index in range(doc.page_count):
            for entry in doc[index].get_fonts(full=True):
                base = re.sub(r"^[A-Z]{6}\+", "", entry[3])
                if base != name:
                    continue
                data = doc.extract_font(entry[0])[3]
                if not data:
                    continue
                with TTFont(io.BytesIO(data), lazy=True, fontNumber=0) as font:
                    for record in font["name"].names:
                        if record.nameID == 6:
                            found = record.toUnicode()
                            break
                if found:
                    return found
    finally:
        doc.close()
    return found


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    out = os.path.abspath(argv[1])
    os.makedirs(out, exist_ok=True)
    font_dir = os.path.join(out, "fonts")
    made = build_fonts(font_dir)
    print("probe fonts:")
    for path, family, subfamily in made:
        print("  %-34s %s / %s" % (os.path.basename(path), family, subfamily))
    families = sorted({family for _, family, _ in made})

    source = os.path.join(out, "probe.typ")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(REPORT)
    reference = os.path.join(out, "reference.pdf")
    run(["typst", "compile", "--root", out, "--ignore-system-fonts",
         "--font-path", font_dir, source, reference])
    print("compiled: %s" % ", ".join(sorted(set(read_fonts(reference)))))

    def convert_to(name, *flags):
        docx = os.path.join(out, name + ".docx")
        result_file = os.path.join(out, name + "-result.json")
        run([sys.executable, "-I", "-B", os.path.join(HERE, "convert.py"),
             "--fonts=" + font_dir] + list(flags) + [reference, docx, result_file])
        with open(result_file, encoding="utf-8") as handle:
            return docx, json.load(handle)

    passed = True
    docx, result = convert_to("probe")
    print("converted: fontsEmbedded=%s fontsRedrawn=%s textCheck=%s"
          % (result["fontsEmbedded"], result["fontsRedrawn"], result["textCheck"]))
    passed &= check(result["fontsEmbedded"] == families, "every probe family is carried", families)
    passed &= check(result["fontsRedrawn"] == [CONTROL],
                    "and the one with PostScript outlines was redrawn to get there")

    for attempt in (1, 2):
        rendered = os.path.join(out, "render%d.pdf" % attempt)
        print("word: %s" % word_render(docx, rendered))
        passed &= report(rendered, attempt, set())

    # The control, one flag apart: the same face, the same document, and the
    # conversion turned off. Word substitutes, which is what it did for every
    # such font before this and would do again if the conversion broke.
    plain, refused = convert_to("probe-noconvert", "--no-font-conversion")
    passed &= check(refused["fontsEmbedded"] == [f for f in families if f != CONTROL],
                    "with conversion off the PostScript family is not carried",
                    refused["fontsEmbedded"])
    passed &= check(any(CONTROL in warning for warning in refused["warnings"]),
                    "and a warning names it")
    rendered = os.path.join(out, "render-noconvert.pdf")
    print("word: %s" % word_render(plain, rendered))
    passed &= report(rendered, "noconvert", {CONTROL})
    return 0 if passed else 1


def check(condition, label, detail=""):
    print("%-5s %s%s" % ("ok" if condition else "FAIL", label, (" -- " + str(detail)) if detail else ""))
    return bool(condition)


def report(rendered, label, expect_substituted):
    """Which face drew each glyph in one of Word's renders, and whether it fits.

    `expect_substituted` is the set of probe families this render is supposed
    to have lost, which is empty unless the conversion was turned off.
    """
    listed = read_fonts(rendered)
    print("pdffonts render %s: %s" % (label, ", ".join(listed)))
    behind = {name: (name if name.startswith("BtctProbe") else (face_behind(rendered, name) or name))
              for name in listed}
    for name in listed:
        print("    %-24s %s" % (name, behind[name]))
    passed, substituted = True, set()
    for font, text in visible_spans(rendered):
        # PyMuPDF hands a span's font name back out of a 24 byte field, so the
        # long ones arrive cut short of what `pdffonts` printed.
        face = behind.get(font) or next((f for n, f in behind.items() if n.startswith(font)), font)
        if face.startswith("BtctProbe"):
            continue
        if text.strip() in CONTROL_LINE and CONTROL in expect_substituted:
            substituted.add(CONTROL)
            continue
        print("    FAIL  %r came out in %s" % (text[:44], face))
        passed = False
    passed = check(passed, "render %s: every glyph is in the face the file carries for it" % label)
    if expect_substituted:
        passed &= check(substituted == expect_substituted,
                        "render %s: and the families it was not given did substitute" % label,
                        sorted(substituted))
    return passed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
