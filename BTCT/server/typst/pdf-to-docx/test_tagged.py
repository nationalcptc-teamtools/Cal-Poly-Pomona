#!/usr/bin/env python3
"""Checks for tagged.py. Run: <venv>/python -I -B test_tagged.py"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tagged  # noqa: E402


def check(ok, label, detail=""):
    print("%-5s %s%s" % ("ok" if ok else "FAIL", label, (" -- " + str(detail)) if detail else ""))
    return bool(ok)


HEAD = b"/Artifact <</Type /Pagination /Subtype /Header>> BDC q BT /F1 9 Tf 50 780 Td (Report title) Tj ET Q EMC"
FOOT = b"/Artifact <</Type /Pagination /Subtype /Footer>> BDC BT /F1 9 Tf 50 20 Td (Page 3) Tj ET EMC"
BODY = b"/P <</MCID 0>> BDC BT /F1 11 Tf 50 700 Td (Body EMC BDC text) Tj ET EMC"


def main():
    passed = True
    out, n = tagged.remove_artifacts(HEAD + b"\n" + BODY + b"\n" + FOOT)
    passed &= check(n == 2, "both artifacts removed", n)
    passed &= check(b"Report title" not in out and b"Page 3" not in out, "their text is gone")
    passed &= check(b"(Body EMC BDC text) Tj" in out, "operator names inside a string do not cut the body")
    nested = b"/Artifact <</Subtype /Header>> BDC /Span <</MCID 1>> BDC BT (x) Tj ET EMC EMC " + BODY
    out, n = tagged.remove_artifacts(nested)
    passed &= check(n == 1 and out.strip().startswith(b"/P"), "a nested BDC inside the artifact is removed with it", out[:40])
    bg = b"/Artifact <</Type /Pagination /Subtype /Background>> BDC 0 0 m 10 10 l S EMC " + BODY
    out, n = tagged.remove_artifacts(bg)
    passed &= check(n == 0 and out == bg, "a Background artifact is kept")
    unbalanced = b"/Artifact <</Subtype /Header>> BDC q BT (x) Tj ET EMC Q " + BODY
    passed &= check(tagged.remove_artifacts(unbalanced) is None, "an artifact that opens q without closing it refuses")
    esc = b"/Artifact <</Subtype /Footer>> BDC BT (a \\) EMC ( nested ) b) Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(esc)
    passed &= check(n == 1 and b"(Body EMC BDC text)" in out, "escaped and nested parentheses in a string")
    hexs = b"/Artifact <</Subtype /Header>> BDC BT <454D43> Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(hexs)
    passed &= check(n == 1 and b"<454D43>" not in out, "a hex string inside the artifact goes with it")

    # A hex string as the last thing in a property dict must not be read as the end of the dict.
    hexdict = b"/Artifact <</Subtype /Header /Alt <41>>> BDC BT (x) Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(hexdict)
    passed &= check(n == 1 and out.strip().startswith(b"/P"), "a hex string ending a property dict", out[:40])
    # A subtype that only starts with Header is not a Header.
    longer = b"/Artifact <</Subtype /HeaderRow>> BDC BT (x) Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(longer)
    passed &= check(n == 0 and out == longer, "/HeaderRow is not /Header")
    # A comment naming an operator does not count, and a name ending in EMC is a name.
    commented = HEAD + b" % EMC BDC\n/EMCx BDC BT (y) Tj ET EMC " + BODY
    out, n = tagged.remove_artifacts(commented)
    passed &= check(n == 1 and b"(y) Tj" in out, "comments are skipped", out[:60])
    # An unterminated hex string does not raise.
    try:
        tagged.tokenize(b"BT <4142 ")
        ok = True
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(exc)
    passed &= check(ok, "an unterminated hex string does not raise")
    toks = tagged.tokenize(b"/P <</MCID 0>> BDC [(a) 1] TJ")
    passed &= check([t[2] for t in toks] == ["name", "dict", "op", "array", "str", "num", "array", "op"],
                    "token kinds", [t[2] for t in toks])
    # An inline image's binary data is not tokenised as operators.
    inline = b"BI /W 1 /H 1 ID \x00EMC (\xff\nEI " + HEAD + b" " + BODY
    out, n = tagged.remove_artifacts(inline)
    passed &= check(n == 1 and b"(Body EMC BDC text)" in out, "inline image data is skipped")

    # Malformed nesting refuses instead of cutting body text.
    extra_close = (b"/Document <<>> BDC /Artifact <</Subtype /Header>> BDC /Span <<>> BDC BT (h) Tj ET EMC "
                   b"/P <</MCID 0>> BDC BT (BODYTEXT) Tj ET EMC EMC")
    passed &= check(tagged.remove_artifacts(extra_close) is None, "a block that never closes refuses")
    stray = b"EMC " + HEAD + b" " + BODY
    passed &= check(tagged.remove_artifacts(stray) is None, "an EMC with nothing open refuses")
    inline_trap = (b"BI /W 1 /H 1 ID \x00\nEI\n/Artifact <</Subtype /Header>> BDC \xff EI "
                   b"/P <</MCID 0>> BDC BT (BODYTEXT) Tj ET EMC")
    res = tagged.remove_artifacts(inline_trap)
    passed &= check(res is None or b"BODYTEXT" in res[0], "inline data faking an artifact never removes body text")
    # Each inline image is scanned from where it starts, not from a copy of
    # the rest of the stream: 150,000 of them took 42.7 s when every one
    # sliced the stream again.
    import time
    many = b"BI /W 1 /H 1 ID \x00\nEI\n" * 100000
    started = time.perf_counter()
    toks = tagged.tokenize(many)
    took = time.perf_counter() - started
    passed &= check(len(toks) == 100000 * 7 and took < 5.0, "100,000 inline images tokenise quickly",
                    "%d tokens, %.2f s" % (len(toks), took))

    # A document that cannot even be copied gives no answer rather than raising.
    class Unreadable:
        def tobytes(self):
            raise RuntimeError("forced: the document cannot be written")

    try:
        made = tagged.stripped_copy(Unreadable())
        ok = made is None
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(exc)
    passed &= check(ok, "stripped_copy of a document that cannot be copied is None")
    passed &= document_checks()
    return 0 if passed else 1


def document_checks():
    import cases  # noqa: E402
    if not hasattr(cases, "TAGGED_SKIP_PAGES") or not shutil.which("typst"):
        return True
    import subprocess
    import tempfile
    import pymupdf
    passed = True
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "a.typ")
        pdf = os.path.join(tmp, "a.pdf")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write(cases.TAGGED_SKIP_PAGES)
        subprocess.run(["typst", "compile", src, pdf], check=True, timeout=120)
        with pymupdf.open(pdf) as doc:
            passed &= check(tagged.is_tagged(doc), "typst output is tagged")
            passed &= check("/H1" in tagged.struct_types(doc), "the tag tree has an H1")
            made = tagged.stripped_copy(doc)
            passed &= check(made is not None and made[1].get(1, 0) >= 1, "stripped_copy removes a block on page 2")
            if made:
                made[0].close()
    return passed


if __name__ == "__main__":
    sys.exit(main())
