"""Read what typst tagged in its PDF: the Header/Footer artifacts and the structure tree.

PyMuPDF cannot say which marked-content block a text span came from, so the
running band is found by removing the Header and Footer artifact blocks from
each page's content stream and diffing the page's text before and after.
"""
import re

import pymupdf

DELIMS = b"()<>[]{}/%"
WS = b" \t\r\n\f\x00"
NUMBER = re.compile(rb"[+-]?(\d+\.?\d*|\.\d+)")


def _skip_string(raw, i):
    """Index just past the literal string that opens at raw[i] == '('."""
    n, depth, i = len(raw), 1, i + 1
    while i < n and depth:
        if raw[i] == 0x5C:  # backslash escape
            i += 2
            continue
        if raw[i] == 0x28:
            depth += 1
        elif raw[i] == 0x29:
            depth -= 1
        i += 1
    return min(i, n)


def _skip_hex(raw, i):
    """Index just past the hex string that opens at raw[i] == '<' (end of data if unterminated)."""
    end = raw.find(b">", i)
    return len(raw) if end < 0 else end + 1


def _skip_dict(raw, i):
    """Index just past the dictionary that opens at raw[i:i+2] == '<<'."""
    n, depth = len(raw), 0
    while i < n:
        two = raw[i:i + 2]
        if two == b"<<":
            depth += 1
            i += 2
        elif two == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                return i
        elif raw[i] == 0x28:
            i = _skip_string(raw, i)
        elif raw[i] == 0x3C:  # a hex string: its '>' is not half of a '>>'
            i = _skip_hex(raw, i)
        elif raw[i] == 0x25:  # comment
            while i < n and raw[i] not in b"\r\n":
                i += 1
        else:
            i += 1
    return n


INLINE_IMAGE_END = re.compile(rb"\sEI(?=\s|$)")


def _skip_inline_image(raw, i):
    """Index of the 'EI' that ends the inline image whose 'ID' operator ends at i.

    Searched in place from i: slicing the rest of the stream once per image
    made a stream of many small images quadratic.
    """
    m = INLINE_IMAGE_END.search(raw, i)
    return m.start() + 1 if m else len(raw)


def tokenize(raw):
    tokens, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i:i + 1]
        if raw[i] in WS:
            i += 1
            continue
        start = i
        if c == b"%":
            while i < n and raw[i] not in b"\r\n":
                i += 1
            continue
        if c == b"(":
            i = _skip_string(raw, i)
            tokens.append((start, i, "str", raw[start:i]))
            continue
        if raw[i:i + 2] == b"<<":
            i = _skip_dict(raw, i)
            tokens.append((start, i, "dict", raw[start:i]))
            continue
        if c == b"<":
            i = _skip_hex(raw, i)
            tokens.append((start, i, "hex", raw[start:i]))
            continue
        if c in (b"[", b"]"):
            i += 1
            tokens.append((start, i, "array", c))
            continue
        if c == b"/":
            i += 1
            while i < n and raw[i] not in WS and raw[i] not in DELIMS:
                i += 1
            tokens.append((start, i, "name", raw[start:i]))
            continue
        while i < n and raw[i] not in WS and raw[i] not in DELIMS:
            i += 1
        if i == start:  # a stray delimiter such as '>' or '{'
            i += 1
        word = raw[start:i]
        kind = "num" if NUMBER.fullmatch(word) else "op"
        tokens.append((start, i, kind, word))
        if word == b"ID":  # inline image data is binary, not operators
            i = _skip_inline_image(raw, i)
    return tokens


def remove_artifacts(raw, subtypes=("Header", "Footer")):
    """The stream without the artifact blocks of those subtypes, and how many were removed.

    None when a removed block does not balance its own q/Q or BT/ET, since cutting
    it would change the graphics state or text object of what follows.
    """
    wanted = re.compile(rb"/Subtype\s*/(?:%s)(?![^\s/<>\[\]()])" % b"|".join(s.encode() for s in subtypes))
    toks = tokenize(raw)
    cuts, stack = [], []   # per open marked-content block: (is_target, start_offset, q_depth, bt_depth)
    q = bt = 0
    removed = 0
    for idx, (s, e, kind, word) in enumerate(toks):
        if kind != "op":
            continue
        if word == b"BDC":
            tag = toks[idx - 2][3] if idx >= 2 else b""
            props = toks[idx - 1][3] if idx >= 1 else b""
            target = tag == b"/Artifact" and bool(wanted.search(props))
            begin = toks[idx - 2][0] if idx >= 2 else s
            stack.append((target, begin, q, bt))
        elif word == b"BMC":
            stack.append((False, toks[idx - 1][0] if idx >= 1 else s, q, bt))
        elif word == b"EMC":
            if not stack:
                return None  # an EMC with nothing open: the stream does not balance
            target, begin, q0, bt0 = stack.pop()
            if target and not any(t for t, *_ in stack):
                if q != q0 or bt != bt0:
                    return None
                cuts.append((begin, e))
                removed += 1
        elif word == b"q":
            q += 1
        elif word == b"Q":
            q -= 1
        elif word == b"BT":
            bt += 1
        elif word == b"ET":
            bt -= 1
    if stack:
        return None  # a block never closed: cutting could take body text
    if not cuts:
        return raw, 0
    out, last = [], 0
    for s, e in cuts:
        out.append(raw[last:s])
        last = e
    out.append(raw[last:])
    return b"".join(out), removed


def is_tagged(doc):
    cat = doc.pdf_catalog()
    mark = doc.xref_get_key(cat, "MarkInfo")[1]
    return "/Marked true" in mark and doc.xref_get_key(cat, "StructTreeRoot")[0] != "null"


def struct_types(doc):
    types = set()
    for x in range(1, doc.xref_length()):
        try:
            if doc.xref_get_key(x, "Type")[1] == "/StructElem":
                types.add(doc.xref_get_key(x, "S")[1])
        except Exception:  # noqa: BLE001 - a broken object is simply not a struct element
            continue
    return types


def stripped_copy(doc, subtypes=("Header", "Footer")):
    """(copy with every page's Header/Footer artifacts removed, blocks removed per page index).

    `subtypes` names the ones to remove: an edge that is not lifted keeps its
    artifacts, since removing them would delete their text from the Word file.

    clean_contents() leaves one content stream per page in PyMuPDF 1.28; a page
    that still has several is refused (a block could span them), so None, and
    so is a document that cannot be written out and opened again.
    """
    counts = {}
    try:
        copy = pymupdf.open("pdf", doc.tobytes())
    except Exception:  # noqa: BLE001 - a document that cannot be copied gives no answer
        return None
    try:
        for index in range(copy.page_count):
            page = copy[index]
            page.clean_contents()
            xrefs = page.get_contents()
            if not xrefs:
                counts[index] = 0
                continue
            if len(xrefs) != 1:
                copy.close()
                return None
            result = remove_artifacts(copy.xref_stream(xrefs[0]), subtypes)
            if result is None:
                copy.close()
                return None
            out, n = result
            if n:
                copy.update_stream(xrefs[0], out)
            counts[index] = n
    except Exception:  # noqa: BLE001 - any page that cannot be read means no answer
        copy.close()
        return None
    return copy, counts


def band_texts(pdf_path):
    """Texts of rows that disappear when the Header and Footer artifacts are removed."""
    import convert  # local: keeps module load free of the convert -> tagged cycle
    doc = pymupdf.open(pdf_path)
    try:
        made = stripped_copy(doc)
        if made is None:
            return []
        copy, _ = made
        seen = []
        try:
            for i in range(doc.page_count):
                after = {r["text"] for r in convert.page_rows(copy[i])}
                for r in convert.page_rows(doc[i]):
                    if r["text"] not in after and r["text"] not in seen:
                        seen.append(r["text"])
        finally:
            copy.close()
        return seen
    finally:
        doc.close()
