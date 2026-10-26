"""Reproducible stress documents for the Word export, all neutral filler.

    <venv>/python -I -B stress.py <out_root> [--cptc-template DIR]

Builds each document into <out_root>/<name>/ (main.typ, assets/, fonts/ for
CPTC). The CPTC template belongs to the owner and is read from its folder,
never copied into the repo. Redacted regions are drawn already pixelated
into the PNGs (see the plan's correction note).
"""
import os
import random
import shutil
import sys

import numpy as np
import pymupdf

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
# Report-card rows that fit one page of the CPTC template; 26 do, 27 do not.
REPORT_CARD_PAGE_ROWS = 26

DOCUMENTS = {
    "stress-cptc-57": {"template": "cptc", "findings": 19},
    "stress-cptc-short": {"template": "cptc", "findings": 3},
    "stress-cptc-long": {"template": "cptc", "findings": 50},
    "stress-findings": {"template": "findings", "findings": 40},
    "stress-thesis": {"template": "thesis", "findings": 24},       # "findings" = chapters' sections
    "stress-assessment": {"template": "assessment", "findings": 10}, # = landscape sections
    # The same template written out the way a finished report is: every finding
    # with several hosts, four to six walkthrough steps of commands and tool
    # output, nested remediation and a list of references, and an attack
    # narrative of timestamped steps over several days. `verbose` leaves the
    # documents above exactly as they were.
    "stress-cptc-verbose-a": {"template": "cptc", "findings": 8, "verbose": True},
    "stress-cptc-verbose-b": {"template": "cptc", "findings": 14, "verbose": True},
    "stress-cptc-verbose-c": {"template": "cptc", "findings": 22, "verbose": True},
    "stress-cptc-verbose-d": {"template": "cptc", "findings": 30, "verbose": True},
    # Verbose and then some: many findings, 10 to 20 hosts each, long tool
    # output, a week of narrative and long additional-findings and artifact
    # tables, with every figure allowed to break across pages. data-a stays
    # under convert.py's MAX_PAGES (300); data-b, at 436 pages, is over it on
    # purpose, so its Word export is the refusal. `compact` keeps data-b the
    # larger of the two in findings and host rows while fitting the server: one
    # screenshot and two or three steps a finding, so its images stay under the
    # 120 MP export budget and its PDF under 300 pages.
    "stress-cptc-data-a": {"template": "cptc", "findings": 36, "verbose": True, "data": True},
    "stress-cptc-data-b": {"template": "cptc", "findings": 60, "verbose": True, "data": True, "compact": True},
    # Six documents that vary the shape of the content rather than the amount;
    # see "Shape documents" below for what each one exercises.
    "stress-cptc-shape-a": {"template": "cptc", "findings": 6, "shape": "a"},
    "stress-cptc-shape-b": {"template": "cptc", "findings": 10, "shape": "b"},
    "stress-cptc-shape-c": {"template": "cptc", "findings": 15, "shape": "c"},
    "stress-cptc-shape-d": {"template": "cptc", "findings": 20, "shape": "d"},
    "stress-cptc-shape-e": {"template": "cptc", "findings": 25, "shape": "e"},
    "stress-cptc-shape-f": {"template": "cptc", "findings": 12, "shape": "f"},
}

# The per-document generator state. build() sets it before dispatching, so the
# helpers below draw from one seeded stream, in the same order the neutral
# generator this grew from did.
_rng = random.Random(7)

PALETTES = [(0.12, 0.14, 0.2), (0.95, 0.96, 0.98), (0.2, 0.3, 0.45), (0.98, 0.94, 0.88)]
REDACTIONS = [(0.03, 0.2, 0.4, 0.12), (0.03, 0.5, 0.3, 0.1)]
CELL = 12

LOREM = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut "
         "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
         "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit "
         "esse cillum dolore eu fugiat nulla pariatur.").split()


def image(path, title, redact=False, width=960, height=540):
    """A synthetic 'screenshot': window chrome, a title, rows of text and a bar chart.

    With redact set, two regions are block-averaged into 12 px cells before the
    PNG is written, so the redaction is part of the pixels.
    """
    rng = _rng
    doc = pymupdf.open()
    page = doc.new_page(width=width, height=height)
    bg = rng.choice(PALETTES)
    dark = sum(bg) < 1.5
    fg = (0.9, 0.92, 0.95) if dark else (0.15, 0.15, 0.2)
    page.draw_rect(page.rect, fill=bg, color=None)
    page.draw_rect(pymupdf.Rect(0, 0, width, 34), fill=(0.3, 0.32, 0.36), color=None)
    for i, c in enumerate([(0.9, 0.3, 0.3), (0.95, 0.75, 0.2), (0.3, 0.8, 0.4)]):
        page.draw_circle((20 + i * 20, 17), 6, fill=c, color=None)
    page.insert_text((90, 23), title, fontsize=13, fontname="helv", color=(1, 1, 1))
    y = 70
    for i in range(12):
        words = " ".join(rng.choice(["alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
                                     "golf", "hotel", "india", "juliet", "kilo", "lima"])
                         for _ in range(rng.randint(4, 9)))
        page.insert_text((30, y), "%02d  %s" % (i + 1, words), fontsize=12, fontname="cour", color=fg)
        y += 22
    for i in range(8):
        h = rng.randint(40, 200)
        x = 560 + i * 45
        page.draw_rect(pymupdf.Rect(x, 480 - h, x + 30, 480),
                       fill=(rng.random() * 0.6 + 0.3, rng.random() * 0.5 + 0.3, 0.8), color=None)
    pix = page.get_pixmap(dpi=96)
    doc.close()
    if redact:
        w, h, n = pix.width, pix.height, pix.n
        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(h, w, n).copy()
        for fx, fy, fw, fh in REDACTIONS:
            x0, y0 = int(fx * w), int(fy * h)
            x1, y1 = min(w, int((fx + fw) * w)), min(h, int((fy + fh) * h))
            for cy in range(y0, y1, CELL):
                for cx in range(x0, x1, CELL):
                    block = arr[cy:min(cy + CELL, y1), cx:min(cx + CELL, x1)]
                    block[:] = block.reshape(-1, n).mean(axis=0).astype(np.uint8)
        pix = pymupdf.Pixmap(pymupdf.csRGB, w, h, bytes(arr), 0)
    pix.save(path)


def prose(n):
    start = _rng.randint(0, len(LOREM) - 1)
    words = [LOREM[(start + i) % len(LOREM)] for i in range(n)]
    text = " ".join(words).replace(",", "").replace(".", "")
    return text[0].upper() + text[1:] + "."


def para(sentences=4):
    return " ".join(prose(_rng.randint(10, 22)) for _ in range(sentences))


def s(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')


def write_text(folder, name, text):
    with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# CPTC

LEVEL_ORDER = [("critical", "9.1"), ("high", "7.8"), ("medium", "5.4"), ("low", "3.1")]
TOPICS = ["Outdated software component", "Weak configuration setting", "Missing security header",
          "Verbose error message", "Default service banner", "Excessive account permissions",
          "Unencrypted internal service", "Stale user accounts", "Missing patch baseline",
          "Inconsistent logging policy", "Legacy protocol enabled", "Shared local credentials",
          "Overly broad firewall rule", "Unrestricted file share", "Expired certificate",
          "Unmonitored backup job", "Weak password policy", "Open management interface",
          "Missing asset inventory entry"]


def level_counts(total):
    crit = max(1, round(0.15 * total))
    high = max(1, round(0.25 * total))
    med = max(1, round(0.30 * total))
    low = max(1, total - crit - high - med)
    return [crit, high, med, low]


def cptc_finding_block(f):
    scope = ", ".join('("%s", "%s", "%s")' % h for h in f["hosts"])
    steps = []
    for k, img in enumerate(f["imgs"], 1):
        steps.append(
            '  *%d. Observation step %d* \\\n  %s\n  #cmd[```bash\n  # sample command output for step %d\n'
            '  echo "checking host inventory"\n  ls -la /opt/app/config\n  ```]\n'
            '  #image-placeholder("%s", path: "/assets/%s")\n'
            % (k, k, para(2), k, s("Evidence captured for " + f["title"].lower()), img))
    return (
        '#finding(\n'
        '  level: "%s",\n  title: "%s",\n  impact: "%s",\n  likelihood: "%s",\n'
        '  cvss: "%s",\n  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",\n'
        '  scope: (%s,),\n'
        '  description: [%s],\n  business-impact: [%s],\n  likelihood-description: [%s],\n'
        '  tactics: ("Technique A", "Technique B"),\n  mitigations: ("Mitigation A", "Mitigation B"),\n'
        '  exploitation: [\n%s  ],\n'
        '  remediation: [\n  + %s\n  + %s\n  + %s\n  ],\n'
        '  resources: ([#link("https://example.com/guidance")[Vendor guidance]], [#link("https://example.org/reference")[Reference article]]),\n'
        ')\n\n#end-of-block\n'
    ) % (f["level"], s(f["title"]), f["level"].title(), _rng.choice(["Low", "Medium", "High"]), f["cvss"],
         scope, para(3), para(2), para(2), "\n".join(steps), prose(12), prose(10), prose(14))


# Verbose CPTC documents

NARRATIVE_DAYS = 5
DATA_NARRATIVE_DAYS = 7
# Set by build_cptc for a "data" document: everything verbose, only more of it.
_data = False
_compact = False
NARRATIVE_SHOTS = 2
STEP_TITLES = ["Service discovery", "Version fingerprinting", "Unauthenticated access check",
               "Credential validation", "Configuration review", "Privilege review",
               "Lateral reachability", "Data exposure check", "Persistence review", "Cleanup and verification"]
TECHNIQUES = ["T1046 Network Service Discovery", "T1078 Valid Accounts", "T1110 Brute Force",
              "T1190 Exploit Public-Facing Application", "T1021 Remote Services",
              "T1083 File and Directory Discovery", "T1552 Unsecured Credentials", "T1210 Exploitation of Remote Services"]
MITIGATIONS = ["M1026 Privileged Account Management", "M1032 Multi-factor Authentication",
               "M1042 Disable or Remove Feature or Program", "M1051 Update Software",
               "M1030 Network Segmentation", "M1047 Audit", "M1027 Password Policies"]
WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"]


def cvss_vector():
    pick = _rng.choice
    return "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s" % (
        pick("NAL"), pick("LH"), pick("NLH"), pick("NR"), pick("UC"), pick("HLN"), pick("HLN"), pick("HLN"))


def host():
    return "10.10.%d.%d" % (_rng.randint(1, 9), _rng.randint(2, 250))


def narrative_days():
    return DATA_NARRATIVE_DAYS if _data else NARRATIVE_DAYS


def tool_session(target):
    """A command and some tool output for it, as the lines of a code block."""
    kind = _rng.randrange(4)
    if kind == 0:
        lines = ["$ nmap -sV -Pn -p 22,80,443,445,8080 %s" % target,
                 "Nmap scan report for %s" % target, "PORT     STATE SERVICE  VERSION"]
        for port, service in [(22, "ssh"), (80, "http"), (443, "https"), (445, "smb"), (8080, "http-alt")]:
            if _rng.random() < 0.8:
                lines.append("%-8s open  %-8s %s %d.%d" % ("%d/tcp" % port, service, _rng.choice(WORDS),
                                                            _rng.randint(1, 9), _rng.randint(0, 20)))
        lines.append("Service detection performed. %d IP address scanned." % 1)
    elif kind == 1:
        lines = ["$ curl -sk -D - https://%s/%s -o /dev/null" % (target, _rng.choice(WORDS)),
                 "HTTP/1.1 200 OK", "Server: %s/%d.%d" % (_rng.choice(WORDS), _rng.randint(1, 9), _rng.randint(0, 9)),
                 "Content-Type: text/html; charset=utf-8", "Cache-Control: no-store",
                 "X-Request-Id: %08x" % _rng.getrandbits(32), "Content-Length: %d" % _rng.randint(400, 9000)]
    elif kind == 2:
        lines = ["$ smbclient -L //%s -N" % target, "    Sharename       Type      Comment",
                 "    ---------       ----      -------"]
        for _ in range(_rng.randint(12, 24) if _data else _rng.randint(3, 6)):
            lines.append("    %-15s Disk      %s" % (_rng.choice(WORDS) + "$" * _rng.randint(0, 1), prose(3).rstrip(".")))
    else:
        lines = ["$ python3 check_%s.py --target %s --verbose" % (_rng.choice(WORDS), target)]
        for i in range(_rng.randint(20, 40) if _data else _rng.randint(5, 10)):
            lines.append("[%s] %s %s" % (_rng.choice(["+", "*", "-"]), _rng.choice(WORDS),
                                         " ".join(_rng.choice(WORDS) for _ in range(_rng.randint(3, 7)))))
        lines.append("[+] done in %d.%02ds" % (_rng.randint(0, 9), _rng.randint(0, 99)))
    return lines


def code_block(lines, indent="  "):
    return "%s#cmd[```bash\n%s\n%s```]\n" % (indent, "\n".join(indent + line for line in lines), indent)


def verbose_finding_block(f):
    """A finding written out in full: the shape of a finished report, not a sketch."""
    scope = ", ".join('("%s", "%s", "%s")' % h for h in f["hosts"])
    steps = []
    for k in range(1, (_rng.randint(2, 3) if _compact else _rng.randint(5, 7) if _data else _rng.randint(4, 6)) + 1):
        target = f["hosts"][(k - 1) % len(f["hosts"])][0]
        step = "  *%d. %s* \\\n  %s\n\n  %s\n%s" % (
            k, _rng.choice(STEP_TITLES), para(3), para(2), code_block(tool_session(target)))
        if k <= len(f["imgs"]):
            step += '  #image-placeholder("%s", path: "/assets/%s")\n' % (
                s("%s, step %d" % (f["title"], k)), f["imgs"][k - 1])
        steps.append(step)
    remediation = []
    for _ in range(_rng.randint(3, 4)):
        subs = "".join("\n    - %s" % prose(_rng.randint(8, 14)) for _ in range(_rng.randint(2, 3)))
        remediation.append("  + %s%s" % (prose(_rng.randint(6, 10)), subs))
    remediation.append(code_block(["# example hardening change, applied per host", "sudo systemctl stop %s" % _rng.choice(WORDS),
                                   "sudo sed -i 's/^Enabled=.*/Enabled=false/' /etc/%s.conf" % _rng.choice(WORDS),
                                   "sudo systemctl start %s" % _rng.choice(WORDS)]))
    resources = ", ".join('[#link("https://example.%s/%s")[%s]]' % (_rng.choice(["com", "org", "net"]), _rng.choice(WORDS), prose(4).rstrip("."))
                          for _ in range(_rng.randint(4, 5)))
    return (
        '#finding(\n'
        '  level: "%s",\n  title: "%s",\n  impact: "%s",\n  likelihood: "%s",\n'
        '  cvss: "%s",\n  vector: "%s",\n'
        '  scope: (%s,),\n'
        '  description: [%s\n\n  %s\n\n  %s],\n  business-impact: [%s\n\n  %s],\n  likelihood-description: [%s],\n'
        '  tactics: (%s),\n  mitigations: (%s),\n'
        '  exploitation: [\n%s  ],\n'
        '  remediation: [\n%s\n  ],\n'
        '  resources: (%s,),\n'
        ')\n\n#end-of-block\n'
    ) % (f["level"], s(f["title"]), f["level"].title(), _rng.choice(["Low", "Medium", "High"]), f["cvss"],
         cvss_vector(), scope, para(4), para(3), para(3), para(3), para(2), para(3),
         ", ".join('"%s"' % t for t in _rng.sample(TECHNIQUES, 3)) + ",",
         ", ".join('"%s"' % m for m in _rng.sample(MITIGATIONS, 3)) + ",",
         "\n".join(steps), "\n".join(remediation), resources)


def verbose_narrative(findings):
    """Several days of timestamped steps, each with commands, output and screenshots."""
    days = []
    for d in range(1, narrative_days() + 1):
        out = ["=== September %d, 2026\n\n%s\n" % (7 + d, para(4))]
        clock = _rng.randint(8, 10) * 60 + _rng.randint(0, 59)
        shots = 0
        steps = _rng.randint(4, 6)
        for k in range(steps):
            clock += _rng.randint(12, 75)
            related = findings[_rng.randrange(len(findings))]["title"]
            out.append("*%02d:%02d UTC: %s* \\\n%s The activity here is recorded as %s. %s\n"
                       % (clock // 60 % 24, clock % 60, _rng.choice(STEP_TITLES), para(2), s(related), para(2)))
            out.append(code_block(tool_session(host()), indent=""))
            if shots < NARRATIVE_SHOTS and k in (1, steps - 1):
                shots += 1
                out.append('#image-placeholder("Activity on day %d, capture %d", path: "/assets/narrative-day%d-%d.png")\n'
                           % (d, shots, d, shots))
        out.append(para(3) + "\n")
        days.append("\n".join(out))
    return days


# Shape documents
#
# The six `shape` documents vary the SHAPE of the content rather than the
# amount: where the screenshots sit, where the code goes, which tables the
# author draws and what inline formatting they reach for. Between them they
# exercise every placement the template allows, so a converter defect that
# depends on position shows up in at least one. Each has one emphasis:
#   a: images (a grid of two, one in a table cell, full width, 2 in wide,
#      portrait, one followed by code, one under a heading, one last on its
#      page, a long caption, a finding with eight and one with none)
#   b: code (60-line output across a page break, six languages, 150-char
#      lines, YAML and Python indentation, back to back, in a table cell,
#      first after a heading, last on its page, an appendix of scripts)
#   c: tables (merged header cells, a row across a page break, six columns,
#      no fill, every row filled, long wrapped cells, a list in a cell, one
#      right after a code block, 10 to 20 hosts a finding, long additional
#      findings and artifact tables)
#   d: inline formatting (bold, italic, both, monospace, links, highlight,
#      colour, bullets three deep, numbered sub-steps, a quote, a footnote, a
#      rule, a forced page break inside a finding, a two-line title, a
#      two-sentence finding, headings to level four)
#   e: a table of contents over two pages (40 or more entries), 25 findings,
#      and the longest additional-findings and artifact tables
#   f: all of the above, mixed by the generator
# Each shape document seeds its own stream, and the paths below run only when
# `shape` is set, so every other document is built byte for byte as before.
_shape = None
SHAPE_LANGS = ["bash", "powershell", "python", "yaml", "json", ""]
SHAPE_NARRATIVE_DAYS = 4
LONG_TITLE = ("with an unmaintained dependency chain reachable through the externally exposed "
              "administrative interface of the primary application cluster")


def shape_plan(shape, i, total):
    """What finding i of a shape document holds: steps, images and extras."""
    o = {"steps": 3, "kinds": ["placeholder"] * 3, "langs": ["bash"], "long_output": False,
         "back_to_back": False, "long_lines": False, "code_in_cell": False, "config": "bash",
         "hosts": (2, 6), "marks": False, "nested": False, "quote": False, "footnote": False,
         "break": False, "rule": False, "long_title": False, "tiny": False, "cell_tables": False}
    if shape == "a":
        if i == 0:
            o["steps"] = 8
            o["kinds"] = ["then-code", "heading", "small", "full", "portrait", "grid", "cell", "longcaption"]
        elif i == 1:
            o["kinds"] = []
        else:
            o["steps"] = 4
            o["kinds"] = ["placeholder"] * 3
    elif shape == "b":
        o["steps"] = 4
        o["kinds"] = ["placeholder"]
        o["langs"] = SHAPE_LANGS[i % 6:] + SHAPE_LANGS[:i % 6]
        o["long_output"] = i % 2 == 0
        o["back_to_back"] = i % 3 == 0
        o["long_lines"] = i % 4 == 1
        o["code_in_cell"] = i % 4 == 2
        o["config"] = ["yaml", "json", "powershell"][i % 3]
    elif shape == "c":
        o["steps"] = 2
        o["kinds"] = ["placeholder"]
        o["hosts"] = (10, 20)
        o["cell_tables"] = i % 2 == 0
    elif shape == "d":
        o["steps"] = 2 if i % 2 else 3
        o["kinds"] = ["placeholder"] * (1 if i % 2 else 2)
        o["marks"] = True
        o["nested"] = True
        o["quote"] = i % 2 == 0
        o["footnote"] = i % 3 == 0
        o["break"] = i == 2
        o["rule"] = True
        o["long_title"] = i == 0
        if i == 3:
            o.update({"tiny": True, "steps": 1, "kinds": [], "nested": False, "quote": False, "footnote": False})
    elif shape == "e":
        o["steps"] = 2
        o["kinds"] = ["placeholder"]
        o["hosts"] = (2, 4)
    else:
        pick = _rng.choice
        o["steps"] = _rng.randint(2, 5)
        kinds = ["placeholder", "full", "small", "portrait", "grid", "cell", "longcaption", "heading", "then-code"]
        o["kinds"] = [pick(kinds) for _ in range(_rng.randint(0, o["steps"]))]
        o["langs"] = _rng.sample(SHAPE_LANGS, 3)
        o["long_output"] = _rng.random() < 0.3
        o["back_to_back"] = _rng.random() < 0.3
        o["long_lines"] = _rng.random() < 0.25
        o["code_in_cell"] = _rng.random() < 0.25
        o["config"] = pick(["bash", "yaml", "json", "powershell"])
        o["hosts"] = pick([(2, 6), (8, 14)])
        o["marks"] = _rng.random() < 0.5
        o["nested"] = _rng.random() < 0.5
        o["quote"] = _rng.random() < 0.3
        o["footnote"] = _rng.random() < 0.3
        o["rule"] = _rng.random() < 0.3
        o["cell_tables"] = _rng.random() < 0.3
        o["long_title"] = i == 1
    return o


def shape_code(lang, lines, indent="  "):
    """A #cmd strip in one language; an empty language is a bare fence."""
    return "%s#cmd[```%s\n%s\n%s```]\n" % (indent, lang, "\n".join(indent + line for line in lines), indent)


def shape_long_output(target, count=70):
    lines = ["$ python3 enum_%s.py --target %s --verbose --all" % (_rng.choice(WORDS), target)]
    for i in range(count):
        lines.append("[%03d] [%s] %s" % (i + 1, _rng.choice("+*-"), " ".join(_rng.choice(WORDS) for _ in range(_rng.randint(4, 9)))))
    lines.append("[+] finished: %d records" % count)
    return lines


def shape_long_lines(target):
    token = "".join(_rng.choice("abcdef0123456789") for _ in range(96))
    return ["$ curl -sk -H 'Authorization: Bearer %s' 'https://%s/api/v2/%s/%s?page=1&size=200&sort=name&include=all&format=json' -o /dev/null -w '%%{http_code}'"
            % (token[:40], target, _rng.choice(WORDS), _rng.choice(WORDS)),
            "200",
            "$ wget -q https://%s/downloads/releases/%s/%s/%s.tar.gz" % (target, token, token[::-1], token[:48]),
            "[+] %s" % " ".join(_rng.choice(WORDS) for _ in range(32))]


def shape_lang_sample(lang, target):
    if lang == "bash":
        return tool_session(target)
    if lang == "powershell":
        rows = ["PS C:\\> Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort", "",
                "LocalAddress LocalPort", "------------ ---------"]
        for port in (135, 445, 3389, 5985):
            if _rng.random() < 0.85:
                rows.append("0.0.0.0      %d" % port)
        return rows
    if lang == "python":
        return ["import socket", "", "def probe(host, port):",
                "    with socket.create_connection((host, port), timeout=3) as s:",
                "        s.sendall(b\"HEAD / HTTP/1.0\\r\\n\\r\\n\")",
                "        return s.recv(256)", "", "for port in (22, 80, 443):",
                "    print(port, probe(\"%s\", port))" % target]
    if lang == "yaml":
        return ["server:", "  listen: %s:8080" % target, "  tls:", "    enabled: false", "  auth:",
                "    mode: none", "    allow_anonymous: true", "logging:", "  level: debug",
                "  targets:", "    - stdout", "    - /var/log/%s.log" % _rng.choice(WORDS)]
    if lang == "json":
        return ["{", '  "host": "%s",' % target, '  "ports": [22, 80, 443],', '  "findings": {',
                '    "critical": %d,' % _rng.randint(0, 3), '    "high": %d' % _rng.randint(0, 5), "  },",
                '  "notes": "%s"' % prose(6).rstrip("."), "}"]
    return ["Connection to %s 445 port [tcp/microsoft-ds] succeeded!" % target, "NT_STATUS_OK",
            "session setup ok", "tree connect ok", "%s" % prose(8)]


def shape_marks(target):
    return ("*Bold text*, _italic text_, *_bold italic text_*, `inline monospace` and "
            "#link(\"https://example.com/%s\")[a link to guidance]; #highlight[highlighted text] and "
            "#text(fill: rgb(\"#c0504d\"))[coloured text] were observed on #raw(\"%s\")." % (_rng.choice(WORDS), target))


def shape_caption(f, k, long=False):
    text = "%s, step %d" % (f["title"], k)
    if long:
        text += ": " + para(3)
    return s(text)


def shape_image(f, k, shot):
    """One screenshot placement inside an exploitation step."""
    kind, files = shot
    path = "/assets/%s" % files[0]
    if kind == "placeholder":
        return '  #image-placeholder("%s", path: "%s")\n' % (shape_caption(f, k), path)
    if kind == "then-code":
        return ('  #image-placeholder("%s", path: "%s")\n' % (shape_caption(f, k), path)
                + shape_code("bash", ["$ id", "uid=0(root) gid=0(root) groups=0(root)"]))
    if kind == "heading":
        return '  ==== Evidence for step %d\n  #image-placeholder("%s", path: "%s")\n' % (k, shape_caption(f, k), path)
    if kind == "small":
        return ('  #[\n  #show figure: set align(left)\n  #figure(image("%s", width: 2in), caption: [%s])\n  ]\n'
                % (path, shape_caption(f, k)))
    if kind == "full":
        return '  #figure(image("%s", width: 100%%), caption: [%s])\n' % (path, shape_caption(f, k))
    if kind == "portrait":
        return '  #figure(image("%s", height: 5in), caption: [%s])\n' % (path, shape_caption(f, k))
    if kind == "grid":
        return ('  #figure(grid(columns: (1fr, 1fr), gutter: 8pt, image("%s", width: 100%%), image("/assets/%s", width: 100%%)),\n'
                '    caption: [%s])\n' % (path, files[1], shape_caption(f, k)))
    if kind == "cell":
        return ('  #table(columns: (1.3in, 1fr),\n    lcell[Capture], image("%s", width: 100%%),\n'
                '    lcell[Notes], [%s],\n  )\n' % (path, para(2)))
    if kind == "longcaption":
        return '  #image-placeholder("%s", path: "%s")\n' % (shape_caption(f, k, long=True), path)
    raise ValueError(kind)


def shape_command_table(f):
    rows = []
    for host_ip, service, port in f["hosts"][:4]:
        rows.append("    [%s], [```bash\n    nmap -sV -p %s %s\n    ```],\n" % (host_ip, port, host_ip))
    return "  #table(columns: (1.2in, 1fr),\n    hcell(align: left)[Host], hcell(align: left)[Command],\n%s  )\n" % "".join(rows)


def shape_cell_list_table():
    return ("  #table(columns: (1.2in, 1fr),\n    hcell(align: left)[Check], hcell(align: left)[Result],\n"
            "    [Steps taken], [#enum([%s], [%s], [%s])],\n    [Observation], [%s],\n  )\n"
            % (prose(6), prose(7), prose(5), para(3)))


def shape_exploitation(f, o):
    steps = []
    kinds = f["shots"]
    for k in range(1, o["steps"] + 1):
        target = f["hosts"][(k - 1) % len(f["hosts"])][0]
        lang = o["langs"][(k - 1) % len(o["langs"])]
        parts = ["  *%d. %s* \\\n  %s\n" % (k, _rng.choice(STEP_TITLES), para(2 if o["tiny"] else 3))]
        if o["marks"] and k == 1:
            parts.append("\n  %s\n" % shape_marks(target))
        if o["quote"] and k == 1:
            parts.append("\n  #quote(block: true, attribution: [Internal policy])[%s]\n" % prose(18))
        if o["footnote"] and k == min(2, o["steps"]):
            parts.append("\n  %s#footnote[%s]\n" % (prose(8), prose(10)))
        if o["long_output"] and k == 2:
            lines = shape_long_output(target)
        elif o["long_lines"] and k == 3:
            lines = shape_long_lines(target)
        else:
            lines = shape_lang_sample(lang, target)
        parts.append(shape_code(lang, lines))
        if o["back_to_back"] and k == 1:
            parts.append(shape_code("json", shape_lang_sample("json", target)))
        if o["code_in_cell"] and k == 2:
            parts.append(shape_command_table(f))
        if o["cell_tables"] and k == 1:
            parts.append(shape_cell_list_table())
        if k - 1 < len(kinds):
            parts.append(shape_image(f, k, kinds[k - 1]))
        if o["break"] and k == 1:
            parts.append("  #colbreak()\n")
        if o["rule"] and k < o["steps"]:
            parts.append("  #line(length: 100%, stroke: 0.5pt + luma(150))\n")
        steps.append("".join(parts))
    return "\n".join(steps)


def shape_remediation(o):
    if o["tiny"]:
        return "  + %s\n" % prose(9)
    items = []
    for _ in range(_rng.randint(2, 4)):
        if o["nested"]:
            subs = ""
            for _ in range(_rng.randint(1, 3)):
                subs += "\n    - %s" % prose(_rng.randint(6, 12))
                if _rng.random() < 0.7:
                    subs += "\n      - %s\n      - %s" % (prose(5), prose(6))
            items.append("  + %s%s" % (prose(_rng.randint(6, 10)), subs))
        else:
            items.append("  + %s" % prose(_rng.randint(8, 14)))
    items.append("  + Apply the configuration below.\n    + Back up the current file first.\n    + Restart the service after the change.")
    items.append(shape_code(o["config"], shape_lang_sample(o["config"], host())))
    return "\n".join(items) + "\n"


def shape_finding_block(f):
    o = f["plan"]
    scope = ", ".join('("%s", "%s", "%s")' % h for h in f["hosts"])
    title = f["title"] + " " + LONG_TITLE if o["long_title"] else f["title"]
    description = prose(12) + " " + prose(10) if o["tiny"] else "%s\n\n  %s" % (para(4), para(3))
    resources = ", ".join('[#link("https://example.%s/%s")[%s]]' % (_rng.choice(["com", "org", "net"]), _rng.choice(WORDS), prose(4).rstrip("."))
                          for _ in range(_rng.randint(2, 4)))
    return (
        '#finding(\n'
        '  level: "%s",\n  title: "%s",\n  impact: "%s",\n  likelihood: "%s",\n'
        '  cvss: "%s",\n  vector: "%s",\n'
        '  scope: (%s,),\n'
        '  description: [%s],\n  business-impact: [%s],\n  likelihood-description: [%s],\n'
        '  tactics: (%s),\n  mitigations: (%s),\n'
        '  exploitation: [\n%s  ],\n'
        '  remediation: [\n%s  ],\n'
        '  resources: (%s,),\n'
        ')\n\n#end-of-block\n'
    ) % (f["level"], s(title), f["level"].title(), _rng.choice(["Low", "Medium", "High"]), f["cvss"],
         cvss_vector(), scope, description, prose(14) if o["tiny"] else para(2), prose(12),
         ", ".join('"%s"' % t for t in _rng.sample(TECHNIQUES, 2)) + ",",
         ", ".join('"%s"' % m for m in _rng.sample(MITIGATIONS, 2)) + ",",
         shape_exploitation(f, o), shape_remediation(o), resources)


def shape_narrative(findings, shape):
    """Four days; each day places its captures differently."""
    days = []
    for d in range(1, SHAPE_NARRATIVE_DAYS + 1):
        out = ["=== September %d, 2026\n\n%s\n" % (7 + d, para(3))]
        clock = _rng.randint(8, 10) * 60 + _rng.randint(0, 59)
        for k in range(_rng.randint(3, 4)):
            clock += _rng.randint(12, 75)
            related = findings[_rng.randrange(len(findings))]["title"]
            out.append("*%02d:%02d UTC: %s* \\\n%s The activity here is recorded as %s.\n"
                       % (clock // 60 % 24, clock % 60, _rng.choice(STEP_TITLES), para(2), s(related)))
            if shape in ("b", "f") or k == 1:
                lines = shape_long_output(host(), count=64) if shape == "b" and k == 1 and d == 2 else tool_session(host())
                out.append(code_block(lines, indent=""))
            if shape == "d" and k == 0:
                out.append("- %s\n  - %s\n    - %s\n    - %s\n  - %s\n- %s\n" % tuple(prose(_rng.randint(5, 9)) for _ in range(6)))
            if shape == "c" and k == 0:
                out.append("#table(columns: 6, align: left,\n  hcell[Time], hcell[Host], hcell[Port], hcell[Service], hcell[Result], hcell[Note],\n%s)\n"
                           % "".join("  [%02d:%02d], [%s], [%d], [%s], [%s], [%s],\n"
                                     % (clock // 60 % 24, (clock + j) % 60, host(), _rng.choice([22, 80, 443, 445]),
                                        _rng.choice(["ssh", "http", "https", "smb"]), _rng.choice(["open", "closed", "filtered"]), prose(3).rstrip("."))
                                     for j in range(6)))
        a, b = "narr-d%d-1.png" % d, "narr-d%d-2.png" % d
        if d == 1:
            # The capture is the last thing on its page.
            out.append('#image-placeholder("Activity on day %d, capture 1", path: "/assets/%s")\n#pagebreak()\n' % (d, a))
        elif d == 2:
            out.append('==== Evidence collected on day %d\n#image-placeholder("Activity on day %d, capture 1", path: "/assets/%s")\n' % (d, d, a))
        elif d == 3:
            out.append('#image-placeholder("Activity on day %d, capture 1", path: "/assets/%s")\n%s' % (d, a, code_block(tool_session(host()), indent="")))
        else:
            out.append('#figure(grid(columns: (1fr, 1fr), gutter: 8pt, image("/assets/%s", width: 100%%), image("/assets/%s", width: 100%%)),\n'
                       '  caption: [Two captures from day %d, side by side])\n' % (a, b, d))
        out.append(para(3) + "\n")
        days.append("\n".join(out))
    return days


def shape_appendices(shape, findings):
    """Extra level-1 sections after Appendix B, one set per emphasis."""
    out = []
    if shape in ("b", "f"):
        out.append("= APPENDIX C: SCRIPTS\n\n== COLLECTION SCRIPT\n" + shape_code("python", shape_lang_sample("python", host()), indent="")
                   + "\n" + shape_code("yaml", shape_lang_sample("yaml", host()), indent="")
                   + "\n== INVENTORY\n\n%s\n" % para(2)
                   + shape_code("", shape_lang_sample("", host()), indent="")
                   + "#table(columns: (1.5in, 1fr), hcell(align: left)[Host], hcell(align: left)[Result],\n%s)\n"
                   % "".join("  [%s], [%s],\n" % (host(), prose(5)) for _ in range(6))
                   + "\n== LONG LINES\n\n" + shape_code("bash", shape_long_lines(host()), indent="")
                   + "#pagebreak()\n\n== CLOSING NOTE\n\n%s\n" % para(2))
    if shape in ("c", "f"):
        wide = "".join("    [%s], [%s], [%d], [%s], [%s], [%s],\n"
                       % (host(), _rng.choice(["Linux", "Windows", "Appliance"]), _rng.choice([22, 80, 443, 445, 3389]),
                          _rng.choice(["ssh", "http", "https", "smb", "rdp"]), _rng.choice(["open", "closed"]), prose(3).rstrip("."))
                       for _ in range(30))
        long_cell = " \\\n    ".join("[%03d] %s" % (i + 1, prose(7).rstrip(".")) for i in range(60))
        out.append(
            "= APPENDIX C: HOST INVENTORY\n\n== MERGED HEADERS\n\n%s\n\n"
            "#figure(table(columns: (1.5in, 1fr, 1fr),\n  hcell(colspan: 3)[Inventory summary],\n  hcell[Host], hcell(colspan: 2)[Services and notes],\n%s),\n  caption: [A table with merged header cells])\n\n"
            "== SIX COLUMNS\n\n#figure(table(columns: 6,\n    hcell[Host], hcell[OS], hcell[Port], hcell[Service], hcell[State], hcell[Note],\n%s  ),\n  caption: [A six-column inventory that breaks across pages])\n\n"
            "== NO FILL\n\n#table(columns: 3, fill: none,\n  [*Name*], [*Value*], [*Note*],\n%s)\n\n"
            "== EVERY ROW FILLED\n\n#table(columns: 3, fill: rgb(\"#e8eef7\"),\n  [*Name*], [*Value*], [*Note*],\n%s)\n\n"
            "== LONG CELLS\n\n#table(columns: (1.2in, 1fr),\n%s)\n\n"
            "== A LIST IN A CELL\n\n%s\n"
            "== AFTER CODE\n\n%s#table(columns: (1.5in, 1fr), hcell(align: left)[Host], hcell(align: left)[Result],\n%s)\n\n"
            "== A ROW ACROSS A PAGE BREAK\n\n#table(columns: (1.2in, 1fr),\n  hcell(align: left)[Log], hcell(align: left)[Lines],\n  [session.log], [\n    %s\n  ],\n)\n"
            % (para(2),
               "".join("  [%s], [%s], [%s],\n" % (host(), prose(4), prose(5)) for _ in range(5)),
               wide,
               "".join("  [%s], [%d], [%s],\n" % (_rng.choice(WORDS), _rng.randint(1, 999), prose(4)) for _ in range(6)),
               "".join("  [%s], [%d], [%s],\n" % (_rng.choice(WORDS), _rng.randint(1, 999), prose(4)) for _ in range(6)),
               "".join("  [%s], [%s],\n" % (host(), para(3)) for _ in range(5)),
               shape_cell_list_table().replace("\n  ", "\n"),
               shape_code("bash", tool_session(host()), indent=""),
               "".join("  [%s], [%s],\n" % (host(), prose(5)) for _ in range(5)),
               long_cell))
    if shape in ("d", "f"):
        out.append(
            "= APPENDIX C: FORMATTING SAMPLES\n\n== HEADINGS\n\n%s\n\n=== A THIRD-LEVEL HEADING\n\n%s\n\n==== A fourth-level heading\n\n%s\n\n"
            "== MARKS\n\n%s\n\n#line(length: 100%%, stroke: 0.5pt + luma(150))\n\n#quote(block: true, attribution: [Engagement lead])[%s]\n\n"
            "== LISTS\n\n+ %s\n  + %s\n    + %s\n  + %s\n+ %s\n\n- %s\n  - %s\n    - %s\n\n"
            "%s#footnote[%s]\n"
            % (para(2), para(2), para(2), shape_marks(host()), prose(16),
               prose(6), prose(6), prose(6), prose(6), prose(6), prose(6), prose(6), prose(6),
               para(2), prose(10)))
    if shape in ("e", "f"):
        for letter, name in zip("CDEFG", ["TOOLING", "TIMELINE DETAIL", "SCAN COVERAGE", "CREDENTIAL HANDLING", "DATA HANDLING"]):
            if shape == "f" and letter > "D":
                break
            subs = "\n\n".join("== %s %s\n\n%s" % (name.title(), _rng.choice(WORDS).upper(), para(3)) for _ in range(6))
            out.append("= APPENDIX %s: %s\n\n%s\n" % (letter, name, subs))
    return "\n".join(out)


def build_cptc(name, folder, template_dir, total, rng, verbose=False, data=False, compact=False, shape=None):
    global _data, _compact, _shape
    _data = data
    _compact = compact
    _shape = shape
    assets = os.path.join(folder, "assets")
    counts = level_counts(total)
    findings = []
    n = 0
    for (level, cvss), count in zip(LEVEL_ORDER, counts):
        for _ in range(count):
            topic = TOPICS[n % len(TOPICS)]
            if shape:
                plan = shape_plan(shape, n, total)
                shots = []
                for k, kind in enumerate(plan["kinds"], 1):
                    files = []
                    for j in range(2 if kind == "grid" else 1):
                        img = "finding-%02d-step%d%s.png" % (n + 1, k, "ab"[j] if kind == "grid" else "")
                        size = {"width": 540, "height": 960} if kind == "portrait" else {}
                        image(os.path.join(assets, img), "Evidence for %s, step %d" % (topic.lower(), k),
                              redact=(k == 1 and n % 3 == 0) or (kind in ("full", "cell", "grid") and n % 2 == 1), **size)
                        files.append(img)
                    shots.append((kind, files))
                findings.append({"level": level, "title": "%s %d" % (topic, n + 1), "cvss": cvss, "imgs": [],
                                 "shots": shots, "plan": plan,
                                 "hosts": [("10.10.%d.%d" % (rng.randint(1, 9), rng.randint(2, 250)),
                                            rng.choice(["HTTP", "HTTPS", "SMB", "SSH", "LDAP"]),
                                            str(rng.choice([22, 80, 443, 445, 389, 8080])))
                                           for _ in range(rng.randint(*plan["hosts"]))]})
                n += 1
                continue
            imgs = []
            for step in ((1,) if compact else (1, 2, 3) if verbose else (1, 2)):
                img = "finding-%02d-step%d.png" % (n + 1, step)
                image(os.path.join(assets, img), "Evidence for %s, step %d" % (topic.lower(), step),
                      redact=(n % 3 == 0 and step == 1) or (verbose and step == 3 and n % 2 == 1))
                imgs.append(img)
            findings.append({"level": level, "title": "%s %d" % (topic, n + 1), "cvss": cvss, "imgs": imgs,
                             "hosts": [("10.10.%d.%d" % (rng.randint(1, 9), rng.randint(2, 250)),
                                        rng.choice(["HTTP", "HTTPS", "SMB", "SSH", "LDAP"]),
                                        str(rng.choice([22, 80, 443, 445, 389, 8080])))
                                       for _ in range(rng.randint(10, 20) if data else
                                                      rng.randint(3, 8) if verbose else rng.randint(1, 4))]})
            n += 1

    image(os.path.join(assets, "topology.png"), "Network overview (synthetic)", width=1200, height=900)
    for d in range(1, 5):
        image(os.path.join(assets, "narrative-day%d.png" % d), "Day %d activity summary" % d, redact=(d == 2))
    if verbose:
        for d in range(1, narrative_days() + 1):
            for k in range(1, NARRATIVE_SHOTS + 1):
                image(os.path.join(assets, "narrative-day%d-%d.png" % (d, k)), "Day %d, capture %d" % (d, k),
                      redact=(k == 2 and d % 2 == 0))
    if shape:
        for d in range(1, SHAPE_NARRATIVE_DAYS + 1):
            for k in (1, 2):
                image(os.path.join(assets, "narr-d%d-%d.png" % (d, k)), "Day %d, capture %d" % (d, k), redact=(d % 2 == 0))

    with open(os.path.join(template_dir, "main.typ"), encoding="utf-8") as f:
        src = f.read()

    def once(old, new):
        nonlocal src
        if old not in src:
            raise ValueError("template marker not found: %r" % old[:60])
        src = src.replace(old, new, 1)

    once('"{{OUR_COMPANY}}"', '"Blue Harbor Security"')
    once('"{{CLIENT}}"', '"ACME"')
    once('"{{CLIENT NAME}}"', '"ACME Corporation"')
    once('"{{YEAR}}"', '"2026"')
    once('"{{DATE}}"', '"September 29, 2026"')
    once("(critical: 1, high: 1, medium: 1, low: 1)",
         "(critical: %d, high: %d, medium: %d, low: %d)" % tuple(counts))
    for date in ["August 18, 2026", "September 8 to 12, 2026", "September 29, 2026"]:
        once("lcell[{{DATE}}]", "lcell[%s]" % date)
    for person, role, email in [("Jordan Lee", "IT Director", "jordan.lee\\@acme.example"),
                                ("Sam Rivera", "Lead Consultant", "sam.rivera\\@blueharbor.example")]:
        once("[{{NAME}}]", "[%s]" % person)
        once("[{{ROLE}}]", "[%s]" % role)
        once("[{{EMAIL}}]", "[%s]" % email)
    once("{{EXECUTIVE SUMMARY}}", "\n\n".join(para(5) for _ in range(3)))
    # Every occurrence, so none is left in the output: the first three take
    # the finding total, the host count and a fixed figure, the rest the host count.
    values = [str(total), "96", "42"]
    k = 0
    while "{{\\#\\#}}" in src:
        once("{{\\#\\#}}", values[k] if k < len(values) else "96")
        k += 1
    for _ in range(3):
        once("{{RECOMMENDATION}}", prose(14))
    for _ in range(4):
        once("=== {{STRENGTH}}\n\n{{DESCRIPTION}}", "=== %s\n\n%s" % (prose(3).rstrip("."), para(3)))
    for _ in range(3):
        once("=== {{AREA FOR IMPROVEMENT}}\n\n{{DESCRIPTION}}", "=== %s\n\n%s" % (prose(3).rstrip("."), para(3)))
    once("{{ACCESS METHOD}}", "a site-to-site VPN")
    once("[{{HOSTS}}]", "[10.10.0.5]")
    once("[{{HOSTS}}]", "[10.10.0.6]")
    once("{{CRITICAL SYSTEM}}", "production services")
    once("[{{RANGES}}]", "[10.10.0.0/16 \\ 172.16.20.0/24]")
    once("on {{DATE}}.", "on March 3, 2025.")
    once("{{whether it improved or got worse}}", "the overall posture improved")
    if data or shape:
        # The additional-findings and artifact tables are figures too, and at
        # 30 and 40 rows they outgrow a page, so every figure may break.
        once("#show figure: set block(above: 16pt, below: 16pt)",
             "#show figure: set block(above: 16pt, below: 16pt, breakable: true)")

    # Report card: one row per finding.
    start = src.index("#let rc-group")
    end = src.index(") <table-report-card>") + len(") <table-report-card>")
    colour = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
    rows = "\n".join('    table.cell(fill: %s)[], [%s], [%s],' % (colour[f["level"]], s(f["title"]), prose(8))
                     for f in findings)
    card = (
        "#figure(\n  table(\n    columns: (0.18in, 1fr, 1fr),\n"
        "    fill: (_, row) => if row > 0 and calc.even(row) { rgb(\"#f2f2f2\") } else { none },\n"
        "    hcell[], hcell[Finding], hcell[Remediation],\n%s\n  ),\n"
        "  caption: [Summarized and condensed report card for each identified vulnerability],\n"
        ") <table-report-card>" % rows)
    if total > REPORT_CARD_PAGE_ROWS or verbose or shape:
        # Typst never splits a figure, and a card longer than a page has its
        # overflow rows piled on one another at the foot of the page, which
        # cannot be read in the PDF and so cannot be in the Word file either.
        # An author would let it break, as here; a card that fits a page keeps
        # the template's own layout. The verbose documents always break: in
        # the template's own Poppins the remediation column wraps and only
        # about 19 rows fit, where 26 is the count without it.
        card = "#[\n#show figure: set block(breakable: true)\n%s\n]" % card
    src = src[:start] + card + src[end:]

    once("[{{FINDING}}], [{{REMEDIATION}}],\n    ..range(7).map(_ => (blank, blank)).flatten(),",
         "\n".join("    [%s], [%s]," % (prose(4), prose(9))
                   for _ in range(30 if data else {"c": 25, "e": 30, "f": 15}.get(shape, 10))))
    once('#image-placeholder("Discovered systems in the network", height: 4.5in)',
         '#image-placeholder("Discovered systems in the network", path: "/assets/topology.png", height: 4.5in)')

    narr = shape_narrative(findings, shape) if shape else verbose_narrative(findings) if verbose else []
    for d in ([] if verbose or shape else range(1, 5)):
        narr.append("=== September %d, 2026\n\n%s\n\n%s\n\n#image-placeholder(\"Activity on day %d\", path: \"/assets/narrative-day%d.png\")\n"
                    % (7 + d, para(4), para(3), d, d))
    once("=== {{DATE}}\n\n{{NARRATIVE}}\n\n=== {{DATE}}\n\n{{NARRATIVE}}", "\n".join(narr))

    start = src.index("== CRITICAL-RISK FINDINGS <sec-critical>")
    end = src.index("= APPENDIX A: METHODOLOGY")
    parts = []
    for level, label, head in [("critical", "sec-critical", "CRITICAL-RISK FINDINGS"),
                               ("high", "sec-high", "HIGH-RISK FINDINGS"),
                               ("medium", "sec-medium", "MEDIUM-RISK FINDINGS"),
                               ("low", "sec-low", "LOW-RISK FINDINGS")]:
        block = shape_finding_block if shape else verbose_finding_block if verbose else cptc_finding_block
        blocks = "\n#pagebreak(weak: true)\n\n".join(block(f) for f in findings if f["level"] == level)
        parts.append("== %s <%s>\n\n%s\n#pagebreak(weak: true)\n" % (head, label, blocks))
    src = src[:start] + "\n".join(parts) + "\n" + src[end:]

    once("[{{NAME}}], [{{DESCRIPTION}}], [{{SCOPE}}],\n    ..range(7).map(_ => (blank, blank, blank)).flatten(),",
         "\n".join('    [artifact-%02d.txt], [%s], [10.10.%d.%d],' % (i, prose(6), rng.randint(1, 9), rng.randint(2, 250))
                   for i in range(1, 41 if data else {"c": 31, "e": 41, "f": 21}.get(shape, 9))))
    if shape:
        src += "\n\n" + shape_appendices(shape, findings)

    write_text(folder, "main.typ", src)
    fonts_src = os.path.join(template_dir, "fonts")
    if os.path.isdir(fonts_src):
        shutil.copytree(fonts_src, os.path.join(folder, "fonts"))
    shutil.copy(os.path.join(template_dir, "assets", "cover.png"), os.path.join(assets, "cover.png"))


# Findings template

SEVERITIES = [("Critical", "9.8"), ("High", "7.5"), ("Medium", "5.3"), ("Low", "3.1")]


def build_findings(folder, n, rng):
    with open(os.path.join(CORPUS, "findings", "main.typ"), encoding="utf-8") as f:
        template = f.read()
    marker = "= Summary of findings"
    if marker not in template:
        raise ValueError("findings template marker not found: %r" % marker)
    out = [template[:template.index(marker)]]
    items = []
    for i in range(n):
        sev, cvss = SEVERITIES[i % 4]
        items.append(("NW-%02d" % (i + 1), "%s %d" % (TOPICS[i % len(TOPICS)], i + 1), sev, cvss))
    out.append("= Summary of findings\n\n#table(\n  columns: (auto, 1fr, auto),\n"
               "  fill: (_, row) => if row == 0 { luma(230) },\n"
               "  table.header([*ID*], [*Finding*], [*Severity*]),\n")
    for fid, title, sev, _ in items:
        out.append("  [%s], [%s], text(fill: severity-colour.%s)[*%s*],\n" % (fid, title, sev, sev))
    out.append(")\n\n= Findings\n\n")
    for i, (fid, title, sev, cvss) in enumerate(items):
        img = "f-%d.png" % (i + 1)
        image(os.path.join(folder, "assets", img), "Evidence for %s" % title.lower(), redact=(i % 3 == 2))
        hosts = ",\n    ".join("[host-%d-%d.example], [10.20.%d.%d]" % (i + 1, h + 1, rng.randint(1, 9), rng.randint(2, 250))
                               for h in range(rng.randint(2, 4)))
        out.append(
            '#finding("%s", "%s", "%s", "%s")[\n'
            '  %s\n\n  %s\n\n'
            '  ```text\n  # sample output\n  echo "checking host inventory"\n  ls -la /opt/app/config\n  ```\n\n'
            '  #figure(image("assets/%s", width: 80%%), caption: [Evidence for %s.])\n\n'
            '  *Affected hosts*\n  #table(columns: (auto, auto),\n    %s)\n\n'
            '  *Recommendation.* %s\n]\n\n#v(0.8em)\n'
            % (fid, s(title), sev, cvss, para(3), para(2), img, s(title.lower()), hosts, prose(10)))
    write_text(folder, "main.typ", "".join(out))


# Thesis template

BIB_KEYS = ["miller1990", "godefroid2008", "pham2020"]


def build_thesis(folder, n, rng):
    with open(os.path.join(CORPUS, "thesis", "main.typ"), encoding="utf-8") as f:
        template = f.read()
    marker = "#counter(heading).update(2)"
    if marker not in template:
        raise ValueError("thesis template marker not found: %r" % marker)
    out = [template[:template.index(marker) + len(marker)], "\n\n"]
    for i in range(n):
        out.append("= Chapter section %d\n\n" % (i + 1))
        for j in range(3):
            img = "t-%d-%d.png" % (i + 1, j + 1)
            image(os.path.join(folder, "assets", img), "Figure %d.%d (synthetic)" % (i + 1, j + 1),
                  redact=((i * 3 + j) % 3 == 0))
            key = BIB_KEYS[(i + j) % len(BIB_KEYS)]
            out.append("== Subsection %d.%d\n%s @%s.#footnote[%s]\n\n%s\n\n"
                       "$ x_i = sum_(j=1)^n a_(i j) y_j $\n\n"
                       % (i + 1, j + 1, para(4), key, prose(14), para(3)))
            out.append("#figure(\n  image(\"assets/%s\", width: 70%%),\n  caption: [Synthetic figure %d.%d.],\n)\n\n"
                       % (img, i + 1, j + 1))
            if (i % 2 == 1) and j == 1:
                out.append("#figure(\n  table(\n    columns: 3,\n    align: (left, right, right),\n"
                           "    table.header([*Case*], [*Count*], [*Share*]),\n"
                           "    [Alpha], [%d], [%d],\n    [Bravo], [%d], [%d],\n    [Charlie], [%d], [%d],\n  ),\n"
                           "  caption: [Synthetic counts for section %d.],\n)\n\n"
                           % (rng.randint(1, 90), rng.randint(1, 99), rng.randint(1, 90), rng.randint(1, 99),
                              rng.randint(1, 90), rng.randint(1, 99), i + 1))
    out.append('#bibliography("refs.bib")\n')
    write_text(folder, "main.typ", "".join(out))
    shutil.copy(os.path.join(CORPUS, "thesis", "refs.bib"), os.path.join(folder, "refs.bib"))


# Assessment template

MATRIX = (
    '  #let cell(label, colour) = table.cell(fill: colour)[#align(center)[#label]]\n'
    '  #table(\n'
    '    columns: (auto, 1fr, 1fr, 1fr, 1fr, 1fr),\n'
    '    rows: 1.2cm,\n'
    '    align: horizon,\n'
    '    [], [*Rare*], [*Unlikely*], [*Possible*], [*Likely*], [*Almost certain*],\n'
)


def build_assessment(folder, n, rng):
    with open(os.path.join(CORPUS, "assessment", "main.typ"), encoding="utf-8") as f:
        template = f.read()
    marker = "= Scope"
    if marker not in template:
        raise ValueError("assessment template marker not found: %r" % marker)
    # The template's own matrix rows, so the coloured cells stay the template's.
    rows = [ln for ln in template.splitlines() if ln.lstrip().startswith("[*") and "cell(" in ln]
    if len(rows) != 5:
        raise ValueError("assessment template matrix rows not found")
    out = [template[:template.index(marker)]]
    for i in range(n):
        out.append("= Section %d\n%s\n\n%s\n\n" % (i + 1, para(5), para(4)))
        out.append("#page(flipped: true)[\n  = Risk matrix %d\n%s%s\n  )\n  %s\n]\n\n"
                   % (i + 1, MATRIX, "\n".join(rows), prose(30)))
        out.append("= Hosts %d\n#table(\n  columns: (auto, auto, auto, 1fr),\n"
                   "  table.header(repeat: true, [*Host*], [*Address*], [*OS*], [*Open services*]),\n"
                   "  ..range(1, 61).map(i => (\n    [WS-#str(%d + i)],\n    [10.%d.0.#i],\n"
                   "    [#if calc.rem(i, 3) == 0 [Windows Server 2019] else [Windows 11]],\n"
                   "    [#if calc.rem(i, 5) == 0 [SMB, RDP, WinRM] else [SMB, RDP]],\n"
                   "  )).flatten(),\n)\n\n" % (i + 1, 1000 * (i + 1), i + 1))
    out.append("= Conclusion\n%s\n" % para(4))
    write_text(folder, "main.typ", "".join(out))


# Dispatch

def _seed(name):
    return 7 if name == "stress-cptc-57" else sum(map(ord, name))


def build(name, out_root, cptc_template=None):
    global _rng
    spec = DOCUMENTS[name]
    if spec["template"] == "cptc" and cptc_template is None:
        raise ValueError("%s needs --cptc-template" % name)
    folder = os.path.join(out_root, name)
    if os.path.isdir(folder):
        shutil.rmtree(folder)
    os.makedirs(os.path.join(folder, "assets"))
    _rng = random.Random(_seed(name))
    kind = spec["template"]
    if kind == "cptc":
        build_cptc(name, folder, cptc_template, spec["findings"], _rng, verbose=spec.get("verbose", False),
                   data=spec.get("data", False), compact=spec.get("compact", False), shape=spec.get("shape"))
    elif kind == "findings":
        build_findings(folder, spec["findings"], _rng)
    elif kind == "thesis":
        build_thesis(folder, spec["findings"], _rng)
    else:
        build_assessment(folder, spec["findings"], _rng)
    return folder


def build_all(out_root, cptc_template=None):
    built = []
    for name, spec in DOCUMENTS.items():
        if spec["template"] == "cptc" and cptc_template is None:
            continue
        built.append((name, build(name, out_root, cptc_template)))
    return built


def main(argv):
    args = list(argv)
    template = None
    if "--cptc-template" in args:
        i = args.index("--cptc-template")
        template = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        print("usage: stress.py <out_root> [--cptc-template DIR]", file=sys.stderr)
        return 2
    for name, folder in build_all(args[0], template):
        print("%s: %s" % (name, folder))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
