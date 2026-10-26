"""Whitelist matching: decide which whitelisted tool(s) a command line runs.

Pure functions (no I/O), unit-tested in tests/test_matcher.py. Tolerant of the
ways a pentester actually types commands: `sudo`/`doas`, env-var prefixes
(`FOO=bar cmd`, `env cmd`), absolute paths (`/usr/bin/nmap`), and pipelines
(`cat hosts | nmap -iL -`). A line matches if ANY pipeline segment's program is
in the whitelist.
"""
from __future__ import annotations

import os
import re
import shlex
from typing import List, Set, Tuple

_ENVASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# sudo/doas flags that take a value (so we skip the value too when finding the
# real program). Everything else is treated as a valueless flag.
_SUDO_VALUE_FLAGS = {"-u", "-g", "-U", "--user", "--group", "-p", "--prompt", "-C", "-r", "-t"}


def split_segments(line: str) -> List[List[str]]:
    """Split a command line into pipeline/list segments, each a token list.

    Uses shlex with punctuation_chars so `|`, `&`, `;` split segments but the
    same characters *inside quotes* do not. Falls back to a naive whitespace
    split if the line can't be lexed (unbalanced quotes, heredocs, …).
    """
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = line.split()

    segments: List[List[str]] = []
    current: List[str] = []
    for tok in tokens:
        # A pure run of operator characters is a separator between segments.
        if tok and set(tok) <= {"|", "&", ";"}:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def program_of(tokens: List[str]) -> str | None:
    """The effective program name of one segment, or None if empty.

    Strips leading env assignments / `env`, then `sudo`/`doas` and their flags,
    then reduces an absolute or relative path to its basename.
    """
    i = 0
    n = len(tokens)
    # Leading env assignments and a bare `env`.
    while i < n and (_ENVASSIGN.match(tokens[i]) or tokens[i] == "env"):
        i += 1
    # A privilege wrapper and its options.
    if i < n and tokens[i] in ("sudo", "doas"):
        i += 1
        while i < n and tokens[i].startswith("-"):
            takes_value = tokens[i] in _SUDO_VALUE_FLAGS
            i += 2 if takes_value else 1
        # sudo can be followed by more env assignments (`sudo FOO=bar cmd`).
        while i < n and _ENVASSIGN.match(tokens[i]):
            i += 1
    if i >= n:
        return None
    return os.path.basename(tokens[i])


def command_programs(line: str) -> List[str]:
    """Every effective program in the line, one per pipeline segment."""
    out: List[str] = []
    for seg in split_segments(line):
        prog = program_of(seg)
        if prog:
            out.append(prog)
    return out


def is_whitelisted(line: str, whitelist: Set[str]) -> Tuple[bool, List[str]]:
    """(matched, matching_programs). Matched if any segment's program is listed."""
    progs = command_programs(line)
    matches = [p for p in progs if p in whitelist]
    return (bool(matches), matches)
