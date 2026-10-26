"""Secret redaction: scrub credentials from a command line before shipping.

Pure functions (no I/O), unit-tested in tests/test_redactor.py. Operates on the
argv token list (via shlex), NOT a naive regex over the string, so a flag and
its value are handled as a pair.

The landmine this module exists to avoid: `-p` means a *port* for nmap/masscan/
smbclient but a *password* for mysql/hydra/sshpass. Blanket-redacting `-p` would
gut the log. So redaction is TOOL-AWARE: a per-program table of secret flags
plus a set of globally-secret token patterns. Each pipeline segment is redacted
using its OWN program's table (`cat x | mysql -pPW` must use mysql's rules).

Honest limits (documented in the README):
  * positional secrets have no marker (`mysql db theP@ss`): not redacted.
  * shlex.join re-quotes, so the shipped line's cosmetics may differ from what
    was typed (the local log keeps the exact original).
  * on a shlex failure (unbalanced quotes) we fall back to global-pattern regex
    and flag the result as `degraded`: we never ship the raw line on failure.
  * the table is a denylist; a novel tool's novel secret flag leaks until added.
"""
from __future__ import annotations

import re
import shlex
from typing import List, Tuple

PLACEHOLDER = "«REDACTED»"  # «REDACTED»

# Flags whose following value is always secret, regardless of program.
VALUE_FLAGS_GLOBAL = {
    "--password", "--pass", "--passwd", "--hash", "--hashes", "--ntlm",
    "--api-key", "--apikey", "--token", "--secret", "--auth",
}

# Program-specific secret flags. nmap/masscan/rustscan are DELIBERATELY absent:
# their -p is a port range and must survive.
VALUE_FLAGS_BY_TOOL = {
    "mysql": {"-p", "--password"},
    "mysqldump": {"-p", "--password"},
    "mariadb": {"-p", "--password"},
    "psql": {"--password"},
    "mongo": {"-p", "--password"},
    "mongosh": {"-p", "--password"},
    "redis-cli": {"-a", "--pass"},
    "sshpass": {"-p"},
    "hydra": {"-p"},               # -p = one password; -P = a wordlist file (kept)
    "medusa": {"-p"},
    "ncrack": {"--pass"},
    "crackmapexec": {"-p", "-H", "--hash"},
    "nxc": {"-p", "-H", "--hash"},
    "netexec": {"-p", "-H", "--hash"},
    "evil-winrm": {"-p", "-H"},
    "smbclient": {"--password"},   # NOT -p: smbclient -p is a port
    "smbmap": {"-p"},
    "wget": {"--password"},
    "curl": {"--pass"},
}

# Programs where the secret is attached to the flag: `mysql -pSECRET`.
INLINE_P_TOOLS = {"mysql", "mysqldump", "mariadb", "mongo", "mongosh"}

_RE_URL_CRED = re.compile(r"://[^/\s:@]+:([^@/\s]+)@")
_RE_HEADER = re.compile(r"(?i)^(authorization|cookie|x-api-key|proxy-authorization):")
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$")  # md5 / LM:NT

_ENVASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _program_of(tokens: List[str]) -> str:
    """Basename of the segment's program (after env/sudo), for table lookup."""
    import os
    i = 0
    n = len(tokens)
    while i < n and (_ENVASSIGN.match(tokens[i]) or tokens[i] == "env"):
        i += 1
    if i < n and tokens[i] in ("sudo", "doas"):
        i += 1
        while i < n and tokens[i].startswith("-"):
            i += 1
    return os.path.basename(tokens[i]) if i < n else (tokens[0] if tokens else "")


def _redact_token(tok: str) -> str:
    """Apply the global token patterns to a single argument."""
    # user:pass@host anywhere in the token (URLs, git remotes, proxy strings).
    tok = _RE_URL_CRED.sub(lambda m: m.group(0).replace(m.group(1), PLACEHOLDER), tok)
    if _RE_HEADER.match(tok):
        return tok.split(":", 1)[0] + ": " + PLACEHOLDER
    if _RE_HASH.match(tok):
        return PLACEHOLDER
    return tok


def redact_segment(tokens: List[str]) -> List[str]:
    """Redact one pipeline segment using its own program's secret-flag table."""
    if not tokens:
        return tokens
    prog = _program_of(tokens)
    secret_flags = VALUE_FLAGS_GLOBAL | VALUE_FLAGS_BY_TOOL.get(prog, set())
    out: List[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        # --flag=value form
        if tok.startswith("--") and "=" in tok and tok.split("=", 1)[0] in secret_flags:
            out.append(tok.split("=", 1)[0] + "=" + PLACEHOLDER)
            i += 1
            continue
        # attached inline password: mysql -pSECRET (but a bare -p keeps its next tok)
        if prog in INLINE_P_TOOLS and re.match(r"^-p.+", tok):
            out.append("-p" + PLACEHOLDER)
            i += 1
            continue
        # flag followed by its value in the next token
        if tok in secret_flags and i + 1 < n:
            out.append(tok)
            out.append(PLACEHOLDER)
            i += 2
            continue
        out.append(_redact_token(tok))
        i += 1
    return out


def _regex_fallback(line: str) -> str:
    """Best-effort redaction when the line can't be tokenized."""
    line = _RE_URL_CRED.sub(lambda m: m.group(0).replace(m.group(1), PLACEHOLDER), line)
    # crude flag/value redaction on the raw string
    for flag in sorted(VALUE_FLAGS_GLOBAL, key=len, reverse=True):
        line = re.sub(re.escape(flag) + r"(=|\s+)\S+", flag + r"\1" + PLACEHOLDER, line)
    return line


def redact_line(line: str) -> Tuple[str, bool]:
    """Return (redacted_line, degraded).

    degraded=True means the line couldn't be fully tokenized and only the
    global regex fallback was applied: the caller may want to flag it.
    """
    try:
        tokens = shlex.split(line)
    except ValueError:
        return (_regex_fallback(line), True)

    # Split into segments on shell operators, redact each with its own context.
    segments: List[List[str]] = []
    current: List[str] = []
    OPS = {"|", "||", "&&", ";", "&"}
    for tok in tokens:
        if tok in OPS:
            segments.append(current)
            segments.append([tok])  # keep the operator as a passthrough marker
            current = []
        else:
            current.append(tok)
    segments.append(current)

    redacted_tokens: List[str] = []
    for seg in segments:
        if len(seg) == 1 and seg[0] in OPS:
            redacted_tokens.append(seg[0])
        else:
            redacted_tokens.extend(redact_segment(seg))

    try:
        return (shlex.join(redacted_tokens), False)
    except AttributeError:  # shlex.join is py3.8+; guard just in case
        return (" ".join(shlex.quote(t) for t in redacted_tokens), False)
