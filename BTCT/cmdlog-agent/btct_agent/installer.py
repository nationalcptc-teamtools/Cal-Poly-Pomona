"""Install / uninstall the shell hook.

Hook logic lives in ~/.config/btct/hook.{bash,zsh}; the rc file gets only a tiny
guarded block that sources it, so updating hook logic never re-edits the rc. The
block is idempotent: re-running `install` produces a no-op diff.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import List

from . import config

BEGIN = "# >>> btct-cmdlog hook >>>"
END = "# <<< btct-cmdlog hook <<<"

_HOOKS_SRC = Path(__file__).resolve().parent / "hooks"


def _detect_shells(requested: str) -> List[str]:
    if requested in ("bash", "zsh"):
        return [requested]
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return ["zsh"]
    if "bash" in shell:
        return ["bash"]
    return ["bash"]  # sensible default on Kali


def _rc_path(shell: str) -> Path:
    return Path.home() / (".zshrc" if shell == "zsh" else ".bashrc")


def _copy_hook_files() -> None:
    dest = config.config_dir()
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("hook.bash", "hook.zsh"):
        src = _HOOKS_SRC / name
        if src.exists():
            shutil.copyfile(src, dest / name)


def _strip_block(text: str) -> str:
    """Remove any existing managed block, returning the rest verbatim."""
    lines = text.splitlines(keepends=True)
    out: List[str] = []
    skip = False
    for line in lines:
        if line.strip() == BEGIN:
            skip = True
            continue
        if line.strip() == END:
            skip = False
            continue
        if not skip:
            out.append(line)
    return "".join(out)


def _block_for(shell: str) -> str:
    hook = config.config_dir() / f"hook.{shell}"
    return f'{BEGIN}\n[ -f "{hook}" ] && source "{hook}"\n{END}\n'


def install(shell: str) -> List[str]:
    """Install into the detected/requested shell(s). Returns rc paths touched."""
    config.ensure_dirs()
    _copy_hook_files()
    touched: List[str] = []
    for sh in _detect_shells(shell):
        rc = _rc_path(sh)
        original = rc.read_text() if rc.exists() else ""
        # One-time backup before our first edit.
        backup = rc.with_suffix(rc.suffix + ".btct.bak")
        if rc.exists() and not backup.exists():
            shutil.copyfile(rc, backup)
        cleaned = _strip_block(original)
        if cleaned and not cleaned.endswith("\n"):
            cleaned += "\n"
        rc.write_text(cleaned + _block_for(sh))
        touched.append(str(rc))
    return touched


def uninstall(shell: str) -> List[str]:
    """Remove the managed block from the shell(s). Returns rc paths touched."""
    touched: List[str] = []
    for sh in _detect_shells(shell):
        rc = _rc_path(sh)
        if not rc.exists():
            continue
        text = rc.read_text()
        if BEGIN not in text:
            continue
        rc.write_text(_strip_block(text))
        touched.append(str(rc))
    return touched
