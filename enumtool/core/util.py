from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Iterable, Optional

_print_lock = threading.Lock()

_COLORS = {
    "info": "\033[36m",
    "ok": "\033[32m",
    "warn": "\033[33m",
    "err": "\033[31m",
    "step": "\033[35m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def log(msg: str, level: str = "info") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    if _supports_color():
        color = _COLORS.get(level, "")
        line = f"{_COLORS['dim']}{ts}{_COLORS['reset']} {color}{msg}{_COLORS['reset']}"
    else:
        tag = level.upper()
        line = f"{ts} [{tag}] {msg}"
    with _print_lock:
        print(line, flush=True)

def which(binary: str) -> Optional[str]:
    return shutil.which(binary)

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

def run(cmd: list[str], *, timeout: Optional[int] = None,
        capture: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    log(f"$ {' '.join(cmd)}", level="dim")
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=check,
        )
    except subprocess.TimeoutExpired as exc:
        log(f"command timed out after {timeout}s: {' '.join(cmd)}", level="warn")
        return subprocess.CompletedProcess(
            cmd, returncode=124,
            stdout=exc.stdout or "", stderr=(exc.stderr or "") + "\n[timeout]")

def stream(cmd: list[str], *, timeout: Optional[int] = None,
           on_line=None) -> tuple[int, str]:
    log(f"$ {' '.join(cmd)}", level="dim")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    lines: list[str] = []
    start = time.time()
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if on_line:
                on_line(line)
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                lines.append("[timeout]")
                break
        proc.wait(timeout=5)
    except Exception as exc:
        log(f"stream error: {exc}", level="warn")
        try:
            proc.kill()
        except Exception:
            pass
    return proc.returncode or 0, "\n".join(lines)

def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

def resolve_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host

def dedup(items: Iterable) -> list:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out
