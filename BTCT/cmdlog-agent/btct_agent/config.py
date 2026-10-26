"""Paths and persisted agent config.

The shell hook and the daemon share NO config file: both derive the spool path
from the current UID, so the hook can be dead-simple. Only the daemon needs the
server URL / token / operator, which live in ~/.config/btct/agent.conf (an
INI-less flat `key = value` file, stdlib only).
"""
from __future__ import annotations

import os
from pathlib import Path


def runtime_dir() -> Path:
    """UID-scoped runtime dir holding the per-shell spool files (mode 0700).

    Matches the path computed by the shell hooks:
        ${XDG_RUNTIME_DIR:-/tmp}/btct-$(id -u)
    """
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    d = Path(base) / f"btct-{os.getuid()}"
    return d


def spool_dir() -> Path:
    return runtime_dir() / "spool"


def state_dir() -> Path:
    """Persistent per-user state: read offsets, outbox, saved whitelist."""
    base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    return Path(base) / "btct-cmdlog"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "btct"


def config_file() -> Path:
    return config_dir() / "agent.conf"


def default_log_file() -> Path:
    return state_dir() / "commands.log"


def ensure_dirs() -> None:
    runtime_dir().mkdir(parents=True, exist_ok=True)
    os.chmod(runtime_dir(), 0o700)
    spool_dir().mkdir(parents=True, exist_ok=True)
    state_dir().mkdir(parents=True, exist_ok=True)
    config_dir().mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """Read agent.conf into a dict. Missing file → empty dict."""
    path = config_file()
    out: dict = {}
    if not path.exists():
        return out
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip()
    return out


def save_config(values: dict) -> None:
    """Write agent.conf (0600: it holds the ingest token)."""
    config_dir().mkdir(parents=True, exist_ok=True)
    lines = ["# btct-cmdlog agent config (managed by `btct_agent install`)"]
    for key in ("server", "token", "operator", "workspace", "log_file"):
        if values.get(key):
            lines.append(f"{key} = {values[key]}")
    path = config_file()
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def resolve(cli: dict) -> dict:
    """Merge config sources: CLI > env (BTCT_*) > agent.conf."""
    conf = load_config()
    env = {
        "server": os.environ.get("BTCT_SERVER"),
        "token": os.environ.get("BTCT_TOKEN"),
        "operator": os.environ.get("BTCT_OPERATOR"),
        "workspace": os.environ.get("BTCT_WORKSPACE"),
    }
    out = dict(conf)
    for k, v in env.items():
        if v:
            out[k] = v
    for k, v in cli.items():
        if v:
            out[k] = v
    return out
