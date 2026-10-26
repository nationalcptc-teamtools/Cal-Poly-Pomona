"""Spool file parsing + pre/post correlation.

The shell hooks append TAB-framed records to a per-PID spool file. The daemon's
reader thread tails those files, and a Correlator joins each `pre` (command
start) with its `post` (exit + end time) by event id.

Record framing (command/cwd base64'd so multi-line input can't break line
framing):

    btct1<TAB>pre<TAB><eid><TAB><pid><TAB><epoch_start><TAB><b64cmd><TAB><b64cwd>
    btct1<TAB>post<TAB><eid><TAB><exit><TAB><epoch_end>

parse_record() and Correlator are pure and unit-tested (tests/test_spool.py).
SpoolReader does the file I/O + offset tracking + dead-PID reaping.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, List, Optional


def _parse_float(s: str) -> float:
    # bash's $EPOCHREALTIME uses the locale decimal separator, which may be a
    # comma; zsh uses a dot. Accept both.
    return float(s.replace(",", "."))


def _b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def parse_record(line: str) -> Optional[dict]:
    """Parse one spool line into a record dict, or None if malformed."""
    line = line.rstrip("\n")
    if not line:
        return None
    parts = line.split("\t")
    if len(parts) < 2 or parts[0] != "btct1":
        return None
    typ = parts[1]
    try:
        if typ == "pre" and len(parts) >= 7:
            return {
                "type": "pre",
                "eid": parts[2],
                "pid": int(parts[3]),
                "ts": _parse_float(parts[4]),
                "command": _b64(parts[5]),
                "cwd": _b64(parts[6]),
            }
        if typ == "post" and len(parts) >= 5:
            return {
                "type": "post",
                "eid": parts[2],
                "exit": int(parts[3]),
                "ts": _parse_float(parts[4]),
            }
    except (ValueError, IndexError):
        return None
    return None


class Correlator:
    """Join `pre`/`post` records by event id into shippable events.

    Emits a `start` event immediately on `pre` (so a long-running command shows
    up live with exit_code=None), then a `complete` event on `post` carrying the
    exit code and computed duration. A `post` with no matching `pre` (daemon
    started mid-command) yields a `partial` complete with command=None, which
    the daemon drops since it can't be stored without a command.
    """

    def __init__(self) -> None:
        self.pending: Dict[str, dict] = {}

    def feed(self, rec: dict) -> List[dict]:
        if rec["type"] == "pre":
            self.pending[rec["eid"]] = rec
            return [{
                "kind": "start",
                "id": rec["eid"],
                "command": rec["command"],
                "cwd": rec["cwd"],
                "pid": rec["pid"],
                "started_at": int(rec["ts"] * 1000),
                "exit_code": None,
                "duration_ms": None,
            }]
        if rec["type"] == "post":
            pre = self.pending.pop(rec["eid"], None)
            if pre is None:
                return [{
                    "kind": "complete", "id": rec["eid"], "command": None, "cwd": None,
                    "pid": None, "started_at": None, "exit_code": rec["exit"],
                    "duration_ms": None, "partial": True,
                }]
            return [{
                "kind": "complete",
                "id": rec["eid"],
                "command": pre["command"],
                "cwd": pre["cwd"],
                "pid": pre["pid"],
                "started_at": int(pre["ts"] * 1000),
                "exit_code": rec["exit"],
                "duration_ms": max(0, round((rec["ts"] - pre["ts"]) * 1000)),
            }]
        return []

    def sweep(self, older_than_ts: float) -> None:
        """Drop pending starts older than a cutoff so memory stays bounded."""
        stale = [eid for eid, p in self.pending.items() if p["ts"] < older_than_ts]
        for eid in stale:
            del self.pending[eid]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours
    except OSError:
        return False


class SpoolReader:
    """Tails per-PID spool files from a persisted byte offset, reaping the
    files of shells that have exited once fully read."""

    def __init__(self, spool_dir: Path, offsets_path: Path) -> None:
        self.dir = Path(spool_dir)
        self.offsets_path = Path(offsets_path)
        self.offsets: Dict[str, int] = self._load()

    def _load(self) -> Dict[str, int]:
        try:
            return json.loads(self.offsets_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        try:
            self.offsets_path.parent.mkdir(parents=True, exist_ok=True)
            self.offsets_path.write_text(json.dumps(self.offsets))
        except OSError:
            pass

    def poll(self) -> List[dict]:
        """Read all new records across every spool file (in filename order)."""
        records: List[dict] = []
        if not self.dir.exists():
            return records
        for path in sorted(self.dir.glob("shell.*")):
            records.extend(self._read_file(path))
        self._save()
        self._reap()
        return records

    def _read_file(self, path: Path) -> List[dict]:
        name = path.name
        try:
            size = path.stat().st_size
        except OSError:
            return []
        offset = self.offsets.get(name, 0)
        if offset > size:  # truncated/rotated: restart
            offset = 0
        if offset == size:
            return []
        out: List[dict] = []
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                data = fh.read(size - offset)
        except OSError:
            return []
        # Only consume up to the last complete (newline-terminated) line.
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return []  # partial line only; wait for the rest
        consumed = data[: last_nl + 1]
        self.offsets[name] = offset + len(consumed)
        for raw in consumed.decode("utf-8", "replace").splitlines():
            rec = parse_record(raw)
            if rec:
                out.append(rec)
        return out

    def _reap(self) -> None:
        """Delete spool files whose shell has exited and that are fully read."""
        for path in list(self.dir.glob("shell.*")):
            try:
                pid = int(path.name.split(".", 1)[1])
            except (ValueError, IndexError):
                continue
            if _pid_alive(pid):
                continue
            try:
                fully_read = self.offsets.get(path.name, 0) >= path.stat().st_size
            except OSError:
                fully_read = True
            if fully_read:
                try:
                    path.unlink()
                except OSError:
                    pass
                self.offsets.pop(path.name, None)
