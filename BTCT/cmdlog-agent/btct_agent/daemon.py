"""The capture daemon: reads the spool, correlates, filters, redacts, ships.

Threads (stdlib threading):
  * reader  : polls the spool every ~150ms, correlates pre/post, whitelist-
               matches, writes the unredacted local log, redacts, and hands
               shippable events to the shipper.
  * whitelist: refreshes the server tool list every ~60s.
  * shipper : batches + delivers (see shipper.py).

Foreground by default (a tmux pane showing a live counter is more useful to a
CPTC operator than a hidden service); `--daemonize` double-forks.
"""
from __future__ import annotations

import getpass
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import config
from .matcher import is_whitelisted
from .redactor import redact_line
from .shipper import Outbox, Shipper
from .spool import Correlator, SpoolReader
from .whitelist import Whitelist


class Daemon:
    def __init__(self, cfg: dict, no_redact: bool = False, batch_size: int = 25,
                 flush_interval: float = 2.0, max_spool_mb: float = 20.0,
                 whitelist_refresh: float = 60.0, log_file: Optional[str] = None) -> None:
        self.server = cfg["server"].rstrip("/")
        self.token = cfg["token"]
        self.operator = cfg["operator"]
        self.workspace = cfg.get("workspace") or None
        self.no_redact = no_redact
        self.whitelist_refresh = whitelist_refresh

        config.ensure_dirs()
        self.host = socket.gethostname()
        self.local_user = getpass.getuser()
        self.log_path = Path(log_file or cfg.get("log_file") or config.default_log_file())
        self.status_path = config.state_dir() / "status.json"

        self.reader = SpoolReader(config.spool_dir(), config.state_dir() / "offsets.json")
        self.correlator = Correlator()
        self.whitelist = Whitelist(self.server, self.token)

        # ~300 bytes/event heuristic → events for the given MB cap.
        max_events = max(1000, int(max_spool_mb * 1024 * 1024 / 300))
        self.outbox = Outbox(config.state_dir() / "outbox.ndjson", max_events=max_events)
        self.shipper = Shipper(
            self.server + "/api/cmdlog/events", self.token, self.workspace, self.outbox,
            batch_size=batch_size, flush_interval=flush_interval,
        )
        self._stop = threading.Event()

    # ── event processing ──
    def _local_log(self, ev: dict) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ev["started_at"] / 1000))
        cwd = ev.get("cwd") or ""
        line = f"{ts} [{self.operator}@{self.host}] ({cwd}) {ev['command']}\n"
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass

    def _process(self, ev: dict) -> None:
        command = ev.get("command")
        if not command:
            return  # orphan/partial post: nothing to store
        matched, progs = is_whitelisted(command, self.whitelist.tools())
        if not matched:
            return
        tool = progs[0]
        if ev["kind"] == "start":
            self._local_log(ev)  # unredacted, once, at start (durability)
        if self.no_redact:
            command_out, redacted = command, False
        else:
            command_out, _degraded = redact_line(command)
            redacted = True
        self.shipper.submit({
            "id": ev["id"],
            "operator": self.operator,
            "command": command_out,
            "tool": tool,
            "cwd": ev.get("cwd"),
            "host": self.host,
            "localUser": self.local_user,
            "shellPid": ev.get("pid"),
            "startedAt": ev["started_at"],
            "exitCode": ev.get("exit_code"),
            "durationMs": ev.get("duration_ms"),
            "redacted": redacted,
        })

    # ── threads ──
    def _reader_loop(self) -> None:
        last_sweep = time.monotonic()
        while not self._stop.is_set():
            for rec in self.reader.poll():
                for ev in self.correlator.feed(rec):
                    self._process(ev)
            now = time.monotonic()
            if now - last_sweep > 3600:
                self.correlator.sweep(time.time() - 86400)  # drop >24h-stale starts
                last_sweep = now
            self._write_status()
            self._stop.wait(0.15)

    def _whitelist_loop(self) -> None:
        while not self._stop.is_set():
            self.whitelist.refresh()
            self._stop.wait(self.whitelist_refresh)

    def _write_status(self) -> None:
        try:
            self.status_path.write_text(json.dumps({
                "operator": self.operator, "host": self.host, "server": self.server,
                "online": self.shipper.online, "sent": self.shipper.sent,
                "outbox": len(self.outbox), "dropped": self.outbox.dropped,
                "rejected": self.shipper.rejected,
                "pending": len(self.correlator.pending), "pid": os.getpid(),
                "updatedAt": int(time.time() * 1000),
            }))
        except OSError:
            pass

    # ── lifecycle ──
    def run(self) -> int:
        self.whitelist.refresh()  # prime before the first command
        self.shipper.start()
        threading.Thread(target=self._reader_loop, name="cmdlog-reader", daemon=True).start()
        threading.Thread(target=self._whitelist_loop, name="cmdlog-whitelist", daemon=True).start()
        print(f"[btct-cmdlog] operator={self.operator} host={self.host} server={self.server}")
        print(f"[btct-cmdlog] local log: {self.log_path}")
        print("[btct-cmdlog] watching shell activity: Ctrl-C to stop.")
        try:
            while not self._stop.is_set():
                time.sleep(1.0)
                sys.stdout.write(
                    f"\r[btct-cmdlog] sent={self.shipper.sent} "
                    f"outbox={len(self.outbox)} dropped={self.outbox.dropped} "
                    f"rejected={self.shipper.rejected} "
                    f"{'online ' if self.shipper.online else 'OFFLINE'}   "
                )
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n[btct-cmdlog] stopping…")
        self._stop.set()
        self.shipper.stop()
        return 0


def daemonize() -> None:
    """Classic double-fork so the daemon outlives the launching shell."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
