"""Batching, offline outbox, and the HTTP shipping loop.

Events are batched (25 events OR every 2s) and POSTed to /api/cmdlog/events. If
the server is unreachable the batch is spooled to a bounded on-disk outbox and
retried with exponential backoff (the loop waits out the backoff before the
next attempt); on recovery the outbox drains oldest-first so nothing typed
during a network blip is lost. Every event carries its id, and the server
dedups on it, so a retry whose success response was lost can't double-insert.

A batch the server refuses for its content (a 4xx such as 413 payload too large
or 400) is split in half and each half retried, down to single events; an event
that is still refused on its own is dropped and counted as `rejected`, so one
bad event can never block the queue behind it. Statuses that describe the
connection or the server's configuration rather than the events (401, 403,
404, 405, 408, 409, 429) and every 5xx or network error are retried instead.
Commands are cut to the server's own 4096-character limit before they ship.

A batch never holds more than MAX_BATCH_EVENTS (the server's own cap of 200 a
POST): a larger --batch-size is clamped. The server reads only the first 200
events of a POST and answers 200 with what it took, so a larger batch used to
be committed whole and the rest lost. The reply's `accepted` and `skipped`
counts are also checked: events past what the server says it read stay
queued and go in the next POST.

Outbox is a bounded ring: on overflow the OLDEST events are dropped (so the live
tail stays current during a long outage) and a counter is bumped, surfaced via
status. On disk it is an append-only JSONL file plus a committed byte offset,
so an append or a commit costs the new bytes, not a rewrite of the whole
queue; the file is compacted once the committed part is at least half of it.
urllib only: no third-party deps.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Callable, Deque, List, Optional, Tuple

# Same as MAX_CMD_LEN in server/cmdlog.mjs, which truncates there anyway.
MAX_COMMAND_CHARS = 4096
MAX_CWD_CHARS = 512
# Same as MAX_BATCH in server/cmdlog.mjs: events a POST may carry.
MAX_BATCH_EVENTS = 200


def clamp_batch_size(n: int) -> int:
    """A batch size the server accepts whole: 1 to MAX_BATCH_EVENTS."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return 25
    return max(1, min(n, MAX_BATCH_EVENTS))

# 4xx statuses that say nothing about the events themselves: a token being
# rotated, ingest switched off, no target workspace yet, a wrong URL, or rate
# limiting. Dropping events on one of these would lose every command typed
# while the server was misconfigured, so they are retried like a network error.
RETRY_STATUSES = frozenset({401, 403, 404, 405, 408, 409, 429})


def clamp_event(event: dict) -> dict:
    """Cut the command (and cwd) to the server's limits before shipping, so a
    long inline payload cannot push a batch over the server's body cap."""
    out = event
    cmd = event.get("command")
    if isinstance(cmd, str) and len(cmd) > MAX_COMMAND_CHARS:
        out = dict(out, command=cmd[:MAX_COMMAND_CHARS])
    cwd = event.get("cwd")
    if isinstance(cwd, str) and len(cwd) > MAX_CWD_CHARS:
        out = dict(out, cwd=cwd[:MAX_CWD_CHARS])
    return out


def is_permanent_rejection(code: int) -> bool:
    """True for a 4xx that refuses the payload itself (split, then drop)."""
    return 400 <= code < 500 and code not in RETRY_STATUSES


def post_events(url: str, token: str, workspace: Optional[str], events: List[dict], timeout: float = 5.0) -> Optional[dict]:
    """POST a batch. Raises urllib/OSError on any failure (network or non-2xx).
    Returns the server's JSON reply ({"accepted": n, "skipped": m}), or None
    when the body is not a JSON object."""
    body = json.dumps({"workspace": workspace, "events": events}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        code = getattr(resp, "status", resp.getcode())
        if code // 100 != 2:
            raise urllib.error.HTTPError(url, code, "non-2xx", resp.headers, None)
        try:
            reply = json.loads(resp.read() or b"null")
        except ValueError:
            return None
        return reply if isinstance(reply, dict) else None


def events_read(reply: Optional[dict], sent: int) -> Tuple[int, int]:
    """(events the server read from the front of the batch, of those how many
    it skipped as invalid). A reply without counts means the whole batch."""
    if not isinstance(reply, dict):
        return sent, 0
    accepted, skipped = reply.get("accepted"), reply.get("skipped", 0)
    if not isinstance(accepted, int) or isinstance(accepted, bool) or accepted < 0:
        return sent, 0
    if not isinstance(skipped, int) or isinstance(skipped, bool) or skipped < 0:
        skipped = 0
    return min(sent, accepted + skipped), min(skipped, sent)


class Outbox:
    """Bounded, disk-backed FIFO of events awaiting delivery.

    `path` holds one JSON event per line and is only ever appended to;
    `path.offset` holds the byte offset of the first event not yet delivered.
    A reload replays from that offset (an event delivered just before a crash
    may be sent twice, which the server's id dedup absorbs) and then compacts.
    """

    def __init__(self, path: Path, max_events: int = 70000, compact_min_bytes: int = 64 * 1024) -> None:
        self.path = Path(path)
        self.offset_path = self.path.with_name(self.path.name + ".offset")
        self.max_events = max_events
        self.compact_min_bytes = compact_min_bytes
        self.dropped = 0
        # (event, bytes of its line in the file)
        self._events: Deque[Tuple[dict, int]] = deque()
        self._base = 0  # committed bytes at the head of the file
        self._end = 0  # bytes written to the file
        self._broken = False  # a write failed: rewrite the file on the next change
        self._load()

    # ── disk ──
    def _load(self) -> None:
        try:
            base = int(self.offset_path.read_text().strip() or "0")
        except (OSError, ValueError):
            base = 0
        try:
            data = self.path.read_bytes()
        except OSError:
            data = b""
        if base < 0 or base > len(data):
            base = 0  # offset of some other file: replay everything, ids dedup
        for raw in data[base:].split(b"\n"):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except ValueError:
                continue  # a torn last line or a damaged one: skip it
            if isinstance(ev, dict):
                self._events.append((ev, 0))
        while len(self._events) > self.max_events:
            self._events.popleft()
            self.dropped += 1
        if data or base:
            self._rewrite()  # drop committed, torn and damaged lines once

    def _write_offset(self) -> None:
        tmp = self.offset_path.with_name(self.offset_path.name + ".tmp")
        tmp.write_text(str(self._base))
        os.replace(tmp, self.offset_path)

    def _rewrite(self) -> None:
        """Compact: write only the pending events to a fresh file."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lines = [(json.dumps(ev) + "\n").encode("utf-8") for ev, _ in self._events]
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_bytes(b"".join(lines))
            # Offset 0 goes first: a crash before the rename then replays
            # delivered events (deduplicated by id) rather than skipping
            # undelivered ones.
            self._base = 0
            self._write_offset()
            os.replace(tmp, self.path)
            self._events = deque((ev, len(line)) for (ev, _), line in zip(self._events, lines))
            self._end = sum(len(line) for line in lines)
            self._broken = False
        except OSError:
            self._broken = True

    def _maybe_compact(self) -> None:
        if self._broken:
            self._rewrite()
        elif self._base and (not self._events or (self._base >= self.compact_min_bytes and self._base * 2 >= self._end)):
            self._rewrite()

    # ── queue ──
    def __len__(self) -> int:
        return len(self._events)

    def append(self, events: List[dict]) -> None:
        if not events:
            return
        lines = [(json.dumps(ev) + "\n").encode("utf-8") for ev in events]
        for ev, line in zip(events, lines):
            self._events.append((ev, len(line)))
        if not self._broken:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("ab") as fh:
                    fh.write(b"".join(lines))
                self._end += sum(len(line) for line in lines)
            except OSError:
                self._broken = True
        trimmed = False
        while len(self._events) > self.max_events:
            _, n = self._events.popleft()
            self._base += n
            self.dropped += 1
            trimmed = True
        if trimmed and not self._broken:
            self._commit_offset()
        self._maybe_compact()

    def drain(self, n: int) -> List[dict]:
        """Peek the oldest up-to-n events WITHOUT removing them (removal is via
        `commit` after a successful send, so a failed send keeps them)."""
        return [ev for ev, _ in islice(self._events, n)]

    def commit(self, n: int) -> None:
        if n <= 0:
            return
        for _ in range(min(n, len(self._events))):
            _, size = self._events.popleft()
            self._base += size
        if not self._broken:
            self._commit_offset()
        self._maybe_compact()

    def _commit_offset(self) -> None:
        try:
            self._write_offset()
        except OSError:
            self._broken = True


class Shipper:
    """Owns the ship queue + a worker thread that batches and delivers."""

    def __init__(
        self,
        url: str,
        token: str,
        workspace: Optional[str],
        outbox: Outbox,
        batch_size: int = 25,
        flush_interval: float = 2.0,
        poster: Callable[..., None] = post_events,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self.token = token
        self.workspace = workspace
        self.outbox = outbox
        self.batch_size = clamp_batch_size(batch_size)
        self.flush_interval = flush_interval
        self._poster = poster
        self._clock = clock
        self.q: "queue.Queue[dict]" = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.sent = 0
        self.rejected = 0
        self.backoff = 1.0
        self._retry_at = 0.0
        self.online = True

    def submit(self, event: dict) -> None:
        self.q.put(clamp_event(event))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="cmdlog-shipper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def backing_off(self) -> bool:
        return self._clock() < self._retry_at

    def _run(self) -> None:
        pending: List[dict] = []
        last_flush = self._clock()
        while not self._stop.is_set():
            timeout = max(0.05, self.flush_interval - (self._clock() - last_flush))
            try:
                pending.append(self.q.get(timeout=timeout))
            except queue.Empty:
                pass
            due = (self._clock() - last_flush) >= self.flush_interval
            if pending and (len(pending) >= self.batch_size or due):
                if self.backing_off():
                    self.outbox.append(pending)  # keep it safe on disk meanwhile
                else:
                    self._flush(pending)
                pending = []
                last_flush = self._clock()
            elif due:
                last_flush = self._clock()
                if not self.backing_off():
                    self._drain_outbox()

    def _ok(self, n: int) -> None:
        self.sent += n
        self.online = True
        self.backoff = 1.0
        self._retry_at = 0.0

    def _failed(self) -> None:
        self.online = False
        self.backoff = min(self.backoff * 2, 30.0)
        self._retry_at = self._clock() + self.backoff

    def _deliver(self, batch: List[dict]) -> int:
        """POST `batch`; return how many events from its front are finished
        (delivered, or rejected for good). Less than len(batch) means the rest
        must be retried later."""
        if not batch:
            return 0
        if len(batch) > MAX_BATCH_EVENTS:
            done = self._deliver(batch[:MAX_BATCH_EVENTS])
            if done < MAX_BATCH_EVENTS:
                return done
            return done + self._deliver(batch[MAX_BATCH_EVENTS:])
        try:
            reply = self._poster(self.url, self.token, self.workspace, batch)
        except urllib.error.HTTPError as e:
            if not is_permanent_rejection(e.code):
                self._failed()
                return 0
            # The server is up and refuses this payload: narrow it down.
            self.online = True
            if len(batch) == 1:
                self.rejected += 1
                return 1
            mid = len(batch) // 2
            done = self._deliver(batch[:mid])
            if done < mid:
                return done
            return mid + self._deliver(batch[mid:])
        except Exception:
            self._failed()
            return 0
        read, skipped = events_read(reply, len(batch))
        if read <= 0:
            # A 2xx that read nothing: retry later rather than spin.
            self._failed()
            return 0
        # The server validates each event and skips one it cannot store;
        # that is a refusal for good, like a 4xx on a single event.
        self.rejected += skipped
        self._ok(read - skipped)
        if read < len(batch):
            return read + self._deliver(batch[read:])
        return read

    def _flush(self, batch: List[dict]) -> None:
        # Try the outbox first so ordering stays FIFO after an outage.
        self._drain_outbox()
        if len(self.outbox) or self.backing_off():
            self.outbox.append(batch)
            return
        done = self._deliver(batch)
        if done < len(batch):
            self.outbox.append(batch[done:])

    def _drain_outbox(self) -> None:
        while len(self.outbox):
            batch = self.outbox.drain(self.batch_size)
            done = self._deliver(batch)
            self.outbox.commit(done)
            if done < len(batch):
                return  # stop draining; retry after the backoff
