# Server stream: persistence, health, shutdown, history twins, auth

Branch `fix/server`, based on `competition-crash-fixes` (669ed8f). Audit ids:
SRV-5, SRV-6, SRV-19 + S4, SRV-8, SRV-9, SRV-10, S7, SRV-17 (plus the
backup-route missed issue), SRV-18, BLT-8.

Files changed: `server/index.mjs`, `server/history.mjs`, `server/db.mjs`, new
`server/relay-persistence.mjs` (+ `.d.mts`), new
`src/test/relay-persistence.test.ts`, and one `COPY` line in the `Dockerfile`.

## What changed, as a user or operator sees it

### Relay persistence (SRV-6, SRV-19, S4, SRV-5)

`server/relay-persistence.mjs` is the relay's LevelDB binding now (installed
through y-websocket's `setPersistence` in `server/index.mjs`).

- Each room's updates are merged (`Y.mergeUpdates`) and stored as one LevelDB
  entry at most every 300 ms, sooner once 2 MB is buffered, with at most one
  write per room in flight. Before, every keystroke was its own entry in one
  global queue that a burst outran (measured at HEAD: 1396 of 3456 updates
  survived a kill right after a 30 s burst). Now: 3468 of 3468 survived a
  `docker kill` right after the same burst with a 15 MiB room stored beside
  them.
- A failed write is not dropped. The room stores its whole state on the next
  attempt (every 5 s). A room that closes while writes fail keeps its state in
  memory until a write succeeds, and if it is reopened first, that state is put
  back into the room. Measured on a full 8 MB tmpfs: health went to 503, the
  room was still served in full from memory, and once space was freed the
  state was stored and health went back to 200 within one retry.
- Rooms that stay open (btct-shared) are compacted every 15 minutes once they
  have 100 or more stored entries since the last compaction (y-leveldb's
  `flushDocument`). Before, compaction only happened when a room loaded.
- `getPersistence()` returns the binding, which now has `drain()`: it flushes
  every buffer, waits for rooms still loading and for y-leveldb's own queue,
  and resolves `true` when nothing failed. Backup code should call
  `await getPersistence()?.drain?.()` before it reads rooms.
- `status()` on the same object returns the counters (`failing`, `failures`,
  `readFailures`, `lastError`, `pendingRooms`, `pendingBytes`,
  `unsavedClosedRooms`, `writes`, `compactions`, ...).
- The load is still recorded as `doc.whenLoaded` / `doc.loaded` (invariant 20
  is unchanged). Re-verified after this change: the cold-room race probe
  (`qa/exports-verify/scripts/{seed,race}.mjs`, 100 rooms, three runs) reports
  `emptyAtSync: 0`.

### Health (SRV-5)

- `GET /healthz` returns `{ ok, persistence: 'ok'|'failing'|'off', freeBytes }`
  and answers **503** with `ok:false` while persistence is failing (a LevelDB
  write or read failed and nothing has succeeded since) and while the server is
  shutting down (`shuttingDown: true`). Free space is `statfs` of the data
  directory (`YPERSISTENCE`, else the directory of `DB_PATH`). Under 1 GB it
  adds `warning: 'low disk'` (still 200) and logs a line at most every 10
  minutes. The Dockerfile healthcheck already treats a non-2xx as a failure,
  so the container turns `unhealthy`.
- New route `GET /api/admin/status` (admin): `{ ok, persistence: <status()>,
  disk: { path, freeBytes, totalBytes, lowDisk, lowDiskBytes }, history:
  historyStatus(), relay: { rooms }, uptimeS }`. This is the "admin status
  field"; the admin panel banner itself is the client stream's (see below).

### Clean shutdown (SRV-8)

- SIGTERM and SIGINT now shut the server down: stop accepting connections,
  send a close frame to every page room's sockets and wait up to 2 s for the
  rooms to close the normal way (buffer queued, close version recorded, twin
  written), then btct-shared's sockets (up to 1 s), then close whatever is left
  directly, drain LevelDB, wait for the twin writes, close LevelDB and SQLite
  (`closeDb()` checkpoints the WAL first), and exit 0. A forced exit (code 1)
  fires after `SHUTDOWN_TIMEOUT_MS`.
- Measured: `docker stop` 2.0 to 3.0 s with exit 0 right after a 12,000-update
  burst across 100 open rooms (server-side shutdown 0.3 to 1.2 s, logged as
  `stopped in N ms (clean)`). Every update the server had applied was there
  after the restart (12000 of 12000, several runs). HEAD: 10.6 s, exit 137.
- Updates a client sent that were still in transit when the stop began are not
  applied (Bun stops delivering messages once the server sends its close). The
  y-websocket client resends what the server lacks on reconnect, so a browser
  loses nothing; a raw script that never resyncs can.

### Websocket diagnostics (SRV-9)

- Bun closes a socket whose single message is over 16 MiB with code 1006 and
  reason `Received too big message`, and the update is lost. That close is now
  logged as an error naming the room and account and saying the change was not
  stored. Any other abnormal close is logged as a warning with message count,
  bytes and the largest message, except a bare 1006 with no reason and no large
  message (a closed laptop lid). Any single message of 4 MiB or more is logged
  with its size. The limit itself is unchanged (raising it costs memory on a
  1 GB box; a client-side paste cap is the client stream's call).

### History twins (SRV-10, S7)

- A twin that fails to parse (or cannot be read) is renamed to
  `<pageId>.ydoc.corrupt-<timestamp>` before a fresh twin starts, so the next
  flush no longer overwrites the only copy of that page's history. If it cannot
  be moved either, the twin is marked locked and never written over. Measured:
  a truncated twin, 5000 random bytes and a 9-byte varint bomb each ended up as
  a `.corrupt-*` file with the original bytes (md5 equal), the server kept
  serving, and a new twin was written.
- `historyStatus()` (and so `/api/admin/status`) now has `corruptTwins`,
  `lastCorrupt`, `flushFailures`, `lastFlushError`, `writesInFlight`.
- Twin writes go to `<id>.ydoc.tmp-<n>`, are fsynced, then renamed. The
  periodic flush and the room-close flush run off the event loop; a sequence
  number keeps an older write from replacing a newer one. Leftover `.tmp*`
  files are removed at boot.
- A twin is written only when it changed. Opening pages only to read them
  (exports) no longer rewrites their twin files (measured: mtimes unchanged
  across a 100-room reopen).
- `flushAllTwins()` stays synchronous (the backup engine calls it right before
  copying `HISTORY_DIR`) and also lands writes still in flight for rooms that
  just closed. New exports: `closeAllTwins()` (async, for shutdown) and
  `drainTwinWrites()`.
- `GET /api/pages/:id/versions/:vid` for a snapshot version whose twin is
  missing or damaged answers **410** with a plain message instead of a 500.
- Backups copy only `*.ydoc`, so `.corrupt-*` files are not backed up. They
  stay in `HISTORY_DIR` for someone to inspect or remove by hand.

### Auth (SRV-17, backup-route missed issue, SRV-18)

- The websocket upgrade refuses (401) a token whose account no longer exists,
  the same rule the REST routes apply. Measured: before the delete the user's
  token read the page (4053 bytes); after it, the upgrade is refused and the
  probe reads nothing. The refusal behaves exactly like an invalid token's:
  under Bun the `401` status line written before `socket.destroy()` does not
  reach the client (an empty reply, as at HEAD), and the client sees a failed
  connection.
- `GET /api/backup/status` and `POST /api/backup/run` accept an admin checked
  against the users table (`requireAdmin`) or the backup token. They no longer
  trust the token's own `admin` claim. Measured: a deleted admin's token gets
  401 on both.
- The bootstrap admin's password is printed to the log only when it is the
  built-in default. With `ADMIN_PASSWORD` set the line reads
  `created bootstrap admin '<name>' with the password from ADMIN_PASSWORD`.

### Static files (BLT-8)

- A missing file under `/assets/`, or any missing path with a file extension,
  is a 404 (`text/plain`, `no-store`). Only extensionless paths fall back to
  `index.html`. Measured: `/assets/Nope-XXXX.js` and `/foo.png` give 404,
  `/some/deep/route` and `/` give `index.html`, a real hashed chunk gives 200.
- This only helps once the client reloads on a failed chunk load; the
  `vite:preloadError` handler is the client stream's (the cross-checker noted
  that no such handler exists yet).

## New env vars, routes, commands

- `SHUTDOWN_TIMEOUT_MS` (default 8000, minimum 1000): forced-exit timer for
  shutdown. Keep it below docker's stop timeout (10 s by default, or compose's
  `stop_grace_period`).
- `GET /api/admin/status` (admin), described above.
- `/healthz` response shape and the 503, described above.

## Invariants for CLAUDE.md "Critical invariants"

Replace invariant 20's second sentence onward with, or add after it:

> 20b. **Relay persistence is `server/relay-persistence.mjs`, never
> y-websocket's own binding.** It buffers each room and stores merged updates
> every 300 ms, so anything that reads LevelDB directly (backups, exports of
> closed rooms) must first `await getPersistence()?.drain?.()`, or it can miss
> the last 300 ms. A failed write is kept and retried, never dropped, and it
> turns `/healthz` into a 503; do not swallow write errors anywhere else. Load
> `yjs` into it through the server's CJS `require` (invariant 6).

> 22. **The server stops on SIGTERM/SIGINT by closing rooms, draining LevelDB,
> closing LevelDB and SQLite, then exiting 0.** Anything that holds state in
> memory (a buffer, a timer that writes later) must be flushed from that path
> (`shutdown()` in `server/index.mjs`). Keep `SHUTDOWN_TIMEOUT_MS` below the
> container's stop timeout, and never add `init: true` or a non-PID-1 CMD
> without this handler in place.

> 4c addition: **A twin that cannot be parsed is moved aside
> (`.ydoc.corrupt-<ts>`), never overwritten,** and twin writes are temp file,
> fsync, rename, ordered by a sequence number. `flushAllTwins()` must stay
> synchronous: the backup engine copies the files right after it returns.

> 21 addition: **A missing static file is a 404; only extensionless paths fall
> back to `index.html`.**

## README sections that must change

1. "How it works (runtime)", line ~914:
   - Stale: `Serves the built Vite client (STATIC_DIR=/app/dist) on the same port, with SPA fallback to index.html.`
   - New: `Serves the built Vite client (STATIC_DIR=/app/dist) on the same port. Extensionless paths fall back to index.html; a missing file under /assets/ or with an extension is a 404.`
   - Stale (same list): `The JWT is verified once at the WS upgrade.`
   - New: `The JWT is verified once at the WS upgrade, and its account must still exist.`

2. API table, line ~1140:
   - Stale: `` | `GET` | `/healthz` | none | Liveness probe (`{ ok: true }`) | ``
   - New: `` | `GET` | `/healthz` | none | Health: `{ ok, persistence: 'ok'|'failing'|'off', freeBytes }`, plus `warning: 'low disk'` under 1 GB free. 503 while LevelDB writes or reads are failing, or while shutting down | ``
   - Add a row: `` | `GET` | `/api/admin/status` | admin | Persistence counters (failing, failures, pending bytes, unsaved closed rooms, writes, compactions), disk free/total under the data dir, history twin status (tracked, corrupt twins, flush failures), open relay rooms, uptime | ``

3. API table, line ~1174:
   - Stale: `` | `GET` | `/api/backup/status` | admin or backup token | ... ``
   - New Auth cell for both `/api/backup/status` and `/api/backup/run`: `admin (checked against the users table) or backup token`.

4. Env var list, line ~1233:
   - Stale: `` `ADMIN_USERNAME`/`ADMIN_PASSWORD` (bootstrap admin, default `admin`/`changeme!`). ``
   - New: `` `ADMIN_USERNAME`/`ADMIN_PASSWORD` (bootstrap admin, default `admin`/`changeme!`; the password is printed to the log only when it is that default), `SHUTDOWN_TIMEOUT_MS` (forced exit after a SIGTERM, default 8000; keep it below the container's stop timeout). ``

5. Fonts paragraph, line ~2365:
   - Stale: `the static handler answers with index.html and the failure surfaces as a font-parser error from the compiler.`
   - New: `the static handler answers 404 and the failure surfaces as a font load error from the compiler.`
   - The same stale wording is in CLAUDE.md's `bun run fonts` bullet: `(the static handler answers a missing file with index.html)` becomes `(the static handler answers a missing file with a 404)`.

6. Backups / restore sections: note that `docker compose stop btct` now stops the
   server cleanly in a second or two (exit 0) with LevelDB closed, so the
   restore CLI's "LevelDB is locked" refusal should not trigger after a normal stop.

7. CLAUDE.md "Page version history" paragraph: after "flushed atomically to
   `HISTORY_DIR/<pageId>.ydoc`" add "(temp file, fsync, rename; a twin that
   cannot be parsed is renamed to `<pageId>.ydoc.corrupt-<ts>` and counted in
   `historyStatus()`, never overwritten)".

## Verification (all on `btct-qa:server`, built with `WITH_REPORT_BINS=0`)

- `bunx tsc -b`: clean. `bunx vitest run`: 607 passed, 6 failed (the baseline
  5 in `typst-search.test.ts` and 1 in `typst-run-child.test.ts`), 1 skipped.
  The 8 new tests are `src/test/relay-persistence.test.ts`.
- Probes used: the audit's `qa/server/probes/{roomstate,many-updates,rate,bigmsg,roomsize,open-diskroom}.mjs`,
  `qa/exports-verify/scripts/{seed,race}.mjs`, and two new ones written for
  this pass (a 100-room burst that holds its sockets open, and a 100-room
  checker).
- Not verified live: the 15-minute compaction (unit-tested only, with a fake
  LevelDB), and a full backup then restore round trip (the backups stream owns
  that; a backup run on the QA box did complete with all rooms and twins).
