# Bugs stream (open failures after QA round 2)

Branch `fix/bugs2`, from `competition-hardening` at `dc21875`. Each fix below names what caused it, what changed and how it was checked. Server runs used `btct-qa:hardening` (built from `dc21875`; its server files match the branch byte for byte) with the changed `server/*.mjs` files bind-mounted over `/app/server`, on ports 8161 and 8171. No image was built. README.md and CLAUDE.md were updated in the docs commit.

| # | Failure | Result |
|---|---|---|
| 1 | Edits written during and after a disk-full episode lost on restart, persistence reported ok | fixed, verified (3 of 3 runs) |
| 2 | Last edits before a client closes miss the stored room; lost on SIGTERM within 300 ms | fixed, verified |
| 3 | cmdlog agent with `--batch-size` over 200 silently loses commands | fixed, verified (python:3.11-slim and a live server) |
| 4 | `restore.mjs --verify` exits 0 for a run whose payload cannot be restored | fixed, verified |
| 5 | A complete backup reported failed when `/data` is full; keep-last skipped | fixed, verified |
| 6 | Restore's "nothing was changed" paths rewrite files in `/data` | fixed (made read-only), verified on Linux x64 |
| 7 | Relay upgrade refusals reach the client as an empty reply | fixed, verified with curl; the browser side is unit-tested only, not verified in a browser |
| 8 | Any browser session clears emoji page icons | not changed (product decision); now documented |

## 1. Disk-full: torn LevelDB log (HIGH)

**Cause.** A LevelDB log append that fails part way (ENOSPC) leaves a torn record. LevelDB returns the error for that write but carries on: later writes go into the log after the torn bytes (its writer's block offset no longer matches the file) and into the memtable, and reads come from the memtable, so everything looks right while the process lives. `noteSuccess` turned `failing` off at the first write that succeeded. On the next open, log recovery reads up to the torn record and drops the rest ("dropping 6062 bytes; Corruption: checksum mismatch", silently, since `paranoid_checks` is off). Every write after the tear was lost.

**Change (`server/relay-persistence.mjs`, `server/index.mjs`).** New `createLevelDbLogSealer(ldb, dir, fs)`: inside y-leveldb's queue it compacts an empty key range (`[ff ff ff ff]`, no y-leveldb key starts with 0xff). LevelDB's `CompactRange` always flushes the memtable to a table file and switches to a new log first; once the memtable is in a table the old log is deleted. `CompactRange` returns no status, so the sealer checks that every numbered `.log` that existed before is gone. The binding takes it as `sealLog`; after a failure, a successful write starts a seal, and `failing` clears only when a seal finished with no failure since it started and no room or closed room is still waiting for its retry. A failed seal or one overtaken by a failure is retried after `retryMs`. `drain()` waits for a seal in progress, `close()` too. `status()` gains `sealing`.

Found on the way: leveldown's `compactRange` on a handle that is still opening dereferences a null pointer and kills the process (Bun segfault, which also dumped a 6.7 GB core into the worktree; deleted). The sealer waits for levelup's deferred open and refuses a closed handle.

**Checked.** QA's T5e repro as `bugs2/diskfull.sh` (8 MB tmpfs volume `btct-qa-bugs2-small` kept by a holder container, `diskroom` 600 edits, disk filled with `dd`, 100 more edits plus `lostroom` 600, disk freed, `afterroom` 20 edits, `docker stop`, start on the same volume):

| | lostroom | diskroom | afterroom | LOG |
|---|---|---|---|---|
| before (image as built) | 0 | 6080 | 0 | `dropping 6062 bytes; Corruption: checksum mismatch` |
| after, run 1 to 3 | 5290 | 6080 | 150 | clean |

While full: `/healthz` 503, `failing:true`. After freeing: `[persistence] writes are succeeding again; the LevelDB log was sealed into a table`, `/healthz` 200. Tests: `src/test/relay-persistence.test.ts` (stays failing until the seal; a failure during the seal and a failed seal keep it failing), `src/test/leveldb-log-seal.test.ts` (real LevelDB in a child process: without a seal a write lives only in the log; after a seal it survives losing every log, the old log is gone, writes go on; sealing a freshly opened empty database twice; a handle with no `compactRange` reports false).

**Limit.** If the memtable flush itself fails, LevelDB records a sticky background error and every later write fails until the process restarts; the binding then stays `failing` (503) and shutdown's drain reports it. Reopening LevelDB in process was not attempted.

## 2. Close race: last edits before a client closes (MEDIUM)

**Cause.** As QA described: the inbox applied a closing socket's queued update after the socket left OPEN; y-websocket's broadcast (registered before the persistence listener) sent to the closed socket, `send()` called `closeConn()`, and the last connection handed the room to `writeState` with an empty buffer and unmapped it. The update then landed in the detached room with only a 300 ms timer to write it; `drain()` skipped detached rooms. A second issue in the same path: the doc is destroyed once its last write is stored, so a later inbox batch for that socket found no doc.

**Change.** `relay-persistence.mjs` `onUpdate`: an update for a room that is closing or no longer mapped is flushed at once with `final: true` (queued in LevelDB ahead of any reload, tracked in `inflight` so `drain()` waits for it). `relay-inbox.mjs`: new `isOpen` option; the first turn after the socket left OPEN applies everything queued in one go. `index.mjs` passes `isOpen: () => ws.readyState === 1`.

**Checked.** QA's `close-race.mjs` (8 trials each): before, missing 8 of 8 in both `update-only` and `step1-first`; after, 0 of 8 in both. QA's shutdown probe (`sd-run.sh` copied to port 8171 with a bind-mounted data dir): before 7 of 61 rooms empty after restart; after 0 of 60 and 0 of 59. Tests: two in `relay-persistence.test.ts` (an update arriving after `writeState`, the way y-websocket orders it, is there for a reload that starts at once and for `drain()` with a 60 s flush interval), one in `relay-inbox.test.ts`.

## 3. cmdlog agent batch size (MEDIUM-LOW)

**Cause.** The server reads the first 200 events of a POST and answers 200 with `accepted`; the agent took any 2xx as the whole batch delivered.

**Change (`cmdlog-agent/` only; `server/cmdlog.mjs` untouched).** `MAX_BATCH_EVENTS = 200`; `--batch-size` is clamped to 1..200 with a warning on stderr, and `Shipper` clamps too. `_deliver` splits anything over 200. `post_events` returns the reply; events past `accepted + skipped` are sent again, `skipped` events count as `rejected`, and a 2xx that read nothing keeps the batch and backs off.

**Checked.** `python:3.11-slim`, `python -I -B -m unittest discover -s tests`: 54 pass (5 new). Live server, 1000 commands each with QA's probe (ids per agent): old agent batch 25 / 500 / 1000 stored 1000 / 400 / 200 rows; new agent 1000 / 1000 / 1000.

## 4. `restore.mjs --verify` and undecodable payloads (LOW)

**Change.** New `server/restore-checks.mjs` (with `.d.mts`, added to the Dockerfile's COPY list): `checkBackupPayloads` gunzips the SQLite snapshot to a temp file, checks the header, switches it out of WAL and runs `quick_check` (what `finishStagedSqlite` does), and applies every room's update to an empty doc, which must read back to the update's own state vector (what `stageRooms` checks). `restore.mjs` runs it right after `verifyBackupDir`, for `--verify` and for a restore, and refuses with exit 2.

**Checked** (`bugs2/restore-e2e.sh`, a backup from a throwaway box, copies with a random `sqlite.gz` or room update and a manifest rewritten to match): `--verify` good 0, bad SQLite 2, bad room 2 (before: 0, 0, 0); restore of each bad copy 2 (before: 1). Tests: `src/test/restore-checks.test.ts` (Yjs: whole doc, random bytes, truncated, an update missing its dependencies; payload list with a fake SQLite; real SQLite in a Bun child: good, garbage, pages overwritten, not gzip, no temp file left).

## 5. Backup on a full `/data` (LOW)

**Change (`server/backup.mjs`).** Once the run is renamed into place its result is stored best effort: when `setSetting` throws, the run still returns its result, prunes to keep-last, and is kept in memory (`unrecordedGood`), which `lastResult` and `lastGood` prefer when newer, so status shows it until a restart.

**Checked** (QA's repro, `bugs2/fullbackup.sh`, 20 MB `/data` filled with `dd`, keepLast 1, three runs 1.1 s apart): before, three `500 database or disk is full` and three archives; after, three `200 ok`, one archive, status `lastError` null with the newest run as last backup, logs `... is complete, but its result could not be saved in SQLite`. Not unit-tested (`backup.mjs` imports `db.mjs`, which needs `bun:sqlite`). A manual run in the same second as the previous one still answers `already exists (two runs in the same second)`; that is now a real collision with a successful run, so it was left.

## 6. Restore refusals that rewrote `/data` (LOW)

Fixed in code, not in the docs: the claim "nothing was changed" is now true byte for byte on Linux x64/arm64.

**Cause.** The running-server probes opened LevelDB (log replay and compaction: `000010.log` became `.ldb` plus a new log, `CURRENT`, `MANIFEST`, `LOG` rewritten) and SQLite read-write with an exclusive lock (the WAL checkpoint on close deleted an empty `-wal`); `readCurrentSettings` opened the live database read-only, which still writes the `-shm`.

**Change (`server/restore.mjs`, `server/restore-checks.mjs`).** `createPosixLockProbe` calls `fcntl(F_GETLK)` through `bun:ffi` and `libc.so.6` on LevelDB's `LOCK`, the SQLite file and its `-shm`: it takes no lock, writes nothing, and sees a server in another container (the kernel's lock table is per inode; `/proc/locks` was tried first and is filtered by pid namespace, so it cannot see the server's container). `lockedDataFiles` in `restore.mjs` uses it and exits 3 on a holder. Only when it cannot ask (not Linux on x64/arm64, no `libc.so.6`) does `main()` fall back to the old open-based probes, with a warning that says what they rewrite. `readCurrentSettings` reads a temp copy of the database and its `-wal`.

**Checked** (`restore-e2e.sh`, md5 of every file under `/data` before and after): two refused restores (exit 2), exit 3 with the server running, exit 4 on a full tmpfs `/data`: all byte-identical. The old `restore.mjs` on the same data: `-shm` changed and LevelDB compacted after the refused restores, `-wal` deleted and LevelDB rewritten after exit 4. A good restore afterwards still restores (page room 1690 characters, read with the new epoch) and sets a new epoch. Test: the Bun child in `restore-checks.test.ts` holds SQLite (WAL) and LevelDB open in a grandchild, sees both held, both free after release, and both directories unchanged by the probe. A staging failure (exit 1) still creates and removes `.restore-staging` beside the data, as documented.

## 7. Upgrade refusals as an empty reply (LOW)

**Cause.** Under Bun 1.3.14 the upgrade handler's `socket` is not the TCP connection. Probing a bare `node:http` server in the image: `write`+`destroy`, `end`, `write` with a callback, `end` then `destroy` on `finish`, and `write` with a 300 ms delay all gave curl an empty reply. Bun's own `ws` module answers a refused handshake through the request's response (`socket._httpMessage || socket[kBunInternals]`, not reachable from user code), and that does arrive.

**Change (`server/index.mjs`).** `refuseUpgrade(req, socket, head, code)` hands the socket to a `WebSocketServer` per status whose `verifyClient` refuses with that code; all seven refusals use it. Client: browsers cannot read the status of a refused upgrade, so detection stays as it was (401 through `/api/me` after failed connects, then the login banner; 409 through the restore epoch). New: a failed connect of the shared provider calls `checkRestoreEpochNow()` (`src/realtime/restore-epoch.ts`, at most every 5 s), so a tab open across a restore reloads within seconds instead of at the next 30 s poll.

**Checked.** curl on a restored box: no epoch `HTTP/1.1 409`, bad token 401, `/nope` 404, `/yjs/` 400 (all an empty reply before), the right epoch 101 and the room reads back. Bun prints the reason phrase as `[object Object]` (its `ws` passes the headers object where `writeHead` expects the reason); the code is right. Tests: two in `src/test/restore-epoch.test.ts` (reloads on a new epoch, rate limit, no reload offline or without an epoch). Not verified in a browser: the client change was not built into an image.

## 8. Emoji page icons (product decision, unchanged)

`scrubEmojiIcons` was documented only in a code comment, which also described the regex wrongly (it said ASCII plus Latin-1; it clears anything outside ASCII). Now: README invariant 57 and a note at the page feature, a CLAUDE.md line under the two-tier design, and the corrected comment. Behaviour unchanged.

## Tests

`docker run --rm -v <worktree>:/w -w /w oven/bun:1.3.14 sh -c 'bun install --frozen-lockfile && bunx tsc -b && bunx vitest run'`: tsc clean; vitest 778 passed, 1 failed (`typst-run-child` "kills grandchildren too", the known environmental failure), 5 skipped (baseline 761 / 1 / 5). Agent: 54 unittest tests pass in `python:3.11-slim`.

## New files and switches

- `server/restore-checks.mjs` (+ `.d.mts`), in the Dockerfile's runtime COPY list.
- `src/test/fixtures/leveldb-seal-child.mjs`, `src/test/fixtures/restore-checks-child.mjs`: child processes for the real LevelDB, SQLite and `fcntl` tests (a native crash fails the test instead of the vitest worker).
- `status().sealing` in `GET /api/admin/status` persistence counters. No new env vars or routes.
