# Fix-up round 2 (QA failures of competition-hardening @ c1cea76, checked again on 064e053)

Round 1 (`fixup-round1.md`) changed the code for every QA failure but left one open: SIGTERM under a write backlog on half a CPU with docker's default 10 s grace. This round re-ran every failing check against the current branch, fixed that last one, and ran the backup-to-a-new-box suite that QA could not finish.

README.md and CLAUDE.md were updated in the same commit.

## SIGTERM under a write backlog (the open row of round 1)

**What was really happening.** An instrumented server (a 1 s heartbeat and a log line per LevelDB write) showed that the event loop stopped completely for 40 to 46 s while a client sent 3200 updates a second at `--cpus 0.5`: no heartbeat, no write completion, no signal handler. The same stall happened with `YPERSISTENCE` unset, so persistence was not the cause. Bun hands a socket's buffered messages to the `message` listener without going back to the event loop while more data is waiting, and y-websocket applies each message right there (a Yjs transaction, a broadcast, a persistence push and a history-twin apply per keystroke, about 0.16 ms each on half a CPU). A client that sends faster than that keeps the socket readable, so the loop never turns until the client stops and the backlog is gone. LevelDB writes started before the stall never completed, which is why only 90 to 400 characters survived the SIGKILL.

**Change.** New `server/relay-inbox.mjs`, used by `setupRelayConnection` in `server/index.mjs`:

- y-websocket's `message` listener is captured when `setupWSConnection` registers it and put behind a per-socket queue. The socket's own `message` event only queues the bytes, so Bun drains the socket quickly and returns to the loop.
- The queue is applied 256 messages per event-loop turn (`setImmediate`), each batch inside one `doc.transact(..., socket)`. The origin is the socket, as before. One batch is one Yjs transaction, one broadcast, one persistence entry and one twin update. Measured at 0.5 CPU on 150,000 churn updates: 164 us each one by one, 49 us each in batches of 256.
- y-websocket's `close` listener runs after the inbox has applied what is left, so edits that arrived before a client closed are kept. `shutdown()` flushes every inbox before it detaches sockets. `closeUserSockets` (account deleted) discards the inbox before it terminates the socket, so nothing queued from that account is applied.
- A socket with more than 20,000 messages or 64 MiB waiting is terminated and its queue dropped, with a `[relay] ... closed the socket` warning. The queue takes away the TCP back-pressure that a slow handler used to give, so without a cap one client could fill the server's memory. The client still holds those edits and sends them again, as one sync step 2, when its provider reconnects. A browser never comes near the cap; the 150,000-edit churn below never hit it.

**Checked.** `src/test/relay-inbox.test.ts` (6 tests: batching and order, flush on close, discard, the message and byte caps, byte accounting, and a batch in one transaction giving the same text with one update event per batch). QA's repro (`churn.mjs`, 150,000 edits from one socket, then `docker stop`, then `roomsize-slow.mjs` after a restart on the same volume):

| Setup | Round 1 | Now |
|---|---|---|
| `--cpus 0.5`, no init, default 10 s grace | 10.7 s, exit 137, 396 of 59,850 chars | 1.0 s, exit 0, 60,085 of 60,085 |
| `--cpus 0.5`, `--init`, `SHUTDOWN_TIMEOUT_MS=30000`, `docker stop -t 60` | 21.8 s, exit 0, all chars | 0.9 s, exit 0, 60,299 of 60,299 |
| 2 CPUs, no init | 0.6 s, exit 0, all chars | 0.6 s, exit 0, 60,435 of 60,435 |

`docker stop` in the middle of the flood (0.5 CPU, no init): SIGTERM handled at once, `stopped in 401 ms (clean)`, exit 0. `/healthz` polled every 25 ms during the flood: p50 71 ms, p99 189 ms, max 256 ms (QA: over 5 s for 60 to 95 s).

## Every other failure, re-run on this branch

All on `btct-qa:fixup2b` (this commit, `WITH_REPORT_BINS=0`), with QA's own probes where they exist.

| QA failure | Result now |
|---|---|
| Deleted user's open websocket keeps access (`open-then-write.mjs`, delete 2.5 s in) | socket closed (readyState 3, 1006) before it wrote; admin read of the room: text 0; log `closed 1 socket(s) of deleted user 2` |
| Relay dead with `YPERSISTENCE` unset; crash when empty | both modes: server up, first sync 56 to 57 ms, a 3000-edit churn stored in full, manual backup ok; the empty value logs `treating it as unset` |
| cmdlog ingest 2 s per POST on a box with no workspace | 42 ms, then 5 to 7 ms per POST |
| Backup run answers 200 `{"ran":true}` when SQLite is full | 20 MB `/data` filled with `dd`: `500 {"error":"database or disk is full"}`, status `lastError` the same, `lastSuccessAt` null |
| Unfinished cmdlog export blocks every backup | QA's script: the 9e15 `startedAt` import is skipped, the CSV export returns, the next backup succeeds; 5000 rows of 2 KB read with `head -c 100000`, then a backup succeeds; a backup during an export throttled to 2 KB/s succeeds; a full JSON export returns 5000 unique rows, CSV 5001 lines |
| Note images "not found in assets" on a first login | `scripts/qa-fresh-login-render.mjs` against the restored box below, Chromium and Firefox, fresh profiles: 2 images rendered on each note that has them, 0 "image not found", Assets panel 24 images |
| Firefox "Offline cache unavailable" banner after an import | two Firefox imports (as new) of the 100-page, 168-image Acme Internal ZIP: banner 0 before, 0 after, both runs. Timing-dependent, so this shows it is rare, not impossible |
| Export segments over 60 bytes | Chromium export of Acme Internal (870 entries, titles up to 259 bytes): longest segment 50 bytes, longest path 135, none over 60 |
| Change-log cap deletes history | `src/test/change-log-keeps-history.test.ts`; the restored box kept 6000 change-log entries (below) |

## Backup and restore to a new BTCT (the suite QA could not finish)

QA's seeder (`qa2/backup/probes/seed.mjs`, now complete) was run against box A on this branch, then `dump.mjs`, `inventory.py` and `diff.py` from the same folder. Box A held:

- 3 accounts (two admins, one non-admin, a password with spaces and `ü`), per-user colours and prefs (code accent, keybinds, note width, blur defaults, follow settings, heading theme);
- admin theme hardlock with heading colours, blur defaults, retention 365 days, command-log config, whitelist and ingest token, backup config and token;
- 3 workspaces (one with emoji and accents in the name), 300 pages up to 4 deep (duplicate, empty, 259-byte and `\ " * ? < > |` titles), 294 bodies with headings, code blocks of up to 400 lines, tables, task and ordered lists, quotes, links, inline code, `asset_image` nodes and remote images;
- 500 screenshots (PNG and JPEG, 180 MB) and one font, 167 with crop and blur metadata, 15 retired, in 15 nested asset folders;
- a Typst report source per workspace, 2 nmap scans with 14 machines and their raw XML, 6000 change-log entries (1500 with `pageTree` delete snapshots);
- 324 page versions (30 named) and 294 history twins, 6006 command-log rows (6000 from the agent route, 6 manual);
- added for this run: records in all eight retired tables (`siteMaps` to `timelineEvents`) and a legacy `pageSnapshots` entry.

One `POST /api/backup/run` took 5.7 s (1091 files, 183 MB). The folder was copied out with `docker exec ... tar`, checked with `bun restore.mjs --verify`, and restored with `bun restore.mjs <dir> --yes` into an empty named volume. Box B started on it with a different `AUTH_SECRET` and a different `ADMIN_PASSWORD` for the same bootstrap name.

`diff.py A B`: every section PASS, `RESULT: all equal`. That covers logins with the old passwords on all 3 accounts, `/api/me` and the admin user list, the non-admin still refused the admin route, public settings, retention, command-log config with the same ingest token, all 19 shared-doc maps entry by entry plus the shared doc's state vector, 300 page bodies (normalised ProseMirror JSON and state vector), 501 asset blobs (sha256, size, content type), the SQLite asset rows, 324 versions each rebuilt to the same ProseMirror JSON, 294 twin hashes and 6006 command-log rows column by column. `inventory.py` on B: `inventory complete`.

On B afterwards: B's own `ADMIN_PASSWORD` is refused (401; the restored account keeps its password), and the agent's old ingest token is accepted (`{"accepted":1}`). `scripts/qa-compare-boxes.mjs A B` then reported exactly that one new command-log row and the live window entry it pushed out, so it sees drift.

The round trip was repeated on the final images of this commit: box A on `btct-qa:hardening`, the backup restored into box B on `btct-qa:hardening-full` with `ENABLE_TYPST=1` (the report box). `inventory.py` passed on both, and `diff.py` passed every section but public settings, where the only differences are `features.typst` (false on A, true on B, from the environment) and the new `restoreEpoch`. A fresh-profile login on B in Chromium and Firefox rendered every note image with 0 "image not found" and 24 images in the Assets panel. The churn repro at `--cpus 0.5` with the default 10 s grace on `btct-qa:hardening`: stop 0.8 s, exit 0, 60,515 of 60,515 characters.

## New invariants (folded into CLAUDE.md #22 and README #34)

- Never apply a relay message straight from the socket's `message` event. Queue it in the socket's inbox (`server/relay-inbox.mjs`) and apply a batch per event-loop turn in one transaction. A socket's close applies the rest first; shutdown flushes every inbox before detaching sockets; a deleted account's inbox is discarded.

## New files and switches

- `server/relay-inbox.mjs` (+ `.d.mts`), added to the Dockerfile's runtime COPY list.
- No new env vars, routes or settings. Behaviour change: a socket with more than 20,000 messages or 64 MiB waiting to be applied is closed (logged); its client reconnects and resends.
