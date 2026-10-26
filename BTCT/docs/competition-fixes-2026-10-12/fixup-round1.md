# Fix-up round 1 (QA of competition-hardening @ c1cea76)

Every QA failure from the four suites, what caused it, what changed and how it was checked again. README.md and CLAUDE.md were updated in the same commit (this round may edit them directly).

## Backup and restore to a new BTCT

**QA result:** the suite never ran. Its seeder (`qa2/backup/probes/seed.mjs`) was cut off while being written, so this was a harness failure, not a product defect.

**Re-run here instead.** Box B (`btct-qa:hardening-full`, `ENABLE_TYPST=1`) held three imports of the 300-page Alpha archive plus the demo workspace, a second account, command-log config and 18,015 command-log rows. One admin backup run (`POST /api/backup/run`, 8.9 s) wrote 3215 files: 901 rooms, 1413 assets, 900 history twins. The folder was copied out with `docker exec ... tar` and restored with `bun restore.mjs --verify` and then `bun restore.mjs <dir> --yes` into an empty named volume. A new container (box C, its own `AUTH_SECRET`, its own bootstrap admin env) started on that volume and `scripts/qa-compare-boxes.mjs` compared B and C:

```
shared-doc maps (entries on A): {"workspaces":4,"assetFolders":18,"typstAssets":1413,"pages":905,"nmapScans":6,"nmapMachines":42,"changeLogs":18000,"timelineEvents":6,"texts":1865}
page bodies compared: 905 (900 non-empty)
asset blobs compared: 1413 (20.6 MB; 0 with no blob on A either)
page versions compared: 900, twins compared: 900
accounts compared: 2
command-log rows compared: 18015
RESULT: identical
```

The probe compares every shared-doc map entry (retired tables included), every page body, every asset's bytes (sha256), every page's version list and twin bytes, accounts, `/api/settings`, the command-log and retention config, and each workspace's full command-log export. Deleting an account and one workspace's command log on C afterwards made it report exactly those two differences, so it does detect drift.

## Export and import

### Note images "not found in assets" on first login in a fresh browser

**Cause:** `loadWorkspaces()` set `activeWorkspaceId` to the first workspace without loading that workspace's `typstAssets`, `assetFolders` or `commandLogs`; `App.tsx` reloaded only pages, change log and scans on `activeWorkspaceId`. The `typstAssets` observer had already fired during the initial sync while the id was still null.

**Change:** a store action `loadWorkspaceData()` loads all six workspace-scoped lists. `setActiveWorkspace`, `loadWorkspaces` (when it picks the default) and the `App.tsx` effect on `activeWorkspaceId` all call it.

**Checked:** `src/test/default-workspace-load.test.ts` (fails without the fix). In the browser (`scripts/qa-fresh-login-render.mjs`, fresh profile, no workspace switch) on box B after an import: Chromium and Firefox both rendered the note's 2 images with no "image not found" and the Assets panel showed 24 images. The same probe on the pre-fix `btct-qa:exports` image showed 0 images in the Assets panel.

### Firefox "Offline cache unavailable" banner after a large import

**Cause:** `whenIdbLoaded` reported a slow open (no database after 3 s) the same way as a failed one, and a page context called the global `markIdbUnavailable()` for either. An import opens about 300 page databases four at a time, and in Firefox one could cross 3 s.

**Change:** `whenIdbLoaded`'s callback now gets a reason, `'failed'` or `'timeout'`. A page context raises the global banner only for `'failed'`; on `'timeout'` it runs from memory and the server, and goes back to its cache (`memoryOnly = false`) if the database opens later. The shared doc still raises the banner on either, so a store that never opens is still reported.

**Checked:** `src/test/idb-ready.test.ts` (new reason assertions). Three Firefox imports of the Alpha ZIP into box B: banner 0 before and 0 after each (QA had 1 after, 3 of 3). The original failure depended on timing, so three clean runs show it is much rarer, not that it cannot happen.

### Export segments over the 60-byte cap

**Cause:** the note title was capped at 60 bytes and `.attachments` or `.md` was appended afterwards. The same applied to the root folder: workspace name capped at 60 plus `_YYYY-MM-DD_HHMM`, and to the single-page Markdown download.

**Change:** `NOTE_TITLE_BYTES = NOTE_SEGMENT_BYTES - '.attachments'.length` (48) caps note folder names; the root caps the workspace name at 60 minus the stamp; the single-page `.md` caps the title at 57.

**Checked:** `src/test/export-segments.test.ts`. Browser export of Alpha from box B: 2336 entries, longest segment 60 bytes, longest path 172 (before: 72 and 196).

## Server chaos and soak

### SIGTERM never handled under a write backlog; recent edits lost

**Cause (the part in our code):** `flushRoom` merged the whole buffer with one `Y.mergeUpdates`, which is quadratic in the number of updates, and the buffer had no count cap. A backlog made each merge slower, which grew the next buffer.

**Change (`server/relay-persistence.mjs`):** the buffer flushes at 2000 updates as well as at 2 MB. Up to 1000 buffered updates are merged in groups of 64 (`mergeUpdatesBounded`, exported); a longer buffer is written as `Y.encodeStateAsUpdate(doc, baseSV)`, where `baseSV` is the state vector taken in `beforeTransaction` just before the buffer's first update. A buffer that began before the room loaded never gets a `baseSV` and is always merged in groups, so the diff never rewrites the stored state. Measured on 0.5 CPU for 150,000 churn edits: grouped merges in flushes of 500 took 4.1 s, diffs 6.4 s; in flushes of 2000, 3.4 s against 2.0 s; one plain `mergeUpdates` of 2000 took 22.6 s. With y-websocket's own update listener counted, the persistence now adds no measurable cost to applying those 150,000 updates (33.9 s without it, 33.0 s with it, at 0.5 CPU).

**Checked:** four new tests in `src/test/relay-persistence.test.ts` (diff path with two writers and deletes never re-stores the loaded state, count flush, pre-load buffer, grouped merge equals one merge). Repro rerun with QA's `churn.mjs` (150,000 edits, one socket):

| Setup | Before | After |
|---|---|---|
| `--cpus 0.5`, `--init`, `SHUTDOWN_TIMEOUT_MS=30000`, `docker stop -t 60` | 61.0 s, exit 137, 375 of 60,396 chars | 21.8 s, exit 0 (clean), 60,453 of 60,453 chars |
| 2 CPUs, no init, default 10 s | passed | 0.6 s, exit 0, 60,251 of 60,251 |
| `--cpus 0.5`, no init, default 10 s | 10.8 s, exit 137, 314 chars | **still fails**: 10.7 s, exit 137, 396 of 59,850 chars |

The last row is not fixed. At 0.5 CPU, Yjs itself needs about 0.22 ms to apply one of these updates (34 s for the 150,000), so a client sending 3200 updates a second builds a backlog of socket messages, and Bun does not run the SIGTERM handler until that backlog is drained (21.8 s after `docker stop` in the compose-like run). The compose settings (init, 60 s grace, 30 s shutdown timeout) cover it; a plain `docker run` with 10 s does not. Making the relay shed or defer that load is a design change, not a bug fix, so it is left open.

### A deleted account's open websocket kept reading and writing

**Change (`server/index.mjs`):** `watchSocket` records each socket under its account id; `DELETE /api/admin/users/:id` calls `closeUserSockets(id)`, which terminates them (no close handshake, so nothing sent afterwards is applied) and logs the count. The upgrade handler checks the account again after the room's load, since that await can span a delete.

**Checked:** QA's `open-then-write.mjs` with a delete 2.5 s in: the socket was closed (readyState 3, code 1006) before it wrote, and an admin read of the room found no text. Password reset and rename were left alone on purpose: tokens carry no version, so a reset does not revoke the old token, and closing the socket would only make it reconnect.

### Relay dead with YPERSISTENCE unset; crash with it empty

**Cause:** `loadRelayDoc`, `yjs-data.mjs` `shared()` and `data-export.mjs` awaited `doc.whenLoaded`, which on a doc no persistence has bound is Yjs's own subdocument promise and never resolves. An empty `YPERSISTENCE` made y-websocket open LevelDB at `''`.

**Change:** all three await `whenLoaded` only when persistence is set. New `server/env.mjs`, imported first by `index.mjs` (and copied by the Dockerfile), treats an empty `YPERSISTENCE` as unset and logs when rooms are memory-only.

**Checked:** both modes on `btct-qa:hardening` with `--entrypoint env`: the server stays up, a page room's first sync arrives in 30 to 56 ms, a manual backup runs. Before: no sync in 15 s, and exit 1 at boot for the empty value.

### Command-log ingest took 2 s per POST on a box with no workspace

**Cause:** `shared()` polled the shared doc for workspaces for up to 2 s on every call while none existed, after already awaiting the load.

**Change:** no poll. After the load (or with no persistence) the doc is authoritative and is memoized. A room LevelDB cannot read is dropped from the relay map and `shared()` throws, so nothing writes into a doc that will never be stored.

**Checked:** five `POST /api/cmdlog/events` with `"workspace":"w1"` on a fresh box: 40 ms, then 4 to 7 ms each (was 2.03 s each).

### Backup run answered 200 {"ran":true} when its result could not be recorded

**Cause:** `runBackupNow` read the outcome back from SQLite (`backup_last_result`), which was the very thing that could not be written.

**Change:** `createJob().trigger()` now resolves `{ ran: true, error, result }` with the run's own outcome, and `runBackupNow` throws on `error` and returns `result`. `runBackup` records a failed result best-effort, so the run's own error is the one reported.

**Checked:** `src/test/scheduler.test.ts`. With `/data` a 20 MB tmpfs filled by `dd`: `POST /api/backup/run` answers `500 {"error":"database or disk is full"}`, matching `backup/status`.

## Adversarial review

### An unfinished command-log export blocked every backup

**Cause:** `handleCmdlogExport` held a cached `db.query().iterate()` cursor across `await`s and returned early (client gone, a `false` write, a throw from `toISOString`). bun:sqlite leaves that statement active, and `VACUUM INTO` then failed until a restart.

**Change (`server/cmdlog.mjs`):** the export reads keyset pages of 500 rows with `.all()` (each runs to completion), so no statement is open across an await. `clampTime` rejects a `startedAt` outside what a `Date` holds (ingest, manual and import), and the CSV writes the raw number for an older row that has one instead of throwing.

**Checked:** QA's repro on the rebuilt image: the import of `startedAt: 9e15` is skipped; a row with that value written straight into SQLite exports as `9000000000000000,...` and the backup after it succeeds; 5000 rows of 2 KB read with `head -c 100000`, then a backup succeeds, and a full JSON export returns 5000 unique rows and a CSV 5001 lines.

### Change-log cap deleted existing history

**Cause:** `changeLogRepo.add()` pruned the workspace's log to 2000 on every write, so the first edit after a restore or an import of a 6000-entry log deleted 4000 entries for every client.

**Change:** `add()` no longer prunes. `prune()` and `pickPruneIds` stay for an explicit trim; growth is still held down by the per-page, per-5-minute coalescing of content saves. An admin-facing, opt-in cap would need a setting and UI, which is a product decision left for later.

**Checked:** `src/test/change-log-keeps-history.test.ts` (6000 entries plus one add keeps 6001; it fails with the old `add()`). Box B kept 6000 change-log entries per imported workspace through import, backup and restore.

## New invariants (already folded into CLAUDE.md and README)

- Never hold a `bun:sqlite` statement across an `await`. A statement left mid-`iterate()` stays active and `VACUUM INTO` fails every backup until a restart.
- Never merge an unbounded list of Yjs updates on the relay's thread. Relay persistence merges at most 1000 in groups of 64 and writes a state-vector diff past that.
- Await `doc.whenLoaded` only when relay persistence is set; on an unbound doc it never resolves.
- Nothing prunes the change log automatically.
- Deleting an account terminates its open relay sockets.
- A page database that is only slow to open must not raise the global offline-cache banner.
- Every export path segment, suffixes included, is at most 60 bytes.

## New files and switches

- `server/env.mjs` (in the Dockerfile's server COPY list): empty `YPERSISTENCE` counts as unset.
- `scripts/qa-compare-boxes.mjs`: field-by-field comparison of two servers (the reimport check above).
- `scripts/qa-fresh-login-render.mjs`: fresh-profile login and note-image render check.
- No new env vars, routes or settings. `POST /api/backup/run` now answers 500 with the run's own error when the run fails, even when SQLite cannot record it.
