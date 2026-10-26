# Backups and restore: competition fixes (2026-10-12, branch fix/backups)

Stream: backups. Base: `competition-crash-fixes` (669ed8f). Audit ids from
`btct-audit-2026-10-12/all.json`. Everything below was run against throwaway
containers built from this branch (`btct-qa:backups3`, `WITH_REPORT_BINS=0`)
with 60 pages, 100 screenshots of 300 KB, 50 command-log rows, a named version
and the history twins, seeded by the audit's `load.mjs`.

## What changed, by issue

### BKP-1 / SRV-15: the documented restore command
The image's working directory is `/app/server`, so the command is
`bun restore.mjs` (or `bun /app/server/restore.mjs`). Fixed in
`Restore-BTCT.ps1`, the admin panel hint and `restore.mjs`'s own header and
usage text. Every restore below was run as `bun restore.mjs ...` in the image.
`bun restore.mjs` with no arguments prints the usage and exits 1.

### BKP-2 / SRV-23 and its inverse: order of a run
A run now goes: Yjs rooms, then the SQLite snapshot (`VACUUM INTO`), then the
assets listed in that SNAPSHOT (opened read-only), then the history twins. A
blob that is gone by copy time (retention or a delete in between) is recorded
`present: false`. Restore also inserts any `present: true` manifest asset that
the restored database lacks (`INSERT OR IGNORE`), which repairs backups taken
by older builds with the old order.
Measured: `race.mjs asset` at 30, 150, 300 and 600 ms into a run; for each run,
`checkrace.mjs` (scratch probe) found the race asset either referenced AND with
a snapshot row AND a blob, or not referenced at all (4 of 4 consistent). After
restoring onto a fresh volume the referenced race assets answer 200.

### BKP-3: restore undone by browser caches
- `restore.mjs` writes a new `restore_epoch` (uuid) into the restored settings
  whenever it restores Yjs rooms, unless `--keep-browser-caches` is passed.
- `GET /api/settings` now carries `restoreEpoch` (string or null).
- New `src/realtime/restore-epoch.ts`. `main.tsx` awaits
  `prepareClientCaches()` before the first render, so before any
  IndexedDB-backed doc opens: it fetches the epoch (2.5 s cap; offline keeps
  the cache) and, when it differs from `localStorage` `btct.restoreEpoch`,
  deletes every `btct-*` IndexedDB database, then stores the new epoch. A tab
  that clears its cache tells other tabs over the `btct-restore-epoch`
  BroadcastChannel; tabs also poll the epoch every 30 s while visible and
  reload when it moved.
- Both WebsocketProviders send the accepted epoch as the `epoch` query param.
  The relay's upgrade handler answers `409` to any other value (missing
  included) while an epoch is set, so a tab left open across the restore, or
  an old bundle, cannot push its stale state.
- Measured with `cache.mjs`: post-backup edit plus a deleted page record,
  restore, start. Fresh client: no edit, page present. Stale client
  reconnecting without the epoch: refused, never synced (timeout). Fresh
  client again: still no edit, page present. (At the base commit the stale
  client brought both back.)
- Not verified in a real browser: the IndexedDB deletion and reload flow is
  covered by `src/test/restore-epoch.test.ts` with fake-indexeddb only.

### BKP-4 / SRV-20 / S6: disk use per run
- Unchanged assets are hard links to the newest complete run that holds assets
  (same path and size), with a copy fallback on EXDEV, EPERM, ENOTSUP,
  EOPNOTSUPP, EMLINK, ENOSYS or EACCES. The previous run's sha256 is reused, so
  linked assets are not re-hashed. Manifests record `linkedBytes`.
- Opt-in `keepLast` (setting `backup_keep_last`, default 0 = keep all): after a
  successful run, the oldest complete runs beyond N are deleted.
- At scheduler start, `btct-backup-*.tmp` folders older than 1 h are removed.
- Measured: run 1 31 MB, runs 2 and 3 840 KB each on disk (`du`), asset link
  count 3. A sqlite-only run in between no longer breaks the chain (next full
  run 380 KB new). keepLast 3 with 116 runs on disk left 3. A 2-hour-old `.tmp`
  was removed at boot, a fresh one kept.

### BKP-5 / BLT-7: status and list cost
Run summaries are cached in memory by name plus directory mtime, dropped by a
run and a delete. The admin panel polls status with `pollWhileVisible` (15 s,
no overlap, paused while hidden). Manifests are written compact.
Measured with 115 runs on disk (`statuslag.mjs`): status 194 ms on the first
call after boot, then 3 to 6 ms; list 5 to 11 ms.

### SRV-7: persistence backlog and unreadable rooms
The run awaits `getPersistence().drain()` when the persistence provides it (the
server stream adds it; without it the call is a no-op), lists rooms from the
relay map, LevelDB and the history twins' ids, and reads each room through
`exportDocUpdate` (which awaits `whenLoaded`). A room that throws or times out
is recorded in `manifest.failedDocs` and in the result as `failedRooms`; the
run continues. Empty updates are skipped. Measured with a 1 ms room timeout
during a room-open storm: 57 rooms recorded as failed, run written, the admin
status and `restore.mjs --verify` both warn.

### BKP-7: a stuck run
Overall deadline (`BACKUP_DEADLINE_S`, default 1800) and per-room timeout
(`BACKUP_ROOM_TIMEOUT_S`, default 60). A run past its deadline is abandoned:
its `.tmp` is removed, `lastError` says "backup timed out after ...", and a
late step that wakes up writes nothing more. Status reports `runningSince`.
Measured: with `BACKUP_DEADLINE_S=0.3` under a 24-worker room storm the run
failed in 0.8 s, no `.tmp` left, `running:false`. With realistic settings the
same storm slowed a run to 15.7 s and RSS stayed at 81 MB.

### BKP-8: space, last good backup, retry
- `statfs` precheck: free space on `BACKUP_DIR` must cover the estimate (the
  previous run's non-asset bytes plus 20%, plus assets that run does not hold)
  plus `BACKUP_MIN_FREE_MB` (default 256). Fails fast with
  "not enough space in /backups: ...".
- `backup_last_good` is stored apart from `backup_last_result`; status
  `lastBackup` is the last good run even after a failure.
- A failed scheduled run is retried after min(interval, 5 min).
- The admin panel warns when scheduled backups have not succeeded for two
  intervals and shows free space.
- Measured on `--tmpfs /backups:size=20m`: 500 with the space message after
  293 ms, nothing written, `lastBackup` still the previous good run.

### BKP-9: restore while the server runs, older manifests
Restore probes the LevelDB lock whenever `YPERSISTENCE` is set and the live
SQLite with `locking_mode=EXCLUSIVE` plus `BEGIN EXCLUSIVE` (a plain
`BEGIN EXCLUSIVE` succeeds next to an idle WAL reader; measured), whatever the
backup holds. A manifest without an `includes` key (pre-history schema 1)
restores without `--partial`; the absent category keeps the current data.
Measured: sqlite-only `--partial` against a running box exits 3 (LevelDB
probe), and exits 3 again with `YPERSISTENCE` unset (SQLite probe). A manifest
with `includes.history` removed and `stateVector`/`dataVersion` added restores
with exit 0.

### BKP-10: permissions
Run directories 0700, files 0600 (verified with `stat`). Hard-linking a file
from an older 0644 run tightens it to 0600 for every run sharing the inode.

### BKP-11: dead code
Removed `pauseAllJobs`/`jobsPausedUntil`, `sqliteDataVersion`, `stateVectorOf`,
the per-doc `stateVector` and `sqlite.dataVersion`, and the OneDrive comment.
`readManifest` stays tolerant; the backup-format test keeps an old manifest
with both keys verifying.

### Missed issues from the cross-check
- **Config rewind**: the restored database keeps THIS box's `backup_*`
  settings (schedule, interval, includes, keepLast, token, instance id, last
  run and results). On a fresh box the backup's config is kept and its
  `backup_last_result` dropped. Measured: enable, interval 30, keepLast 50,
  regenerate the token, restore a run taken with the schedule off, start: the
  new token works, status shows enabled/30/50 and the boot log says
  "schedule every 30 min, keeping the last 50".
- **Tampered manifest**: `verifyBackupDir` (so restore and `--verify`) refuses
  asset ids, room names and history page ids that are not
  `^[A-Za-z0-9_-]{1,128}$` or whose file is not in `manifest.files`, and an
  included sqlite without `sqlite/data.sqlite.gz`. Measured: an added
  `{id: '../escaped.txt', present: true}` exits 2, the target volume stays
  empty, no `escaped.txt` anywhere.
- **Staged, atomic restore**: everything is built in `<parent>/.restore-staging`
  (normally `/data/.restore-staging`) after a statfs check, then each current
  file or folder is renamed into `pre-restore-<stamp>/` and the staged one
  renamed in. A failed swap is undone, and when it cannot be, the exact `mv`
  commands are printed. A target that is a mount point is refused up front.
  Measured: a 60 MB tmpfs for a 30 MB backup exits 4 with "not enough space"
  and the marker file untouched; a backup whose sqlite is garbage but hashes
  correctly exits 1 "nothing was changed" with `/data` byte-identical
  (listing and md5 of `data.sqlite` diffed).
- **`--verify`**: `bun restore.mjs --verify <dir>` exits 0 or 2, prints one
  line (plus a failed-rooms warning), never touches `/data` and never probes
  the server, so it runs next to a live box.
- **SRV-16**: rooms are written to the staged LevelDB, then each is read back
  and its decoded state vector compared with the backup update's; any mismatch
  fails the restore before the swap. Only the passing path was exercised (61
  rooms read back); a LevelDB write failure was not provoked.

### Full reimport onto a new box (the user's QA request)
Fresh volume, `bun restore.mjs /backups/<run> --yes` (3.9 s for 30 MB), new
`AUTH_SECRET`, then `verify.mjs` with the epoch: workspace present, 60/60 pages
in the shared doc, 59/60 page bodies identical (the 60th is the page the race
probe appended images to after seeding, as expected), 100/100 screenshots by
sha256, 100 typstAssets records, 51 command-log rows (REST and the live
window), 2 versions including the named one, its render, the history twin
(200) and the cmdlog config (login used the same admin password on both boxes, so it does not prove which users table answered). Partial restores (sqlite only,
shared doc only) kept the other categories intact (60 pages, 100 assets,
versions).

## New and changed surface

- Env vars (all optional): `BACKUP_DEADLINE_S` (1800), `BACKUP_ROOM_TIMEOUT_S`
  (60), `BACKUP_MIN_FREE_MB` (256). Fractions are accepted.
- Settings keys: `backup_keep_last`, `backup_last_good`, `restore_epoch`
  (not a `backup_*` key on purpose).
- `GET /api/settings`: new `restoreEpoch`.
- `POST /api/backup/config`: accepts `keepLast` (0 to 1000). `GET` returns it.
- `GET /api/backup/status`: new `keepLast`, `freeBytes`, `runningSince`,
  `usage.newBytes`, `lastBackup.newBytes`, `lastBackup.failedRooms`;
  `lastBackup` is now the last GOOD run.
- `GET /api/backup/list`: entries gain `newBytes` and `failedRooms` (count).
- `POST /api/backup/run`: result gains `newBytes` and `failedRooms`.
- WebSocket `/yjs/<room>`: new optional `epoch` query param; `409` when an
  epoch is set and the param does not match.
- Manifest: `failedDocs`, `linkedBytes`; `docs[].stateVector` and
  `sqlite.dataVersion` no longer written.
- `restore.mjs`: `--verify` (alias `--verify-only`), `--keep-browser-caches`;
  exit codes 0 done, 1 failed or bad usage (nothing changed unless it says
  so), 2 refused, 3 server running, 4 not enough space.
- `Restore-BTCT.ps1`: `-Verify`, `-KeepBrowserCaches`, `-HostBackupDir`; starts
  the container again after exit 2, 3 or 4 (nothing changed). Not run (no
  PowerShell here).
- `Backup-BTCT.ps1`: treats 409 as "already running" (Invoke-RestMethod threw
  before), prints new bytes, exits 1 when rooms were missing so a scheduled
  task shows the failure. Not run.

## Invariants for CLAUDE.md "Critical invariants"

- **A backup run reads rooms first, then the SQLite snapshot, then the assets
  listed in that snapshot, then the twins.** Reordering it (or reading asset
  rows from the live database) brings back screenshots that restore as 404 or
  rows without bytes.
- **A restore never writes into /data until everything is staged and
  checked.** New restore steps build into `.restore-staging` and join the
  final rename swap; they never move or write live files earlier.
- **Restore keeps the box's own `backup_*` settings and writes `restore_epoch`
  (not a `backup_*` key) when it rolls rooms back.** Every WebsocketProvider
  must pass `restoreEpochParams()`, and nothing may open a Yjs doc before
  `prepareClientCaches()` resolves in `main.tsx`; otherwise the relay refuses
  the client after a restore or a stale cache merges back in.
- **Every id in a manifest that becomes a path must match `ENTRY_ID_RE` and be
  listed in `manifest.files`** (`validateManifestEntries`).

## README / CLAUDE.md text that must change

1. CLAUDE.md:58 and README.md:2126, README.md:2226:
   stale `docker compose run --rm btct bun server/restore.mjs /backups/<name> --yes`
   replace with `docker compose run --rm btct bun restore.mjs /backups/<name> --yes`.
2. README.md:1648-1649:
   stale "Tar the btct-data volume to a timestamped .tgz" / "Restore a .tgz back into the volume"
   replace with "Ask the running app for a backup (POST /api/backup/run with the backup token)" /
   "Stop the container, restore a backup folder with restore.mjs, start it again (-Verify checks only)".
3. README.md:2091: stale "accounts, settings, chat sessions, asset index"
   replace with "accounts, settings, asset index, command-log archive, page version list".
4. README.md:2103-2106: stale "The four checkboxes choose what a run covers; leaving
   out accounts or workspace metadata makes the run restorable only with
   `--partial`. ... Nothing is deleted automatically: the panel lists every run
   with its size and a bin icon removes one."
   replace with "The five checkboxes choose what a run covers; leaving any of
   them out makes the run restorable only with `--partial`. *Back up now* runs
   one immediately. Screenshots that did not change since the previous run are
   hard links to it, so a run costs the new screenshots plus a few MB (copy the
   folder off the box with `rsync -aH`, since `-a` alone and robocopy expand
   the links into full copies). Nothing is deleted automatically unless you set
   *keep last N*; the panel lists every run with its size and a bin icon
   removes one. A run checks free space first (it keeps `BACKUP_MIN_FREE_MB`,
   default 256, free), has a deadline (`BACKUP_DEADLINE_S`, default 1800) and
   a per-room timeout (`BACKUP_ROOM_TIMEOUT_S`, default 60); a room it cannot
   read is listed as missing rather than failing the run, and a failed
   scheduled run is retried after 5 minutes. Run folders are 0700 and files
   0600: they hold password hashes and the command-log and backup tokens."
5. README.md:2131-2135 (restore paragraph): replace with "It re-hashes every
   file and checks every id in the manifest, refuses while the server runs
   (LevelDB lock and an exclusive SQLite lock), checks free space, builds the
   new data in `/data/.restore-staging` (each room is read back and compared),
   then moves the current data into `/data/pre-restore-<stamp>/` (kept, not
   deleted) and renames the new data in. A failure before the swap changes
   nothing. The restored database keeps this box's backup settings and token.
   `--partial` restores a backup that left a category out on top of the
   existing data; a backup made before a category existed needs no flag.
   `bun restore.mjs --verify /backups/<name>` checks a copy without touching
   anything (exit 0 or 2). Exit codes: 0 done, 1 failed, 2 refused, 3 server
   running, 4 not enough space. `Restore-BTCT.ps1` wraps the three commands."
6. New README paragraph after it, **Rollback or recovery**: "A restore that
   puts Yjs rooms back gives the server a new restore epoch. Every browser
   compares it on load, deletes its cached copies (`btct-*` IndexedDB) when it
   changed, and the relay refuses a client with an older epoch, so edits and
   deletions made after the backup do NOT come back: this is a rollback. For
   recovery onto a replacement box at the same address, pass
   `--keep-browser-caches` (`-KeepBrowserCaches`): the epoch stays, and
   browsers merge whatever they cached after the backup back in. A tab left
   open across a restore reloads itself; a tab still running a build from
   before this change cannot reconnect until it is reloaded."
7. README.md:2147 and 1695, 2064: stale volume name `beenthereconqueredthat_btct-data`
   replace with `<project>_btct-data` and a note to find it with
   `docker volume ls | grep btct-data`.
8. New README note for an interrupted swap (rare, the CLI prints the exact
   commands): `docker compose stop btct`, then
   `docker run --rm -v <project>_btct-data:/data btct:latest sh -c 'cd /data && mkdir -p .undo && mv yjs assets history data.sqlite* .undo/ 2>/dev/null; mv pre-restore-<stamp>/* . && rmdir pre-restore-<stamp>'`.
9. CLAUDE.md:132 (Backups architecture): replace "Nothing is pruned
   automatically by decision; the UI lists and deletes runs. `restore.mjs` is a
   CLI for a stopped server: verifies hashes, refuses if LevelDB is locked,
   moves old data to `pre-restore-<stamp>/`, rebuilds rooms with
   `storeUpdate`." with "Order: rooms, SQLite snapshot, assets from the
   snapshot, twins. Unchanged assets are hard links to the newest complete run;
   keep-last-N is opt-in (`backup_keep_last`, 0 = all); stale `.tmp` runs are
   removed at boot; run summaries are cached for status/list. `restore.mjs` is
   a CLI for a stopped server: verifies hashes and manifest ids, refuses while
   LevelDB or SQLite is locked, stages into `.restore-staging`, reads every
   room back, then swaps with the old data in `pre-restore-<stamp>/`; keeps the
   box's `backup_*` settings and writes `restore_epoch`
   (`src/realtime/restore-epoch.ts` clears browser caches on a new one)."
10. README "Key files map": add `src/realtime/restore-epoch.ts` (restore epoch:
    clears IndexedDB caches after a server restore).
11. README "Commands"/"Backups" verify command for off-box copies:
    `docker run --rm -v /media/usb/btct-backups:/backups:ro btct:latest bun restore.mjs --verify /backups/<run>`.

## Not done here
- `/healthz` backup fields and a SIGTERM handler belong to the server stream.
- `requireAdmin` on `/api/backup/status` and `/run` (missed issue in the server
  area) is the server stream's; the two routes are unchanged here.
