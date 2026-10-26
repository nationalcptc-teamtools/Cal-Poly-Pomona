# Backups, per-user history, and theming: task breakdown (2026-08-22)

Scope of this plan, as requested:

1. Connect to OneDrive for constant backups, with a selection of what to back up, at an interval in minutes or seconds.
2. A rollback and history management system per user, modelled on Google Docs version history.
3. Local backups at an interval, for Windows and Linux hosts.
4. A per-user config so each user can change the colour of note headings.
5. An admin "hardlock" that forces one theme on everyone when enabled.

This document is a breakdown into tasks, not an implementation. It records what already exists in the repo, the design decisions the tasks assume, the tasks themselves (grouped into epics, with dependencies, sizes and acceptance criteria), a suggested order, and the open questions that need an answer before the corresponding epic starts.

Sizes: S is up to half a day, M is one to two days, L is three to five days.

---

## 1. What exists today (and what does not)

The features build on real code. This is the starting point for each one.

### History and rollback

| Exists | Where | Gap |
|---|---|---|
| Whole-page snapshots with author, timestamp, optional label, size | `src/realtime/page-snapshots.ts`, `src/db/page-snapshot-repo.ts`, `PageSnapshot` in `src/types/index.ts:298-309` | Snapshot bytes are base64 **inside the shared CRDT** (`pageSnapshots` table), so every version is broadcast to and cached by every client |
| Auto snapshot 2 minutes after the last edit, keep 20 unlabelled per page | `page-snapshots.ts:24-59`, trigger at `PageEditor.tsx:345` | Client-only: nothing snapshots when no browser is open, and server-side edits (AI assistant, MCP) are never captured. No size cap, no "skip if unchanged" |
| Named versions ("Label (optional)" + Save), restore, delete | `src/components/sidebar/PageHistoryPanel.tsx` | No diff, no compare, no per-user filter, no grouping, restore is a confirm dialog |
| Restore | `page-snapshots.ts:68-97` | Clears the fragment and re-inserts clones in one transaction: correct but not a minimal delta, and it creates no "restore" version |
| Entity change log with restore for deletes/renames | `changeLogRepo`, `app-store.ts:202-226, 724-806`, `ChangeLogPanel.tsx` | Capped at 200 in memory, no filters, no archive; page bodies intentionally excluded, so versions and the change log are two disconnected timelines |
| Per-page Y.Doc | `src/realtime/yjs-providers.ts:59` | `new Y.Doc()` with garbage collection **on**, and the relay's docs are GC-on too (`GC` env unset). `Y.snapshot`/`Y.createDocFromSnapshot` require GC off |
| Collaborator identity in awareness (id, name, colour) | `yjs-providers.ts:41-49` | `Y.PermanentUserData` is never set and `ySyncOpts` is never passed (`PageEditor.tsx:488-513` only sets `yCursorOpts`), so there is no per-character authorship |

### Preferences and theme

| Exists | Where | Gap |
|---|---|---|
| Per-user prefs blob on the account | `users.prefs` (`server/db.mjs:95-97`), `POST /api/me/profile` validator (`server/index.mjs:302-359`), `src/lib/editor-prefs.ts` (`codeAccent`, `keybinds`, `follow`), applied in `App.tsx:42-46` | No theme-related per-user prefs; every new key needs the hand-written validator extended |
| Global accent colour, admin-only | `theme_color` setting, `POST /api/settings/theme`, `src/lib/theme.ts` (`--primary`, `--ring` only), `ThemePicker.tsx`, button in `LeftSidebar.tsx:558-576` | Reaches other clients only on reload (`loadTheme()` runs once at mount) |
| Heading styles | `src/index.css` `.milkdown-host .ProseMirror h1..h6` | No `color` and no CSS variable, so nothing to override yet |
| Dark/light toggle | `app-store.ts:685-691` | Client-local, not persisted |
| Precedence model | none | Admin settings and user prefs both write `document.documentElement` with no rule for who wins |

### Admin settings and server plumbing

| Exists | Where | Gap |
|---|---|---|
| `settings` KV table, `getSetting`/`setSetting` | `server/db.mjs:29-32, 189-202` | Untyped strings, no defaults registry, no audit, secrets (`anthropic_api_key`, `mcp_token`, `cmdlog_token`) in **plaintext** |
| Admin Panel with AI / MCP / cmdlog / users sections | `src/components/sidebar/AdminPanel.tsx` | No backup or theme policy sections |
| Admin gate | `requireAdmin` (`server/index.mjs:166-177`) | fine |
| Background jobs | none (`setInterval` appears zero times in `server/`) | A scheduler is needed before any backup work |
| Outbound HTTP | only the Anthropic SDK (`server/ai.mjs`) | OneDrive will be the first raw `fetch` client in the server |

### Data layout

| Exists | Where | Gap |
|---|---|---|
| One volume `btct-data:/data`: SQLite (WAL) at `/data/data.sqlite`, y-leveldb at `/data/yjs`, asset blobs at `/data/assets` | `docker-compose.yml:11-33`, `server/db.mjs:6-14`, `server/assets.mjs:32-39` | `ASSETS_DIR` is not set explicitly in compose |
| Host-side PowerShell backup/restore | `Backup-BTCT.ps1`, `Restore-BTCT.ps1` | The backup tars the **live** volume: a WAL-mode SQLite file and an open LevelDB directory copied mid-write can be corrupt. Windows only |
| In-app Export / Import | `src/components/ui/ExportDialog.tsx`, `src/export/workspace-zip.ts` | Per-workspace, browser-driven, no SQLite side (users, prefs, settings, chat), no asset bytes, and skips page bodies not opened in the current session |
| Dockerfile copies server files one by one | `Dockerfile:50-59` | Every new `server/*.mjs` must be added to the `COPY` list |

---

## 2. Research conclusions the tasks rely on

Full source lists are at the end. These are the points that changed the design.

### OneDrive / Microsoft Graph

- **Auth flow: device code.** Microsoft only accepts `https` redirect URIs except for `http://localhost`; `http://192.168.x.x` and plain hostnames are rejected. A self-hosted LAN app therefore cannot complete an authorization-code redirect without TLS and a real hostname. The device code flow needs no redirect URI: the admin sees a short code and a link (microsoft.com/devicelogin), signs in there, and the server polls for the token. It works for personal accounts (tenant `/consumers` or `/common`). The app registration needs "Allow public client flows" set to Yes.
- **Scope: `Files.ReadWrite.AppFolder offline_access`.** The app gets its own folder under `Apps/<app name>` and nothing else. Always address it as `/me/drive/special/approot`, never by path (the `Apps` folder name is localised and sometimes literally "Graph"). Microsoft's own pages disagree on whether AppFolder works for work/school accounts, so the UI should offer `Files.ReadWrite` as an opt-in fallback.
- **Refresh tokens** last 90 days by default, rotate on every use, and are revoked when the user changes their password. They must be stored encrypted, and the UI needs a "reconnect" state.
- **Upload:** `PUT .../approot:/{path}:/content` under 10 MiB, `createUploadSession` above it (chunks that are multiples of 320 KiB, 5 to 10 MiB each, `@microsoft.graph.conflictBehavior: replace`). `GET .../approot/children` to list, `DELETE` for retention.
- **Throttling:** every 429/503 carries `Retry-After` and ignoring it makes things worse. Field reports (Duplicati, rclone, abraunegg/onedrive, remotely-save) all converged on: concurrency 1, honour Retry-After globally, exponential backoff, a decorated `User-Agent`. A fixed timer every few seconds is the wrong shape for a cloud target; "constant" backups should be **change-driven** (upload only what changed, after a short quiet period) with a floor of 30 s and a default of 60 s, plus a slower periodic full archive.
- Plain `fetch` is enough (Bun has it natively); no Graph SDK or MSAL dependency is needed for two token POSTs and a handful of REST calls.

### Consistent capture of `/data`

- **Never copy the live SQLite file.** In WAL mode recent commits live in `-wal`. Use `VACUUM INTO 'tmpfile'`: a consistent snapshot, does not block writers, plain SQL on the existing `bun:sqlite` connection. On restore, delete any stale `-wal`/`-shm` beside the restored file.
- **Never copy the live LevelDB directory.** LevelDB is single-process (LOCK file) and has no checkpoint API; a copy can capture a torn log or manifest. Export through y-leveldb instead: `getAllDocNames()`, `getYDoc(name)` + `Y.encodeStateAsUpdate`, `getAllDocStateVectors()` for cheap change detection, `storeUpdate` to rebuild on restore. The Yjs update format is stable across LevelDB versions. The persistence instance is reachable through y-websocket's `getPersistence()` (verify when implementing; invariant #6 applies, one `require('yjs')`).
- **Assets** are immutable uuid-named blobs: copy by id, upload once, keep a ledger.
- Archive = `manifest.json` (schema version, instance id, timestamp, what is included, sha256 per file, per-doc state vectors, SQLite `PRAGMA data_version`) + `sqlite/data.sqlite` + `yjs/<room>.yupdate` + `assets/<id>`. Verify the manifest before upload and after download.

### Local host backups

- Least fragile for non-expert operators: **bind-mount a host folder** into the container (`./backups:/backups`) and let the in-app scheduler write there. Same code path on Windows (Docker Desktop, WSL2 9p mounts are fine for sequential writes) and Linux (set `user:` in compose so files are not root-owned).
- Host-side schedulers stay optional: `schtasks /sc minute /mo N` or a systemd timer (`Persistent=true` runs missed jobs) calling `POST /api/backup/run` with a token. Windows trap: Docker Desktop needs an interactive session, so a task running as SYSTEM with nobody logged in fails.
- Cold volume copies (`docker run --rm -v btct-data:/data:ro ... tar`) are only safe with the app stopped; keep them for migrations.
- Retention: restic-style keep-last N plus hourly/daily/weekly buckets, applied identically to the local folder and to OneDrive.

### Google Docs-style history

- What makes it feel like Google Docs: a day-grouped sidebar whose entries expand into minute-level versions, per-collaborator coloured "Show changes", named versions (Google caps at 40) that never get merged away plus a named-only filter, **non-destructive restore** (restoring creates a new version, later versions stay), "see new changes since you last looked", and history visible to editors only.
- Everyone else converges on the same mechanism: a full checkpoint on a time window (Notion: every 10 minutes while editing plus 2 minutes after the last edit; Outline: at least every 5 minutes; HackMD: 10 minutes; AFFiNE: 10 minutes) attributed to the set of users who edited in that window, dedupe when nothing changed, named checkpoints exempt from collapsing, restore as a forward edit.
- **Yjs gives this almost for free, on one condition.** `Y.snapshot(doc)` is a few KB pointer (state vector + delete set), `Y.createDocFromSnapshot` rebuilds any past state, `Y.PermanentUserData` maps client ids to account ids so attribution survives reconnects, and y-prosemirror's `ySyncPlugin` renders a diff between two snapshots with per-user colours when given `{ snapshot, prevSnapshot }` meta. The condition: the doc being snapshotted must have **GC off**, and a GC-off doc keeps every tombstone forever (reports of 5 MB docs for 75 KB of text; an 8.8x size difference measured on a 260k-edit trace).
- Therefore: keep the live page docs GC-on and fast, and maintain a server-side **GC-off "history twin"** per page fed by the same updates. Snapshots are taken against the twin. When a twin passes a size threshold, close the epoch (archive its bytes plus its versions) and start a fresh twin. Restore is a **forward edit**: build the old content from the snapshot, convert to a ProseMirror node, dispatch one transaction in the live editor (y-prosemirror's `updateYFragment` turns that into a minimal CRDT delta, which also satisfies invariant #3b), and record a `restore` version.

---

## 3. Design decisions (assumed by the tasks)

| # | Decision | Alternatives considered |
|---|---|---|
| D1 | One server-side scheduler module with no-overlap runs, drift correction, persisted last-run, and a global pause that honours `Retry-After` | `setInterval` (drifts, overlaps); `croner` (fine, but a dependency for "every N seconds" is optional) |
| D2 | Backup engine = `VACUUM INTO` + y-leveldb doc export + asset copy + manifest, with two interchangeable targets (local folder, OneDrive) behind one writer interface | Raw volume copy (unsafe live); per-workspace browser export (incomplete) |
| D3 | Two cadences: change-driven incremental (per-doc `.yupdate`, SQLite on `data_version` change, assets once) with a quiet period in **seconds**, and a periodic full archive in **minutes** | One fixed timer (re-ships everything, throttled by OneDrive) |
| D4 | OneDrive auth = device code flow, AppFolder scope by default, refresh token AES-256-GCM encrypted with a key derived from `AUTH_SECRET` | Auth-code + PKCE (needs https redirect); MSAL/Graph SDK (unneeded weight) |
| D5 | Local target = bind-mounted host folder written by the in-app scheduler; host-side Task Scheduler / systemd are documented extras hitting `POST /api/backup/run` | Host-only scripts (two code paths, Windows-only today) |
| D6 | Page versions move **out of the shared CRDT** into server storage: a SQLite `page_versions` index plus files under `/data/history/<pageId>/` (twin epochs). Metadata only is mirrored into the shared doc for live UI updates (the cmdlog pattern) | Keep base64 snapshots in the CRDT (broadcast to every client, unbounded growth) |
| D7 | Live docs stay GC-on; a GC-off history twin per page lives on the server, persisted as whole-state files (not in y-leveldb, whose compaction runs through a GC-on doc and would drop tombstones) | GC off everywhere (unbounded growth in every client's IndexedDB) |
| D8 | Attribution via `Y.PermanentUserData` keyed by account id, set by the client after sync and passed to the collab plugin as `ySyncOpts.permanentUserData` | Awareness-only (lost on reconnect); server-side guessing from connection ownership (wrong with two tabs) |
| D9 | Restore is a forward edit that records a `restore` version; nothing in history is ever rewound | Rewinding the CRDT (destroys later versions, cannot merge with concurrent edits) |
| D10 | Theme precedence is a pure function: admin lock wins when enabled, otherwise user prefs over admin defaults over built-ins. New CSS variables for heading colours; applied live through the existing `apply*` pattern (no editor rebuild, invariant #3) | Per-user stylesheets; inline styles on headings |
| D11 | "Config file per user" = the existing server-stored per-account `prefs`, extended with theme keys and given JSON export/import (so a user can keep a file). A literal file on the server per user would not survive the multi-browser, multi-device reality of a web app | Literal `users/<name>.json` on disk |
| D12 | Public settings (theme, lock) are pushed live to clients by the server writing a `settingsPublic` map into the shared doc (metadata only, LWW JSON, like `commandLogs`) with REST seed on load | Polling `/api/settings`; reload-only (today) |
| D13 | The "server is dumb about domain data" invariant (#4) gains two named exceptions: `backup.mjs` (moves bytes, knows nothing about meaning) and `history.mjs` (knows page ids and snapshots, never page semantics) | Doing history client-side only (cannot capture when no browser is open) |

---

## 4. Epics and tasks

Dependencies reference task ids. "Touches" lists the main files; every server file added must also be added to the Dockerfile `COPY` list and every route/env/shortcut to README + CLAUDE.md (repo rule).

### Epic 0: Foundations (shared by everything below)

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| F-01 | **Scheduler module.** `createJob({ name, intervalMs, minIntervalMs, run })`: `while (enabled) { await runOnce(); await sleep(untilNext) }` so runs never overlap; drift-corrected against a target timeline; jitter on retries; status object `{ enabled, running, lastRunAt, lastSuccessAt, lastDurationMs, lastError, nextRunAt }`; `lastRunAt` persisted in `settings` so an overdue job fires right after a restart; a global `pauseUntil` that any job can set (used for `Retry-After`). Pure timing math in a separately testable function | M | none | `server/scheduler.mjs` (new), `Dockerfile` | Unit tests for next-run math, overlap protection, and pause; `bun build` sanity check passes |
| F-02 | **Secrets at rest.** `server/secrets.mjs`: AES-256-GCM with a key derived from `AUTH_SECRET` via HKDF; `getSecret(key)` / `setSecret(key, value)` over `settings` with an `enc:` prefix; startup warning if `AUTH_SECRET` is the ephemeral random one (secrets would not survive a restart). Optionally migrate `anthropic_api_key` on first read | S | none | `server/secrets.mjs` (new), `server/db.mjs`, `Dockerfile` | Round-trip test; a changed `AUTH_SECRET` yields a clear "re-enter credentials" error, not a crash |
| F-03 | **Settings registry.** `server/settings-schema.mjs` with typed defaults, validators, and the list of keys that are public (returned by `GET /api/settings`) vs admin-only vs secret. Refactor existing `theme_color`, AI, MCP, cmdlog keys onto it without behaviour change | M | none | `server/settings-schema.mjs` (new), `server/index.mjs`, `server/ai.mjs`, `server/mcp.mjs`, `server/cmdlog.mjs` | All existing admin panel flows unchanged; unknown keys rejected with 400 |
| F-04 | **Data export primitives.** `server/data-export.mjs`: `exportSqlite(dir)` via `VACUUM INTO` to a temp file then atomic rename; `listDocs()` / `getDocStateVectors()` / `exportDoc(name)` via the y-leveldb instance (`getPersistence()` from y-websocket utils, same CJS require as invariant #6); `listAssets()`; `dataVersion()` from `PRAGMA data_version` | M | none | `server/data-export.mjs` (new), `Dockerfile` | Exported SQLite opens cleanly and has every table; every room in LevelDB is exported; runs while clients are editing without blocking them |
| F-05 | **Live public settings channel.** Server writes the public settings subset into a `settingsPublic` Y.Map in the shared doc (via `server/yjs-data.mjs`, LWW JSON, no Y.Text), clients observe it (`shared-bindings.ts`) after a REST seed (`theme-store.ts`) | S | F-03 | `server/yjs-data.mjs`, `src/realtime/shared-doc.ts`, `src/stores/shared-bindings.ts`, `src/stores/theme-store.ts` | Changing `theme_color` in one browser recolours every connected client without reload |
| F-06 | **Health check with dependencies.** `/healthz` reports SQLite writable, LevelDB open, free disk under `/data`, and (later) last backup status. Keep the unauthenticated `{ ok }` shape, add a `details` object behind admin auth | S | none | `server/index.mjs` | Compose healthcheck still passes; corrupt DB flips `ok` to false |

### Epic A: Backup engine and local target

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| A-01 | **Archive format and manifest.** `docs/backup-format.md` + `server/backup.mjs`: layout `manifest.json`, `sqlite/data.sqlite`, `yjs/<room>.yupdate`, `assets/<id>`; manifest carries schemaVersion, instanceId (generated once, stored in `settings`), createdAt, includes, sha256 per file, per-doc state vectors, `data_version`. Packaging as `.tar.gz` (streaming `tar` package) with `verifyArchive()` that re-hashes every entry | M | F-04 | `server/backup.mjs` (new), `docs/backup-format.md` (new), `Dockerfile` | A 200 MB synthetic `/data` archives without loading it into memory; `verifyArchive` detects a flipped byte |
| A-02 | **Selection model.** `backup_includes` setting: `{ sqlite, yjsShared, yjsPages, assets }` booleans in v1; the page-doc set can optionally be filtered by workspace (the server maps page rooms to workspaces through the shared doc's `pages` table via `getYDoc('btct-shared')`). Warn in the UI that excluding SQLite loses users/settings and excluding the shared doc loses all metadata | S | A-01 | `server/backup.mjs`, `server/settings-schema.mjs` | Manifest `includes` matches the selection; restore refuses partial archives unless `--partial` |
| A-03 | **Target interface + local target.** `Target = { put(path, stream, meta), list(prefix), delete(path), stat() }`. `LocalTarget(BACKUP_DIR)` writes to a temp name then renames (atomic), checks free space first, records bytes written. Compose gains `BACKUP_DIR=/backups` and a bind mount `./backups:/backups`; docs cover Windows (`C:/btct/backups` or relative path, Docker Desktop file sharing) and Linux (`user:` in compose) | M | A-01 | `server/backup-targets.mjs` (new), `docker-compose.yml`, `Dockerfile`, `README.md` | Fresh clone on Windows and on Linux produces a readable archive in `./backups` with one `docker compose up` |
| A-04 | **Retention policy.** Pure function: keep-last N plus hourly/daily/weekly buckets (a snapshot survives if any rule keeps it); applied to any target's `list()`. Separate policies for full archives and for the `live/` incremental set (live set keeps only the latest per object) | S | A-03 | `server/backup-retention.mjs` (new), tests | Property-style tests against generated timestamp sets; never deletes the newest archive |
| A-05 | **Full-archive job.** Scheduler job `backup.full` with `backup_full_interval_min` (floor 1 min local), `backup_full_enabled`; writes to every enabled target; `POST /api/backup/run` (admin, `{ target?, kind: 'full' \| 'live' }`) and `GET /api/backup/status` (per target: last/next run, bytes, error, retention counts). A dedicated `backup_token` (MCP-token pattern) so host schedulers can call run without an admin session | M | F-01, A-03, A-04 | `server/backup.mjs`, `server/index.mjs`, `README.md` (API table) | A scheduled archive appears on time; a second run cannot overlap; status is accurate after a restart |
| A-06 | **Change-driven live mode.** Dirty tracking: `doc.on('update')` on every relay doc (y-websocket `docs` map) marks the room dirty; SQLite dirty when `data_version` changes; assets dirty on upload. Job `backup.live` with `backup_live_quiet_sec` (default 5) and `backup_live_max_latency_sec` (default 30, floor 10 local): writes only dirty objects to `live/docs/<room>.yupdate`, `live/data.sqlite`, `live/assets/<id>` (once, ledger in SQLite). This is the "every N seconds" control | L | A-05 | `server/backup.mjs`, `server/db.mjs` (asset ledger table) | Editing one page uploads one file; idle server uploads nothing; a cold page edited via MCP is still captured |
| A-07 | **Restore tooling.** `server/restore.mjs` CLI run in the same image (`docker compose run --rm btct bun server/restore.mjs <archive> [--yes] [--partial]`): refuses to run while the app is up (lock file / port probe), verifies manifest, moves `/data` aside, writes SQLite (deletes stray `-wal`/`-shm`), rebuilds LevelDB through `storeUpdate` per `.yupdate`, copies assets, prints a summary. Also a "restore from live set" mode that assembles the latest full + live objects. Retire or rewrite `Backup-BTCT.ps1`/`Restore-BTCT.ps1` to call the new endpoints/CLI | L | A-05 | `server/restore.mjs` (new), `Backup-BTCT.ps1`, `Restore-BTCT.ps1`, `README.md` | Round trip: archive, wipe volume, restore, `/healthz` ok, every page opens with its content, users can log in |
| A-08 | **Host-side scheduler recipes (optional path).** Documented `schtasks` command and a systemd `.timer`/`.service` pair calling `POST /api/backup/run` with the backup token; note the Docker Desktop interactive-session trap on Windows | S | A-05 | `README.md`, `docs/` | Copy-paste works on both platforms |

### Epic B: OneDrive target

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| B-01 | **Entra app registration guide.** Step-by-step for the admin: new registration, audience (personal vs any), "Allow public client flows" = Yes, no redirect URI, copy the Application (client) ID; which scope to grant. The client id is entered in the admin UI and stored in `settings` (not a secret) | S | none | `README.md`, `docs/onedrive-setup.md` (new) | A non-developer can complete it in under 10 minutes |
| B-02 | **Device-code auth.** `server/onedrive-auth.mjs`: `POST /api/backup/onedrive/connect` returns `{ userCode, verificationUri, expiresIn }` and starts server-side polling of `/oauth2/v2.0/token` at the returned interval; on success stores the refresh token via F-02 and the account display name; `GET .../status` (`disconnected \| pending \| connected \| reconnectRequired`); `POST .../disconnect` wipes the token. Silent refresh with rotation (store the new token, discard the old); `invalid_grant` flips to `reconnectRequired`. Tenant `/consumers` for personal, `/common` otherwise; scope default `Files.ReadWrite.AppFolder offline_access`, opt-in `Files.ReadWrite` | M | F-02, F-03 | `server/onedrive-auth.mjs` (new), `server/index.mjs`, `Dockerfile` | Connect, restart the container, next upload still works; revoking the app in the Microsoft account surfaces `reconnectRequired` within one run |
| B-03 | **Graph client.** `server/onedrive.mjs`: `approot` addressing only, `<instanceId>/` prefix, small `PUT ...:/content` under 10 MiB, `createUploadSession` above with 5 to 10 MiB chunks in 320 KiB multiples and `conflictBehavior: replace`, `children` listing with paging, `DELETE`; concurrency 1; on 429/503 read `Retry-After`, set the scheduler's global pause, exponential backoff with jitter; `User-Agent: NONISV|BTCT|btct/<version>`; never upload zero-byte files (OneDrive rejects them) | M | B-02 | `server/onedrive.mjs` (new), `Dockerfile` | 15 MB file uploads via a session and verifies by size + sha (Graph returns `file.hashes` on personal accounts); a forced 429 pauses every job |
| B-04 | **OneDrive target.** Implements the A-03 interface on top of B-03: full archives under `full/`, live objects under `live/`, retention via listing; `backup_onedrive_enabled`, independent interval and quiet-period settings with cloud floors (live quiet 30 s min, default 60 s; full 15 min min) | M | A-03, A-04, B-03 | `server/backup-targets.mjs` | Same archive lands locally and in OneDrive; retention prunes both identically |
| B-05 | **Admin UI: Backups section.** New section in `AdminPanel.tsx` (reuse the `McpConfigSection` patterns): OneDrive connect card (code + link + pending spinner, account name, disconnect, scope toggle), include checkboxes (A-02), full interval (minutes) and live quiet period (seconds) per target with the floors shown, retention fields, last/next run and last error per target, Run now (full / live), backup token reveal/regenerate, link to restore docs | L | A-05, B-04 | `src/components/sidebar/AdminPanel.tsx`, `src/auth/auth-store.ts` (API helpers) | Every setting round-trips; validation errors show inline; status refreshes on a timer while the panel is open |
| B-06 | **Failure surfacing.** Persistent error banner for admins when a target has failed more than N consecutive runs; `/healthz` details include backup state (F-06); server log lines are structured (`[backup] target=onedrive kind=live bytes=... ms=...`) | S | B-05 | `server/backup.mjs`, `LeftSidebar.tsx` or a toast | A disconnected OneDrive is visible without opening the panel |

### Epic D: Per-user history and rollback (Google Docs style)

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| D-01 | **Version store.** SQLite table `page_versions(id, page_id, workspace_id, epoch, created_at, trigger 'auto'\|'named'\|'restore'\|'import', name, created_by, changed_by JSON, snapshot BLOB, twin_bytes INTEGER)` with idempotent migration (invariant #5). Twin epochs as files `/data/history/<pageId>/epoch-<n>.ydoc` written atomically. Metadata-only mirror `pageVersionsIndex` map in the shared doc for live UI (no bytes, LWW JSON, bounded per page) | M | none | `server/db.mjs`, `server/history.mjs` (new), `server/yjs-data.mjs`, `src/realtime/shared-doc.ts`, `Dockerfile` | Versions survive restarts; the shared doc never carries snapshot bytes again |
| D-02 | **History twin.** `server/history.mjs` keeps a GC-off `Y.Doc` per open page room, fed by `doc.on('update')` from the relay doc, seeded from the twin file (or from the relay doc's current state if no twin exists yet); debounced whole-state flush to the epoch file; epoch rollover when the twin exceeds `history_twin_max_bytes` (default 8 MB): archive current file + mark versions with the epoch, start a fresh GC-off twin from current state. Pages edited server-side (AI, MCP) are covered because they go through the same relay doc | L | D-01 | `server/history.mjs`, `server/index.mjs` (hook into the upgrade handler / docs map) | Delete a paragraph, reload server, the twin still contains the deleted text; rollover produces a restorable old epoch |
| D-03 | **Attribution.** Client: after `whenSynced`, `new Y.PermanentUserData(doc).setUserMapping(doc, doc.clientID, String(user.id))` (re-run on reconnect) in `yjs-providers.ts`; pass `ySyncOpts: { permanentUserData, colors, colorMapping }` through Milkdown's collab `setOptions` in `PageEditor.tsx` (one-time, before the binding connects: invariant #3). Server: `changed_by` between consecutive snapshots computed from item visibility + `getUserByClientId` / `getUserByDeletedId` | M | D-02 | `src/realtime/yjs-providers.ts`, `src/components/editor/PageEditor.tsx`, `server/history.mjs` | Two users editing one page produce a version whose `changed_by` lists both; a reconnected tab still attributes to the same account |
| D-04 | **Version policy job.** Scheduler job: for each dirty page, create an auto version when 2 minutes passed since the last update, or when 10 minutes passed since the last auto version during continuous editing (Notion's rule); skip if `Y.equalSnapshots` with the previous; named versions via `POST /api/pages/:id/versions { name }`; `restore` versions from D-07. Collapsing: keep everything 24 h, unnamed versions thinned to hourly for 30 days and daily after, named never; `history_retention_*` settings. Migration: import existing `pageSnapshots` rows as `trigger: 'import'` versions holding full-state bytes, then stop writing the CRDT table | L | F-01, D-02, D-03 | `server/history.mjs`, `src/realtime/page-snapshots.ts`, `src/db/page-snapshot-repo.ts` | Continuous typing for 35 minutes yields about 4 auto versions; an untouched page yields none; named versions survive thinning |
| D-05 | **Read API.** `GET /api/pages/:id/versions?user=&named=1&cursor=` (newest first, paged), `GET /api/pages/:id/versions/:vid` (snapshot + epoch), `GET /api/pages/:id/history/epoch/:n` (twin bytes, gzip), `DELETE /api/pages/:id/versions/:vid` (admin, or author for named), `POST /api/pages/:id/versions/:vid/copy` (new page from that version, D-07 helper). Any authenticated user may read (all users are editors today; see open question Q6) | M | D-01 | `server/index.mjs`, `server/history.mjs`, `src/auth/auth-store.ts` | Paging and filters covered by tests against a seeded store |
| D-06 | **History tab (viewer).** New `TabKind: 'history'` (touch `types/index.ts`, `SplitContainer.tsx` branch, `TabBar.tsx` icons + pane chip, per the CLAUDE.md recipe). Left: read-only ProseMirror/Milkdown instance bound to a local GC-off doc loaded from the epoch bytes, rendering `{ snapshot, prevSnapshot }` through `ySyncPluginKey` with per-user colours from the twin's `users` map; "Show changes" toggle (prevSnapshot = previous version vs none). Right: day-grouped list with expandable minute-level entries, author dots and names, "Named only" and per-user filters, "Name this version", "Restore", "Make a copy", "Delete". Opens from the Properties panel (`PageHistoryPanel.tsx` becomes the launcher plus the quick "save named version" form) | L | D-05 | `src/components/history/*` (new), `src/types/index.ts`, `src/components/ui/SplitContainer.tsx`, `src/components/ui/TabBar.tsx`, `PageHistoryPanel.tsx`, `index.css` (diff colours) | Selecting a version shows that exact content; Show changes colours insertions/deletions per user; the live editor in the other pane keeps its collab binding |
| D-07 | **Restore as forward edit.** Replace `restoreSnapshot`: `Y.createDocFromSnapshot(twin, snapshot)` then `yXmlFragmentToProseMirrorRootNode` then one ProseMirror transaction replacing the live doc content (the sync plugin's `updateYFragment` emits a minimal delta), then `POST .../versions { trigger: 'restore' }`. "Make a copy" creates a new page from the same node. Confirm dialog explains "everyone sees this; later versions are kept" | M | D-06 | `src/realtime/page-snapshots.ts`, `src/components/history/*` | Restoring an old version while another user types does not drop their cursor or their concurrent edit; the restored state appears as a new version at the top |
| D-08 | **"New since you last looked".** Per-user `last_seen_version` per page (small SQLite table or a `prefs.history.lastSeen` map, capped); the page tab shows a dot and the history tab opens with "changes since your last visit" pre-selected (`prevSnapshot` = the last-seen version) | S | D-06 | `server/db.mjs`, `server/index.mjs`, `src/components/history/*`, `TabBar.tsx` | Reopening a page someone else edited shows the dot; opening history clears it |
| D-09 | **Unified activity timeline (stretch).** Merge `changeLogs` entity events and version events into one per-page and per-workspace "Activity" view with author/target/time filters and server-side paging; optional SQLite archive for change logs beyond the 200 in-memory cap (cmdlog pattern) | M | D-05 | `ChangeLogPanel.tsx`, `server/db.mjs`, `server/index.mjs` | Filtering by a user shows both their renames and their page versions |
| D-10 | **Cleanup and invariants.** Remove the `pageSnapshots` CRDT table after one release of dual-read; update invariant #4b (the "snapshots are the binary exception" sentence goes away) and add: "live docs GC-on, history twin GC-off, twin files never pass through y-leveldb compaction" | S | D-04 | `src/realtime/shared-doc.ts`, `CLAUDE.md`, `README.md` | `grep pageSnapshots src` returns only the migration shim |

### Epic E: Per-user config (heading colours and more)

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| E-01 | **Prefs schema.** `EditorPrefs.theme = { headingColor?: hex, headings?: { h1?..h6?: hex }, darkMode?: 'dark' \| 'light' \| 'system' }`; defaults, `resolvePrefs` validation, server validator in `POST /api/me/profile` (hex check, drop unknown keys), types | S | none | `src/lib/editor-prefs.ts`, `server/index.mjs`, `src/types/index.ts` | Malformed values are dropped, not persisted; existing prefs untouched |
| E-02 | **CSS variables and apply function.** `--heading-color` and `--heading-1..6` on `:root` (unset by default), heading rules become `color: var(--heading-N, var(--heading-color, inherit))`; `applyHeadingColors(theme)` in `src/lib/theme.ts` next to `applyThemeColor`/`applyCodeAccent`; persist dark mode through the same path (`toggleDarkMode` writes the pref) | S | E-01 | `src/index.css`, `src/lib/theme.ts`, `src/App.tsx`, `src/stores/app-store.ts` | Changing a heading colour recolours open editors instantly with no remount (collab cursors survive) |
| E-03 | **Profile UI.** In `ProfileEditor.tsx`: one "all headings" picker plus an "advanced: per level" disclosure with H1 to H6 pickers, live preview and revert-on-unmount (the existing code-accent pattern), "Reset to default", and a small rendered sample (H1, H2, paragraph) | M | E-02 | `src/components/sidebar/ProfileEditor.tsx` | Save persists; reload applies; Reset clears the keys |
| E-04 | **Config file export/import.** "Export my settings" downloads `btct-prefs-<username>.json` (the resolved prefs); "Import" reads a file, runs it through `resolvePrefs`, shows a diff summary, saves via the normal profile route. This is the concrete "config file per user" | S | E-03 | `ProfileEditor.tsx`, `src/lib/editor-prefs.ts` | A file exported on one machine applies identically on another; a tampered file is rejected field-by-field |

### Epic G: Admin theme hardlock

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| G-01 | **Settings.** `theme_lock_enabled` and `theme_lock` JSON `{ primary, headingColor, headings?, codeAccent?, darkMode? }` in the registry (F-03), public subset exposed by `GET /api/settings`, admin route `POST /api/settings/theme-lock` | S | F-03 | `server/settings-schema.mjs`, `server/index.mjs` | Invalid colours rejected; `GET /api/settings` shows the lock to the login screen |
| G-02 | **Precedence function.** `resolveEffectiveTheme(builtins, adminDefaults, userPrefs, lock)` (pure, tested): lock enabled means lock values win for every key it sets; otherwise user prefs win over admin defaults. All `apply*` calls go through it from one place in `App.tsx` | S | E-02, G-01 | `src/lib/theme.ts`, `src/App.tsx`, tests | Table-driven tests for every combination |
| G-03 | **Live enforcement.** Lock changes ride the `settingsPublic` channel (F-05) so every client re-resolves immediately; while locked, user theme controls in `ProfileEditor` are disabled with "Locked by your admin" and their stored prefs are kept (restored when unlocked). Server still accepts prefs writes so nothing is lost | S | F-05, G-02 | `src/stores/theme-store.ts`, `ProfileEditor.tsx` | Toggling the lock recolours all open clients within a second; unlocking restores each user's own colours |
| G-04 | **Admin UI: Theme section.** Move `ThemePicker` into a "Theme" section of the Admin Panel: accent presets (existing), heading colours, dark/light default, "Hardlock for everyone" toggle with a preview and a warning; keep the sidebar button as a shortcut to that section | M | G-03 | `AdminPanel.tsx`, `ThemePicker.tsx`, `LeftSidebar.tsx` | Non-admins never see theme policy controls; admins see lock state at a glance |

### Epic H: Docs, tests, release

| Id | Task | Size | Depends on | Touches | Acceptance |
|---|---|---|---|---|---|
| H-01 | README + CLAUDE.md sync for every route, env var (`BACKUP_DIR`), compose change, Dockerfile `COPY` line, shortcut, and new invariants ("never copy live SQLite/LevelDB", "secrets through `secrets.mjs`", GC twin rule, precedence function) | M | each epic | `README.md`, `CLAUDE.md` | the em-dash grep from CLAUDE.md returns 0; API table matches `index.mjs` |
| H-02 | Tests for every pure module: scheduler math, retention, manifest verify, selection, precedence, version thinning, `changed_by` computation (Yjs in jsdom like `code-fence-rule.test.ts`) | M | each epic | `src/test/*` | Added to the baseline count; no new failures |
| H-03 | Upgrade notes: take a cold backup before upgrading (the new restore CLI can read it), snapshot migration is automatic, `AUTH_SECRET` must be stable from now on | S | A-07, D-04 | `README.md`, `docs/` | A reader can upgrade and roll back |

---

## 5. Suggested order and milestones

The request listed OneDrive first, but OneDrive is a *target* for a backup engine that does not exist yet, and the theming work is small and independent. Recommended sequence:

| Milestone | Tasks | Rough size | Outcome |
|---|---|---|---|
| M1: Foundations + local backups | F-01, F-02, F-03, F-04, F-06, A-01 to A-05, A-07 | about 8 to 10 days | Scheduled, verified, restorable archives in a host folder on Windows and Linux; "run now" endpoint |
| M2: Theming | F-05, E-01 to E-04, G-01 to G-04 | about 4 to 5 days | Per-user heading colours with export/import; admin hardlock applied live |
| M3: OneDrive + live mode | B-01 to B-06, A-06, A-08 | about 7 to 9 days | Change-driven uploads every N seconds, full archives every N minutes, retention, reconnect handling |
| M4: History | D-01 to D-08, then D-09, D-10 | about 12 to 15 days | Google Docs-style history tab with per-user coloured diffs, named versions, non-destructive restore |
| H: Docs/tests | H-01 to H-03 | folded into each milestone | |

M2 can run in parallel with M1 (no shared files except the settings registry F-03). M4 is the largest and riskiest piece; it should not start until M1's scheduler and storage conventions are settled, because the version job and twin flush reuse them.

---

## 6. Open questions (answers change the tasks)

| # | Question | Default assumed above |
|---|---|---|
| Q1 | Interval floors: is a 30 s floor for OneDrive live uploads (default 60 s) and 10 s locally acceptable? Anything faster is change-driven anyway, so "seconds" means the quiet period after an edit, not a fixed tick | Yes |
| Q2 | Which OneDrive account: personal, or work/school (Microsoft 365)? Personal works with `/consumers` and the AppFolder scope; a work tenant may need an admin to consent and may need `Files.ReadWrite` | Personal |
| Q3 | Selection granularity: categories only (SQLite / shared doc / page docs / assets) in v1, with per-workspace filtering later? | Categories in v1 |
| Q4 | "Local backups for Windows and Linux": the host that runs Docker (bind-mounted folder, recommended), or each operator's own machine (would need a per-operator agent like `cmdlog-agent`)? | Docker host |
| Q5 | "Config file per user": server-stored prefs plus JSON export/import (D11), or a literal file the server reads from disk per user? | Prefs + export/import |
| Q6 | Who can see history and who can delete versions? Today every account is an editor; there are no roles. Proposal: everyone reads, author or admin deletes named versions, admin only for the rest | As proposed |
| Q7 | Retention defaults: versions (24 h all, hourly for 30 d, daily after), twin epoch threshold 8 MB, backups keep-last 10 + 24 hourly + 30 daily + 12 weekly? | As listed |
| Q8 | Should the hardlock cover dark/light mode and the code accent too, or only the accent and heading colours? | Accent + headings; dark mode and code accent optional keys |
| Q9 | Should the old per-workspace Export / Import dialog stay as-is, or be reworked to download a full-instance archive from the new engine (admin) plus the existing per-workspace export (everyone)? | Keep, add an admin "download full backup" button later |

---

### Answers (2026-08-22)

- Q1: floors accepted (30 s OneDrive live, 10 s local; full archives 1 min local / 15 min OneDrive).
- Q2: personal Microsoft account (`/consumers` tenant, `Files.ReadWrite.AppFolder`; the work/school toggle ships untested).
- Q3: categories only in v1.
- Q4: the Docker host folder (bind mount).
- Q5: server-stored prefs plus JSON export/import.
- Q6: everyone views history; a named version is deletable by its author or an admin, auto versions only by an admin.
- Q7: **keep everything, never thin.** A-04 and the thinning half of D-04 shrink to a manual "delete" action plus a disk-usage readout; no automatic deletion anywhere. The twin epoch rollover (D-02) stays, it is about size, not retention.
- Q8: the lock covers the accent and the heading colours only; dark/light mode and the code accent stay per user.
- Q9: keep the per-workspace Export / Import dialog; an admin "download full backup" arrives with Epic A.
- Order: Epics E and G first (theming), then A (local backups), then B (OneDrive), then D (history).


## 7. Risks

- **GC-off growth.** The twin keeps every tombstone; epoch rollover (D-02) bounds it but adds a second store to back up and restore (A-01 must include `/data/history`).
- **Invariant #4 erosion.** Two more server modules touch domain concepts. Keep them to ids and bytes; no page semantics on the server.
- **OneDrive throttling and token revocation.** Mitigated by concurrency 1, global Retry-After pause, reconnect state, and the change-driven cadence; still expect occasional 429s in the wild.
- **`AUTH_SECRET` rotation** breaks encrypted secrets (F-02); document it and warn at startup.
- **Windows scheduled tasks** with Docker Desktop need an interactive session; the in-app scheduler avoids this, host jobs are optional.
- **Snapshot migration.** Existing `pageSnapshots` are full-state bytes, not Yjs snapshots; they import as `trigger: 'import'` versions restorable the old way, without per-user diffs.
- **Two editors per page in the History tab** must never share or remount the live editor (invariant #3); the viewer gets its own GC-off doc and its own ProseMirror instance.

---

## 8. Sources

OneDrive / Graph: https://learn.microsoft.com/en-us/entra/identity-platform/reply-url , https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code , https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens , https://learn.microsoft.com/en-us/graph/onedrive-sharepoint-appfolder , https://learn.microsoft.com/en-us/graph/api/driveitem-put-content , https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession , https://learn.microsoft.com/en-us/graph/throttling , https://learn.microsoft.com/en-us/answers/questions/1840991/appfolder-is-named-graph , https://forum.duplicati.com/t/onedrive-throttling/15051 , https://rclone.org/onedrive/ , https://github.com/remotely-save/remotely-save/blob/master/docs/remote_services/onedrive/README.md

Consistent capture: https://www.sqlite.org/howtocorrupt.html , https://sqlite.org/lang_vacuum.html , https://bun.com/docs/api/sqlite , https://github.com/yjs/y-leveldb , https://docs.yjs.dev/api/document-updates , https://github.com/google/leveldb/blob/main/doc/impl.md , https://litestream.io/how-it-works/

Local backups and scheduling: https://docs.docker.com/engine/storage/bind-mounts/ , https://docs.docker.com/desktop/features/wsl/best-practices/ , https://github.com/docker/for-win/issues/13790 , https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create , https://man7.org/linux/man-pages/man5/systemd.timer.5.html , https://restic.readthedocs.io/en/latest/060_forget.html , https://github.com/Hexagon/croner , https://github.com/nodejs/node/issues/21822

History: https://support.google.com/docs/answer/190843 , https://workspaceupdates.googleblog.com/2021/05/view-more-context-on-google-docs-edits-with-show-editors.html , https://www.notion.com/help/duplicate-delete-and-restore-content , https://docs.getoutline.com/s/guide/doc/revision-history-AiL6p22Ssq , https://github.com/outline/outline/blob/main/server/queues/processors/RevisionsProcessor.ts , https://github.com/toeverything/AFFiNE/blob/canary/packages/backend/server/schema.prisma , https://github.com/yjs/yjs/blob/main/src/utils/Snapshot.js , https://unpkg.com/yjs@13.6.27/src/utils/PermanentUserData.js , https://unpkg.com/y-prosemirror@1.3.7/src/plugins/sync-plugin.js , https://github.com/yjs/yjs-demos/blob/main/prosemirror-versions/prosemirror-versions.js , https://www.palanikannan.com/blogs/yjs-snapshots-part-5-production , https://github.com/Deln0r/ygo , https://tiptap.dev/docs/collaboration/documents/snapshot , https://tiptap.dev/docs/collaboration/documents/snapshot-compare , https://liveblocks.io/docs/guides/how-to-add-version-history-to-your-app
