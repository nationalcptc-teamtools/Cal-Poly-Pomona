# Competition hardening plan

Date: 2026-10-11. Branch: `lw-version`. Status: plan for review, nothing implemented.

The target is the competition build: `ENABLE_TYPST=0`, `--build-arg WITH_REPORT_BINS=0`, a 1 GB / 2 CPU container, 4 to 6 operators for 8 hours, 300+ pages, 500+ pasted screenshots, the command-log agent posting from every Kali box. The question for every item is whether it can take the server down, corrupt the team's notes, or make the app slower the longer the engagement runs.

Each finding carries how sure we are:
- **Verified**: read and confirmed in today's code while writing this plan.
- **Measured**: a probe reproduced it (scratchpad scripts, Bun 1.3.11; the image ships 1.3.14, so re-run them there).
- **Reported**: found by a code survey, not yet re-checked.

## Step 0: measure the build we will actually run

The preview on `127.0.0.1:8081` runs with `ENABLE_TYPST=1` (peak RSS 568 MB, 313 MB idle), so it is not the competition build. Before fixing anything:

1. Rebuild the preview with the flag off and `WITH_REPORT_BINS=0`. Record image size, idle RSS and `VmHWM` from `/proc/<pid>/status`.
2. Seed a competition-sized workspace: 300 pages (nested, several "Untitled", long and emoji titles), 500 screenshots with a mix of blur and crop, 5000 command-log rows.
3. Run a one-hour soak with six synthetic editors (Bun `y-websocket` clients typing into pages and saving records at the editor's 2 s / 10 s cadence) and record each minute: server RSS, event-loop lag (a ping round trip on a seventh socket), `du -sh /data/yjs`, `/data/history` and `/data/assets`.
4. Keep the numbers in this file. Every fix below is re-measured against them.

## Step 1: things that can crash the server or corrupt notes (fix before the competition)

| id | where | what happens | sure | fix | proof |
|---|---|---|---|---|---|
| S1 | `server/` has no `process.on` handler; y-websocket `bindState` has no catch | Disk fills, a room with over 500 stored updates opens, y-leveldb returns `null`, `encodeStateAsUpdate(null)` throws as an unhandled rejection and Bun exits. Docker restarts it, the first client reopens `btct-shared`, and it crashes again in a loop. | Verified (no handlers), Measured (Bun exits) | Log-and-continue handlers for `unhandledRejection` and `uncaughtException`; wrap persistence with a null check | 5 MB tmpfs on `/data/yjs`, edit until full, restart |
| S2 | `server/assets.mjs:263` | `createReadStream(file).pipe(res)` has no error listener. The file vanishing between `stat` and open (retention deleting a retired image while History shows it), or EMFILE, exits the process. | Verified, Measured | `stream.pipeline(src, res, cb)` | Delete the blob between stat and open in a probe |
| S8 | `server/history.mjs:114` | A corrupt history twin file throws inside the websocket `connection` handler and kills the process when that page opens. | Reported | try/catch around `trackPageDoc` | Write garbage to one `.ydoc`, open the page |
| C1 | `PageEditor.tsx:424,461-463` | A page this browser never cached is opened while the server is slow for more than 3 s (a backup running, a restart). The 3 s fallback fires, the fragment is empty, the editor seeds it from markdown, then the server's copy merges in: the body is duplicated for the whole team. | Verified | Seed only after the provider reports `synced`; if the timer fired, bind without seeding and seed on the first `sync` only if still empty | vitest with a provider that syncs at 4 s; live: `docker pause` 5 s while opening a cold page |
| C6 | `note-image-paste.ts:135-142` | Cutting an image and pasting it back (or restoring an older version) retires an asset that is still in a note, and nothing un-retires it. With retention on, its bytes are later deleted. | Verified | Un-retire when an `asset_image` with that id is inserted | vitest with a cut-then-paste transaction pair |
| C3 | no error boundary anywhere in `src/` | One page that throws while rendering blanks the whole app, and the saved tabs replay it on reload. After a redeploy, an old lazy chunk 404s into `index.html` with the same result. | Verified | A boundary per pane (reload or close the tab); reload once on `vite:preloadError` | vitest with a throwing tab; rebuild `dist` mid-session |
| S5, C8 | `App.tsx:355-359`, `shared-doc.ts:104-108` | Right after a restart, a fresh browser can be marked ready before the shared doc arrives, see zero workspaces and write the demo workspace into the team's doc. | Reported | Never auto-seed while a server is configured; open `btct-shared` at boot before `listen` | Restart, connect a clean browser profile at once |
| S3 | Bun's `ws` shim (`index.mjs:918`) | Any websocket message over 16 MiB closes the socket (1006) whatever `maxPayload` says. A 20 MB tool-output paste or a huge nmap import reconnects in a loop and those edits never reach the server. | Measured | Cap a single paste on the client (offer to save large output as a file asset); split nmap imports | 20 MB paste in a browser |
| C5 | `note-image-paste.ts:35-51` | A paste whose upload fails (server restarting, expired token) is swallowed: the screenshot is gone with no message. | Reported | Keep the file, show a retry notice | vitest with a failing upload |
| S9 | `/healthz`, y-leveldb store errors | Disk full turns every store failure into a console warning. Edits live only in memory and `/healthz` still says ok, so a restart loses them. | Reported | Report free space (`fs.statfs`) in `/healthz` and the admin panel; warn under 1 GB | Same tmpfs test as S1 |
| S10 | `docker-compose.yml` | Bun is PID 1 with no SIGTERM handler, so `up -d --build` mid-event waits 10 s then kills it, losing up to 5 s of history. No `mem_limit`, no log rotation, and an unhealthy container is never restarted. | Reported | `init: true`, a SIGTERM handler that flushes twins and LevelDB, `mem_limit`, log `max-size` | `time docker compose stop` (10 s means it was killed) |

## Step 2: things that get slower or bigger over 8 hours

The biggest single source is the markdown copy of every page body kept inside each page record in the shared doc (S4, C9, C10). Every typist's save rebroadcasts the whole body to every client, every client re-derives the whole pages table, and the unmemoized sidebar rescans all pages per item. The preview already shows 41 MB of `/data/yjs` against 276 KB of SQLite.

| id | where | what grows | sure | fix |
|---|---|---|---|---|
| S4 | `database.ts:160`, y-leveldb | Each content save appends the whole record to `btct-shared` updates; LevelDB only compacts when the room opens, and that room never closes. A restart then loads them all at once, a spike of several hundred MB. | Reported | Short term: flush the `btct-shared` document every 15 minutes. Long term: take `content` out of the record. |
| C9 | `PageEditor.tsx:161-171`, `shared-bindings.ts:35`, `LeftSidebar.tsx:507-543` | O(pages²) work on every client per save | Reported | Children-by-parent map and `memo` on tree items; keep `content` out of the store's page list |
| C10 | `shared-doc.ts:321-366` | The title mirror writes back from every client, not only the one typing: N whole-record writes per burst, and a stale write can roll back a content save | Reported | Write back only for local transactions |
| C2 | `src/lib/assets.ts:147`, `AssetsPanel.tsx` | `croppedCache` has no size limit and the Assets tab mounts every card at full size. 500 screenshots can reach 250 to 750 MB of heap and crash a Firefox tab. | Verified (no cap), rest Reported | Byte-capped LRU (about 64 MB), lazy cards, downscaled thumbnails |
| S12, C11 | `changelog-repo.ts`, `app-store.ts:324-352` | Change log is never capped, and each page delete stores the full body | Reported | Cap per workspace like `commandLogs`; store delete snapshots without the body |
| S6 | `backup.mjs` | Each backup copies every asset synchronously (relay stalls for seconds with 500 screenshots, which also triggers C1) and nothing prunes old runs | Reported | Hard-link unchanged assets from the previous run, keep the last N runs, make the copy async |
| S7 | `history.mjs:64-114` | Each edited page re-encodes and synchronously writes its whole twin every 5 s | Reported | Async write and rename, 30 s flush, no twin for export-only opens |
| C13 | y-indexeddb | Every 500 updates the browser re-reads and re-encodes the whole shared doc on the main thread (100 to 400 ms stalls) | Reported | Follows from cutting S4/C9/C11 volume |
| C12 | `ExportDialog.tsx:174-175` | Import awaits one transaction per record, O(n²) on big tables | Reported | Covered by the export spec (batched writes) |

## Step 3: lower priority

- C14: if IndexedDB fails to open, the app shows "Connecting…" forever. Race it against a timeout and run memory-only with a banner.
- C15: any `/api/me` failure, including a network blip during a redeploy, logs the user out, and nothing shows the connection state. Log out only on 401; add a status dot.
- S11: uploads buffer up to 25 MB twice and write synchronously; a full disk leaves an orphan blob.
- S13: the production healthcheck starts a full `bun -e` every 30 s; copy the preview's lighter one.
- Static files are gzip only (open item #36 from 2026-08-28).
- C4, C7 (unsynced export, Firefox download race): covered by the export spec.

## How we check for crashes

Each run happens against the rebuilt competition preview with the seeded workspace, two browsers open (Chrome and Firefox ESR), and the soak script running:

1. **Disk full**: mount a 5 MB tmpfs on `/data/yjs`, edit until it fills, restart. Pass: no crash loop, `/healthz` reports the problem.
2. **Slow server**: `docker pause` for 5 s while a teammate opens a page they never opened before, and again during an export. Pass: no duplicated body, export names the slow pages.
3. **Restart mid-session**: `docker compose restart` with three browsers editing, then connect a fresh browser profile immediately. Pass: no edits lost, no demo workspace appears.
4. **Redeploy mid-session**: rebuild `dist` with tabs open, then open a tab type not yet loaded. Pass: a reload prompt, not a blank app.
5. **Big paste**: 20 MB of tool output into a note. Pass: a clear refusal or a file asset, not a reconnect loop.
6. **Images**: cut an image and paste it back, restore an old version containing an image, paste while the server restarts. Pass: every image still in the Assets Manager, a failed paste says so.
7. **Firefox ESR on Kali**: paste a screenshot taken with an X11 tool, drag-resize at 125% interface zoom, export and download. CSS `zoom` needs Firefox 126 or later, so check the ESR version first.
8. **Soak**: the one-hour, six-editor run. Pass: RSS stays under 600 MB, event-loop lag under 100 ms at the 95th percentile, `/data/yjs` growth recorded and stable after the 15-minute flush.
9. **Hard kill**: `docker kill` the container mid-edit. Pass: nothing lost beyond the 5 s history window.

## Checked and fine

- With the flag off, `server/typst/` and jimp are never imported.
- Malformed websocket frames and TCP resets do not crash the server. JSON bodies are capped (413), and command-log batches are capped at 200 events and 512 KB.
- Every HTTP route is wrapped in a try/catch. Scheduler jobs, twin flushes and auto versions catch their own errors.
- Relay rooms and history twins unload on the last disconnect.
- The login-failure map is pruned. SQLite runs WAL with `synchronous = NORMAL`.
- Page contexts are leased and released with a committed IndexedDB snapshot. The raw-bytes cache is capped at 12.
- No selectorless `useAppStore()` calls. The command-log view renders at most 400 rows.

## Order of work

1. Step 0 baseline.
2. The export spec (`docs/superpowers/specs/2026-10-11-workspace-export-tree-design.md`), since the competition workflow depends on it.
3. Step 1, in table order. Each fix ships with the test or chaos run in its row.
4. Step 2, starting with S4/C9/C10 because it is the largest source of growth.
5. Re-run the full crash checklist and the soak on the final competition image.

If the report build lives on a separate branch, every fix in steps 1 and 2 has to land on both branches. Building both versions from one branch with two compose configs (`ENABLE_TYPST`, `WITH_REPORT_BINS`) avoids that, and keeps the export format identical on both by construction.
