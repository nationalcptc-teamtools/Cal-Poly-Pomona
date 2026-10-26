# Exports stream: workspace archive, command-log export, downloads

Branch `fix/exports`, based on `competition-crash-fixes` (669ed8f). This file lists every change, what a user sees, the new routes, the invariants to add to CLAUDE.md, and the README text that must change. The merge step applies the README and CLAUDE.md edits; nothing in this branch touches either file.

## What changed, for a user

### Full Workspace → ZIP (schema 3)

The ZIP is now one folder named `<workspace>_<YYYY-MM-DD_HHMM>` (local time), and the file is that name plus `.zip`:

```
CPTC Team5_2026-10-12_2248/
├── README.md                      counts, the page tree as links, "original.* is unredacted",
│                                  and, when not empty: Possibly incomplete pages,
│                                  Images that failed to export, Command log, Paths too long
├── notes/
│   ├── Command log.csv            the whole command-log archive of the workspace
│   └── <Title>/<Title>.md         a folder per page, children inside their parent
│       └── <Title>.attachments/NN-<stem>/modified.<ext>, original.<ext>
├── assets/<Assets Manager folders>/<stem>/modified|original.<ext>, <font file>
└── .btct/                         the lossless copy another server imports
    manifest.json (schemaVersion 3), workspace.json, pages.json, changeLogs.json,
    nmapScans.json, nmapMachines.json, pageSnapshots.json, pageYjsUpdates.json,
    assets.json, assetFolders.json, assetFiles.json, commandLogs.json,
    report.typ (when the workspace has one), <retired table>.json (when not empty)
```

- Every page gets its own `.md`; nothing collides any more. Names are NFC, have no control or illegal characters, no Windows device names, no trailing dots or spaces, at most 60 bytes a segment (40 for a picture stem), and are deduplicated per folder ignoring case (`Untitled`, `Untitled-2`). A child page called `Recon.attachments` becomes `Recon.attachments-2`. A page whose parent is missing or part of a loop goes to the top level.
- Note images travel twice: `modified` (crop and blur applied, as the note shows it) and `original` (the upload). Links in the markdown point at `modified`. GIF and SVG keep their original bytes in both. An image whose render fails keeps its `original`, its link stays `asset:<id>`, and it is listed.
- Which assets: every asset a note shows (in its markdown or as an `asset_image` in its body, retired or not), plus every asset that is not retired. Fonts travel as the single file.
- The change log is exported uncapped (it stopped at the newest 5000 before). Snapshots are gathered in one scan instead of one per page.
- The command log is in the archive: `.btct/commandLogs.json` and `notes/Command log.csv`, read uncapped from the server. If the server cannot be read, the live window is exported instead and the status line and README say so.
- Text is DEFLATEd (level 6), PNG/JPEG/GIF/WebP/WOFF are stored. A 300-page workspace came to 815 KB.
- Bodies are read through read-only connections (`?ro=1`) with no IndexedDB and no BroadcastChannel, four at a time, 15 s each. A body that comes back empty while the page's markdown is not is read again after 1 s; if it is still empty, or the server did not answer, the page is listed as possibly incomplete. When the server does not answer, this browser's offline copy is used if it has one (still listed). After four timeouts in a row the reader drops to 2 s a page.
- The status line is honest: `Exported N notes and M images, K command-log entries.` plus, when not zero, incomplete pages (first five named), failed images, image links with no asset, long paths and a partial command log, all repeated in README.md.

### Import

- **Import as new** mints a fresh id for every record: workspace, pages, change log, nmap scans and hosts, snapshots, retired-table rows, asset folders; the server mints one for every uploaded asset. References follow: `parentId`, `targetId` (including the page JSON inside a delete entry's `prevValue`), `scanId`, `linkedNodeId`, `folderId`, retired ids, `asset:<id>` in markdown and `assetId` of every `asset_image` node in a page body and in legacy snapshots. Each body is written to the NEW page's room. Importing next to the original therefore shares nothing with it (before, it moved every page out of the original workspace and both copies edited one body).
- Assets are uploaded four at a time with crop, blurs, size, font family and folder kept and `deletedAt` cleared, so a blur stays removable after import. A file name the server changed (an extension correction, or a clash in replace mode) is listed and rewritten in `report.typ` (`/assets/<old>` to `/assets/<new>`, exact names only, one pass).
- Records are written in shared-doc transactions of about 1 MB of JSON (was one per record: one websocket message and one table reload per record on every client).
- Bodies are written four at a time through leased page contexts. A body counts only when a second, read-only connection sees the server's state vector cover it; the lease is released after that. Pages the server did not confirm within 30 s are named in the status line.
- The command log goes to the server through the new import route (500 rows a request).
- **Replace existing** keeps ids. Records in the workspace that the archive does not have are deleted; every other record is overwritten in place in the same chunked transactions, so a page on both sides never disappears and teammates' tabs stay open. Collaborative texts (titles, names) are set with a minimal splice. Page bodies are CRDT-merged, not reset: text added after the export stays, and the page's History tab rolls a body back. A live page keeps its live markdown mirror for the same reason. Assets and asset folders that the archive does not have are kept, and the status line counts them. The dialog shows this note when Replace is selected.
- A damaged archive is an error that says so (`Invalid workspace zip: the file is damaged or not a ZIP (...)`); a damaged optional part (`pageYjsUpdates.json`, a table, `assetFiles.json`) is imported without it and named in the status line, as is a manifest whose body count disagrees with the archive. A non-BTCT ZIP still says `Import failed: Invalid workspace zip: missing workspace.json`.
- Schema 2 (flat JSON at the top) and schema 1 (`pages/_index.json`, `graphs/<id>/*.json`) archives still import. Schema 2 builds cannot read schema 3: both the competition box and the report box must run this code.

### All Pages → Markdown

Kept (the spec proposed removing it; the task said keep it). It now writes the same collision-free notes tree as the workspace ZIP's `notes/` (`<workspace>_<time>_notes.zip`, text only, image links stay `asset:<id>`), or one `<sanitized title>.md` for a single page.

### Downloads

Every download goes through `src/lib/download.ts` `downloadBlob(data, filename, mime)` (and `downloadText`): the anchor is attached for the click and removed, and the object URL is revoked 60 s later. Used by the workspace export, All Pages → Markdown, the Command Log CSV and JSON, the profile settings export and the Report tab's PDF/SVG/server exports (TypstView's `triggerDownload` now calls it).

### Command Log tab

- When the archive query returns as many rows as it asked for (1000 for the last 24 h, 5000 for the full archive), the header adds `loaded N of M archived (exports read them all)`, and the CSV and JSON buttons read the whole archive through `GET /api/cmdlog/export` and apply the same filters before downloading. If that read fails, the export says it holds only the loaded rows.
- CSV cells that start with `=`, `+`, `-`, `@`, a tab or CR get a leading apostrophe (numbers are left alone, so `-1` stays a number). The CSV ends with a newline.

## New routes

| Method | Route | Auth | What |
|---|---|---|---|
| `GET` | `/api/cmdlog/export?workspaceId=&format=json\|csv\|count` | yes (JWT) | The whole command-log archive of a workspace, oldest first, streamed from a SQLite cursor with backpressure (`Content-Disposition: attachment`). `count` answers `{ total }`. CSV cells get the formula guard. |
| `POST` | `/api/cmdlog/import` | yes (JWT) | `{ workspaceId, logs: [...] }`, at most 1000 rows, 8 MB. Upserts by id in one transaction (SQLite only, not the live CRDT window). A row whose id already belongs to another workspace is stored as `imp-<sha256(workspace, id)>`, so an import next to its original overwrites nothing and a repeated import writes nothing new. Answers `{ imported, remapped, skipped }`. |

Websocket: `/yjs/<room>?token=…&ro=1` marks a read-only reader; the server keeps no history twin for that connection (`trackPageDoc` is skipped). It is a hint, not a permission: a writer that connects later is tracked from the room's state at that moment.

No new env vars, settings or commands. No new server files (the Dockerfile is unchanged).

## Files

- New: `src/lib/download.ts`, `src/lib/export-names.ts`, `src/export/page-body-codec.ts`, `src/export/body-sync.ts`, `src/export/page-bodies.ts`, `src/export/import-workspace.ts`, `src/export/export-workspace.ts`, `src/export/cmdlog-io.ts`, `src/export/pages-markdown.ts`, `scripts/qa-exports-playwright.mjs`.
- Rewritten: `src/export/workspace-zip.ts` (plan, writer, parser), `src/components/ui/ExportDialog.tsx` (buttons and a status line only).
- Changed: `src/export/retired.ts` (pure `remapRetiredRows`), `src/export/index.ts`, `src/lib/assets.ts` (`renderAssetBytes`, `fetchAssetBytesUncached`), `src/lib/cmdlog-filter.ts` (`csvCell` exported, formula guard, trailing newline), `src/components/cmdlog/CommandLogView.tsx`, `src/components/sidebar/ProfileEditor.tsx`, `src/components/typst/TypstView.tsx`, `server/cmdlog.mjs`, `server/index.mjs`.
- Tests: `export-names`, `page-body-codec`, `download`, `body-sync`, `workspace-roundtrip` (real shared doc, export, parse, import new and replace, schema 2 and 1, damaged archives), `live-exports` (skipped unless `BTCT_LIVE_PHASE` is set), `cmdlog-filter` (formula guard), `workspace-zip-report` (manifest path moved to `.btct/`).

## Invariants for CLAUDE.md "Critical invariants" (and README "Conventions & invariants")

- **Every download goes through `downloadBlob` (`src/lib/download.ts`).** Attached anchor, revoke on a 60 s timer, never a synchronous revoke and never a detached click.
- **Every exported file or folder name comes from `src/lib/export-names.ts`.** JSZip silently replaces an entry with the same name, so a name built anywhere else can lose a page.
- **Import as new mints a fresh id for every record and writes each body to the new page's room**, rewriting every reference through one id map (records) plus the server's asset ids (`asset:<id>` in markdown, `asset_image` `assetId` in bodies). A copy must never share a record, a room or an asset with its original.
- **Bulk shared-doc writes go in transactions of about 1 MB of JSON** (`writeChunked` in `src/export/import-workspace.ts`): not one per record (O(n²) reloads on every client), not one per table (the relay closes a websocket message over 16 MiB).
- **Replace-import never deletes a record the archive has.** It overwrites in place and deletes only ids the archive lacks, so tabs on surviving pages stay open; bodies are merged, never cleared.
- **The export reads bodies read-only** (`?ro=1`, no IndexedDB, no BroadcastChannel) and lists every page whose body it could not confirm; it never reports a page as included because a timer fired. The export never goes through `rawBytesCache`/`croppedCache` (`fetchAssetBytesUncached` + `renderAssetBytes`).
- **An imported body counts only when the server's state vector covers it**, checked on a second read-only connection, before the lease is released.
- **CSV cells starting with `= + - @`, tab or CR get a leading apostrophe** on both the client (`csvCell`) and the server (`server/cmdlog.mjs`); keep the two rules identical.

## README sections that must change

1. **Export & import** (README.md:826). Replace:

   > - **Markdown**: per page (single `.md` or a `.zip`).
   > - **Lossless workspace ZIP**: the full workspace (every entity as JSON, plus per-page raw CRDT state and human-readable `.md` companions), with *import-as-new* (re-IDed) or *replace-existing* modes. The workspace's Typst report source, ...

   with:

   > - **All Pages → Markdown**: the notes as a folder tree (a folder per page, children inside their parent, portable names deduplicated per folder), or one `.md` for a single page. Image links stay `asset:<id>`.
   > - **Full Workspace → ZIP** (schema 3): one folder `<workspace>_<YYYY-MM-DD_HHMM>/` holding `README.md`, `notes/<Title>/<Title>.md` with `<Title>.attachments/NN-<stem>/modified.<ext>` and `original.<ext>` (the original is unredacted), `notes/Command log.csv`, `assets/` (images no note shows, and fonts, under their Assets Manager folders) and `.btct/` (every table uncapped, asset records with crop and blur, asset folders, the command log, page bodies, `report.typ`, retired tables). README.md and the status line list pages that may be incomplete, images that failed and paths too long for Windows Explorer.
   > - **Import as new** gives every record, page room and asset a fresh id, so a copy imported next to its original shares nothing with it; images are uploaded with their crop and blur, and the command log is imported into the server's archive. **Replace existing** keeps ids, overwrites records in place and deletes only those the archive lacks (teammates' tabs stay open); page bodies are merged, so text added after the export stays and the History tab rolls a body back; assets and folders not in the archive are kept. Schema 2 and 1 archives still import; older builds cannot read schema 3.
   > - (keep the existing sentences on the report source three-state rule and the retired tables, changing "under the same filenames older builds used" to "under `.btct/`, with the same file names older builds used".)

2. **Command log feature tour** (README.md:237). Replace "**exports the filtered set as CSV or JSON** for the report." with "**exports the filtered set as CSV or JSON** for the report; when the archive holds more rows than the view loaded, the header says `loaded N of M` and the export reads the whole archive. CSV cells that a spreadsheet would run as a formula get a leading apostrophe."

3. **Performance paragraph** (README.md:258). Replace "Exports wait for document state before encoding it." with "Exports read every page body read-only from the server (no IndexedDB, no history twin) four at a time, re-read a body that comes back empty, and list any page they could not confirm."

4. **REST API table** (README.md:1163-1170): add the two rows from "New routes" above, and a note under the websocket row that `?ro=1` skips history tracking.

5. **Retired features** paragraph (README.md:262) is still true; add "(under `.btct/` in schema 3)".

## Verification

- `bunx tsc -b`: clean. `bunx vitest run`: 640 passed, 6 failed, 5 skipped (the 6 are the baseline failures: 5 in `typst-search.test.ts`, 1 in `typst-run-child.test.ts`; the 4 extra skips are the live phases). 41 new tests run by default.
- Live, image `btct-qa:exports` built from this branch with `WITH_REPORT_BINS=0`, server A on 8134 (named volume, so it could be restarted cold), server B on 8144 (tmpfs, `ENABLE_TYPST=1`), both `--memory 1g --cpus 2`, `YPERSISTENCE=/data/yjs`. `src/test/live-exports.test.ts` phases, run with `bunx vitest run` in `oven/bun:1.3.14` with `--network host`:
  - 30 pages, 6 images (one cropped, one blurred, two in a folder), 6000 change-log rows, 6000 command-log rows: seed, `docker restart` A, export from cold rooms in 1.4 s: 0 incomplete pages, every body back with its block and image, 6000 + 6000 rows. `/data/history` file count unchanged and `find -newer` lists 0 twins rewritten by the export (EXP-12).
  - Import into B: 2.4 s, 30 of 30 bodies confirmed, 6 uploads, 6000 command-log rows. Verify from a fresh client: 30 pages with parent links inside the new workspace, every `asset_image` and `asset:` id resolves to an asset of the new workspace whose bytes equal the seeded PNG, 6000 change-log rows, command-log count 6000.
  - Import as new on A itself (next to the original): 1.8 s, the original still has 30 pages, the copy is complete, the 6000 command-log rows were stored under remapped ids; a repeated import of one row left the count at 6000.
  - Import into B with `docker pause` for 5 s during the import: 30 of 30 bodies confirmed, verify passes.
  - 300 pages: export from cold rooms 3.7 s (815 KB, 0 incomplete, 0 twins rewritten), import 4.6 s with 300 of 300 bodies confirmed, verify passes. Server B 232 MiB including its tmpfs data.
  - The archive: `zipfile.testzip()` clean, extracted on `python:3.11-slim` (Debian) with 0 failures, no case-insensitive duplicate paths, longest segment 23 bytes; `.md`, `.json`, `.csv`, `.typ` deflated, `.png` stored.
  - Command-log routes with curl: 401 without a token; CSV of 6000 rows by Python's csv reader, formula cell came out `'=HYPERLINK("http://x")`; JSON 6000; malformed bodies answer 400, bad rows are counted as skipped; the server stayed up.
- Browser, `scripts/qa-exports-playwright.mjs` in `mcr.microsoft.com/playwright:v1.49.1-noble`: the dialog's export downloaded on the first click in Chromium and in Firefox (234 KB, no download failure, status `Exported 30 notes and 6 images, 6000 command-log entries.`), and All Pages → Markdown downloaded in both. The blurred image's `modified.png` differs from `original.png` in both browsers (real canvas render), plain and full-frame ones are byte-identical. Importing the Chromium ZIP into B through the file picker: `Imported as a new workspace: 30 notes, 6 images, 6000 of 6000 command-log entries.`, and opening a note rendered its picture from a blob URL with no "image not found". The verify phase passed on that import too.

## Not fixed, or not verified

- **Firefox ESR on Kali** was not tested; Playwright's Firefox build is not ESR. Windows `Expand-Archive` and macOS `ditto` extraction were not tested (Linux only).
- **Scale**: 300 pages with 6 images was measured; 500 images and peak browser memory were not. The ZIP is still built in memory (the spec's non-goal); if a 500-screenshot export exceeds the browser's memory, a streaming writer is the next step.
- **Replace with a teammate's tabs open** is verified by a unit test (no delete event for any id in the archive during a replace) and by reading `reconcileTabs`, not in two live browsers.
- **Replace resets nothing in bodies** (CRDT merge, documented in the dialog and here). Resetting a body to the archive would need a delete of the live fragment, which can drop a concurrent edit: a product decision, not taken.
- **Assets and asset folders not in the archive survive a replace.** Deleting them could orphan an image a merged body still shows. A product decision, not taken.
- **What the workspace archive does not carry**: page version history (server `page_versions` and twins), users, settings (theme policy, cmdlog/backup tokens, retention) and other workspaces. Those need a full backup (Admin → Backups, `server/restore.mjs`); the backups stream owns that path.
- **The command log's live CRDT window** is not filled on import; the Command Log tab reads the imported rows from the archive over REST.
- **`?ro=1` is a hint**, not an enforced read-only connection.
- The spec's removal of All Pages → Markdown and of `pagesToMarkdownBundle` was not done (the task said keep the button; the function is still exported and tested).
