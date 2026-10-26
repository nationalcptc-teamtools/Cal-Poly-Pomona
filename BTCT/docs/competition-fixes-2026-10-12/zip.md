# Zip stream: every download and every backup is a ZIP

Branch `fix/zip2`, based on `competition-hardening` (dc21875). The user asked: "exports should also be exported in a zip" and "include backups as zip too".

## A. Browser downloads

### Inventory (before and after)

Found by grepping `downloadBlob`, `downloadText`, `a.download`, `createObjectURL`, `window.open` and `href="/api` across `src/`. Every `createObjectURL` not listed below is an image preview (`<img src>`), not a download.

| Where | Before | After (ZIP name) | Inside the ZIP |
|---|---|---|---|
| Export dialog, Full Workspace → ZIP | `<ws>_<YYYY-MM-DD_HHMM>.zip` | unchanged (one ZIP, no ZIP inside it) | unchanged |
| Export dialog, All Pages → Markdown, several pages | `<ws>_<date>_notes.zip` | unchanged (already a ZIP) | unchanged |
| Export dialog, All Pages → Markdown, one page | `<Title>.md` | `<Title>_<date>.zip` | `<Title>.md` |
| Command Log tab, CSV | `command-log-<ms>.csv` | `command-log_<date>.zip` | `command-log-<ms>.csv` (DEFLATE) |
| Command Log tab, JSON | `command-log-<ms>.json` | `command-log_<date>.zip` | `command-log-<ms>.json` (DEFLATE) |
| Profile, settings Export | `btct-prefs-<user>.json` | `btct-prefs-<user>_<date>.zip` | `btct-prefs-<user>.json` |
| Report tab, PDF (browser) | `document.pdf` | `<ws>_<date>.zip` | `document.pdf` (STORE) |
| Report tab, SVG (browser) | `document.svg` | `<ws>_<date>.zip` | `document.svg` (DEFLATE) |
| Report tab, PDF (server) | `<ws>.pdf` | `<ws>_<date>.zip` | `<ws>.pdf` (STORE) |
| Report tab, DOCX (server) | `<ws>.docx` | `<ws>_<date>.zip` | `<ws>.docx` (STORE) |
| Note editor, oversized paste → Save as .txt | `paste-<iso>.txt` (its own anchor code, revoked after 10 s) | `paste_<date>.zip` | `paste-<iso>.txt` |

Not present in this build, so nothing to wrap: single asset downloads, nmap exports, admin settings export. `commandLogExportUrl` (server CSV/JSON URL) is defined but no UI uses it; `GET /api/cmdlog/export` stays raw for the cmdlog-agent, the workspace export and scripts.

`<date>` is local time `YYYY-MM-DD_HHMM` and the stem is made portable by `exportRootName` (export-names.ts), so it is the same rule the workspace ZIP uses. Two downloads of the same kind in the same minute get the same suggested name; the browser adds ` (1)`. (Changed later, see `fixup-round3.md`: the ZIP name now ends in the inner file's extension, `_pdf`, `_docx`, `_csv` and so on, so only two downloads of the same format in the same minute share a name.)

### Code

- `src/lib/download-zip.ts`: `downloadAsZip(stem, files)`, `buildDownloadZip`, `downloadZipName`, `zipEntryNames` (sanitized, deduplicated ignoring case), `zipCompressionFor` (STORE for png/jpg/gif/webp/pdf/docx/xlsx/zip/gz/woff and other compressed formats, DEFLATE level 6 for the rest). JSZip is a dynamic import; it lands in its own chunk and the entry bundle only carries the preload map entry. The typst gate (`grep -l typst_ts_web_compiler dist/assets/index-*.js`) stays empty.
- `src/lib/zip-upload.ts`: `readUploadText(file, { pick, maxBytes, what })` reads the bare file, or the first member of a ZIP (recognised by its `PK` signature, not its name) whose base name `pick` accepts, through JSZip's internal stream so an oversize member is refused before it is inflated. Messages: `<file> holds no <what>.`, `... is too large for a <what>.`, `... is not a readable ZIP (...)`.
- Callers: `pages-markdown.ts` (single page), `CommandLogView.tsx`, `ProfileEditor.tsx` (export, and import with `accept=".zip,.json"` and a 1 MB cap), `TypstView.tsx` (`triggerDownload(stem, name, data)`), `note-image-paste.ts` (its private anchor code is gone; it now goes through `downloadBlob` too), `ExportDialog.tsx` (status line names the file).

### Imports

| Import | Accepts |
|---|---|
| Workspace import (Export dialog) | the workspace ZIP, as before (its format did not change) |
| Profile settings Import | the new `.zip` and the bare `.json` from older builds |
| Command-log import | there is no browser import of a command-log file; the log is imported inside the workspace ZIP through `POST /api/cmdlog/import` (unchanged) |
| Markdown import | none exists |

## B. Backups

### Format

One file per run: `BACKUP_DIR/btct-backup-YYYYMMDD-HHMMSS.zip`, entries in run order `yjs/<room>.yupdate.gz`, `sqlite/data.sqlite.gz`, `assets/<id>`, `history/<pageId>.ydoc`, then `manifest.json` (sha256 and size of every other entry; same schema 1 manifest as the folder runs, `linkedBytes` always 0).

`server/zip-stream.mjs` (new, Node APIs only, `.d.mts` beside it, added to the Dockerfile COPY list):

- `ZipWriter`: STORE entries, CRC32 (`zlib.crc32` when the runtime has it, which Bun 1.3.14 does; a table fallback otherwise), sha256 of each entry while streaming, the local header written first and patched in place once CRC and size are known (no data descriptors), UTF-8 names, unix mode 0600 in the central directory. ZIP64: an extra field is reserved in the local header only when the entry's size hint could reach 4 GiB (or there is no hint); the central directory gets ZIP64 fields for sizes or offsets past 4 GiB, and a ZIP64 end record when the count passes 65535 or the directory starts past 4 GiB. Small writes are gathered into a 1 MiB buffer (one write per header made 65,600 entries take 100 s; buffered, 2.5 s). `addFile` opens the file before writing anything, so a file deleted since the SQLite snapshot fails with ENOENT and leaves the archive untouched.
- `openZip`: finds the end record (and the ZIP64 locator), reads the central directory (capped at 64 MB), refuses an archive with an encrypted member, a method other than STORE or DEFLATE, a duplicate name or an unsafe name (`safeEntryName`: empty, absolute, drive letter, backslash, control characters, `.` or `..` segments). `openStream` checks CRC32 and size; `extractEntryTo` (refuses an existing file) and `hashEntry` sit on it.

`server/backup.mjs` `writeRun`: precheck, `ZipWriter.create(<name>.zip.tmp, 0600)`, rooms (gzipped one at a time, as before), `VACUUM INTO <name>.tmp/data.sqlite` gzipped straight into the ZIP, assets streamed from `ASSETS_DIR`, twins, manifest, `finish()` (central directory, fsync, close), chmod 0600, rename, fsync of `BACKUP_DIR`, scratch folder removed. A deadline abort closes the writer and removes the `.zip.tmp` and the scratch folder.

### Retention, precheck, inventory

- `estimateRunBytes` now counts every asset (no hard links), the previous run's non-asset bytes plus 20%, the raw SQLite scratch file and 200 bytes of headers per entry. The run fails with `not enough space in /backups: ... (lower "keep last" or delete old backups)` rather than leave less than `BACKUP_MIN_FREE_MB` (256) free.
- `KEEP_LAST_DEFAULT = 12`: `normalizeKeepLast(null or '')` returns 12, an explicit `0` still keeps every run. A box whose admin never touched "keep last" therefore starts pruning to 12 runs after this change (see "Decisions for the user").
- `listBackups()` (now async, as are `backupStatus()` and `backupUsage()`; the two routes in `index.mjs` await them) lists `.zip` files and older folders, newest first, with `format: 'zip' | 'folder'`, reading each ZIP's manifest once (cached by name, mtime and size). A `<name>.tmp` scratch folder next to a `<name>.zip.tmp` is not listed. `deleteBackup` takes the listed name (`.zip` file or folder). `runsToPrune` sorts ZIPs and folders by the time in the name. `removeStaleTmpRuns` removes `.zip.tmp` files and `.tmp` folders older than an hour at boot.

### Restore

`bun restore.mjs <zip | folder> [--yes] [--partial] [--keep-browser-caches]`, `bun restore.mjs --verify <zip | folder>`. For a ZIP: verify hashes every listed member straight out of the archive (nothing written); a restore streams only the members the plan needs into `<data>/.restore-unpack/` (each re-hashed against the manifest, the path checked again against the unpack root), moves assets and twins from there into `.restore-staging` (rename, copy on EXDEV), reads the gzipped SQLite and rooms from there as before, and removes the folder on success, on failure and on `process.exit`. The free-space check adds the unpacked SQLite and room bytes. A folder is read in place as before (copied, never moved).

### Admin panel, scripts, docs

- Admin → Backups: "one self-contained .zip per run", "each ZIP is a full copy", keep-last tooltip says 12 by default, folder runs are marked `(folder)`, the restore and verify commands carry `.zip`.
- `Restore-BTCT.ps1` takes `btct-backup-<stamp>.zip`, the name without `.zip` (resolved to the file), or an older folder. `Backup-BTCT.ps1` no longer prints "MB new on disk". `install-btct.sh` prints where the ZIPs go.
- README (Backups & restore, Moving an engagement, API table, env vars, key files, invariants 43 and 50, Export & import, Command log, Report export, profile settings, paste) and CLAUDE.md (Commands, Backups, Workspace archive, invariants 26 and 30) updated.

## Measurements

All on this host, server code from this branch mounted into `btct-qa:hardening` (`d118ac5f`), `--memory 1g --cpus 2`, `/data` on tmpfs, `BACKUP_DIR` a bind mount on the host disk, seeded by `qa2/backup/probes/seed.mjs`: 3 users, 3 workspaces, 300 pages with bodies, 501 screenshots (182 MB), 294 history twins, 324 versions, 6000 change-log rows, 6006 command-log rows.

| | ZIP (this branch) | Folder (competition-hardening) |
|---|---|---|
| One run | 192,275,834 bytes (183.4 MiB), 1092 entries, 7.4 s | 191,799,655 bytes, 7.9 s |
| Peak RSS of the server during a run | 189 to 220 MB (idle between runs 133 to 170 MB, so +50 to 70 MB) | 212 MB |
| Three runs on disk | 576,831,928 bytes | about 197 MB (each later run about 2.5 MB: rooms 0.97 MB, SQLite 0.48 MB, twins 1.05 MB; screenshots hard-linked) |
| Keep-last default (12 runs, measured: 13 runs written, 12 kept) | 2,307,363,505 bytes | about 220 MB |
| Keep everything, hourly for 72 h (computed) | about 13.8 GB | about 370 MB |
| `restore.mjs --verify` | 4.9 s | |
| `restore.mjs` (unpack, stage, read 295 rooms back, swap) | 16.7 s | 13.8 s (folder) |

Thirteen consecutive runs took 5.4 to 7.9 s each. The ZIP passed `unzip -t`, `7z t` and Python `zipfile.testzip()`.

## Verification

- `bunx tsc -b`: clean. `bunx vitest run`: 787 passed, 1 failed (`typst-run-child` "kills grandchildren too", the known environmental failure), 5 skipped. New: `src/test/zip-stream.test.ts` (13: CRC32 check value, name rules, round trip of buffer, file and unsized stream read back by our reader and by JSZip, duplicate/unsafe/missing refused, traversal ZIP and non-ZIP refused, DEFLATE member read, flipped byte caught by CRC, 65,600 entries (ZIP64 end record), an entry at a 5 GiB offset in a sparse file (ZIP64 offsets), `verifyBackupZip` ok/mismatch/missing/unsafe id/no manifest), `src/test/download-zip.test.ts` (11: names, entry dedupe, STORE vs DEFLATE checked in the archive bytes, one ZIP handed to `downloadBlob`, single-page markdown ZIP, `readUploadText` bare file, ZIP member, no member, oversize member in a small ZIP, oversize bare file, damaged ZIP), `backup-format.test.ts` updated (keep-last default, mixed ZIP and folder pruning, entry names, `.zip.tmp` staleness, new estimate).
- Live round trip (ZIP): seeded box, backup, `truth` dump (`probes/dump.mjs`), `restore.mjs --verify` (exit 0), `restore.mjs --yes` into an empty data folder, new server on it, dump, `probes/diff.py`: **all equal** (logins, accounts and prefs, settings, every shared map, 300 bodies and state vectors, 501 asset blobs by sha256, 501 inventory rows, 324 versions rendered, 294 twins by sha256, 6006 command-log rows). No `.restore-unpack` left behind.
- Live round trip (old folder): a run written by the unmodified `competition-hardening` image, listed by this branch next to a ZIP (`format: folder`), verified and restored by this branch's `restore.mjs`: **all equal**.
- Refusals, each exit 2 with nothing changed: a ZIP with `../../data/evil`, one with `/etc/evil`, one with a backslash name, a manifest listing `../x`, and a copy of a real backup with one byte flipped inside an asset (`CRC mismatch`). `restore.mjs` against the running box's own data: "the server appears to be running".
- Keep-last 2 removed the two oldest ZIPs after the fourth run; `DELETE /api/backup/archives/<zip>` removed one, `..%2Fx.zip` answered "invalid backup name", an unknown name "backup not found".
- Boot cleanup removed a two-hour-old `.zip.tmp` and `.tmp` folder and kept a fresh `.zip.tmp`, which `/api/backup/list` showed as partial. `BACKUP_MIN_FREE_MB=100000000` made a run fail with the "not enough space" message and write nothing. `BACKUP_DEADLINE_S=2` on the seeded box: "backup timed out after 2 s", no `.zip.tmp` or scratch folder left, `/healthz` 200. `docker kill` in the middle of a run leaves `<name>.zip.tmp` and `<name>.tmp` (removed at the next boot after an hour).
- Browser (`mcr.microsoft.com/playwright:v1.49.1-noble`, Chromium and Firefox, against `btct-qa:hardening-full` with this branch's `dist/` and server files, `ENABLE_TYPST=1`): every download in the inventory arrived on the first click with the name in the table and the original file inside (CSV 2002 rows, JSON 2002 rows, `%PDF-` for both PDFs, a DOCX, an SVG); the workspace ZIP had 866 members and no nested ZIP; settings Import accepted the downloaded ZIP and the bare JSON taken out of it, and refused a notes ZIP with "holds no BTCT settings export". The oversized-paste Save as .txt downloaded `paste_<date>.zip` with the 1,100,000-character `.txt` in Chromium.
- PowerShell: both scripts parse in `pwsh` 7.4; `Restore-BTCT.ps1` with a stub `docker` resolved `<name>` to `<name>.zip`, passed a folder name through, ran stop/restore/start with `-Force`, and refused an unknown name.

## Not fixed, or not verified

- **Keep-last default of 12 is a choice for the user to confirm.** It deletes runs automatically on a box whose admin never set "keep last" (before this change those boxes kept everything, which was cheap with hard links). At 192 MB a run, 12 runs are 2.3 GB; the precheck still stops any run that would leave less than 256 MB free. Raising `BACKUP_MIN_FREE_MB` or lowering the default are the levers.
- The oversized-paste download in **Firefox**: not verified (Playwright's synthetic paste event did not reach the editor with its data in Firefox; the same step passed in Chromium).
- The **single-page** All Pages → Markdown ZIP: verified by unit test only (the seeded workspace has 100 pages).
- **Windows Explorer and macOS** extraction of the backup ZIP and of the download ZIPs: not tested (Linux `unzip`, 7-Zip and Python only).
- **A real ZIP past 4 GiB**: the ZIP64 paths are tested with 65,600 entries and with a sparse 5 GiB offset, not with a 4 GiB file written to disk.
- Backup timing was measured with `/data` on tmpfs; on a slow disk the reads take longer. The restore figures are for an empty target.
- `.restore-unpack` needs the gzipped SQLite and room bytes on the data volume during a restore (about 1.5 MB here); assets and twins are moved, not copied.
