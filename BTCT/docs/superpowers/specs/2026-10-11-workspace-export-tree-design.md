# Workspace export as a notes tree with images

Date: 2026-10-11. Branch: `lw-version`. Status: design approved in conversation, spec awaiting review.

## Why

The competition workflow is: take notes on the lightweight box (report tab off), export the workspace, import it on a machine with more resources where the report tab is on, and write the report there. Today's exports cannot support that:

1. **No images leave the app.** Neither the "All Pages → Markdown" ZIP nor the lossless workspace ZIP carries asset bytes or asset records. A note image is written as `![alt](asset:<uuid>)`, and a ZIP imported on another server shows "image not found in assets" for every screenshot. Only a full-server restore from Admin → Backups carries images.
2. **Pages overwrite each other.** Files are named by title alone and JSZip replaces a same-named entry, so every page still called "Untitled" (the default) collapses into one file. An empty title in the markdown export becomes `.md`, a hidden file on Linux.
3. **Names are not portable.** Only `/\?%*:|"<>` are replaced: no byte cap (ext4 rejects names over 255 bytes), control characters pass through, the page tree is flattened.
4. **Firefox risk.** Every download clicks a detached anchor and revokes its blob URL on the next line (`ExportDialog.tsx:53`, `CommandLogView.tsx:57`). Kali ships Firefox ESR.
5. **Silent partial export.** `collectPageYjsUpdates` waits at most 3 s per page (`yjs-providers.ts:103`), then stores whatever this browser cached, which is nothing for a page it never opened, and the status still counts it as included.

## Goals

- One ZIP that is both a browsable folder of notes and images, and a lossless archive another BTCT server imports with images intact.
- Every image exported twice: `modified` (crop and blur as the note shows it) and `original` (the untouched upload).
- File and folder names that extract cleanly on Linux, Windows and macOS.
- Downloads that work in Firefox ESR and Chrome.
- The export says which pages may be incomplete and which images failed, instead of reporting success regardless.
- A crop or blur stays removable after import (the original bytes and the framing metadata both travel).

## Non-goals

- Building the export on the server. The blur and crop renderer runs in the browser; the server's only renderer belongs to the report feature, and decoding hundreds of screenshots on the 1 GB box would compete with the Yjs relay.
- A streaming ZIP writer, unless the measurement in "Testing" calls for it.
- Page version history (lives on the server; full backups cover it) and the command log (SQLite plus a live window; not in today's ZIP either).
- Human-readable nmap or command-log files. Nmap records ride in `.btct/` as today.
- Changing the markdown serializer or the `page.content` mirror.

## Layout

```
CPTC-Team5_2026-10-11_1432/
├── README.md
├── notes/
│   ├── Recon/
│   │   ├── Recon.md
│   │   └── Recon.attachments/
│   │       ├── 01-nmap-scan/
│   │       │   ├── modified.png
│   │       │   └── original.png
│   │       └── 02-image-2/
│   │           ├── modified.png
│   │           └── original.png
│   └── Domain Controller/
│       ├── Domain Controller.md
│       ├── Domain Controller.attachments/
│       │   └── 01-bloodhound/
│       │       ├── modified.png
│       │       └── original.png
│       └── Kerberoasting/
│           ├── Kerberoasting.md
│           └── Kerberoasting.attachments/
│               └── 01-tgs-hashes/
│                   ├── modified.png
│                   └── original.png
├── assets/
│   └── <Assets Manager folder path>/
│       ├── <picture_name>/modified.png, original.png
│       └── <font file>
└── .btct/
    ├── manifest.json
    ├── workspace.json, pages.json, changeLogs.json, nmapScans.json,
    │   nmapMachines.json, pageSnapshots.json, pageYjsUpdates.json
    ├── report.typ                      (when the workspace has a report)
    ├── <retired table>.json            (as today)
    ├── assets.json                     (new: asset records, crop and blur included)
    ├── assetFolders.json               (new)
    └── assetFiles.json                 (new: asset id → ZIP path of its original bytes)
```

Rules:

- **Root folder and ZIP name:** `<workspace name>_<YYYY-MM-DD_HHMM>` in local time, sanitized like any segment. The ZIP is that name plus `.zip`.
- **Notes:** each page is a folder `notes/<Title>/` holding `<Title>.md` (the title's own case) and, only when the note has images, `<Title>.attachments/`. Child pages are folders inside their parent's folder. Sibling order follows `sortOrder` (it only shows in `README.md`).
- **Pictures:** `<NN>-<stem>/` where NN is the image's position in the note's markdown (an image found only in the Yjs update, because the markdown mirror lagged, is numbered after those in fragment order), zero-padded to two digits (three when a note has 100 or more), and `<stem>` is the asset's filename without its extension. Asset filenames are already unique per workspace (`typstAssetRepo.uniqueFilename`), so pastes appear as `image`, `image-2`, and so on until renamed in the Assets Manager.
- **Both files, always:** `modified.<ext>` and `original.<ext>`, where `<ext>` is the asset filename's extension (`resolveAssetBytes` keeps the claimed format). With no crop or blur the two are identical. GIF and SVG cannot be re-encoded by a canvas, so their `modified` file is the original bytes.
- **Reuse:** the same asset twice in one note gets one picture folder and both links point to it. The same asset in two notes gets a copy in each note's attachments.
- **Which assets:** every asset a note references (its id appears as `asset:<id>` in the page's markdown or as the `assetId` of an `asset_image` element in its Yjs update), whether or not it is retired, plus every non-retired asset no note references. A referenced asset can carry `deletedAt` today, because cutting an image and pasting it back retires it and nothing un-retires it (`note-image-paste.ts:135-142`); selecting by `deletedAt` alone would drop it. Unreferenced retired assets are not exported.
- **`assets/`:** the unreferenced ones (report figures, Assets Manager uploads), under their Assets Manager folder path. Images use the same `<stem>/modified, original` layout; fonts are the single file.
- **`README.md`:** export time, schema version, counts, the page tree as relative links, a line saying `original.*` files are unredacted, and, only when non-empty, sections "Possibly incomplete pages", "Images that failed to export" and "Paths too long for Windows Explorer" (any path over 240 characters; extract those with 7-Zip).
- **`.btct/`:** everything today's ZIP holds at its top level, moved here, plus the three new files. `manifest.json` carries `schemaVersion: 3` and adds `assets` and `assetFolders` to `counts`.

## Naming rules

A pure module, `src/export/export-names.ts`, owns every name and path so it can be tested without a browser.

`sanitizeSegment(name, maxBytes)`:
1. NFC-normalize.
2. Replace `/ \ ? % * : | " < >`, C0 and C1 control characters and DEL with `_`.
3. Collapse runs of whitespace to one space; trim spaces and dots at both ends.
4. Empty result becomes `Untitled`.
5. A Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, case-insensitive, with or without an extension) gets a `_` suffix.
6. Cap at `maxBytes` UTF-8 bytes without splitting a code point, then trim trailing spaces and dots again. Caps: 60 bytes for note titles and folder names, 40 for picture stems.

`dedupe(names)` within one directory: compare case-insensitively after sanitizing; later entries get `-2`, `-3`. A note's own `.md` and `.attachments` names are reserved first, so a child page titled `Recon.attachments` becomes `Recon.attachments-2`.

Tree building: a page whose `parentId` is missing, points outside the workspace, or closes a loop is placed at the top level. Loops are detected with a visited set, never by recursion depth.

Link rewriting: in each note's markdown, `![alt](asset:<uuid>)` with an optional title is rewritten to the relative path of its `modified` file, each segment passed through `encodeURIComponent` so spaces and parentheses survive every previewer. Only uuid-shaped ids are touched. An id with no exported record is left as written and listed under "Images that failed to export". Non-asset images are not touched. Known edge: the same pattern typed literally inside a code block with a real asset id would also be rewritten; accepted.

## Export data flow

1. Gather records as today, plus the workspace's `typstAssets` (selected as in "Which assets") and its `assetFolders`.
2. Collect page Yjs updates, now returning `{ updates, unsynced }`. `PageYContext` gains `whenServerSynced(timeoutMs): Promise<boolean>`, which resolves `true` on the provider's `sync` event and `false` at the timeout, with no IndexedDB-only fallback. The export waits up to 15 s per page (4 pages at a time, as now); a page that times out is still exported from local state and goes into `unsynced`. The 3 s `whenFullySynced` stays as it is for the editor; fixing the editor's own use of it is hardening item C1, not part of this change.
3. Build the plan with `export-names.ts`: every ZIP path, the rewritten markdown per note, and the list of image jobs.
4. Run image jobs 4 at a time. `original` comes from a fetch of `/api/assets/:id`; `modified` comes from a new non-caching `renderAssetBytes(asset, raw)` in `src/lib/assets.ts`, which `resolveAssetBytes` also calls. The export never goes through `rawBytesCache` or `croppedCache`, because `croppedCache` has no size cap (`src/lib/assets.ts:147`) and an export of 500 images would otherwise pin every render for the rest of the session. A failed job is recorded and the export continues.
5. Write the ZIP: images with `compression: 'STORE'` (PNG and JPEG are already compressed), text with `DEFLATE`.
6. Download through the shared helper (below).
7. Status line: `Exported N notes and M images.` followed, when non-zero, by `K pages may be incomplete` and `J images failed`, with the same lists in `README.md`.

## Import data flow

1. `parseWorkspaceZip` checks for `.btct/manifest.json`. Present: read schema 3 from `.btct/`. Absent: read today's v2 layout, then v1, exactly as now.
2. Records are imported with today's rules (`new` and `replace` modes, id remapping on conflict), but written in batches: one `sharedTransact` per chunk of a table, a chunk closing at 1 MB of JSON. Today's loop awaits one transaction per record, and each one reloads the table on every client (an O(n²) import on 5000 change-log entries). One transaction per whole table is also wrong: the Bun websocket shim closes any message over 16 MiB with code 1006, measured, so a large table sent as one update would never reach the server.
3. Folders from `assetFolders.json` are added with remapped ids, parents before children.
4. Assets, 4 at a time:
   - If a non-retired record with the same id already exists in the destination workspace (re-importing on the same server), reuse it.
   - Otherwise read the bytes at the path `assetFiles.json` gives, upload with `uploadAsset` to the imported workspace, and add the record with the server's new id and returned filename, keeping `crop`, `blurs`, `width`, `height`, `fontFamily` and the remapped `folderId`. `deletedAt` is cleared, since every exported retired asset was one a note still used.
   - A failed upload is recorded and the import continues.
   - A filename the server changed (extension correction) is listed, since `report.typ` refers to assets by filename.
5. Asset ids are remapped where notes refer to them:
   - `page.content`: the same regex as the export, `asset:<old>` to `asset:<new>`.
   - `pageYjsUpdates`: a pure `remapAssetIdsInUpdate(update, idMap, Y)` applies the update to a temporary `Y.Doc`, walks the `prosemirror` fragment, calls `setAttribute('assetId', new)` on every `asset_image` element whose id is in the map, and returns `Y.encodeStateAsUpdate` of the temporary doc. Skipped when every id mapped to itself.
6. `seedMissingYTexts`, then reload pages, nmap, change log, `typstAssets` and `assetFolders` in the store.
7. Status line names the counts and any failures, like the export.

## Download helper

`TypstView.tsx:89-102` (`triggerDownload`) already does this correctly and says why: append the anchor, click, remove it, revoke on a timer, because a synchronous revoke races the browser's read of the blob. That function moves to `src/lib/download.ts` as `downloadBlob(data, filename, mime)`, keeping its no-copy check for a Blob that already has the right type, with the revoke delay raised from 10 s to 60 s for multi-hundred-megabyte ZIPs. It replaces the inline copies in `ExportDialog.tsx`, `CommandLogView.tsx` and `ProfileEditor.tsx`, and `TypstView.tsx` imports it (`src/lib/download.ts` imports nothing typst-related, so invariant #17 holds).

## Removed

- The "All Pages → Markdown" button and `handleExportPagesMarkdown`. The workspace ZIP holds every note as markdown.
- `pagesToMarkdownBundle`, which nothing else calls.

## Error handling

| Situation | Behaviour |
|---|---|
| Page not synced from the server in time | Exported from local state, listed as possibly incomplete in the status and `README.md` |
| Image fetch or render fails | Picture folder skipped, link left as `asset:<id>`, listed in `README.md` |
| Asset id in a note with no record | Link left as written, listed |
| Upload fails on import | Import continues; the note keeps the old id and shows "image not found"; listed |
| Server renames an uploaded file | Record takes the new name; listed so `report.typ` can be fixed |
| ZIP is not a BTCT export | `Import failed: Invalid workspace zip: missing workspace.json` (as today) |
| Path over 240 characters | Exported anyway; listed under "Paths too long for Windows Explorer" |

## Compatibility

- Schema 3 importers read schema 2 and 1 archives unchanged. Schema 2 importers (older builds) cannot read schema 3; the competition box and the report machine must both run this code. If the report build lives on a separate branch, `src/export/`, `src/lib/download.ts` and `src/components/ui/ExportDialog.tsx` must be identical on both.
- The existing `src/test/workspace-zip-report.test.ts` cases keep passing; the report three-state logic (`reportImportAction`) is unchanged and reads `.btct/report.typ` and `.btct/manifest.json` for schema 3.

## Testing

Unit (vitest, `src/test/`):
- `export-names.test.ts`: each sanitizer rule, including a 4-byte emoji at the byte cap and every device name; dedupe with case collisions and the reserved `.attachments` name; tree building with an orphan, a cross-workspace parent and a two-page loop; link rewriting with spaces, parentheses, an optional title, an unknown id and a non-asset image left alone; the longest path for a three-deep tree of maximum-length names.
- `workspace-zip-tree.test.ts`: export from fixtures with injected `getOriginal` and `getModified` functions (no network, no canvas), assert the exact path list, parse it back, assert records and `assetFiles.json`; a schema 2 fixture still parses.
- `asset-id-remap.test.ts`: `remapAssetIdsInUpdate` on a doc with nested `asset_image` elements, unmapped ids untouched, identity map is a no-op; markdown remap.
- `download.test.ts`: anchor attached during the click, revoke deferred (fake timers).

Integration, against the preview container rebuilt from this branch on `127.0.0.1:8081`:
- A seeded workspace: 300 pages with nesting, several "Untitled", emoji and 200-character titles, a loop-free orphan; 500 images with a mix of blur, crop and neither, some shared between notes.
- Export in Chrome and in Firefox ESR. Record wall time and peak renderer memory. If peak memory exceeds 1 GB, add streaming before shipping.
- `unzip -t` and a full extract in `debian:bookworm-slim`; `Expand-Archive` on Windows; compare the extracted path list with the unit-test expectation.
- Import the ZIP into a fresh server with `ENABLE_TYPST=1`: notes render their images in the editor, a blurred image's blur can be removed in the image editor, `report.typ` is present, and the Assets Manager shows the folders.

## Acceptance

- The seeded workspace exports and re-imports with every note and every image, and no file in the ZIP overwrites another.
- The extracted tree matches the layout above on Linux and Windows.
- Both browsers download the ZIP.
- The status line and `README.md` list any incomplete pages and failed images.
- `bun run build` and `bun run test` pass, and README.md and CLAUDE.md describe the new export (feature tour, "Conventions & invariants" for the schema 3 layout and the export's cache bypass).
