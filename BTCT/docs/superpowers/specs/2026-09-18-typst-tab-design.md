# Typst report tab, behind a flag: design

Date: 2026-09-18. Branch: `lw-version`. Status: approved design, no code yet.

## Why

The workflow is two machines. Notes are taken on a small range box (1 to 2 GB of RAM, 1 to 2 cores). Afterwards the workspace is exported, imported into a BTCT instance on a desktop, and the report is written there. The report editor must therefore cost the range box nothing while it runs, and be fully available on the desktop, from one branch and one image.

The source of the feature is Typst Studio (`C:\Users\rober\Desktop\university-tools\advanced-typst-editor`), which descends from the Typst tab removed from BTCT in `8a549fb` and has grown since: the compiler runs in a Web Worker, the preview doubled in size, and it gained a place-screenshot dialog, a search panel with a source map, and an MCP server.

## Measured cost of the source project

From Typst Studio's `dist/`:

| Piece | Raw | Gzipped |
|---|---|---|
| Typst compiler wasm | 28.3 MB | 10.8 MB |
| Renderer wasm | 0.97 MB | not measured |
| Fonts (NewCM, Libertinus, DejaVu Mono) | 8.4 MB | not measured |
| Editor and view JS chunks | 365 KB | 116 KB |
| Total | about 38 MB | |

Compilation happens in the browser, so none of this is server RAM or CPU. The server-side extras (MCP, PDF and DOCX export) add `@modelcontextprotocol/sdk`, `zod`, `jimp`, and the `typst` and `pandoc` binaries. Their image-size cost is unmeasured and is recorded during step 1 and step 2 (see "Bloat budget").

## Decisions

| Question | Decision |
|---|---|
| Availability | Runtime env flag `ENABLE_TYPST`, off on the range box, on at home. One image. |
| Storage | Yjs. One report per workspace, under the same key the removed tab used. |
| Client extras | Place-screenshot dialog, search panel, source map. |
| Server extras | MCP server, server-side PDF export, DOCX export. |
| DOCX route | Pandoc on the server (`-f typst -t docx`). Structure survives, custom Typst layout does not. |
| MCP scope | Report tools plus read-only access to notes, hosts and the command log. |
| MCP auth | Admin-generated static bearer token, the same pattern as the command-log ingest token. |
| Port strategy | Copy Typst Studio's current code and swap its storage seam. `8a549fb^` is the reference for the old Yjs wiring. |

Rejected: reverting `8a549fb` and forward-porting (two diverged copies of every file to hand-merge), and running Typst Studio as a second container (no Yjs, no shared assets).

## Section 1: shape and the flag

**The flag.** `ENABLE_TYPST=1` in the server environment. `GET /api/settings` exposes it as `features.typst`. It is an env var and not an admin setting on purpose, so the range box cannot be switched on from the UI.

**Client.**
- A `typst` TabKind returns: `src/types/index.ts`, a `lazy()` branch in `SplitContainer.tsx`, icons in `TabBar.tsx` and the pane chip.
- The sidebar entry and the tab render only when `features.typst` is true.
- The wasm, fonts and Typst JS stay in their own chunks. With the flag off they are files on disk that no browser requests.
- Ported as they are: `typst-compiler*.ts` (worker included), `typst-placeholders.ts`, `typst-source-map.ts`, `typst-search.ts`, `typst-pages.ts`, `typst-geometry.ts`, `typst-language.ts`, `typst-default-fonts.ts`, `TypstEditor.tsx`, `TypstPreview.tsx`, `TypstSearchPanel.tsx`, `TypstView.tsx`, `PlaceScreenshotDialog.tsx`, `typst-editor-bridge.ts`.
- Replaced (the storage seam): `api/client.ts`, `hooks/use-workspace-file.ts`, `lib/typst-assets.ts`, `lib/typst-mount.ts`, and the store. Not ported: the sidebar, settings view, folder browser, disk-change bar, workspace groups, autosave and backup code, which only make sense for a file-based app.
- `blur-math.ts`, `crop-math.ts`, `FigureViewport.tsx` and `pane-resize.ts` already exist in BTCT. BTCT's copies win; any Typst Studio improvement to them is merged deliberately, not overwritten, because `effectiveStyle`/`effectiveStrength` fallbacks must not move.

**Source.**
- Key: `textKey('typst', workspaceId, 'source')` in the shared doc's `texts` map. Reports from before `8a549fb` reappear untouched.
- Pre-seeded from the starter template on first open with `getOrInitYText` (invariant #1).
- Edited through CodeMirror's Yjs binding. Programmatic rewrites (slot placement, MCP edits) use `replaceYTextContent` (invariant #3b).
- No JSON record field mirrors it, so `TEXT_FIELDS_BY_ENTITY` is not touched.

**Assets.** No second asset system. Figures reference the existing `typstAssets` records. The compiler's virtual filesystem is fed from `resolveAssetBytes`, so crop and blur are already applied before the compiler sees an image. `PlaceScreenshotDialog` picks from the same data the Assets Manager shows. Fonts use the existing `kind: 'font'` asset records.

**Export and import.** Full backups already copy the shared doc, so they carry the source. The workspace ZIP gains a `report.typ` entry, written on export and restored into the `Y.Text` on import, and it works with the flag off on the exporting side.

**Moving an engagement between machines is server backup plus restore, not the ZIP** (decided 2026-09-19). The workspace ZIP carries no `typstAssets` records, no asset folders, no image bytes, no command log and no page history, so a ZIP import leaves every note screenshot as a broken placeholder. A backup run carries all of it, at the price that `restore.mjs` replaces the target instance's whole data set. Teaching the ZIP to carry assets is a separate feature and out of scope here.

**Server.** A new `server/typst/` directory, loaded by one dynamic `import()` inside an `if (ENABLE_TYPST)` branch in `index.mjs`. With the flag off: routes return 404, no module loads, nothing is spawned.

## Section 2: the server side (`server/typst/`)

Plain `.mjs`, like the rest of the server. Typst Studio's TypeScript server code is ported, not copied.

**Shared-doc access stays in `yjs-data.mjs`** (invariant #4). Three additions:
- `readTypstSource(workspaceId)`.
- `writeTypstSource(workspaceId, next)`: the first server code that writes a `Y.Text`. It applies a minimal delta (the server twin of `replaceYTextContent`), so an MCP edit merges with a person typing and leaves their cursor alone. The source has no JSON record field, so there is no mirror to set alongside it.
- `listAssetRecords(workspaceId)`: crop and blur metadata, for baking.

Yjs is loaded through the existing CJS `require` (invariant #6).

**`compile.mjs`.**
1. Create a temp directory under the OS tmp folder.
2. Write `main.typ`, each referenced asset with crop and blur baked in by `bake.mjs`, and the fonts.
3. Spawn `typst compile` asynchronously, so the relay keeps running.
4. Return diagnostics or the output bytes.
5. Remove the directory in a `finally`.

Exports run one at a time; a second request queues behind the first. Each has a timeout that kills the child process.

**`bake.mjs`.** `jimp`, imported lazily on the first export. It mirrors the client's crop and blur math, including the `effectiveStyle`/`effectiveStrength` fallbacks for old records.

**`docx.mjs`.** The same staged directory, then `pandoc main.typ -f typst -t docx`. The images in that directory are already redacted, so a Word file cannot carry an unblurred original. The UI says plainly that structure survives and custom layout does not.

> **Addendum, 2026-09-19.** This is no longer how the Word file is made. The pandoc route was tried on a real CPTC report and rejected: 15 pages against the PDF's 23, no cover, every heading numbered "0", and no colours, table fills, headers or layout, because that template is built from `#place`, grids, counters and custom `#show` rules that pandoc's Typst reader does not follow. DOCX now comes from the finished PDF instead: the same staged directory and the same typst compile as `format=pdf`, then `pdf-to-docx/convert.py` (pdf2docx, in an isolated Python child). The redaction guarantee is unchanged and in fact shorter, because there is only one path to the pixels now. The pandoc source rewrite, the AST filter and the sandbox discussion are gone with the route. Measurements and the two defects that had to be repaired are in [docs/typst-tab-2026-09.md](../../typst-tab-2026-09.md).

**HTTP.** `POST /api/typst/:ws/export?format=pdf|docx`, account auth, streams the file back. The tab's Export menu keeps browser-side PDF as the default and adds "DOCX" and "PDF (server)". A missing binary makes the route return 501 and the UI hides that item.

**`mcp.mjs`.** Streamable HTTP at `/mcp`.
- Auth: bearer `typst_mcp_token`, generated in the Admin panel, stored in `settings`, compared with `timingSafeEqual`. Never in `settingsPublic` (invariant #11). 404 when no token is set.
- Report tools: `list_workspaces` (read-only), `get_source`, `set_source`, `edit_source`, `list_slots`, `add_slot`, `place_image`, `clear_slot`, `set_slot_height`, `list_assets`, `update_asset` (crop and blur), `compile`, `render_preview`, `export_pdf`, `export_docx`.
- Not exposed: workspace create, rename or delete, asset upload or delete, backup tools. Those stay in the UI.
- `export_pdf` and `export_docx` return bytes as a resource, not an absolute path, because Claude and the server may not share a disk.

**`notes-reader.mjs`.** Read-only.
- `list_pages(ws)`, `list_hosts(ws)`: JSON records from the shared doc.
- `query_commands(ws, filters)`: the existing SQLite query.
- `get_page(pageId)`: takes the page's Yjs update through `data-export.mjs` (relay doc when open, else y-leveldb) and walks the `prosemirror` `Y.XmlFragment` with a small hand-written markdown serializer. It covers headings, lists, tasks, code fences with language, tables, quotes, links and marks, and `asset_image` as `![](asset:<id>)`. It is pure with `Y` injected, like `history-diff.mjs`, so it gets a `.d.mts` and unit tests. Milkdown is not loaded on the server. An unknown node degrades to its text content and never throws.

This is a fifth deliberate exception to "keep the server dumb" and is recorded as such in CLAUDE.md. The server still never writes a page body.

**Dockerfile.** The build stage fetches pinned `typst` and `pandoc` release binaries; the runtime stage copies both in. New lines: `COPY server/typst ./server/typst`, and the `.d.mts` copy for the client-build stage. New server dependencies: `@modelcontextprotocol/sdk`, `zod`, `jimp`.

## Section 3: testing and the bloat budget

**Unit tests (Vitest, `src/test/`).**
- The ported pure suites come along with their libs: placeholders, source map, search, pages, geometry, compiler client.
- `notes-reader` serializer: one fixture per node type, plus the unknown-node fallback.
- Minimal-delta writer: a concurrent edit on a second doc merges, and a relative cursor position survives.
- MCP tool table: schema checks, and `edit_source` rejects a non-unique match.
- Feature flag: with `features.typst` false, no Typst entry renders and `SplitContainer` never calls the lazy import.

**Server checks.**
- `bun build` syntax check on each new `.mjs`.
- An integration script against a throwaway DB. Flag off: `/mcp` and `/api/typst/*` return 404. Flag on: export a fixture report with one blurred asset to PDF and to DOCX, unzip the DOCX, and assert the embedded image differs from the original upload. That is the redaction guarantee, end to end.

**Bloat budget.** Measured, recorded in `docs/typst-tab-2026-09.md`:

| Metric | How | Pass condition |
|---|---|---|
| Main bundle size | `bun run build`, before and after | unchanged within 1 KB gzipped |
| Flag-off server RSS | preview compose (1 GB, 2 CPU), idle, before and after | no measurable change |
| Flag-off network | load the app and take notes with devtools open | zero requests for wasm, fonts or Typst chunks |
| Image size | `docker images`, before and after | recorded, not gated |
| Flag-on export | time and peak RSS of one PDF and one DOCX export | recorded |

If a flag-off row fails, the feature does not ship to the range box.

**Docs.** README: feature tour and its anchor, API rows, the env var, MCP setup. CLAUDE.md: the flag, the two new invariant #4 exceptions (`server/typst/`'s compile and export path, and the notes reader), the `Y.Text`-writing note in `yjs-data.mjs`, and the Dockerfile lines. The "Retired features" and "Performance" paragraphs that say the Typst tab and its packages are gone are corrected.

## Build order

Each step gets its own implementation plan and leaves a working app.

1. The flag, the tab on Yjs, the ZIP `report.typ` entry, and the flag-off measurements. After this step the two-machine workflow already works with browser PDF export.
2. `compile.mjs`, `bake.mjs`, and server PDF and DOCX export.
3. MCP with the report tools.
4. The notes reader and its MCP tools.

## Out of scope

Multiple Typst files per workspace, per-user attribution of MCP edits, a Typst version history (the source is a `Y.Text` in the shared doc, not a per-page doc, so `server/history.mjs` does not cover it), and a build variant that leaves the wasm out of the image.
