# Performance and bug audit, 2026-08-28

A multi-agent pass over the whole application: five finders (client rendering
and store traffic, CRDT and realtime, server and static serving, Typst and
editor libraries, bundle and assets), an adversarial verifier per finding, and
a "test breaker" that wrote failing tests against the pure modules. Every
finding below was either confirmed by a second agent reading the code, or
refuted and dropped. 54 findings were confirmed, 2 refuted, and the breaker
produced 13 genuine failing tests. Those 13 are now regression tests in
`src/test/audit-fixes.test.ts`.

Companion records: [perf-audit-2026-08-19.md](perf-audit-2026-08-19.md)
(the earlier CPU/memory pass) and [ui-audit-2026-08-28.md](ui-audit-2026-08-28.md)
(unthemed controls).

## Results at a glance

| | Before | After |
|---|---|---|
| Unit tests | 334 passing, 2 known failures | 351 passing, 0 failures |
| Logo bytes on first paint | 2,747,025 (one 1254x1254 PNG used as favicon, login image and sidebar icon) | 7,559 (64 px sidebar/login) + 20,286 (`.ico`), touch icon 51,350 on demand |
| Render-blocking font requests | 1 (Google Fonts, Poppins, unused by the Glass skin) | 0 |
| Copies of `@codemirror/state` / `@codemirror/commands` in the bundle | 2 / 3 | 1 / 1 |
| Initial JS chunk (minified) | 2,523,015 bytes, every tab view statically imported | 576,272 bytes; graph, nmap, findings, timeline, Typst, assistant, command log and history load on first use |
| Static caching | `immutable` on every file including `index.html` | `immutable` only under `/assets/`, `no-cache` + ETag elsewhere; `.wasm` served with `application/wasm` |

The two "known failing" tests (`pane-layout` moveTab-to-centre and
`highlight-plugin` ToggleHighlight) turned out to be one real bug and one
wrong assertion; both are fixed rather than skipped.

## Fixed in this change

Numbers are the audit's finding ids; severity is the verifier's.

### High

| # | Area | Defect | Fix |
|---|---|---|---|
| 1, 31, 42 | `src/lib/pane-layout.ts` | `moveTab` collapsed the layout before re-adding the tab, so dropping a pane's only tab onto its own pane (centre or edge) removed it from every pane. Root cause of the baseline test failure. | Remove, then add or split, then collapse last. Dropping onto your own pane centre, or onto an unknown pane, is a no-op. |
| 2 | `index.html`, `LeftSidebar`, `LoginScreen` | 2.7 MB logo fetched three ways on first paint. | Generated `public/new-logo-64.png` and `public/apple-touch-icon.png`; favicon is the existing `.ico`; the big PNG is gone. |
| 3 | `src/db/seed.ts`, `ExportDialog` (zip import) | Records created without their `Y.Text`s, so inline title and label edits were dropped until a reload. | `seedMissingYTexts(getSharedDoc())` runs after a seed or import (exported from `shared-doc.ts`). |
| 4 | `src/realtime/shared-doc.ts` | The text mirror rewrote the whole record (page content included) three times per title keystroke. | Write-back is debounced 150 ms per text key. |
| 5 | `src/stores/app-store.ts` | Deleting a page, graph or scan left `activePaneId`/`activeTabId` on a collapsed pane, so the next `openTab` went into an invisible pane. | `reconcileActive()` after every layout change; `openTab`/`setActiveTab` self-heal an orphaned active pane. |
| 6 | `src/components/typst/TypstEditor.tsx` | Opening the Typst tab replaced the awareness `user` field without the account id, removing the user from everyone's presence roster and the follow feature. | The awareness user now carries `id`. |
| 7 | `package.json` | Two `@codemirror/state` and three `@codemirror/commands` copies bundled (cross-instance `instanceof` hazard in the Typst editor). | Bumped to `^6.7.0` and added `overrides` so one copy resolves. |

### Medium

| # | Area | Defect | Fix |
|---|---|---|---|
| 9 | `src/db/database.ts` | `Y.Text`s of deleted records lived forever in the shared doc. | `deleteTextsFor()` in `Table.delete` and `deleteIds`. |
| 10 | `server/index.mjs` | Oversized bodies got a socket reset instead of a 413. | `readJsonBody` pauses the request and rejects with `status = 413`; the handler answers, then closes the connection. |
| 11 | `shared-bindings` | Every title keystroke triggered a full `pages` reload. | Mitigated by the 150 ms mirror debounce (one reload per pause, not per key). |
| 12 | `LeftSidebar` | Sidebar resize wrote the store per mousemove. | Writes `style.width` per event, commits once on mouseup (same pattern as the Typst pane resizer). |
| 13 | `FindingsCollector` | Refetched and flashed "Loading findings" on every narrative rename keystroke. | Effect keyed on graph ids; no loading flash when findings already exist. |
| 14 | `server/index.mjs` | `.wasm` missing from the MIME table forced the 28 MB compiler onto the non-streaming instantiate path. | `application/wasm` added. |
| 18 | `app-store`, `shared-bindings` | Tabs for pages deleted remotely rendered "Loading..." forever. | `reconcileTabs()` prunes tabs whose entity is gone, run after page/graph/scan reloads and local deletes (guarded until the shared doc has synced). |
| 19 | `src/App.tsx` | Arrow-key tab switching fired while a React Flow node was focused. | `.react-flow` counts as an editable target. |
| 20 | `SplitContainer` | Every tab view statically imported into the initial chunk. | Heavy views are `React.lazy` behind one `Suspense`. |
| 21, 43, 49 | `HistoryView` | Re-downloaded the twin and rebuilt the viewer every 30 s regardless. | The poll re-fetches the twin only when the latest version id or the dirty flag changed; identical bytes and equivalent selections never reach state. |
| 22 | `GraphCanvas` | Ctrl+F / Ctrl+Z hijacked globally while any graph tab was mounted. | Handler runs only for the active graph tab and never inside inputs. |
| 23 | `HistoryView` restore | Restore could run before the page doc had synced. | Awaits `whenFullySynced` first. (Checking the editor is collab-bound before the ProseMirror path is still open, see below.) |
| 24 | `server/index.mjs` | Programming errors were 400s with raw messages. | `TypeError`/`ReferenceError`/`RangeError` become a logged 500 "internal error"; `err.status` is honoured; validation errors stay 400. |

### Low

| # | Area | Defect | Fix |
|---|---|---|---|
| 30, 32, 37 | `src/test/highlight-plugin.test.ts` | Asserted `toggleHighlightCommand.key`, which Milkdown 7.20 assigns only once an editor runs the plugin. The runtime path (the editor has run it) was never affected. | The test asserts the exported slice is a plugin function. |
| 33 | `server/yjs-data.mjs` | `setText` cleared and reinserted (invariant 3b). | Minimal prefix/suffix delta. |
| 34 | `server/history.mjs` | Every page open/close paid a twin flush with zero edits. | `unflushed` flag; `flushTwin` skips clean twins. |
| 40 | `app-store.closeTab` | Closing the focused pane's last tab left `activeTabId` null while another pane still showed a tab. | Falls back to the surviving pane's tab. |
| 41, 45 | `LeftSidebar` | Rename opened with the title captured at mount. | The rename input is filled from the current record when it opens. |
| 44 | `PageEditor` | Subscribed to the whole `graphNodes` array. | Selects only the node linked to this page. |
| 47 | `SplitContainer` | Divider drag clamped 0.1..0.9, store clamped 0.15..0.85. | Same clamp in both. |
| 50 | `index.html`, `index.css` | Render-blocking Google Fonts request for Poppins. | Removed; the font stack is the system stack the Glass skin already uses. |
| 51 | `src/lib/active-editor.ts` | A selection inside the read-only history viewer counted as a Milkdown selection, so Ctrl+K swallowed the command palette. | `.history-viewer` is excluded. |
| 54 | `server/db.mjs` | `LIMIT` interpolated into SQL text, defeating the statement cache. | Bound parameter. |
| breaker 11 | `server/backup-format.mjs` | A blank interval became "a full backup every minute" (`Number('')` is 0). | Blank or null falls back to the 60 minute default. |

### Pure-module defects found by the breaker

All of these have a test in `src/test/audit-fixes.test.ts`.

| Module | Defect | Fix |
|---|---|---|
| `server/history-diff.mjs` | Yjs merges adjacent deleted ranges and structs, so a second deletion next to an earlier one was invisible (`changed: false`, no user credited). | Only the sub-ranges the previous snapshot did not cover are walked (`subtractRanges`), struct by struct. |
| `src/lib/typst-placeholders.ts` | `setSlotPath` on a call with a trailing comma produced `,,`; `ensureHelper` inserted the helper inside a multi-line `#set page(`; a `//` inside a string hid every slot on the line; `parseStringLiteral` dropped `\n`, `\t`, `\u{...}`. | Trailing empty args dropped before appending; preamble scan is bracket-depth aware; comment detection is string aware; escapes decode. |
| `src/lib/typst-search.ts` | Whole-word wrapped the query in `\b`, so `#set` never matched; `replaceOne` re-ran the regex on the isolated slice, so lookarounds silently did nothing. | `(?<!\w)...(?!\w)` for whole word; replacement runs a sticky regex against the full source at the match offset. |
| `src/lib/typst-source-map.ts` | A stray `(` in prose kept the depth counter above zero, hiding every later design line. | Brackets are counted only inside a region. |
| `src/lib/typst-geometry.ts` | Only `paper:` as a named argument was read; `#set page("us-letter")` fell back to A4. | Positional paper argument accepted. |
| `src/lib/crop-math.ts` | `zoomCrop` clamped width only, so a tall box let the height grow unbounded. | One factor, clamped for both axes. |
| `src/lib/page-history.ts` | "Yesterday" was `now - 24 h`, wrong in the first hour after a DST change. | Calendar arithmetic. |

## Confirmed but still open

These were verified as real and are documented here with the recommended fix
so they can be picked up one at a time. None of them affect correctness of
stored data.

| # | Area | Finding | Recommended fix |
|---|---|---|---|
| 8 | `database.ts` cascades | Cascading deletes and bulk imports issue one Yjs transaction per record. | Wrap the cascade in one `sharedTransact` and let the observer debounce collapse the reloads. |
| 15 | `app-store` | The observer reload also fires for local writes, so each local action costs a duplicate `set()` and a table rescan. | Tag local transactions with an origin and skip the reload when `transaction.origin` is ours. |
| 16 | `GraphCanvas` | Node drag-stop rebuilds every React Flow node object in every open graph tab. | Update only the moved node in the nodes array; keep the others referentially equal. |
| 17 | `yjs-providers.ts`, `workspace-zip.ts` | `getPageYContext` never evicts, and export opens a socket, IndexedDB and PermanentUserData per page, exporting empty bodies for pages that never synced. | Reference-count contexts, destroy on last close; export should await `whenFullySynced` per page and release afterwards. |
| 23 (rest) | `page-snapshots.ts` | `restoreFromState` does not confirm the page editor is collab-bound before the ProseMirror path. | Check for the y-prosemirror plugin state on the view before choosing that path. |
| 25 | `yjs-providers.ts` | Per-page providers are never released and keep reconnecting at 2.5 s, including after the 7-day token expires. | Tie reconnects to auth state; stop on 401/expiry and resume on the next login. |
| 26 | `SplitContainer`, `TypstView` | Every return to the Typst tab recompiles from scratch behind a loading placeholder. | Keep the last render per page in a module cache keyed by source hash. |
| 27 | `shared-doc.ts` | Whole-record LWW: a mirror write can clobber a concurrent field update from another user. | Store text-mirrored fields as their own map entries, or merge the record by field on write-back. |
| 28 | `TypstPreview.tsx` | Two full copies of a base64-image-bearing SVG string, re-parsed into the DOM after every typing pause. | Diff pages by hash and replace only pages whose SVG changed. |
| 29 | `shared-doc.ts` | Time-based ready gates can seed the demo workspace on top of remote state. | Gate on the provider `synced` event (with a generous timeout only as a fallback). |
| 35 | `ai/markdown.tsx` | The full shiki bundle (400+ grammars, 9.2 MB on disk) is reachable from the assistant. | Use `shiki/core` with a short language allowlist, loaded lazily. |
| 36 | `Dockerfile` | Precompression is gzip only. | Add brotli siblings (`.br`) and prefer them when accepted; roughly 3.6 MB less for the compiler download. |
| 38, 39 | `page-history-api.ts`, `history.mjs` | PermanentUserData doubles traffic for deleting keystrokes and grows every page doc; on the twin each deletion costs O(all deletions). | Batch delete-set writes per debounce window; consider attributing on the server from update origins instead. |
| 46 | `backup.mjs` | Backup and the 15 s status poll do synchronous work on the relay's event loop. | Move `VACUUM INTO`, gzip and hashing to a worker; cache the status listing. |
| 48 | `typst-source-map.ts` | Re-normalises the whole document per click. Measured cheap up to ~800 KB. | Memoise the normalised string by source identity if larger reports appear. |
| 52 | `code-theme.ts` + one more plugin | Per-transaction work on selection-only and remote-cursor transactions. | Early-return when `!tr.docChanged`. |
| 53 | `typst-assets.ts` | The 12-entry raw-bytes LRU can evict font bytes, triggering a full compiler rebuild. | Keep fonts out of the LRU (they are few and never re-encoded). |

## Refuted

| Claim | Why it was dropped |
|---|---|
| `TabBar` re-renders every chip on active-tab change because it selects the whole `paneLayout`. | Its `useShallow` selector already includes `activeTabId` and `tabs`; the chips are inline JSX, so the re-render is the intended one. |
| History polling re-encodes and gzips the twin every 30 s and each version click rebuilds a doc synchronously. | The code path exists but the cost is small at real page sizes; the client-side change (fetch the twin only when the version list moved) removes the polling half anyway. |

## How the verification ran

- `tsc -b`, the full Vitest suite (351 tests), `bun build` syntax checks for every edited server module, and a production `vite build`.
- A throwaway server on the built `dist/` confirmed: `index.html` is `no-cache` with an ETag, hashed assets are `immutable`, `.wasm` is `application/wasm`, a 20 KB JSON body gets a 413 and the process stays up, a 3 MB body is refused the same way, invalid JSON is a 400, and `GET /api/cmdlog/query` works with the bound `LIMIT`.
