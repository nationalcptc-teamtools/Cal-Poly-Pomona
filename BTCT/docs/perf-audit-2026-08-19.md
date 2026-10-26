# Performance audit and fixes, 2026-08-19

A CPU/memory pass over the whole app (client data layer, React components,
Bun server). Each finding was verified against the source before any change,
and the load-bearing numbers were benchmarked rather than estimated. This
document records what was found, what was fixed, and the measurements.

Baseline test state is unchanged by this work: 270 passing, with the two
pre-existing failures (`pane-layout` "moveTab to center" and `highlight-plugin`
"ToggleHighlight command") still the only reds.

## How the numbers were taken

- Client benchmarks use the repo's own `yjs` build so update sizes reflect
  what actually crosses the wire. Script kept at
  `scratchpad/perf-bench.mjs` for re-runs.
- Server benchmarks import the real `server/db.mjs` against a throwaway
  SQLite file and use `crypto` directly for the hash timing.
- Hardware-dependent absolute times (hashing, sort cost) will vary; the
  ratios are the durable result.

## Headline measurements

| What | Before | After | Note |
|---|---|---|---|
| Page-record body re-broadcast while typing | ~2.32 MB/min/user | ~238 KB/min/user | ~10x less sync traffic (40 KB body) |
| 300-node auto-layout write | 300 update messages, 8.1 ms | 1 update message, 1.4 ms | one Yjs transaction |
| cmdlog batch ingest (200 records) | 13.1 ms, 200 fsync'd txns | 2.1 ms, 1 txn | 6.2x, one WAL commit |
| Login PBKDF2 (200k iters) | ~25 ms on the event loop | off-thread | relay stays responsive under a login flood |
| changeLogs reload on content save | every ~1 s while typing | once per page per minute | 2.4 ms scan+sort no longer per keystroke |

## Client: data layer

**1. Page body re-broadcast every 400 ms of typing (fixed).** The debounced
`updatePage({ content })` re-encoded the whole `Page` record (body included)
into a Yjs update, broadcast to server and every peer, on a 400 ms idle
debounce. The record copy is only a cold-start/export mirror; the live body
is the per-page Y.Doc. Changed the cadence to 2 s idle with a 10 s ceiling
(`src/components/editor/PageEditor.tsx`), and the unmount flush still catches
page switches. Measured 40 KB body: ~2.32 MB/min/user of redundant sync
dropped to ~238 KB/min/user.

**2. changeLogs grew unbounded and re-sorted on every write (fixed).** Each
400 ms save also appended an "Updated page content" change-log entry to the
shared `changeLogs` map, whose reload path scans + sorts the whole table.
Coalesced content-save logging to one entry per page per minute
(`src/stores/app-store.ts`). At 10k entries the reload is 2.4 ms; it no
longer runs every second while typing. (Retention capping of the CRDT table
itself is noted below as not-yet-done.)

**3. Nine components subscribed to the whole store (fixed).** Selectorless
`useAppStore()` snapshots the entire state, whose identity changes on every
`set()`, so all nine re-rendered on any store write. Replaced with
`useShallow` field selectors in `App.tsx`, `LeftSidebar`, `TabBar`,
`RightSidebar`, `NmapScanView`, `CommandPalette`, `WorkspaceSelector`,
`ExportDialog`. (The dead `MainContent.tsx` was left alone.) This is the
multiplier that turned every other write into a full-tree render.

**4. Per-page Yjs auth listener leaked on reconnect (fixed).** The
`useAuthStore.subscribe` that keeps awareness fresh was torn down on
`connection-close`, which fires on every transient disconnect, so after the
first reconnect the refresh was silently gone (and for a socket that never
connected, the subscription leaked). Moved teardown to context disposal
(`src/realtime/yjs-providers.ts`).

**5. Linked-node label mirror ran per keystroke (fixed).** Typing a page
title wrote the linked graph node's label record on every keystroke (a full
record rewrite plus a store-wide graph reload). Debounced to 500 ms
(`src/components/editor/PageEditor.tsx`); the collaborative value already
flows through the node's own Y.Text.

**6. nmapMachines reload was O(scans) per change (fixed).** Any machine
change reloaded every known scan (S table scans, S array copies, S store
writes). `subscribeTable` now passes the Yjs event's changed keys, and the
binding reloads only the scans whose machines actually changed
(`src/realtime/shared-doc.ts`, `src/stores/shared-bindings.ts`). Also removed
the dead `open` set the handler built and discarded.

**7. Auto-layout / drag position writes were N transactions (fixed).** A
300-node layout issued 300 Yjs updates and 300 store notifications. Added
`updateGraphNodePositions` (`src/stores/app-store.ts`) that wraps the writes
in one `sharedTransact` and does one store `set`; used by drag-stop and
auto-layout in `GraphCanvas.tsx`. Measured: 300 messages/8.1 ms to 1
message/1.4 ms.

**8. `Where.first()` re-scanned on reversed queries (fixed).** The reversed
branch called `collect()` (full scan + array build) from inside the loop.
Rewritten to a single pass tracking the last match
(`src/db/database.ts`). Latent (no current reversed caller) but removed.

## Client: React components

**9. Split-pane drag wrote the store on every mousemove (fixed).** Each
mousemove produced a new `paneLayout`, which triggered the synchronous
`localStorage` persist and re-rendered every mounted tab view (Milkdown,
React Flow, Typst), plus a forced reflow from `getBoundingClientRect`.
Rewrote to write `style.width/height` inside a rAF during the drag and commit
the ratio once on mouseup (`src/components/ui/SplitContainer.tsx`), the same
pattern TypstView already uses. This was the single hottest UI path.

**10. AI chat re-rendered and force-scrolled per streamed token (fixed).**
`setPhase({ kind: 'idle' })` minted a new object per token (re-render on a
no-op), and the auto-scroll effect listed the `phase` object in its deps so
it read `scrollHeight` and scrolled per token. Changed to a functional
`setPhase` that keeps the same object when already idle, and keyed the scroll
effect on `phase.kind` (`src/components/ai/AiAssistant.tsx`).

**11. PageEditor fallback subscribed to the whole store (fixed).** For
graph-node pages, `useAppStore.subscribe(refetch)` did a repo read + setState
on every store event, including the editor's own content save. Scoped the
subscription to fire only when `state.pages` identity changes
(`src/components/editor/PageEditor.tsx`).

**12. FloatingFormatPanel queued an unguarded rAF per event (fixed).** A
capture-phase scroll listener (fires for every scroller) plus `selectionchange`
(every caret move) each queued a `requestAnimationFrame(update)` that reads
layout. Added a single pending-frame guard (`src/components/editor/PageEditor.tsx`).

**13. TypstSearchPanel rescanned the document per keystroke (fixed).**
`searchAll` was memoized on `source`, which changes on every character typed
in the editor, so the whole document was rescanned while the panel was open;
result rows also got a fresh `onClick` closure each render, defeating the row
memo. Debounced the searched `source` (150 ms) and passed a stable
`onSelect(index)` (`src/components/typst/TypstSearchPanel.tsx`).

**14. TypstView mirrored the whole source per keystroke (fixed).** The
`ytext.observe` handler did an O(document) `toString()` into React state per
character, re-rendering three panels. Coalesced into one trailing update per
~120 ms; every downstream consumer (compile, slot scan, search) already
debounces further (`src/components/typst/TypstView.tsx`).

**15. CommandLogView rendered the full archive unmemoized (fixed).** Rows
were inline (not a memoized child) and `operatorColor` (a char-loop hash) ran
twice per row per render over up to 5000 rows. Extracted a memoized `LogRow`,
cached `operatorColor` by name, and capped the rendered slice at 400 with a
"showing N of M" note (`src/components/cmdlog/CommandLogView.tsx`). Also fixed
a correctness bug found here: the "last 24h" window froze `Date.now()` inside
a memo at mount, so it never advanced; it now ticks every 30 s.

**16. AttackTimeline reloaded on any graph array identity change (fixed).**
The load effect depended on the `graphs` array, so a graph rename (Y.Text,
per keystroke) re-ran five `getAllByType` reads plus a `getByGraph` per graph.
Keyed the effect on a sorted id list; names are still picked up live by the
memo (`src/components/findings/AttackTimeline.tsx`).

**17. PageHistoryPanel polled every 5 s (fixed).** The poll called `setSnaps`
with a fresh array every tick, re-rendering forever regardless of change.
Replaced with a `pageSnapshots` table subscription so it refreshes only on an
actual change (`src/components/sidebar/PageHistoryPanel.tsx`).

**18. NmapScanView resolved links O(machines x nodes) (fixed).** The machine
grid did `graphNodes.find` and `graphs.find` per card. Added `nodeById` /
`graphById` lookup maps (`src/components/nmap/NmapScanView.tsx`).

**19. Graph PNG export could allocate an oversized canvas (fixed).** At
`pixelRatio: 4`, a 4000x3000 graph backs an ~8000x6000 bitmap (~192 MB) and
can hit the browser canvas limit or crash the tab. Clamped the ratio so the
longest exported side stays under 8192px, keeping 4x for normal graphs
(`src/components/graph/GraphCanvas.tsx`).

## Server (Bun, `.mjs`)

**20. Login blocked the event loop, unthrottled (fixed).** `verifyPassword`
ran `crypto.pbkdf2Sync` (200k iterations, ~25 ms measured here) on the main
thread, which also runs the Yjs relay, so a login flood against a known
username (the bootstrap `admin` always qualifies) stalled every editor.
Switched hashing to async `crypto.pbkdf2` (libuv threadpool) in
`server/auth.mjs` and awaited it at all call sites, and added a per
username+IP failed-attempt throttle (10 / minute, returns 429) in
`server/index.mjs`. Verified: the loop stayed responsive during 8 concurrent
async hashes; the throttle returns 429 after 10 bad attempts.

**21. Static assets served uncompressed (fixed).** The main bundle is ~2.4 MB
raw (~730 KB gzipped, 3.3x) and the Typst wasm is ~28 MB (~11 MB gzipped),
shipped raw on every cold load. The Dockerfile now precompresses compressible
files at build time, and `tryServeStatic` serves the `.gz` sibling when the
client accepts gzip (`Dockerfile`, `server/index.mjs`). Compressing ahead of
time keeps that CPU off the relay's event loop; plain local runs fall through
to the raw file.

**22. Static serving had no validator (fixed).** Added an mtime+size ETag and
`If-None-Match` handling so `index.html` and any non-hashed file revalidate
with a 304 instead of a full re-download (`server/index.mjs`). Verified: a
conditional GET returns 304.

**23. cmdlog batch ingest = 200 fsync'd transactions + 200 redundant SELECTs
(fixed).** `records.map(upsertCommandLog)` ran each upsert as its own implicit
transaction, and Bun's SQLite stayed at `synchronous = FULL` (confirmed), so a
full 200-record batch was 200 fsyncs. Added `PRAGMA synchronous = NORMAL` (the
recommended WAL pairing) and an `upsertCommandLogBatch` wrapped in one
`db.transaction` (`server/db.mjs`, called from `server/cmdlog.mjs`). Measured:
13.1 ms to 2.1 ms (6.2x). The per-record second SELECT to return the merged
row remains; it is cheap relative to the commit and left for a later
`RETURNING *` pass.

**24. cmdlog query recompiled SQL per request (fixed).** `queryCommandLogs`
was the one query using `db.prepare` per call; switched to `db.query`, which
caches the compiled statement by SQL text (`server/db.mjs`). Cursor pagination
for the 5000-row "full archive" path is noted below as not-yet-done.

**25. AI chat: per-request client, no abort, unbounded transcript (fixed).**
`new Anthropic()` was built per request (no connection reuse); there was no
`res.on('close')`, so a browser that aborted the SSE stream left the 12-round
loop calling the API and, in edit mode, writing the CRDT to a dead socket;
and tool results were fed back uncapped. Added a per-key client cache, an
abort flag from `res.on('close')` that stops the loop and aborts the live
stream, and a 100 KB cap on tool-result payloads (`server/ai.mjs`).

**26. MCP rebuilt every zod schema per request; unbounded body (fixed).**
`buildServer` rebuilt ~100 zod objects through `toZodShape` on every JSON-RPC
request. Memoized `toZodShape` by schema identity (a `WeakMap` over the
immutable tool defs), and capped the request body at 4 MB while concatenating
as buffers (a `string +=` loop could split a multi-byte UTF-8 sequence across
a chunk boundary and corrupt the JSON) (`server/mcp.mjs`).

**27. Smaller server items (fixed).** `pruneCommandLogs` now early-returns when
the live map is under cap instead of materializing and sorting every batch;
`shared()` caches its resolved doc handles per doc instance so helpers stop
re-paying the 2 s cold-doc populate poll; `nextPosition` counts by iterating
instead of building a full node array (was O(N^2) over an AI create loop);
`saveChatSession` runs the prune subquery only when the session count actually
exceeds the cap. All in `server/db.mjs` / `server/yjs-data.mjs`.

## Verified-clean (checked, not changed)

Both auditors confirmed these are already mitigated, to avoid churn: shiki
uses a singleton highlighter and CodeBlock debounces; completed chat messages
are memoized on exact text; `TypstEditor` never remounts on parent state and
its collab binding survives pane drags; `TypstAssetsPanel` debounces its slot
scan, memoizes cards, and revokes object URLs; asset-download cache headers
are correct (`immutable`); `timingSafeEqual` is used correctly in all three
gates; the Yjs relay encodes each update once and fans out the same buffer; no
leaked listeners, observers, timers, or object URLs anywhere in
`src/components`.

## Not done (would change behavior or need a policy decision)

Left deliberately, each because it changes user-visible behavior or needs a
retention/eviction policy the maintainer should choose:

- **CRDT table capping.** `changeLogs`, `commandLogs` tombstones, and page
  snapshots accumulate in the shared doc for the workspace's life. Capping is
  a retention decision, and every connecting client syncs the history.
- **Per-page Yjs context eviction.** Contexts (with a live WebSocket each) are
  cached until logout; a long session opening many pages keeps them all
  resident. Needs an LRU eviction policy; revisiting an evicted page would
  re-sync from IndexedDB rather than being instant.
- **WebSocket backpressure / `maxPayload`.** No cap or backpressure today;
  adding one drops slow clients, so it is a policy call.
- **cmdlog cursor pagination.** The "full archive" view fetches up to 5000
  rows and `JSON.stringify`s them on the event loop; real pagination changes
  the client contract.
- **GraphCanvas identity-preserving node/edge diff.** Rebuilding every node
  `data` object on any graph change defeats the React Flow memo; a diff needs
  care around the `skipNextNodesSync` flag.
