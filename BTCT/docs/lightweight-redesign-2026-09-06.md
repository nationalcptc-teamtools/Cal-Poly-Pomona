# Lightweight Operations redesign

Branch: `codex/lightweight-gotham-redesign`

The interface uses compact slate panels, clear borders, system fonts and native CSS. The overview shows the current workspace's notes, narratives, scan groups and attack chains, with links to findings, timeline and reports. The Glass skin, backdrop blur, continuous decorative animations and hover-only tab close controls are removed.

Web recon is retired across the client, server, agent and Docker image. Its routes return 404. Legacy recon records remain available in lossless ZIP exports and full server backups as archive data. Nmap, command capture, graph narratives, notes, history, collaboration, reports and account controls remain.

## Implementation choices

- Keep the existing React, Yjs and editor integrations to preserve collaboration and document compatibility. TypeScript compiles to browser JavaScript; no replacement application framework was added.
- Load note editors, reports, exports, image tools and account panels when opened. Keep preference updates in small modules so setting an accent or shortcut does not load or rebuild the editor.
- Reuse CodeMirror's lazy language grammars for chat syntax highlighting. Remove Shiki and unused direct Mantine, Radix, Dexie and class-variance-authority dependencies. Some Radix packages remain transitively required by the command palette.
- Keep open page and history documents connected, including background app tabs. After the last owner closes, commit an offline snapshot before releasing the connection, IndexedDB provider and Y.Doc. Operation leases protect exports and editor cleanup; failed storage keeps the document in memory.
- Reuse editor decorations on selection-only transactions. Pause history polling and the minute-aligned UTC clock while the browser is hidden. Load AI and MCP SDKs only when those features need them.
- Stop tracking generated `dist/` files. Both the local production build and Docker regenerate the client from source, without stale recon bundles.

## Measurements

Baseline and final client builds were measured on the same Windows device. Startup assets are JavaScript and CSS referenced directly by the generated HTML, including module preloads; gzip sizes use level 9. These are bundle measurements, not a claim about page-load time on every device.

| Measure | Before | After |
| --- | ---: | ---: |
| Startup JS/CSS, gzip | 719,532 bytes | 190,594 bytes |
| Startup JS/CSS, raw | 2,452,609 bytes | 677,861 bytes |
| Startup asset references | 47 | 23 |
| Total generated JavaScript | 13,588,482 bytes | 4,039,212 bytes |
| JavaScript chunks | 493 | 184 |
| Total CSS | 206,208 bytes | 177,645 bytes |

Startup assets are approximately 73% smaller; total JavaScript is approximately 70% smaller. The running Docker image served 191,550 bytes for its 23 startup assets. Its precompression, platform and build context produce slightly different totals from the local build.

The preview container was healthy and used 38.81 MiB with 0.34% CPU in a single post-verification sample, under a 1 GiB memory limit and two-CPU limit. This excludes Docker Desktop's own memory and is not a multi-user load test.

## Verification

- `bun run test`: 392 tests passed across 41 files. New coverage exercises real Yjs and y-indexeddb with fake IndexedDB for offline close/reopen, operation leases, rapid reopen and failed-storage preservation; it also covers grammar highlighting, visibility polling and retired archive remapping.
- `bun run build`: typecheck and production build passed. The Docker production build passed too. The existing large optional editor/report chunks still produce Vite's size advisory.
- HTTP checks passed for health, authenticated login, rejection of unauthenticated profile requests, remaining feature settings and retired recon routes.
- Browser checks passed for login, note editing, close/reopen persistence, persistence after container replacement, diagram zoom/fit, workspace ZIP export (49 page documents), report rendering, report PDF action, named page version creation and the history viewer.
- No browser errors occurred during these checks. Existing ProseMirror virtual-cursor warnings about non-inclusive marks remain.

The preview is available at `http://127.0.0.1:8081` as container `btct-lightweight-preview`, with separate named data and backup volumes. Preview-only credentials are in ignored `.env.preview`. The existing `btct` container and its data were left unchanged.

Start or rebuild:

```sh
docker compose --env-file .env.preview -f docker-compose.preview.yml up -d --build
```

Stop while keeping preview data:

```sh
docker compose --env-file .env.preview -f docker-compose.preview.yml stop
```

## Remaining limits

The optional Typst compiler and renderer still total about 29.3 MB of WebAssembly and load only with reports. Report compilation remains in the browser, and default report fonts are fetched from jsDelivr on first use. AI requests and external MCP client operations were not exercised because the isolated preview has no API key or enabled MCP token. No cloud instance was deployed; the branch and Docker configuration are ready for subsequent deployment.

---

## 2026-09-07: six features removed, and what that bought

Removed outright: web recon (already gone on this branch), the attack-narrative
graph canvas, the Findings Collector, the Attack Timeline, attack chains, and
the in-app Claude assistant together with the hosted MCP server that shared its
tools. Nothing of them survives at runtime: no tab kind, route, repo, store
slice, subscription or `TABLE_NAMES` entry. Their records do survive, in
`src/export/retired.ts`, which reads and writes the old maps straight off the
shared document so a workspace ZIP is still a full archive and still re-imports
into an older build.

Dependencies that left with them: `@xyflow/react`, `@dagrejs/dagre`,
`html-to-image` and `date-fns` (client), `@anthropic-ai/sdk`,
`@modelcontextprotocol/sdk` and `zod` (server). The `chat_sessions` SQLite table
is no longer created.

### Client bundle

Measured with `bun run build` on this branch versus `114a94f`, the commit it
started from.

| | Before | After | Change |
|---|---|---|---|
| Entry chunk | 345.1 KB | 300.2 KB | -13.0% |
| Cold load (every file `index.html` pulls), raw | 661 KB | 581 KB | -12.1% |
| Cold load, gzipped | 186 KB | 169 KB | -9.1% |
| All JS in `dist/assets` | 4293 KB | 3857 KB | -10.2% |
| JS chunks emitted | 184 | 178 | -6 |
| WebAssembly | 28616 KB | 28616 KB | none |

### Server, measured against the 1 GB target

Bun 1.4.2, one server per configuration, same synthetic load applied to each:
20 page rooms opened over the real `/yjs` websocket path, 40 paragraphs typed
into each, so every room also gets its GC-off history twin.

| | Idle | After 20 rooms |
|---|---|---|
| Working set | 49.3 MB | 60.6 MB |
| Idle CPU | 16 ms per 30 s (0.05% of one core) | none |

Twenty concurrently-open pages cost about 11 MB. The server is nowhere near the
1 GB limit and never was: **the constraint on a small box is the browser tab,
not the container.**

### What was tried and did not work

- **`bun --smol`.** Two identical servers, one with the flag, same load: 60.6 MB
  against 61.2 MB. No measurable benefit at this scale, so the flag is not worth
  the CPU it trades. Revisit only if a workload actually approaches the heap
  limit.
- **Turning off Crepe's `Latex` feature.** KaTeX is the single heaviest thing in
  the chunk that loads with the first note, but Milkdown imports it statically:
  the runtime feature flag does not remove it from the bundle. Rebuilding with
  `[Crepe.Feature.Latex]: false` produced a byte-identical `dist`. Reverted, and
  the feature stays on.

### What is still heavy

The Typst compiler and renderer are 29.3 MB of WebAssembly, unchanged and
untouchable without dropping local report compilation. They load only when the
Typst tab is opened, so a session that never opens a report never pays for them,
but on a 1 to 2 GB machine opening one is the largest single memory event in the
app. That is the next thing to look at if the target machine gets tighter.

One more thing worth knowing: a workspace that used to have graphs still carries
those records inside the shared Yjs document, and the whole document syncs to
every client and stays resident on the server. A fresh install carries nothing.
An old one carries its history, deliberately. There is no prune, because for an
archived engagement the document may be the only copy left.

---

## 2026-09-07 (later): the Typst report tab is gone

The report tab, its in-browser compiler, the preview, the whole-document search
panel, the figure-slot machinery and the custom-font path were removed. What
stayed is the part notes actually need: the **Assets** tab, its folder tree, and
the non-destructive crop and redaction editor. Note images were always shared
assets, so pasting a screenshot into a page still uploads it once, still shows
up in the Assets tab, and a redaction is still removable.

Files: `TypstView`, `TypstEditor`, `TypstPreview` and `TypstSearchPanel` are
deleted, along with `lib/typst-compiler`, `typst-language`, `typst-pages`,
`typst-placeholders`, `typst-search`, `typst-source-map` and `typst-geometry`.
`components/typst/` became `components/assets/`, `TypstAssetsPanel` became
`AssetsPanel`, `PlaceScreenshotDialog` became `ImageEditorDialog` (crop and
redact only), `lib/typst-assets.ts` became `lib/assets.ts`, and
`db/typst-asset-repo.ts` became `db/asset-repo.ts`.

The crop frame used to take its shape from the document's page geometry and the
target figure's height. With no document, it takes the **image's own aspect
ratio**, so an untouched asset now opens as the identity crop instead of an
arbitrary letterbox.

Two names deliberately did not change: the shared-doc table `typstAssets` and
the `TypstAsset` type. The table name is persisted CRDT data in every existing
workspace, and renaming the type for tidiness is not worth the churn.

Dependencies dropped: `@myriaddreamin/typst.ts`,
`@myriaddreamin/typst-ts-web-compiler`, `@myriaddreamin/typst-ts-renderer`.

### What it bought

| | Before this pass | After |
|---|---|---|
| `dist/assets` total | 33917 KB | 5054 KB (-85%) |
| WebAssembly | 29.3 MB in 2 files | none |
| All JS | 3857 KB | 3646 KB |
| Entry chunk | 300.2 KB | 298.8 KB |
| Cold load, gzipped | 169 KB | 166 KB |

The wasm was always lazy, so the cold load barely moves. What changes is the
ceiling: opening a report used to instantiate a 28 MB compiler module in the
tab, which was by a wide margin the largest single memory event in the app on a
1 to 2 GB machine. There is no longer anything in the client that can do that.

The Docker image also loses ~29 MB of payload, and the build no longer gzips
28 MB of wasm at image-build time.

### Colour: the interface is neutral grey now

First pass moved `DEFAULT_THEME_COLOR` off the Operations blue `#7db4dc` to
`#6b7280`. That was not enough, and the reason is worth writing down: `#6b7280`
is Tailwind's `gray-500`, which is hue 220. It is a *blue* grey. So was every
surface in the interface: `operations.css` painted the canvas, panels, borders
and hover states at hue 206 to 213, and the sidebar tinted every page row and
every file glyph with `--status-blue`, which is not a status.

All of it is zero-saturation now, at the same lightness values, so contrast is
unchanged:

| Token | Before | After |
|---|---|---|
| `--op-canvas` | `#10161d` | `#171717` |
| `--op-panel` | `#171f28` | `#1f1f1f` |
| `--op-raised` | `#1d2833` | `#292929` |
| `--op-border` | `#2b3947` | `#3b3b3b` |
| `--op-muted` | `#9aabbc` | `#ababab` |
| `--op-text` | `#e2e9f0` | `#e8e8e8` |
| `--op-blue` (now `--op-accent`) | `#7db4dc` | `#adadad` |
| `--op-hover` | `#223140` | `#313131` |
| dark surface HSL | hue 210 to 212, 20 to 31% sat | `0 0%` |
| light `--op-*` | hue 206 to 213 | neutral |
| `DEFAULT_THEME_COLOR` | `#7db4dc` | `#737373` |
| `--ring` fallback | the old signature red | `0 0% 45%` |

The sidebar's page rows used `--status-blue` for their border, background,
active state and file icon. They use `--border`/`--muted`/`--accent` now, with
the account accent marking the active row. `--status-blue` survives in exactly
one place: the Windows glyph on an nmap host, where blue means Windows.

What deliberately keeps its colour: the status palette (red, amber, green,
purple), the code-syntax themes (GitHub-dark for most languages, the terminal
palette for shell and PowerShell) and the editor's text-highlight swatches.
Those carry meaning or are user content. With no brand colour competing with
them, they are now the only hues on screen. Any account can still pick its own
accent in Profile, and the old blue is still in the swatch list.

---

## 2026-09-08: the blur drag was doing 400 renders a second

Drawing a redaction rectangle stuttered, and got worse the more rectangles were
already on the image. Two causes, both in `FigureViewport`:

1. Every `pointermove` called `setState`, so React re-rendered the viewport per
   pointer sample. A mouse reports at 125 to 1000 Hz; a display shows 60. Each
   render restyled two full-size `<img>` elements and re-laid-out one outline
   per committed region, which is why more regions meant more lag.
2. The in-flight rectangle carried `backdrop-filter: blur(6px)` and changed
   size on every one of those samples. A backdrop filter whose geometry moves
   forces the compositor to re-blur everything behind it, and behind it were
   both images plus a 9999px box-shadow overlay.

Both now follow invariant #3c, the rule the pane resizer already used: write
geometry **straight to the DOM, once per animation frame**, and touch React
state only when the gesture ends. The draft rectangle is a permanently mounted
node positioned by hand. The pan and wheel-zoom gestures got the same treatment,
coalescing their `onCropChange` calls to one per frame.

### Measured

A synthetic 400-event drag, timed in jsdom, which does no layout, paint or
compositing at all. The real browser cost was strictly worse than these numbers
on both sides, and the compositor half of cause 2 does not appear here.

| Drag | Before | After |
|---|---|---|
| 400 moves, no existing regions | 387.6 ms (0.97 ms/event), 402 React commits | 29.7 ms (0.074 ms/event), 0 commits |
| 400 moves, 12 existing regions | 1288.3 ms (3.22 ms/event), 402 React commits | 22.1 ms (0.055 ms/event), 0 commits |
| 400-move pan | 400 `onCropChange` calls | 1 per frame |

13x faster on an empty image, 58x with a dozen regions already drawn. At
3.2 ms per event a 60 Hz frame could absorb five samples; a 400 Hz mouse sends
seven per frame, so the queue never drained. That is the stutter.

`src/test/viewport-drag.test.tsx` locks it in by counting work rather than
milliseconds, so it holds on any machine: zero React commits during a blur
drag, no `backdrop-filter` on the draft, fewer crop updates than moves, and the
region still commits with the right geometry. Three of its five assertions fail
against the previous component.

### The one deliberate visual change

The draft rectangle no longer previews a live blur while you drag; it is a
translucent purple wash with a solid border. The real, stronger blur is baked
and shown the instant you release, which is what it always did. Restoring the
live preview means paying the per-frame backdrop re-blur again.

### Looked at and left alone

The sidebar resize (`LeftSidebar`), the note-image resize handle
(`lib/image-resize.ts`) and the editor toolbar's scroll/selection listener
(`PageEditor`) were already writing straight to the DOM or coalescing per
frame. Invariant #8 (never subscribe to the store without a selector) has no
violations. The crop window was the only place that had drifted.

### Candidates not implemented, because they cannot be measured here

Thumbnails in the Assets tab call `resolveAssetBytes`, which bakes a **full
resolution** crop and blur for a card rendered at 150 px. It is cached per
asset and framing, so it costs once, but the first paint of a tab holding a
dozen redacted screenshots does a dozen full-size canvas decodes and keeps a
dozen full-size PNGs in memory, which matters most on exactly the small host
this branch targets. Capping the rendered size for thumbnails is the obvious
fix and probably a large win. It is not done here because jsdom has no canvas:
there is no way to verify it in this environment, and the crop and blur
pipeline is not somewhere to make an unverified change. The same applies to
`loading="lazy"` and `decoding="async"` on the thumbnail images.
