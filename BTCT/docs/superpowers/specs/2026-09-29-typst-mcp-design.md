# Report MCP server (step 3 of the Typst tab): design

Date: 2026-09-29. Branch: `lw-version`. Status: approved design, no code yet. Parked behind the DOCX generality round, which goes first.

This replaces the `mcp.mjs` paragraph of [2026-09-18-typst-tab-design.md](2026-09-18-typst-tab-design.md), which was written before step 2 shipped and before the Word file came to be made from the PDF.

## Purpose

Claude Code on the desktop co-writes the report with the operator: it edits the live source, places screenshots in figure slots, compiles, looks at rendered pages, and exports. The operator watches the Report tab update as it happens and keeps typing. There is no read-only mode.

## Approach

Stateless Streamable HTTP, restored from the MCP server BTCT had before `8a549fb` (static admin token, POST only, no sessions, SDK loaded on the first request), with the report tools from Typst Studio (`advanced-typst-editor/server/mcp-tools.ts`) pointed at the `Y.Text` instead of files.

Rejected: Typst Studio's stateful server (sessions, an SSE stream and a sweep, for server-to-client notifications no report tool needs), and a separate MCP process that joins as a Yjs client (a second copy of the shared doc in memory, its own login, a second thing to deploy).

## Section 1: the write path

**`updateTypstSource(workspaceId, compute)`** in `yjs-data.mjs` is the server twin of `updateYTextContent`: read the live `Y.Text`, call `compute(current)`, write only the changed span inside one `doc.transact`. Every MCP edit goes through it, and the pure slot functions (`setSlotPath`, `setSlotHeight`, `ensureHelper`, `appendSlot`) are the compute functions, so no edit is ever computed from a stale copy. The span diff moves out of `src/realtime/use-y-text.ts` into a pure module that both sides import. Nothing new constructs a Y type, so invariant #6 holds. The `yjs-data.mjs` header ("writes none") and CLAUDE.md invariant #4 are corrected: the server now writes one `Y.Text`, the report source, which has no JSON record behind it.

**Seeding and cold docs.** The server never creates the report's `Y.Text` (invariant #1). When `typst:<ws>:source` is absent, every source tool refuses with "This workspace has no report yet. Open its Report tab once." That also covers a cold doc (persistence off with no browser connected, or LevelDB still loading), because `shared()` waits at most 2 s and an empty doc has no key. With persistence on and nobody connected, writes land in the relay doc and persist like any other update.

**Slot paths.** `ASSET_DIR` and `assetPath` move from `src/lib/assets.ts` (which imports the auth store) into a new pure `src/lib/asset-path.ts`, re-exported by `assets.ts` and imported by the server. A filename reaches the source only through `toStringLiteral`, because an asset record is hostile input (invariant #18).

**Attribution.** MCP edits carry no user. The report has no version history, so nothing depends on one.

## Section 2: the tools

`server/typst/mcp-tools.mjs` is a pure tool table with its dependencies injected. Every tool except `list_workspaces` takes `workspace_id`, checked against the export route's `WORKSPACE_ID` pattern.

| Tool | Input | Returns |
|---|---|---|
| `list_workspaces` | none | id, name, whether it has a report |
| `get_source` | | `{source, slots}` |
| `set_source` | `source`, at most 1 MB | `{slots}` |
| `edit_source` | `old_string`, `new_string`, `replace_all?` | `{replacements, slots}`. Exact literal match; empty `old_string`, 0 matches, or more than 1 without `replace_all` is an error. The replacement is inserted literally (no `$` patterns). |
| `list_slots` | | `findScreenshotSlots` output |
| `add_slot` | `caption` | `ensureHelper` then `appendSlot`; `{slot, slotCount, helperChanged}` |
| `place_image` | `slot_index`, `asset_id`, `height?` | image assets only; path from `assetPath` |
| `clear_slot` | `slot_index` | `{slots}` |
| `set_slot_height` | `slot_index`, `height` or null | `parseLength` (pt, mm, cm, in; greater than 0) |
| `list_assets` | | id, filename, kind, size, crop, blurs, whether the source references it |
| `update_asset` | `asset_id`, `crop?`, `blurs?` | validated the way the client validates; merges into the existing `typstAssets` record only |
| `compile` | | `{ok, diagnostics, warnings}` |
| `render_preview` | `page?` (default 1), `ppi?` (36 to 200, default 110) | an MCP image block plus `{page, pageCount}` |
| `export_pdf`, `export_docx` | | an embedded base64 resource plus `{baked, warnings}` |

Every slot tool re-finds the slot by index inside its compute function, against the live text. `update_asset` cannot create a record or change `filename`, `kind` or `workspaceId`; it is a last-writer-wins merge like every other write to that map, done inside `yjs-data.mjs`.

Not exposed: workspace create, rename or delete; asset upload, font upload or delete; anything that reads or writes a server path (Typst Studio's `upload_asset` `path` and `export_pdf` `to` are an arbitrary read and an arbitrary write); backups.

**One queue.** `exportReport(workspaceId, format)` gains `check` and `png`. All four formats go through `stageReport` and the same admission gate (one running, one waiting), so an MCP call made during an operator's export gets "busy, try again" as an error result. Preview is one typst run with `--format png --pages N --ppi D`. Compile stages the full report, redaction bake included: staging originals for a check whose output is discarded was considered and rejected, because invariant #18 allows no fallback to original bytes and a check-only exception is how one would leak into a preview later. The cost is about 0.25 s per redacted image per call, measured and recorded in step 3's results.

**Caps.** MCP exports are refused above 20 MB (base64 grows by a third and the whole reply sits in the relay process); the error points at the Export button. The reference report's PDF is 1.8 MB. Preview size is bounded by the ppi cap: letter at 200 ppi is 1700 by 2200 px.

**Errors.** An `ExportError` becomes `isError` text, already path-scrubbed and capped by `diagnostics.mjs`. Anything else is logged and returned as "tool failed".

## Section 3: auth, admin, gating, tests

**`server/typst/mcp.mjs`.** Bearer token compared with `timingSafeEqual`; POST only; `sessionIdGenerator: undefined`; 4 MB body cap; one server and transport per request, closed with the response. Settings keys are new: `typst_mcp_enabled` and `typst_mcp_token`. The pre-`8a549fb` keys `mcp_enabled` and `mcp_token` may still exist in old databases with the endpoint enabled, and reusing them would switch it on at upgrade with a token nobody remembers issuing. The token is minted on first enable, returned to admins only, and never mirrored to `settingsPublic` (invariant #11).

**Gating, in order.** `ENABLE_TYPST` off: `/mcp` is 404 and nothing is imported. MCP disabled or no token: 404, indistinguishable from flag off. Bad token: 401. `@modelcontextprotocol/sdk` (^1.30) and `zod` are imported only inside the first authorised request.

**Admin panel.** A "Report MCP" section in `AdminPanel.tsx`, rendered only when `features.typst` is on, following `CmdlogConfigSection`: enable toggle, reveal, copy and regenerate the token, and a copyable `claude mcp add --transport http btct-report <origin>/mcp --header "Authorization: Bearer <token>"`. Routes `GET/POST /api/typst/mcp/config` and `POST /api/typst/mcp/token`, admin only, inside the `/api/typst/` branch so the flag gates them.

**Tests.**
- Vitest, through `.d.mts` declarations: the shared span diff (a concurrent edit on a second doc merges; a relative cursor survives a slot write); `mcp-tools.mjs` with fake dependencies (`edit_source` at 0, 1 and 2 matches and `replace_all`; a missing report key refuses and never creates the `Y.Text`; a slot index re-found against text that changed; `place_image` rejects a font and escapes a hostile filename; `update_asset` validation; the 20 MB cap; queue-busy becomes `isError`); the gate (flag off, disabled, bad token, good token); `typst-import-graph.test.ts` extended so no client module imports the new server files.
- Integration on a throwaway database with the real server and the SDK's own client: `tools/list`; `get_source`, `edit_source`, and an open browser tab showing the edit; `render_preview` returns PNG bytes; `export_docx` unzipped, with a blurred asset's embedded image differing from its upload.
- Container, preview compose (1 GB, 2 CPUs): time and peak RSS of `compile` and `render_preview` on the reference report, and the worst health check during each. Flag-off rows re-measured: entry bundle, idle RSS, zero Typst requests.

**Docs and image.** README feature tour, API rows and MCP setup; CLAUDE.md invariant #4 wording, the new `src/lib` files on the Dockerfile's named `COPY ... /app/src/lib/` line (`asset-path`, `typst-placeholders`, `typst-geometry`, the span diff), the new settings keys; measurements in `docs/typst-tab-2026-09.md`; the SDK's image cost recorded.
