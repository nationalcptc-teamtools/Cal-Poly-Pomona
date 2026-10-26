# CLAUDE.md
WHEN PUSHING TO GITHUB NEVER ADD CLAUDE AS CO AUTHOR AND ANY EVIDENCE OF IT BEING A AUTHOR OR CO CONTRIBUTOR OR AUTHOR REMOVE CLAUDE AS AN AUTHOR.

BTCT ("Been There, Conquered That") is a real-time, multi-user pentest note-taking app: collaborative markdown pages, nmap import, team command capture and shared screenshot assets. Runtime is **Bun** everywhere; it ships as one Docker image and is built for a small box (1 to 2 GB RAM, 1 to 2 cores), so a feature that costs steady memory or CPU has to earn it. There is no database in the usual sense: data lives in Yjs CRDT documents relayed by a thin Bun server. Architecture and full invariant text: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). User-facing docs: [README.md](README.md).

## Keep the docs in sync

Update `README.md` (user-facing) and `docs/ARCHITECTURE.md` (detail) in the same change. Touch this file only when a command or a one-line invariant changes.

## Writing style for generated prose

**Never use em dashes (`—`) in anything you write.** Not in docs, not in commit messages, not in code comments, not in PR descriptions, not in the blog. An em dash is almost always a decision that got skipped, so make the decision instead:

| Instead of | Use |
|---|---|
| `Notes went in Word — five operators, five documents` | a full stop: `Notes went in Word. Five operators, five documents` |
| `- **Term** — definition` | a colon: `- **Term**: definition` |
| `read — and, when allowed, edit — the workspace` | parentheses: `read (and, when allowed, edit) the workspace` |
| `it renders offline — no network calls` | a comma: `it renders offline, with no network calls` |
| a table cell containing only `—` | `none` |

En dashes are fine in real ranges (`H1–H3`, `3–32`) and inside literal UI strings you are quoting. Run `grep -c '—' <file>` before you call a doc change done. It should be `0` everywhere; the table just above is the only deliberate exception in this repo, because it has to quote the character to name it.

Related habits worth keeping: skip the ban-list words (seamless, leverage, robust, comprehensive, delve, unlock, supercharge), do not bold every feature noun, and vary sentence length instead of writing everything at 20 words.

For anything under `blog/`, read the style notes in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#writing-for-blog) first.

## Commands

- Tests (always in the container, from the repo root): `docker run --rm -v "$PWD":/app -w /app -v <nm-volume>:/app/node_modules oven/bun:1.3.14 sh -c 'bun install --frozen-lockfile; bun x vitest run <file>'` (`<nm-volume>`: any named docker volume, one per worktree, so `node_modules` stays off the checkout). Known failure: "kills grandchildren too".
- Typecheck: `bun x tsc -b`. Build (typecheck + bundle): `bun run build`.
- Typst gate after a build: `grep -l typst_ts_web_compiler dist/assets/index-*.js` must print nothing (invariant 17).
- The `.mjs` server is not covered by `tsc`; check syntax with `bun build ./server/<file>.mjs --target=bun --external '<npm deps>' --outfile /tmp/x.js`.
- Health: `curl 127.0.0.1:8080/healthz` (use `127.0.0.1`, not `localhost`).
- Run the real app: `docker compose up -d --build` (needs `AUTH_SECRET` in `.env`). Update a deployed box: `btct update`.
- Dev: `bun run dev` (client) and `cd server && bun run dev` (needs `AUTH_SECRET`, `YPERSISTENCE=./data/yjs`).
- Full command detail (installer, backups, competition day, converter scoring, Dockerfile COPY rules): [docs/ARCHITECTURE.md#commands](docs/ARCHITECTURE.md#commands).

## Critical invariants

One line each; full text and the reason behind each: [docs/ARCHITECTURE.md#critical-invariants](docs/ARCHITECTURE.md#critical-invariants).

1. Pre-seed `Y.Text`s in every repo `create()`; a new collaborative field touches `TEXT_FIELDS_BY_ENTITY`, `TEXT_FIELD_TO_TABLE`, the repo and `useYTextInput` (`src/realtime/shared-doc.ts`).
2. Read the JSON record, not the `Y.Text`; only the editor/input layer touches `texts`.
3. Never rebuild the editor to apply settings; use module-level refs and CSS vars (`src/lib/editor-keybinds.ts`).
3b. Programmatic `Y.Text` rewrites use `replaceYTextContent` (minimal delta), never clear-and-reinsert (`src/realtime/use-y-text.ts`).
3c. A drag writes to the DOM once per animation frame and commits to React state only on pointer-up (`src/lib/pane-resize.ts`).
4. Keep the server dumb about domain data; the five named exceptions are in the full text (`server/yjs-data.mjs`).
4b. Never put binary content in the shared doc; upload it and reference it by id (`server/assets.mjs`).
4c. Live page docs are GC-on, history twins are GC-off, and twin files never pass through y-leveldb (`server/history.mjs`).
5. DB migrations are idempotent; guard every `ALTER TABLE` with a `PRAGMA table_info` check (`server/db.mjs`).
6. Load `yjs` on the server via CJS `require('yjs')`, never `import`, or Yjs is loaded twice (`server/*.mjs`).
7. Deletes cascade in one transaction and log a snapshot of every removed record (`src/db/`, `src/lib/change-log-policy.ts`).
8. Subscribe to the store with a selector, never bare `useAppStore()` (`src/stores/app-store.ts`).
9. Password hashing is async (`crypto.pbkdf2`) and stays off the event loop (`server/auth.mjs`).
10. Batch CRDT and SQLite writes: one `sharedTransact`, one `db.transaction` (`server/db.mjs`).
11. Never put secrets in `settingsPublic`; it is mirrored to every client (`server/index.mjs`).
12. Never copy the live SQLite file or LevelDB directory; go through `server/data-export.mjs`.
13. A skin must not create stacking contexts on the rails or the content column, and never resets `transform` on `*` (`src/themes/`).
14. No native browser dialogs; use the shared Dialog and `ConfirmDialog`, and native controls follow the theme (`src/components/ui/`).
14b. One token source, no hard-coded colours, radii, fonts or pixel sizes (`src/themes/tokens.css`, `src/test/tokens.test.ts`).
15. Tabs reconcile against the shared doc and the active pane is always a live leaf (`reconcileTabs`, `reconcileActive` in `src/stores/app-store.ts`).
16. Bulk record creation outside the repos must call `seedMissingYTexts(getSharedDoc())` (`src/realtime/shared-doc.ts`).
17. The Typst tab stays unreachable from the entry bundle: lazy imports and `features.typst` gating (`src/components/typst/`).
18. Server export treats report text and every `typstAssets` record as hostile input (`server/typst/`).
19. Interface zoom is CSS `zoom` on `<html>`; size against the viewport with that in mind (`src/lib/ui-zoom.ts`).
20. A relay room answers its first sync only after its stored state has loaded (`doc.whenLoaded`, `server/relay-persistence.mjs`).
21. Await every route handler and never let a request exit the process (`server/index.mjs`).
22. Relay persistence is `server/relay-persistence.mjs`, never y-websocket's own binding.
23. The server stops on SIGTERM/SIGINT via `shutdown()`: close rooms, drain LevelDB, close SQLite, exit 0 (`server/index.mjs`).
24. An unparseable history twin is moved aside (`.ydoc.corrupt-<ts>`), never overwritten (`server/history.mjs`).
25. Health checks test the status line (`' 200 '`), not the body; never track `.env` or key material (`Dockerfile`, compose).
26. A backup run is one streamed, fsynced, renamed `.zip.tmp` in a fixed read order (`server/backup.mjs`).
27. A restore that rolls rooms back writes a new `restore_epoch`, and every client honours it (`src/realtime/restore-epoch.ts`).
28. Only the client whose transaction changed a `Y.Text` writes it back to the record, and only that field (`src/stores/shared-bindings.ts`).
29. Log out only on 401/403; use `whenIdbLoaded`, never y-indexeddb's `whenSynced` (`src/realtime/idb-ready.ts`).
30. Workspace import and export: every download goes through `downloadBlob` (`src/lib/download.ts`, `src/export/`).
31. Default accounts are created, never changed (`ensureSeedAccounts`, `server/seed-accounts.mjs`).
32. A session token never goes in a URL; plain-link downloads use a one-time ticket (`signTicket`/`redeemTicket` in `server/auth.mjs`).
33. Live preview decorations never write to the document (`src/components/editor/live-preview/`).
34. The report preview's lock and find are one operator's view, never shared state (`src/lib/preview-lock.ts`).
35. An asset link (`btct-asset:<id>`) is resolved where it is pasted, never stored (`src/lib/asset-link.ts`).
36. The finding block's arguments are named only in `src/lib/typst-finding-schema.ts`.

## How to work here

- Plan in the main session. Implement through Sonnet subagents, each with a self-contained brief: files it owns, interfaces it must keep, what is out of scope, and the failing test that proves the change.
- Review with a fresh reviewer that did not write the code.
- A bug claim needs a reproducer first: a failing test or command, before any fix.
- No two agents edit the same file. Implementers never edit README.md, CLAUDE.md or docs/ARCHITECTURE.md; the main session integrates the docs.
- If docs/brain/ exists, start at docs/brain/INDEX.md (optional; the repo works without it).
