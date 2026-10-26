# Integration of the five fix streams (2026-10-12)

Branch `competition-hardening`, from `competition-crash-fixes` (669ed8f).
Merged with `--no-ff` in this order: `fix/build`, `fix/server`, `fix/backups`,
`fix/client`, `fix/exports`. README.md and CLAUDE.md carry the text from every
stream's notes file; the notes files stay as the record of what was measured.

## Conflicts and how they were resolved

- `server/index.mjs`, `GET /api/settings`: the build stream reports
  `features.typst` from `TYPST_TAB` (flag on and the typst wasm present), the
  backups stream adds `restoreEpoch`. Both kept.
- `src/realtime/shared-doc.ts` imports: the backups stream's
  `restoreEpochParams` and the client stream's connection-status and
  idb-ready imports. Both kept.
- `src/components/sidebar/ProfileEditor.tsx`: the client stream had rewritten
  the file with LF line endings, which made the whole file conflict. Taken
  from the exports side (CRLF, as the file has always been) with the client's
  three-line change (hide the zoom control when CSS zoom is unsupported)
  applied on top.
- `src/lib/assets.ts`: the client's size-capped caches and thumbnails, plus
  the exports stream's `fetchAssetBytesUncached` and `renderAssetBytes`
  (`resolveAssetBytes` now calls `renderAssetBytes`).

## Contract fixes made at merge time

- **Delete entries after an import as new.** The client stream now logs a
  page delete as `{kind:'pageTree', version:1, pages:[...]}`; the exports
  stream's id remap only knew the old single-record shape, so a restore from
  the change log after an import as new would have targeted the original
  workspace's ids. `remapLogValue` in `src/export/import-workspace.ts` now
  remaps every page record inside a `pageTree` snapshot (id, parentId,
  workspace, asset ids in the markdown). Covered by a new case in
  `src/test/workspace-roundtrip.test.ts`.
- **Export readers and the restore epoch.** The exports stream's read-only
  providers (`src/export/page-bodies.ts`) did not send `epoch`, so after any
  restore every export and every import confirmation would have been refused
  with 409. They now pass `restoreEpochParams()`.
- **Backups and the relay drain.** `drainPersistence()` (data-export.mjs)
  returns the result of the server stream's `drain()`, and a backup run logs
  a warning when the relay persistence reports failing writes (a room closed
  during the failure is then only in memory, so its latest edits are not in
  that run).
- **Shutdown budget under compose.** Both compose files pass
  `SHUTDOWN_TIMEOUT_MS=30000`, below their 60 s `stop_grace_period`, now that
  `init: true` ships together with the SIGTERM handler.
- Test mocks of `@/auth/auth-store` in `workspace-roundtrip.test.ts` and
  `live-exports.test.ts` provide `probeSession`, which `shared-doc.ts` calls
  since the client stream.

## Verification

- `bunx tsc -b`: clean. `bunx vitest run` (oven/bun:1.3.14): 746 passed,
  1 failed, 5 skipped (752). The failure is the environment-dependent
  `typst-run-child.test.ts` "kills grandchildren too", present at the base.
  The 5 typst-search failures of the base are fixed (client stream). The 5
  skips are the 4 live-export phases and the base's one skip.
- cmdlog agent: `python3 -m unittest tests.test_matcher tests.test_redactor
  tests.test_shipper_outbox tests.test_spool` from `cmdlog-agent/`: 49 pass.
- `bun build --target=bun --packages=external` passes for every server module
  touched (index, relay-persistence, history, backup, backup-format, restore,
  data-export, scheduler, cmdlog, db, yjs-data, assets, retention).
- Images: `btct-qa:hardening` (`WITH_REPORT_BINS=0 WITH_TYPST_CLIENT=0`)
  276,101,162 B; `btct-qa:hardening-full` (defaults) 996,461,162 B.
- Smoke, `btct-qa:hardening` on port 8140 with tmpfs data: `/healthz` 200
  `{ok, persistence:'ok', freeBytes}`; login; a write to `btct-shared` read
  back on a second connection; a page body written; asset upload and
  byte-identical download; `/assets/Nope-XXXX.js` 404; manual cmdlog entry
  201, a `null` body 400 with the server still up, export count 1;
  `/api/admin/status` 200; backup run with no failed rooms. `docker stop`:
  0.59 s, exit 0, log "stopped in 12 ms (clean)". Docker health `healthy`.
- Reimport onto a new box: `bun restore.mjs --verify` exit 0, then a restore
  into an empty named volume (exit 0, 2 rooms read back, 1 asset, 1 twin) and
  a server on it with a NEW `AUTH_SECRET`: the original password logs in (the
  users table came from the backup), workspace and page records, the page
  body, the asset bytes, the command log (1 row), the version list (1, twin
  present) and the twin route (200) all came back, a client without the new
  restore epoch was refused, and `docker stop` took 0.56 s with exit 0.
- `btct-qa:hardening-full` with `ENABLE_TYPST=1`: `features.typst` true and
  the typst wasm served as `application/wasm`. `btct-qa:hardening` with
  `ENABLE_TYPST=1`: `features.typst` false and the boot warning logged.

## Left open

- The admin-panel banner for `GET /api/admin/status` (persistence failing,
  low disk) was not built by any stream; the data is there.
- `shared()` in `server/yjs-data.mjs` still polls up to 2 s on a server whose
  shared doc has no workspace yet, so the first cmdlog ingests there are
  slow (build stream's side finding).
- No browser was driven against the merged build; each stream's browser QA
  ran on its own branch.
