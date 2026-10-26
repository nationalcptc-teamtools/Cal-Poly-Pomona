# Merge of fix/bugs2 and fix/zip2 into competition-hardening

Both branches were merged with `--no-ff`, fix/bugs2 first (clean), then
fix/zip2 (conflicts in `server/restore.mjs`, `README.md` and `CLAUDE.md`).
`server/backup.mjs`, `server/index.mjs` and the Dockerfile merged on their
own; the result was checked by hand:

- `writeRun` streams into the ZIP (zip2) and still treats a run that is on
  disk as a success when SQLite cannot record it, then prunes (bugs2). The
  warning now names the `.zip` file.
- The Dockerfile copies both new server modules, `zip-stream.mjs` and
  `restore-checks.mjs`.

## The one real conflict: payload checks on a ZIP

fix/bugs2 made `restore.mjs` decode every payload (`checkBackupPayloads` in
`server/restore-checks.mjs`) right after the hash check. It read
`sqlite/data.sqlite.gz` and `yjs/<room>.yupdate.gz` from the run folder.
After the zip2 merge that folder is `<data>/.restore-unpack` for a ZIP, which
does not exist yet at that point (it is filled later, and only for a real
restore), so every ZIP would have failed the check.

Fix: `checkBackupPayloads` is now async and takes an injected `read(rel)`.
For a folder run it reads `<dir>/<rel>` as before. For a ZIP, `restore.mjs`
opens the archive with `openZip` and passes `zipMemberReader(zip)`, which
reads each member in place (CRC32 and size checked by the reader). Nothing
is unpacked and nothing under `/data` is written, so `--verify` on a ZIP
stays read-only. `checkSqliteSnapshot` takes the gzipped bytes (`gz`) as an
alternative to a path. Memory is the same as before: the snapshot was
already read whole to gunzip it.

Tests: `src/test/restore-checks.test.ts` gains two ZIP cases written with
the real `ZipWriter` and read with `openZip`: good members decode, and bad
SQLite, a bad room and a member the archive lacks are all named.

## Docs

README and CLAUDE.md keep both sides: ZIP layout, unpack and keep-last from
zip2; payload checks, the `fcntl(F_GETLK)` lock probe, real refusal status
lines and the "complete run stays a success" rule from bugs2. Invariant 43
(README) and 26 (CLAUDE.md) say that `--verify` reads a ZIP in place. The
README restore timings (verify 4.9 s, restore 16.7 s on the 192 MB ZIP) were
measured before the payload checks existed and now say so; they were not
measured again. (Measured again in `fixup-round3.md`: verify 6.2 to 6.8 s, restore
18.0 to 18.5 s; README updated.)

## Verification

- `bunx tsc -b` clean; `bunx vitest run` 806 passed, 1 failed
  (typst-run-child "kills grandchildren too", the known environmental
  failure), 5 skipped.
- Images rebuilt: `btct-qa:hardening` (WITH_REPORT_BINS=0,
  WITH_TYPST_CLIENT=0) and `btct-qa:hardening-full`.
- Smoke on port 8140 with `btct-qa:hardening-full` (tmpfs `/data`):
  healthz 200, login, a Yjs write and read back over the relay, a manual
  backup wrote exactly one `btct-backup-<stamp>.zip` (mode 0600),
  `restore.mjs --verify` on it exited 0. Two hand-made ZIPs with matching
  hashes but a random room update or a random SQLite snapshot each exited 2
  with the member named. A real restore of the good ZIP into an empty data
  folder exited 0 ("each read back"). A Playwright Chromium run of
  Export / Import, Full Workspace downloaded
  `ACME Corp Engagement_<date>.zip` (starts with `PK`, no page errors).
- `btct-qa:hardening` on port 8140: healthz, a manual backup to one `.zip`,
  and `--verify` printed OK (its exit code was not captured).
- Not verified here: a server booted on the restored data, the other ZIP
  downloads in the browser, and the large 500-screenshot fixture. Those were
  covered by the stream runs on the unmerged branches only.
