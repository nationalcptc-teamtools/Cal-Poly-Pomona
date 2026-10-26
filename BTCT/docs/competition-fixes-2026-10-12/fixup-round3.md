# Fix-up round 3 (QA failures of competition-hardening @ d719ad2)

QA ran three suites on the merged branch (backup, export, chaos). This round answers the five backup and export rows. Two of them changed code, two were docs, and the browser flake is reported as not reproduced. Two of the rows also asked for product decisions; those are listed at the end and were not made here.

README.md and CLAUDE.md were updated in the same commit.

## Fresh box restored from another box's ZIP shows the other box's last backup

**What was wrong.** Restored into an empty `/data`, there is no settings table to keep, so `mergeBackupSettings` kept every `backup_*` key from the backup and dropped only `backup_last_result`. `backup_last_good` (added after that rule was written) and `backup_last_run_at` survived. Box B's `GET /api/backup/status` therefore named `btct-backup-20261013-071439.zip`, a ZIP in box A's folder (B's `usage.count` was 0), with A's `lastRunAt`, and B's scheduler counted its next run from A's last one.

**Change.** `server/backup-format.mjs` exports `BACKUP_RUN_HISTORY_KEYS` (`backup_last_result`, `backup_last_good`, `backup_last_run_at`). On a box with no settings of its own, all three are dropped. Config, host token and instance id are still taken from the backup, as before: that is the "new box takes the old box's place" case, and a host scheduler pointed at the new box keeps working. `restore.mjs` now says so in its closing lines:

```
[restore] took the backup's own backup settings, host token and instance id (no settings of this box to keep, so it takes the place of the box that made the backup; regenerate the backup token in the admin panel if that box keeps running) and cleared its run history.
```

A restore onto a box that already has settings is unchanged (it keeps the box's own `backup_*` keys).

**Checked.** `src/test/backup-format.test.ts`: a fresh-box merge deletes exactly `BACKUP_RUN_HISTORY_KEYS` and keeps `backup_enabled`, `backup_token` and `backup_instance_id`. Live, on `btct-qa:hardening` built from this commit: box A seeded with QA's `seed.mjs` (3 users, 3 workspaces, 300 pages, 501 assets, 6006 command-log rows), one manual backup (192 MB, 1091 files, 6.6 s), `restore.mjs <zip> --yes` into an empty bind-mounted data folder, box B started on it with a new `AUTH_SECRET`. On B: `lastRunAt`, `lastSuccessAt`, `lastError` and `lastBackup` all null, `usage.count` 0, `nextRunAt` one interval after boot; config `enabled: true`, interval 60 and the same token and instance id as A (as intended, see below). A manual backup on B then wrote `btct-backup-20261013-080035.zip` into B's folder and status named it.

## Restore and verify timings in the README

Measured again on the instance above (192 MB ZIP), `btct-qa:hardening`, in a container: `restore.mjs --verify` 6.3 and 6.4 s (QA: 6.2 to 6.8 s, peak RSS 162 MB); restore into an empty data folder 18.5 s, 19.7 s with `docker run` start-up (QA: 18.0 s, peak RSS 234 MB). The README now gives "verify 6.2 to 6.8 s, restore 18.0 to 18.5 s". The RSS figures are QA's: the cgroup `memory.peak` I could read counts page cache from the unpack (408 MB for the restore), so it is not comparable.

## Downloads in the same minute share one ZIP name

**Change.** `downloadAsZip` names the ZIP `<stem>_<YYYY-MM-DD_HHMM>_<format>.zip`, where the format tag is the inner file's extension (`zipFormatTag` in `src/lib/download-zip.ts`: lower case, one per distinct extension in order, joined by `-`, empty for a name with no extension or more than three kinds). `exportRootName` takes an optional suffix and keeps the whole name within the 60-byte segment cap. The single-page markdown download passes `md`. The workspace archive and the multi-page notes archive keep their names. Names inside the ZIPs are unchanged, and imports recognise a ZIP by its signature, not its name, so the profile settings import still takes the new name.

| Download | Before | Now |
|---|---|---|
| Report PDF (browser), PDF (server) | `<ws>_<date>.zip` | `<ws>_<date>_pdf.zip` |
| Report SVG | `<ws>_<date>.zip` | `<ws>_<date>_svg.zip` |
| Report DOCX | `<ws>_<date>.zip` | `<ws>_<date>_docx.zip` |
| Command Log CSV / JSON | `command-log_<date>.zip` | `command-log_<date>_csv.zip` / `_json.zip` |
| Profile settings export | `btct-prefs-<user>_<date>.zip` | `btct-prefs-<user>_<date>_json.zip` |
| One page as markdown | `<Title>_<date>.zip` | `<Title>_<date>_md.zip` |
| Oversized paste | `paste_<date>.zip` | `paste_<date>_txt.zip` |

The two PDF buttons still share a name in the same minute: same format, and the browser adds ` (1)`.

**Checked.** `src/test/download-zip.test.ts` (tag after the stamp, a 200-character stem capped to 60 bytes with the tag kept, a bad tag ignored, tags from file lists). QA's `zip-downloads.mjs` on box B (`btct-qa:hardening-full`, `ENABLE_TYPST=1`), Chromium: every name above as listed, members unchanged, prefs import of the new ZIP, of the bare JSON and refusal of a wrong ZIP all as before, no page errors. Firefox: the same up to the paste step, where the probe's synthetic `ClipboardEvent` does not reach the editor in Firefox (a harness limit: QA used `paste.mjs` with the real clipboard for Firefox). `paste.mjs` in Firefox: `paste_2026-10-13_0804_txt.zip` holding the 1,100,000-byte `.txt`.

## Command-log ZIP posted to `/api/cmdlog/import`

No import of a command-log download was added: whether to offer one is a product decision (see below). What changed is the answer to the repro: a body whose `Content-Type` names zip now gets `415` with a sentence saying what the route takes and that the log comes back inside a workspace ZIP, instead of `400 {"error":"invalid json"}`. The body is not read. Checked with curl on box B: a 9-byte and a 20 MB `application/zip` body each answered 415 at once (85 ms for the 20 MB one), a JSON body still answered 200, and `/healthz` stayed 200. Not covered by vitest (`server/cmdlog.mjs` needs `bun:sqlite`); the curl probe is the check.

## Blank page on a fresh Chromium context

Not reproduced. QA's screenshot (`qa3/backup/out/history-chromium-err.png`) is an empty dark page: the app shell never mounted, with no console output captured. On box B, `boot.mjs` with 20 fresh contexts per browser: Chromium 353 to 472 ms to the login form, Firefox 497 to 1319 ms, 0 console errors, page errors or failed requests. No code changed.

## Not done (product decisions)

- **Token and instance id on a fresh-box restore.** B still takes A's host token and instance id, so while both boxes run, A's scheduler token triggers backups on B too. Keeping them makes a move work without touching the host scheduler; minting new ones makes a copy safe to run beside the original. Documented in README (restore section and invariant) and in the restore output; the choice is the owner's.
- **Importing a command-log download** (the ZIP or the bare CSV/JSON) from the Command Log tab. `zip.md` lists it as intentionally absent; the log comes back inside a workspace ZIP.
