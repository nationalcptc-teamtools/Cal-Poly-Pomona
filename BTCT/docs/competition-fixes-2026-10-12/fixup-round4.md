# Fix-up round 4 (QA failures of competition-hardening @ 93b7a5c)

QA's backup and export suites left three rows. Each one changed code here: an unreadable backup copy now gets a message and exit code of its own, a ZIP sent to the command-log import route is recognised by its bytes as well as its `Content-Type`, and the Report tab retries a capability probe that got no answer. Importing a command-log download is still a product decision and was not added.

README.md and CLAUDE.md were updated in the same commit.

## `--verify` on a copy the image user cannot read

**What was wrong.** A backup ZIP is written mode 0600 by uid 1000. A root `cp` to a USB folder makes a root-owned 0600 copy. The README's off-box command (`docker run ... -v /usb:/backups:ro ... bun restore.mjs --verify`) runs as uid 1000, `openZip` failed with EACCES, and `restore.mjs` closed with "backup failed verification" and exit 2. That is the same exit code and wording as a damaged backup.

**Change.** `server/backup-format.mjs` exports `isAccessError` (EACCES or EPERM). `verifyBackup`, `verifyBackupZip` and `verifyBackupDir` return `{ ok: false, unreadable: true }` with `cannot read <path>: EACCES (running as uid 1000); this says nothing about the backup itself` when the stat, the open, the folder manifest or a folder file is denied. `restore.mjs` then exits 1 (failed) instead of 2 (refused), with:

```
[restore] cannot read the backup copy, so it was not checked; nothing was changed. Make it readable by this user (chown 1000:1000 <file>, or chmod a+r <file> and its folder) and run again.
```

A plain restore takes the same path, because it verifies first. The README says the copy must stay readable by uid 1000 (`cp -p` as the same user, or `chown`/`chmod a+r` a root copy; a FAT or exFAT stick needs nothing), and its exit-code lines (and CLAUDE.md's) list the case under 1.

**Checked.** `src/test/backup-verify-unreadable.test.ts` covers a denied ZIP open, a denied stat (not reported as "no such backup"), a denied folder manifest, and two negative cases: a damaged but readable ZIP and a folder with no manifest stay ordinary failures. The tests run as root in the container, so the denial is made with `vi.spyOn` on `fs`/`fs/promises`. Live, on both rebuilt images: a manual backup copied by root (`-rw------- root root`), then QA's command. `btct-qa:hardening-full` and `btct-qa:hardening` both printed the lines above and exited 1. After `chown 1000:1000` the copy verified OK with exit 0, and the same after `chmod a+r`. A copy with 4 bytes overwritten still printed "backup failed verification" with exit 2. A restore (not `--verify`) of the root copy into a tmpfs `/data` exited 1 with the same message.

## Command-log ZIP sent as `application/octet-stream`

**Change.** `handleCmdlogImport` (`server/cmdlog.mjs`) keeps the first four bytes of the body while `readJsonBody` reads it. When the read fails (invalid JSON, or over the 8 MB limit) and those bytes are a ZIP signature (`startsWithZipSignature` in `server/zip-stream.mjs`: `PK 03 04`, `PK 05 06` or `PK 07 08`), it answers the same 415 as a zip `Content-Type`. On the 8 MB case it also sends `Connection: close`, since the body was not read to the end. A body that is not a ZIP gets the same answer as before.

**Checked.** `src/test/zip-stream.test.ts`: a JSZip archive, an empty archive and the spanned marker match; JSON, `PK`, `PKZZ` and null do not. Live, curl on `btct-qa:hardening-full`:

| Body | Content-Type | Answer |
|---|---|---|
| command-log JSON ZIP | `application/octet-stream` | 415 in 8 ms (was 400 `invalid json`) |
| same | `application/zip`, `application/x-zip-compressed`, curl's default | 415 in 2 to 3 ms |
| 20 MB starting `PK 03 04` | `application/octet-stream` | 415 in 29 ms |
| 20 MB random | `application/octet-stream` | 413 `payload too large`, as before |
| `hello` | `application/octet-stream` | 400 `invalid json`, as before |
| JSON | `application/json` or `application/octet-stream` | 200 |

`/healthz` stayed 200 afterwards and the server logged no errors. `server/cmdlog.mjs` itself still has no vitest (it needs `bun:sqlite`); the curl table is the check for the handler.

## Report tab server export buttons missing once

**Cause, not verified.** QA could not reproduce it and neither could I. The code path QA suspected was real, though. `TypstView` probed `/api/typst/capabilities` once on mount, and `fetchExportCapabilities` turned a network error or any non-ok answer into `{ pdf: false, docx: false }`, so a single lost probe hid both buttons until the tab was remounted. On a fresh box the first probe is also the slowest one. The server answers it only after a Python child has imported pdf2docx (1.3 s on `btct-qa:hardening-full` with `--cpus 1` and a warm page cache, later calls 3 to 4 ms), and `pdf` waits for that too.

**Change.** `src/lib/typst-export-api.ts`: `probeExportCapabilities` returns `{ caps, retry }`. `retry` is set for a network error, a 5xx other than 501, 408, 429, or a 200 whose body is not JSON. A 404 (flag off), 501, 401 or 403 is an answer and is not retried. `loadExportCapabilities(onCaps)` probes and then probes again after 1.5, 3, 6 and 12 s while `retry` is set, and returns a cancel function. `TypstView` calls it from its mount effect. `fetchExportCapabilities` is unchanged for its callers. The README capabilities row describes the retry.

**Checked.** `src/test/typst-export-api.test.ts` has 6 new cases: 200 taken, 404/501/401/403 not retried, network error, 500/502/503/504/408/429 and a non-JSON 200 retried, buttons shown after two failed probes, giving up after the last delay, and nothing called after cancel. Live, with `fix4/pwt/caps-retry.mjs` (Playwright route interception on `btct-qa:hardening-full` with `ENABLE_TYPST=1`, fresh context each run):

| Browser | First probes | Buttons |
|---|---|---|
| Chromium x2 | 2 aborted | shown, third probe 200 (4.6 and 5.3 s after the first) |
| Chromium | 4 answered 503 | shown, fifth probe 200 (22.6 s after the first) |
| Firefox x2 | 1 aborted | shown, second probe 200 (1.7 s after the first) |
| Chromium x3 | untouched | shown 24 ms after the Report toolbar, one probe |
| Chromium | 5 aborted | hidden after 5 probes: the retry gives up, as designed |

The last row is what every run with one failed probe looked like before this change. Whether QA's single failure was a lost or a slow probe is still not known, since its capability response was never captured.

## Not done (product decision)

- **Importing a command-log download** from the Command Log tab (the ZIP, or the bare CSV/JSON). Unchanged from `fixup-round3.md` and `zip.md`: the log comes back inside a workspace ZIP (6005 of 6005 rows in QA's run), and the route now says so for any ZIP body.

## Tests and images

`tsc -b` clean. Vitest: 823 passed, 1 failed (`typst-run-child` "kills grandchildren too", the known environmental failure), 5 skipped. Both QA images were rebuilt from this tree: `btct-qa:hardening` (`WITH_REPORT_BINS=0`, `WITH_TYPST_CLIENT=0`) and `btct-qa:hardening-full`.
