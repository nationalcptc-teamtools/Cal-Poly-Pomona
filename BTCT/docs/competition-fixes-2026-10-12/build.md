# Build stream: image, compose, repo hygiene and the cmdlog agent (2026-10-12)

Branch `fix/build`, based on `competition-crash-fixes` (669ed8f). Audit ids are
from `/home/user/btct-audit-2026-10-12/all.json`. Every change below was built
and smoke-tested in throwaway containers; the measurements are at the end.

## What changed, by commit

### 1. Secrets and stray files out of git (BLT-12, BLT-13)

- `.env` (it held a real `AUTH_SECRET`) and `tls/cert.pem` + `tls/key.pem`
  (a private key nothing uses) are no longer tracked. `.gitignore` now ignores
  `.env` and `.env.*` (keeping `!.env.example` and `!.env.docker.example`),
  `tls/` and `*.pem`. `.dockerignore` adds `tls`, `*.pem`, `.__*` and `testxml`.
- Deleted: `build.log`, `tsc-out.txt`, `testxml/`, `.__geo/`, `.__out.svg`,
  the empty `src/api/client.ts`, and committed Python bytecode under
  `cmdlog-agent/**/__pycache__/`. Ignore rules stop them coming back.
- Not done (needs a decision, BLT-13b and BLT-11): moving `reports/` and
  `research_notes/`, dropping stale blog images, and purging `.env` and
  `tls/key.pem` from history (a force push).

**Merge warning.** Pulling a commit that untracks `.env` makes git delete an
unmodified working copy of it, and refuse the pull when the copy is modified.
The live box builds from `/home/user/BTCT-latest`, whose `.env` is locally
modified (` M .env`). Before that checkout takes this branch, copy its `.env`
aside (`cp -p .env /root/btct.env.keep`), merge, and put it back. The value in
it may be the committed one: check without printing it
(`git log -p --all -- .env | grep -c "$(grep ^AUTH_SECRET= .env)"` must be 0)
and rotate if it is not. Rotating logs everyone out.

### 2. `install-btct.sh` never keeps a public secret

- Step 5 writes a fresh `AUTH_SECRET` when `.env` is missing, has none, holds
  the `.env.docker.example` placeholder, or holds any value that ever appeared
  in `git log -p --all -- .env` (compared with `grep -qxF` on a here-string,
  never printed; quotes and CR stripped the way compose reads them). Other
  keys in `.env` are kept. `.env` is always left mode 600.
- The update path (an existing clone in `$BTCT_DIR`) sets a tracked `.env`
  aside before `git pull` and puts it back after, so the untracking commit
  neither blocks the pull nor deletes the file.
- `git` runs with `-c safe.directory=$APP_DIR`, so a root run in a user-owned
  clone still reads history.
- Tested in a scratch repo: committed value, rerun (idempotent), quoted
  committed value, private value, missing file, placeholder, not a git
  checkout, and the pull that untracks `.env` with a local edit.

`Start-BTCT.ps1` got the same rule (and a `RandomNumberGenerator` secret
instead of `Get-Random`); `-Update` sets a tracked `.env` aside around the
pull. Tested in a `mcr.microsoft.com/powershell` container.

### 3. Dependencies declared, dead code removed (BLT-10, BLT-3, BLT-16)

- `server/package.json`: `level ^6.0.1` is a direct dependency (`restore.mjs`
  requires it; it only resolved through y-leveldb's hoisting). `jimp` moved to
  `optionalDependencies`. `server/bun.lock` changed only in its workspace
  block; no resolved version moved.
- Client: `table-keys.ts` and `table-keys.test.ts` import from
  `@milkdown/prose/tables` instead of the undeclared `prosemirror-tables`;
  `image-resize.ts` imports `imageBlockSchema` from
  `@milkdown/components/image-block`, and `@milkdown/components ^7.20.0` is
  now declared (the version already locked through crepe, so no new copy).
- Removed `@types/uuid` (uuid 13 has its own types) and the `lint` script
  (it ran an eslint that is neither installed nor configured).
- Deleted unused code: `pageSnapshotRepo` (and its `bytesToBase64`; the file
  keeps `base64ToBytes`), `restoreSnapshot`, `countAssetReferences`.
  `createImageResizeProsePlugin`, `decorateOutputSpec`, `withHeaderLabels`,
  `hslTriplet` are used inside their modules, so they only lose `export`.
  The `AppDatabase` class stays; only the redundant `export { AppDatabase }`
  went.

### 4. cmdlog agent (SRV-11 and the outbox missed issue)

- `Shipper.submit` cuts `command` to 4096 characters and `cwd` to 512 (the
  server's limits) before shipping.
- A batch refused with a 4xx is split in half and retried down to single
  events; an event still refused alone is dropped and counted in a new
  `rejected` counter (status file, `btct_agent status`, the status line).
  Retried instead of split: 401, 403, 404, 405, 408, 409, 429, every 5xx and
  network errors. **This widens the audit's 401/408/429 list** with 403, 404,
  405 and 409, because those describe the server or its configuration (409 is
  "no target workspace", 404 a wrong URL), and splitting on them would drop
  every command typed while the box was misconfigured.
- The computed backoff is now honoured: while it runs, new batches go to the
  outbox and nothing is posted.
- Outbox: append-only `outbox.ndjson` plus `outbox.ndjson.offset` (committed
  byte offset, written via a temp file and rename). Compaction rewrites only
  the pending events once the delivered part is at least 64 KB and half the
  file, or the queue is empty. A reload replays from the offset and compacts
  once (torn or damaged lines are skipped). Compaction writes offset 0 before
  renaming, so a crash replays delivered events (the server dedups by id)
  rather than skipping undelivered ones. `drain` uses `islice`. An old
  outbox (no offset file) loads whole.
- Tests: `cmdlog-agent/tests/test_shipper_outbox.py` grew from 5 to 21
  cases; `python3 -m unittest discover -s tests` runs 49, all pass.

### 5. Dockerfile and compose

New build args (both default `1`, declared globally before the first FROM):

| arg | at 0 |
|---|---|
| `WITH_REPORT_BINS` | no typst CLI, no pdf2docx venv, no python3, server deps installed with `--omit optional` (no jimp), `server/typst/` ships only `*.mjs`. The `report-bins`, `pdf2docx-venv` and `typst-src` stages are picked by name (`FROM report-bins-${WITH_REPORT_BINS}`), so a 0 build pulls no `debian:bookworm-slim` and reaches no network for report tools. |
| `WITH_TYPST_CLIENT` | `scripts/fonts.ts` (the CDN font fetch) is skipped and `dist/fonts` plus `dist/assets/typst_ts_*.wasm` are deleted before gzip; the build fails if a typst wasm is still there. |

Other Dockerfile changes:
- `ENV YPERSISTENCE=/data/yjs` (SRV-14). A plain `docker run` now persists
  rooms and unloads idle ones.
- server-deps: `COPY server/package.json server/bun.lock` (no glob, so a
  missing lock fails the build) and `bun install --frozen-lockfile` with no
  `|| bun install` fallback (BLT-9). Measured: a missing lock and a
  `package.json` the lock cannot satisfy both fail the build. A range edit
  the locked version still satisfies (`^13.6.30` to `^13.6.29`) does not fail
  with Bun 1.3.14; that is Bun's frozen-lockfile behaviour.
- leveldown keeps only `prebuilds/linux-x64` and `prebuilds/linux-arm64` and
  loses `deps/` (BLT-15, dash-safe `find ... ! -name` form). The stage then
  asserts `node_modules/level` and the x64 prebuild exist.
- HEALTHCHECK (BLT-4/SRV-22): `bash -c 'exec 3<>/dev/tcp/127.0.0.1/${PORT:-8080}
  && printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && read -t 4 -r l <&3 &&
  [[ $l == *" 200 "* ]]'`, exec form, interval 30 s, timeout 5 s.

`server/index.mjs` (one constant, kept minimal for the server stream):
`TYPST_TAB = ENABLE_TYPST && (no STATIC_DIR || dist/assets holds
typst_ts_web_compiler_bg*.wasm)`, and `GET /api/settings` reports
`features.typst: TYPST_TAB`. A warning is logged at boot when the flag is on
and the wasm is missing. The `/api/typst/*` routes still follow
`ENABLE_TYPST` alone.

`docker-compose.yml`:
- `build.args` `WITH_REPORT_BINS: "${WITH_REPORT_BINS:-1}"` and
  `WITH_TYPST_CLIENT: "${WITH_TYPST_CLIENT:-1}"` (BLT-1, BLT-2), so
  `docker compose up -d --build` and `install-btct.sh` honour `.env`.
- the bash healthcheck with `$$l` (compose interpolates a single `$`),
  `start_period: 10s`.
- `init: true`, `stop_grace_period: 60s`, `logging: json-file` with
  `max-size: 10m`, `max-file: 3`, and commented-out `mem_limit: 1g` /
  `cpus: 2`.

`docker-compose.preview.yml`: the same two build args, healthcheck, grace
period and log limits (it already had `init` and the limits).

## New env vars, settings, commands

- `.env` keys read by compose at build time: `WITH_REPORT_BINS` (default 1),
  `WITH_TYPST_CLIENT` (default 1).
- No new routes or settings. `features.typst` can now be false with
  `ENABLE_TYPST=1` (image built with `WITH_TYPST_CLIENT=0`).
- `bun run lint` no longer exists.
- Agent status JSON gains `rejected`.

## Invariants for CLAUDE.md "Critical invariants"

- **`init: true` ships only with a SIGTERM handler.** tini forwards SIGTERM to
  Bun at once; without a handler that flushes pending Yjs writes, Bun dies
  with the backlog unwritten (measured here: `docker compose stop` took
  1.26 s, exit 143, on this branch alone). The handler is the server stream's
  SRV-8 and must merge with or before this compose file.
- **The compose healthcheck writes `$$l`; the Dockerfile writes `$l`.** Compose
  interpolates `$l` to an empty string and the container never turns healthy;
  Dockerfile HEALTHCHECK does no substitution. Both probes must test the
  status line (`' 200 '`), not the body, so a degraded `/healthz` that
  answers 503 fails them.
- **A conditional file in the image is a stage picked by a global ARG**
  (`FROM x-${ARG} AS x`), never an `rm` in a later layer, which does not
  shrink the image. New files under `server/typst/` that the runtime needs
  must be `.mjs` (the `typst-src-0` stage copies only `server/typst/*.mjs`).
- **`server/bun.lock` is copied by name and installed frozen with no
  fallback.** A dependency change means regenerating the lock in the same
  commit. Report-only server dependencies go in `optionalDependencies`.
- **Never track `.env` or key material.** `install-btct.sh` and
  `Start-BTCT.ps1` replace any `AUTH_SECRET` found in the history of `.env`.
- **cmdlog agent: never let a refused event block the outbox.** Payload
  rejections split and drop (counted); configuration and transport failures
  retry. The outbox is append-only with a committed offset; do not go back to
  rewriting it per batch.

## README / CLAUDE.md text that is now stale

CLAUDE.md, Commands:
- "`bun run lint`: ESLint." Delete the line.
- install-btct.sh bullet: "writes `.env` with an `AUTH_SECRET` if absent".
  Replace with: "makes sure `.env` holds a private `AUTH_SECRET` (a fresh one
  replaces a missing one, the example placeholder, or any value ever
  committed to `.env`; `.env` is untracked and left mode 600)".
- ENABLE_TYPST bullet: "Off, the image still carries the compiler's 29.3 MB of
  wasm and 8.7 MB of fonts in `dist/`, and no client ever requests them."
  Replace with: "Off, the image still carries the compiler's wasm and fonts
  (55 MB of `dist/` with their `.gz` siblings) unless it was built with
  `WITH_TYPST_CLIENT=0`, which drops them and makes `features.typst` false
  whatever `ENABLE_TYPST` says; turning the tab on then needs a rebuild."
- `server/typst/` bullet: "the whole directory is copied, so a new module
  there is already in the image" and "`--build-arg WITH_REPORT_BINS=0` leaves
  both out". Replace with: every `server/typst/*.mjs` is copied (a new module
  must be `.mjs` at that level); `pdf-to-docx/` only when
  `WITH_REPORT_BINS=1`. `WITH_REPORT_BINS=0` (build arg, or `.env` for
  compose) leaves out the typst CLI, the venv, python3, jimp and the Python
  sources, and pulls no debian image.
- Word converter paragraph, last sentence: "`.dockerignore` keeps `corpus/`
  out of the image, since the Dockerfile copies `server/typst/` whole." Now:
  "... since the `typst-src-1` stage copies `server/typst/` whole."
- Add under Deploy: "`.env` may set `WITH_REPORT_BINS=0` and
  `WITH_TYPST_CLIENT=0` (both default 1) for a smaller image; compose passes
  them as build args."
- Add: the container healthcheck is bash `/dev/tcp`, not Bun.

CLAUDE.md, Performance (the line the task calls CLAUDE.md:175): "they put
29.3 MB of WebAssembly plus 8.7 MB of fonts into `dist/` and 180 MB onto the
image". Measured on this branch: the Typst client is the difference between
a 62.6 MB and a 7.65 MB `dist/` layer (55 MB, wasm and fonts with their `.gz`
siblings); the report tools (`WITH_REPORT_BINS=1`) are 461 MB of layers
(719.3 MB against 257.9 MB). Replace "and 180 MB onto the image" with "and
55 MB onto the image (with the `.gz` siblings; `WITH_TYPST_CLIENT=0` drops
them)".

CLAUDE.md "Command log ingest" section: add one sentence that the agent cuts
commands to 4096 characters, splits a refused batch and drops (counts as
`rejected`) an event the server still refuses alone, and keeps its outbox as
an append-only JSONL with a committed offset.

README:
- Line ~1063: "`changelogRepo`, `pageSnapshotRepo`, `nmapScanRepo`..." Drop
  `pageSnapshotRepo` (the module now only exports `base64ToBytes`).
- Line ~1242 (file map): "`api/client.ts               REST client base`".
  Delete the line; the file is gone.
- Line ~1425, invariant 18: "**Set `AUTH_SECRET` and `YPERSISTENCE`** in any
  real deployment". The image now defaults `YPERSISTENCE=/data/yjs`; say
  "Set `AUTH_SECRET` (the image defaults `YPERSISTENCE=/data/yjs`; a run from
  source must set it)".
- Lines ~1745-1751: "Together they cost about 405 MiB of image (measured:
  689 MiB against 283 MiB with them left out) ... A box that will never export
  can leave them out with `docker build --build-arg WITH_REPORT_BINS=0`".
  Replace the numbers with the table below and add: "With docker compose, put
  `WITH_REPORT_BINS=0` in `.env`. That build pulls no debian image, omits jimp
  and the converter's Python, and makes no network request for report tools.
  `WITH_TYPST_CLIENT=0` also leaves out the Report tab's compiler and fonts
  (and the build's CDN font fetch); `ENABLE_TYPST=1` then has no effect until
  a rebuild with 1."
- Line ~2284 (install-btct.sh): "It then writes `.env` with a fresh
  `AUTH_SECRET` (never replacing one)". Replace with: "It then makes sure
  `.env` holds a private `AUTH_SECRET`: it writes a fresh one when `.env` is
  missing, has none, holds the example placeholder, or holds any value ever
  committed to `.env` (older commits tracked it, so those values are public).
  Replacing one logs everyone out. `.env` is left mode 600."
- Command log section (~line 215) and the agent's own README: the
  `rejected` counter and the delivery rules (the agent README is updated in
  this branch).
- Conventions and invariants: add the invariants above.
- Deploy section: note that compose now has `init: true`,
  `stop_grace_period: 60s` and log rotation (10 MB x 3), and that
  `mem_limit`/`cpus` are there commented out.

## Measurements

Images built from this branch with `docker build --build-arg ...`; the "base"
rows are 669ed8f built from `git archive`. `inspect` is
`docker image inspect -f '{{.Size}}'`; `layers` sums `docker history`.

| image | inspect (B) | layers | dist layer | server node_modules | server/typst layer |
|---|---|---|---|---|---|
| base, bins=1 | 1,004,826,387 | 725.5 MB | 62.6 MB | 54.2 MB | 3.84 MB |
| base, bins=0 | 423,093,253 | 300.5 MB | 62.6 MB | 54.2 MB | 3.84 MB |
| bins=1, typst client=1 | 996,213,531 | 719.3 MB | 62.6 MB | 50.1 MB | 1.74 MB |
| bins=1, typst client=0 | 907,362,444 | 664.4 MB | 7.65 MB | 50.1 MB | 1.74 MB |
| bins=0, typst client=1 | 364,704,647 | 257.9 MB | 62.6 MB | 15.3 MB | 156 kB |
| bins=0, typst client=0 | 275,853,561 | 202.9 MB | 7.65 MB | 15.3 MB | 156 kB |

Smoke test per variant (each passed): `YPERSISTENCE` in the env and "Persisting
documents to /data/yjs" in the log with no `-e YPERSISTENCE`; `/healthz`;
login; `features.typst` true or false as expected with `ENABLE_TYPST=1`; a
y-websocket write, then a cold read of the same room after it unloaded
(LevelDB with the pruned leveldown); asset upload and byte-identical download;
`/api/typst/capabilities` ({pdf,docx} false at bins=0, true at bins=1) and 501
from the export route at bins=0; jimp absent at bins=0; only the two Linux
prebuilds and no `deps/`; `pdf-to-docx/` absent at bins=0; Docker health
`healthy`; admin backup run, `restore.mjs --help`, a real restore into the
stopped volume, and the backed-up room text and asset back after restart.

bins=1 only: a real PDF (200, `%PDF`, 0.75 s) and DOCX (200, `PK`, 11.2 s)
export from a seeded report, the wasm served as `application/wasm`, and
`server/typst/bake.check.mjs` ("bake: ok", which exercises jimp).

Moving data to a new box: an image built from the base commit (what the live
box runs) made a workspace, a Typst source, a page room, a second user, an
asset, a command-log entry and a backup. The bins=0 / client=0 image restored
that backup into an empty volume and came up with both users' passwords
working, the page text, the shared doc (workspace, report source, cmdlog
window), the asset bytes, the SQLite command log and the history route.

Healthcheck: rc 0 on `/healthz`, rc 1 on a 401 route and on a closed port,
rc 142 after 4.28 s with the Bun process frozen (`kill -STOP`), rc 0 after
`kill -CONT`. A compose stack from `docker-compose.yml` (with an override for
image, name, port and volume) went healthy in 6 s with `$$l`, ran
`/sbin/docker-init` as PID 1 and had the json-file limits.

cmdlog agent against a bins=0 server: the audit's `agent_hol.py` now ends
`sent=35 outbox=0 online=True` (the base agent: `sent=10 outbox=25
online=False`). Draining a pre-filled outbox of 20,000 events of 2 KB: 17.6 s
wall and 2.8 s CPU; the base agent had sent 2,300 after 60 s and 35 s of CPU.

Side finding for the server stream: on a server whose shared doc has no
workspace yet, every cmdlog ingest takes 2 s, because `shared()` in
`server/yjs-data.mjs` polls up to 2 s for workspaces and does not cache an
empty result. Now that `doc.whenLoaded` exists that poll can probably go.

`tsc -b` clean; vitest 599 passed, 6 failed (the known 5 in
`typst-search.test.ts` and 1 in typst-run-child), 1 skipped: the baseline.
