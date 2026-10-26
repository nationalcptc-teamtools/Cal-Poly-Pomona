# syntax=docker/dockerfile:1.7

# Build switches. Both default to 1 (everything in); docker compose passes
# them from .env. They are declared here, before the first FROM, because two
# of them pick a stage by name further down (`FROM report-bins-${...}`), which
# is how a COPY is made conditional and how a 0 build avoids pulling the
# report stages' base image at all.
#
#   WITH_REPORT_BINS=0   leave out the server-side PDF/Word export: the typst
#                        CLI, the pdf2docx virtualenv, python3, jimp and the
#                        converter's Python sources. Export routes answer 501.
#   WITH_TYPST_CLIENT=0  leave out the Report tab's compiler wasm and its 17
#                        fonts, and skip the CDN font fetch. The server then
#                        reports features.typst=false even with ENABLE_TYPST=1,
#                        so turning the tab on needs a rebuild with 1.
ARG WITH_REPORT_BINS=1
ARG WITH_TYPST_CLIENT=1

# ─────────────────────────────────────────────────────────────────────────
# Stage 1: build the Vite client.
# ─────────────────────────────────────────────────────────────────────────
FROM oven/bun:1.3 AS client-build
ARG WITH_TYPST_CLIENT
WORKDIR /app

# Install client deps using the lockfile for reproducible builds.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy the client source and build. No VITE_API_URL / VITE_WS_URL is set
# here: the client falls back to same-origin at runtime, which is what
# the single-container deployment uses.
COPY tsconfig.json vite.config.ts vite-env.d.ts index.html ./
COPY public ./public
COPY src ./src
COPY scripts ./scripts
# Type declarations for the pure server modules that src/test imports
# (scheduler, backup-format). `bun run build` runs tsc over the tests too,
# so the .d.mts files must exist here even though the server itself is
# built in a later stage.
COPY server/*.d.mts ./server/
COPY server/typst/*.d.mts ./server/typst/
RUN set -eu; \
    case "${WITH_TYPST_CLIENT}" in 0|1) ;; *) echo "WITH_TYPST_CLIENT must be 0 or 1" >&2; exit 1;; esac; \
    if [ "${WITH_TYPST_CLIENT}" = "1" ]; then bun scripts/fonts.ts; fi; \
    bun run build

# `public/fonts` is dockerignored, so the fonts here were fetched from the
# CDN by the step above rather than copied from a developer's machine. A
# missing font is not visible at runtime (the static handler answers with
# index.html and the compiler reports a parser error), so fail the build
# instead. Keep this ahead of the gzip step below, which leaves a `.gz`
# sibling next to each font and would make the count 34.
# Without the Typst client the compiler and renderer wasm are deleted here
# (about 55 MB with their .gz siblings); nothing outside the lazy Report tab
# requests them, and the server reports the tab off when they are missing.
RUN set -eu; \
    if [ "${WITH_TYPST_CLIENT}" = "1" ]; then \
      test "$(ls dist/fonts | wc -l)" -eq 17; \
    else \
      rm -rf dist/fonts; \
      rm -f dist/assets/typst_ts_*.wasm; \
      if ls dist/assets | grep -q '^typst_ts_.*\.wasm$'; then echo "typst wasm still in dist" >&2; exit 1; fi; \
    fi

# Precompress the compressible static files so the server can hand a
# `file.gz` sibling to any client that accepts gzip (see tryServeStatic).
# Compress both the small startup bundles and the optional report compiler,
# with zero per-request CPU spent compressing.
RUN cd dist && find . -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' -o -name '*.wasm' -o -name '*.json' -o -name '*.otf' -o -name '*.ttf' \) -size +1k -exec gzip -k -9 {} \;

# ─────────────────────────────────────────────────────────────────────────
# Stage 2: install the server's runtime deps in isolation.
# The lockfile is named without a glob so a missing one fails the COPY, and
# --frozen-lockfile has no fallback: a lock out of step with package.json
# fails the build instead of resolving new versions on build day.
# jimp is an optional dependency used only by the report export, so a
# WITH_REPORT_BINS=0 build omits it with its transitive packages. leveldown
# ships prebuilt binaries for eight platforms plus its C++ sources; only the
# two Linux ones the image can run on are kept.
# ─────────────────────────────────────────────────────────────────────────
FROM oven/bun:1.3 AS server-deps
ARG WITH_REPORT_BINS
WORKDIR /server
COPY server/package.json server/bun.lock ./
RUN set -eu; \
    if [ "${WITH_REPORT_BINS}" = "0" ]; then \
      bun install --frozen-lockfile --omit optional; \
    else \
      bun install --frozen-lockfile; \
    fi; \
    find node_modules/leveldown/prebuilds -mindepth 1 -maxdepth 1 ! -name linux-x64 ! -name linux-arm64 -exec rm -rf {} +; \
    rm -rf node_modules/leveldown/deps; \
    test -d node_modules/level; \
    test -d node_modules/leveldown/prebuilds/linux-x64

# ─────────────────────────────────────────────────────────────────────────
# Stage 3: the typst compiler. It is only ever spawned when ENABLE_TYPST=1,
# but it ships by default so turning the flag on is a restart rather than a
# rebuild. The archive is pinned by version and by sha256.
#
# A box that will never export can build without the export tools and save
# the measured size: `--build-arg WITH_REPORT_BINS=0` (or WITH_REPORT_BINS=0
# in .env for docker compose). The server still starts, the capabilities
# route reports both false, the buttons do not appear and the export routes
# answer 501. That build uses the empty `-0` stages below instead, so it
# neither pulls debian nor reaches the network for the report tools.
# ─────────────────────────────────────────────────────────────────────────
FROM scratch AS report-bins-0
WORKDIR /out

FROM debian:bookworm-slim AS report-bins-1

# THE TWO DIGESTS BELOW ARE TRUST-ON-FIRST-USE, recorded 2026-09-19.
# The project publishes no signed checksum file, so they were computed from
# the release artefacts the first build downloaded and cross-checked against
# the digest GitHub's own release API reports for the same assets. That makes
# them an integrity control (the build fails if those bytes ever change) and
# not an authenticity one.
#
# TO BUMP THE VERSION: change the ARG, run the build, let the sha256sum step
# fail and print the digest it saw. Before pasting that digest in, check it
# out of band against the release asset itself:
#
#   gh api repos/typst/typst/releases/tags/v<X> --jq '.assets[] | {name, digest}'
#
# Then update the date on this comment. The bump also invalidates a measured
# safety property, so it is not only a version change: re-run the SVG href
# checks in docs/typst-tab-2026-09.md. A staged SVG is never sized, and that
# is safe only because usvg resolves an href for exactly <image> and
# <feImage> and typst refuses http, file and out-of-root hrefs inside an SVG.
ARG TYPST_VERSION=0.14.2
ARG TARGETARCH

RUN set -eu; \
    mkdir -p /out; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl xz-utils; \
    rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) T=x86_64-unknown-linux-musl; \
        TS=a6044cbad2a954deb921167e257e120ac0a16b20339ec01121194ff9d394996d;; \
      arm64) T=aarch64-unknown-linux-musl; \
        TS=491b101aa40a3a7ea82a3f8a6232cabb4e6a7e233810082e5ac812d43fdcd47a;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1;; \
    esac; \
    curl -fsSL -o /tmp/typst.tar.xz "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${T}.tar.xz"; \
    echo "${TS}  /tmp/typst.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/typst.tar.xz -C /tmp; \
    install -m 0755 "/tmp/typst-${T}/typst" /out/typst; \
    rm -rf /tmp/typst.tar.xz "/tmp/typst-${T}"; \
    /out/typst --version

FROM report-bins-${WITH_REPORT_BINS} AS report-bins

# ─────────────────────────────────────────────────────────────────────────
# Stage 3b: the Word converter's Python environment. The DOCX export turns
# the finished PDF into Word with pdf2docx (server/typst/pdf-to-docx), which
# needs a real Python. It is built on the runtime's own base image so the
# virtualenv's interpreter symlink resolves to the same /usr/bin/python3
# there, and it is copied over whole.
#
# TO BUMP A PIN: edit server/typst/pdf-to-docx/requirements.txt. The hashes
# are what `pip-compile --generate-hashes` produced for pdf2docx's whole
# dependency tree, so regenerate the file rather than editing one line:
#
#   docker run --rm oven/bun:1.3-slim sh -c 'apt-get update >/dev/null && \
#     apt-get install -y --no-install-recommends python3 python3-venv >/dev/null && \
#     python3 -m venv /v && /v/bin/pip install -q pip-tools && \
#     echo pdf2docx==<X> > /req.in && \
#     /v/bin/pip-compile --generate-hashes --no-header -o /dev/stdout /req.in'
#
# Then re-run server/typst/pdf-to-docx/test_convert.py, compare.ps1 and
# font_probe.py against a real report: the band and table-of-contents repairs
# are written against what pdf2docx produces, and a new version can change
# that. font_probe.py in particular, because convert.py overrides how pdf2docx
# names a span's font (Fonts.get), which is a private method: if it moves, the
# override stops applying and Word starts substituting again in silence.
# Re-check stream_tables_in_page_order in convert.py and the footer-reach
# check (cases.FOOTER_TABLE_REACH) in test_convert.py too: the wrapper sorts
# the blocks of pdf2docx's private TablesConstructor.stream_tables, falls
# through to pdf2docx's own step if they cannot be sorted, and the check fails
# once raw pdf2docx stops losing that text, which means the wrapper can go.
# borders_follow_cell_edges and merged_fills_keep_parts replace three more
# private methods (Shapes._merge_shapes, Borders.finalize and
# Borders._finalize_by_strokes) so a borderless table's borders land on the
# PDF's cell edges; run_cell_edge_checks in test_convert.py fails if they stop
# applying, and a failure inside them counts cell-edges-fallthrough.
# spans_keep_inner_blanks replaces Spans.restore (it dropped the span of one
# space typst draws between two coloured code tokens: "def exploit" became
# "defexploit") and straddling_lines_keep_their_chars wraps
# TableBlock.assign_blocks (it dropped a line or a ligature's letter that no
# cell held half of); run_token_space_checks and run_orphan_char_checks fail
# if they stop applying or raw pdf2docx stops needing them, and their
# fall-throughs count spaces-fallthrough and orphan-chars-fallthrough.
# carry_cells_across_rows (inside the page-order wrapper) overrides the page
# blocks' group_by_rows for one stream_tables call so a cell's second line is
# not flow layout (Blocks.collect_stream_lines closed a striped table between
# a cell's two lines); it reads Shapes.table_fillings and counts
# cell-rows-fallthrough when those names move.
# Then run scorecard.py over the corpus, which the rule is measured against.
# ─────────────────────────────────────────────────────────────────────────
FROM scratch AS pdf2docx-venv-0
WORKDIR /opt/pdf2docx

FROM oven/bun:1.3-slim AS pdf2docx-venv-1
COPY server/typst/pdf-to-docx/requirements.txt /tmp/requirements.txt
RUN set -eu; \
    mkdir -p /opt/pdf2docx; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 python3-venv; \
    rm -rf /var/lib/apt/lists/*; \
    python3 -m venv /opt/pdf2docx; \
    /opt/pdf2docx/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes -r /tmp/requirements.txt; \
    /opt/pdf2docx/bin/python -I -c "import pdf2docx"; \
    find /opt/pdf2docx -depth -name __pycache__ -type d -exec rm -rf {} +; \
    /opt/pdf2docx/bin/python -c "import pdf2docx, pymupdf, docx"
# pip compiles everything it installs, which is bytecode for hundreds of
# modules the converter never loads; the line above throws that away and then
# imports once to put back only what it does load. The export child runs with
# -B, so without this it would recompile pymupdf, numpy and OpenCV on every
# export, on the one core it is allowed.

FROM pdf2docx-venv-${WITH_REPORT_BINS} AS pdf2docx-venv

# ─────────────────────────────────────────────────────────────────────────
# Stage 3c: the server/typst/ sources. The modules are always copied (the
# Report tab's routes import them when ENABLE_TYPST=1). The Word converter's
# Python, its tests and scorecard tools (1.7 MB) only ever run with the report
# tools present, so the `-0` stage takes the modules alone. A COPY cannot be
# conditional, and an rm in a later layer would not shrink the image.
# ─────────────────────────────────────────────────────────────────────────
FROM scratch AS typst-src-0
COPY server/typst/*.mjs /t/

FROM scratch AS typst-src-1
COPY server/typst/ /t/

FROM typst-src-${WITH_REPORT_BINS} AS typst-src

# ─────────────────────────────────────────────────────────────────────────
# Stage 4: minimal runtime image. Server code + server node_modules +
# the built client. Runs as a non-root user; persistent SQLite goes to
# /data which is the standard volume mount point.
# ─────────────────────────────────────────────────────────────────────────
FROM oven/bun:1.3-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    STATIC_DIR=/app/dist \
    DB_PATH=/data/data.sqlite \
    BACKUP_DIR=/backups \
    YPERSISTENCE=/data/yjs \
    PDF2DOCX_PYTHON=/opt/pdf2docx/bin/python
# YPERSISTENCE is set here, not only in compose: without it y-websocket keeps
# every room in memory only, so a plain `docker run` loses notes on restart and
# never unloads a room it has opened.

# Copy server source + its node_modules. Ownership is set as each layer is
# written: a later `chown -R … /app` would rewrite every file and duplicate
# the whole 55.6 MB dist layer in the image.
COPY --from=server-deps --chown=bun:bun /server/node_modules /app/server/node_modules
COPY --chown=bun:bun server/package.json /app/server/package.json
COPY --chown=bun:bun server/index.mjs   /app/server/index.mjs
COPY --chown=bun:bun server/env.mjs     /app/server/env.mjs
COPY --chown=bun:bun server/auth.mjs    /app/server/auth.mjs
COPY --chown=bun:bun server/db.mjs      /app/server/db.mjs
COPY --chown=bun:bun server/seed-accounts.mjs /app/server/seed-accounts.mjs
COPY --chown=bun:bun server/yjs-data.mjs /app/server/yjs-data.mjs
COPY --chown=bun:bun server/scan-ingest.mjs /app/server/scan-ingest.mjs
COPY --chown=bun:bun server/assets.mjs  /app/server/assets.mjs
COPY --chown=bun:bun server/cmdlog.mjs  /app/server/cmdlog.mjs
COPY --chown=bun:bun server/scheduler.mjs     /app/server/scheduler.mjs
COPY --chown=bun:bun server/backup-format.mjs /app/server/backup-format.mjs
COPY --chown=bun:bun server/zip-stream.mjs    /app/server/zip-stream.mjs
COPY --chown=bun:bun server/data-export.mjs   /app/server/data-export.mjs
COPY --chown=bun:bun server/backup.mjs        /app/server/backup.mjs
COPY --chown=bun:bun server/restore.mjs       /app/server/restore.mjs
COPY --chown=bun:bun server/restore-checks.mjs /app/server/restore-checks.mjs
COPY --chown=bun:bun server/history.mjs       /app/server/history.mjs
COPY --chown=bun:bun server/history-diff.mjs  /app/server/history-diff.mjs
COPY --chown=bun:bun server/retention.mjs     /app/server/retention.mjs
COPY --chown=bun:bun server/relay-persistence.mjs /app/server/relay-persistence.mjs
COPY --chown=bun:bun server/relay-inbox.mjs       /app/server/relay-inbox.mjs

# The server-side report export (ENABLE_TYPST=1). server/typst/ comes from
# the typst-src stage: every .mjs module, so a new module there cannot be
# forgotten, plus the Word converter's Python only when the report tools are
# built in. The report-bins and pdf2docx-venv stages are empty directories in
# a WITH_REPORT_BINS=0 build.
ARG WITH_REPORT_BINS
COPY --from=report-bins /out/ /usr/local/bin/
COPY --from=pdf2docx-venv /opt/pdf2docx /opt/pdf2docx
COPY --from=typst-src --chown=bun:bun /t/ /app/server/typst/
# The crop and blur math the browser uses, imported by server/typst/bake.mjs
# rather than copied, so a redaction bakes with the same numbers the preview
# drew. The list comes from reading those imports and then the imports of
# each file named: blur-math and crop-math take only types (erased by Bun)
# and image-format takes nothing. cwd is /app/server, so ../../src/lib from
# /app/server/typst resolves here. A new src/lib import under server/typst/
# needs a name on this line.
COPY --chown=bun:bun src/lib/blur-math.ts src/lib/crop-math.ts src/lib/image-format.ts /app/src/lib/
# The Python the virtualenv's interpreter symlink points at. python3 is the
# smallest package that brings a working standard library on Debian trixie;
# python3-minimal alone leaves out modules pdf2docx imports.
RUN set -eu; \
    if [ "${WITH_REPORT_BINS}" = "1" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends python3; \
      rm -rf /var/lib/apt/lists/*; \
    fi
# Fail the build here rather than at somebody's first export. Skipped, not
# relaxed, when the export tools were deliberately left out.
RUN if [ "${WITH_REPORT_BINS}" = "1" ]; then typst --version && /opt/pdf2docx/bin/python -I -B -c "import pdf2docx; print('pdf2docx ok')"; \
    else echo "report tools left out (WITH_REPORT_BINS=0): server export is unavailable"; fi

# Copy the static client build.
COPY --from=client-build --chown=bun:bun /app/dist /app/dist

# Persistent volume for SQLite + Yjs + assets, and the backup folder the
# compose file bind-mounts from the host (created here so a run without the
# mount still has somewhere writable). Only these two need the recursive
# chown: everything under /app arrived owned by bun already.
RUN mkdir -p /data /backups && chown -R bun:bun /data /backups
VOLUME ["/data"]
USER bun

EXPOSE 8080

# Healthcheck hits /healthz on the configured port with bash's /dev/tcp
# rather than a second Bun runtime (about 34 MB RSS and 65 ms of CPU per probe
# against about 12 ms here). curl and wget are not in the slim image; bash is.
# It passes only on a " 200 " status line, so a degraded /healthz that answers
# 503 turns the container unhealthy. Docker does not substitute variables in
# HEALTHCHECK, so $l and ${PORT:-8080} reach bash as written. The compose file
# overrides this probe and must write $$l there.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT:-8080} && printf 'GET /healthz HTTP/1.0\\r\\n\\r\\n' >&3 && read -t 4 -r l <&3 && [[ $l == *' 200 '* ]]"]

WORKDIR /app/server
CMD ["bun", "run", "index.mjs"]
