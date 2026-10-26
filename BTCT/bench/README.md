# BTCT baseline benchmarks

Scripts that measure the client bundle, the test suite and a throwaway server, so a change can be compared against [BASELINE.md](BASELINE.md). Everything runs in the pinned `oven/bun:1.3.14` container with the `btct-harden-nm` node_modules volume (the same mounts as the test suite). No image is built.

| Script | What it measures | Time |
|---|---|---|
| `bench/client-bundle.sh` | `bun run build`, then entry chunk raw and gzip -9, initial load (entry plus every modulepreload and stylesheet in `index.html`), dist total, chunk counts, the 10 largest files and JS chunks, and the typst gate (`grep -l typst_ts_web_compiler dist/assets/index-*.js` must be empty) | about 40 s |
| `bench/tests.sh [file]` | wall time of `bun x vitest run` plus the vitest summary | about 60 s |
| `bench/server.sh` | starts `btct:latest` as container `btct-bench` on `127.0.0.1:8098` with a fresh volume `btct-bench-data`, then cold start, idle memory, `bench/api.mjs` and `bench/relay.mjs`; removes the container and volume on exit (also on Ctrl-C) | about 60 s |
| `bench/api.mjs` | `/healthz` latency (200 GETs), `POST /api/login` latency (20 sequential, then 5 concurrent), command log ingest of 10,000 events in batches of 200 through `POST /api/cmdlog/events`, then the count and a JSON export | run by `server.sh` |
| `bench/relay.mjs` | 10 y-websocket clients in one room; 1000 paced updates at 200/s, then a 2000-update burst; end-to-end propagation p50/p95/p99 measured on one clock | run by `server.sh` |

## Running

From the repo root:

```sh
bench/client-bundle.sh                 # SKIP_BUILD=1 measures an existing dist/
bench/tests.sh                         # or: bench/tests.sh src/test/foo.test.ts
bench/server.sh                        # unconstrained
LIMITS=1 bench/server.sh               # --memory 1g --cpus 2, the target box
```

`server.sh` knobs (env): `EVENTS` (10000), `N` (10), `M_PACED` (1000), `RATE` (200), `M_BURST` (2000), `IDLE_WAIT_S` (15), `BENCH_PORT` (8098), `BENCH_CONTAINER` (`btct-bench`), `BENCH_VOLUME` (`btct-bench-data`). It refuses a name of `btct`, anything containing `btct-data`, and port 8080, so it cannot touch the live instance. Raw JSON of the last run lands in `bench/.server-run/` (gitignored, like the build and test logs).

The two `.mjs` scripts also run on their own against any server: `docker run --rm --network host -v "$PWD":/app:ro -w /app -v btct-harden-nm:/app/node_modules -e BASE=http://127.0.0.1:8098 oven/bun:1.3.14 bun bench/relay.mjs`. Credentials come from `BENCH_USER`/`BENCH_PASS` (default the seeded admin `Roberto` / `typst-best456`, which only a fresh volume is sure to have).

## What the numbers mean

- **Memory.** `rss_kb` is the sum of `VmRSS` over every process in the container (the image has no `ps`). `docker stats` is the cgroup figure, which drops reclaimable page cache and so reads lower; both are recorded.
- **Cold start** is `docker run` to the first `/healthz` 200, polled every 50 ms, on a fresh volume (so it includes creating SQLite, LevelDB and the six seed accounts).
- **Login** is dominated by the PBKDF2 verify. Five concurrent logins taking about as long as one shows the hash runs on the threadpool (invariant 9); under `--cpus 2` they queue.
- **Relay.** The room URL is formed as the client does (`src/realtime/yjs-providers.ts`): `ws://host/yjs/<room>?token=<jwt>[&epoch=<restoreEpoch>]`. Each update is one `Y.Map.set` of a 64-byte string by a rotating writer, and the other N-1 clients each record a delivery. `disableBc` is on, so nothing bypasses the server. In the burst phase the send loop and the receivers share one Bun process, so `sendLoopMs` close to `wallMs` means the benchmark client, not the relay, was the bottleneck; read burst throughput as a lower bound.
- The client and the server run on the same host, so latencies exclude a real network.
