# BTCT baseline, 2026-10-20

- Commit: `6364d28` (Merge feat/finding-copy-modular), branch `hardening/2026-10-20`, worktree `/home/user/btct-wt-harden`.
- Server image: the existing `btct:latest` (`sha256:d6b8dcf33cad`, created 2026-10-20 09:48, 998 MB). It was not built by this run, so it may not be exactly `6364d28`.
- Machine: 8 vCPUs (`nproc` 8, QEMU Virtual CPU 2.5+ at 2.0 GHz), 15.6 GiB RAM (`free`: about 11.4 GiB available, 1.6 GiB free, 9.8 GiB cache, swap 974 MiB with 772 MiB used), Linux 6.1.0-53-amd64, Docker 29.8.2, 3.2 GB disk free. Other containers were running (`btct`, `btct-report-preview`, `btct-theme-studio`), so treat small differences as noise.
- How to rerun: [README.md](README.md).

## Client bundle (`bench/client-bundle.sh`)

| Metric | Value |
|---|---|
| `bun run build` wall time (tsc -b + vite build) | 35.7 s |
| Entry chunk `assets/index-BkeKd_yS.js` | 258,541 B raw, 77,403 B gzip -9 |
| Initial load (entry + 29 modulepreloads + CSS, 31 files) | 660,074 B raw, 196,037 B gzip -9 |
| dist total | 34,983,526 B (35 MB) |
| JS chunks / CSS files / wasm files | 213 / 3 / 2 |
| All JS | 3,984,316 B |
| Typst gate (`grep -l typst_ts_web_compiler dist/assets/index-*.js`) | PASS, empty |

Largest 10 files (raw, gzip -9):

| File | Raw | Gzip |
|---|---|---|
| typst_ts_web_compiler_bg-D2mWRS72.wasm | 28,325,178 | 10,767,684 |
| typst_ts_renderer_bg-DRRWm1TP.wasm | 972,425 | 355,196 |
| asset-image-C1jZhQMR.js | 701,617 | 219,078 |
| lib-FCYYGHm4.js | 315,984 | 94,265 |
| dist-C0m-jgs6.js | 310,260 | 98,658 |
| index-BkeKd_yS.js (entry) | 258,541 | 77,403 |
| db-BAm2ZQ0n.js | 132,178 | 40,360 |
| index-DHeH6EwM.css | 105,246 | 19,252 |
| dist-udCQ5Hmc.js | 100,541 | 32,061 |
| dist-BV5Kcdao.js | 97,738 | 27,596 |

Largest 10 JS chunks: the seven JS files above, then jszip.min-DJIyqfGp.js (95,880 / 28,052), TypstView-BlC35mO7.js (90,119 / 29,920), dist-Dz5KH2Ir.js (84,630 / 32,372).

## Test suite (`bench/tests.sh`)

| Metric | Value |
|---|---|
| Wall time (docker run to exit) | 56.7 s |
| Vitest duration | 54.2 s (transform 13.5 s, setup 23.7 s, import 48.3 s, tests 55.0 s, environment 193.9 s summed over workers) |
| Files | 118 passed, 1 failed, 1 skipped (120) |
| Tests | 1394 passed, 1 failed, 5 skipped (1400) |
| Failure | `typst-run-child.test.ts > kills grandchildren too`, the known pre-existing one |

## Server (`bench/server.sh`, throwaway `btct:latest` on port 8098, fresh volume)

Env: `AUTH_SECRET` random, `YPERSISTENCE=/data/yjs`, `ENABLE_TYPST=1`. "Unconstrained" has the whole host; "1 GB / 2 CPU" is `LIMITS=1` (`--memory 1g --cpus 2`, the target box).

| Metric | Unconstrained | 1 GB / 2 CPU |
|---|---|---|
| Cold start, `docker run` to `/healthz` 200 | 2644 ms | 2692 ms |
| Cold start, container created to `/healthz` 200 | 1934 ms | 1866 ms |
| Idle RSS, 15 s after healthy (sum VmRSS) | 71.3 MB (71,328 kB) | 70.5 MB |
| Idle `docker stats` memory | 30.9 MiB | 26.9 MiB |
| `/healthz` p50 / p95 / max (200 sequential) | 1.18 / 4.89 / 17.8 ms | 1.12 / 3.51 / 17.2 ms |
| Login p50 / p95 (20 sequential, PBKDF2) | 238.9 / 250.4 ms | 231.5 / 267.8 ms |
| 5 concurrent logins, wall | 251 ms | 537 ms |
| Cmdlog ingest, 10,000 events in 50 POSTs of 200 | 1884 ms, 5308 events/s | 1975 ms, 5063 events/s |
| Cmdlog batch POST p50 / p95 / max | 23.5 / 119.7 / 365.6 ms | 22.5 / 182.9 / 429.0 ms |
| Cmdlog count (10,000) / JSON export (3.3 MB) | 12.5 ms / 195 ms | 6.3 ms / 210 ms |
| RSS after API run | 107.4 MB | 102.1 MB |

### Relay (`bench/relay.mjs`, 10 clients, one room, 64-byte `Y.Map.set` per update)

| Metric | Unconstrained | 1 GB / 2 CPU |
|---|---|---|
| 10 clients connected and synced | 59 ms | 68 ms |
| Paced, 1000 updates at 200/s, 9000 deliveries: p50 / p95 / p99 / max | 2.95 / 11.0 / 16.5 / 27.1 ms | 2.77 / 8.85 / 15.7 / 24.9 ms |
| Burst, 2000 updates, 18,000 deliveries, wall | 1344 ms | 1496 ms |
| Burst throughput (lower bound, client-bound) | 1488 updates/s, 13,395 deliveries/s | 1337 updates/s, 12,032 deliveries/s |
| Burst p50 / p95 / max | 34.6 / 63.9 / 112.1 ms | 32.5 / 69.3 / 110.4 ms |
| Server RSS before / peak / after / after 10 s | 107.4 / 123.9 / 111.9 / 112.0 MB | 102.0 / 115.3 / 114.0 / 103.7 MB |
| `docker stats` after | 67.9 MiB | 57.2 MiB |

All deliveries arrived in every run, and `/healthz` was still 200 at the end.

## Notes

- The burst send loop took about as long as the whole burst (1341 of 1344 ms), so the benchmark process limited it, not the relay. A multi-process load generator would be needed to find the relay's ceiling.
- Login: one verify is about 230 ms on this CPU. Five at once took one verify's time unconstrained and about twice that under 2 CPUs, which is what an off-loop PBKDF2 on a 2-core box looks like.
- Cmdlog: the median batch is about 23 ms; a few batches took 120 to 430 ms. Which ones, and why (WAL checkpoint, the CRDT append into the shared doc), was not broken down.
- RSS of about 70 MB idle grows to about 105 to 110 MB after 10,000 cmdlog rows, with the commandLogs live window in the shared doc and SQLite cache counted in.

## After the hardening pass

Same machine, 2026-10-20, branch `hardening/2026-10-20` at `7e46bc2`. Server numbers use `SERVER_SRC=1 bench/server.sh`, which overlays the checkout's `server/*.mjs` on the existing `btct:latest` image.

| Metric | Baseline (6364d28) | After (7e46bc2) |
|---|---|---|
| Entry chunk raw / gzip | 258,541 / 77,403 B | 259,314 / 77,656 B |
| Cold start, container up to `/healthz` 200 | 1934 ms | 1783 ms |
| Idle RSS / `docker stats` | 71.3 MB / 30.9 MiB | 71.5 MB / 32.2 MiB |
| Login p50 / p95 | 238.9 / 250.4 ms | 248.5 / 251.4 ms |
| Command-log ingest, 10,000 events | 5308 events/s | 5232 events/s |
| Relay paced p50 / p95 / p99 | 2.95 / 11.0 / 16.5 ms | 3.09 / 12.8 / 18.6 ms |
| Relay burst, deliveries/s | 13,395 | 14,300 |
| Server RSS around the relay run: before / peak / after 10 s | 107.4 / 123.9 / 112.0 MB | 102.3 / 122.3 / 109.1 MB |

Every difference is inside run-to-run noise on this shared host. The pass was about bounds and leaks: an abandoned upgrade used to keep its room forever (2000 dropped upgrades left 1998 rooms open; now 0), and the login throttle map grew to 300 MB RSS under 30,000 distinct usernames (now capped at 1000 entries).

