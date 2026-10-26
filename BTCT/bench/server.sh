#!/bin/sh
# Server benchmark against a THROWAWAY container from the existing btct:latest
# image. Never touches the real "btct" container, its volume or port 8080.
#
#   bench/server.sh                 # unconstrained
#   LIMITS=1 bench/server.sh        # 1 GB / 2 CPUs, the target box
#
# Measures: cold start to /healthz 200, idle memory, /healthz and login
# latency, cmdlog ingest of EVENTS events (bench/api.mjs), y-websocket relay
# propagation with N clients (bench/relay.mjs), server memory before, peak
# during and after the relay run. Removes the container and volume on exit.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMG=${BUN_IMAGE:-oven/bun:1.3.14}
NM_VOL=${NM_VOLUME:-btct-harden-nm}
NAME=${BENCH_CONTAINER:-btct-bench}
VOL=${BENCH_VOLUME:-btct-bench-data}
PORT=${BENCH_PORT:-8098}
BASE="http://127.0.0.1:$PORT"
OUT=${BENCH_OUT:-$ROOT/bench/.server-run}
mkdir -p "$OUT"

case "$NAME$VOL$PORT" in *btct-data*|*8080*) echo "refusing: would touch the live instance"; exit 2;; esac
[ "$NAME" = "btct" ] && { echo "refusing: container name btct is the live instance"; exit 2; }

cleanup() {
  [ -n "${SAMPLER:-}" ] && kill "$SAMPLER" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Server process memory from inside the container: sum of VmRSS over every
# process (the image has no ps). docker stats is the cgroup figure, which also
# counts page cache.
rss_kb() {
  docker exec "$NAME" sh -c 'for f in /proc/[0-9]*/status; do awk "/^VmRSS/{print \$2}" "$f" 2>/dev/null; done' | awk '{s+=$1} END {print s+0}'
}
cg_mem() { docker stats --no-stream --format '{{.MemUsage}}' "$NAME"; }
bunrun() {
  docker run --rm --network host -v "$ROOT":/app:ro -w /app -v "$NM_VOL":/app/node_modules \
    -e BASE="$BASE" "$@"
}

cleanup
docker volume create "$VOL" >/dev/null
SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
LIMIT_ARGS=""
[ "${LIMITS:-0}" = "1" ] && LIMIT_ARGS="--memory 1g --cpus 2"

t0=$(date +%s%N)
# shellcheck disable=SC2086
# SERVER_SRC=1 overlays this checkout's server/*.mjs on the image, to measure
# server changes without building a new image.
SRC_ARGS=""
if [ "${SERVER_SRC:-0}" = "1" ]; then
  for f in "$ROOT"/server/*.mjs; do SRC_ARGS="$SRC_ARGS -v $f:/app/server/$(basename "$f"):ro"; done
fi
docker run -d --name "$NAME" -p 127.0.0.1:$PORT:8080 -v "$VOL":/data $LIMIT_ARGS $SRC_ARGS \
  -e AUTH_SECRET="$SECRET" -e YPERSISTENCE=/data/yjs -e ENABLE_TYPST=1 btct:latest >/dev/null
t1=$(date +%s%N)
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz" 2>/dev/null)" = "200" ]; do
  [ $(( ($(date +%s%N) - t0) / 1000000 )) -gt 120000 ] && { echo "no healthz after 120 s"; docker logs "$NAME" | tail -30; exit 1; }
  sleep 0.05
done
t2=$(date +%s%N)
echo "cold_start_docker_run_to_healthz_ms: $(( (t2 - t0) / 1000000 ))"
echo "cold_start_container_up_to_healthz_ms: $(( (t2 - t1) / 1000000 ))"
echo "limits: ${LIMIT_ARGS:-none}"

sleep "${IDLE_WAIT_S:-15}"
echo "idle_rss_kb: $(rss_kb)"
echo "idle_docker_stats: $(cg_mem)"

echo "--- api.mjs (healthz, login, cmdlog ingest)"
bunrun -e EVENTS="${EVENTS:-10000}" "$IMG" bun bench/api.mjs | tee "$OUT/api.json"
sleep 3
echo "after_api_rss_kb: $(rss_kb)"
echo "after_api_docker_stats: $(cg_mem)"

echo "--- relay.mjs"
before=$(rss_kb)
echo "relay_before_rss_kb: $before"
: > "$OUT/rss-samples.txt"
( while :; do rss_kb >> "$OUT/rss-samples.txt" 2>/dev/null || true; sleep 0.25; done ) &
SAMPLER=$!
bunrun -e N="${N:-10}" -e M_PACED="${M_PACED:-1000}" -e RATE="${RATE:-200}" -e M_BURST="${M_BURST:-2000}" \
  "$IMG" bun bench/relay.mjs | tee "$OUT/relay.json"
kill "$SAMPLER" 2>/dev/null || true; SAMPLER=""
echo "relay_peak_rss_kb: $(sort -n "$OUT/rss-samples.txt" | tail -1)"
echo "relay_after_rss_kb: $(rss_kb)"
sleep 10
echo "relay_after_10s_rss_kb: $(rss_kb)"
echo "relay_after_docker_stats: $(cg_mem)"
echo "healthz_final: $(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")"
docker logs "$NAME" 2>&1 | grep -iE 'error|warn' | head -10 || true
