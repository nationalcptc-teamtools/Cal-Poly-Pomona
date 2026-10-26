#!/bin/sh
# Client bundle benchmark: runs `bun run build` in the pinned Bun container
# (same mounts as the test suite), then reports bundle sizes and the typst gate.
# Usage: bench/client-bundle.sh            (from anywhere)
#        SKIP_BUILD=1 bench/client-bundle.sh   (measure an existing dist/)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMG=${BUN_IMAGE:-oven/bun:1.3.14}
NM_VOL=${NM_VOLUME:-btct-harden-nm}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  start=$(date +%s.%N)
  docker run --rm -v "$ROOT":/app -w /app -v "$NM_VOL":/app/node_modules "$IMG" \
    sh -c 'bun run build' > "$ROOT/bench/.build.log" 2>&1 || { tail -40 "$ROOT/bench/.build.log"; exit 1; }
  end=$(date +%s.%N)
  echo "build_wall_s: $(echo "$end - $start" | bc)"
fi

# Measure inside the container too so the numbers do not depend on host tools.
docker run --rm -v "$ROOT":/app -w /app "$IMG" sh -c '
  set -e
  cd dist
  entry=$(ls assets/index-*.js | head -1)
  # The entry chunk is the one index.html loads as type=module.
  ref=$(grep -o "assets/index-[A-Za-z0-9_-]*\.js" index.html | head -1)
  [ -n "$ref" ] && entry=$ref
  raw=$(wc -c < "$entry")
  gz=$(gzip -9 -c "$entry" | wc -c)
  echo "entry_chunk: $entry"
  echo "entry_raw_bytes: $raw"
  echo "entry_gzip9_bytes: $gz"
  # Initial load = entry + every modulepreload + stylesheet index.html names.
  files=$(grep -oE "(href|src)=\"/?assets/[^\"]+\.(js|css)\"" index.html | sed -E "s/^(href|src)=\"\/?//; s/\"$//" | sort -u)
  n=0; ir=0; ig=0
  for f in $files; do n=$((n+1)); ir=$((ir + $(wc -c < "$f"))); ig=$((ig + $(gzip -9 -c "$f" | wc -c))); done
  echo "initial_load_files: $n"
  echo "initial_load_raw_bytes: $ir"
  echo "initial_load_gzip9_bytes: $ig"
  echo "dist_total_bytes: $(du -sb . | cut -f1)"
  echo "dist_total_human: $(du -sh . | cut -f1)"
  echo "js_chunks: $(find . -name "*.js" | wc -l)"
  echo "css_files: $(find . -name "*.css" | wc -l)"
  echo "wasm_files: $(find . -name "*.wasm" | wc -l)"
  echo "js_total_bytes: $(find . -name "*.js" -exec cat {} + | wc -c)"
  echo "largest_10_files:"
  find . -type f -printf "%s %p\n" | sort -rn | head -10 | while read s p; do
    g=$(gzip -9 -c "$p" | wc -c); echo "  $s $g $p"; done
  echo "largest_10_js_chunks (raw gzip path):"
  find . -name "*.js" -type f -printf "%s %p\n" | sort -rn | head -10 | while read s p; do
    g=$(gzip -9 -c "$p" | wc -c); echo "  $s $g $p"; done
  hits=$(grep -l typst_ts_web_compiler assets/index-*.js || true)
  if [ -z "$hits" ]; then echo "typst_gate: PASS (no index-*.js references typst_ts_web_compiler)"; else echo "typst_gate: FAIL $hits"; fi
'
