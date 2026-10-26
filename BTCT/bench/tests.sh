#!/bin/sh
# Test suite wall time, same command the repo uses. Prints the vitest summary
# lines and the wall time. Optional arg: a single test file.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMG=${BUN_IMAGE:-oven/bun:1.3.14}
NM_VOL=${NM_VOLUME:-btct-harden-nm}
start=$(date +%s.%N)
docker run --rm -v "$ROOT":/app -w /app -v "$NM_VOL":/app/node_modules "$IMG" \
  sh -c "bun x vitest run ${1:-}" > "$ROOT/bench/.tests.log" 2>&1
rc=$?
end=$(date +%s.%N)
grep -E "Test Files|Tests |Duration|FAIL" "$ROOT/bench/.tests.log" | sed 's/\x1b\[[0-9;]*m//g' | tail -15
echo "vitest_exit: $rc"
echo "tests_wall_s: $(echo "$end - $start" | bc)"
