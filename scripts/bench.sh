#!/usr/bin/env bash
# Runs both benchmark harnesses and writes results/bench-<host>.csv.
# Usage: bench.sh [reps]
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
REPS="${1:-15}"
bash scripts/build-cpp.sh release >/dev/null
cargo build --release -p ccb-cpp --example bench >/dev/null 2>&1
# Pin to one core when possible: fewer migrations, steadier medians.
PIN=""
command -v taskset >/dev/null && PIN="taskset -c ${CCB_BENCH_CPU:-2}"
mkdir -p results
OUT="results/bench-${CCB_HOST:-$(hostname -s)}.csv"
{
  $PIN "$CCB_BUILD/release/bench" "$REPS"
  $PIN "$CARGO_TARGET_DIR/release/examples/bench" "$REPS" | tail -n +2
} > "$OUT"
echo "wrote $OUT"
python3 scripts/bench_table.py "$OUT"
