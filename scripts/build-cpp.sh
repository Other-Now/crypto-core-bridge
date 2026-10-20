#!/usr/bin/env bash
# Configure + build the C++ side. Usage: build-cpp.sh [release|asan]
# Builds the Rust staticlib first so the cross-language targets link.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
MODE="${1:-release}"
cargo build --release -p ccb --features test-hooks
case "$MODE" in
  release) EXTRA="-DCCB_SANITIZE=OFF" ;;
  asan)    EXTRA="-DCCB_SANITIZE=ON" ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac
cmake -S cpp -B "$CCB_BUILD/$MODE" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo $EXTRA \
  -DCCB_RUST_LIB="$CARGO_TARGET_DIR/release/libccb.a" >/dev/null
cmake --build "$CCB_BUILD/$MODE"
