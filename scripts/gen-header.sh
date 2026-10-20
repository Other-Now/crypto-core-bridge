#!/usr/bin/env bash
# Regenerate include/ccb.h from the Rust FFI layer.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh 2>/dev/null || true
cbindgen --config crates/ccb/cbindgen.toml --crate ccb --output include/ccb.h crates/ccb
