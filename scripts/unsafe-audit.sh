#!/usr/bin/env bash
# Counts every `unsafe` in the hand-written Rust (same approach as
# tick2trade-rs): blocks, unsafe fns, unsafe impls, and whether each block
# carries a `// SAFETY:` comment. Excludes tests/, fuzz targets, and generated
# code (cxx output lives in target/).
set -euo pipefail
cd "$(dirname "$0")/.."
total_lines=0
printf "%-28s %6s %7s %10s %11s %9s\n" file lines blocks "unsafe fn" "unsafe impl" "SAFETY:"
for f in crates/ccb/src/*.rs crates/ccb-cpp/src/*.rs; do
  lines=$(grep -cv '^\s*\(//.*\)\?$' "$f" || true)
  blocks=$(grep -Ec 'unsafe \{|unsafe\s*\{' "$f" || true)
  fns=$(grep -Ec 'unsafe (extern "C" )?fn ' "$f" || true)
  impls=$(grep -Ec 'unsafe impl' "$f" || true)
  safety=$(grep -c '// SAFETY:' "$f" || true)
  total_lines=$((total_lines + lines))
  printf "%-28s %6d %7d %10d %11d %9d\n" "$f" "$lines" "$blocks" "$fns" "$impls" "$safety"
done
echo
echo "clippy::undocumented_unsafe_blocks is enabled (warn, -D warnings in CI): every block needs a SAFETY comment."
echo "code lines: $total_lines"
