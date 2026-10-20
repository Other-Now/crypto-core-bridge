#!/usr/bin/env bash
# Builds and runs the ML-KEM / ML-DSA interop test against OpenSSL 3.5.
# OSSL35_PREFIX defaults to ~/ossl35 (scripts/build-openssl35.sh 3.5.x).
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
PREFIX="${OSSL35_PREFIX:-$HOME/ossl35}"
python3 pq/flatten_vectors.py testvectors/wycheproof "$CCB_BUILD/pq-vectors"
cmake -S pq -B "$CCB_BUILD/pq" -G Ninja -DOPENSSL_ROOT_DIR="$PREFIX" >/dev/null
cmake --build "$CCB_BUILD/pq"
"$CCB_BUILD/pq/pq_interop" "$CCB_BUILD/pq-vectors" "${1:-1000}"
