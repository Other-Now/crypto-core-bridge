#!/usr/bin/env bash
# Build OpenSSL 3.5 (ML-KEM/ML-DSA) into ~/ossl35 for the optional PQ interop test.
# The main build uses the distro OpenSSL 3.0.
set -euo pipefail
VER="${1:?usage: build-openssl35.sh 3.5.x}"
PREFIX="${OSSL35_PREFIX:-$HOME/ossl35}"
SRC="$HOME/ossl35-src"
mkdir -p "$SRC" && cd "$SRC"
[ -f "openssl-$VER.tar.gz" ] || curl -sSLO "https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz"
tar xzf "openssl-$VER.tar.gz" && cd "openssl-$VER"
./Configure --prefix="$PREFIX" --libdir=lib no-docs no-tests shared >/dev/null
make -j"$(nproc)" >/dev/null 2>&1
make install_sw >/dev/null
LD_LIBRARY_PATH="$PREFIX/lib" "$PREFIX/bin/openssl" version
