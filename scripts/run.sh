#!/usr/bin/env bash
# Run a command from the repo root with scripts/env.sh loaded (used from WSL).
set -e
cd "$(dirname "$0")/.."
source scripts/env.sh
"$@"
