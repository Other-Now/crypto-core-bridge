#!/usr/bin/env bash
# Create the two SoftHSM2 tokens the tests use ($CCB_P11_TOKEN, $CCB_P11_TOKEN2).
# --reset deletes and recreates them.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
UTIL="$(command -v softhsm2-util || echo "$HOME/softhsm/root/usr/bin/softhsm2-util") --module $CCB_P11_MODULE"
for label in "$CCB_P11_TOKEN" "$CCB_P11_TOKEN2"; do
  if [ "${1:-}" = "--reset" ]; then
    $UTIL --delete-token --token "$label" >/dev/null 2>&1 || true
  fi
  if $UTIL --show-slots 2>/dev/null | grep -Eq "Label: +$label *$"; then
    echo "token '$label' exists"
  else
    $UTIL --init-token --free --label "$label" --pin "$CCB_P11_PIN" --so-pin 5678 >/dev/null
    echo "token '$label' created"
  fi
done
