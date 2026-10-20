# Source from WSL/Linux: build dirs off the /mnt/d 9p mount, SoftHSM paths.
source ~/.cargo/env 2>/dev/null || true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/ccb-target}"
export CCB_BUILD="${CCB_BUILD:-$HOME/ccb-build}"
if [ -z "${CCB_P11_MODULE:-}" ]; then
  for m in "$HOME/softhsm/root/usr/lib/softhsm/libsofthsm2.so" /usr/lib/softhsm/libsofthsm2.so; do
    [ -f "$m" ] && export CCB_P11_MODULE="$m" && break
  done
fi
[ -f "$HOME/softhsm/softhsm2.conf" ] && export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/softhsm/softhsm2.conf}"
export CCB_P11_TOKEN="${CCB_P11_TOKEN:-ccb}"
export CCB_P11_PIN="${CCB_P11_PIN:-1234}"
export CCB_P11_TOKEN2="${CCB_P11_TOKEN2:-ccb-b}"
