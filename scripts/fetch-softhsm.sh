#!/usr/bin/env bash
# Unpack SoftHSM2 from the Ubuntu debs into ~/softhsm without sudo
# (CI installs the softhsm2 package instead).
set -euo pipefail
DEST="${SOFTHSM_PREFIX:-$HOME/softhsm}"
mkdir -p "$DEST/debs" "$DEST/tokens"
cd "$DEST/debs"
apt-get download softhsm2 softhsm2-common libsofthsm2 >/dev/null
for d in *.deb; do dpkg-deb -x "$d" "$DEST/root"; done
cat > "$DEST/softhsm2.conf" <<CONF
directories.tokendir = $DEST/tokens
objectstore.backend = file
log.level = ERROR
CONF
echo "module: $(find "$DEST/root" -name libsofthsm2.so | head -1)"
