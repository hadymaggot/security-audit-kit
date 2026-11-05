#!/usr/bin/env sh
# Uji TLS (protokol usang, cipher lemah) dan security header respons.
# Keduanya mekanis dan cocok diotomasi — menangkap "Deprecated Cryptography
# Protocol" dan "Missing Security Header" ala laporan pentest.
#
# Pakai:
#   ./run-tls-headers.sh dev.contoh.local            # TLS + header di /
#   ./run-tls-headers.sh dev.contoh.local /login     # probe path lain
set -eu

HOST="${1:-}"
PROBE="${2:-/}"
OUTDIR="${OUTDIR:-./reports}"
[ -n "$HOST" ] || { echo "host wajib. contoh: ./run-tls-headers.sh dev.contoh.local" >&2; exit 2; }
mkdir -p "$OUTDIR"

echo "== TLS ($HOST) =="
# testssl.sh via docker; ringkas ke protokol & kerentanan.
docker run --rm -v "$(pwd)/$OUTDIR:/out" drwetter/testssl.sh:latest \
  --protocols --vulnerable --severity HIGH \
  --jsonfile /out/testssl.json "$HOST" || true

echo
echo "== Security header ($HOST$PROBE) =="
URL="https://$HOST$PROBE"
HDRS=$(curl -skD - -o /dev/null "$URL")
printf '%s\n' "$HDRS" > "$OUTDIR/headers.txt"

# Header yang diharapkan ada; yang tidak ada ditandai.
for h in \
  "Strict-Transport-Security" \
  "Content-Security-Policy" \
  "X-Content-Type-Options" \
  "X-Frame-Options" \
  "Referrer-Policy" ; do
  if printf '%s' "$HDRS" | grep -iq "^$h:"; then
    echo "ok   $h"
  else
    echo "MISS $h"
  fi
done

# Header yang justru membocorkan info sebaiknya TIDAK ada.
for h in "Server" "X-Powered-By" ; do
  val=$(printf '%s' "$HDRS" | grep -i "^$h:" || true)
  [ -n "$val" ] && echo "LEAK $val" || echo "ok   $h tidak dibocorkan"
done
