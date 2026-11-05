#!/usr/bin/env sh
# Pembungkus OWASP ZAP via image resmi (zaproxy/zap-stable).
# Tiga mode:
#   baseline  — passive scan cepat satu URL (aman, tanpa serangan aktif). Default.
#   api       — scan dari spesifikasi OpenAPI (import endpoint lalu uji).
#   full      — active scan (kirim payload uji). HANYA ke dev/staging milik sendiri.
#
# Autentikasi: set ZAP_AUTH_HEADER untuk menyertakan header di tiap request,
#   mis. export ZAP_AUTH_HEADER="Authorization: Bearer <token-uji>"
#
# Pakai:
#   ./run-zap.sh baseline https://dev.contoh.local
#   ./run-zap.sh api https://dev.contoh.local https://dev.contoh.local/api/docs/openapi.json
#   ZAP_AUTH_HEADER="Authorization: Bearer xxx" ./run-zap.sh full https://dev.contoh.local
set -eu

MODE="${1:-baseline}"
TARGET="${2:-}"
OPENAPI="${3:-}"
OUTDIR="${ZAP_OUTDIR:-./reports}"
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

if [ -z "$TARGET" ]; then
  echo "target wajib. contoh: ./run-zap.sh baseline https://dev.contoh.local" >&2
  exit 2
fi
mkdir -p "$OUTDIR"

# Opsi tambahan ZAP: sisipkan header auth bila ada, supaya scan di balik login.
EXTRA=""
if [ -n "${ZAP_AUTH_HEADER:-}" ]; then
  # -config replacer menambah header ke semua request keluar.
  EXTRA="-config replacer.full_list(0).description=auth \
-config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER \
-config replacer.full_list(0).matchstr=$(printf %s "$ZAP_AUTH_HEADER" | cut -d: -f1) \
-config replacer.full_list(0).replacement=$(printf %s "$ZAP_AUTH_HEADER" | cut -d: -f2- | sed 's/^ //')"
fi

run() { docker run --rm -v "$(pwd)/$OUTDIR:/zap/wrk:rw" "$IMAGE" "$@"; }

case "$MODE" in
  baseline)
    # Passive — tidak menyerang; menandai header hilang, cookie, info bocor, dll.
    run zap-baseline.py -t "$TARGET" -r zap-baseline.html -J zap-baseline.json -I $EXTRA
    ;;
  api)
    [ -n "$OPENAPI" ] || { echo "mode api butuh argumen OpenAPI" >&2; exit 2; }
    run zap-api-scan.py -t "$OPENAPI" -f openapi -r zap-api.html -J zap-api.json -I $EXTRA
    ;;
  full)
    echo "ACTIVE SCAN — pastikan target dev/staging milik sendiri. Ctrl-C untuk batal." >&2
    sleep 3
    run zap-full-scan.py -t "$TARGET" -r zap-full.html -J zap-full.json -I $EXTRA
    ;;
  *)
    echo "mode tak dikenal: $MODE (baseline|api|full)" >&2
    exit 2
    ;;
esac

echo "Laporan di $OUTDIR/"
