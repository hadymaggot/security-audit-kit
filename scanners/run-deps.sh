#!/usr/bin/env sh
# Analisis statis repo kode (SAST + SCA + secret scan) via image resmi.
# Setara pola yang umum dipakai di CI: gitleaks + semgrep + trivy.
#
# Pakai: ./run-deps.sh [path-repo]   (default: direktori saat ini)
set -eu

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
OUTDIR="${OUTDIR:-./reports}"
mkdir -p "$OUTDIR"

echo "== gitleaks (rahasia ter-commit) =="
# --no-renames penting: tanpa itu commit rename murni tak ter-diff & isinya terlewat.
docker run --rm -v "$REPO:/repo:ro" -w /repo zricethezav/gitleaks:latest \
  detect --source /repo --redact --no-banner \
  --report-path /dev/stdout --exit-code 0 --log-opts="--no-renames" || true

echo
echo "== semgrep (SAST, OWASP Top 10) =="
docker run --rm -v "$REPO:/src:ro" -w /src -e SEMGREP_SEND_METRICS=off \
  semgrep/semgrep:latest semgrep scan \
    --config p/owasp-top-ten --config p/security-audit \
    --severity ERROR --metrics=off \
    --exclude vendor --exclude node_modules || true

echo
echo "== trivy (dependensi rentan & rahasia) =="
CACHE="${HOME}/.cache/sak-trivy"
mkdir -p "$CACHE"
docker run --rm -v "$REPO:/repo:ro" -v "$CACHE:/root/.cache/trivy" \
  aquasec/trivy:latest fs /repo \
    --scanners vuln,secret --severity HIGH,CRITICAL \
    --ignore-unfixed || true

echo
echo "Selesai. Tinjau temuan — skrip ini tidak menggagalkan build (informatif)."
