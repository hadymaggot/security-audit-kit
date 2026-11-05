#!/usr/bin/env sh
# Sinkronkan label GitHub dari .github/labels.yml (sumber kebenaran).
# Butuh: gh CLI (sudah login) + yq. Idempoten — bikin yang belum ada, update warna/deskripsi.
#
# Pakai (dari root repo):
#   sh scripts/sync-labels.sh
set -eu

FILE=".github/labels.yml"
[ -f "$FILE" ] || { echo "Tak ketemu $FILE" >&2; exit 1; }
command -v gh >/dev/null || { echo "Butuh gh CLI" >&2; exit 1; }
command -v yq >/dev/null || { echo "Butuh yq (mikefarah/yq)" >&2; exit 1; }

n=$(yq 'length' "$FILE")
i=0
while [ "$i" -lt "$n" ]; do
  name=$(yq -r ".[$i].name" "$FILE")
  color=$(yq -r ".[$i].color" "$FILE")
  desc=$(yq -r ".[$i].description" "$FILE")
  # --force = update kalau sudah ada.
  gh label create "$name" --color "$color" --description "$desc" --force
  i=$((i + 1))
done
echo "Selesai: $n label disinkronkan."
