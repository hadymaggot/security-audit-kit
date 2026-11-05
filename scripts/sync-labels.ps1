#!/usr/bin/env pwsh
# Sinkronkan label GitHub dari .github/labels.yml (sumber kebenaran).
# Butuh: gh CLI (sudah login). Tanpa yq — parsing sederhana di PowerShell.
# Idempoten: --force = bikin kalau belum ada, update warna/deskripsi kalau sudah.
#
# Pakai (dari root repo):
#   .\scripts\sync-labels.ps1

param([string]$File = ".github/labels.yml")
$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) { Write-Error "Tak ketemu $File"; exit 1 }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Write-Error "Butuh gh CLI"; exit 1 }

$content = Get-Content $File -Raw
# Format flat: - name / color / description, berurutan.
$pattern = '(?ms)^-\s+name:\s*"([^"]+)"\s*\r?\n\s*color:\s*"([^"]+)"\s*\r?\n\s*description:\s*"([^"]*)"'
$matches = [regex]::Matches($content, $pattern)

$n = 0
foreach ($m in $matches) {
    $name = $m.Groups[1].Value
    $color = $m.Groups[2].Value
    $desc = $m.Groups[3].Value
    gh label create $name --color $color --description $desc --force
    $n++
}
Write-Host "Selesai: $n label disinkronkan."
