#!/usr/bin/env pwsh
# Sync GitHub labels from .github/labels.yml (the source of truth).
# Requires the gh CLI (logged in). No yq: simple parsing in PowerShell.
# Idempotent: --force creates a missing label and updates color/description of an existing one.
#
# Usage (from the repo root):
#   .\scripts\sync-labels.ps1

param([string]$File = ".github/labels.yml")
$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) { Write-Error "Tak ketemu $File"; exit 1 }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Write-Error "Butuh gh CLI"; exit 1 }

$content = Get-Content $File -Raw
# Flat format: - name / color / description, in that order.
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
