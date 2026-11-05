#!/usr/bin/env pwsh
# Pembungkus PowerShell untuk Windows — perintah pendek, meneruskan ke `python audit.py`.
# Contoh:
#   .\audit.ps1 install
#   .\audit.ps1 all
#   .\audit.ps1 zap baseline
#   .\audit.ps1 clientleak
#   .\audit.ps1 report

param(
    [Parameter(Position = 0)]
    [string]$Module = "help",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Pilih interpreter Python yang tersedia.
$py = (Get-Command python -ErrorAction SilentlyContinue) `
    ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $py) { Write-Error "Python tidak ditemukan di PATH."; exit 2 }

switch ($Module) {
    "help" {
        Write-Host "Perintah:"
        Write-Host "  .\audit.ps1 install        - pasang dependensi Python"
        Write-Host "  .\audit.ps1 all            - semua modul + susun laporan"
        Write-Host "  .\audit.ps1 zap baseline   - OWASP ZAP passive"
        Write-Host "  .\audit.ps1 zap api        - OWASP ZAP dari OpenAPI"
        Write-Host "  .\audit.ps1 zap full       - OWASP ZAP active (dev/staging sendiri)"
        Write-Host "  .\audit.ps1 authz          - regresi kontrol akses per peran"
        Write-Host "  .\audit.ps1 upload         - uji penolakan unggahan berbahaya"
        Write-Host "  .\audit.ps1 auth-policy    - kebijakan sandi & captcha"
        Write-Host "  .\audit.ps1 clientleak     - cache klien, rahasia JS/HTML, berkas ter-ekspos"
        Write-Host "  .\audit.ps1 tls            - protokol/cipher TLS"
        Write-Host "  .\audit.ps1 headers        - security header respons"
        Write-Host "  .\audit.ps1 deps           - CVE dependensi + SAST + rahasia"
        Write-Host "  .\audit.ps1 report         - gabungkan jadi reports/laporan.html"
        Write-Host "  .\audit.ps1 clean          - hapus isi reports/"
    }
    "install" {
        & $py.Source -m pip install -r requirements.txt
    }
    "clean" {
        Get-ChildItem -Path "reports" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Force
        Write-Host "reports/ dibersihkan."
    }
    default {
        # Teruskan apa adanya: modul + argumen sisa (mis. 'zap baseline').
        & $py.Source "audit.py" $Module @Rest
        exit $LASTEXITCODE
    }
}
