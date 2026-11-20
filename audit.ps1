#!/usr/bin/env pwsh
# Pembungkus PowerShell untuk Windows — perintah pendek, meneruskan ke `python audit.py`.
# Contoh:
#   .\audit.ps1 install
#   .\audit.ps1 all
#   .\audit.ps1 zap baseline
#   .\audit.ps1 clientleak
#   .\audit.ps1 report
# Multi-project (paralel, satu terminal per project):
#   .\audit.ps1 init authz,upload -Project apple-gatrik   # buat projects\apple-gatrik\
#   .\audit.ps1 all -Project apple-gatrik
#   .\audit.ps1 headers -Project D:\audit\kumham           # folder di mana saja

param(
    [Parameter(Position = 0)]
    [string]$Module = "help",

    # Nama project (-> <kit>\projects\<nama>) atau folder; setara `--project` / SAK_PROJECT_DIR.
    [string]$Project = "",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
# Path project relatif diselesaikan terhadap folder pemanggil, bukan folder kit.
$env:SAK_CALLER_CWD = (Get-Location).Path
Set-Location -Path $PSScriptRoot

# Pilih interpreter Python yang tersedia.
$py = (Get-Command python -ErrorAction SilentlyContinue) `
    ?? (Get-Command python3 -ErrorAction SilentlyContinue)
if (-not $py) { Write-Error "Python tidak ditemukan di PATH."; exit 2 }

$projectArgs = @()
if ($Project) { $projectArgs = @("--project", $Project) }

switch ($Module) {
    "help" {
        Write-Host "Perintah (tambahkan -Project <nama|folder> untuk multi-project):"
        Write-Host "  .\audit.ps1 install        - pasang dependensi Python"
        Write-Host "  .\audit.ps1 init a,b       - siapkan folder project (+ config modul a,b)"
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
    default {
        # Teruskan apa adanya: [--project X] modul + argumen sisa (mis. 'zap baseline').
        & $py.Source "audit.py" @projectArgs $Module @Rest
        exit $LASTEXITCODE
    }
}
