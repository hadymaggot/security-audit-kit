#!/usr/bin/env pwsh
# PowerShell wrapper for Windows: short commands that forward to `python audit.py`.
# Examples:
#   .\audit.ps1 install
#   .\audit.ps1 all
#   .\audit.ps1 zap baseline
#   .\audit.ps1 clientleak
#   .\audit.ps1 report
# Multi-project (parallel, one terminal per project):
#   .\audit.ps1 init authz,upload -Project my-app   # creates projects\my-app\
#   .\audit.ps1 all -Project my-app
#   .\audit.ps1 headers -Project D:\audit\client-b           # any folder

param(
    [Parameter(Position = 0)]
    [string]$Module = "help",

    # Project name (-> <kit>\projects\<name>) or folder; same as `--project` / SAK_PROJECT_DIR.
    [string]$Project = "",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
# Relative project paths resolve against the caller's folder, not the kit folder.
$env:SAK_CALLER_CWD = (Get-Location).Path
Set-Location -Path $PSScriptRoot

# Pick whichever Python interpreter is available.
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
        # Forward as-is: [--project X] module + remaining args (e.g. 'zap baseline').
        & $py.Source "audit.py" @projectArgs $Module @Rest
        exit $LASTEXITCODE
    }
}
