# Security Audit Kit

Toolkit security testing buat web app yang di-config lewat file, jalan di Windows
maupun Linux, dan bisa dipakai ulang lintas project. Idenya: ubah temuan pentest jadi
automated test yang jalan terus di CI, lalu rangkum jadi report yang bisa
dipertanggungjawabkan — ada metodologi, bukti, alasan severity, rekomendasi plus contoh
solusinya, dan rujukan ke OWASP/BSSN.

> ⚠️ Cuma buat sistem milik sendiri atau yang kamu punya izin tertulis buat diuji.
> Scan aktif arahkan ke dev/staging, jangan ke production yang lagi dipakai user.

## Modul

| Modul | Fungsi |
|---|---|
| `authz` | Access control per role: privilege escalation, lompat status, IDOR, header `X-Auth-*` palsu dari client |
| `zap` | OWASP ZAP — passive scan / API scan dari OpenAPI, bisa jalan di balik login |
| `clientleak` | Cache response sensitif, secret/endpoint yang nyangkut di bundle JS & HTML, source map, file kebuka (`.env`, `.git/`, dump, backup) — tetap jalan walau app-nya nggak pakai JS |
| `upload` | Nolak file upload berbahaya: PDF ber-JS, polyglot, double extension, kegedean |
| `auth-policy` | Kekuatan password, captcha harus regenerate tiap gagal |
| `cors` | CORS misconfiguration: reflected origin, wildcard+credentials, Origin `null` diterima |
| `open-redirect` | Parameter pengalih (`next`/`url`/`redirect`/…) yang mengarah ke host luar |
| `tls` / `headers` | Protokol/cipher TLS usang, security header yang kurang atau malah bocorin info |
| `deps` | CVE dependency (Trivy) + SAST OWASP Top 10 (semgrep) + secret ke-commit (gitleaks) |
| `report` | Gabung semua hasil jadi `reports/laporan.html` & `.md` |

Automation ini bukan pengganti pentest manual: temuan scanner tetap harus diverifikasi,
dan celah logika bisnis cuma ketangkep kalau test-nya ditulis khusus buat kasus itu.

## Prasyarat

Python 3.10+, Docker (buat ZAP/Trivy/semgrep/gitleaks/testssl). `make` opsional.

## Cara pakai

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
cp config/targets.example.yml config/targets.yml      # isi base URL target
python audit.py all                                   # -> reports/laporan.html
```

Kredensial lewat environment variable, bukan ditaruh di file (file `*.yml` yang asli udah
masuk gitignore). Satu entry point buat semua OS: `python audit.py <modul>`. Mau perintah
pendek, pakai `make <modul>` di Linux/macOS atau `.\audit.ps1 <modul>` di Windows.

## Struktur

```
audit.py            entry point lintas-OS (satu pintu)
report.py           perangkai report gabungan
remediation.py      knowledge base remediasi & justifikasi
config/             target (contoh; yang asli di-gitignore)
scanners/           wrapper ZAP, testssl, header, trivy/semgrep/gitleaks
tests/              authz-matrix, client-leak, upload-safety, auth-policy
docs/               metodologi & pemetaan temuan -> test
.github/workflows/  contoh pipeline CI
Makefile, audit.ps1 wrapper perintah pendek per-OS
```

Lebih detail ada di [docs/metodologi.md](docs/metodologi.md) dan
[docs/temuan-to-test-mapping.md](docs/temuan-to-test-mapping.md).

## Lisensi

Apache-2.0 — lihat [LICENSE](LICENSE).
