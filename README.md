# Security Audit Kit

Toolkit security testing untuk web app yang di-config lewat file, berjalan di Windows
maupun Linux, dan dapat digunakan ulang lintas project. Idenya: ubah temuan pentest menjadi
automated test yang berjalan terus di CI, lalu rangkum menjadi report yang dapat
dipertanggungjawabkan — ada metodologi, bukti, alasan severity, rekomendasi beserta contoh
solusinya, dan rujukan ke OWASP/BSSN.

> ⚠️ Hanya untuk sistem milik sendiri atau yang Anda miliki izin tertulis untuk diuji.
> Scan aktif arahkan ke dev/staging, jangan ke production yang sedang digunakan user.

## Modul

| Modul | Fungsi |
|---|---|
| `authz` | Access control per role: privilege escalation, lompat status, IDOR, header `X-Auth-*` palsu dari client |
| `zap` | OWASP ZAP — passive scan / API scan dari OpenAPI, bisa jalan di balik login |
| `clientleak` | Cache response sensitif, secret/endpoint yang tersisip di bundle JS & HTML, source map, file terekspos (`.env`, `.git/`, dump, backup) — tetap berjalan walau app-nya tidak menggunakan JS |
| `upload` | Menolak file upload berbahaya: PDF ber-JS, polyglot, double extension, terlalu besar |
| `auth-policy` | Kekuatan password, captcha harus regenerate tiap gagal |
| `mass-assignment` | Mass assignment / privilege escalation (BOPLA): menyuntikkan field terlarang (`role`, `is_admin`, `company_id`) ke objek milik sendiri. **Destruktif tapi reversibel** — tiap tulisan dicatat ke jurnal & dipulihkan otomatis setelah laporan (`audit.py rollback` untuk replay) |
| `cors` | CORS misconfiguration: reflected origin, wildcard+credentials, Origin `null` diterima |
| `open-redirect` | Parameter pengalih (`next`/`url`/`redirect`/…) yang mengarah ke host luar |
| `tls` / `headers` | Protokol/cipher TLS usang, security header yang kurang atau malah membocorkan info |
| `webstack` | Deteksi versi dari banner `Server`/`X-Powered-By` lalu petakan ke CVE yang diketahui (mis. Apache mod_http2, NGINX HTTP/2, PHP2Shell); mendukung rentang `min_version`, non-destruktif, `known_vulnerable` dapat diperbarui lewat config |
| `injection` | SQL injection (error-based, boolean-based, time-based opsional); non-destruktif (probing baca, tidak mengubah data) |
| `deps` | CVE dependency (Trivy) + SAST OWASP Top 10 (semgrep) + secret ter-commit (gitleaks) |
| `report` | Gabung semua hasil jadi `reports/laporan.html` & `.md` |

Automation ini bukan pengganti pentest manual: temuan scanner tetap harus diverifikasi,
dan celah logika bisnis hanya terdeteksi apabila test-nya ditulis khusus untuk kasus itu.

## Prasyarat

Python 3.10+, Docker (untuk ZAP/Trivy/semgrep/gitleaks/testssl). `make` opsional.

## Penggunaan

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
cp config/targets.example.yml config/targets.yml      # isi base URL target
python audit.py all                                   # -> reports/laporan.html
```

Kredensial lewat environment variable, bukan ditaruh di file (file `*.yml` yang asli sudah
masuk gitignore). Satu entry point untuk semua OS: `python audit.py <modul>`. Untuk perintah
pendek, gunakan `make <modul>` di Linux/macOS atau `.\audit.ps1 <modul>` di Windows.

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
Makefile, audit.ps1 wrapper perintah pendek per OS
```

Lebih detail ada di [docs/metodologi.md](docs/metodologi.md) dan
[docs/temuan-to-test-mapping.md](docs/temuan-to-test-mapping.md). Contoh bentuk
laporan akhir: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Dokumentasi

| Dokumen | Isi |
|---|---|
| [docs/panduan-penggunaan.md](docs/panduan-penggunaan.md) | Panduan step-by-step: instalasi, konfigurasi, autentikasi, menjalankan scan, membaca laporan, rollback, troubleshooting |
| [docs/metodologi.md](docs/metodologi.md) | Metodologi uji & acuan standar (OWASP, ASVS, Risk Rating) |
| [docs/temuan-to-test-mapping.md](docs/temuan-to-test-mapping.md) | Menerjemahkan temuan laporan pentest menjadi kasus uji per modul |
| [docs/contoh-laporan.md](docs/contoh-laporan.md) · [contoh-laporan.html](docs/contoh-laporan.html) · [slide](docs/contoh-laporan-slides.html) | Contoh output laporan (data fiktif) — format konsultan + varian presentasi/slide |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Kontribusi, kebijakan keamanan, kode etik |

## Kontribusi

Alur kontribusi, cara menambahkan check, dan konvensi commit ada di
[CONTRIBUTING.md](CONTRIBUTING.md).

## Lisensi

Apache-2.0 — lihat [LICENSE](LICENSE).
