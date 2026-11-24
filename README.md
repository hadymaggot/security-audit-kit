**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](README.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](README.de.md)

# Security Audit Kit

![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
[![Sponsor di GitHub](https://img.shields.io/badge/Sponsor_di-GitHub-ea4aaa?style=flat&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/hadymaggot)
[![Dukung di Saweria](https://img.shields.io/badge/Dukung_di-Saweria-faae2b?style=flat&logo=buymeacoffee&logoColor=black)](https://saweria.co/hadymaggot)

Toolkit security testing berbasis *file* config untuk web app: mengubah temuan pentest menjadi automated test, lalu menyusun hasilnya menjadi report yang dapat dipertanggungjawabkan.

- Menguji lebih dari 20 modul: *header*, TLS, *access control*, *upload*, injection, JWT, CORS, *dependency*, dan lainnya.
- Non-destruktif secara bawaan. Modul yang menulis data (`mass-assignment`, `ratelimit`, `session-mgmt`) dan scan aktif ZAP dengan blok `snapshot` dipulihkan otomatis lewat *rollback*.
- Report setara konsultan dalam HTML, Markdown, dan slide: bukti, alasan severity, rekomendasi dengan contoh perbaikan, dan rujukan OWASP/BSSN.

> Hanya untuk sistem milik sendiri atau yang Anda miliki izin tertulis untuk diuji. Arahkan scan aktif ke dev/staging, bukan production.

## Mulai cepat

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
python audit.py --project my-app init
# edit projects/my-app/config/targets.yml: base_url: "https://dev.example.com"
python audit.py --project my-app headers
python audit.py --project my-app report
```

Hasil yang diharapkan: tiap *header* dicetak `ok`, `MISS`, atau `LEAK` (kode keluar 1 jika ada temuan), lalu `projects/my-app/reports/laporan.html` terbentuk. Buka *file* itu di browser.

## Modul

Jalankan dengan `python audit.py --project my-app <modul>`. `all` menjalankan semua modul yang config-nya ada, lalu report dan *rollback*.

| Modul | Pemeriksaan | Kredensial? |
|---|---|---|
| `headers` | Security *header* yang kurang; bocoran `Server`/`X-Powered-By` | Tidak |
| `tls` | Protokol/cipher TLS usang dan kerentanan TLS (testssl.sh) | Tidak |
| `webstack` | Versi dari banner `Server`/`X-Powered-By` dipetakan ke CVE | Tidak |
| `zap` | OWASP ZAP: `baseline` (passive), `api` dari OpenAPI, `full` (aktif) | Opsional |
| `deps` | CVE *dependency* (Trivy), SAST (semgrep), *secret* ter-commit (gitleaks) | Tidak |
| `recon` | OSINT pasif (subfinder, dnsx, httpx); port scan dan nuclei hanya jika diaktifkan di config | Tidak |
| `clientleak` | *Cache response* sensitif, secret/source map di JS dan HTML, *file* terekspos (`.env`, `.git/`) | Opsional |
| `cookie-flags` | `HttpOnly`, `Secure`, `SameSite`, dan masa berlaku *cookie* | Opsional |
| `cors` | Reflected origin, wildcard dengan *credentials*, Origin `null` | Opsional |
| `open-redirect` | Parameter *redirect* (`next`, `url`, `redirect`) ke host luar | Opsional |
| `response-leak` | Key sensitif, *secret*, *stack trace*, dan IP internal di *response* API | Opsional |
| `openapi-coverage` | Operasi GET yang dilindungi menurut OpenAPI tetapi terbuka tanpa *login* | Tidak |
| `captcha` | Jawaban captcha yang bocor di *response* tantangan | Tidak |
| `auth-policy` | Kekuatan *password*, captcha harus berganti tiap kali | Opsional |
| `authz` | *Access control* per *role*: privilege escalation, IDOR, *header* `X-Auth-*` palsu | Ya |
| `upload` | Penolakan *upload* berbahaya: PDF ber-JS, polyglot, double extension | Opsional |
| `injection` | SQL injection error-based, boolean-based, dan time-based (opsional) | Opsional |
| `jwt` | Algoritma `none`, *secret* lemah, *token* dipalsukan atau tanpa `exp` | Ya |
| `ssrf` | *Endpoint* yang menerima URL, diuji dengan listener canary lokal | Opsional |
| `mass-assignment` | Field terlarang (`role`, `is_admin`) pada objek sendiri; dipulihkan otomatis | Ya |
| `ratelimit` | *Rate limit*, *lockout* akun, dan enumerasi akun pada akun uji sekali pakai | Ya |
| `session-mgmt` | Sesi dicabut setelah *logout* dan ganti *password* | Ya |

Perintah lain: `init`, `report`, `rollback`, `clean`. Daftar lengkap: `python audit.py --help`. Hasil scanner tetap perlu diverifikasi; celah logika bisnis hanya terdeteksi jika test-nya ditulis untuk kasus itu.

## Prasyarat

- [ ] Python 3.10+ dan `pip install -r requirements.txt`
- [ ] Docker untuk `zap`, `tls`, dan `deps`
- [ ] Opsional: Playwright untuk verifikasi *cache* browser di `clientleak`
- [ ] Kredensial lewat environment variable, bukan di *file*

## Dokumentasi

| Dokumen | Isi |
|---|---|
| [Panduan penggunaan](docs/panduan-penggunaan.md) | Instalasi, config, autentikasi, scan, report, *rollback*, troubleshooting |
| [Runner otonom](docs/runner.md) | Menjalankan seluruh audit dari scan sampai report tanpa campur tangan manual dan tanpa AI; dapat dipakai untuk project baru lewat satu config |
| [Glosarium](docs/glosarium.md) | Istilah teknis per bahasa dan opsi `--lang` |
| [Metodologi](docs/metodologi.md) | Tahapan uji dan acuan standar (OWASP, ASVS) |
| [Pemetaan temuan ke test](docs/temuan-to-test-mapping.md) | Mengubah temuan pentest menjadi kasus uji |
| [Contoh report](docs/contoh-laporan.md) | Contoh output dengan data fiktif ([HTML](docs/contoh-laporan.html), [slide](docs/contoh-laporan-slides.html)) |
| [Contributing](CONTRIBUTING.md) | Alur kontribusi dan cara menambah check |
| [Situs](https://hadymaggot.github.io/security-audit-kit/id/) | Halaman proyek dan open scanner pasif ([setup Worker](worker/README.md)) |

Opsi lanjutan (di panduan): [multi-project](docs/panduan-penggunaan.md#multi-project-paralel), [menjalankan dari folder mana pun](docs/panduan-penggunaan.md#menjalankan-dari-folder-mana-pun), [warna keluaran](docs/panduan-penggunaan.md#warna-konsol), [bahasa dan istilah](docs/panduan-penggunaan.md#bahasa-dan-istilah-teknis).

## Struktur proyek

```text
audit.py, audit.ps1, Makefile   # entry point lintas-OS dan wrapper pendek
runner.py                       # runner audit otonom: scan sampai report dari satu config
report.py                       # penyusun report gabungan
remediation.py                  # knowledge base remediasi dan justifikasi severity
glossary.py, glosarium.yml      # pemuat dan data glosarium
config/                         # targets.example.yml (targets.yml asli di-gitignore)
tests/<modul>/                  # runner dan contoh config tiap modul
tests/unit/                     # unit test
scanners/                       # skrip pembungkus ZAP, testssl, header, deps
projects/                       # project buatan init (di-gitignore)
docs/                           # panduan dan situs hasil build
site/                           # templat, kamus id/en/de, glosarium situs
worker/                         # Cloudflare Worker untuk open scanner
.github/workflows/              # pipeline CI
```

## Berkontribusi

Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk alur, cara menambah check, dan konvensi commit.

## Lisensi

Apache-2.0, lihat [LICENSE](LICENSE).
