**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](metodologi.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](metodologi.de.md)

# Metodologi

Kit ini mengubah alur pentest berbasis OWASP menjadi automated regression test: kelas kerentanan yang pernah ditemukan tidak boleh muncul kembali tanpa terdeteksi, dan kelas yang bersifat mekanis (security *header*, TLS, *password* policy, *dependency* rentan) disapu pada setiap run.

## Acuan

| Topik | Standar atau tool |
|---|---|
| Severity | OWASP Risk Rating (*Likelihood* x *Impact*) |
| Kategori temuan | OWASP Top 10 2021, OWASP API Security Top 10 2023 |
| Kontrol yang diuji | OWASP ASVS |
| DAST | OWASP ZAP |
| CVE *dependency* dan *secret* | Trivy |
| TLS | testssl.sh |
| SAST dan *secret* yang ter-commit | semgrep, gitleaks |

## Tahapan

**Static scan lebih dahulu:** `python audit.py deps`. Tidak memerlukan target hidup, sehingga aman dijalankan pada PR: CVE *dependency*, SAST OWASP Top 10, dan *secret* yang ter-commit.

**Pengujian dinamis** setelah target dev/staging tersedia:

| Modul | Yang diuji |
|---|---|
| `zap baseline` | Passive scan, tidak menyerang. |
| `zap api` | Scan dari definisi OpenAPI; dapat berjalan di balik *login* melalui `ZAP_AUTH_HEADER`. |
| `authz` | Regression *access control* per *role*: privilege escalation, IDOR, *header* `X-Auth-*` palsu dari client, *bypass* gateway langsung ke port service. |
| `mass-assignment` | Mass assignment / Broken Object Property Level Authorization (BOPLA). |
| `clientleak` | *Cache response* sensitif, secret/endpoint pada *bundle* JS dan HTML, *source map*, *file* yang terekspos. |
| `upload` | Penolakan *file upload* berbahaya. |
| `auth-policy` | Kekuatan *password* dan regenerasi captcha. |
| `cors`, `open-redirect` | CORS *misconfiguration* dan open *redirect*. |
| `injection` | SQL injection (error-based, boolean-based, time-based opsional); non-destruktif, hanya probing baca. |
| `webstack` | Versi web server dari banner, dipetakan ke CVE yang diketahui (mis. Apache mod_http2, NGINX HTTP/2); non-destruktif. |
| `tls`, `headers` | Protokol/cipher TLS usang dan security *header* yang kurang. |

**Laporan:** `python audit.py report` merangkai `reports/laporan.html`, `laporan.md`, dan `laporan-slides.html`. Perintah `audit.py all` memanggil report secara otomatis di akhir.

Modul lain di `PY_MODULES`: `cookie-flags`, `response-leak`, `openapi-coverage`, `ratelimit`, `session-mgmt`, `captcha`, `jwt`, `ssrf`, serta `recon`.

## Non-destruktif dan *rollback*

Mayoritas runner hanya mengirim *request* biasa dan membaca status/isi *response*: tanpa exploit, tanpa menghapus data, tanpa *brute-force*. *Payload upload* sengaja dibuat jinak (hanya penanda) untuk menguji validasi.

`zap full` (active scan) dipisahkan dan disertai peringatan; jalankan hanya pada environment milik sendiri, bukan production.

Sebagian modul menulis ke target (`mass-assignment` menyuntik field terlarang) atau membuat data uji (`ratelimit`, `session-mgmt`). Untuk modul tersebut:

1. Setiap penulisan dicatat ke *rollback* journal segera setelah dieksekusi.
2. Sebagai tahap terakhir setelah laporan dibuat, target dipulihkan otomatis ke keadaan semula.
3. Log pemulihan tersimpan di `reports/rollback.json`; `python audit.py rollback` menjalankan pemulihan ulang bila diperlukan.

Dengan demikian pengujian destruktif tetap meninggalkan target seperti sedia kala.

## Lintas-OS

Seluruh perintah dijalankan melalui `python audit.py ...`, sehingga perilakunya identik di Windows dan Linux. Scanner menggunakan Docker image resmi. Script `.sh` pada `scanners/` bersifat opsional untuk pengguna Linux; `.gitattributes` memaksa line ending LF agar aman saat di-bind-mount ke container dari Windows.

## Batasan

- Laporan adalah hasil automation, bukan pengganti pentest manual.
- Temuan scanner dapat berupa false positive; verifikasi sebelum menetapkan severity final.
- Celah logika bisnis hanya terdeteksi bila test-nya ditulis secara khusus.
- Cakupan terbatas pada target dan *endpoint* yang dikonfigurasi saat dijalankan.
