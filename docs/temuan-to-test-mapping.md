**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](temuan-to-test-mapping.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](temuan-to-test-mapping.de.md)

# Menerjemahkan laporan pentest menjadi test

Mengunci temuan dari laporan pentest (misalnya BSSN/Gov-CSIRT) menjadi test, agar temuan itu tidak kambuh: tentukan modul yang sesuai per temuan, lalu tambahkan kasusnya.

## Kelas temuan ke modul

| Kelas temuan | Modul | Cara menambahkan kasus |
|---|---|---|
| Broken Access Control / privilege escalation | `authz` | Tambahkan endpoint sensitif, `expect: { regular_user: deny }` |
| Lack of authorization status / lompat alur | `authz` | Endpoint ubah status + body status, `deny` untuk role yang tidak berwenang |
| IDOR | `authz` | Endpoint menggunakan id milik akun lain, `deny` |
| Header authz dipercaya dari client | `authz` | Isi blok `forged_headers` |
| Service microservice terekspos langsung (bypass gateway/ForwardAuth) | `authz` | Endpoint dengan `base_url` port service + `expect: { anon: deny }`, dan blok `forged_headers` `as_role: anon` ke port itu (lihat `authz_matrix.traefik-sanctum.example.yml`) |
| SQL Injection | `injection` (atau `zap api`) | Isi `targets` (path, param, location, baseline); deteksi error/boolean-based, time-based opsional. Non-destruktif; verifikasi temuan sebelum severity final |
| Stored/Reflected XSS | `zap` + `upload` | Scan; apabila XSS lewat upload gunakan modul upload |
| Upload berbahaya (JS di PDF, polyglot, ekstensi ganda, oversize) | `upload` | Sudah tercakup; sesuaikan `allow_only`/`max_bytes`, gunakan `endpoint.data` untuk field wajib, dan isi `cleanup` agar berkas uji yang diterima otomatis terhapus |
| Mass assignment / privilege escalation (BOPLA) | `mass-assignment` | Isi `targets` (get/update/inject/fields). DESTRUKTIF tapi reversibel: tiap tulisan dicatat ke jurnal & dipulihkan otomatis setelah laporan (`audit.py rollback` untuk replay manual) |
| Weak Password Policy | `auth-policy` | Isi `register` atau `password_checks` + `weak_passwords`; tambahkan `strong_password` sebagai kontrol. Hanya 422 di field sandi yang dianggap ditolak |
| Improper Captcha | `auth-policy` | Isi blok `captcha` |
| CORS misconfiguration | `cors` | Isi `paths`; cek ACAO reflektif / wildcard+creds / origin null |
| Open redirect | `open-redirect` | Isi `paths` + `params`; cek Location ke host luar |
| Deprecated Cryptography | `tls` | `python audit.py tls` |
| Missing Security Header | `headers` | `python audit.py headers` |
| Web server/komponen versi rentan (CVE) | `webstack` | Isi `known_vulnerable` (server, max_version, cve); non-destruktif, membaca banner `Server`/`X-Powered-By` + HTTP/2. Perbarui saat ada CVE baru (mis. Apache mod_http2, NGINX HTTP/2) |
| Cache response sensitif | `clientleak` | Isi `sensitive_paths`; cek `Cache-Control: no-store` |
| Cache response sensitif (bukti tersimpan di browser) | `clientleak` | `browser_cache.enabled: true` (butuh Playwright + Chromium) |
| Secret/endpoint admin bocor di JS (awal temuan BSSN) | `clientleak` | `auto_discover_js` + `internal_endpoints` |
| Secret/endpoint bocor di HTML (app tanpa JS) | `clientleak` | `scan_html: true` |
| File sensitif terekspos (`.env`, `.git/`, dump, backup) | `clientleak` | `probe_sensitive_files: true` |
| Source map (.map) terekspos di production | `clientleak` | Otomatis saat menyisir JS |
| Dependency usang (CVE) | `deps` | Otomatis; CVE muncul di report |

## Alurnya

1. Baca laporan dan daftar tiap temuan beserta lokasinya (endpoint/parameter).
2. Petakan ke modul pada tabel di atas, lalu tambahkan kasusnya di `*.yml` modul terkait. Jangan menaruh kredensial di situ; gunakan environment variable.
3. Jalankan `python audit.py all`. Temuan lama harus gagal (merah): artinya test benar-benar menangkap celahnya.
4. Perbaiki app, jalankan lagi sampai lulus (hijau), lalu pasang di CI agar regresi terdeteksi otomatis.

`reports/laporan.html` memuat per temuan: deskripsi, bukti, dampak, alasan severity, rekomendasi beserta contoh solusi, dan rujukan standar. Siap dilampirkan sebagai bukti tindak lanjut.
