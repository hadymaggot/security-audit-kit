# Menerjemahkan laporan pentest menjadi test

Cara menggunakan kit ini untuk "mengunci" temuan dari sebuah laporan pentest (misalnya dari
BSSN/Gov-CSIRT) agar tidak kambuh. Per temuan, tentukan modul yang sesuai lalu tambahkan
kasusnya.

| Kelas temuan | Modul | Cara menambahkan kasus |
|---|---|---|
| Broken Access Control / privilege escalation | `authz` | Tambahkan endpoint sensitif, `expect: { role_rendah: deny }` |
| Lack of authorization status / lompat alur | `authz` | Endpoint ubah status + body status, `deny` untuk role yang tidak berwenang |
| IDOR | `authz` | Endpoint menggunakan id milik akun lain, `deny` |
| Header authz dipercaya dari client | `authz` | Isi blok `forged_headers` |
| Service microservice terekspos langsung (bypass gateway/ForwardAuth) | `authz` | Endpoint dengan `base_url` port service + `expect: { anon: deny }`, dan blok `forged_headers` `as_role: anon` ke port itu (lihat `authz_matrix.traefik-sanctum.example.yml`) |
| SQL Injection | `zap api` + verifikasi | Beri OpenAPI; review alert ZAP, pastikan true positive |
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

Baca laporan, daftar tiap temuan beserta lokasinya (endpoint/parameter), petakan ke modul di
tabel atas, lalu tambahkan kasusnya di `*.yml` modul terkait — jangan menaruh kredensial di
situ, gunakan environment variable.

Jalankan `python audit.py all`, pastikan temuan lama sekarang menjadi gagal (merah) — artinya
test-nya memang menangkap celahnya. Setelah itu perbaiki app-nya, jalankan lagi sampai lulus (hijau),
lalu pasang di CI agar regresi terdeteksi otomatis.

`reports/laporan.html` berisi per temuan: deskripsi, bukti, dampak, alasan severity,
rekomendasi beserta contoh solusi, dan rujukan standar — siap dilampirkan sebagai bukti
tindak lanjut.
