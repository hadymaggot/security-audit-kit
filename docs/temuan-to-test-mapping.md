# Nerjemahin laporan pentest jadi test

Cara makai kit ini buat "ngunci" temuan dari sebuah laporan pentest (misalnya dari
BSSN/Gov-CSIRT) biar nggak kambuh. Per temuan, tentuin modul yang pas lalu tambahin
kasusnya.

| Kelas temuan | Modul | Cara nambah kasus |
|---|---|---|
| Broken Access Control / privilege escalation | `authz` | Tambah endpoint sensitif, `expect: { role_rendah: deny }` |
| Lack of authorization status / lompat alur | `authz` | Endpoint ubah status + body status, `deny` buat role yang nggak berwenang |
| IDOR | `authz` | Endpoint pakai id milik akun lain, `deny` |
| Header authz dipercaya dari client | `authz` | Isi blok `forged_headers` |
| SQL Injection | `zap api` + verifikasi | Kasih OpenAPI; review alert ZAP, pastiin true positive |
| Stored/Reflected XSS | `zap` + `upload` | Scan; kalau XSS lewat upload pakai modul upload |
| Upload berbahaya (JS di PDF, polyglot) | `upload` | Udah kecover; sesuaikan `allow_only` & `max_bytes` |
| Weak Password Policy | `auth-policy` | Isi `register` + `weak_passwords` |
| Improper Captcha | `auth-policy` | Isi blok `captcha` |
| CORS misconfiguration | `cors` | Isi `paths`; cek ACAO reflektif / wildcard+creds / origin null |
| Open redirect | `open-redirect` | Isi `paths` + `params`; cek Location ke host luar |
| Deprecated Cryptography | `tls` | `python audit.py tls` |
| Missing Security Header | `headers` | `python audit.py headers` |
| Cache response sensitif | `clientleak` | Isi `sensitive_paths`; cek `Cache-Control: no-store` |
| Secret/endpoint admin bocor di JS (awal temuan BSSN) | `clientleak` | `auto_discover_js` + `internal_endpoints` |
| Secret/endpoint bocor di HTML (app tanpa JS) | `clientleak` | `scan_html: true` |
| File sensitif kebuka (`.env`, `.git/`, dump, backup) | `clientleak` | `probe_sensitive_files: true` |
| Source map (.map) kebuka di production | `clientleak` | Otomatis pas nyisir JS |
| Dependency usang (CVE) | `deps` | Otomatis; CVE muncul di report |

## Alurnya

Baca laporan, daftar tiap temuan plus lokasinya (endpoint/parameter), petain ke modul di
tabel atas, lalu tambah kasusnya di `*.yml` modul terkait — jangan taruh kredensial di
situ, pakai environment variable.

Jalanin `python audit.py all`, pastiin temuan lama sekarang jadi gagal (merah) — artinya
test-nya emang nangkep celahnya. Baru perbaiki app-nya, jalanin lagi sampai lulus (hijau),
terus pasang di CI biar regresi ketangkep otomatis.

`reports/laporan.html` isinya per temuan: deskripsi, bukti, dampak, alasan severity,
rekomendasi plus contoh solusi, dan rujukan standar — siap dilampirin sebagai bukti
tindak lanjut.
