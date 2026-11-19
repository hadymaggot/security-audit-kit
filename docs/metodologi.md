# Metodologi

Kit ini mengadaptasi alur pentest berbasis OWASP menjadi automated regression testing.
Terdapat dua tujuan: memastikan kelas kerentanan yang pernah ditemukan tidak muncul
kembali tanpa terdeteksi, dan menyapu kelas kerentanan yang bersifat mekanis (security
header, TLS, password policy, dependency rentan).

## Acuan

Severity mengikuti OWASP Risk Rating (Likelihood x Impact), kategori temuan mengikuti
OWASP Top 10 2021 dan OWASP API Security Top 10 2023, dan kontrol yang diuji berbasis
OWASP ASVS. Tooling yang digunakan: OWASP ZAP untuk DAST, Trivy untuk CVE dependency
dan secret, testssl.sh untuk TLS, serta semgrep dan gitleaks untuk SAST dan deteksi
secret yang telah ter-commit.

## Tahapan

Static scan dijalankan lebih dahulu — `python audit.py deps` — yang aman dijalankan
pada PR karena tidak memerlukan target hidup: CVE dependency, SAST OWASP Top 10, dan
secret yang ter-commit.

Setelah target dev/staging tersedia, pengujian dinamis dijalankan:

- `zap baseline` — passive scan, tidak menyerang.
- `zap api` — scan dari definisi OpenAPI, dapat berjalan di balik login melalui `ZAP_AUTH_HEADER`.
- `authz` — regression access control per role: privilege escalation, IDOR, header
  `X-Auth-*` palsu dari client, dan bypass gateway langsung ke port service.
- `mass-assignment` — mass assignment / Broken Object Property Level Authorization (BOPLA).
- `clientleak` — cache response sensitif, secret/endpoint pada bundle JS dan HTML, source
  map, serta file yang terekspos.
- `upload` — penolakan file upload berbahaya.
- `auth-policy` — kekuatan password dan regenerasi captcha.
- `cors` dan `open-redirect` — CORS misconfiguration dan open redirect.
- `tls` dan `headers` — protokol/cipher TLS usang dan security header yang kurang.

Tahap terakhir, `python audit.py report` merangkai `reports/laporan.html` dan
`laporan.md`. Perintah `audit.py all` memanggil report secara otomatis di akhir.

## Non-destruktif dan rollback

Mayoritas runner hanya mengirim request biasa lalu membaca status/isi response —
tidak melakukan exploit, tidak menghapus data, dan tidak melakukan brute-force. Payload
upload sengaja dibuat jinak (hanya penanda) untuk menguji validasi. `zap full` (active
scan) dipisahkan dan disertai peringatan; jalankan hanya pada environment milik sendiri,
bukan production.

Sebagian modul bersifat destruktif karena harus menulis ke target (mis.
`mass-assignment` menyuntik field terlarang). Untuk modul semacam ini, setiap penulisan
dicatat ke rollback journal segera setelah dieksekusi, lalu dipulihkan secara otomatis
ke keadaan semula sebagai tahap terakhir setelah laporan dibuat. Dengan demikian
pengujian destruktif tetap "terasa non-destruktif": target kembali seperti sedia kala.
Log pemulihan tersimpan di `reports/rollback.json`, dan `python audit.py rollback`
dapat menjalankan pemulihan ulang bila diperlukan.

## Lintas-OS

Seluruh perintah dijalankan melalui `python audit.py ...`, sehingga perilakunya identik
di Windows dan Linux. Scanner menggunakan Docker image resmi. Script `.sh` pada
`scanners/` bersifat opsional untuk pengguna Linux; `.gitattributes` memaksa line ending
LF agar aman saat di-bind-mount ke container dari Windows.

## Batasan

Laporan ini merupakan hasil automation, bukan pengganti pentest manual. Temuan scanner
dapat berupa false positive dan wajib diverifikasi sebelum severity final ditetapkan.
Celah logika bisnis hanya terdeteksi apabila test-nya ditulis secara khusus. Cakupan
pengujian terbatas pada target dan endpoint yang dikonfigurasi saat dijalankan.
