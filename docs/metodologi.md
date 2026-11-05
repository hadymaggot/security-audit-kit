# Metodologi

Kit ini niru alur pentest berbasis OWASP tapi dijadikan automated regression. Dua
tujuan: biar kelas celah yang udah pernah ketemu nggak kambuh diam-diam, dan nyapu
kelas celah yang emang mekanis (header, TLS, password policy, dependency rentan).

## Acuan

Severity ngikut OWASP Risk Rating (Likelihood x Impact), kategori temuan ngikut OWASP
Top 10 2021, kontrol yang diuji basisnya OWASP ASVS. Tooling-nya OWASP ZAP buat DAST,
Trivy buat CVE dependency + secret, testssl.sh buat TLS, semgrep + gitleaks buat SAST
dan secret yang udah ke-commit.

## Tahapan

Scan statis duluan — `python audit.py deps` — aman jalan di PR karena nggak butuh target
hidup: CVE dependency, SAST OWASP Top 10, secret ke-commit.

Begitu ada target dev/staging, baru yang dinamis: `zap baseline` (passive, nggak
nyerang), `zap api` (scan dari OpenAPI, bisa di balik login lewat `ZAP_AUTH_HEADER`),
`authz` (regression access control per role — ini intinya), `clientleak` (cache + secret
di JS/HTML + file kebuka), `upload`, `auth-policy`, lalu `tls` dan `headers`.

Terakhir `python audit.py report` ngerangkai `reports/laporan.html` & `laporan.md`.
`audit.py all` udah manggil report otomatis di ujung.

## Non-destruktif

Semua runner cuma ngirim request biasa terus baca status/isi response — nggak
nge-exploit, nggak hapus data, nggak brute-force. Payload upload sengaja jinak (cuma
penanda) buat ngetes validasi. `zap full` (active scan) dipisah dan dikasih warning;
jalanin cuma ke environment sendiri yang bukan production.

## Lintas-OS

Semua lewat `python audit.py ...`, jadi sama persis di Windows dan Linux. Scanner pakai
Docker image resmi. Script `.sh` di `scanners/` opsional buat yang di Linux; `.gitattributes`
maksa line ending LF biar aman waktu di-bind-mount ke container dari Windows.

## Batasan

Ini automation, bukan pengganti pentest manual. Temuan scanner bisa false positive dan
wajib diverifikasi sebelum severity final dikunci. Celah logika bisnis cuma ketangkep
kalau test-nya ditulis khusus. Cakupannya sebatas target & endpoint yang di-config pas
dijalanin.
