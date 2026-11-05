# Contoh Laporan Hasil Uji Keamanan

> **Catatan:** ini **contoh output** dari data fiktif (host, endpoint, dan CVE dibuat untuk ilustrasi), bukan hasil audit sistem nyata. Versi HTML (`reports/laporan.html`) punya kartu ringkasan & garis temuan berwarna per severity; isinya sama. Dibuat dengan `python audit.py report`.

## 1. Metodologi

Testing dijalankan otomatis dan non-destruktif ke target yang berwenang diuji. Acuannya OWASP Top 10 2021, OWASP ASVS, dan OWASP Risk Rating Methodology (severity = Likelihood x Impact). Tooling-nya OWASP ZAP, Trivy, dan testssl.sh, ditambah rangkaian regression test buat access control, upload, dan password policy.

## 2. Ringkasan Temuan

| Severity | Jumlah |
|---|---|
| 🔴 Critical | 1 |
| 🟠 High | 4 |
| 🟡 Medium | 3 |
| 🟢 Low | 4 |
| ⚪ Info | 0 |
| ✅ Lulus (kontrol OK) | 5 |

Total CVE terdeteksi: **3**.

## 3. Rincian Temuan & Rekomendasi

### 1. 🔴 [forged] GET /api/admin/users  `CRITICAL`

- **Modul:** authz-matrix
- **Deskripsi:** Klien dapat menyuntik header otorisasi internal (mis. X-Auth-Roles) dan gateway/reverse proxy tidak menimpanya, sehingga hak akses naik.
- **Bukti:** Role 'operator', respons HTTP 200. X-Auth-Role: admin palsu dari client diterima; daftar user kebuka
- **CVE/CWE:** -
- **Dampak:** Bypass otorisasi total hanya dengan menambahkan header pada request.
- **Justifikasi severity:** Likelihood tinggi (cukup edit header) x Impact tinggi (menyamar sebagai admin).
- **Rekomendasi & contoh solusi:**
  - Konfigurasikan reverse proxy untuk SELALU menghapus lalu menyetel ulang header X-Auth-* dari sumber tepercaya; jangan teruskan nilai dari klien.
  - Contoh (Traefik forwardAuth): pakai authResponseHeaders agar hanya nilai dari service auth yang diteruskan ke backend.
  - Backend juga harus memverifikasi token/sesi, tidak mempercayai header mentah.
- **Referensi:** OWASP A01:2021 Broken Access Control; BSSN Perban No.4/2021 Pasal 26 huruf b (manajemen sesi)

### 2. 🟠 IDOR GET /api/reports/1042  `HIGH`

- **Modul:** authz-matrix
- **Deskripsi:** Referensi objek langsung (ID pada URL/parameter) tidak diverifikasi kepemilikannya, sehingga data milik akun lain bisa diakses.
- **Bukti:** Role 'pelaksana_a', respons HTTP 200. laporan milik tenant lain kebuka tanpa cek kepemilikan
- **CVE/CWE:** -
- **Dampak:** Kebocoran/putaran data antar pengguna atau antar perusahaan.
- **Justifikasi severity:** Likelihood sedang–tinggi (ID mudah ditebak) x Impact tinggi (data pribadi/perusahaan lain terungkap).
- **Rekomendasi & contoh solusi:**
  - Verifikasi di server bahwa objek yang diminta memang milik pengguna/scope yang sedang login sebelum mengembalikannya.

  ```
      // contoh: batasi query dengan pemilik, jangan hanya by-id
      SELECT * FROM doc WHERE id = :id AND company_id = :currentCompany;
  ```

  - Pertimbangkan ID tak-terprediksi (UUID/ULID) sebagai lapis tambahan, bukan pengganti cek otorisasi.
- **Referensi:** OWASP A01:2021 Broken Access Control; BSSN Perban No.4/2021 Pasal 26 huruf g (proteksi data)

### 3. 🟠 File terekspos: /.git/config  `HIGH`

- **Modul:** client-leak
- **Deskripsi:** Berkas atau informasi sensitif terekspos publik tanpa perlu JavaScript: file konfigurasi (.env), repository (.git/), backup/dump, atau komentar/isi HTML yang membocorkan secret maupun endpoint internal.
- **Bukti:** respons HTTP 200. repo git kebuka publik, bisa rekonstruksi source
- **CVE/CWE:** -
- **Dampak:** Kebocoran kredensial, kode sumber, atau struktur sistem yang memudahkan serangan lanjutan.
- **Justifikasi severity:** Likelihood tinggi (cukup GET satu URL) x Impact bervariasi (dari peta serangan s/d kredensial langsung).
- **Rekomendasi & contoh solusi:**
  - Jangan sajikan file sensitif dari web root: blokir akses ke .env, .git/, file backup/dump, dan file sumber.
  - Contoh (nginx):

  ```
      location ~ /\.(?!well-known) { deny all; }
      location ~* \.(env|bak|sql|zip|tar\.gz)$ { deny all; }
  ```

  - Pindahkan konfigurasi secret ke environment variable / secret manager.
  - Bersihkan komentar HTML yang memuat info sensitif sebelum rilis.
- **Referensi:** OWASP A05:2021 Security Misconfiguration; OWASP A01:2021 (akses file); BSSN Perban No.4/2021 huruf g & m (proteksi data & konfigurasi)

### 4. 🟠 CVE-2024-4068 — braces  `HIGH`

- **Modul:** trivy-cve
- **Deskripsi:** Komponen/dependensi versi usang dengan kerentanan yang telah terdaftar (CVE).
- **Bukti:** Paket braces 3.0.2 di package-lock.json. Perbaikan: 3.0.3. braces: uncontrolled resource consumption (ReDoS)
- **CVE/CWE:** CVE-2024-4068
- **Dampak:** Bergantung CVE: dari kebocoran info hingga eksekusi kode jarak jauh (RCE) lewat pustaka yang rentan.
- **Justifikasi severity:** Mengikuti skor CVSS pada CVE terkait; eksploit publik menaikkan likelihood.
- **Rekomendasi & contoh solusi:**
  - Perbarui paket ke versi perbaikan (fixed version) yang tertera pada temuan.
  - Bila belum ada perbaikan, terapkan mitigasi/pin versi aman & pantau rilis.
  - Otomatiskan: Dependabot/Renovate + gerbang CI (trivy/osv-scanner) agar CVE baru cepat terdeteksi.
- **Referensi:** OWASP A06:2021 Vulnerable and Outdated Components; NVD / CVE; BSSN Perban No.4/2021 (komponen usang)

### 5. 🟠 secure_renego  `HIGH`

- **Modul:** testssl
- **Deskripsi:** Server menerima protokol/cipher TLS usang.
- **Bukti:** server mendukung renegotiasi tidak aman
- **CVE/CWE:** CVE-2009-3555
- **Dampak:** Komunikasi berpotensi didekripsi (downgrade/known attacks).
- **Justifikasi severity:** Likelihood rendah (butuh posisi MITM) x Impact tinggi (kerahasiaan data).
- **Rekomendasi & contoh solusi:**
  - Nonaktifkan SSLv3/TLS1.0/TLS1.1; minimal TLS 1.2, utamakan TLS 1.3.
  - Pakai cipher suite modern (ECDHE + AES-GCM/ChaCha20), nonaktifkan cipher lemah.
- **Referensi:** OWASP A02:2021 Cryptographic Failures; BSSN Perban No.4/2021 huruf e (kriptografi)

### 6. 🟡 Rahasia di /assets/app.a1b2.js  `MEDIUM`

- **Modul:** client-leak
- **Deskripsi:** Bundle/aset JavaScript sisi klien membocorkan informasi sensitif: endpoint internal/admin, secret (API key/token), atau source map (.map) yang membuka kode sumber asli.
- **Bukti:** respons HTTP 200. pola API key Google (AIza...) nyangkut di bundle
- **CVE/CWE:** -
- **Dampak:** Memberi peta serangan — penyerang menemukan endpoint admin & struktur API (seperti temuan privilege escalation yang berawal dari analisa JS), atau memakai secret yang terekspos.
- **Justifikasi severity:** Likelihood tinggi (aset klien dapat diunduh siapa saja) x Impact bervariasi (enabler s/d akses langsung bila berisi secret).
- **Rekomendasi & contoh solusi:**
  - Jangan menaruh secret (API key, token, kredensial) di kode frontend — pindahkan ke server; frontend memanggil lewat backend.
  - Nonaktifkan publikasi source map di produksi (mis. build tanpa .map, atau jangan sajikan file .map).
  - Otorisasi endpoint di server — endpoint yang tertera di JS tetap harus menolak pengguna tak berwenang (lihat juga Broken Access Control).
  - Audit berkala isi bundle (CI) untuk pola secret & referensi .map.
- **Referensi:** OWASP A01/A05:2021; OWASP ASVS V14 Configuration; BSSN Perban No.4/2021 huruf g (proteksi data)

### 7. 🟡 CORS reflektif /api/profile  `MEDIUM`

- **Modul:** cors
- **Deskripsi:** Konfigurasi CORS terlalu longgar: server memantulkan Origin apa pun ke Access-Control-Allow-Origin, atau memadukan wildcard dengan Access-Control-Allow-Credentials, atau menerima Origin 'null'.
- **Bukti:** respons HTTP 200. ACAO memantulkan Origin asing (https://evil.example) + credentials
- **CVE/CWE:** -
- **Dampak:** Situs jahat yang dibuka korban bisa mengirim request berkredensial ke API dan membaca responsnya — pencurian data terautentikasi lintas-origin.
- **Justifikasi severity:** Likelihood sedang (butuh korban buka situs jahat sambil login) x Impact tinggi (baca data terautentikasi).
- **Rekomendasi & contoh solusi:**
  - Jangan pantulkan Origin mentah. Pakai allowlist origin yang tepercaya saja.
  - Contoh (pola backend):

  ```
      if (allowlist.includes(origin)) resp.header('Access-Control-Allow-Origin', origin);
  ```

  - Kalau butuh Access-Control-Allow-Credentials: true, Origin WAJIB spesifik, bukan '*' dan bukan hasil pantulan sembarangan.
  - Tolak Origin 'null'. Batasi method & header yang diizinkan seperlunya.
- **Referensi:** OWASP A05:2021 Security Misconfiguration; OWASP ASVS V14 Configuration; BSSN Perban No.4/2021 huruf h (keamanan komunikasi)

### 8. 🟡 CVE-2023-26136 — tough-cookie  `MEDIUM`

- **Modul:** trivy-cve
- **Deskripsi:** Komponen/dependensi versi usang dengan kerentanan yang telah terdaftar (CVE).
- **Bukti:** Paket tough-cookie 4.0.0 di package-lock.json. Perbaikan: 4.1.3. tough-cookie: prototype pollution
- **CVE/CWE:** CVE-2023-26136
- **Dampak:** Bergantung CVE: dari kebocoran info hingga eksekusi kode jarak jauh (RCE) lewat pustaka yang rentan.
- **Justifikasi severity:** Mengikuti skor CVSS pada CVE terkait; eksploit publik menaikkan likelihood.
- **Rekomendasi & contoh solusi:**
  - Perbarui paket ke versi perbaikan (fixed version) yang tertera pada temuan.
  - Bila belum ada perbaikan, terapkan mitigasi/pin versi aman & pantau rilis.
  - Otomatiskan: Dependabot/Renovate + gerbang CI (trivy/osv-scanner) agar CVE baru cepat terdeteksi.
- **Referensi:** OWASP A06:2021 Vulnerable and Outdated Components; NVD / CVE; BSSN Perban No.4/2021 (komponen usang)

### 9. 🟢 Captcha regenerate tiap gagal login  `LOW`

- **Modul:** auth-policy
- **Deskripsi:** Nilai captcha tidak diperbarui setelah percobaan gagal / dapat dipakai ulang.
- **Bukti:** respons HTTP 200. token captcha sama dipakai ulang 5x tanpa regenerate
- **CVE/CWE:** -
- **Dampak:** Captcha tak efektif menahan otomasi/brute-force.
- **Justifikasi severity:** Likelihood sedang x Impact rendah (lapis tambahan, bukan satu-satunya).
- **Rekomendasi & contoh solusi:**
  - Regenerasi token & tantangan captcha setiap percobaan gagal; sekali pakai dengan masa berlaku singkat.
  - Padukan dengan rate-limit dan lockout per-akun.
- **Referensi:** OWASP A07:2021 Identification & Authentication Failures

### 10. 🟢 Open redirect /login?next=  `LOW`

- **Modul:** open-redirect
- **Deskripsi:** Parameter pengalih (redirect/next/url/return) dipakai menyusun Location tanpa validasi, sehingga bisa diarahkan ke domain luar.
- **Bukti:** respons HTTP 302. Location mengarah ke https://evil.example tanpa validasi allowlist
- **CVE/CWE:** -
- **Dampak:** Dipakai untuk phishing (tautan terlihat sah tapi mengarah ke situs jahat) dan bypass proteksi berbasis domain.
- **Justifikasi severity:** Likelihood sedang x Impact rendah–sedang (umumnya enabler phishing, bukan akses langsung).
- **Rekomendasi & contoh solusi:**
  - Validasi tujuan redirect terhadap allowlist path/domain internal.
  - Hindari redirect ke URL absolut dari input pengguna; pakai path relatif saja.
  - Kalau tujuan eksternal memang perlu, tampilkan halaman antara (interstitial).
- **Referensi:** OWASP A01:2021 (Unvalidated Redirects); OWASP Unvalidated Redirects & Forwards Cheat Sheet

### 11. 🟢 Content-Security-Policy  `LOW`

- **Modul:** headers
- **Deskripsi:** Security header respons tidak dikonfigurasi (atau header pembocor info seperti Server/X-Powered-By masih tampil).
- **Bukti:** respons HTTP 200. header tidak ada
- **CVE/CWE:** -
- **Dampak:** Memudahkan clickjacking, MIME sniffing, XSS, dan fingerprinting server.
- **Justifikasi severity:** Likelihood rendah–sedang x Impact rendah (umumnya enabler, bukan celah tunggal).
- **Rekomendasi & contoh solusi:**
  - Set header di reverse proxy/framework:

  ```
      Strict-Transport-Security: max-age=31536000; includeSubDomains
      Content-Security-Policy: default-src 'self'
      X-Content-Type-Options: nosniff
      X-Frame-Options: DENY
      Referrer-Policy: strict-origin-when-cross-origin
  ```

  - Kosongkan/hapus header Server dan X-Powered-By.
- **Referensi:** OWASP A05:2021 Security Misconfiguration; OWASP Secure Headers Project

### 12. 🟢 Strict-Transport-Security  `LOW`

- **Modul:** headers
- **Deskripsi:** Security header respons tidak dikonfigurasi (atau header pembocor info seperti Server/X-Powered-By masih tampil).
- **Bukti:** respons HTTP 200. header tidak ada
- **CVE/CWE:** -
- **Dampak:** Memudahkan clickjacking, MIME sniffing, XSS, dan fingerprinting server.
- **Justifikasi severity:** Likelihood rendah–sedang x Impact rendah (umumnya enabler, bukan celah tunggal).
- **Rekomendasi & contoh solusi:**
  - Set header di reverse proxy/framework:

  ```
      Strict-Transport-Security: max-age=31536000; includeSubDomains
      Content-Security-Policy: default-src 'self'
      X-Content-Type-Options: nosniff
      X-Frame-Options: DENY
      Referrer-Policy: strict-origin-when-cross-origin
  ```

  - Kosongkan/hapus header Server dan X-Powered-By.
- **Referensi:** OWASP A05:2021 Security Misconfiguration; OWASP Secure Headers Project

## 4. Daftar CVE

| CVE | Paket/Lokasi | Severity |
|---|---|---|
| CVE-2024-4068 | CVE-2024-4068 — braces | 🟠 HIGH |
| CVE-2023-26136 | CVE-2023-26136 — tough-cookie | 🟡 MEDIUM |
| CVE-2009-3555 | secure_renego | 🟠 HIGH |

## 5. Batasan & Pertanggungjawaban

Laporan ini hasil automation, bukan pengganti pentest manual. Temuan scanner (misalnya ZAP) bisa false positive dan wajib diverifikasi sebelum severity final dikunci. Celah logika bisnis cuma ketangkep kalau test-nya ditulis khusus. Cakupannya sebatas target & endpoint yang di-config pas dijalanin.
