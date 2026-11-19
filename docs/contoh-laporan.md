# Laporan Hasil Uji Keamanan (Otomatis)

> **Catatan:** ini **contoh output** dari data fiktif (host `demo.example.test`, endpoint, temuan, dan CVE dibuat untuk ilustrasi), bukan hasil audit sistem nyata. Versi HTML ada di [`contoh-laporan.html`](contoh-laporan.html) — isinya sama, dengan ringkasan risiko berwarna, daftar alert bernavigasi, dan tabel instance. Dibuat dengan `python audit.py report`.

> Dibuat: 2026-11-19 07:52 · Security Audit Kit — dibuat oleh hadymaggot · https://github.com/hadymaggot/security-audit-kit

## 1. Metodologi

Testing dijalankan otomatis dan non-destruktif ke target yang berwenang diuji. Acuannya OWASP Top 10 2021, OWASP ASVS, dan OWASP Risk Rating Methodology (severity = Likelihood x Impact). Tooling-nya OWASP ZAP, Trivy, dan testssl.sh, ditambah rangkaian regression test buat access control, upload, dan password policy.

## 2. Ringkasan Temuan

| Severity | Jumlah instance |
|---|---|
| 🔴 Critical | 3 |
| 🟠 High | 4 |
| 🟡 Medium | 0 |
| 🟢 Low | 3 |
| ⚪ Info | 0 |
| ✅ Lulus (kontrol OK) | 12 |

Total alert: **6** · Total CVE terdeteksi: **2**.

### Daftar Alert

| # | Alert | Risiko | Keyakinan | Instance |
|---|---|---|---|---|
| 1 | Header identitas (X-Auth-*) dipercaya dari klien | 🔴 CRITICAL | Tinggi | 2 |
| 2 | Dependensi dengan kerentanan (CVE) | 🔴 CRITICAL | Tinggi | 2 |
| 3 | IDOR — akses objek milik entitas lain | 🟠 HIGH | Tinggi | 2 |
| 4 | Upload berkas berbahaya diterima | 🟠 HIGH | Tinggi | 1 |
| 5 | Header keamanan tidak diset | 🟢 LOW | Tinggi | 2 |
| 6 | Captcha tidak regenerasi | 🟢 LOW | Tinggi | 1 |

## 3. Rincian Temuan & Rekomendasi

### 1. 🔴 Header identitas (X-Auth-*) dipercaya dari klien  `CRITICAL`

- **Risiko:** CRITICAL &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** authz-matrix (`forged-header`)
- **Deskripsi:** Klien dapat menyuntik header otorisasi internal (mis. X-Auth-Roles) dan gateway/reverse proxy tidak menimpanya, sehingga hak akses naik.
- **Jumlah instance:** 2

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `GET http://demo.example.test:18002/api/users  (inject: X-Auth-Roles,X-Auth-User-Id)` | [forged] admin via port langsung | 200 | Role 'anon', respons HTTP 200. X-Auth-Roles: admin palsu diterima; daftar user kebuka |
  | 2 | `GET http://demo.example.test:18004/api/roles  (inject: X-Auth-Roles)` | [forged] role management via port langsung | 200 | Role 'anon', respons HTTP 200. service hilir percaya header mentah tanpa verifikasi |

- **CVE/CWE:** -
- **Dampak:** Bypass otorisasi total hanya dengan menambahkan header pada request.
- **Justifikasi severity:** Likelihood tinggi (cukup edit header) x Impact tinggi (menyamar sebagai admin).
- **Rekomendasi & contoh solusi:**
  - Konfigurasikan reverse proxy untuk SELALU menghapus lalu menyetel ulang header X-Auth-* dari sumber tepercaya; jangan teruskan nilai dari klien.
  - Contoh (Traefik forwardAuth): pakai authResponseHeaders agar hanya nilai dari service auth yang diteruskan ke backend.
  - Backend juga harus memverifikasi token/sesi, tidak mempercayai header mentah.
- **Referensi:** OWASP A01:2021 Broken Access Control; BSSN Perban No.4/2021 Pasal 26 huruf b (manajemen sesi)

### 2. 🔴 Dependensi dengan kerentanan (CVE)  `CRITICAL`

- **Risiko:** CRITICAL &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** trivy-cve (`vuln-dependency`)
- **Deskripsi:** Komponen/dependensi versi usang dengan kerentanan yang telah terdaftar (CVE).
- **Jumlah instance:** 2

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `-` | CVE-2024-4068 — braces | - | Paket braces 3.0.2 di package-lock.json. Perbaikan: 3.0.3. braces ReDoS via regex |
  | 2 | `-` | CVE-2023-3824 — php | - | Paket php 8.1.2 di composer.lock. Perbaikan: 8.1.22. php buffer overflow |

- **CVE/CWE:** CVE-2024-4068, CVE-2023-3824
- **Dampak:** Bergantung CVE: dari kebocoran info hingga eksekusi kode jarak jauh (RCE) lewat pustaka yang rentan.
- **Justifikasi severity:** Mengikuti skor CVSS pada CVE terkait; eksploit publik menaikkan likelihood.
- **Rekomendasi & contoh solusi:**
  - Perbarui paket ke versi perbaikan (fixed version) yang tertera pada temuan.
  - Bila belum ada perbaikan, terapkan mitigasi/pin versi aman & pantau rilis.
  - Otomatiskan: Dependabot/Renovate + gerbang CI (trivy/osv-scanner) agar CVE baru cepat terdeteksi.
- **Referensi:** OWASP A06:2021 Vulnerable and Outdated Components; NVD / CVE; BSSN Perban No.4/2021 (komponen usang)

### 3. 🟠 IDOR — akses objek milik entitas lain  `HIGH`

- **Risiko:** HIGH &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** authz-matrix (`idor`)
- **Deskripsi:** Referensi objek langsung (ID pada URL/parameter) tidak diverifikasi kepemilikannya, sehingga data milik akun lain bisa diakses.
- **Jumlah instance:** 2

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `GET http://demo.example.test/api/reports/1042` | IDOR laporan milik unit lain | 200 | Role 'operator', respons HTTP 200. operator unit A membaca laporan unit B |
  | 2 | `GET http://demo.example.test/api/analytics/dashboard/company/88?year=2024` | IDOR dashboard perusahaan lain | 200 | Role 'operator', respons HTTP 200. tak ada cek kepemilikan company |

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

### 4. 🟠 Upload berkas berbahaya diterima  `HIGH`

- **Risiko:** HIGH &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** upload-safety (`upload-accepted`)
- **Deskripsi:** Berkas berbahaya (mis. PDF ber-JavaScript, polyglot, ekstensi ganda, melebihi batas) diterima server karena validasi lemah.
- **Jumlah instance:** 1

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `POST http://demo.example.test/api/reports/77/attachments  (file='a.pdf', type=application/pdf)` | PDF berisi JavaScript | 201 | respons HTTP 201. DITERIMA padahal harus ditolak; tak ada pemindaian isi berkas |

- **CVE/CWE:** -
- **Dampak:** Stored XSS saat file dibuka pengguna lain, penyimpanan konten berbahaya, potensi pencurian sesi.
- **Justifikasi severity:** Likelihood sedang (perlu menyusun file) x Impact tinggi (eksekusi skrip pada konteks korban).
- **Rekomendasi & contoh solusi:**
  - Validasi tipe file berdasarkan ISI (magic bytes), bukan hanya ekstensi/Content-Type dari klien.
  - Terapkan allowlist ekstensi & batas ukuran di server; tolak ekstensi ganda.
  - Bersihkan/normalkan nama file (hindari path traversal), simpan dengan nama acak dan sajikan lewat Content-Disposition: attachment.
  - Untuk PDF: tolak/strip objek /JavaScript & /OpenAction. Terapkan CSP ketat pada halaman yang menampilkan konten upload.
- **Referensi:** OWASP A03:2021 Injection; OWASP File Upload Cheat Sheet; BSSN Perban No.4/2021 Pasal 26 huruf d (validasi input)

### 5. 🟢 Header keamanan tidak diset  `LOW`

- **Risiko:** LOW &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** headers (`missing-header`)
- **Deskripsi:** Security header respons tidak dikonfigurasi (atau header pembocor info seperti Server/X-Powered-By masih tampil).
- **Jumlah instance:** 2

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `GET http://demo.example.test/` | Content-Security-Policy | 200 | respons HTTP 200. header tidak ada |
  | 2 | `GET http://demo.example.test/` | Strict-Transport-Security | 200 | respons HTTP 200. HSTS tidak diset |

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

### 6. 🟢 Captcha tidak regenerasi  `LOW`

- **Risiko:** LOW &nbsp; **Keyakinan:** Tinggi
- **Sumber/plugin:** auth-policy (`captcha-static`)
- **Deskripsi:** Nilai captcha tidak diperbarui setelah percobaan gagal / dapat dipakai ulang.
- **Jumlah instance:** 1

  | # | Endpoint diuji | Konteks | HTTP | Bukti |
  |---|---|---|---|---|
  | 1 | `GET http://demo.example.test/api/captcha` | captcha-regenerasi | - | token captcha berulang |

- **CVE/CWE:** -
- **Dampak:** Captcha tak efektif menahan otomasi/brute-force.
- **Justifikasi severity:** Likelihood sedang x Impact rendah (lapis tambahan, bukan satu-satunya).
- **Rekomendasi & contoh solusi:**
  - Regenerasi token & tantangan captcha setiap percobaan gagal; sekali pakai dengan masa berlaku singkat.
  - Padukan dengan rate-limit dan lockout per-akun.
- **Referensi:** OWASP A07:2021 Identification & Authentication Failures

### Kontrol yang Lolos (LULUS: 12)

Pemeriksaan yang diuji dan berperilaku benar (bukan temuan) — bukti cakupan uji.

| Pemeriksaan | Modul | Endpoint diuji | HTTP |
|---|---|---|---|
| Daftar pengguna (admin only) | authz-matrix | `GET http://demo.example.test/api/users` | 200 |
| Daftar pengguna (admin only) | authz-matrix | `GET http://demo.example.test/api/users` | 403 |
| Kelola role (admin only) | authz-matrix | `GET http://demo.example.test/api/roles` | 403 |
| [forged] admin via gateway | authz-matrix | `GET http://demo.example.test/api/users  (inject: X-Auth-Roles)` | 403 |
| Polyglot GIF+PHP | upload-safety | `POST http://demo.example.test/api/reports/77/attachments  (file='a.pdf', type=application/pdf)` | 422 |
| Ekstensi ganda berakhir .php | upload-safety | `POST http://demo.example.test/api/reports/77/attachments  (file='a.pdf.php', type=application/pdf)` | 422 |
| Melebihi batas ukuran | upload-safety | `POST http://demo.example.test/api/reports/77/attachments  (file='big.pdf', type=application/pdf)` | 422 |
| PDF sah (kontrol) | upload-safety | `POST http://demo.example.test/api/reports/77/attachments  (file='ok.pdf', type=application/pdf)` | 201 |
| ganti sandi sandi lemah 12345678 | auth-policy | `POST http://demo.example.test/api/auth/change-password` | 422 |
| ganti sandi sandi lemah password | auth-policy | `POST http://demo.example.test/api/auth/change-password` | 422 |
| ganti sandi kontrol sandi kuat | auth-policy | `POST http://demo.example.test/api/auth/change-password` | 422 |
| X-Content-Type-Options | headers | `GET http://demo.example.test/` | 200 |

## 4. Daftar CVE

| CVE | Paket/Lokasi | Severity |
|---|---|---|
| CVE-2024-4068 | CVE-2024-4068 — braces | 🟠 HIGH |
| CVE-2023-3824 | CVE-2023-3824 — php | 🔴 CRITICAL |

## 5. Batasan & Pertanggungjawaban

Laporan ini hasil automation, bukan pengganti pentest manual. Temuan scanner (misalnya ZAP) bisa false positive dan wajib diverifikasi sebelum severity final dikunci. Celah logika bisnis cuma ketangkep kalau test-nya ditulis khusus. Cakupannya sebatas target & endpoint yang di-config pas dijalanin.

---

_Security Audit Kit — dibuat oleh hadymaggot · https://github.com/hadymaggot/security-audit-kit_
