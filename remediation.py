#!/usr/bin/env python3
"""Remediation and justification knowledge base, generic across projects.

Each finding is classified into a 'kind'. For every kind the KB holds:
  description    : what the weakness is
  impact         : consequence if left unfixed
  severity       : default level + the basis for it (justification)
  recommendation : fix steps + sample solution (code/config, framework-agnostic)
  references     : cited standards (OWASP, BSSN Perban 4/2021, etc.)

Used by report.py to build a defensible report.
"""
from __future__ import annotations

# Severity is rated with the OWASP Risk Rating (Likelihood x Impact).
KB = {
    "broken-access": {
        "description": "Endpoint sensitif dapat diakses oleh role yang tidak berwenang "
                     "karena otorisasi tidak ditegakkan di sisi server.",
        "impact": "Peningkatan hak akses (privilege escalation), pembuatan/penghapusan "
                  "akun, perubahan data kritikal — berpotensi pengambilalihan sistem.",
        "severity": "Critical",
        "severity_basis": "Likelihood tinggi (dapat dipicu oleh pengguna login biasa tanpa "
                          "alat khusus) x Impact tinggi (kendali penuh fungsi admin).",
        "recommendation": [
            "Tegakkan otorisasi di SISI SERVER pada setiap endpoint, bukan hanya "
            "menyembunyikan menu di klien.",
            "Terapkan authorization middleware/guard sebelum handler, contoh pola:",
            "    // middleware: tolak jika role tak termasuk daftar yang diizinkan\n"
            "    if (!user.roles.intersects(endpoint.allowedRoles)) return deny(403);",
            "Gunakan RBAC/ABAC terpusat; jadikan 'default deny' sebagai perilaku bawaan.",
        ],
        "references": ["OWASP A01:2021 Broken Access Control",
                      "OWASP ASVS V4 Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf c (persyaratan access control)"],
    },
    "forged-header": {
        "description": "Klien dapat menyuntik header otorisasi internal (mis. X-Auth-Roles) "
                     "dan gateway/reverse proxy tidak menimpanya, sehingga hak akses naik.",
        "impact": "Bypass otorisasi total hanya dengan menambahkan header pada request.",
        "severity": "Critical",
        "severity_basis": "Likelihood tinggi (cukup edit header) x Impact tinggi "
                          "(menyamar sebagai admin).",
        "recommendation": [
            "Konfigurasikan reverse proxy untuk SELALU menghapus lalu menyetel ulang "
            "header X-Auth-* dari sumber tepercaya; jangan teruskan nilai dari klien.",
            "Contoh (Traefik forwardAuth): pakai authResponseHeaders agar hanya nilai "
            "dari service auth yang diteruskan ke backend.",
            "Backend juga harus memverifikasi token/session, tidak mempercayai header mentah.",
        ],
        "references": ["OWASP A01:2021 Broken Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf b (manajemen session)"],
    },
    "idor": {
        "description": "Referensi objek langsung (ID pada URL/parameter) tidak diverifikasi "
                     "kepemilikannya, sehingga data milik akun lain bisa diakses.",
        "impact": "Information disclosure/tampering data antar pengguna atau antar perusahaan.",
        "severity": "High",
        "severity_basis": "Likelihood sedang–tinggi (ID mudah ditebak) x Impact tinggi "
                          "(data pribadi/perusahaan lain terungkap).",
        "recommendation": [
            "Verifikasi di server bahwa objek yang diminta memang milik pengguna/scope "
            "yang sedang login sebelum mengembalikannya.",
            "    // contoh: batasi query dengan pemilik, jangan hanya by-id\n"
            "    SELECT * FROM doc WHERE id = :id AND company_id = :currentCompany;",
            "Pertimbangkan ID tak-terprediksi (UUID/ULID) sebagai lapis tambahan, "
            "bukan pengganti cek otorisasi.",
        ],
        "references": ["OWASP A01:2021 Broken Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf g (proteksi data)"],
    },
    "upload-accepted": {
        "description": "File berbahaya (mis. PDF ber-JavaScript, polyglot, ekstensi ganda, "
                     "melebihi batas) diterima server karena validasi lemah.",
        "impact": "Stored XSS saat file dibuka pengguna lain, penyimpanan konten "
                  "berbahaya, potensi pencurian session.",
        "severity": "High",
        "severity_basis": "Likelihood sedang (perlu menyusun file) x Impact tinggi "
                          "(eksekusi skrip pada konteks korban).",
        "recommendation": [
            "Validasi tipe file berdasarkan ISI (magic bytes), bukan hanya ekstensi/"
            "Content-Type dari klien.",
            "Terapkan allowlist ekstensi & batas ukuran di server; tolak ekstensi ganda.",
            "Bersihkan/normalkan nama file (hindari path traversal), simpan dengan nama "
            "acak dan sajikan lewat Content-Disposition: attachment.",
            "Untuk PDF: tolak/strip objek /JavaScript & /OpenAction. Terapkan CSP ketat "
            "pada halaman yang menampilkan konten upload.",
        ],
        "references": ["OWASP A03:2021 Injection", "OWASP File Upload Cheat Sheet",
                      "BSSN Perban No.4/2021 Pasal 26 huruf d (validasi input)"],
    },
    "weak-password": {
        "description": "Kebijakan password menerima password lemah/umum.",
        "impact": "Akun mudah ditebak/brute-force, pengambilalihan akun.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang x Impact sedang–tinggi (per-akun).",
        "recommendation": [
            "Tetapkan panjang minimal (mis. 12–16 karakter) dan tolak password yang ada di "
            "daftar password breached/umum.",
            "Aktifkan MFA/2FA, dan wajibkan password lama saat mengganti password.",
            "Simpan password dengan hash kuat (bcrypt/argon2), jangan plaintext/MD5/SHA1.",
        ],
        "references": ["OWASP A07:2021 Identification & Authentication Failures",
                      "NIST SP 800-63B",
                      "BSSN Perban No.4/2021 Pasal 26 huruf a (autentikasi)"],
    },
    "captcha-static": {
        "description": "Nilai captcha tidak diperbarui setelah percobaan gagal / dapat dipakai ulang.",
        "impact": "Captcha tak efektif menahan otomasi/brute-force.",
        "severity": "Low",
        "severity_basis": "Likelihood sedang x Impact rendah (lapis tambahan, bukan satu-satunya).",
        "recommendation": [
            "Regenerasi token & tantangan captcha setiap percobaan gagal; sekali pakai "
            "dengan masa berlaku singkat.",
            "Padukan dengan rate-limit dan lockout per-akun.",
        ],
        "references": ["OWASP A07:2021 Identification & Authentication Failures"],
    },
    "missing-header": {
        "description": "Security header response tidak dikonfigurasi (atau header information "
                     "disclosure seperti Server/X-Powered-By masih tampil).",
        "impact": "Memudahkan clickjacking, MIME sniffing, XSS, dan fingerprinting server.",
        "severity": "Low",
        "severity_basis": "Likelihood rendah–sedang x Impact rendah (umumnya enabler, "
                          "bukan celah tunggal).",
        "recommendation": [
            "Set header di reverse proxy/framework:",
            "    Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "    Content-Security-Policy: default-src 'self'\n"
            "    X-Content-Type-Options: nosniff\n"
            "    X-Frame-Options: DENY\n"
            "    Referrer-Policy: strict-origin-when-cross-origin",
            "Kosongkan/hapus header Server dan X-Powered-By.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP Secure Headers Project"],
    },
    "mass-assignment": {
        "description": "Server menerima field yang tidak semestinya boleh diubah klien "
                     "(mis. role, is_admin, company_id, status) saat membuat/memperbarui "
                     "objek — mass assignment / otorisasi level-properti objek yang rusak.",
        "impact": "Eskalasi hak atau manipulasi data: pengguna biasa menaikkan diri jadi "
                  "admin, pindah tenant, atau mengubah kepemilikan objek hanya dengan "
                  "menambah satu field pada request.",
        "severity": "High",
        "severity_basis": "Likelihood sedang (cukup tambah field di body) x Impact tinggi "
                          "(eskalasi hak / integritas data).",
        "recommendation": [
            "Pakai allowlist field yang boleh di-assign; jangan mass-assign seluruh input.",
            "    // Laravel: batasi via $fillable + FormRequest->validated(),\n"
            "    // JANGAN Model::update($request->all()).",
            "Pisahkan field yang hanya boleh diubah admin; tolak/abaikan field istimewa "
            "dari role non-admin.",
            "Terapkan otorisasi per-properti (BOPLA), bukan hanya per-objek.",
        ],
        "references": ["OWASP API3:2023 Broken Object Property Level Authorization",
                      "CWE-915 Improperly Controlled Modification of Object Attributes"],
    },
    "sql-injection": {
        "description": "Input pengguna disusun langsung ke query SQL tanpa parameterisasi, "
                     "sehingga penyerang dapat mengubah logika query (error-based, "
                     "boolean-based, atau time-based).",
        "impact": "Pembacaan/perubahan data di luar wewenang, bypass autentikasi, hingga "
                  "potensi RCE tergantung konfigurasi DBMS.",
        "severity": "High",
        "severity_basis": "Likelihood sedang–tinggi (vektor klasik, tooling melimpah) x "
                          "Impact tinggi (kerahasiaan & integritas data). Deteksi otomatis "
                          "wajib diverifikasi manual sebelum severity final dikunci.",
        "recommendation": [
            "Gunakan prepared statement / parameterized query (bind parameter), jangan "
            "merangkai string query dari input.",
            "    // Laravel: Model::where('x', $input) / DB::select('... = ?', [$input])\n"
            "    // JANGAN DB::raw(\"... = '$input'\").",
            "Terapkan allowlist tipe/format input dan least-privilege pada akun DB.",
            "Pakai ORM/query builder dengan benar; hindari raw query berisi input mentah.",
        ],
        "references": ["OWASP A03:2021 Injection",
                      "CWE-89 SQL Injection",
                      "OWASP Testing Guide WSTG-INPV-05"],
    },
    "server-vuln": {
        "description": "Versi web server/komponen yang terdeteksi dari banner cocok dengan "
                     "kerentanan yang telah terdaftar (CVE), mis. Apache mod_http2 atau "
                     "NGINX HTTP/2.",
        "impact": "Bergantung CVE-nya, berpotensi remote code execution, DoS, atau "
                  "memory corruption pada server yang exposed.",
        "severity": "High",
        "severity_basis": "Likelihood sedang (eksploit publik untuk CVE yang aktif) x "
                          "Impact tinggi (RCE/DoS). Deteksi berbasis banner — keyakinan "
                          "sedang, wajib dikonfirmasi ke advisory vendor.",
        "recommendation": [
            "Update ke versi yang sudah diperbaiki sesuai advisory vendor (mis. Apache "
            "httpd 2.4.71+, NGINX 1.30.7+/1.31.9+).",
            "Batasi exposure komponen yang rentan; terapkan mitigasi sementara (mis. WAF, "
            "nonaktifkan modul/fitur terkait bila memungkinkan).",
            "Kosongkan banner versi (ServerTokens Prod / server_tokens off) agar tidak "
            "memudahkan fingerprint.",
        ],
        "references": ["OWASP A06:2021 Vulnerable and Outdated Components",
                      "CISA Known Exploited Vulnerabilities (KEV)"],
    },
    "tls-weak": {
        "description": "Server menerima protokol/cipher TLS usang.",
        "impact": "Komunikasi berpotensi didekripsi (downgrade/known attacks).",
        "severity": "Medium",
        "severity_basis": "Likelihood rendah (butuh posisi MITM) x Impact tinggi "
                          "(kerahasiaan data).",
        "recommendation": [
            "Nonaktifkan SSLv3/TLS1.0/TLS1.1; minimal TLS 1.2, utamakan TLS 1.3.",
            "Pakai cipher suite modern (ECDHE + AES-GCM/ChaCha20), nonaktifkan cipher lemah.",
        ],
        "references": ["OWASP A02:2021 Cryptographic Failures",
                      "BSSN Perban No.4/2021 huruf e (kriptografi)"],
    },
    "client-cache": {
        "description": "Response yang memuat data sensitif (halaman/endpoint terautentikasi) "
                     "tidak melarang penyimpanan cache, sehingga bisa tersimpan di cache "
                     "browser, proxy bersama, atau tombol Back setelah logout.",
        "impact": "Data sensitif pengguna terbaca dari perangkat/proxy bersama oleh pihak "
                  "lain setelah session berakhir.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (perangkat/proxy bersama, histori browser) x "
                          "Impact sedang–tinggi (data pribadi terungkap).",
        "recommendation": [
            "Set header anti-cache pada response sensitif/terautentikasi:",
            "    Cache-Control: no-store, no-cache, must-revalidate, private\n"
            "    Pragma: no-cache\n"
            "    Expires: 0",
            "Jangan pakai 'public' atau 'max-age' besar pada response yang memuat data user.",
            "Pastikan aset statis publik tetap boleh di-cache (jangan berlebihan sebaliknya).",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V8 Data Protection",
                      "BSSN Perban No.4/2021 huruf g (proteksi data)"],
    },
    "js-leak": {
        "description": "Bundle/aset JavaScript sisi klien expose informasi sensitif: "
                     "endpoint internal/admin, secret (API key/token), atau source map "
                     "(.map) yang membuka source code asli.",
        "impact": "Memberi peta serangan — penyerang menemukan endpoint admin & struktur "
                  "API (seperti temuan privilege escalation yang berawal dari analisa JS), "
                  "atau memakai secret yang exposed.",
        "severity": "Medium",
        "severity_basis": "Likelihood tinggi (aset klien dapat diunduh siapa saja) x Impact "
                          "bervariasi (enabler s/d akses langsung bila berisi secret).",
        "recommendation": [
            "Jangan menaruh secret (API key, token, kredensial) di kode frontend — "
            "pindahkan ke server; frontend memanggil lewat backend.",
            "Nonaktifkan publikasi source map di produksi (mis. build tanpa .map, atau "
            "jangan sajikan file .map).",
            "Otorisasi endpoint di server — endpoint yang tertera di JS tetap harus menolak "
            "pengguna tak berwenang (lihat juga Broken Access Control).",
            "Audit berkala isi bundle (CI) untuk pola secret & referensi .map.",
        ],
        "references": ["OWASP A01/A05:2021",
                      "OWASP ASVS V14 Configuration",
                      "BSSN Perban No.4/2021 huruf g (proteksi data)"],
    },
    "info-exposure": {
        "description": "File atau informasi sensitif exposed publik tanpa perlu JavaScript: "
                     "file konfigurasi (.env), repository (.git/), backup/dump, atau "
                     "komentar/isi HTML yang expose secret maupun endpoint internal.",
        "impact": "Exposure kredensial, source code, atau struktur sistem yang memudahkan "
                  "serangan lanjutan.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi (cukup GET satu URL) x Impact bervariasi "
                          "(dari peta serangan s/d kredensial langsung).",
        "recommendation": [
            "Jangan sajikan file sensitif dari web root: blokir akses ke .env, .git/, "
            "file backup/dump, dan file sumber.",
            "Contoh (nginx):",
            "    location ~ /\\.(?!well-known) { deny all; }\n"
            "    location ~* \\.(env|bak|sql|zip|tar\\.gz)$ { deny all; }",
            "Pindahkan konfigurasi secret ke environment variable / secret manager.",
            "Bersihkan komentar HTML yang memuat info sensitif sebelum rilis.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP A01:2021 (akses file)",
                      "BSSN Perban No.4/2021 huruf g & m (proteksi data & konfigurasi)"],
    },
    "cors-misconfig": {
        "description": "Konfigurasi CORS terlalu longgar: server memantulkan Origin apa pun "
                     "ke Access-Control-Allow-Origin, atau memadukan wildcard dengan "
                     "Access-Control-Allow-Credentials, atau menerima Origin 'null'.",
        "impact": "Situs jahat yang dibuka korban bisa mengirim request berkredensial ke "
                  "API dan membaca responsnya — pencurian data terautentikasi lintas-origin.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (butuh korban buka situs jahat sambil login) x "
                          "Impact tinggi (baca data terautentikasi).",
        "recommendation": [
            "Jangan pantulkan Origin mentah. Pakai allowlist origin yang tepercaya saja.",
            "Contoh (pola backend):",
            "    if (allowlist.includes(origin)) resp.header('Access-Control-Allow-Origin', origin);",
            "Kalau butuh Access-Control-Allow-Credentials: true, Origin WAJIB spesifik, "
            "bukan '*' dan bukan hasil pantulan sembarangan.",
            "Tolak Origin 'null'. Batasi method & header yang diizinkan seperlunya.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V14 Configuration",
                      "BSSN Perban No.4/2021 huruf h (keamanan komunikasi)"],
    },
    "open-redirect": {
        "description": "Parameter pengalih (redirect/next/url/return) dipakai menyusun "
                     "Location tanpa validasi, sehingga bisa diarahkan ke domain luar.",
        "impact": "Dipakai untuk phishing (tautan terlihat sah tapi mengarah ke situs "
                  "jahat) dan bypass proteksi berbasis domain.",
        "severity": "Low",
        "severity_basis": "Likelihood sedang x Impact rendah–sedang (umumnya enabler "
                          "phishing, bukan akses langsung).",
        "recommendation": [
            "Validasi tujuan redirect terhadap allowlist path/domain internal.",
            "Hindari redirect ke URL absolut dari input pengguna; pakai path relatif saja.",
            "Kalau tujuan eksternal memang perlu, tampilkan halaman antara (interstitial).",
        ],
        "references": ["OWASP A01:2021 (Unvalidated Redirects)",
                      "OWASP Unvalidated Redirects & Forwards Cheat Sheet"],
    },
    "vuln-dependency": {
        "description": "Komponen/dependency versi usang dengan kerentanan yang telah "
                     "terdaftar (CVE).",
        "impact": "Bergantung CVE: dari information disclosure hingga eksekusi kode jarak jauh "
                  "(RCE) lewat library yang rentan.",
        "severity": "High",
        "severity_basis": "Mengikuti skor CVSS pada CVE terkait; eksploit publik menaikkan "
                          "likelihood.",
        "recommendation": [
            "Perbarui paket ke versi perbaikan (fixed version) yang tertera pada temuan.",
            "Bila belum ada perbaikan, terapkan mitigasi/pin versi aman & pantau rilis.",
            "Otomatiskan: Dependabot/Renovate + gerbang CI (trivy/osv-scanner) agar CVE "
            "baru cepat terdeteksi.",
        ],
        "references": ["OWASP A06:2021 Vulnerable and Outdated Components",
                      "NVD / CVE", "BSSN Perban No.4/2021 (komponen usang)"],
    },
    "zap-generic": {
        "description": "Temuan hasil scan OWASP ZAP yang perlu analisis lanjutan "
                     "untuk memastikan true/false positive.",
        "impact": "Bergantung jenis alert; tinjau detail per alert.",
        "severity": "Info",
        "severity_basis": "Dari skor risiko ZAP; verifikasi manual sebelum ditetapkan.",
        "recommendation": [
            "Tinjau detail alert pada laporan ZAP (reports/zap-*.html).",
            "Konfirmasi apakah dapat direproduksi; tetapkan severity final setelah verifikasi.",
        ],
        "references": ["OWASP ZAP", "OWASP Top 10 2021"],
    },
    "ssrf": {
        "description": "Server melakukan request HTTP ke URL yang dikendalikan pengguna, termasuk "
                     "alamat privat/loopback, tanpa validasi tujuan (Server-Side Request Forgery).",
        "impact": "Penyerang dapat memakai server sebagai proxy ke jaringan internal: memindai "
                  "layanan privat, membaca metadata cloud (kredensial), atau mengakses layanan "
                  "internal yang tidak exposed ke internet.",
        "severity": "High",
        "severity_basis": "Likelihood sedang (butuh endpoint yang menerima URL) x Impact tinggi "
                          "(akses jaringan internal, scope berubah).",
        "recommendation": [
            "Validasi URL dengan allowlist host/skema; tolak alamat privat, loopback, link-local "
            "(termasuk 169.254.169.254) dan semua representasi alternatifnya (desimal, heks, IPv6-mapped).",
            "Resolve DNS sendiri, validasi IP hasil resolve, lalu hubungi IP itu langsung "
            "(cegah DNS rebinding); nonaktifkan atau validasi ulang redirect.",
            "Contoh (pseudo): ip = resolve(host); if (is_private(ip)) reject(); "
            "client.get(url, allow_redirects=False)",
            "Jalankan fetcher di jaringan terisolasi tanpa akses ke layanan internal/metadata; "
            "wajibkan IMDSv2 di cloud.",
        ],
        "references": ["OWASP A10:2021 Server-Side Request Forgery",
                      "OWASP API7:2023 Server Side Request Forgery",
                      "OWASP SSRF Prevention Cheat Sheet", "CWE-918"],
    },
    "jwt-forgery": {
        "description": "Server menerima JWT yang dipalsukan: tanpa tanda tangan (alg=none), dengan "
                     "tanda tangan dibuang, atau dengan payload yang diubah.",
        "impact": "Siapa pun dapat membuat token sah untuk identitas/role apa pun — "
                  "pengambilalihan akun dan eskalasi hak akses total.",
        "severity": "Critical",
        "severity_basis": "Likelihood tinggi (tanpa prasyarat) x Impact kritikal (bypass "
                          "autentikasi penuh).",
        "recommendation": [
            "Selalu verifikasi tanda tangan dan WAJIBKAN algoritma yang diizinkan (whitelist); "
            "tolak alg=none.",
            "Jangan percaya header 'alg' dari token: tentukan algoritma di sisi server.",
            "Contoh (jsonwebtoken/Node): jwt.verify(token, key, { algorithms: ['HS256'] });",
            "Perbarui library JWT ke versi terbaru dan tambahkan uji regresi untuk token palsu.",
        ],
        "references": ["OWASP API2:2023 Broken Authentication", "OWASP JWT Cheat Sheet",
                      "CWE-347, CWE-287"],
    },
    "jwt-weak-secret": {
        "description": "Token JWT bertanda tangan HMAC memakai secret yang lemah/umum sehingga "
                     "dapat ditebak lewat kamus.",
        "impact": "Penyerang yang mengetahui secret dapat menerbitkan token sah untuk identitas apa pun.",
        "severity": "Critical",
        "severity_basis": "Likelihood tinggi (kamus kecil cukup) x Impact kritikal.",
        "recommendation": [
            "Ganti secret dengan nilai acak minimal 256 bit dari CSPRNG dan putar (rotate) segera; "
            "cabut seluruh token lama.",
            "Pertimbangkan algoritma asimetris (RS256/ES256) agar kunci penandatanganan tak dibagi.",
            "Simpan secret di secret manager/environment variable, bukan di kode.",
        ],
        "references": ["OWASP JWT Cheat Sheet", "RFC 8725 JWT Best Current Practices",
                      "CWE-521, CWE-798"],
    },
    "jwt-weak-config": {
        "description": "Konfigurasi JWT tidak mengikuti praktik baik: tanpa/exp terlalu panjang, "
                     "klaim sensitif di payload, alg=none, atau header kunci (kid/jku) berisiko.",
        "impact": "Token curian berlaku lama; data sensitif terbaca dari payload (hanya di-encode); "
                  "header kunci dapat disalahgunakan bila tidak divalidasi.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang x Impact sedang (memperbesar dampak pencurian token).",
        "recommendation": [
            "Set exp pendek (menit-jam) dengan refresh token dan kemampuan pencabutan.",
            "Jangan menaruh data sensitif di payload (JWT hanya di-encode, tidak dienkripsi).",
            "Validasi/whitelist kid, jku, x5u, dan jwk; jangan mengambil kunci dari URL token.",
        ],
        "references": ["RFC 8725 JWT Best Current Practices", "OWASP JWT Cheat Sheet", "CWE-613"],
    },
    "captcha-answer-leak": {
        "description": "Response tantangan captcha expose jawabannya (kunci jawaban, atau offset "
                     "posisi pada SVG/gambar), sehingga captcha dapat dilewati secara otomatis "
                     "tanpa memecahkannya.",
        "impact": "Captcha sebagai kontrol anti-otomatisasi (brute-force login, spam, pendaftaran "
                  "massal) menjadi tidak efektif; bot dapat melewatinya dengan membaca response.",
        "severity": "Medium",
        "severity_basis": "Likelihood tinggi (cukup mem-parsing response) x Impact sedang (kontrol "
                          "anti-otomatisasi gugur, namun rate limit/lockout dapat meredam).",
        "recommendation": [
            "Jangan mengirim posisi/jawaban ke klien: simpan target di server dan validasi "
            "jawaban di sisi server.",
            "Untuk captcha slider: render lubang DAN potongan puzzle sebagai bitmap yang "
            "tidak memuat koordinat target; jangan sertakan offset translate/clip yang setara posisi target.",
            "Pertimbangkan captcha yang terbukti (Cloudflare Turnstile, hCaptcha, reCAPTCHA) "
            "ketimbang implementasi sendiri.",
            "Pertahankan lapisan lain: rate limit, lockout akun, dan deteksi anomali.",
        ],
        "references": ["OWASP ASVS V2.2.3 / V11.1 Anti-automation",
                      "OWASP Automated Threats (OAT-009 CAPTCHA Defeat)", "CWE-804, CWE-602"],
    },
    "session-not-revoked": {
        "description": "Setelah password diganti, session lain milik akun yang sama tetap berlaku "
                     "(session tidak dicabut di server).",
        "impact": "Session yang telah dicuri (malware, jaringan tak aman, perangkat hilang) tetap "
                  "dapat dipakai penyerang walau korban sudah mengganti password.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (butuh pencurian session sebelumnya) x Impact tinggi "
                          "(akses akun berlanjut).",
        "recommendation": [
            "Cabut semua session lain saat password berubah (pertahankan session yang mengganti, bila perlu).",
            "Contoh Laravel: Auth::logoutOtherDevices($newPassword) + hapus record session/perangkat "
            "milik user (mis. DeviceSession) dan session di Redis.",
            "Kirim notifikasi keamanan dan tawarkan 'keluar dari semua perangkat'.",
        ],
        "references": ["OWASP ASVS V3.3.3 Session Termination",
                      "OWASP Session Management Cheat Sheet", "CWE-613"],
    },
    "logout-no-invalidate": {
        "description": "Logout tidak mencabut session di server: cookie session lama masih diterima "
                     "setelah logout.",
        "impact": "Cookie session yang pernah exposed tetap dapat dipakai (replay) walau pengguna "
                  "sudah logout.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang x Impact tinggi (pembajakan session).",
        "recommendation": [
            "Hapus/invalidasi session di penyimpanan server saat logout, bukan hanya cookie klien.",
            "Contoh Laravel: Auth::logout(); $request->session()->invalidate(); "
            "$request->session()->regenerateToken();",
        ],
        "references": ["OWASP ASVS V3.3.1", "OWASP Session Management Cheat Sheet", "CWE-613"],
    },
    "old-password-accepted": {
        "description": "Password lama masih diterima setelah password diganti, atau password baru tidak "
                     "berlaku.",
        "impact": "Penggantian password tidak memutus akses pihak yang mengetahui password lama.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi x Impact tinggi (kredensial lama tetap sah).",
        "recommendation": [
            "Pastikan hash password diganti secara atomik dan password lama langsung tidak valid.",
            "Periksa cache/replika yang masih menyimpan kredensial lama.",
        ],
        "references": ["OWASP ASVS V2.1", "CWE-620, CWE-613"],
    },
    "no-rate-limit": {
        "description": "Endpoint sensitif (mis. login) tidak membatasi laju request, sehingga "
                     "percobaan kredensial dapat diulang tanpa batas.",
        "impact": "Brute-force dan credential stuffing dapat dijalankan pada kecepatan penuh "
                  "hingga kredensial valid ditemukan.",
        "severity": "Medium",
        "severity_basis": "Likelihood tinggi (tanpa prasyarat) x Impact sedang-tinggi "
                          "(pengambilalihan akun), diredam bila ada kontrol lain (captcha, MFA).",
        "recommendation": [
            "Terapkan rate limit per IP dan per akun pada endpoint login, reset password, dan OTP.",
            "Contoh Laravel (routes/api.php):",
            "    Route::post('/login', [LoginController::class, 'login'])\n"
            "        ->middleware('throttle:5,1');   // 5 percobaan per menit",
            "Tambahkan rate limit di gateway/WAF sebagai lapisan kedua; kembalikan 429 + Retry-After.",
        ],
        "references": ["OWASP API4:2023 Unrestricted Resource Consumption",
                      "OWASP ASVS V2.2 Anti-automation", "CWE-307"],
    },
    "weak-lockout": {
        "description": "Penguncian akun setelah password salah berulang tidak ditegakkan sesuai "
                     "kebijakan (tidak terkunci, terlalu lambat, atau durasi tidak wajar).",
        "impact": "Penyerang dapat menebak password tanpa dihentikan; atau kunci tak berbatas "
                  "dapat dipakai untuk mengunci akun korban (denial of service).",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (kontrol lain mungkin meredam) x Impact sedang.",
        "recommendation": [
            "Kunci akun sementara (mis. 15 menit) setelah N password salah (mis. 5) dan reset "
            "penghitung saat login berhasil.",
            "Pastikan kunci bersifat sementara agar tidak menjadi vektor penguncian akun korban.",
            "Kombinasikan dengan rate limit per IP dan captcha/MFA.",
        ],
        "references": ["OWASP ASVS V2.2.1", "OWASP Authentication Cheat Sheet", "CWE-307"],
    },
    "lockout-bypass": {
        "description": "Login dengan password benar berhasil walaupun akun berstatus terkunci.",
        "impact": "Penguncian akun tidak melindungi; penyerang yang menebak password tetap berhasil "
                  "masuk di tengah masa kunci.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi x Impact tinggi (kontrol anti brute-force tidak efektif).",
        "recommendation": [
            "Periksa status kunci SEBELUM memverifikasi password dan tolak (423) selama masa kunci.",
            "Contoh pola: if ($user->isLocked()) return response()->json([...], 423);",
        ],
        "references": ["OWASP ASVS V2.2.1", "CWE-307, CWE-287"],
    },
    "user-enumeration": {
        "description": "Response autentikasi berbeda untuk akun terdaftar dan tidak terdaftar "
                     "(status, pesan, atau perilaku penguncian), sehingga keberadaan akun dapat ditebak.",
        "impact": "Penyerang dapat menyusun daftar akun valid untuk serangan password/phishing yang terarah.",
        "severity": "Low",
        "severity_basis": "Informasi pendukung serangan lanjutan; dampak langsung rendah.",
        "recommendation": [
            "Kembalikan response generik yang identik (status + pesan) untuk akun terdaftar dan tidak.",
            "Terapkan penghitung gagal/penguncian secara seragam, atau jangan membedakan response "
            "penguncian (mis. selalu 401 dengan pesan sama) dan beri tahu pemilik akun lewat email.",
        ],
        "references": ["OWASP ASVS V2.2.1 / V3.2", "OWASP Authentication Cheat Sheet", "CWE-204"],
    },
    "auth-coverage-gap": {
        "description": "Endpoint yang menurut spesifikasi OpenAPI wajib autentikasi ternyata "
                     "dapat diakses tanpa kredensial (penegakan autentikasi tidak sesuai desain).",
        "impact": "Siapa pun tanpa login dapat membaca (atau memicu) fungsi yang dianggap "
                  "terlindungi — akses data tanpa otorisasi.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi (tanpa prasyarat, cukup memanggil URL) x Impact "
                          "tinggi (data/fungsi terlindungi terbuka).",
        "recommendation": [
            "Pasang middleware autentikasi pada route tersebut, atau kelompokkan route "
            "terlindungi dalam satu grup auth sehingga default-nya terkunci.",
            "Contoh Laravel:",
            "    Route::middleware('auth:sanctum')->group(function () {\n"
            "        Route::get('/laporan', [LaporanController::class, 'index']);\n"
            "    });",
            "Terapkan 'default deny': route baru otomatis butuh auth kecuali dikecualikan eksplisit.",
            "Selaraskan spesifikasi OpenAPI dengan perilaku nyata, lalu jadikan uji ini bagian CI.",
        ],
        "references": ["OWASP API2:2023 Broken Authentication",
                      "OWASP API5:2023 Broken Function Level Authorization",
                      "OWASP A01:2021 Broken Access Control", "CWE-306"],
    },
    "unauthenticated-endpoint": {
        "description": "Endpoint tidak mendeklarasikan autentikasi, tidak termasuk daftar publik "
                     "yang diizinkan, namun dapat diakses tanpa kredensial.",
        "impact": "Bila endpoint seharusnya privat, data atau fungsi terbuka bagi publik; bila "
                  "memang publik, daftar allowlist/spesifikasi perlu dilengkapi.",
        "severity": "Medium",
        "severity_basis": "Perlu tinjauan: dampak bergantung apakah endpoint memang publik.",
        "recommendation": [
            "Tinjau tiap endpoint: bila privat, tambahkan autentikasi; bila publik, "
            "daftarkan di allowlist dan deklarasikan `security: []` di spesifikasi.",
            "Pastikan endpoint publik tidak mengembalikan data sensitif atau internal.",
        ],
        "references": ["OWASP API2:2023 Broken Authentication", "OWASP A01:2021", "CWE-306"],
    },
    "anon-server-error": {
        "description": "Request anonim (tanpa autentikasi) memicu error server 5xx, menandakan "
                     "validasi atau penanganan error belum dilakukan sebelum autentikasi.",
        "impact": "Error tak tertangani dapat expose detail internal, mengindikasikan "
                  "bug yang bisa dipicu tanpa login, dan menjadi vektor gangguan layanan.",
        "severity": "Low",
        "severity_basis": "Dapat dipicu tanpa prasyarat, tetapi dampak langsung terbatas "
                          "(ketersediaan/informasi).",
        "recommendation": [
            "Pastikan autentikasi dan validasi input berjalan lebih dulu dan menolak dengan "
            "401/403/422, bukan 500.",
            "Tangani exception di lapisan global dan kembalikan response generik.",
            "Periksa log server untuk penyebab 500 dan tambahkan uji regresinya.",
        ],
        "references": ["OWASP API8:2023 Security Misconfiguration", "CWE-755, CWE-209"],
    },
    "spec-mismatch": {
        "description": "Spesifikasi OpenAPI tidak akurat terhadap perilaku nyata: operasi tidak "
                     "mendeklarasikan `security` padahal sebenarnya menolak akses anonim.",
        "impact": "Dokumentasi menyesatkan; klien dan uji otomatis tidak dapat memercayai "
                  "spesifikasi, sehingga celah autentikasi sulit terdeteksi.",
        "severity": "Low",
        "severity_basis": "Masalah kualitas dokumentasi; tidak membuka akses langsung.",
        "recommendation": [
            "Deklarasikan skema keamanan global dan `security` per operasi pada spesifikasi.",
            "Contoh (OpenAPI): components.securitySchemes + security: [{ cookieAuth: [] }]; "
            "tandai endpoint publik dengan `security: []`.",
            "Generate spesifikasi dari kode (mis. Scramble) dengan konfigurasi security yang benar.",
        ],
        "references": ["OpenAPI 3.x Security Requirement Object",
                      "OWASP API9:2023 Improper Inventory Management"],
    },
    "sensitive-data-exposure": {
        "description": "Response API memuat data sensitif (password/hash, secret, token, kunci "
                     "pribadi, atau data rahasia lain) yang seharusnya tidak dikirim ke klien.",
        "impact": "Kredensial atau secret yang exposed dapat dipakai untuk pengambilalihan akun, "
                  "akses ke layanan pihak ketiga, atau serangan lanjutan.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi (cukup memanggil endpoint) x Impact tinggi "
                          "(exposure kredensial/secret).",
        "recommendation": [
            "Jangan serialisasi field sensitif: pakai whitelist field eksplisit (API "
            "Resource/DTO) alih-alih mengembalikan model utuh.",
            "Contoh Laravel: sembunyikan di model dan gunakan Resource.",
            "    protected $hidden = ['password', 'remember_token', 'two_factor_secret',\n"
            "                          'two_factor_recovery_codes'];",
            "Cabut (revoke) dan rotasi secret yang sudah terlanjur exposed.",
            "Terapkan authorization per field pada response yang sama untuk role berbeda.",
        ],
        "references": ["OWASP API3:2023 Broken Object Property Level Authorization",
                      "OWASP A02:2021 Cryptographic Failures",
                      "CWE-200, CWE-201, CWE-522"],
    },
    "verbose-error": {
        "description": "Response (terutama error) expose detail implementasi: stack trace, "
                     "path file server, versi framework, atau pesan SQL.",
        "impact": "Detail internal mempermudah pemetaan teknologi dan pengembangan serangan "
                  "terarah (mis. injeksi, eksploitasi versi rentan).",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (mudah dipicu) x Impact rendah-sedang "
                          "(informasi pendukung serangan, bukan kompromi langsung).",
        "recommendation": [
            "Matikan mode debug di luar lokal (Laravel: APP_DEBUG=false; Django: DEBUG=False).",
            "Kembalikan pesan error generik + ID korelasi; simpan detail hanya di log server.",
            "Contoh Laravel (bootstrap/app.php): render JSON generik untuk request API.",
            "    $exceptions->render(fn (Throwable $e, Request $r) => $r->is('api/*')\n"
            "        ? response()->json(['message' => 'Terjadi kesalahan.'], 500) : null);",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP API8:2023 Security Misconfiguration", "CWE-209, CWE-215"],
    },
    "internal-info-leak": {
        "description": "Response memuat alamat IP internal atau hostname jaringan privat.",
        "impact": "Membantu pemetaan topologi jaringan internal untuk SSRF atau pivot.",
        "severity": "Low",
        "severity_basis": "Informasi pendukung; dampak langsung rendah.",
        "recommendation": [
            "Hapus alamat/hostname internal dari response dan header.",
            "Gunakan nama layanan publik atau ID opak alih-alih IP internal.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration", "CWE-200"],
    },
    "cookie-flags": {
        "description": "Cookie session/autentikasi tidak memakai atribut keamanan lengkap "
                     "(HttpOnly, Secure, SameSite) atau berumur terlalu panjang.",
        "impact": "Tanpa HttpOnly, XSS dapat mencuri cookie session; tanpa Secure, cookie "
                  "dapat exposed lewat HTTP biasa; tanpa SameSite, risiko CSRF meningkat.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang (butuh XSS/jaringan tak aman/CSRF sebagai "
                          "prasyarat) x Impact sedang-tinggi (pengambilalihan session).",
        "recommendation": [
            "Set HttpOnly pada seluruh cookie session/autentikasi (kecuali yang memang harus "
            "dibaca SPA, mis. XSRF-TOKEN).",
            "Set Secure dan sajikan situs hanya lewat HTTPS (aktifkan HSTS).",
            "Set SameSite=Lax (atau Strict untuk session sensitif); gunakan None hanya bila "
            "perlu lintas-situs dan wajib bersama Secure.",
            "Contoh Laravel (config/session.php):",
            "    'http_only' => true,\n    'secure' => env('SESSION_SECURE_COOKIE', true),\n"
            "    'same_site' => 'lax',\n    'lifetime' => 120,   // menit",
            "Pertimbangkan prefix __Host- untuk cookie session.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V3.4 Cookie-based Session Management",
                      "OWASP Session Management Cheat Sheet", "CWE-1004, CWE-614, CWE-1275"],
    },
    "recon-subdomain": {
        "description": "Aset/subdomain yang dapat ditemukan publik melalui OSINT "
                     "(subfinder/httpx), memperluas attack surface.",
        "impact": "Subdomain lupa (dangling), staging terbuka, atau panel admin "
                  "exposed dapat menjadi titik masuk awal.",
        "severity": "Info",
        "severity_basis": "Informatif — inventaris aset; severity naik bila host "
                          "membuka layanan/panel sensitif (lihat temuan terkait).",
        "recommendation": [
            "Inventarisasi seluruh subdomain; matikan/arsipkan yang tidak dipakai.",
            "Pastikan tidak ada subdomain dangling (DNS menunjuk ke resource terhapus) "
            "untuk mencegah subdomain takeover.",
            "Batasi akses environment non-produksi (staging/dev) dengan allowlist/VPN.",
        ],
        "references": ["OWASP WSTG-INFO", "OWASP ASM (Attack Surface Management)",
                      "MITRE ATT&CK T1595 Active Scanning"],
    },
    "exposed-service": {
        "description": "Port/layanan terbuka ke internet (mis. SSH, database, Redis, "
                     "Elasticsearch) yang seharusnya dibatasi.",
        "impact": "Layanan admin/datastore yang exposed memudahkan brute-force, "
                  "akses tanpa autentikasi, atau eksploitasi CVE layanan.",
        "severity": "Medium",
        "severity_basis": "Likelihood sedang–tinggi (terindeks pemindai massal) x Impact "
                          "bergantung layanan; datastore tanpa auth = tinggi.",
        "recommendation": [
            "Tutup port yang tidak perlu; terapkan default-deny pada firewall/security group.",
            "Batasi akses manajemen (SSH/RDP/DB) ke IP tepercaya atau via VPN/bastion.",
            "Wajibkan autentikasi kuat pada datastore (Redis/Elasticsearch/Mongo) dan "
            "jangan paparkan ke 0.0.0.0.",
        ],
        "references": ["OWASP A05:2021 Security Misconfiguration",
                      "NIST SP 800-115", "CIS Controls v8 4.x"],
    },
    "leaked-secret": {
        "description": "Kredensial/secret (API key, token, password) terdeteksi di source "
                     "atau aset (trufflehog), berpotensi ter-commit ke repository.",
        "impact": "Secret yang exposed dapat dipakai menyalahgunakan layanan pihak ketiga, "
                  "mengakses data, atau pivot ke sistem internal.",
        "severity": "High",
        "severity_basis": "Likelihood tinggi (mudah ditemukan via scanner otomatis) x "
                          "Impact tinggi (akses langsung ke layanan/data). Terverifikasi = High.",
        "recommendation": [
            "Cabut (revoke) dan rotasi segera secret yang exposed; anggap sudah terkompromi.",
            "Hapus secret dari riwayat git (git filter-repo/BFG), bukan hanya commit terbaru.",
            "Pindahkan secret ke environment variable / secret manager; jangan commit ke repo.",
            "Pasang pre-commit hook (gitleaks/trufflehog) untuk mencegah exposure berulang.",
        ],
        "references": ["OWASP A07:2021 Identification and Authentication Failures",
                      "CWE-798 Use of Hard-coded Credentials", "OWASP ASVS V2.10"],
    },
    "sast-finding": {
        "description": "Analisis statis kode (semgrep) menemukan pola yang berpotensi rentan "
                     "(mis. injeksi, XSS, kriptografi lemah, konfigurasi tidak aman) pada source.",
        "impact": "Bergantung aturan yang cocok; dapat berupa celah yang dapat dieksploitasi "
                  "(SQL injection, command injection, XSS) atau false positive yang perlu triase.",
        "severity": "Medium",
        "severity_basis": "Mengikuti severity aturan semgrep (ERROR=High, WARNING=Medium); "
                          "wajib diverifikasi manual karena SAST dapat menghasilkan false positive.",
        "recommendation": [
            "Triase tiap temuan: konfirmasi apakah jalur data pengguna benar-benar mencapai sink.",
            "Perbaiki sesuai pesan aturan (parameterized query, escaping output, API kripto aman).",
            "Tambahkan `# nosemgrep: <aturan>` hanya untuk false positive yang terverifikasi, "
            "disertai alasan di komentar.",
            "Jalankan semgrep di CI agar regresi tertangkap sebelum merge.",
        ],
        "references": ["OWASP Top 10 2021", "semgrep rules (p/owasp-top-ten, p/security-audit)",
                      "CWE sesuai metadata aturan"],
    },
    "recon-finding": {
        "description": "Temuan dari pemindaian vuln aktif (nuclei) terhadap aset hidup. "
                     "Severity dibawa langsung dari template nuclei yang cocok.",
        "impact": "Bergantung template; dapat mencakup CVE, misconfiguration, "
                  "exposure, atau default-login yang dapat dieksploitasi.",
        "severity": "Medium",
        "severity_basis": "Mengikuti severity template nuclei (CVSS/komunitas); "
                          "verifikasi true-positive sebelum eskalasi.",
        "recommendation": [
            "Verifikasi tiap temuan (true/false positive) pada target yang berwenang.",
            "Patch komponen rentan sesuai CVE/CWE yang tertera; cek ketersediaan versi fix.",
            "Perbaiki misconfiguration (header, CORS, panel exposed) sesuai kategori tag.",
        ],
        "references": ["OWASP Top 10 2021", "nuclei templates (ProjectDiscovery)",
                      "CVSS v3.1"],
    },
}

# Map ZAP alert names to a more specific kind when recognized.
ZAP_KEYWORDS = [
    ("sql injection", "broken-access"),   # routed to a dedicated injection KB entry when one exists
    ("cross site scripting", "upload-accepted"),
    ("xss", "upload-accepted"),
    ("content security policy", "missing-header"),
    ("strict-transport", "missing-header"),
    ("x-frame-options", "missing-header"),
    ("x-content-type", "missing-header"),
    ("cookie", "missing-header"),
    ("tls", "tls-weak"),
    ("cipher", "tls-weak"),
]


def classify(module: str, title: str) -> str:
    j = (title or "").lower()
    if module == "authz-matrix":
        if j.startswith("[forged]"):
            return "forged-header"
        if "idor" in j:
            return "idor"
        return "broken-access"
    if module == "upload-safety":
        return "upload-accepted"
    if module == "mass-assignment":
        return "mass-assignment"
    if module == "webstack":
        return "server-vuln" if j.startswith("versi rentan") else "missing-header"
    if module == "injection":
        return "sql-injection"
    if module == "auth-policy":
        if "captcha" in j:
            return "captcha-static"
        return "weak-password"
    if module == "client-leak":
        if "cache" in j:
            return "client-cache"
        if j.startswith("file") or "exposed" in j or "html" in j:
            return "info-exposure"
        return "js-leak"
    if module == "cors":
        return "cors-misconfig"
    if module == "open-redirect":
        return "open-redirect"
    if module == "cookie-flags":
        return "cookie-flags"
    if module == "semgrep":
        return "sast-finding"
    if module == "gitleaks":
        return "leaked-secret"
    if module == "ssrf":
        return "ssrf"
    if module == "jwt":
        if "secret" in j:
            return "jwt-weak-secret"
        if "pemalsuan" in j:
            return "jwt-forgery"
        return "jwt-weak-config"
    if module == "captcha":
        return "captcha-answer-leak"
    if module == "session-mgmt":
        if j.startswith("logout"):
            return "logout-no-invalidate"
        if "password lama" in j or "password baru" in j:
            return "old-password-accepted"
        return "session-not-revoked"
    if module == "ratelimit":
        if "enumerasi" in j:
            return "user-enumeration"
        if "password benar" in j:
            return "lockout-bypass"
        if j.startswith("laju"):
            return "no-rate-limit"
        return "weak-lockout"
    if module == "openapi-coverage":
        if "error server" in j:
            return "anon-server-error"
        if "tak akurat" in j or "spesifikasi" in j and "dilindungi" not in j:
            return "spec-mismatch"
        if "terbuka tanpa" in j:
            return "unauthenticated-endpoint"
        return "auth-coverage-gap"
    if module == "response-leak":
        if "debug" in j or "verbose" in j:
            return "verbose-error"
        if "internal" in j:
            return "internal-info-leak"
        return "sensitive-data-exposure"
    if module == "recon":
        if j.startswith("secret"):
            return "leaked-secret"
        if j.startswith("subdomain") or j.startswith("host aktif") \
                or j.startswith("url historis") or j.startswith("crawl"):
            return "recon-subdomain"
        if j.startswith("port") or j.startswith("path") or "layanan" in j:
            return "exposed-service"
        return "recon-finding"
    if module == "trivy-cve":
        return "vuln-dependency"
    if module == "testssl":
        return "tls-weak"
    if module == "zap":
        for kw, kind in ZAP_KEYWORDS:
            if kw in j:
                return kind
        return "zap-generic"
    return "zap-generic"


def lookup(kind: str) -> dict:
    return KB.get(kind, KB["zap-generic"])
