#!/usr/bin/env python3
"""Basis pengetahuan remediasi & justifikasi — generik, lintas-proyek.

Tiap temuan diklasifikasikan ke sebuah 'kind'. Untuk tiap kind tersedia:
  deskripsi   : apa celahnya
  dampak      : akibat bila dibiarkan
  severity    : tingkat default + dasar penilaiannya (justifikasi)
  rekomendasi : langkah perbaikan + contoh solusi (kode/konfig, framework-agnostic)
  referensi   : standar yang dirujuk (OWASP, BSSN Perban 4/2021, dll)

Dipakai report.py untuk menyusun laporan yang bisa dipertanggungjawabkan.
"""
from __future__ import annotations

# Dasar penilaian severity memakai OWASP Risk Rating (Likelihood x Impact).
KB = {
    "broken-access": {
        "deskripsi": "Endpoint sensitif dapat diakses oleh role yang tidak berwenang "
                     "karena otorisasi tidak ditegakkan di sisi server.",
        "dampak": "Peningkatan hak akses (privilege escalation), pembuatan/penghapusan "
                  "akun, perubahan data kritikal — berpotensi pengambilalihan sistem.",
        "severity": "Critical",
        "severity_dasar": "Likelihood tinggi (dapat dipicu oleh pengguna login biasa tanpa "
                          "alat khusus) x Impact tinggi (kendali penuh fungsi admin).",
        "rekomendasi": [
            "Tegakkan otorisasi di SISI SERVER pada setiap endpoint, bukan hanya "
            "menyembunyikan menu di klien.",
            "Terapkan authorization middleware/guard sebelum handler, contoh pola:",
            "    // middleware: tolak jika role tak termasuk daftar yang diizinkan\n"
            "    if (!user.roles.intersects(endpoint.allowedRoles)) return deny(403);",
            "Gunakan RBAC/ABAC terpusat; jadikan 'default deny' sebagai perilaku bawaan.",
        ],
        "referensi": ["OWASP A01:2021 Broken Access Control",
                      "OWASP ASVS V4 Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf c (persyaratan kontrol akses)"],
    },
    "forged-header": {
        "deskripsi": "Klien dapat menyuntik header otorisasi internal (mis. X-Auth-Roles) "
                     "dan gateway/reverse proxy tidak menimpanya, sehingga hak akses naik.",
        "dampak": "Bypass otorisasi total hanya dengan menambahkan header pada request.",
        "severity": "Critical",
        "severity_dasar": "Likelihood tinggi (cukup edit header) x Impact tinggi "
                          "(menyamar sebagai admin).",
        "rekomendasi": [
            "Konfigurasikan reverse proxy untuk SELALU menghapus lalu menyetel ulang "
            "header X-Auth-* dari sumber tepercaya; jangan teruskan nilai dari klien.",
            "Contoh (Traefik forwardAuth): pakai authResponseHeaders agar hanya nilai "
            "dari service auth yang diteruskan ke backend.",
            "Backend juga harus memverifikasi token/sesi, tidak mempercayai header mentah.",
        ],
        "referensi": ["OWASP A01:2021 Broken Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf b (manajemen sesi)"],
    },
    "idor": {
        "deskripsi": "Referensi objek langsung (ID pada URL/parameter) tidak diverifikasi "
                     "kepemilikannya, sehingga data milik akun lain bisa diakses.",
        "dampak": "Kebocoran/putaran data antar pengguna atau antar perusahaan.",
        "severity": "High",
        "severity_dasar": "Likelihood sedang–tinggi (ID mudah ditebak) x Impact tinggi "
                          "(data pribadi/perusahaan lain terungkap).",
        "rekomendasi": [
            "Verifikasi di server bahwa objek yang diminta memang milik pengguna/scope "
            "yang sedang login sebelum mengembalikannya.",
            "    // contoh: batasi query dengan pemilik, jangan hanya by-id\n"
            "    SELECT * FROM doc WHERE id = :id AND company_id = :currentCompany;",
            "Pertimbangkan ID tak-terprediksi (UUID/ULID) sebagai lapis tambahan, "
            "bukan pengganti cek otorisasi.",
        ],
        "referensi": ["OWASP A01:2021 Broken Access Control",
                      "BSSN Perban No.4/2021 Pasal 26 huruf g (proteksi data)"],
    },
    "upload-accepted": {
        "deskripsi": "Berkas berbahaya (mis. PDF ber-JavaScript, polyglot, ekstensi ganda, "
                     "melebihi batas) diterima server karena validasi lemah.",
        "dampak": "Stored XSS saat file dibuka pengguna lain, penyimpanan konten "
                  "berbahaya, potensi pencurian sesi.",
        "severity": "High",
        "severity_dasar": "Likelihood sedang (perlu menyusun file) x Impact tinggi "
                          "(eksekusi skrip pada konteks korban).",
        "rekomendasi": [
            "Validasi tipe file berdasarkan ISI (magic bytes), bukan hanya ekstensi/"
            "Content-Type dari klien.",
            "Terapkan allowlist ekstensi & batas ukuran di server; tolak ekstensi ganda.",
            "Bersihkan/normalkan nama file (hindari path traversal), simpan dengan nama "
            "acak dan sajikan lewat Content-Disposition: attachment.",
            "Untuk PDF: tolak/strip objek /JavaScript & /OpenAction. Terapkan CSP ketat "
            "pada halaman yang menampilkan konten upload.",
        ],
        "referensi": ["OWASP A03:2021 Injection", "OWASP File Upload Cheat Sheet",
                      "BSSN Perban No.4/2021 Pasal 26 huruf d (validasi input)"],
    },
    "weak-password": {
        "deskripsi": "Kebijakan sandi menerima sandi lemah/umum.",
        "dampak": "Akun mudah ditebak/brute-force, pengambilalihan akun.",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang x Impact sedang–tinggi (per-akun).",
        "rekomendasi": [
            "Tetapkan panjang minimal (mis. 12–16 karakter) dan tolak sandi yang ada di "
            "daftar sandi bocor/umum.",
            "Aktifkan MFA/2FA, dan wajibkan sandi lama saat mengganti sandi.",
            "Simpan sandi dengan hash kuat (bcrypt/argon2), jangan plaintext/MD5/SHA1.",
        ],
        "referensi": ["OWASP A07:2021 Identification & Authentication Failures",
                      "NIST SP 800-63B",
                      "BSSN Perban No.4/2021 Pasal 26 huruf a (autentikasi)"],
    },
    "captcha-static": {
        "deskripsi": "Nilai captcha tidak diperbarui setelah percobaan gagal / dapat dipakai ulang.",
        "dampak": "Captcha tak efektif menahan otomasi/brute-force.",
        "severity": "Low",
        "severity_dasar": "Likelihood sedang x Impact rendah (lapis tambahan, bukan satu-satunya).",
        "rekomendasi": [
            "Regenerasi token & tantangan captcha setiap percobaan gagal; sekali pakai "
            "dengan masa berlaku singkat.",
            "Padukan dengan rate-limit dan lockout per-akun.",
        ],
        "referensi": ["OWASP A07:2021 Identification & Authentication Failures"],
    },
    "missing-header": {
        "deskripsi": "Security header respons tidak dikonfigurasi (atau header pembocor "
                     "info seperti Server/X-Powered-By masih tampil).",
        "dampak": "Memudahkan clickjacking, MIME sniffing, XSS, dan fingerprinting server.",
        "severity": "Low",
        "severity_dasar": "Likelihood rendah–sedang x Impact rendah (umumnya enabler, "
                          "bukan celah tunggal).",
        "rekomendasi": [
            "Set header di reverse proxy/framework:",
            "    Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "    Content-Security-Policy: default-src 'self'\n"
            "    X-Content-Type-Options: nosniff\n"
            "    X-Frame-Options: DENY\n"
            "    Referrer-Policy: strict-origin-when-cross-origin",
            "Kosongkan/hapus header Server dan X-Powered-By.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP Secure Headers Project"],
    },
    "mass-assignment": {
        "deskripsi": "Server menerima field yang tidak semestinya boleh diubah klien "
                     "(mis. role, is_admin, company_id, status) saat membuat/memperbarui "
                     "objek — mass assignment / otorisasi level-properti objek yang rusak.",
        "dampak": "Eskalasi hak atau manipulasi data: pengguna biasa menaikkan diri jadi "
                  "admin, pindah tenant, atau mengubah kepemilikan objek hanya dengan "
                  "menambah satu field pada request.",
        "severity": "High",
        "severity_dasar": "Likelihood sedang (cukup tambah field di body) x Impact tinggi "
                          "(eskalasi hak / integritas data).",
        "rekomendasi": [
            "Pakai allowlist field yang boleh di-assign; jangan mass-assign seluruh input.",
            "    // Laravel: batasi via $fillable + FormRequest->validated(),\n"
            "    // JANGAN Model::update($request->all()).",
            "Pisahkan field yang hanya boleh diubah admin; tolak/abaikan field istimewa "
            "dari peran non-admin.",
            "Terapkan otorisasi per-properti (BOPLA), bukan hanya per-objek.",
        ],
        "referensi": ["OWASP API3:2023 Broken Object Property Level Authorization",
                      "CWE-915 Improperly Controlled Modification of Object Attributes"],
    },
    "sql-injection": {
        "deskripsi": "Input pengguna disusun langsung ke query SQL tanpa parameterisasi, "
                     "sehingga penyerang dapat mengubah logika query (error-based, "
                     "boolean-based, atau time-based).",
        "dampak": "Pembacaan/perubahan data di luar wewenang, bypass autentikasi, hingga "
                  "potensi RCE tergantung konfigurasi DBMS.",
        "severity": "High",
        "severity_dasar": "Likelihood sedang–tinggi (vektor klasik, tooling melimpah) x "
                          "Impact tinggi (kerahasiaan & integritas data). Deteksi otomatis "
                          "wajib diverifikasi manual sebelum severity final dikunci.",
        "rekomendasi": [
            "Gunakan prepared statement / parameterized query (bind parameter), jangan "
            "merangkai string query dari input.",
            "    // Laravel: Model::where('x', $input) / DB::select('... = ?', [$input])\n"
            "    // JANGAN DB::raw(\"... = '$input'\").",
            "Terapkan allowlist tipe/format input dan least-privilege pada akun DB.",
            "Pakai ORM/query builder dengan benar; hindari raw query berisi input mentah.",
        ],
        "referensi": ["OWASP A03:2021 Injection",
                      "CWE-89 SQL Injection",
                      "OWASP Testing Guide WSTG-INPV-05"],
    },
    "server-vuln": {
        "deskripsi": "Versi web server/komponen yang terdeteksi dari banner cocok dengan "
                     "kerentanan yang telah terdaftar (CVE), mis. Apache mod_http2 atau "
                     "NGINX HTTP/2.",
        "dampak": "Bergantung CVE-nya, berpotensi remote code execution, DoS, atau "
                  "memory corruption pada server yang terekspos.",
        "severity": "High",
        "severity_dasar": "Likelihood sedang (eksploit publik untuk CVE yang aktif) x "
                          "Impact tinggi (RCE/DoS). Deteksi berbasis banner — keyakinan "
                          "sedang, wajib dikonfirmasi ke advisory vendor.",
        "rekomendasi": [
            "Update ke versi yang sudah diperbaiki sesuai advisory vendor (mis. Apache "
            "httpd 2.4.71+, NGINX 1.30.7+/1.31.9+).",
            "Batasi exposure komponen yang rentan; terapkan mitigasi sementara (mis. WAF, "
            "nonaktifkan modul/fitur terkait bila memungkinkan).",
            "Kosongkan banner versi (ServerTokens Prod / server_tokens off) agar tidak "
            "memudahkan fingerprint.",
        ],
        "referensi": ["OWASP A06:2021 Vulnerable and Outdated Components",
                      "CISA Known Exploited Vulnerabilities (KEV)"],
    },
    "tls-weak": {
        "deskripsi": "Server menerima protokol/cipher TLS usang.",
        "dampak": "Komunikasi berpotensi didekripsi (downgrade/known attacks).",
        "severity": "Medium",
        "severity_dasar": "Likelihood rendah (butuh posisi MITM) x Impact tinggi "
                          "(kerahasiaan data).",
        "rekomendasi": [
            "Nonaktifkan SSLv3/TLS1.0/TLS1.1; minimal TLS 1.2, utamakan TLS 1.3.",
            "Pakai cipher suite modern (ECDHE + AES-GCM/ChaCha20), nonaktifkan cipher lemah.",
        ],
        "referensi": ["OWASP A02:2021 Cryptographic Failures",
                      "BSSN Perban No.4/2021 huruf e (kriptografi)"],
    },
    "client-cache": {
        "deskripsi": "Respons yang memuat data sensitif (halaman/endpoint terautentikasi) "
                     "tidak melarang penyimpanan cache, sehingga bisa tersimpan di cache "
                     "browser, proxy bersama, atau tombol Back setelah logout.",
        "dampak": "Data sensitif pengguna terbaca dari perangkat/proxy bersama oleh pihak "
                  "lain setelah sesi berakhir.",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang (perangkat/proxy bersama, histori browser) x "
                          "Impact sedang–tinggi (data pribadi terungkap).",
        "rekomendasi": [
            "Set header anti-cache pada respons sensitif/terautentikasi:",
            "    Cache-Control: no-store, no-cache, must-revalidate, private\n"
            "    Pragma: no-cache\n"
            "    Expires: 0",
            "Jangan pakai 'public' atau 'max-age' besar pada respons yang memuat data user.",
            "Pastikan aset statis publik tetap boleh di-cache (jangan berlebihan sebaliknya).",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V8 Data Protection",
                      "BSSN Perban No.4/2021 huruf g (proteksi data)"],
    },
    "js-leak": {
        "deskripsi": "Bundle/aset JavaScript sisi klien membocorkan informasi sensitif: "
                     "endpoint internal/admin, secret (API key/token), atau source map "
                     "(.map) yang membuka kode sumber asli.",
        "dampak": "Memberi peta serangan — penyerang menemukan endpoint admin & struktur "
                  "API (seperti temuan privilege escalation yang berawal dari analisa JS), "
                  "atau memakai secret yang terekspos.",
        "severity": "Medium",
        "severity_dasar": "Likelihood tinggi (aset klien dapat diunduh siapa saja) x Impact "
                          "bervariasi (enabler s/d akses langsung bila berisi secret).",
        "rekomendasi": [
            "Jangan menaruh secret (API key, token, kredensial) di kode frontend — "
            "pindahkan ke server; frontend memanggil lewat backend.",
            "Nonaktifkan publikasi source map di produksi (mis. build tanpa .map, atau "
            "jangan sajikan file .map).",
            "Otorisasi endpoint di server — endpoint yang tertera di JS tetap harus menolak "
            "pengguna tak berwenang (lihat juga Broken Access Control).",
            "Audit berkala isi bundle (CI) untuk pola secret & referensi .map.",
        ],
        "referensi": ["OWASP A01/A05:2021",
                      "OWASP ASVS V14 Configuration",
                      "BSSN Perban No.4/2021 huruf g (proteksi data)"],
    },
    "info-exposure": {
        "deskripsi": "Berkas atau informasi sensitif terekspos publik tanpa perlu JavaScript: "
                     "file konfigurasi (.env), repository (.git/), backup/dump, atau "
                     "komentar/isi HTML yang membocorkan secret maupun endpoint internal.",
        "dampak": "Kebocoran kredensial, kode sumber, atau struktur sistem yang memudahkan "
                  "serangan lanjutan.",
        "severity": "High",
        "severity_dasar": "Likelihood tinggi (cukup GET satu URL) x Impact bervariasi "
                          "(dari peta serangan s/d kredensial langsung).",
        "rekomendasi": [
            "Jangan sajikan file sensitif dari web root: blokir akses ke .env, .git/, "
            "file backup/dump, dan file sumber.",
            "Contoh (nginx):",
            "    location ~ /\\.(?!well-known) { deny all; }\n"
            "    location ~* \\.(env|bak|sql|zip|tar\\.gz)$ { deny all; }",
            "Pindahkan konfigurasi secret ke environment variable / secret manager.",
            "Bersihkan komentar HTML yang memuat info sensitif sebelum rilis.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP A01:2021 (akses file)",
                      "BSSN Perban No.4/2021 huruf g & m (proteksi data & konfigurasi)"],
    },
    "cors-misconfig": {
        "deskripsi": "Konfigurasi CORS terlalu longgar: server memantulkan Origin apa pun "
                     "ke Access-Control-Allow-Origin, atau memadukan wildcard dengan "
                     "Access-Control-Allow-Credentials, atau menerima Origin 'null'.",
        "dampak": "Situs jahat yang dibuka korban bisa mengirim request berkredensial ke "
                  "API dan membaca responsnya — pencurian data terautentikasi lintas-origin.",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang (butuh korban buka situs jahat sambil login) x "
                          "Impact tinggi (baca data terautentikasi).",
        "rekomendasi": [
            "Jangan pantulkan Origin mentah. Pakai allowlist origin yang tepercaya saja.",
            "Contoh (pola backend):",
            "    if (allowlist.includes(origin)) resp.header('Access-Control-Allow-Origin', origin);",
            "Kalau butuh Access-Control-Allow-Credentials: true, Origin WAJIB spesifik, "
            "bukan '*' dan bukan hasil pantulan sembarangan.",
            "Tolak Origin 'null'. Batasi method & header yang diizinkan seperlunya.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V14 Configuration",
                      "BSSN Perban No.4/2021 huruf h (keamanan komunikasi)"],
    },
    "open-redirect": {
        "deskripsi": "Parameter pengalih (redirect/next/url/return) dipakai menyusun "
                     "Location tanpa validasi, sehingga bisa diarahkan ke domain luar.",
        "dampak": "Dipakai untuk phishing (tautan terlihat sah tapi mengarah ke situs "
                  "jahat) dan bypass proteksi berbasis domain.",
        "severity": "Low",
        "severity_dasar": "Likelihood sedang x Impact rendah–sedang (umumnya enabler "
                          "phishing, bukan akses langsung).",
        "rekomendasi": [
            "Validasi tujuan redirect terhadap allowlist path/domain internal.",
            "Hindari redirect ke URL absolut dari input pengguna; pakai path relatif saja.",
            "Kalau tujuan eksternal memang perlu, tampilkan halaman antara (interstitial).",
        ],
        "referensi": ["OWASP A01:2021 (Unvalidated Redirects)",
                      "OWASP Unvalidated Redirects & Forwards Cheat Sheet"],
    },
    "vuln-dependency": {
        "deskripsi": "Komponen/dependensi versi usang dengan kerentanan yang telah "
                     "terdaftar (CVE).",
        "dampak": "Bergantung CVE: dari kebocoran info hingga eksekusi kode jarak jauh "
                  "(RCE) lewat pustaka yang rentan.",
        "severity": "High",
        "severity_dasar": "Mengikuti skor CVSS pada CVE terkait; eksploit publik menaikkan "
                          "likelihood.",
        "rekomendasi": [
            "Perbarui paket ke versi perbaikan (fixed version) yang tertera pada temuan.",
            "Bila belum ada perbaikan, terapkan mitigasi/pin versi aman & pantau rilis.",
            "Otomatiskan: Dependabot/Renovate + gerbang CI (trivy/osv-scanner) agar CVE "
            "baru cepat terdeteksi.",
        ],
        "referensi": ["OWASP A06:2021 Vulnerable and Outdated Components",
                      "NVD / CVE", "BSSN Perban No.4/2021 (komponen usang)"],
    },
    "zap-generic": {
        "deskripsi": "Temuan hasil scan OWASP ZAP yang perlu analisis lanjutan "
                     "untuk memastikan true/false positive.",
        "dampak": "Bergantung jenis alert; tinjau detail per alert.",
        "severity": "Info",
        "severity_dasar": "Dari skor risiko ZAP; verifikasi manual sebelum ditetapkan.",
        "rekomendasi": [
            "Tinjau detail alert pada laporan ZAP (reports/zap-*.html).",
            "Konfirmasi apakah dapat direproduksi; tetapkan severity final setelah verifikasi.",
        ],
        "referensi": ["OWASP ZAP", "OWASP Top 10 2021"],
    },
    "auth-coverage-gap": {
        "deskripsi": "Endpoint yang menurut spesifikasi OpenAPI wajib autentikasi ternyata "
                     "dapat diakses tanpa kredensial (penegakan autentikasi tidak sesuai desain).",
        "dampak": "Siapa pun tanpa login dapat membaca (atau memicu) fungsi yang dianggap "
                  "terlindungi — akses data tanpa otorisasi.",
        "severity": "High",
        "severity_dasar": "Likelihood tinggi (tanpa prasyarat, cukup memanggil URL) x Impact "
                          "tinggi (data/fungsi terlindungi terbuka).",
        "rekomendasi": [
            "Pasang middleware autentikasi pada route tersebut, atau kelompokkan route "
            "terlindungi dalam satu grup auth sehingga default-nya terkunci.",
            "Contoh Laravel:",
            "    Route::middleware('auth:sanctum')->group(function () {\n"
            "        Route::get('/laporan', [LaporanController::class, 'index']);\n"
            "    });",
            "Terapkan 'default deny': route baru otomatis butuh auth kecuali dikecualikan eksplisit.",
            "Selaraskan spesifikasi OpenAPI dengan perilaku nyata, lalu jadikan uji ini bagian CI.",
        ],
        "referensi": ["OWASP API2:2023 Broken Authentication",
                      "OWASP API5:2023 Broken Function Level Authorization",
                      "OWASP A01:2021 Broken Access Control", "CWE-306"],
    },
    "unauthenticated-endpoint": {
        "deskripsi": "Endpoint tidak mendeklarasikan autentikasi, tidak termasuk daftar publik "
                     "yang diizinkan, namun dapat diakses tanpa kredensial.",
        "dampak": "Bila endpoint seharusnya privat, data atau fungsi terbuka bagi publik; bila "
                  "memang publik, daftar allowlist/spesifikasi perlu dilengkapi.",
        "severity": "Medium",
        "severity_dasar": "Perlu tinjauan: dampak bergantung apakah endpoint memang publik.",
        "rekomendasi": [
            "Tinjau tiap endpoint: bila privat, tambahkan autentikasi; bila publik, "
            "daftarkan di allowlist dan deklarasikan `security: []` di spesifikasi.",
            "Pastikan endpoint publik tidak mengembalikan data sensitif atau internal.",
        ],
        "referensi": ["OWASP API2:2023 Broken Authentication", "OWASP A01:2021", "CWE-306"],
    },
    "anon-server-error": {
        "deskripsi": "Request anonim (tanpa autentikasi) memicu galat server 5xx, menandakan "
                     "validasi atau penanganan galat belum dilakukan sebelum autentikasi.",
        "dampak": "Galat tak tertangani dapat membocorkan detail internal, mengindikasikan "
                  "bug yang bisa dipicu tanpa login, dan menjadi vektor gangguan layanan.",
        "severity": "Low",
        "severity_dasar": "Dapat dipicu tanpa prasyarat, tetapi dampak langsung terbatas "
                          "(ketersediaan/informasi).",
        "rekomendasi": [
            "Pastikan autentikasi dan validasi input berjalan lebih dulu dan menolak dengan "
            "401/403/422, bukan 500.",
            "Tangani exception di lapisan global dan kembalikan respons generik.",
            "Periksa log server untuk penyebab 500 dan tambahkan uji regresinya.",
        ],
        "referensi": ["OWASP API8:2023 Security Misconfiguration", "CWE-755, CWE-209"],
    },
    "spec-mismatch": {
        "deskripsi": "Spesifikasi OpenAPI tidak akurat terhadap perilaku nyata: operasi tidak "
                     "mendeklarasikan `security` padahal sebenarnya menolak akses anonim.",
        "dampak": "Dokumentasi menyesatkan; klien dan uji otomatis tidak dapat memercayai "
                  "spesifikasi, sehingga celah autentikasi sulit terdeteksi.",
        "severity": "Low",
        "severity_dasar": "Masalah kualitas dokumentasi; tidak membuka akses langsung.",
        "rekomendasi": [
            "Deklarasikan skema keamanan global dan `security` per operasi pada spesifikasi.",
            "Contoh (OpenAPI): components.securitySchemes + security: [{ cookieAuth: [] }]; "
            "tandai endpoint publik dengan `security: []`.",
            "Generate spesifikasi dari kode (mis. Scramble) dengan konfigurasi security yang benar.",
        ],
        "referensi": ["OpenAPI 3.x Security Requirement Object",
                      "OWASP API9:2023 Improper Inventory Management"],
    },
    "sensitive-data-exposure": {
        "deskripsi": "Respons API memuat data sensitif (sandi/hash, secret, token, kunci "
                     "pribadi, atau data rahasia lain) yang seharusnya tidak dikirim ke klien.",
        "dampak": "Kredensial atau secret yang bocor dapat dipakai untuk pengambilalihan akun, "
                  "akses ke layanan pihak ketiga, atau serangan lanjutan.",
        "severity": "High",
        "severity_dasar": "Likelihood tinggi (cukup memanggil endpoint) x Impact tinggi "
                          "(kebocoran kredensial/secret).",
        "rekomendasi": [
            "Jangan serialisasi field sensitif: pakai whitelist field eksplisit (API "
            "Resource/DTO) alih-alih mengembalikan model utuh.",
            "Contoh Laravel: sembunyikan di model dan gunakan Resource.",
            "    protected $hidden = ['password', 'remember_token', 'two_factor_secret',\n"
            "                          'two_factor_recovery_codes'];",
            "Cabut (revoke) dan rotasi secret yang sudah terlanjur terekspos.",
            "Terapkan authorization per field pada respons yang sama untuk peran berbeda.",
        ],
        "referensi": ["OWASP API3:2023 Broken Object Property Level Authorization",
                      "OWASP A02:2021 Cryptographic Failures",
                      "CWE-200, CWE-201, CWE-522"],
    },
    "verbose-error": {
        "deskripsi": "Respons (terutama error) membocorkan detail implementasi: stack trace, "
                     "path berkas server, versi kerangka kerja, atau pesan SQL.",
        "dampak": "Detail internal mempermudah pemetaan teknologi dan pengembangan serangan "
                  "terarah (mis. injeksi, eksploitasi versi rentan).",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang (mudah dipicu) x Impact rendah-sedang "
                          "(informasi pendukung serangan, bukan kompromi langsung).",
        "rekomendasi": [
            "Matikan mode debug di luar lokal (Laravel: APP_DEBUG=false; Django: DEBUG=False).",
            "Kembalikan pesan error generik + ID korelasi; simpan detail hanya di log server.",
            "Contoh Laravel (bootstrap/app.php): render JSON generik untuk request API.",
            "    $exceptions->render(fn (Throwable $e, Request $r) => $r->is('api/*')\n"
            "        ? response()->json(['message' => 'Terjadi kesalahan.'], 500) : null);",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP API8:2023 Security Misconfiguration", "CWE-209, CWE-215"],
    },
    "internal-info-leak": {
        "deskripsi": "Respons memuat alamat IP internal atau hostname jaringan privat.",
        "dampak": "Membantu pemetaan topologi jaringan internal untuk SSRF atau pivot.",
        "severity": "Low",
        "severity_dasar": "Informasi pendukung; dampak langsung rendah.",
        "rekomendasi": [
            "Hapus alamat/hostname internal dari respons dan header.",
            "Gunakan nama layanan publik atau ID opak alih-alih IP internal.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration", "CWE-200"],
    },
    "cookie-flags": {
        "deskripsi": "Cookie sesi/autentikasi tidak memakai atribut keamanan lengkap "
                     "(HttpOnly, Secure, SameSite) atau berumur terlalu panjang.",
        "dampak": "Tanpa HttpOnly, XSS dapat mencuri cookie sesi; tanpa Secure, cookie "
                  "dapat bocor lewat HTTP biasa; tanpa SameSite, risiko CSRF meningkat.",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang (butuh XSS/jaringan tak aman/CSRF sebagai "
                          "prasyarat) x Impact sedang-tinggi (pengambilalihan sesi).",
        "rekomendasi": [
            "Set HttpOnly pada seluruh cookie sesi/autentikasi (kecuali yang memang harus "
            "dibaca SPA, mis. XSRF-TOKEN).",
            "Set Secure dan sajikan situs hanya lewat HTTPS (aktifkan HSTS).",
            "Set SameSite=Lax (atau Strict untuk sesi sensitif); gunakan None hanya bila "
            "perlu lintas-situs dan wajib bersama Secure.",
            "Contoh Laravel (config/session.php):",
            "    'http_only' => true,\n    'secure' => env('SESSION_SECURE_COOKIE', true),\n"
            "    'same_site' => 'lax',\n    'lifetime' => 120,   // menit",
            "Pertimbangkan prefix __Host- untuk cookie sesi.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "OWASP ASVS V3.4 Cookie-based Session Management",
                      "OWASP Session Management Cheat Sheet", "CWE-1004, CWE-614, CWE-1275"],
    },
    "recon-subdomain": {
        "deskripsi": "Aset/subdomain yang dapat ditemukan publik melalui OSINT "
                     "(subfinder/httpx), memperluas attack surface.",
        "dampak": "Subdomain lupa (dangling), staging terbuka, atau panel admin "
                  "terekspos dapat menjadi titik masuk awal.",
        "severity": "Info",
        "severity_dasar": "Informatif — inventaris aset; severity naik bila host "
                          "membuka layanan/panel sensitif (lihat temuan terkait).",
        "rekomendasi": [
            "Inventarisasi seluruh subdomain; matikan/arsipkan yang tidak dipakai.",
            "Pastikan tidak ada subdomain dangling (DNS menunjuk ke resource terhapus) "
            "untuk mencegah subdomain takeover.",
            "Batasi akses environment non-produksi (staging/dev) dengan allowlist/VPN.",
        ],
        "referensi": ["OWASP WSTG-INFO", "OWASP ASM (Attack Surface Management)",
                      "MITRE ATT&CK T1595 Active Scanning"],
    },
    "exposed-service": {
        "deskripsi": "Port/layanan terbuka ke internet (mis. SSH, database, Redis, "
                     "Elasticsearch) yang seharusnya dibatasi.",
        "dampak": "Layanan admin/datastore yang terekspos memudahkan brute-force, "
                  "akses tanpa autentikasi, atau eksploitasi CVE layanan.",
        "severity": "Medium",
        "severity_dasar": "Likelihood sedang–tinggi (terindeks pemindai massal) x Impact "
                          "bergantung layanan; datastore tanpa auth = tinggi.",
        "rekomendasi": [
            "Tutup port yang tidak perlu; terapkan default-deny pada firewall/security group.",
            "Batasi akses manajemen (SSH/RDP/DB) ke IP tepercaya atau via VPN/bastion.",
            "Wajibkan autentikasi kuat pada datastore (Redis/Elasticsearch/Mongo) dan "
            "jangan paparkan ke 0.0.0.0.",
        ],
        "referensi": ["OWASP A05:2021 Security Misconfiguration",
                      "NIST SP 800-115", "CIS Controls v8 4.x"],
    },
    "leaked-secret": {
        "deskripsi": "Kredensial/secret (API key, token, password) terdeteksi di source "
                     "atau aset (trufflehog), berpotensi ter-commit ke repository.",
        "dampak": "Secret yang bocor dapat dipakai menyalahgunakan layanan pihak ketiga, "
                  "mengakses data, atau pivot ke sistem internal.",
        "severity": "High",
        "severity_dasar": "Likelihood tinggi (mudah ditemukan via scanner otomatis) x "
                          "Impact tinggi (akses langsung ke layanan/data). Terverifikasi = High.",
        "rekomendasi": [
            "Cabut (revoke) dan rotasi segera secret yang bocor; anggap sudah terkompromi.",
            "Hapus secret dari riwayat git (git filter-repo/BFG), bukan hanya commit terbaru.",
            "Pindahkan secret ke environment variable / secret manager; jangan commit ke repo.",
            "Pasang pre-commit hook (gitleaks/trufflehog) untuk mencegah kebocoran berulang.",
        ],
        "referensi": ["OWASP A07:2021 Identification and Authentication Failures",
                      "CWE-798 Use of Hard-coded Credentials", "OWASP ASVS V2.10"],
    },
    "recon-finding": {
        "deskripsi": "Temuan dari pemindaian vuln aktif (nuclei) terhadap aset hidup. "
                     "Severity dibawa langsung dari template nuclei yang cocok.",
        "dampak": "Bergantung template; dapat mencakup CVE, misconfiguration, "
                  "exposure, atau default-login yang dapat dieksploitasi.",
        "severity": "Medium",
        "severity_dasar": "Mengikuti severity template nuclei (CVSS/komunitas); "
                          "verifikasi true-positive sebelum eskalasi.",
        "rekomendasi": [
            "Verifikasi tiap temuan (true/false positive) pada target yang berwenang.",
            "Patch komponen rentan sesuai CVE/CWE yang tertera; cek ketersediaan versi fix.",
            "Perbaiki misconfiguration (header, CORS, panel terekspos) sesuai kategori tag.",
        ],
        "referensi": ["OWASP Top 10 2021", "nuclei templates (ProjectDiscovery)",
                      "CVSS v3.1"],
    },
}

# Pemetaan nama alert ZAP → kind yang lebih spesifik bila dikenali.
ZAP_KEYWORDS = [
    ("sql injection", "broken-access"),   # diarahkan ke injeksi via kb khusus bila ada
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


def classify(modul: str, judul: str) -> str:
    j = (judul or "").lower()
    if modul == "authz-matrix":
        if j.startswith("[forged]"):
            return "forged-header"
        if "idor" in j:
            return "idor"
        return "broken-access"
    if modul == "upload-safety":
        return "upload-accepted"
    if modul == "mass-assignment":
        return "mass-assignment"
    if modul == "webstack":
        return "server-vuln" if j.startswith("versi rentan") else "missing-header"
    if modul == "injection":
        return "sql-injection"
    if modul == "auth-policy":
        if "captcha" in j:
            return "captcha-static"
        return "weak-password"
    if modul == "client-leak":
        if "cache" in j:
            return "client-cache"
        if j.startswith("file") or "terekspos" in j or "html" in j:
            return "info-exposure"
        return "js-leak"
    if modul == "cors":
        return "cors-misconfig"
    if modul == "open-redirect":
        return "open-redirect"
    if modul == "cookie-flags":
        return "cookie-flags"
    if modul == "openapi-coverage":
        if "galat server" in j:
            return "anon-server-error"
        if "tak akurat" in j or "spesifikasi" in j and "dilindungi" not in j:
            return "spec-mismatch"
        if "terbuka tanpa" in j:
            return "unauthenticated-endpoint"
        return "auth-coverage-gap"
    if modul == "response-leak":
        if "debug" in j or "verbose" in j:
            return "verbose-error"
        if "internal" in j:
            return "internal-info-leak"
        return "sensitive-data-exposure"
    if modul == "recon":
        if j.startswith("secret"):
            return "leaked-secret"
        if j.startswith("subdomain") or j.startswith("host aktif") \
                or j.startswith("url historis") or j.startswith("crawl"):
            return "recon-subdomain"
        if j.startswith("port") or j.startswith("path") or "layanan" in j:
            return "exposed-service"
        return "recon-finding"
    if modul == "trivy-cve":
        return "vuln-dependency"
    if modul == "testssl":
        return "tls-weak"
    if modul == "zap":
        for kw, kind in ZAP_KEYWORDS:
            if kw in j:
                return kind
        return "zap-generic"
    return "zap-generic"


def lookup(kind: str) -> dict:
    return KB.get(kind, KB["zap-generic"])
