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
