**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](panduan-penggunaan.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](panduan-penggunaan.de.md)

# Panduan Penggunaan

Panduan langkah demi langkah menjalankan Security Audit Kit, dari instalasi sampai membaca laporan.
Semua perintah memakai satu entry point, `python audit.py <modul>`, identik di Windows dan Linux.

> Hanya untuk sistem milik sendiri atau sistem yang Anda miliki izin tertulis untuk diuji.
> Pengujian tanpa izin melanggar hukum.

## 1. Prasyarat

| Kebutuhan | Dipakai untuk | Cek |
|---|---|---|
| Python 3.10+ | Semua modul | `python --version` |
| Docker | `deps`, `zap`, `tls` (modul lain tidak memerlukannya) | `docker --version` |
| make (opsional) | Perintah pendek di Linux/macOS | `make --version` |
| Playwright (opsional) | Verifikasi *cache* browser pada `clientleak` | `python -m playwright --version` |

Playwright dipasang dengan `pip install playwright` lalu `python -m playwright install chromium`.

## 2. Instalasi

```
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt
```

## 3. Mulai cepat: scan pertama dalam 5 menit

Langkah ini memakai modul `headers` yang pasif, murni Python, dan tidak memerlukan Docker.

1. Buat project.

   ```
   python audit.py --project my-app init
   ```

   Hasil: folder `projects/my-app/` berisi `config/targets.yml` dan `reports/`.

2. Isi `base_url` pada `projects/my-app/config/targets.yml`.

   ```yaml
   base_url: "http://localhost:8080"
   ```

   Hasil: target mengarah ke aplikasi Anda (gunakan dev/staging, bukan production).

3. Jalankan modul `headers`.

   ```
   python audit.py --project my-app headers
   ```

   Hasil: tiap *header* ditandai `ok`, `MISS` (hilang), atau `LEAK` (membocorkan informasi); hasil disimpan di `reports/headers.json`.

4. Susun laporan.

   ```
   python audit.py --project my-app report
   ```

   Hasil: `projects/my-app/reports/laporan.html`. Buka di browser.

## 4. Konfigurasi

Berkas `*.yml` yang asli sudah masuk `.gitignore`, sehingga kredensial tidak ikut ter-commit.

### targets.yml

Field utama (daftar lengkap ada di [config/targets.example.yml](../config/targets.example.yml)):

| Field | Keterangan |
|---|---|
| `base_url` | URL dasar target, mis. `http://localhost:8080` |
| `openapi` | URL atau path spesifikasi OpenAPI (untuk `zap api`) |
| `tls_host` | Host tanpa skema untuk modul `tls` |
| `header_probe_path` | Path untuk modul `headers` (bawaan `/`) |
| `code_path` | Folder repo untuk modul `deps` |
| `docker_network` | Jaringan Docker untuk ZAP dan testssl, wajib bila target `localhost` |
| `snapshot` | Dump dan pemulihan data di sekitar `zap api` dan `zap full` |
| `report` | Penyusun, perusahaan, bahasa laporan (lihat bagian 8) |

### Konfigurasi per modul

Setiap modul pengujian memiliki berkas config sendiri, `tests/<folder>/<nama>.yml`.
Salin dari contohnya dengan `init`, yang tidak menimpa berkas yang sudah ada:

```
python audit.py --project my-app init authz,upload,cors
```

- Tanpa `--project`, salin manual: `tests/<folder>/<nama>.example.yml` menjadi `tests/<folder>/<nama>.yml`.
- Pada `all`, modul tanpa config dilewati. Menjalankan modul langsung tanpa config menghasilkan *error* "belum ada".

### Kredensial: hanya lewat environment variable

Config merujuk kredensial dengan `${NAMA_VARIABEL}`. Nama variabel tertera pada tiap berkas `.example.yml`.
Variabel yang belum diset diganti string kosong tanpa peringatan.

```
export AUTHZ_ADMIN_USER="admin@example.com"
export AUTHZ_ADMIN_PASS="..."
```

```
$env:AUTHZ_ADMIN_USER = "admin@example.com"
$env:AUTHZ_ADMIN_PASS = "..."
```

Baris pertama untuk Linux/macOS, baris kedua untuk Windows PowerShell.
Untuk ZAP di balik *login*, set `ZAP_AUTH_HEADER` berisi `Authorization: Bearer <token>`.

### Autentikasi

| Mode | Isi config |
|---|---|
| Bearer/JWT atau *header* kustom | `auth.header` dan `auth.value`, mis. `value: "${TOKEN}"` dengan `TOKEN="Bearer xxx"` |
| Laravel Sanctum (*session cookie* + CSRF) | `auth.sanctum` (`enabled`, `csrf_path`, `origin`) dan `auth.login` |

- Pada mode Sanctum, runner mengambil *cookie* CSRF, *login*, lalu menyertakan `X-XSRF-TOKEN` dan `Origin` otomatis.
- `origin` wajib cocok dengan `SANCTUM_STATEFUL_DOMAINS` di server.
- Modul `authz` memakai `auth.mode` (`bearer` atau `session_cookie`) dengan daftar *role*; lihat contoh di `tests/authz-matrix/`.

## 5. Menjalankan scan

```
python audit.py authz
python audit.py all
```

| Modul | Yang diperiksa | Memerlukan |
|---|---|---|
| `headers` | Security *header* yang kurang atau membocorkan informasi | Target hidup |
| `tls` | Protokol dan cipher TLS usang | Docker, target hidup |
| `deps` | CVE *dependency* (Trivy), SAST (semgrep), *secret* ter-commit (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP passive scan | Docker, target hidup |
| `zap api` | ZAP active scan dari OpenAPI; destruktif | Docker, target hidup, `openapi` |
| `zap full` | ZAP active scan; destruktif, hanya environment sendiri | Docker, target hidup |
| `authz` | *Access control* per *role*: privilege escalation, IDOR, forged *header*, *bypass* gateway | Target hidup, config |
| `mass-assignment` | Mass assignment (BOPLA); destruktif tetapi reversibel | Target hidup, config |
| `upload` | Penolakan *file upload* berbahaya | Target hidup, config |
| `auth-policy` | Kekuatan *password* dan regenerasi captcha | Target hidup, config |
| `clientleak` | *Cache response* sensitif, *secret* di JS/HTML, *source map*, *file* terekspos | Target hidup, config |
| `cors` | CORS *misconfiguration* | Target hidup, config |
| `open-redirect` | Open *redirect* | Target hidup, config |
| `webstack` | Versi web server dari banner dipetakan ke CVE; non-destruktif | Target hidup, config |
| `injection` | SQL injection (*error*, boolean, time-based opsional); hanya probing baca | Target hidup, config |
| `cookie-flags` | Atribut *cookie* (HttpOnly, Secure, SameSite); pasif | Target hidup, config |
| `response-leak` | Data sensitif, *secret*, dan *stack trace* pada *response* API; pasif | Target hidup, config |
| `openapi-coverage` | Operasi yang dideklarasikan terlindungi tetapi terbuka tanpa *login* | Target hidup, config |
| `ratelimit` | *Rate limit*, *lockout* akun, enumerasi akun; memakai akun uji sekali pakai | Target hidup, config |
| `session-mgmt` | Pencabutan *session* saat *logout* dan ganti *password*; akun uji sekali pakai | Target hidup, config |
| `captcha` | Analisis statis tantangan captcha: apakah *response* membocorkan jawaban | Target hidup, config |
| `jwt` | Kelemahan JWT: alg none, exp hilang, *secret* lemah, *token* palsu | Target hidup, config |
| `ssrf` | SSRF lewat listener canary lokal | Target hidup, config |
| `recon` | OSINT *subdomain*; fase aktif (port scan, nuclei) hanya bila diaktifkan | Tool recon terpasang, config opsional |
| `report` | Merangkai hasil di `reports/` menjadi laporan | Hasil scan |
| `rollback` | Memulihkan aksi destruktif dari jurnal | Jurnal *rollback* |
| `clean` | Menghapus berkas di `reports/` | - |

- `all` menjalankan `headers`, `deps`, `zap baseline`, semua modul yang config-nya ada, dan `recon` bila `recon.yml` ada. Lalu `all` menyusun laporan dan menjalankan *rollback*.
- Setiap modul pengujian yang dijalankan sendiri juga menyusun laporan otomatis.
- Sub-perintah: `zap baseline|api|full`, `deps gitleaks|semgrep|trivy` (satu tool per jalan, hemat memori).
- `recon` menerima argumen bebas: `python audit.py recon example.com -d osint -m fast --active`.
- Alternatif: `.\audit.ps1 <modul>` di Windows (semua modul), `make <target>` di Linux/macOS (hanya sebagian modul; lihat `make help`).

## 6. Membaca laporan

Setelah `report` atau `all`, hasil ada di `reports/`:

| Berkas | Isi |
|---|---|
| `laporan.html` | Laporan lengkap: ringkasan risiko, daftar alert, instance sebagai bukti, tingkat keyakinan, dampak, justifikasi severity, rekomendasi, referensi |
| `laporan.md` | Isi yang sama dalam Markdown |
| `laporan-slides.html` | Slide deck mandiri untuk paparan ke stakeholder; navigasi panah kiri/kanan |
| `evidence/` | Screenshot bukti (mis. dari `clientleak`); sertakan saat laporan dibagikan |

Severity: Critical, High, Medium, Low, Info. Bagian Kontrol yang Lolos (PASS) berisi pemeriksaan yang berperilaku benar, sebagai bukti cakupan, bukan temuan.

Cara memakai temuan:

1. Mulai dari Critical dan High pada ringkasan risiko.
2. Verifikasi tiap temuan secara manual; hasil otomatis bukan pengganti pentest.
3. Terapkan rekomendasi, lalu jalankan ulang modul yang sama.
4. Kunci temuan agar tidak muncul kembali (bagian 10).

Contoh keluaran: [contoh-laporan.md](contoh-laporan.md) dan [contoh-laporan.html](contoh-laporan.html).

## 7. *Rollback*

Modul destruktif (`mass-assignment`, `ratelimit`, `session-mgmt`, serta `zap api` dan `zap full` dengan `snapshot`) memulihkan target secara otomatis sebagai tahap terakhir, setelah laporan dibuat.

1. Runner mencatat cara pemulihan ke `reports/rollback_journal.json` segera setelah tiap penulisan (aman saat crash).
2. Setelah laporan dibuat, `audit.py` memulihkan seluruh perubahan.
3. Log pemulihan ada di `reports/rollback.json`.

Jika pemulihan otomatis gagal (mis. koneksi putus), ulangi:

```
python audit.py rollback
```

Pada `zap api` dan `zap full`, *backup* yang gagal membatalkan scan. Tanpa blok `snapshot`, perubahan data tidak dapat dipulihkan.

## 8. Opsi lanjutan

Opsi global `--project`, `--color`, dan `--lang` dapat diletakkan di posisi mana pun dan berlaku untuk semua modul.

### Multi-project (paralel)

Tanpa `--project`, kit memakai `config/`, `tests/<modul>/*.yml`, dan `reports/` di folder kit (satu project).
Beri tiap project folder sendiri agar beberapa project dapat diaudit bersamaan dari terminal berbeda:

```
python audit.py --project my-app init authz,upload
python audit.py --project my-app all
python audit.py --project client-b headers
```

- Nama saja (mis. `my-app`) berarti `projects/<nama>/` di dalam kit (sudah di-gitignore). Path absolut atau relatif berarti folder itu.
- `init` menyalin `targets.example.yml` dan config modul yang disebut, serta membuat `reports/`.
- Setara: env `SAK_PROJECT_DIR`, `make <target> PROJECT=<nama|folder>`, `.\audit.ps1 <modul> -Project <nama|folder>`.
- Kredensial tetap lewat environment variable, sehingga tiap terminal dapat memakai nilai berbeda.

Saat berjalan bersamaan:

- Trivy memakai *cache* DB bersama (`~/.cache/sak-trivy`); run paralel diantrekan oleh kunci berkas. Isi `trivy_cache_dir` untuk *cache* terpisah.
- ZAP full, trivy, dan semgrep berat di RAM; jalankan bergiliran bila memori terbatas.
- Jangan menjalankan dua modul destruktif ke target yang sama secara bersamaan.

### Menjalankan dari folder mana pun

`python audit.py` hanya berjalan dari folder kit. Dari folder lain, gunakan path lengkap ke `audit.py`.
Folder project boleh di mana saja karena config dibaca dari folder project.

```
python C:\tools\security-audit-kit\audit.py --project C:\Users\you\sak-projects\my-app all
& C:\tools\security-audit-kit\audit.ps1 all -Project C:\Users\you\sak-projects\my-app
python3 /opt/security-audit-kit/audit.py --project ~/sak-projects/my-app all
make -C /opt/security-audit-kit all PROJECT=/home/you/sak-projects/my-app
```

Baris 1-2 untuk Windows PowerShell, baris 3-4 untuk Linux/macOS. Pada `make -C`, gunakan path absolut karena `make` berpindah ke folder kit.

Pintasan `sak` agar tidak mengetik path panjang. Pasang sekali:

```
function sak { python C:\tools\security-audit-kit\audit.py @args }
alias sak='python3 /opt/security-audit-kit/audit.py'
sak --project C:\Users\you\sak-projects\my-app all
sak --project C:\Users\you\sak-projects\client-b headers
```

Baris 1 ditambahkan ke profil PowerShell (`notepad $PROFILE`), baris 2 ke `~/.bashrc` atau `~/.zshrc`. Baris 3-4: pemakaian dari folder mana pun.

Path project relatif dihitung dari folder tempat perintah dijalankan. Simpan folder project di luar folder kit agar tidak hilang saat folder kit dihapus.

### Mode bug bounty

Untuk program di HackerOne, Bugcrowd, Intigriti, dan sejenisnya. Salin scope dan batas rate dari halaman program, lalu aktifkan blok `bounty:` di `targets.yml` project.

```yaml
bounty:
  enabled: true
  in_scope: ["app.example.com", "*.example.com"]
  out_of_scope: ["admin.example.com"]
  max_rps: 5
  allow_active: []
```

- `in_scope` memakai nama host. `*.example.com` hanya cocok untuk *subdomain*, bukan apex; tulis apex secara terpisah. `out_of_scope` selalu menang.
- Semua modul menolak host di luar scope, termasuk `base_url` pada config modul.
- Modul yang mengirim trafik aktif ditolak: `injection`, `ratelimit`, `session-mgmt`, `mass-assignment`, `upload`, `ssrf`, `auth-policy`, `jwt`, `zap api`/`zap full`, serta port scan, nuclei, crawl, dan fuzz di `recon`. Tambahkan namanya ke `allow_active` (`recon-active`, `zap-api`, `zap-full` untuk yang bukan modul Python) hanya jika aturan program mengizinkan.
- `recon` membuang *subdomain* di luar scope sebelum probing dan meneruskan `max_rps` ke httpx (`-rl`).
- Semua modul Python dibatasi otomatis, tanpa konfigurasi per modul: setiap *request* (termasuk tiap *redirect* dan retry) diperiksa terhadap scope dan dijaga agar total lajunya tidak melebihi `max_rps`, dengan jeda merata tanpa lonjakan. *Redirect* ke host di luar scope diblokir sebelum dikirim. Jika scope tidak dapat dimuat, modul tidak dijalankan sama sekali.
- Pengecualian: tool Docker (`zap` baseline dan `tls`) hanya dicek scope-nya, karena `max_rps` tidak dapat dipaksakan pada proses di luar Python. Cek *cache* browser di `clientleak` dinonaktifkan di mode bounty karena Chromium tidak dapat dibatasi tanpa mematikan *cache*; screenshot bukti pada `authz` tetap berjalan lewat guard.

Alur yang disarankan:

```
python audit.py --project acme-h1 init recon,clientleak,cors,open-redirect,cookie-flags,response-leak,webstack
python audit.py --project acme-h1 scope https://app.example.com
python audit.py --project acme-h1 recon
python audit.py --project acme-h1 clientleak
```

`scope` tanpa argumen menampilkan scope aktif; dengan host atau URL ia menjawab *in scope* atau *out of scope* (exit code 1). Hasil scanner hanya peta awal: verifikasi manual dan tulis PoC sebelum melapor, karena temuan otomatis sering berstatus duplicate.

### Penyusun dan perusahaan di laporan

Baris "Disusun oleh" pada laporan HTML, Markdown, dan slide berasal dari blok `report:` di `targets.yml`.
Kredit Security Audit Kit tetap tampil pada baris "Alat".

```yaml
report:
  prepared_by: "Jane Doe"
  organization: "Example Corp"      # "" menyembunyikan perusahaan
  contact: "audit@example.com"      # "" menyembunyikan kontak
  version: "1.0"
```

- Jika field tidak diisi, laporan memakai nilai bawaan kit: penyusun "Sapto Hadi", perusahaan "PT. Wahana Reka Tekindo", kontak "wahanarekatekindo@gmail.com" (kontak hanya untuk perusahaan bawaan). Isi blok di atas agar laporan memuat identitas Anda.
- Env `SAK_REPORT_AUTHOR`, `SAK_REPORT_ORG`, dan `SAK_REPORT_CONTACT` menimpa `targets.yml`.

### Warna konsol

Warna hanya muncul di terminal interaktif (`auto`) dan tidak pernah masuk ke berkas JSON atau laporan.

| Cara | Efek |
|---|---|
| `--color always` (atau `--color` saja) | Paksa menyala, juga ke pipe |
| `--no-color` atau `--color never` | Matikan |
| env `NO_COLOR=1` | Matikan |
| env `SAK_COLOR=always\|never\|auto` | Setara `--color`; menimpa `NO_COLOR` dan `FORCE_COLOR` |
| env `FORCE_COLOR=1` atau `CLICOLOR_FORCE=1` | Paksa menyala |

Git Bash sering tidak terdeteksi sebagai terminal; gunakan `--color always`.

### Bahasa dan istilah teknis

Istilah teknis tetap berbahasa Inggris dan dicetak miring pada laporan; daftarnya ada di `glosarium.yml` (id, en, de).

- Pilih bahasa dengan `--lang id|en|de`, env `SAK_LANG`, atau `report.language` di `targets.yml` (bawaan `en`).
- Katalog teks lengkap saat ini hanya tersedia untuk `id`; bahasa lain memakai teks `id` dengan glosarium bahasa terpilih.
- Rincian dan cara menambah istilah: [Glosarium dan bahasa](glosarium.md).

## 9. Integrasi CI

- `deps` aman dijalankan pada setiap PR karena tidak memerlukan target hidup. Hasilnya informatif (exit code 0).
- Pengujian dinamis memerlukan target hidup; jalankan terjadwal ke dev/staging, bukan production.
- Kredensial lewat GitHub *Secrets*. Modul pengujian mengembalikan exit code 1 bila ada kegagalan.

Contoh pipeline: [security-audit.yml](../.github/workflows/security-audit.yml).

## 10. Menerjemahkan temuan menjadi test

Untuk mengunci temuan dari laporan pentest, lihat [temuan-to-test-mapping.md](temuan-to-test-mapping.md): pemetaan kelas temuan ke modul beserta cara menambah kasus uji.

## 11. Troubleshooting

| Gejala | Penyebab dan solusi |
|---|---|
| `can't open file '...\audit.py'` | Dijalankan dari luar folder kit. Pakai path lengkap, `audit.ps1`, atau pintasan `sak` (bagian 8). |
| `config/targets.yml belum ada` atau `<folder>\config\targets.yml belum ada (project: ...)` | Config belum dibuat atau path project salah. Jalankan `python audit.py --project <nama> init`. |
| `<config> belum ada - salin dari contoh .example-nya` | Config modul belum ada. Jalankan `init <modul>` atau salin berkas `.example.yml`. |
| `Docker tidak ditemukan di PATH` atau scanner gagal | Pasang Docker dan pastikan berjalan serta dapat mengunduh image. |
| ZAP atau testssl `Connection refused` pada target `localhost` | Di dalam container, `localhost` menunjuk ke container itu. Isi `docker_network` di `targets.yml`. |
| *Login* Sanctum gagal 500 "*Session* store not set" | `auth.sanctum.origin` tidak cocok dengan `SANCTUM_STATEFUL_DOMAINS` server. |
| *Login* gagal padahal kredensial benar | Environment variable belum diset (nilai kosong). Set di terminal yang sama. |
| Banyak *request login* tertolak 429 | *Rate limit* target. Beri jeda antar-request. |
| *Error* sertifikat pada target dev dengan self-signed certificate | Set `SAK_INSECURE_TLS=1` (berlaku untuk `headers` dan runner Python; tidak untuk ZAP dan `tls`). |
| `clientleak` melewati cek browser | Playwright belum terpasang (opsional). |
| `semgrep` melewati batas waktu | Persempit `semgrep_paths` atau naikkan `semgrep_timeout_minutes`. |
| Teks aneh seperti `^[[32m`, atau tidak ada warna sama sekali | Terminal tidak mendukung ANSI: pakai `--no-color`. Warna tidak muncul karena keluaran dialihkan atau terminal tidak terdeteksi: pakai `--color always` dan pastikan `NO_COLOR` tidak diset. |
