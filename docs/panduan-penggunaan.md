**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](panduan-penggunaan.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](panduan-penggunaan.de.md)

# Panduan Penggunaan — Step by Step

Panduan ini menjelaskan cara menjalankan Security Audit Kit terhadap sebuah target,
dari instalasi sampai membaca laporan. Seluruh perintah dijalankan melalui satu entry
point `python audit.py <modul>`, identik di Windows maupun Linux.

> Hanya untuk sistem milik sendiri atau sistem yang Anda miliki izin tertulis untuk
> diuji. Pengujian tanpa izin melanggar hukum.

## 1. Prasyarat

- **Python 3.10+**.
- **Docker** — dipakai modul scanner (ZAP, Trivy, semgrep, gitleaks, testssl.sh) melalui
  Docker image resmi. Modul pengujian internal (authz, upload, dll.) tidak memerlukan Docker.
- Opsional: **Playwright** untuk verifikasi cache via browser pada modul `clientleak`
  (`pip install playwright && python -m playwright install chromium`).

Instalasi dependency Python:

```
pip install -r requirements.txt
```

## 2. Konfigurasi target

Salin berkas contoh lalu isi sesuai target. Berkas `*.yml` yang asli sudah masuk
`.gitignore` sehingga kredensial tidak ikut ter-commit.

```
cp config/targets.example.yml config/targets.yml
```

Isi minimal pada `config/targets.yml`:

| Field | Keterangan |
|---|---|
| `base_url` | URL dasar target, mis. `http://localhost:8080` |
| `tls_host` | Host untuk pemeriksaan TLS (modul `tls`) |
| `header_probe_path` | Path untuk pemeriksaan security header (modul `headers`) |
| `code_path` | Path repo untuk scan dependency/secret (modul `deps`) |

## 3. Konfigurasi per modul pengujian

Modul pengujian internal (`authz`, `upload`, `auth-policy`, `clientleak`, `cors`,
`open-redirect`, `mass-assignment`) masing-masing memiliki berkas konfigurasi sendiri.
Salin dari berkas `.example` yang tersedia, lalu sesuaikan:

```
cp tests/authz-matrix/authz_matrix.example.yml tests/authz-matrix/authz_matrix.yml
cp tests/upload-safety/upload_safety.example.yml tests/upload-safety/upload_safety.yml
# ...dan seterusnya untuk modul yang akan dipakai
```

Modul yang berkas konfigurasinya belum ada akan dilewati saat menjalankan `all`.

### Kredensial lewat environment variable

Konfigurasi merujuk kredensial melalui `${NAMA_VARIABEL}`, bukan menuliskannya di
berkas. Set environment variable sebelum menjalankan scan.

Linux/macOS:

```
export AUTHZ_ADMIN_USER="admin@contoh.test"
export AUTHZ_PASS="..."
```

Windows (PowerShell):

```
$env:AUTHZ_ADMIN_USER = "admin@contoh.test"
$env:AUTHZ_PASS = "..."
```

Nama variabel mengikuti yang tertera pada tiap berkas `.example.yml`.

### Autentikasi (Bearer atau Laravel Sanctum)

Dua mode didukung:

- **Token statis (Bearer/JWT atau header kustom)** — isi blok `auth.header` dan
  `auth.value`, mis. `value: "${TOKEN}"` dengan `TOKEN="Bearer xxx"`. Cara memperoleh
  token: login sekali ke endpoint login, ambil token dari response.
- **Laravel Sanctum (SPA, session cookie + CSRF)** — aktifkan blok `auth.sanctum`
  (`enabled: true`, `csrf_path`, `origin`) dan `auth.login`. Runner akan mengambil
  cookie CSRF, login, lalu menyertakan header `X-XSRF-TOKEN` dan `Origin` secara
  otomatis. `origin` wajib cocok dengan `SANCTUM_STATEFUL_DOMAINS` di server.

## 4. Menjalankan scan

### Menjalankan satu modul

```
python audit.py <modul>
```

Modul yang tersedia:

| Modul | Fungsi | Memerlukan |
|---|---|---|
| `deps` | CVE dependency (Trivy) + SAST (semgrep) + secret ter-commit (gitleaks) | Docker |
| `zap baseline` | OWASP ZAP passive scan | Docker, target hidup |
| `zap api` | OWASP ZAP scan dari OpenAPI | Docker, target hidup, OpenAPI |
| `zap full` | OWASP ZAP active scan (destruktif, pakai hanya di environment sendiri) | Docker, target hidup |
| `authz` | Access control per role: privilege escalation, IDOR, forged header, bypass gateway | Target hidup, config |
| `mass-assignment` | Mass assignment / BOPLA — destruktif tapi reversibel (lihat bagian Rollback) | Target hidup, config |
| `upload` | Penolakan file upload berbahaya | Target hidup, config |
| `auth-policy` | Kekuatan password dan regenerasi captcha | Target hidup, config |
| `clientleak` | Cache response sensitif, secret/endpoint di JS/HTML, source map, file terekspos | Target hidup, config |
| `cors` | CORS misconfiguration | Target hidup, config |
| `open-redirect` | Open redirect | Target hidup, config |
| `webstack` | Deteksi versi web server dari banner → CVE yang diketahui (Apache mod_http2, NGINX HTTP/2); non-destruktif | Target hidup, config |
| `injection` | SQL injection (error/boolean-based, time-based opsional); non-destruktif, probing baca | Target hidup, config |
| `tls` / `headers` | Protokol/cipher TLS usang, security header yang kurang | Target hidup |
| `report` | Merangkai seluruh hasil menjadi laporan | Hasil scan di `reports/` |
| `rollback` | Memulihkan ulang aksi destruktif dari rollback journal | — |

### Menjalankan seluruh scan

```
python audit.py all
```

Perintah ini menjalankan `headers`, `deps`, `zap baseline`, lalu setiap modul
pengujian yang konfigurasinya tersedia, kemudian merangkai laporan secara otomatis,
dan terakhir menjalankan rollback bila ada aksi destruktif yang tercatat.

### Alternatif

- `make <modul>` (Linux/macOS, bila `make` tersedia).
- `./audit.ps1 <modul>` (Windows PowerShell).

### Multi-project (paralel)

Tanpa opsi tambahan, kit memakai `config/`, `tests/<modul>/*.yml`, dan `reports/` di folder kit
itu sendiri (satu project). Untuk mengaudit beberapa project sekaligus, beri tiap project folder
sendiri dengan `--project`:

```
python audit.py --project apple-gatrik init authz,upload,cookie-flags
python audit.py --project apple-gatrik all
```

- **Nama saja** (mis. `apple-gatrik`) → folder `projects/<nama>/` di dalam kit (sudah
  di-gitignore). **Path** (absolut atau relatif terhadap direktori kerja) → folder tersebut.
- `init` menyalin `config/targets.example.yml` dan contoh config modul yang disebutkan ke folder
  project, serta membuat `reports/`. Berkas yang sudah ada tidak ditimpa.
- Setara dengan `--project`: env `SAK_PROJECT_DIR`, `make <target> PROJECT=<nama|folder>`, dan
  `.\audit.ps1 <modul> -Project <nama|folder>`.
- Jalankan tiap project di terminal terpisah. Kredensial tetap lewat environment variable,
  sehingga tiap terminal dapat memakai nilai berbeda.

#### Menjalankan dari folder mana pun

`audit.py` berada di folder kit, sehingga `python audit.py` hanya berjalan bila direktori kerja
adalah folder kit. Dari folder lain (mis. `C:\GitHub`) perintah gagal dengan
`can't open file '...\audit.py'`. Gunakan path lengkap ke `audit.py`; folder project boleh di
mana saja karena config dibaca dari folder project, bukan dari direktori kerja:

```powershell
# Windows PowerShell
python C:\GitHub\security-audit-kit\audit.py --project C:\Users\sapto\sak-projects\apple-gatrik all

# atau lewat pembungkus (otomatis berpindah ke folder kit; -Project relatif dihitung dari folder pemanggil)
& C:\GitHub\security-audit-kit\audit.ps1 all -Project C:\Users\sapto\sak-projects\apple-gatrik
```

```bash
# Linux/macOS
python3 /opt/security-audit-kit/audit.py --project ~/sak-projects/apple-gatrik all
make -C /opt/security-audit-kit all PROJECT=/home/sapto/sak-projects/apple-gatrik   # PROJECT absolut
```

Agar tidak mengetik path panjang, buat pintasan sekali saja:

```powershell
# Windows: tambahkan ke profil PowerShell (buka dengan: notepad $PROFILE)
function sak { python C:\GitHub\security-audit-kit\audit.py @args }
# lalu dari folder mana pun:
sak --project C:\Users\sapto\sak-projects\apple-gatrik all
sak --project C:\Users\sapto\sak-projects\kumham headers
```

```bash
# Linux/macOS: tambahkan ke ~/.bashrc atau ~/.zshrc
alias sak='python3 /opt/security-audit-kit/audit.py'
```

Catatan: path project relatif (`--project ./proj` atau `-Project .\proj`) dihitung dari direktori
tempat perintah dijalankan. Untuk `make -C`, gunakan path absolut karena `make` berpindah ke
folder kit terlebih dahulu. Folder project sebaiknya di luar folder kit (mis.
`~/sak-projects/<nama>`) agar tidak ikut hilang saat folder kit atau worktree dihapus.

Yang perlu diperhatikan saat berjalan bersamaan:

- **Trivy** memakai cache DB bersama (`~/.cache/sak-trivy`); run dari beberapa project otomatis
  diantrekan oleh kunci berkas (pesan "menunggu trivy project lain selesai"). Isi
  `trivy_cache_dir` di `targets.yml` untuk cache terpisah.
- **RAM**: ZAP full, trivy, dan semgrep cukup berat; jalankan bergiliran bila memori host terbatas.
- **Target yang sama**: jangan menjalankan dua modul destruktif (mass-assignment, ZAP aktif dengan
  snapshot) ke target yang sama secara bersamaan.

### Penyusun dan perusahaan di laporan

Baris "Disusun oleh" pada laporan HTML, Markdown, dan slide diambil dari blok `report:` di
`targets.yml` project; kredit Security Audit Kit tetap ditampilkan pada baris "Alat".

```yaml
report:
  prepared_by: "Sapto Hadi"                  # default: Sapto Hadi
  organization: "PT. Wahana Reka Tekindo"    # default; isi "" untuk menyembunyikan
  contact: "wahanarekatekindo@gmail.com"     # default hanya bila perusahaan default; "" = sembunyikan
  version: "1.0"                             # versi dokumen
```

Env `SAK_REPORT_AUTHOR`, `SAK_REPORT_ORG`, dan `SAK_REPORT_CONTACT` menimpa nilai tersebut.

## 5. Membaca laporan

Setelah `report` atau `all`, hasil tersimpan di:

- `reports/laporan.html` — laporan lengkap bergaya ZAP: ringkasan risiko, daftar alert,
  rincian tiap temuan beserta instance (endpoint yang diuji sebagai bukti), tingkat
  keyakinan, dampak, justifikasi severity, rekomendasi, dan referensi.
- `reports/laporan.md` — isi yang sama dalam format Markdown.
- `reports/laporan-slides.html` — varian presentasi (slide deck) mandiri untuk paparan
  ringkas ke stakeholder; navigasi dengan panah kiri/kanan.
- `reports/evidence/` — screenshot bukti (mis. dari modul `clientleak` berbasis browser),
  disematkan di laporan & slide. Folder ini harus menyertai berkas laporan saat dibagikan.

Lihat contoh output pada [contoh-laporan.md](contoh-laporan.md) /
[contoh-laporan.html](contoh-laporan.html).

Bagian **Kontrol yang Lolos (PASS)** merinci pemeriksaan yang diuji dan berperilaku
benar — bukti cakupan uji, bukan temuan.

## 6. Rollback (modul destruktif)

Modul destruktif seperti `mass-assignment` menulis ke target, lalu memulihkan keadaan
semula secara otomatis sebagai tahap terakhir setelah laporan dibuat. Prosesnya:

1. Snapshot nilai asli objek.
2. Inject field terlarang (penulisan ke target).
3. Catat cara pemulihan ke `reports/rollback_journal.json` segera (crash-safe).
4. Verifikasi apakah field terlarang diterima (temuan bila ya).
5. Setelah laporan dibuat, `audit.py` memulihkan seluruh perubahan ke nilai semula.

Bila tahap pemulihan otomatis gagal (mis. koneksi putus), jalankan ulang:

```
python audit.py rollback
```

Log pemulihan tersimpan di `reports/rollback.json`.

## 7. Integrasi CI

- Static scan (`deps`) aman dijalankan pada setiap PR karena tidak memerlukan target hidup.
- Pengujian dinamis (DAST, access control, upload, dll.) memerlukan target hidup;
  jalankan terjadwal ke dev/staging, bukan ke production. Kredensial melalui GitHub
  Secrets.

## 8. Menerjemahkan temuan menjadi test

Untuk "mengunci" temuan dari sebuah laporan pentest agar tidak muncul kembali, lihat
[temuan-to-test-mapping.md](temuan-to-test-mapping.md): pemetaan kelas temuan ke modul
beserta cara menambahkan kasus ujinya.

## 9. Troubleshooting

| Gejala | Kemungkinan penyebab & solusi |
|---|---|
| `can't open file '...\audit.py'` | `audit.py` dijalankan dari luar folder kit. Pakai path lengkap (`python C:\GitHub\security-audit-kit\audit.py ...`), `audit.ps1`, atau pintasan `sak` (lihat "Menjalankan dari folder mana pun"). |
| `unrecognized arguments: --project` | Folder kit belum diperbarui; jalankan `git pull` di folder kit. |
| `<folder>\config\targets.yml belum ada (project: ...)` | Folder project belum disiapkan atau path salah: jalankan `python audit.py --project <nama\|folder> init`, atau salin config ke folder itu. |
| `config/targets.yml belum ada` | Salin dari `config/targets.example.yml`. |
| `<config> belum ada — salin dari contoh .example-nya` | Salin berkas `.example.yml` modul terkait. |
| Login Sanctum gagal 500 "Session store not set" | `auth.sanctum.origin` belum cocok dengan `SANCTUM_STATEFUL_DOMAINS` server. |
| Scanner gagal | Pastikan Docker berjalan dan image dapat diunduh. |
| Modul `clientleak` melewati cek browser | Playwright belum terpasang (opsional). |
| Banyak request login tertolak 429 | Rate limit login target; beri jeda antar-request. |
