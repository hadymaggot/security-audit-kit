**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](runner.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](runner.de.md)

# Runner audit otonom

`runner.py` menjalankan seluruh alur audit dari awal sampai report tanpa campur tangan manual dan tanpa AI: menyalakan stack, login semua akun, membangkitkan config modul, menjalankan scan dan uji dinamis, lalu menyusun report. Semua yang bergantung pada project ada dalam satu berkas YAML, sehingga runner yang sama dapat dipakai untuk project existing maupun project baru.

## Prasyarat

- [ ] Python 3.10+ dan `pip install -r requirements.txt`.
- [ ] Docker untuk `zap`, `tls`, `deps`, dan target yang memakai stack container.
- [ ] Berkas config project (lihat [Menambah project baru](#menambah-project-baru)).
- [ ] Kredensial akun uji di berkas env atau seeder, bukan di config.

## Mulai cepat

```bash
python runner.py init --config projects/example-app/audit.config.yml
python runner.py check --config projects/example-app/audit.config.yml
python runner.py run --config projects/example-app/audit.config.yml --target local
python runner.py run --config projects/example-app/audit.config.yml --target dev --skip ratelimit
python runner.py down --config projects/example-app/audit.config.yml
```

Hasil: folder report bernama unik di `project.output`, lengkap dengan HTML, Markdown, slide, bukti per modul, dan ringkasan eksekusi. Kode keluar 2 berarti ada galat yang menghentikan run; temuan keamanan tidak mengubah kode keluar, karena hasilnya ada di report.

## Alur yang dijalankan

1. Memeriksa prasyarat dan memuat config.
2. Target `stack`: menyalakan stack lewat langkah `stack.up`. Langkah bersifat idempotent, layanan yang sudah sehat dibiarkan.
3. Login semua akun dengan pacing terhadap rate limit login, lalu membaca permission aktual tiap akun.
4. Membangkitkan config modul dan matriks akses dari permission tersebut.
5. Menjalankan modul sesuai `pipeline`. Satu modul yang gagal tidak menghentikan modul lain.
6. Menyusun report, memindai kebocoran rahasia, lalu menyalin hasil ke folder keluaran.
7. Opsional `--down-after`: mematikan stack.

## Konfigurasi

Contoh lengkap dengan komentar ada di [config/runner.example.yml](../config/runner.example.yml).

Simpan config di `projects/<nama>/audit.config.yml` pada toolkit, folder yang tidak di-commit seperti project toolkit lainnya, lalu isi `project.repo` dengan lokasi repo aplikasi. Repo itu menjadi tujuan salinan report dan acuan path langkah `stack`.

| Bagian | Isi |
|---|---|
| `project` | Nama, kunci singkat untuk nama berkas, dan folder keluaran |
| `api` | Endpoint login, profil, refresh, logout, ganti password, dan lokasi OpenAPI |
| `accounts` | Sumber akun per jenis target, role rendah dan kuat |
| `stack` | Langkah menyalakan dan mematikan stack, plus akses database |
| `targets` | Daftar target dengan `kind` `stack` atau `remote` |
| `pipeline` | Urutan modul |
| `modules` | Pengaturan tiap modul, `targets` yang menjalankannya, dan `by_target` |

```yaml
modules:
  injection:
    targets: [local, dev]
    time_based: false
    by_target: { local: { time_based: true } }
```

## Target dan tingkat keamanan

- **`stack`:** runner menyalakan stack lalu menguji. Akun dibaca dari database lewat kueri pada `accounts.stack`.
- **`remote`:** menguji host yang sudah ada. URL, tingkat, dan akun dibaca dari berkas env target: `APP_USER_<ROLE>` dan `APP_PASS_<ROLE>`.
- **Tingkat `prod`:** hanya modul pasif yang berjalan (`safety.passive_modules`). Gunakan `--force-active` hanya bila Anda pemilik sistem dan memiliki izin tertulis.
- **Modul yang menulis data:** `upload`, `mass-assignment`, `ssrf`, `session`, `auth-policy`, dan `zap` hanya dijalankan pada target yang Anda aktifkan sendiri di config, dan umumnya hanya pada `stack`.

## Nama dan lokasi report

Setiap run membuat folder dan berkas baru dengan pola `security-audit-kit_<project>_<target>_<YYYYMMDD-HHMMSS>`, sehingga menjalankan ulang untuk perbaikan tidak menimpa report sebelumnya. Isinya:

- `<nama>.html`, `<nama>.md`, dan `<nama>-slides.html`: report lengkap dan slide.
- `<nama>-ringkasan.md`: modul yang dijalankan, dilewati, atau galat, beserta versi toolkit.
- Folder `data/` berisi hasil mentah tiap modul (JSON dan keluaran ZAP) beserta `README.md` statis yang menjelaskan isinya. Folder bukti, bila ada tangkapan layar, tetap di level atas karena dirujuk oleh report.

`RIWAYAT.md` di folder induk memuat satu baris per run agar mudah dibandingkan. Sebelum disalin, seluruh report dipindai terhadap kata sandi, token, dan kunci yang dikenal; bila ada yang bocor, hanya folder run itu yang dihapus.

## Rate limit dan kuota login

Login ke aplikasi yang membatasi percobaan dapat gagal dengan HTTP 429. Runner membaca `Retry-After` dan menunggu, dan `authz` mengulang request yang kena 429 alih-alih menandainya sebagai temuan. Untuk target dengan puluhan akun, run bisa memakan waktu karena menunggu jendela rate limit. Gunakan `--roles-limit` bila hanya butuh sebagian akun.

## Menambah project baru

1. Jalankan `init` untuk membuat kerangka config dari contoh.
2. Isi `api`, `accounts`, `targets`, dan modul yang relevan. Mulailah dari modul pasif dan tambahkan sisanya bertahap.
3. Jalankan `check` sampai tidak ada masalah.
4. Jalankan `run` pada target yang aman, lalu periksa ringkasan eksekusi.

Target baru, seperti staging, cukup ditambahkan di `targets` dengan berkas env sendiri.

## Batasan

- Hasil scanner tetap perlu diverifikasi; celah logika bisnis hanya terdeteksi jika kasusnya ditulis di config.
- `session` memeriksa autentikasi bearer dengan refresh token, dan butuh akun berhak tinggi untuk membuat akun uji sekali pakai.
- `tls` hanya untuk target HTTPS, dan `deps` memindai kode sehingga umumnya dijalankan pada target `stack`.
- Runner membuat project kerja di `work/kit/` di samping config, sehingga `projects/` tetap berisi satu folder per project.
