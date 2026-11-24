# Glosarium dan bahasa

Kit memiliki satu glosarium per bahasa, [`glosarium.yml`](../glosarium.yml), agar istilah teknis konsisten di konsol, laporan, dan dokumentasi.

## Aturan penulisan

- Kalimat memakai bahasa dokumen (Indonesia baku); **istilah teknis tetap dalam bentuk aslinya** (Inggris), misalnya *response*, *request*, *password*, *session*, *file*, *header*, *endpoint*.
- Istilah teknis dicetak miring pada laporan HTML, Markdown, dan slide. Nama produk/alat (OWASP ZAP, Docker, Trivy) dan singkatan (CVE, XSS, RCE) tidak dimiringkan; isi kode, URL, dan nama header/path tetap polos.
- Satu konsep, satu istilah. `respons`, `sandi`, `sesi`, `galat`, dan `berkas` selalu ditulis *response*, *password*, *session*, *error*, dan *file*; kelompok "bocor" dibakukan menjadi *information disclosure*, *exposed*, atau *expose*.
- Komentar dan docstring di kode ditulis dalam Bahasa Inggris, singkat dan jelas.

## Memilih bahasa

Urutan prioritas: opsi `--lang id|en|de`, environment variable `SAK_LANG`, `report.language` pada `targets.yml` project, lalu bawaan glosarium (`id`).

```
python audit.py --project my-app --lang de report
```

Glosarium tersedia untuk `id`, `en`, dan `de`. Katalog teks laporan lengkap untuk `id`, `en`, dan `de`. Teks sumbernya bahasa Indonesia di kode; terjemahannya ada di `locales/text.<bahasa>.yml` (teks laporan) dan `locales/kb.<bahasa>.yml` (deskripsi, dampak, dan rekomendasi tiap jenis temuan), dengan cara kerja seperti gettext atau Transifex. Bukti per instance yang dihasilkan modul uji dan pesan konsol tetap berbahasa Indonesia. Bahasa yang katalognya lengkap didaftarkan di `complete_text` pada `glosarium.yml`.

## Isi `glosarium.yml`

| Kunci | Fungsi |
|---|---|
| `default` | Bahasa bawaan (`id`). |
| `complete_text` | Bahasa yang katalog teks laporan/konsolnya sudah lengkap. |
| `languages.<kode>.italic` | `false` bila teksnya sudah berbahasa Inggris sehingga tidak ada yang dimiringkan (bawaan `true`). |
| `languages.<kode>.terms` | Istilah yang dicetak miring; tidak membedakan huruf besar/kecil, bentuk jamak dan frasa beberapa kata ikut dikenali. |
| `languages.<kode>.map` | Kata lokal menjadi istilah baku; dipakai oleh test penjaga. |
| `languages.<kode>.phrases` | Pasangan `[regex, pengganti]` berurutan untuk kata yang artinya bergantung konteks. |

## Menambah istilah, bahasa, atau glosarium project

Menambah istilah:

1. Tambahkan satu baris pada `terms` bahasa yang sesuai.
2. Jika kata lokal harus diganti dengan istilah itu, tambahkan pasangan `kata: istilah` pada `map`.
3. Jalankan `python -m pytest tests/unit/test_glosarium.py`. Test gagal bila teks yang tampil (konsol, laporan, rekomendasi) masih memakai kata yang dipetakan `map` atau `phrases`.

Kasus lain:

- **Bahasa baru:** tambahkan satu blok di bawah `languages` (kode ISO 639-1).
- **Khusus satu project:** buat `<folder-project>/config/glosarium.yml` dengan struktur yang sama; isinya digabung dengan glosarium kit.
- **Situs web:** memiliki glosarium tersendiri di `site/glosarium.yml` (struktur sama, tidak digabung dengan glosarium kit); lihat bagian situs web di [panduan kontribusi](../CONTRIBUTING.md).

## Peta jalan bahasa

1. Glosarium per bahasa, pembakuan istilah, dan pencetakan miring (selesai).
2. Katalog teks laporan bahasa Inggris dan Jerman (selesai). Periksa dengan `python scripts/catalog_status.py`, yang melaporkan teks yang belum diterjemahkan, sudah usang, atau placeholder-nya berbeda.
3. Terjemahan bukti per instance dari modul uji dan pesan konsol.
