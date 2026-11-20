# Glosarium dan bahasa

Kit memakai satu glosarium per bahasa, [`glosarium.yml`](../glosarium.yml), agar istilah teknis
konsisten di konsol, laporan, dan dokumentasi.

## Aturan penulisan

- Kalimat memakai bahasa dokumen (Indonesia baku); **istilah teknis tetap dalam bentuk aslinya**
  (Inggris), misalnya *response*, *request*, *password*, *session*, *file*, *header*, *endpoint*.
- Istilah teknis dicetak **miring** pada laporan HTML, Markdown, dan slide. Nama produk/alat
  (OWASP ZAP, Docker, Trivy) dan singkatan (CVE, XSS, RCE) tidak dimiringkan; isi kode, URL, dan
  nama *header*/*path* tetap polos.
- Satu konsep, satu istilah. Contoh baku: `respons` ditulis *response*, `sandi` ditulis
  *password*, `sesi` ditulis *session*, `galat` ditulis *error*, `berkas` ditulis *file*, dan
  kelompok "bocor" dibakukan menjadi *information disclosure*, *exposed*, atau *expose*.
- Komentar dan docstring di kode ditulis dalam Bahasa Inggris, singkat dan jelas.

## Memilih bahasa

Urutan prioritas: opsi `--lang id|en|de`, env `SAK_LANG`, `report.language` pada `targets.yml`
project, lalu bawaan glosarium (`en`).

```
python audit.py --project my-app --lang de report
```

Glosarium sudah tersedia untuk `id`, `en`, dan `de` (mengikuti bahasa dokumentasi). Katalog teks
laporan dan konsol saat ini lengkap untuk `id`; bahasa lain sementara memakai teks `id` sambil
tetap memakai glosarium bahasa yang dipilih. Setelah katalog suatu bahasa selesai, tambahkan
kodenya ke `complete_text` di `glosarium.yml`.

## Isi `glosarium.yml`

| Kunci | Fungsi |
|---|---|
| `default` | Bahasa bawaan (`en`). |
| `complete_text` | Bahasa yang katalog teks laporan/konsolnya sudah lengkap. |
| `languages.<kode>.italic` | `false` bila teksnya sudah berbahasa Inggris sehingga tidak ada yang dimiringkan (bawaan `true`). |
| `languages.<kode>.terms` | Istilah yang dicetak miring; tidak membedakan huruf besar/kecil, bentuk jamak dan frasa beberapa kata ikut dikenali. |
| `languages.<kode>.map` | Kata lokal menjadi istilah baku; dipakai oleh test penjaga. |
| `languages.<kode>.phrases` | Pasangan `[regex, pengganti]` berurutan untuk kata yang artinya bergantung konteks. |

## Menambah istilah, bahasa, atau glosarium project

- **Istilah baru:** tambahkan satu baris pada `terms` bahasa yang sesuai.
- **Kata yang harus dibakukan:** tambahkan pasangan `kata: istilah` pada `map`.
- **Bahasa baru:** tambahkan satu blok di bawah `languages` (kode ISO 639-1).
- **Khusus satu project:** buat `<folder-project>/config/glosarium.yml` dengan struktur yang sama;
  isinya digabung dengan glosarium kit.
- **Situs web:** punya glosarium tersendiri di `site/glosarium.yml` (strukturnya sama, tidak digabung
  dengan glosarium kit); lihat bagian situs web di panduan kontribusi.

Setelah mengubah, jalankan `python -m pytest tests/unit/test_glosarium.py`. Test itu gagal bila
teks yang tampil (konsol, laporan, rekomendasi) masih memakai kata yang dipetakan `map` atau
`phrases`, sehingga tidak ada yang terlewat.

## Peta jalan bahasa

1. Glosarium per bahasa, pembakuan istilah, dan pencetakan miring (selesai).
2. Katalog teks laporan dan konsol bahasa Inggris, lalu `en` ditambahkan ke `complete_text`.
3. Katalog bahasa Jerman.
