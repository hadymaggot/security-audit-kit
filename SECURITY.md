**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](SECURITY.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](SECURITY.de.md)

# Kebijakan Keamanan

Terima kasih sudah membantu menjaga keamanan **Security Audit Kit**.

## Versi yang didukung

Perbaikan keamanan diterapkan pada rilis terbaru dan cabang `main`.

| Versi | Didukung |
|---|---|
| Rilis stabil terbaru | ✅ |
| `main` | ✅ |
| Versi lebih lama | ❌ |

## Melaporkan kerentanan

**Jangan** membuka issue publik untuk kerentanan keamanan.

Gunakan **GitHub Private Vulnerability Reporting**:

1. Buka tab **Security** repo ini.
2. Klik **Report a vulnerability**.
3. Isi detail: langkah reproduksi, dampak, versi/commit yang terpengaruh, dan bukti bila ada.

Laporan bersifat privat antara Anda dan maintainer sampai perbaikan tersedia.

### Yang bisa diharapkan

- **Konfirmasi penerimaan:** biasanya dalam 3 hari kerja.
- **Penilaian awal & triase:** dalam 7 hari kerja.
- **Perbaikan & disclosure:** dikoordinasikan bersama pelapor; kredit diberikan bila diinginkan.

## Cakupan

Toolkit ini **menguji keamanan sistem lain**. Laporan yang dimaksud di sini adalah
kerentanan **pada kit itu sendiri** (mis. eksekusi kode tak diinginkan saat parsing
output, kebocoran kredensial dari config/laporan, atau cacat yang membuat kit
menyerang target yang tak diminta).

## Penggunaan yang bertanggung jawab

Kit ini hanya untuk menguji sistem yang **Anda miliki atau berwenang uji**. Pengujian
tanpa izin terhadap sistem pihak lain melanggar hukum di banyak yurisdiksi dan di luar
tujuan proyek ini. Kredensial target selalu lewat environment variable, bukan di berkas
yang di-commit.
