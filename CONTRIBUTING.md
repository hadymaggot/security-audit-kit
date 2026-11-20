**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](CONTRIBUTING.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](CONTRIBUTING.de.md)

# Berkontribusi

Terima kasih sudah mau membantu. Toolkit ini digunakan ulang lintas project, jadi yang
diutamakan: check baru itu **generik** (di-config lewat file, bukan hardcode target),
**non-destruktif**, dan tiap temuan memiliki **remediasi yang dapat dipertanggungjawabkan**.

## Alur singkat

1. Fork / branch dari `main`. Satu branch = satu issue/topik.
2. Buat perubahan + test-nya.
3. `python -m pytest -q tests/unit` harus hijau (ini juga gerbang CI).
4. Buka PR ke `main`, isi sesuai template. CI berjalan otomatis.

## Prinsip check

- **Generik & config-driven.** Target, endpoint, dan kredensial masuk file `*.yml`
  (contohnya `*.example.yml`) atau environment variable — jangan ditanam di kode.
  Kredensial **selalu** lewat env var, jangan pernah di-commit.
- **Non-destruktif.** Default-nya hanya `GET`/pembacaan. Apabila sebuah check memang
  perlu aksi yang mengubah state, matikan secara default dan beri peringatan jelas.
- **Timeout = skip, bukan temuan.** Apabila target tidak dapat dijangkau, tandai `ok`
  dengan note `skip:`; jangan dihitung sebagai celah.
- **Target milik sendiri / berizin.** Scan aktif arahkan ke dev/staging.

## Menambahkan check baru

Satu check = satu runner di `tests/<nama>/run_<nama>.py` + entri di `remediation.py`.

1. **Runner.** Baca config via `--config`, dukung `--json <out>`. Pola output per
   item: `{"label", "status", "ok": bool, "note"}`. Lihat `tests/cors/run_cors.py`
   sebagai contoh paling ringkas. Sertakan `<nama>.example.yml`.
2. **Remediasi (wajib).** Tambahkan entri `KB` di `remediation.py` dengan `description`,
   `impact`, `severity`, `severity_basis`, `recommendation` (list, boleh ada contoh
   solusi/kode), dan `references` (OWASP/BSSN). Petakan di `classify()`.
3. **report.py.** Daftarkan file JSON-nya di `collect()` agar ikut ke laporan gabungan.
4. **audit.py.** Daftarkan modulnya agar dapat `python audit.py <nama>`.
5. **Test.** Tambahkan unit test di `tests/unit/` — logika runner diuji tanpa jaringan
   (lihat `_Sess`/`_Resp` di `test_report.py`). `classify()` dan kelengkapan `KB`
   wajib tercakup test.
6. **Docs.** Perbarui tabel modul di `README.md` dan `docs/temuan-to-test-mapping.md`.

## Bahasa dan glosarium

- **Komentar dan docstring di kode: Bahasa Inggris**, singkat, padat, dan jelas (jelaskan
  *mengapa*, bukan mengulang kode). Nama variabel, fungsi, dan kunci skema juga Bahasa Inggris.
- **Teks yang tampil** (konsol, laporan, rekomendasi) mengikuti [glosarium](docs/glosarium.md):
  kalimat dalam bahasa dokumen, istilah teknis tetap Inggris dan dicetak miring di laporan.
- Menambah istilah cukup satu baris di `glosarium.yml`; `tests/unit/test_glosarium.py` gagal bila
  ada teks tampil yang masih memakai kata yang sudah dibakukan.

## Situs web (GitHub Pages)

Situs di `docs/` dibangun, jangan disunting langsung. Sumbernya ada di `site/`: templat
(`*.template.html`), kamus bahasa (`site/i18n/id|en|de.json`), dan glosarium situs yang terpisah
dari glosarium kit (`site/glosarium.yml`).

1. Ubah templat atau kamus. Tambahkan kunci yang sama di ketiga bahasa.
2. Bangun: `python scripts/build_site.py` (hasil ke `docs/`, `docs/id/`, `docs/de/`, `sitemap.xml`).
3. Jalankan `python -m pytest tests/unit/test_site.py`; test gagal bila hasil build basi atau kamus tidak lengkap.

## Commit & PR

- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`,
  `chore:`. Scope opsional, mis. `feat(cors): …`. `feat` → minor, `fix` → patch,
  `!`/`BREAKING CHANGE` → major (release & tag SemVer dibuat otomatis).
- Pesan singkat dan jelas: satu baris subjek, detail di body apabila perlu.
- Satu PR fokus satu hal. Cantumkan issue terkait (`Closes #N`).

## Contoh output

Lihat [docs/contoh-laporan.md](docs/contoh-laporan.md) untuk gambaran bentuk laporan
akhir — ringkasan severity, rincian temuan + rekomendasi, dan daftar CVE.
