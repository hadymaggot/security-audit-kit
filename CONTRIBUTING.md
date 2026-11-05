# Berkontribusi

Makasih sudah mau bantu. Toolkit ini dipakai ulang lintas project, jadi yang
diutamakan: check baru itu **generik** (di-config lewat file, bukan hardcode target),
**non-destruktif**, dan tiap temuan punya **remediasi yang bisa dipertanggungjawabkan**.

## Alur singkat

1. Fork / branch dari `main`. Satu branch = satu issue/topik.
2. Bikin perubahan + test-nya.
3. `python -m pytest -q tests/unit` harus hijau (ini juga gerbang CI).
4. Buka PR ke `main`, isi sesuai template. CI jalan otomatis.

## Prinsip check

- **Generik & config-driven.** Target, endpoint, dan kredensial masuk file `*.yml`
  (contohnya `*.example.yml`) atau environment variable — jangan ditanam di kode.
  Kredensial **selalu** lewat env var, jangan pernah di-commit.
- **Non-destruktif.** Default-nya cuma `GET`/pembacaan. Kalau sebuah check memang
  perlu aksi yang mengubah state, matikan secara default dan kasih peringatan jelas.
- **Timeout = skip, bukan temuan.** Kalau target nggak bisa dijangkau, tandai `ok`
  dengan note `skip:`; jangan dihitung sebagai celah.
- **Target milik sendiri / berizin.** Scan aktif arahkan ke dev/staging.

## Nambah check baru

Satu check = satu runner di `tests/<nama>/run_<nama>.py` + entri di `remediation.py`.

1. **Runner.** Baca config via `--config`, dukung `--json <out>`. Pola output per
   item: `{"label", "status", "ok": bool, "note"}`. Lihat `tests/cors/run_cors.py`
   sebagai contoh paling ringkas. Sertakan `<nama>.example.yml`.
2. **Remediasi (wajib).** Tambah entri `KB` di `remediation.py` dengan `deskripsi`,
   `dampak`, `severity`, `severity_dasar`, `rekomendasi` (list, boleh ada contoh
   solusi/kode), dan `referensi` (OWASP/BSSN). Petakan di `classify()`.
3. **report.py.** Daftarkan file JSON-nya di `collect()` biar ikut ke laporan gabungan.
4. **audit.py.** Daftarkan modulnya biar bisa `python audit.py <nama>`.
5. **Test.** Tambah unit test di `tests/unit/` — logika runner diuji tanpa jaringan
   (lihat `_Sess`/`_Resp` di `test_report.py`). `classify()` dan kelengkapan `KB`
   wajib ketutup test.
6. **Docs.** Update tabel modul di `README.md` dan `docs/temuan-to-test-mapping.md`.

## Commit & PR

- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`,
  `chore:`. Scope opsional, mis. `feat(cors): …`. `feat` → minor, `fix` → patch,
  `!`/`BREAKING CHANGE` → major (release & tag SemVer dibuat otomatis).
- Pesan singkat dan jelas: satu baris subjek, detail di body kalau perlu.
- Satu PR fokus satu hal. Cantumkan issue terkait (`Closes #N`).

## Contoh output

Lihat [docs/contoh-laporan.md](docs/contoh-laporan.md) buat gambaran bentuk laporan
akhir — ringkasan severity, rincian temuan + rekomendasi, dan daftar CVE.
