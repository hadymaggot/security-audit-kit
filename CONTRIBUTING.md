**<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia** · [<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English](CONTRIBUTING.en.md) · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](CONTRIBUTING.de.md)

# Berkontribusi

Toolkit ini digunakan ulang lintas project. Check baru harus **generik** (dikonfigurasi lewat *file*, bukan hardcode target), **non-destruktif**, dan disertai **remediasi yang dapat dipertanggungjawabkan**.

## Menyiapkan dalam 3 menit

Prasyarat: Python 3.10+ (CI memakai 3.12) dan git. Docker hanya diperlukan untuk menjalankan scanner (ZAP, Trivy, dan sebagainya), bukan untuk unit test.

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -q
```

Hasil yang diharapkan: semua test lulus dalam kurang lebih satu menit, tanpa target hidup. Setelah itu buat branch dari `main`, satu branch per topik.

## Struktur proyek

| Path | Isi |
|---|---|
| `audit.py` | Entry point CLI; registri modul `PY_MODULES` |
| `tests/<folder>/` | Satu check: runner `run_<x>.py` + config `<x>.example.yml` (contoh: `tests/cors/`) |
| `tests/_*.py` | Helper bersama (warna, fixture, *rollback*, snapshot, *login* Sanctum, screenshot) |
| `tests/unit/` | Unit test; ini gerbang CI |
| `config/targets.example.yml` | Contoh config target; salin ke `config/targets.yml` yang diabaikan git |
| `scanners/` | Wrapper ZAP, testssl, *header*, trivy/semgrep/gitleaks |
| `remediation.py` | Knowledge base remediasi `KB` dan `classify()` |
| `report.py` | `collect()` dan laporan HTML/Markdown/slide |
| `glossary.py`, `glosarium.yml` | Pemuat glosarium dan data glosarium per bahasa |
| `site/`, `scripts/` | Sumber situs web; `build_site.py`, `italicize_docs.py` |
| `docs/` | Dokumen Markdown (ditulis manual) dan situs web hasil build |
| `worker/` | Cloudflare Worker untuk demo open scanner pasif |
| `.github/workflows/` | `ci.yml`, `release.yml`, `security-audit.yml` |

Bentuk laporan akhir: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Menambahkan check baru

Aturan yang berlaku untuk setiap check:

- **Berbasis config.** Target dan *endpoint* masuk ke `*.yml`; kredensial hanya lewat environment variable, tidak pernah di-commit.
- **Read-only secara default.** Hanya `GET`/pembacaan. Aksi yang mengubah state dimatikan secara default, disertai peringatan jelas, dan penulisannya dicatat lewat `tests/_rollback.py`.
- **Timeout = skip, bukan temuan.** Tandai `ok` dengan note `skip:`.
- **Hanya target berizin.** Arahkan scan aktif ke dev/staging.

Checklist (`<x>` = bagian nama *file*, `<folder>` = folder di `tests/`, `<kind>` = kunci KB):

1. **Runner.** Buat `tests/<folder>/run_<x>.py` dan `tests/<folder>/<x>.example.yml`. Runner menerima `--config` dan `--json <out>`, mencetak tabel, dan keluar dengan kode 1 bila ada temuan. Setiap hasil berbentuk `{"label", "status", "ok": bool, "note"}`; berkas JSON-nya `{"module", "failures", "results"}`.
2. **audit.py.** Tambahkan satu entri ke `PY_MODULES`. Dengan itu `python audit.py <nama>`, `init`, dan `all` (menjalankan modul bila config-nya ada di project) berfungsi. Jika check menulis ke target, tambahkan juga `<nama>` ke `ROLLBACK_AFTER`.
3. **report.py.** Tambahkan `("<x>.json", "<folder>")` ke tuple di `collect()`.
4. **remediation.py, KB (wajib).** Tambahkan `KB["<kind>"]` dengan tepat kunci berikut.
5. **remediation.py, classify.** Petakan hasil ke `<kind>` di `classify(module, title)`. Alternatif: isi `kind` pada tiap hasil dan daftarkan modul di cabang kind-hint pada `collect()`. Hasil yang tidak terpetakan jatuh ke `zap-generic`.
6. **Test.** Tambahkan `tests/unit/test_<x>.py` untuk logika runner tanpa jaringan (*session* palsu, lihat `_Sess`/`_Resp` di `tests/unit/test_authz_matrix.py`), asersi `classify()`, dan kasus `collect()` di `tests/unit/test_report.py`. `test_all_kb_entries_wellformed` sudah memeriksa setiap entri KB.
7. **Docs.** Tambahkan baris pada tabel modul di `README.md`/`.en.md`/`.de.md`, di `docs/temuan-to-test-mapping*.md`, dan pada daftar tahapan `docs/metodologi*.md` (ketiga bahasa). Shortcut di `Makefile` atau `audit.ps1` bersifat opsional.

```python
"<name>": ("<folder>", "run_<x>.py", "<x>.yml", "<x>.json"),
```

```python
"<kind>": {
    "description": "...",
    "impact": "...",
    "severity": "Medium",
    "severity_basis": "...",
    "recommendation": ["...", "..."],
    "references": ["..."],
},
```

Aturan KB: `severity` salah satu dari Critical, High, Medium, Low, Info; `severity_basis` menyebut *Likelihood* x *Impact*; `recommendation` berupa list tidak kosong yang boleh memuat contoh solusi; `references` berupa list tidak kosong (OWASP, BSSN).

## Aturan bahasa dan glosarium

1. Komentar dan docstring di kode berbahasa Inggris, singkat, dan menjelaskan alasan.
2. Identifier dan kunci skema (config, JSON, KB) berbahasa Inggris. `tests/unit/test_english_code.py` menjaganya.
3. Teks yang tampil (konsol, laporan, rekomendasi) mengikuti [glosarium](docs/glosarium.md): kalimat dalam bahasa dokumen, istilah teknis tetap Inggris. Saat ini katalog teks hanya tersedia dalam Bahasa Indonesia.
4. Menambah istilah cukup satu baris di `glosarium.yml`. `tests/unit/test_glosarium.py` gagal bila teks yang tampil masih memakai kata yang sudah dibakukan glosarium.
5. Dokumen: `tests/unit/test_docs.py` mewajibkan jumlah bagian `##` dan perintah yang sama di ketiga bahasa, serta tautan yang valid. Setelah menyunting dokumen berbahasa Indonesia, jalankan:

```bash
python scripts/italicize_docs.py
```

## Situs web

`docs/index.html`, `docs/scan.html`, `docs/id/`, `docs/de/`, dan `docs/sitemap.xml` dihasilkan otomatis; jangan disunting langsung. Sumbernya ada di `site/`: templat (`*.template.html`), kamus bahasa (`site/i18n/id|en|de.json`), dan glosarium situs (`site/glosarium.yml`) yang terpisah dari glosarium kit.

1. Ubah templat atau kamus. Tambahkan kunci yang sama di ketiga bahasa.
2. Bangun situs.
3. Jalankan test situs; test gagal bila hasil build basi atau kamus tidak lengkap.

```bash
python scripts/build_site.py
python -m pytest tests/unit/test_site.py -q
```

## Commit dan PR

1. Gunakan Conventional Commits: `tipe(lingkup): deskripsi`, dengan tipe `feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`. `feat` menaikkan minor, `fix` patch, `!` atau `BREAKING CHANGE` major.
2. Subjek singkat; body hanya untuk menjelaskan alasan. Satu PR satu maksud; cantumkan issue dengan `Closes #N`.
3. Isi checklist pada template PR.
4. CI (`ci.yml`) berjalan pada setiap PR dan push ke `main`: `py_compile` untuk `audit.py`, `report.py`, `remediation.py`, dan semua runner, lalu `pytest -q tests/unit`. `security-audit.yml` juga menjalankan static scan (`deps`) pada PR; hasilnya hanya informatif.
5. Release dan tag SemVer dibuat otomatis setiap bulan bila `main` memiliki commit baru (`release.yml`).
