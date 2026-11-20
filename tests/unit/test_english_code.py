"""Guard: identifiers and schema keys in the kit code must be English."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Indonesian words that must not appear as a whole word inside an identifier or a schema key.
DENY = set("""nama deskripsi dampak rekomendasi referensi keyakinan hasil jumlah berkas sandi peran kasus konten harus
ditolak diterima judul tingkat temuan bukti lolos gagal uji akun sesi kunci nilai daftar catatan batas waktu
percobaan kebijakan pesan galat respons permintaan keluaran masukan tulis baca hapus ubah jalankan salin buat
ambil kirim terdeteksi terkunci dipulihkan lemah kuat benar salah lama baru berhasil selesai kosong bocor
jawaban posisi tantangan terlarang dilarang wajib bawaan contoh lulus modul moduls prioritas ringkas skor
teknik tindak padankan batasan klasifikasi metodologi""".split())
WORD = re.compile(r"[A-Za-z][a-z]*|[A-Z]+(?![a-z])")


def _words(name):
    return {w.lower() for part in name.split("_") for w in WORD.findall(part)}


def _code_files():
    files = [ROOT / "audit.py", ROOT / "report.py", ROOT / "remediation.py", ROOT / "glossary.py"]
    files += sorted((ROOT / "tests").glob("*/run_*.py")) + sorted((ROOT / "tests").glob("_*.py"))
    files += sorted((ROOT / "tests" / "unit").glob("*.py"))
    return files


def test_identifiers_are_english():
    bad = []
    for f in _code_files():
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            names = []
            if isinstance(n, (ast.ClassDef,)):
                names.append(n.name)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not (f.parent.name == "unit" and n.name.startswith("test_")):    # test names: checked separately
                    names.append(n.name)
                names += [a.arg for a in n.args.args + n.args.kwonlyargs]
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.append(n.id)
            elif isinstance(n, ast.keyword) and n.arg:
                names.append(n.arg)
            for nm in names:
                if _words(nm) & DENY:
                    bad.append(f"{f.relative_to(ROOT).as_posix()}:{getattr(n, 'lineno', '?')}: {nm}")
    assert not bad, "Indonesian identifier(s); use English names:\n" + "\n".join(bad)


def test_schema_keys_are_english():
    bad = []
    for f in _code_files():
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            keys = []
            if isinstance(n, ast.Dict):
                keys = [k for k in n.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                keys = [n.slice]
            for k in keys:
                if " " not in k.value and _words(k.value) & DENY:
                    bad.append(f"{f.relative_to(ROOT).as_posix()}:{k.lineno}: {k.value!r}")
    assert not bad, "Indonesian schema key(s); use English keys:\n" + "\n".join(bad)


def test_yaml_example_keys_are_english():
    import yaml

    bad = []

    def walk(o, rel):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and " " not in k and _words(k) & DENY:
                    bad.append(f"{rel}: {k}")
                walk(v, rel)
        elif isinstance(o, list):
            for x in o:
                walk(x, rel)

    skip = {"glosarium.yml"}      # its `map` keys are the Indonesian words being standardized
    for p in sorted(ROOT.glob("config/*.example.yml")) + sorted(ROOT.glob("tests/*/*.example.yml")):
        if p.name not in skip:
            walk(yaml.safe_load(p.read_text(encoding="utf-8")), p.name)
    assert not bad, "Indonesian config key(s); use English keys:\n" + "\n".join(bad)
