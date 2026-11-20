"""Unit test multi-project (--project / SAK_PROJECT_DIR), init, kunci berkas, dan metadata
penyusun laporan — tanpa jaringan/Docker."""
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AU = _load("audit_proj_t", "audit.py")
RP = _load("report_proj_t", "report.py")


@pytest.fixture(autouse=True)
def _restore_project(monkeypatch):
    for k in ("SAK_PROJECT_DIR", "SAK_CALLER_CWD", "SAK_REPORT_AUTHOR", "SAK_REPORT_ORG",
              "SAK_REPORT_CONTACT"):
        monkeypatch.delenv(k, raising=False)
    yield
    AU.PROJECT = AU.ROOT
    os.environ.pop("SAK_PROJECT_DIR", None)


# ── penentuan folder project ────────────────────────────────────────────────
def test_resolve_kosong_folder_kit():
    assert AU.resolve_project(None) == AU.ROOT
    assert AU.resolve_project("  ") == AU.ROOT


def test_resolve_nama_ke_projects():
    assert AU.resolve_project("apple-gatrik") == (AU.ROOT / "projects" / "apple-gatrik").resolve()


def test_resolve_path_absolut_dan_relatif(tmp_path, monkeypatch):
    assert AU.resolve_project(str(tmp_path / "x")) == (tmp_path / "x").resolve()
    monkeypatch.setenv("SAK_CALLER_CWD", str(tmp_path))       # wrapper ps1 pindah ke folder kit
    assert AU.resolve_project("./proj-a") == (tmp_path / "proj-a").resolve()
    assert AU.resolve_project("sub/proj-b") == (tmp_path / "sub" / "proj-b").resolve()


def test_pop_project_arg_posisi_mana_pun():
    assert AU.pop_project_arg(["--project", "a", "all"]) == ("a", ["all"])
    assert AU.pop_project_arg(["zap", "full", "--project=b"]) == ("b", ["zap", "full"])
    assert AU.pop_project_arg(["recon", "x.com", "--project", "c", "-m", "y"]) == \
        ("c", ["recon", "x.com", "-m", "y"])
    assert AU.pop_project_arg(["headers"]) == (None, ["headers"])


def test_set_project_mengarahkan_config_dan_reports(tmp_path):
    AU.set_project(tmp_path)
    assert os.environ["SAK_PROJECT_DIR"] == str(tmp_path)
    assert AU.project_cfg("config", "targets.yml") == tmp_path / "config" / "targets.yml"
    assert AU.reports_dir() == tmp_path / "reports" and (tmp_path / "reports").is_dir()
    script, cfg, jn = AU.py_module_paths("authz")
    assert script == AU.ROOT / "tests" / "authz-matrix" / "run_authz_matrix.py"   # kode tetap di kit
    assert cfg == tmp_path / "tests" / "authz-matrix" / "authz_matrix.yml"        # config di project
    assert jn == "authz.json"


def test_mod_py_menulis_json_ke_reports_project(tmp_path, monkeypatch):
    AU.set_project(tmp_path)
    cfg = tmp_path / "c.yml"
    cfg.write_text("x: 1", encoding="utf-8")
    calls = []
    monkeypatch.setattr(AU, "run", lambda cmd: calls.append(cmd) or 0)
    AU.mod_py(Path("r.py"), cfg, "authz.json")
    assert calls[0][-1] == str(tmp_path / "reports" / "authz.json")


def test_mod_report_meneruskan_dir_project(tmp_path, monkeypatch):
    AU.set_project(tmp_path)
    calls = []
    monkeypatch.setattr(AU, "run", lambda cmd: calls.append(cmd) or 0)
    AU.mod_report()
    assert calls[0][-2:] == ["--dir", str(tmp_path / "reports")]


# ── init & clean ─────────────────────────────────────────────────────────────
def test_init_membuat_struktur_tanpa_menimpa(tmp_path, capsys):
    AU.set_project(tmp_path / "proj")
    assert AU.mod_init("authz,upload") == 0
    t = tmp_path / "proj" / "config" / "targets.yml"
    assert t.read_text(encoding="utf-8") == (AU.ROOT / "config" / "targets.example.yml").read_text(encoding="utf-8")
    assert (tmp_path / "proj" / "tests" / "authz-matrix" / "authz_matrix.yml").exists()
    assert (tmp_path / "proj" / "tests" / "upload-safety" / "upload_safety.yml").exists()
    assert (tmp_path / "proj" / "reports").is_dir()
    t.write_text("name: milik-saya\n", encoding="utf-8")
    assert AU.mod_init("authz") == 0
    assert t.read_text(encoding="utf-8") == "name: milik-saya\n"           # tidak ditimpa


def test_init_menolak_modul_tak_dikenal_dan_folder_kit(tmp_path):
    AU.set_project(tmp_path)
    assert AU.mod_init("authz,tidak-ada") == 2
    AU.PROJECT = AU.ROOT
    assert AU.mod_init("") == 2                                  # init tanpa --project ditolak


def test_clean_hanya_berkas_reports_project(tmp_path):
    AU.set_project(tmp_path)
    r = AU.reports_dir()
    (r / "a.json").write_text("{}")
    (r / ".gitkeep").write_text("")
    (r / "evidence").mkdir()
    AU.mod_clean()
    assert sorted(p.name for p in r.iterdir()) == [".gitkeep", "evidence"]


def test_dua_project_tidak_saling_menimpa(tmp_path):
    """Inti paralel: laporan dua project berada di folder masing-masing."""
    a, b = tmp_path / "a", tmp_path / "b"
    AU.set_project(a)
    (AU.reports_dir() / "authz.json").write_text('{"p": "a"}')
    AU.set_project(b)
    (AU.reports_dir() / "authz.json").write_text('{"p": "b"}')
    assert json.loads((a / "reports" / "authz.json").read_text())["p"] == "a"
    assert json.loads((b / "reports" / "authz.json").read_text())["p"] == "b"


# ── kunci berkas (antrean trivy) ─────────────────────────────────────────────
def test_file_lock_mengantrekan_proses_lain(tmp_path):
    lock = tmp_path / "x.lock"
    code = ("import sys,time,importlib.util as u;"
            f"s=u.spec_from_file_location('a',r'{ROOT / 'audit.py'}');m=u.module_from_spec(s);s.loader.exec_module(m);"
            f"l=m.file_lock(r'{lock}','uji',poll=0.1);l.__enter__();print('ok',flush=True);time.sleep(1.5);l.__exit__()")
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ok"                 # proses lain memegang kunci
    t0 = time.monotonic()
    with AU.file_lock(lock, "uji", poll=0.1):
        waited = time.monotonic() - t0
    p.wait(timeout=10)
    assert waited >= 0.8                                       # harus menunggu sampai dilepas


def test_file_lock_bisa_dipakai_ulang(tmp_path):
    for _ in range(2):
        with AU.file_lock(tmp_path / "y.lock"):
            pass


def test_trivy_cache_dir_default_dan_override(tmp_path):
    assert AU.trivy_cache_dir({"trivy_cache_dir": str(tmp_path / "c")}) == tmp_path / "c"
    assert AU.trivy_cache_dir({}).name == "sak-trivy"


# ── metadata penyusun laporan ────────────────────────────────────────────────
def test_report_meta_default():
    m = RP.report_meta({})
    assert m["by"] == "Sapto Hadi" and m["org"] == "PT. Wahana Reka Tekindo"
    assert m["line"] == "Sapto Hadi — PT. Wahana Reka Tekindo (wahanarekatekindo@gmail.com)"
    assert m["version"] == "1.0"


def test_report_meta_dari_config_dan_kosongkan_org():
    m = RP.report_meta({"report": {"prepared_by": "Budi", "organization": "PT Contoh",
                                   "contact": "sec@contoh.id", "version": "2.1"}})
    assert m["line"] == "Budi — PT Contoh (sec@contoh.id)" and m["version"] == "2.1"
    assert RP.report_meta({"report": {"organization": ""}})["line"] == "Sapto Hadi"


def test_report_meta_kontak_default_hanya_untuk_perusahaan_default():
    assert RP.report_meta({"report": {"organization": "PT Lain"}})["line"] == "Sapto Hadi — PT Lain"
    assert RP.report_meta({"report": {"contact": ""}})["line"] == "Sapto Hadi — PT. Wahana Reka Tekindo"
    assert RP.report_meta({"report": {"prepared_by": "Budi"}})["line"] == \
        "Budi — PT. Wahana Reka Tekindo (wahanarekatekindo@gmail.com)"


def test_report_meta_env_menimpa_config(monkeypatch):
    monkeypatch.setenv("SAK_REPORT_AUTHOR", "Ani")
    monkeypatch.setenv("SAK_REPORT_ORG", "CV Lain")
    m = RP.report_meta({"report": {"prepared_by": "Budi", "organization": "PT Contoh"}})
    assert m["line"] == "Ani — CV Lain"


def test_report_membaca_targets_project_dan_menulis_kredit(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "targets.yml").write_text(
        "name: Proyek A\nbase_url: http://a.local\nreport:\n  prepared_by: Budi\n  organization: PT Contoh\n",
        encoding="utf-8")
    monkeypatch.setenv("SAK_PROJECT_DIR", str(tmp_path))
    assert RP.read_target() == ("Proyek A", "http://a.local")
    out = tmp_path / "reports"
    monkeypatch.setattr(sys, "argv", ["report.py", "--dir", str(out)])
    RP.main()
    md = (out / "laporan.md").read_text(encoding="utf-8")
    html = (out / "laporan.html").read_text(encoding="utf-8")
    slides = (out / "laporan-slides.html").read_text(encoding="utf-8")
    assert "| Disusun oleh | Budi — PT Contoh |" in md
    assert "| Alat | Security Audit Kit — dibuat oleh hadymaggot" in md      # kredit kit tetap ada
    assert "Budi — PT Contoh" in html and "dibuat oleh <b>hadymaggot</b>" in html
    assert "PT Contoh · Dibuat" in html                                     # perusahaan di header
    assert "Disusun oleh Budi — PT Contoh" in slides
