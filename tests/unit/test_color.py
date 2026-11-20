"""Unit test warna konsol (tests/_color.py) dan opsi --color/--no-color pada audit.py."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = _load("_color_t", "tests/_color.py")
AU = _load("audit_color_t", "audit.py")

GREEN, RED, REDB, YEL, CYAN, DIM, RST = "\033[32m", "\033[31m", "\033[1;31m", "\033[33m", "\033[36m", "\033[2m", "\033[0m"


class FakeTTY:
    def __init__(self, tty=True):
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.fixture(autouse=True)
def _bersih(monkeypatch):
    for k in ("SAK_COLOR", "NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE", "TERM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(C, "_vt_ok", True)          # lewati aktivasi konsol Windows sungguhan


# ── aturan aktif/mati ────────────────────────────────────────────────────────
def test_otomatis_hanya_di_terminal():
    assert C.enabled(FakeTTY(True)) is True
    assert C.enabled(FakeTTY(False)) is False         # pipe / berkas / CI
    assert C.enabled(object()) is False               # stream tanpa isatty


def test_default_stdout_pytest_bukan_terminal():
    assert C.enabled() is False                       # pytest menangkap stdout


def test_no_color_mematikan(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert C.enabled(FakeTTY(True)) is False
    monkeypatch.setenv("NO_COLOR", "")                # kosong = tidak berlaku (spesifikasi no-color.org)
    assert C.enabled(FakeTTY(True)) is True


def test_term_dumb_mematikan(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    assert C.enabled(FakeTTY(True)) is False


def test_force_color_menyalakan_ke_pipe(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert C.enabled(FakeTTY(False)) is True
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert C.enabled(FakeTTY(False)) is False
    monkeypatch.delenv("FORCE_COLOR")
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    assert C.enabled(FakeTTY(False)) is True


@pytest.mark.parametrize("val", ["always", "1", "true", "ON"])
def test_sak_color_always_mengalahkan_semuanya(monkeypatch, val):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("SAK_COLOR", val)
    assert C.enabled(FakeTTY(False)) is True


@pytest.mark.parametrize("val", ["never", "0", "false", "OFF"])
def test_sak_color_never_mengalahkan_semuanya(monkeypatch, val):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("SAK_COLOR", val)
    assert C.enabled(FakeTTY(True)) is False


def test_gagal_aktivasi_vt_windows_mematikan_warna(monkeypatch):
    monkeypatch.setattr(C, "_vt_ok", False)
    assert C.enabled(FakeTTY(True)) is False          # tak mencetak kode mentah di konsol lama


# ── pewarnaan ────────────────────────────────────────────────────────────────
def test_paint_tanpa_warna_tidak_mengubah_teks():
    assert C.good("ok") == "ok" and C.bad("XX") == "XX" and C.tag("PASS") == "PASS"
    assert C.status("XX gagal") == "XX gagal" and C.severity("high") == "high"


def test_paint_dengan_warna(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.good("ok") == f"{GREEN}ok{RST}"
    assert C.bad("MISS") == f"{RED}MISS{RST}"
    assert C.warn("x") == f"{YEL}x{RST}" and C.info("x") == f"{CYAN}x{RST}" and C.dim("x") == f"{DIM}x{RST}"
    assert C.paint("", "good") == ""                  # teks kosong tak dibungkus
    assert C.paint("x", "tidak-ada") == "x"           # jenis tak dikenal -> apa adanya


def test_status_menurut_kata_pertama(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.status("ok") == f"{GREEN}ok{RST}"
    assert C.status("ok unik") == f"{GREEN}ok{RST} unik"                # hanya kata pertama hijau
    assert C.status("XX DITERIMA (password lemah lolos)") == f"{RED}XX DITERIMA (password lemah lolos){RST}"
    assert C.status("MISS strict-transport-security").startswith(RED)
    assert C.status("skip: rate limit") == f"{DIM}skip: rate limit{RST}"
    assert C.status("catatan biasa") == "catatan biasa"
    assert C.status("") == ""


def test_tag_dan_severity(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.tag("PASS") == f"{GREEN}PASS{RST}"
    assert C.tag("FAIL") == f"{REDB}FAIL{RST}"
    assert C.tag("CRITICAL") == f"{REDB}CRITICAL{RST}"
    assert C.tag("HIGH") == f"{RED}HIGH{RST}"
    assert C.tag("MEDIUM") == f"{YEL}MEDIUM{RST}"
    assert C.tag("LOW") == f"{CYAN}LOW{RST}" and C.tag("INFO") == f"{DIM}INFO{RST}"
    assert C.tag("ASING") == "ASING"
    assert C.severity("medium", "Medium 3") == f"{YEL}Medium 3{RST}"


# ── opsi CLI ─────────────────────────────────────────────────────────────────
def test_pop_color_arg_bentuk_yang_didukung():
    assert AU.pop_color_arg(["--no-color", "all"]) == ("never", ["all"])
    assert AU.pop_color_arg(["all", "--color", "always"]) == ("always", ["all"])
    assert AU.pop_color_arg(["--color=never", "zap", "full"]) == ("never", ["zap", "full"])
    assert AU.pop_color_arg(["--color", "headers"]) == ("always", ["headers"])   # tanpa nilai = always
    assert AU.pop_color_arg(["--color", "auto", "all"]) == ("auto", ["all"])
    assert AU.pop_color_arg(["headers"]) == (None, ["headers"])


def test_pop_color_arg_nilai_salah_keluar_kode_2(capsys):
    with pytest.raises(SystemExit) as e:
        AU.pop_color_arg(["--color=pelangi", "all"])
    assert e.value.code == 2 and "pelangi" in capsys.readouterr().err


def test_main_meneruskan_pilihan_warna_ke_env(monkeypatch):
    monkeypatch.delenv("SAK_COLOR", raising=False)
    monkeypatch.setattr(AU, "mod_clean", lambda: 0)
    AU.PROJECT = AU.ROOT
    assert AU.main(["--no-color", "clean"]) == 0
    assert AU.os.environ["SAK_COLOR"] == "never"       # diwariskan ke runner dan report.py
    AU.os.environ.pop("SAK_COLOR", None)
    AU.os.environ.pop("SAK_PROJECT_DIR", None)


@pytest.fixture
def server_header(tmp_path):
    """Server HTTP lokal yang hanya mengirim x-frame-options; project sementara menunjuk ke sana."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()

        do_HEAD = do_GET

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    proj = tmp_path / "proj"
    (proj / "config").mkdir(parents=True)
    (proj / "config" / "targets.yml").write_text(
        f'name: uji\nbase_url: "http://127.0.0.1:{srv.server_address[1]}"\nheader_probe_path: "/"\n',
        encoding="utf-8")
    yield proj
    srv.shutdown()


def _headers(proj, *extra, env=None):
    import os
    import subprocess
    import sys

    e = {k: v for k, v in os.environ.items() if k not in ("SAK_COLOR", "NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE")}
    e.update(env or {})
    p = subprocess.run([sys.executable, str(ROOT / "audit.py"), "--project", str(proj), *extra, "headers"],
                       capture_output=True, text=True, encoding="utf-8", env=e, timeout=60)
    return p.stdout


def test_keluaran_polos_saat_dialihkan_ke_pipe(server_header):
    out = _headers(server_header)                       # stdout = pipe -> bukan terminal
    assert "MISS strict-transport-security: tidak diset" in out and "\033" not in out


def test_color_always_mewarnai_tetapi_json_tetap_polos(server_header):
    out = _headers(server_header, "--color", "always")
    assert f"{RED}MISS{RST} strict-transport-security: tidak diset" in out
    assert f"{GREEN}ok{RST}   x-frame-options: diset" in out
    assert f"{GREEN}ok{RST}   x-powered-by: tanpa information disclosure" in out
    assert f"{RED}LEAK{RST} server: information disclosure (BaseHTTP" in out          # http.server sends a Server header
    saved = (server_header / "reports" / "headers.json").read_text(encoding="utf-8")
    assert "\033" not in saved and "\\u001b" not in saved       # data tersimpan tidak berisi kode warna


def test_no_color_dan_env_no_color(server_header):
    assert "\033" not in _headers(server_header, "--no-color", env={"FORCE_COLOR": "1"})
    assert "\033" not in _headers(server_header, env={"NO_COLOR": "1", "FORCE_COLOR": "1"})
