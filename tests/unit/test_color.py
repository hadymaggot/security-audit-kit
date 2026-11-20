"""Unit tests for console colors (tests/_color.py) and the --color/--no-color option of audit.py."""
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
def _clean_env(monkeypatch):
    for k in ("SAK_COLOR", "NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE", "TERM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(C, "_vt_ok", True)          # skip real Windows console activation


# --- on/off rules ---
def test_auto_only_on_terminal():
    assert C.enabled(FakeTTY(True)) is True
    assert C.enabled(FakeTTY(False)) is False         # pipe / file / CI
    assert C.enabled(object()) is False               # stream without isatty


def test_default_pytest_stdout_is_not_terminal():
    assert C.enabled() is False                       # pytest captures stdout


def test_no_color_disables(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert C.enabled(FakeTTY(True)) is False
    monkeypatch.setenv("NO_COLOR", "")                # empty = ignored (no-color.org spec)
    assert C.enabled(FakeTTY(True)) is True


def test_term_dumb_disables(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    assert C.enabled(FakeTTY(True)) is False


def test_force_color_enables_for_pipe(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert C.enabled(FakeTTY(False)) is True
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert C.enabled(FakeTTY(False)) is False
    monkeypatch.delenv("FORCE_COLOR")
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    assert C.enabled(FakeTTY(False)) is True


@pytest.mark.parametrize("val", ["always", "1", "true", "ON"])
def test_sak_color_always_overrides_all(monkeypatch, val):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("SAK_COLOR", val)
    assert C.enabled(FakeTTY(False)) is True


@pytest.mark.parametrize("val", ["never", "0", "false", "OFF"])
def test_sak_color_never_overrides_all(monkeypatch, val):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("SAK_COLOR", val)
    assert C.enabled(FakeTTY(True)) is False


def test_windows_vt_activation_failure_disables_color(monkeypatch):
    monkeypatch.setattr(C, "_vt_ok", False)
    assert C.enabled(FakeTTY(True)) is False          # no raw escape codes on legacy consoles


# --- coloring ---
def test_paint_without_color_keeps_text():
    assert C.good("ok") == "ok" and C.bad("XX") == "XX" and C.tag("PASS") == "PASS"
    assert C.status("XX gagal") == "XX gagal" and C.severity("high") == "high"


def test_paint_with_color(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.good("ok") == f"{GREEN}ok{RST}"
    assert C.bad("MISS") == f"{RED}MISS{RST}"
    assert C.warn("x") == f"{YEL}x{RST}" and C.info("x") == f"{CYAN}x{RST}" and C.dim("x") == f"{DIM}x{RST}"
    assert C.paint("", "good") == ""                  # empty text is not wrapped
    assert C.paint("x", "tidak-ada") == "x"           # unknown kind -> returned as is


def test_status_colors_by_first_word(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.status("ok") == f"{GREEN}ok{RST}"
    assert C.status("ok unik") == f"{GREEN}ok{RST} unik"                # only the first word is green
    assert C.status("XX DITERIMA (password lemah lolos)") == f"{RED}XX DITERIMA (password lemah lolos){RST}"
    assert C.status("MISS strict-transport-security").startswith(RED)
    assert C.status("skip: rate limit") == f"{DIM}skip: rate limit{RST}"
    assert C.status("catatan biasa") == "catatan biasa"
    assert C.status("") == ""


def test_tag_and_severity(monkeypatch):
    monkeypatch.setenv("SAK_COLOR", "always")
    assert C.tag("PASS") == f"{GREEN}PASS{RST}"
    assert C.tag("FAIL") == f"{REDB}FAIL{RST}"
    assert C.tag("CRITICAL") == f"{REDB}CRITICAL{RST}"
    assert C.tag("HIGH") == f"{RED}HIGH{RST}"
    assert C.tag("MEDIUM") == f"{YEL}MEDIUM{RST}"
    assert C.tag("LOW") == f"{CYAN}LOW{RST}" and C.tag("INFO") == f"{DIM}INFO{RST}"
    assert C.tag("ASING") == "ASING"
    assert C.severity("medium", "Medium 3") == f"{YEL}Medium 3{RST}"


# --- CLI options ---
def test_pop_color_arg_supported_forms():
    assert AU.pop_color_arg(["--no-color", "all"]) == ("never", ["all"])
    assert AU.pop_color_arg(["all", "--color", "always"]) == ("always", ["all"])
    assert AU.pop_color_arg(["--color=never", "zap", "full"]) == ("never", ["zap", "full"])
    assert AU.pop_color_arg(["--color", "headers"]) == ("always", ["headers"])   # no value = always
    assert AU.pop_color_arg(["--color", "auto", "all"]) == ("auto", ["all"])
    assert AU.pop_color_arg(["headers"]) == (None, ["headers"])


def test_pop_color_arg_invalid_value_exits_2(capsys):
    with pytest.raises(SystemExit) as e:
        AU.pop_color_arg(["--color=pelangi", "all"])
    assert e.value.code == 2 and "pelangi" in capsys.readouterr().err


def test_main_passes_color_choice_to_env(monkeypatch):
    monkeypatch.delenv("SAK_COLOR", raising=False)
    monkeypatch.setattr(AU, "mod_clean", lambda: 0)
    AU.PROJECT = AU.ROOT
    assert AU.main(["--no-color", "clean"]) == 0
    assert AU.os.environ["SAK_COLOR"] == "never"       # inherited by runners and report.py
    AU.os.environ.pop("SAK_COLOR", None)
    AU.os.environ.pop("SAK_PROJECT_DIR", None)


@pytest.fixture
def server_header(tmp_path):
    """Local HTTP server that sends only x-frame-options; a temp project points at it."""
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


def test_output_is_plain_when_piped(server_header):
    out = _headers(server_header)                       # stdout = pipe -> not a terminal
    assert "MISS strict-transport-security: tidak diset" in out and "\033" not in out


def test_color_always_colors_output_but_json_stays_plain(server_header):
    out = _headers(server_header, "--color", "always")
    assert f"{RED}MISS{RST} strict-transport-security: tidak diset" in out
    assert f"{GREEN}ok{RST}   x-frame-options: diset" in out
    assert f"{GREEN}ok{RST}   x-powered-by: tanpa information disclosure" in out
    assert f"{RED}LEAK{RST} server: information disclosure (BaseHTTP" in out          # http.server sends a Server header
    saved = (server_header / "reports" / "headers.json").read_text(encoding="utf-8")
    assert "\033" not in saved and "\\u001b" not in saved       # saved data contains no color codes


def test_no_color_flag_and_env(server_header):
    assert "\033" not in _headers(server_header, "--no-color", env={"FORCE_COLOR": "1"})
    assert "\033" not in _headers(server_header, env={"NO_COLOR": "1", "FORCE_COLOR": "1"})
