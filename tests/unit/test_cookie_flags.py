"""Unit test modul cookie-flags — murni, tanpa jaringan."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CF = _load("run_cookie_flags_t", "tests/cookie-flags/run_cookie_flags.py")
RP = _load("report_cf_t", "report.py")

HTTP = "http://t.example"
HTTPS = "https://t.example"


def _by(rows):
    return {r["check"].split(": ", 1)[1]: r for r in rows}


# ── parser ──────────────────────────────────────────────────────────────────
def test_parse_set_cookie():
    c = CF.parse_set_cookie("laravel_session=abc%3D; expires=Thu, 19 Nov 2026 12:00:00 GMT; "
                            "Max-Age=7200; path=/; HttpOnly; SameSite=lax")
    assert c["name"] == "laravel_session" and c["value"] == "abc%3D"
    assert c["attrs"]["httponly"] is True and c["attrs"]["samesite"] == "lax"
    assert c["attrs"]["max-age"] == "7200"
    assert CF.parse_set_cookie("") is None and CF.parse_set_cookie("tanpa-sama-dengan") is None


# ── evaluasi atribut ────────────────────────────────────────────────────────
def test_cookie_aman_https_lolos_semua():
    c = CF.parse_set_cookie("sid=1; Secure; HttpOnly; SameSite=Strict; Max-Age=3600")
    rows = _by(CF.evaluate(c, HTTPS, {}))
    assert all(r["ok"] for r in rows.values())
    assert set(rows) == {"HttpOnly", "Secure", "SameSite", "masa berlaku"}


def test_tanpa_httponly_gagal():
    c = CF.parse_set_cookie("laravel_session=1; SameSite=lax")
    rows = _by(CF.evaluate(c, HTTP, {}))
    assert rows["HttpOnly"]["ok"] is False and "JavaScript" in rows["HttpOnly"]["note"]


def test_xsrf_token_dikecualikan_dari_httponly():
    c = CF.parse_set_cookie("XSRF-TOKEN=abc; SameSite=lax")
    rows = _by(CF.evaluate(c, HTTP, {}))
    assert rows["HttpOnly"]["ok"] is True and "dikecualikan" in rows["HttpOnly"]["note"]
    assert "masa berlaku" not in rows            # bukan cookie sesi


def test_secure_hanya_wajib_di_https():
    c = CF.parse_set_cookie("sid=1; HttpOnly; SameSite=lax")
    assert _by(CF.evaluate(c, HTTP, {}))["Secure"]["ok"] is True       # skip di HTTP
    assert "skip" in _by(CF.evaluate(c, HTTP, {}))["Secure"]["note"]
    assert _by(CF.evaluate(c, HTTPS, {}))["Secure"]["ok"] is False     # wajib di HTTPS
    assert _by(CF.evaluate(c, HTTP, {"require_secure": True}))["Secure"]["ok"] is False


def test_samesite_variasi():
    base = "sid=1; HttpOnly; Secure"
    ok = lambda extra: _by(CF.evaluate(CF.parse_set_cookie(base + extra), HTTPS, {}))["SameSite"]["ok"]
    assert ok("; SameSite=Lax") and ok("; SameSite=Strict")
    assert ok("; SameSite=None")                       # None + Secure = disengaja
    assert not ok("")                                  # tak diset
    none_no_secure = CF.parse_set_cookie("sid=1; HttpOnly; SameSite=None")
    assert _by(CF.evaluate(none_no_secure, HTTP, {}))["SameSite"]["ok"] is False


def test_masa_berlaku_cookie_sesi():
    now = datetime(2026, 11, 19, tzinfo=timezone.utc)
    long_exp = format_datetime(now + timedelta(days=400), usegmt=True)
    c = CF.parse_set_cookie(f"remember_token=x; HttpOnly; SameSite=lax; expires={long_exp}")
    r = _by(CF.evaluate(c, HTTP, {}, now=now))["masa berlaku"]
    assert r["ok"] is False and "melebihi" in r["note"]
    short = CF.parse_set_cookie("sid=1; HttpOnly; SameSite=lax; Max-Age=3600")
    assert _by(CF.evaluate(short, HTTP, {}))["masa berlaku"]["ok"] is True
    sesi = CF.parse_set_cookie("sid=1; HttpOnly; SameSite=lax")
    assert "hilang saat browser" in _by(CF.evaluate(sesi, HTTP, {}))["masa berlaku"]["note"]


def test_evaluate_all_dedup_per_nama():
    a = CF.parse_set_cookie("sid=1; HttpOnly; SameSite=lax")
    b = CF.parse_set_cookie("sid=2; HttpOnly; SameSite=lax")
    rows = CF.evaluate_all([(a, "/", 200), (b, "/login", 200)], HTTP, {})
    assert len([r for r in rows if r["check"].endswith("HttpOnly")]) == 1


# ── collect (session palsu) ─────────────────────────────────────────────────
class _Raw:
    def __init__(self, cookies):
        self._c = cookies

    def getlist(self, name):
        return list(self._c) if name == "Set-Cookie" else []


class _Resp:
    def __init__(self, cookies, status=200):
        self.raw = type("R", (), {"headers": _Raw(cookies)})()
        self.headers = {}
        self.status_code = status


class _Sess:
    def __init__(self, by_path):
        self.by_path, self.verify = by_path, True
        self.cookies = {}

    def get(self, url, **kw):
        for p, ck in self.by_path.items():
            if url.endswith(p):
                return _Resp(ck)
        return _Resp([])

    def request(self, *a, **kw):
        return _Resp(["sid=9; HttpOnly; SameSite=lax"], 200)


def test_collect_dari_probe_path():
    s = _Sess({"/": ["laravel_session=1; SameSite=lax", "XSRF-TOKEN=2; SameSite=lax"]})
    seen, notes = CF.collect({"base_url": HTTP, "probe_paths": ["/"]}, sess=s)
    assert {c["name"] for c, _, _ in seen} == {"laravel_session", "XSRF-TOKEN"} and notes == []


def test_collect_login_sanctum():
    s = _Sess({"/sanctum/csrf-cookie": ["XSRF-TOKEN=2; SameSite=lax"]})
    cfg = {"base_url": HTTP, "probe_paths": [],
           "auth": {"sanctum": {"enabled": True, "origin": HTTP},
                    "login": {"method": "POST", "path": "/api/login", "body": {}}}}
    seen, _ = CF.collect(cfg, sess=s)
    assert {"XSRF-TOKEN", "sid"} <= {c["name"] for c, _, _ in seen}


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_cookie_flags(tmp_path):
    rows = CF.evaluate(CF.parse_set_cookie("laravel_session=1; SameSite=lax"), HTTP, {})
    (tmp_path / "cookie_flags.json").write_text(json.dumps(
        {"module": "cookie-flags", "failures": 1, "results": rows}), encoding="utf-8")
    f = RP.collect(tmp_path)
    gagal = [x for x in f if not x["lulus"]]
    assert gagal and gagal[0]["kind"] == "cookie-flags" and gagal[0]["severity"] == "medium"
    assert RP.cvss_for("cookie-flags", "medium")[0] == 4.2
    assert "cookie-flags" in RP.KIND_LABEL
