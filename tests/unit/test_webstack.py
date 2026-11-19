"""Unit test runner webstack — tanpa jaringan."""
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "run_webstack_t", ROOT / "tests" / "webstack" / "run_webstack.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


WS = _load()

KNOWN = [
    {"server": "apache", "max_version": "2.4.71", "cve": "CVE-2026-119618",
     "catatan": "mod_http2 RCE"},
    {"server": "nginx", "max_version": "1.30.7", "cve": "CVE-2026-123633",
     "catatan": "HTTP/2"},
]


class _Resp:
    def __init__(self, headers, status=200):
        self.headers = headers
        self.status_code = status


class _Sess:
    def __init__(self, headers):
        self._h = headers
        self.headers = {}

    def get(self, url, timeout=None, allow_redirects=None):
        return _Resp(self._h)


def _check(headers, http2=None, known=None):
    sess = _Sess(headers)
    return WS.check_target(sess, "http://t/", known if known is not None else KNOWN,
                           http2_probe=lambda u: http2)


# known_vulnerable PHP multi-branch (backport) — dua entri, CVE sama.
PHP_KNOWN = [
    {"server": "php", "min_version": "8.4.0", "max_version": "8.4.27",
     "cve": "CVE-2026-109618", "catatan": "PHP2Shell"},
    {"server": "php", "min_version": "8.3.0", "max_version": "8.3.36",
     "cve": "CVE-2026-109618", "catatan": "PHP2Shell"},
]


def _vuln(res):
    return [r for r in res if r["check"].startswith("Versi rentan")]


def test_x_powered_by_php_in_range_flagged():
    res = _check({"Server": "nginx/1.31.9", "X-Powered-By": "PHP/8.3.20"}, known=PHP_KNOWN)
    v = _vuln(res)
    assert len(v) == 1 and v[0]["cve"] == ["CVE-2026-109618"]
    assert "X-Powered-By" in v[0]["note"]


def test_php_patched_version_not_flagged():
    res = _check({"X-Powered-By": "PHP/8.3.36"}, known=PHP_KNOWN)   # tepat versi perbaikan
    assert _vuln(res) == []


def test_php_other_branch_not_false_positive():
    # 8.5.x tak masuk rentang 8.3/8.4 → tak ditandai oleh entri itu.
    res = _check({"X-Powered-By": "PHP/8.5.1"}, known=PHP_KNOWN)
    assert _vuln(res) == []


def test_php_multibranch_dedup_one_finding():
    # Versi 8.3.20 cocok entri 8.3; CVE sama dengan entri 8.4 → tetap satu temuan.
    res = _check({"X-Powered-By": "PHP/8.3.20"}, known=PHP_KNOWN)
    assert len(_vuln(res)) == 1


# --- helper versi ---

def test_ver_tuple_and_less_than():
    assert WS.ver_tuple("2.4.70") == (2, 4, 70)
    assert WS.less_than("2.4.70", "2.4.71") is True
    assert WS.less_than("2.4.71", "2.4.71") is False
    assert WS.less_than("1.31.0", "1.30.7") is False      # panjang beda, >= tetap benar


def test_parse_banner():
    assert WS.parse_banner("Apache/2.4.70 (Unix)") == ("apache", "2.4.70")
    assert WS.parse_banner("nginx") == ("nginx", "")
    assert WS.parse_banner("") == ("", "")


# --- deteksi ---

def test_flags_known_vulnerable_version():
    res = _check({"Server": "Apache/2.4.70"})
    vuln = [r for r in res if r["check"].startswith("Versi rentan")]
    assert len(vuln) == 1
    assert vuln[0]["ok"] is False and vuln[0]["cve"] == ["CVE-2026-119618"]
    # Version disclosure juga jadi temuan (banner memuat versi).
    disc = [r for r in res if r["check"].startswith("Version disclosure")][0]
    assert disc["ok"] is False and "2.4.70" in disc["note"]


def test_patched_version_not_flagged():
    res = _check({"Server": "Apache/2.4.71"})
    assert not [r for r in res if r["check"].startswith("Versi rentan")]
    # Masih version-disclosure (banner tetap bocor versi), tapi bukan server-vuln.
    assert any(r["check"].startswith("Version disclosure") and not r["ok"] for r in res)


def test_no_version_not_claimed_vulnerable():
    # Banner tanpa versi (ServerTokens Prod) → tak ada klaim rentan, tak ada disclosure.
    res = _check({"Server": "Apache"})
    assert not [r for r in res if r["check"].startswith("Versi rentan")]
    disc = [r for r in res if r["check"].startswith("Version disclosure")][0]
    assert disc["ok"] is True


def test_http2_note_added_when_alpn_h2():
    res = _check({"Server": "nginx/1.30.6"}, http2=True)
    vuln = [r for r in res if r["check"].startswith("Versi rentan")][0]
    assert "HTTP/2 aktif" in vuln["note"] and vuln["cve"] == ["CVE-2026-123633"]


def test_x_powered_by_disclosure():
    res = _check({"Server": "nginx", "X-Powered-By": "PHP/8.1.2"})
    disc = [r for r in res if r["check"].startswith("Version disclosure")][0]
    assert disc["ok"] is False and "PHP/8.1.2" in disc["note"]


def test_request_error_is_skip():
    class _Boom:
        headers = {}

        def get(self, *a, **k):
            raise ConnectionError("putus")

    res = WS.check_target(_Boom(), "http://t/", KNOWN, http2_probe=lambda u: None)
    assert len(res) == 1 and res[0]["ok"] is True and res[0]["note"].startswith("skip")


# --- main() end-to-end ---

def test_main_writes_json_and_rc(tmp_path, monkeypatch):
    cfg = {"base_url": "http://t", "known_vulnerable": KNOWN}
    p = tmp_path / "ws.yml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    out = tmp_path / "ws.json"
    monkeypatch.setattr(WS.requests, "Session", lambda: _Sess({"Server": "Apache/2.4.70"}))
    monkeypatch.setattr(WS, "supports_http2", lambda u: None)
    monkeypatch.setattr(sys, "argv", ["x", "--config", str(p), "--json", str(out)])
    rc = WS.main()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert rc == 1 and data["module"] == "webstack"
    assert any(r.get("cve") == ["CVE-2026-119618"] for r in data["results"])
