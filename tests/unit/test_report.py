"""Unit test report.py & remediation.classify — tanpa jaringan.

Jalankan dari root repo: pytest -q
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import remediation as R  # noqa: E402
import report as RP  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- remediation.classify ---

def test_classify_cors():
    assert R.classify("cors", "CORS reflektif /api") == "cors-misconfig"


def test_classify_open_redirect():
    assert R.classify("open-redirect", "open redirect /login?next") == "open-redirect"


def test_classify_authz_variants():
    assert R.classify("authz-matrix", "[forged] /api/users") == "forged-header"
    assert R.classify("authz-matrix", "IDOR - detail akun lain") == "idor"
    assert R.classify("authz-matrix", "Daftar pengguna") == "broken-access"


def test_classify_client_leak_variants():
    assert R.classify("client-leak", "cache respons /api") == "client-cache"
    assert R.classify("client-leak", "File terekspos: .env") == "info-exposure"
    assert R.classify("client-leak", "Rahasia di app.js: JWT") == "js-leak"


def test_every_kind_has_kb():
    # Tiap kind yang bisa dikembalikan classify harus punya entri KB.
    for kind in ("cors-misconfig", "open-redirect", "broken-access", "forged-header",
                 "idor", "info-exposure", "client-cache", "js-leak", "weak-password",
                 "captcha-static", "missing-header", "tls-weak", "vuln-dependency"):
        kb = R.lookup(kind)
        assert {"deskripsi", "dampak", "severity", "severity_dasar",
                "rekomendasi", "referensi"} <= set(kb)


# --- report.collect / summarize ---

def test_collect_cors_and_counts(tmp_path):
    (tmp_path / "cors.json").write_text(json.dumps({
        "module": "cors", "failures": 1, "results": [
            {"label": "CORS reflektif /api", "status": 200, "ok": False,
             "note": "ACAO memantulkan Origin asing"},
            {"label": "CORS /health", "status": 200, "ok": True, "note": ""},
        ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    cors = [f for f in findings if f["modul"] == "cors"]
    assert len(cors) == 2
    bad = [f for f in cors if not f["lulus"]][0]
    assert bad["kind"] == "cors-misconfig"
    assert bad["severity"] == "medium"
    assert counts["medium"] == 1
    assert counts["lulus"] == 1


def test_collect_skips_missing_files(tmp_path):
    # Direktori kosong = nol temuan, tak error.
    assert RP.collect(tmp_path) == []


# --- runner CORS: logika evaluate tanpa jaringan ---

class _Resp:
    def __init__(self, headers):
        self.headers = headers


class _Sess:
    def __init__(self, headers):
        self._h = headers
        self.headers = {}

    def get(self, url, headers=None, timeout=None, allow_redirects=None):
        return _Resp(self._h)


def test_cors_reflected_origin_flagged():
    cors = _load("run_cors", ROOT / "tests" / "cors" / "run_cors.py")
    sess = _Sess({"Access-Control-Allow-Origin": "https://evil.example",
                  "Access-Control-Allow-Credentials": "true"})
    res = cors.evaluate("/api", sess, "http://t/api", "https://evil.example")
    assert any(not r["ok"] and "reflektif" in r["label"] for r in res)


def test_cors_no_cors_headers_ok():
    cors = _load("run_cors", ROOT / "tests" / "cors" / "run_cors.py")
    sess = _Sess({})  # tak ada header CORS
    res = cors.evaluate("/api", sess, "http://t/api", "https://evil.example")
    assert all(r["ok"] for r in res)


# --- runner open-redirect: logika is_external tanpa jaringan ---

def test_open_redirect_is_external():
    orr = _load("run_open_redirect", ROOT / "tests" / "open-redirect" / "run_open_redirect.py")
    assert orr.is_external("https://evil.example/x", "evil.example")
    assert orr.is_external("//evil.example/x", "evil.example")       # protocol-relative
    assert not orr.is_external("/dashboard", "evil.example")         # path internal
    assert not orr.is_external("https://app.sah/x", "evil.example")  # host lain
    assert not orr.is_external("", "evil.example")
