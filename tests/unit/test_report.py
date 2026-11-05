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


def test_classify_trivy_cve_uses_dependency_kb():
    # Temuan CVE dari Trivy harus pakai remediasi dependensi, bukan fallback ZAP.
    assert R.classify("trivy-cve", "CVE-2024-4068 — braces") == "vuln-dependency"


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


# --- classify: cabang modul yang tersisa ---

def test_classify_remaining_modules():
    assert R.classify("upload-safety", "PDF ber-JS diterima") == "upload-accepted"
    assert R.classify("auth-policy", "Captcha tidak regenerate") == "captcha-static"
    assert R.classify("auth-policy", "Password lemah diterima") == "weak-password"
    assert R.classify("testssl", "TLS 1.0 aktif") == "tls-weak"


def test_classify_zap_keyword_and_fallback():
    assert R.classify("zap", "Content Security Policy tidak diset") == "missing-header"
    assert R.classify("zap", "Weak TLS cipher") == "tls-weak"
    assert R.classify("zap", "Sesuatu yang tak dikenali") == "zap-generic"
    # Modul asing pun jatuh ke zap-generic, bukan error.
    assert R.classify("modul-ngaco", "apa saja") == "zap-generic"


def test_lookup_unknown_kind_falls_back_to_zap_generic():
    assert R.lookup("kind-tidak-ada") is R.KB["zap-generic"]


def test_all_kb_entries_wellformed():
    # Jauh lebih kuat dari daftar hardcode: tiap entri KB apa pun harus lengkap & waras.
    need = {"deskripsi", "dampak", "severity", "severity_dasar", "rekomendasi", "referensi"}
    for kind, kb in R.KB.items():
        assert need <= set(kb), f"{kind} kurang field"
        assert kb["severity"].lower() in {"critical", "high", "medium", "low", "info"}
        assert isinstance(kb["rekomendasi"], list) and kb["rekomendasi"], f"{kind} tanpa rekomendasi"
        assert isinstance(kb["referensi"], list) and kb["referensi"], f"{kind} tanpa referensi"


# --- report.collect: lintas modul dalam satu direktori ---

def test_collect_multi_module(tmp_path):
    (tmp_path / "headers.json").write_text(json.dumps({"results": [
        {"label": "Content-Security-Policy", "status": 200, "ok": False, "note": "header tidak ada"},
        {"label": "X-Content-Type-Options", "status": 200, "ok": True, "note": "nosniff"},
    ]}), encoding="utf-8")
    (tmp_path / "trivy.json").write_text(json.dumps({"Results": [
        {"Target": "package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-4068", "PkgName": "braces", "InstalledVersion": "3.0.2",
             "FixedVersion": "3.0.3", "Severity": "HIGH", "Title": "ReDoS"},
        ]},
    ]}), encoding="utf-8")
    (tmp_path / "testssl.json").write_text(json.dumps([
        {"id": "secure_renego", "severity": "HIGH", "cve": "CVE-2009-3555", "finding": "x"},
        {"id": "cert_ok", "severity": "INFO", "finding": "ok"},  # info diabaikan
    ]), encoding="utf-8")

    findings = RP.collect(tmp_path)
    kinds = {f["judul"]: f for f in findings}

    # headers: missing-header via kind_hint, bukan classify.
    csp = kinds["Content-Security-Policy"]
    assert csp["kind"] == "missing-header" and not csp["lulus"]
    assert any(f["lulus"] and f["kind"] == "missing-header" for f in findings)  # yg ok tetap kebaca

    # trivy: kind vuln-dependency + CVE terbawa.
    cve = kinds["CVE-2024-4068 — braces"]
    assert cve["kind"] == "vuln-dependency" and cve["severity"] == "high"
    assert "CVE-2024-4068" in cve["cve"]

    # testssl: hanya yang high masuk, info di-skip.
    assert "secure_renego" in kinds and "cert_ok" not in kinds
    assert "CVE-2009-3555" in kinds["secure_renego"]["cve"]


# --- write_md / write_html: smoke + pewarnaan ---

def _render(tmp_path):
    (tmp_path / "cors.json").write_text(json.dumps({"results": [
        {"label": "CORS reflektif /api", "status": 200, "ok": False, "note": "pantul origin"},
    ]}), encoding="utf-8")
    (tmp_path / "trivy.json").write_text(json.dumps({"Results": [
        {"Target": "lock", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-4068", "PkgName": "braces", "InstalledVersion": "3.0.2",
             "FixedVersion": "3.0.3", "Severity": "HIGH", "Title": "ReDoS"}]}]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    cves = []
    seen = set()
    for f in findings:
        for c in f["cve"]:
            if c and c.startswith("CVE") and c not in seen:
                seen.add(c)
                cves.append({"id": c, "where": f["judul"], "sev": f["severity"]})
    RP.write_md(tmp_path / "laporan.md", findings, counts, "2026-01-01 00:00", cves)
    RP.write_html(tmp_path / "laporan.html", findings, counts, "2026-01-01 00:00", cves)
    return ((tmp_path / "laporan.md").read_text(encoding="utf-8"),
            (tmp_path / "laporan.html").read_text(encoding="utf-8"))


def test_write_md_has_emoji_and_dependency_remediation(tmp_path):
    md, _ = _render(tmp_path)
    assert "🟠 High" in md                       # penanda warna di ringkasan
    assert "fixed version" in md.lower()          # CVE pakai remediasi vuln-dependency
    assert "## 4. Daftar CVE" in md and "CVE-2024-4068" in md


def test_write_html_colors_per_severity(tmp_path):
    _, h = _render(tmp_path)
    assert f"border-left:5px solid {RP.SEV_COLOR['high']}" in h   # garis kartu temuan
    assert "nvd.nist.gov/vuln/detail/CVE-2024-4068" in h          # tautan CVE
    assert "class='badge'" in h                                   # badge severity CVE
