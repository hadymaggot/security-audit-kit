"""Unit tests for report.py and remediation.classify. No network.

Run from the repo root: pytest -q
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


# remediation.classify

def test_classify_cors():
    assert R.classify("cors", "CORS reflektif /api") == "cors-misconfig"


def test_classify_open_redirect():
    assert R.classify("open-redirect", "open redirect /login?next") == "open-redirect"


def test_classify_trivy_cve_uses_dependency_kb():
    # Trivy CVE findings must use dependency remediation, not the ZAP fallback.
    assert R.classify("trivy-cve", "CVE-2024-4068 — braces") == "vuln-dependency"


def test_classify_authz_variants():
    assert R.classify("authz-matrix", "[forged] /api/users") == "forged-header"
    assert R.classify("authz-matrix", "IDOR - detail akun lain") == "idor"
    assert R.classify("authz-matrix", "Daftar pengguna") == "broken-access"


def test_classify_client_leak_variants():
    assert R.classify("client-leak", "cache response /api") == "client-cache"
    assert R.classify("client-leak", "File exposed: .env") == "info-exposure"
    assert R.classify("client-leak", "Rahasia di app.js: JWT") == "js-leak"


def test_every_kind_has_kb():
    # Every kind classify can return must have a KB entry.
    for kind in ("cors-misconfig", "open-redirect", "broken-access", "forged-header",
                 "idor", "info-exposure", "client-cache", "js-leak", "weak-password",
                 "captcha-static", "missing-header", "tls-weak", "vuln-dependency"):
        kb = R.lookup(kind)
        assert {"description", "impact", "severity", "severity_basis",
                "recommendation", "references"} <= set(kb)


# report.collect / summarize

def test_collect_cors_and_counts(tmp_path):
    (tmp_path / "cors.json").write_text(json.dumps({
        "module": "cors", "failures": 1, "results": [
            {"label": "CORS reflektif /api", "status": 200, "ok": False,
             "note": "ACAO memantulkan Origin asing"},
            {"label": "CORS /health", "status": 200, "ok": True, "note": ""},
        ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    cors = [f for f in findings if f["module"] == "cors"]
    assert len(cors) == 2
    bad = [f for f in cors if not f["passed"]][0]
    assert bad["kind"] == "cors-misconfig"
    assert bad["severity"] == "medium"
    assert counts["medium"] == 1
    assert counts["passed"] == 1


def test_collect_skips_missing_files(tmp_path):
    # An empty directory yields zero findings, not an error.
    assert RP.collect(tmp_path) == []


# CORS runner: evaluate logic without network

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
    sess = _Sess({})  # no CORS headers
    res = cors.evaluate("/api", sess, "http://t/api", "https://evil.example")
    assert all(r["ok"] for r in res)


# open-redirect runner: is_external logic without network

def test_open_redirect_is_external():
    orr = _load("run_open_redirect", ROOT / "tests" / "open-redirect" / "run_open_redirect.py")
    assert orr.is_external("https://evil.example/x", "evil.example")
    assert orr.is_external("//evil.example/x", "evil.example")       # protocol-relative
    assert not orr.is_external("/dashboard", "evil.example")         # internal path
    assert not orr.is_external("https://app.sah/x", "evil.example")  # other host
    assert not orr.is_external("", "evil.example")


# classify: remaining module branches

def test_classify_remaining_modules():
    assert R.classify("upload-safety", "PDF ber-JS diterima") == "upload-accepted"
    assert R.classify("auth-policy", "Captcha tidak regenerate") == "captcha-static"
    assert R.classify("auth-policy", "Password lemah diterima") == "weak-password"
    assert R.classify("testssl", "TLS 1.0 aktif") == "tls-weak"


def test_classify_zap_keyword_and_fallback():
    assert R.classify("zap", "Content Security Policy tidak diset") == "missing-header"
    assert R.classify("zap", "Weak TLS cipher") == "tls-weak"
    assert R.classify("zap", "Sesuatu yang tak dikenali") == "zap-generic"
    # An unknown module also falls back to zap-generic, not an error.
    assert R.classify("modul-ngaco", "apa saja") == "zap-generic"


def test_lookup_unknown_kind_falls_back_to_zap_generic():
    assert R.lookup("kind-tidak-ada") is R.KB["zap-generic"]


def test_all_kb_entries_wellformed():
    # Stronger than a hardcoded list: every KB entry must be complete and sane.
    need = {"description", "impact", "severity", "severity_basis", "recommendation", "references"}
    for kind, kb in R.KB.items():
        assert need <= set(kb), f"{kind} kurang field"
        assert kb["severity"].lower() in {"critical", "high", "medium", "low", "info"}
        assert isinstance(kb["recommendation"], list) and kb["recommendation"], f"{kind} tanpa rekomendasi"
        assert isinstance(kb["references"], list) and kb["references"], f"{kind} tanpa referensi"


# report.collect: multiple modules in one directory

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
        {"id": "cert_ok", "severity": "INFO", "finding": "ok"},  # info is ignored
    ]), encoding="utf-8")

    findings = RP.collect(tmp_path)
    kinds = {f["title"]: f for f in findings}

    # headers: missing-header via kind_hint, not classify.
    csp = kinds["Content-Security-Policy"]
    assert csp["kind"] == "missing-header" and not csp["passed"]
    assert any(f["passed"] and f["kind"] == "missing-header" for f in findings)  # passed rows are still collected

    # trivy: kind vuln-dependency and the CVE is carried over.
    cve = kinds["CVE-2024-4068 — braces"]
    assert cve["kind"] == "vuln-dependency" and cve["severity"] == "high"
    assert "CVE-2024-4068" in cve["cve"]

    # testssl: only high is kept, info is skipped.
    assert "secure_renego" in kinds and "cert_ok" not in kinds
    assert "CVE-2009-3555" in kinds["secure_renego"]["cve"]


# write_md / write_html: smoke test and coloring

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
                cves.append({"id": c, "where": f["title"], "sev": f["severity"]})
    RP.write_md(tmp_path / "laporan.md", findings, counts, "2026-01-01 00:00", cves)
    RP.write_html(tmp_path / "laporan.html", findings, counts, "2026-01-01 00:00", cves)
    return ((tmp_path / "laporan.md").read_text(encoding="utf-8"),
            (tmp_path / "laporan.html").read_text(encoding="utf-8"))


def test_write_md_has_emoji_and_dependency_remediation(tmp_path):
    md, _ = _render(tmp_path)
    assert "🟠 High" in md                       # color marker in the summary
    assert "fixed version" in md.lower()          # CVE uses vuln-dependency remediation
    assert "## 5. Daftar CVE" in md and "CVE-2024-4068" in md


def test_write_html_colors_per_severity(tmp_path):
    _, h = _render(tmp_path)
    assert f"background:{RP.SEV_COLOR['high']}" in h              # severity color via badge (not a left strip)
    assert "nvd.nist.gov/vuln/detail/CVE-2024-4068" in h          # CVE link
    assert "class='badge'" in h                                   # CVE severity badge


# URL/endpoint as evidence

def test_collect_carries_url_from_runner(tmp_path):
    (tmp_path / "authz.json").write_text(json.dumps([
        {"endpoint": "admin", "role": "low", "expected": "deny", "status": 200,
         "ok": False, "note": "exposed", "url": "GET http://t:18002/api/admin"},
    ]), encoding="utf-8")
    f = RP.collect(tmp_path)[0]
    assert f["url"] == "GET http://t:18002/api/admin"


def test_url_appears_as_instance_evidence(tmp_path):
    (tmp_path / "authz.json").write_text(json.dumps([
        {"endpoint": "File exposed", "role": "anon", "expected": "deny", "status": 200,
         "ok": False, "note": "exposed", "url": "GET http://t:18008/api/activity-logs"},
    ]), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    RP.write_md(tmp_path / "m.md", findings, counts, "2026-01-01", [])
    RP.write_html(tmp_path / "m.html", findings, counts, "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    h = (tmp_path / "m.html").read_text(encoding="utf-8")
    assert "Endpoint diuji" in md and "http://t:18008/api/activity-logs" in md
    assert "Endpoint diuji" in h and "http://t:18008/api/activity-logs" in h


def test_screenshot_embedded_in_all_formats(tmp_path):
    (tmp_path / "client_leak.json").write_text(json.dumps({"results": [
        {"kind": "cache", "label": "cache response /account", "status": 200, "ok": False,
         "note": "ter-cache", "url": "GET http://t/account",
         "screenshot": "evidence/cache_account.png"},
    ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    assert findings[0]["screenshot"] == "evidence/cache_account.png"
    counts = RP.summarize(findings)
    RP.write_md(tmp_path / "m.md", findings, counts, "2026-01-01", [])
    RP.write_html(tmp_path / "m.html", findings, counts, "2026-01-01", [])
    RP.write_slides(tmp_path / "s.html", findings, counts, "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    h = (tmp_path / "m.html").read_text(encoding="utf-8")
    s = (tmp_path / "s.html").read_text(encoding="utf-8")
    assert "![bukti](evidence/cache_account.png)" in md                 # MD: image link
    assert "<img class='shot' src='evidence/cache_account.png'" in h    # HTML: thumbnail
    assert "evidence/cache_account.png" in s                            # slide: image


def test_no_screenshot_no_img(tmp_path):
    (tmp_path / "headers.json").write_text(json.dumps({"results": [
        {"label": "CSP", "status": 200, "ok": False, "note": "x", "url": "GET http://t/"},
    ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    RP.write_html(tmp_path / "m.html", findings, RP.summarize(findings), "2026-01-01", [])
    assert "class='shot'" not in (tmp_path / "m.html").read_text(encoding="utf-8")


def test_missing_url_renders_dash(tmp_path):
    (tmp_path / "headers.json").write_text(json.dumps({"results": [
        {"label": "Content-Security-Policy", "status": 200, "ok": False, "note": "x"},
    ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    RP.write_md(tmp_path / "m.md", findings, RP.summarize(findings), "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    assert "Endpoint diuji" in md and "| `-` |" in md   # no url -> '-' cell


# ZAP style: alerts grouped by kind, confidence, author credit

def test_group_alerts_by_kind_with_instances():
    failed = [
        {"module": "authz-matrix", "title": "[forged] http://t:18002/x", "kind": "forged-header",
         "passed": False, "severity": "critical", "status": 200, "evidence": "e1",
         "url": "GET http://t:18002/x", "cve": [], "kb": R.lookup("forged-header")},
        {"module": "authz-matrix", "title": "[forged] http://t:18004/y", "kind": "forged-header",
         "passed": False, "severity": "critical", "status": 200, "evidence": "e2",
         "url": "GET http://t:18004/y", "cve": [], "kb": R.lookup("forged-header")},
        {"module": "authz-matrix", "title": "IDOR company", "kind": "idor",
         "passed": False, "severity": "high", "status": 200, "evidence": "e3",
         "url": "GET http://t/api/companies/9", "cve": [], "kb": R.lookup("idor")},
    ]
    alerts = RP.group_alerts(failed)
    assert [a["kind"] for a in alerts] == ["forged-header", "idor"]   # critical first
    assert len(alerts[0]["instances"]) == 2 and alerts[0]["confidence"] == "Tinggi"
    assert alerts[0]["name"] == RP.KIND_LABEL["forged-header"]


def test_zap_module_confidence_is_medium():
    assert RP._confidence({"zap"}) == "Sedang"
    assert RP._confidence({"authz-matrix"}) == "Tinggi"
    assert RP._confidence({"zap", "authz-matrix"}) == "Tinggi"


def test_professional_structure_present(tmp_path):
    # One finding: check the standard consultant-report elements in MD and HTML.
    (tmp_path / "authz.json").write_text(json.dumps([
        {"endpoint": "Admin panel", "role": "anon", "expected": "deny", "status": 200,
         "ok": False, "note": "terbuka", "url": "GET http://t/api/admin"},
    ]), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    RP.write_md(tmp_path / "m.md", findings, counts, "2026-01-01", [])
    RP.write_html(tmp_path / "m.html", findings, counts, "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    h = (tmp_path / "m.html").read_text(encoding="utf-8")
    for doc in (md, h):
        assert "SAK-001" in doc                       # finding ID
        assert "RAHASIA / CONFIDENTIAL" in doc        # classification
        assert "Ringkasan Eksekutif" in doc           # executive summary
        assert "Ruang Lingkup" in doc                 # scope
        assert "CVSS v3.1" in doc              # CVSS column/label
    assert "## 6. Lampiran" in md and "6. Lampiran" in h


def test_exec_summary_empty_vs_findings():
    assert "Tidak ditemukan temuan" in RP.exec_summary([], RP.summarize([]))
    a = [{"name": "X", "severity": "high", "instances": [1]}]
    c = {k: 0 for k in RP.SEV_ORDER}
    c["high"] = 1
    assert "1 instance temuan" in RP.exec_summary(a, c)


def test_finding_id_format():
    assert RP.finding_id(1) == "SAK-001" and RP.finding_id(42) == "SAK-042"


def test_write_slides_selfcontained(tmp_path):
    (tmp_path / "authz.json").write_text(json.dumps([
        {"endpoint": "Admin", "role": "anon", "expected": "deny", "status": 200,
         "ok": False, "note": "x", "url": "GET http://t/api/admin"},
    ]), encoding="utf-8")
    findings = RP.collect(tmp_path)
    RP.write_slides(tmp_path / "s.html", findings, RP.summarize(findings), "2026-01-01", [])
    h = (tmp_path / "s.html").read_text(encoding="utf-8")
    assert "id=\"deck\"" in h and "class=\"slide cover\"" in h      # deck structure
    assert "SAK-001" in h and "Ringkasan Eksekutif" in h           # finding slide and exec summary
    assert RP.KIT_AUTHOR in h and RP.CLASSIFICATION in h              # credit and classification
    assert "cdn" not in h.lower() and "src=\"http" not in h        # no external dependency


def test_write_slides_empty(tmp_path):
    # Without findings it still produces a valid deck (cover, summary, closing).
    RP.write_slides(tmp_path / "s.html", [], RP.summarize([]), "2026-01-01", [])
    h = (tmp_path / "s.html").read_text(encoding="utf-8")
    assert "Ringkasan Risiko" in h and RP.KIT_AUTHOR in h


def test_credit_always_in_every_report(tmp_path):
    # Even with no findings at all, the author credit stays in MD and HTML.
    findings = RP.collect(tmp_path)   # empty directory -> zero findings
    RP.write_md(tmp_path / "m.md", findings, RP.summarize(findings), "2026-01-01", [])
    RP.write_html(tmp_path / "m.html", findings, RP.summarize(findings), "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    h = (tmp_path / "m.html").read_text(encoding="utf-8")
    assert RP.KIT_AUTHOR in md and RP.KIT_URL in md
    assert RP.KIT_AUTHOR in h and RP.KIT_URL in h


# client-leak runner: timeout-skip and SPA-fallback guards without network

class _LeakResp:
    def __init__(self, status=200, headers=None, content=b"x"):
        self.status_code = status
        self.headers = headers or {}
        self.content = content
        self.text = content.decode("utf-8", "replace") if isinstance(content, bytes) else content


class _LeakSess:
    """Fake session: each URL maps to a _LeakResp or an Exception (timeout)."""

    def __init__(self, mapping, default=None):
        self._map = mapping
        self._default = default
        self.headers = {}

    def get(self, url, timeout=None, allow_redirects=None, headers=None):
        for frag, resp in self._map.items():
            if frag in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        if isinstance(self._default, Exception):
            raise self._default
        return self._default or _LeakResp(404, {}, b"")


def _leak():
    return _load("run_client_leak", ROOT / "tests" / "client-leak" / "run_client_leak.py")


class _FakePage:
    def __init__(self):
        self.calls = []

    def screenshot(self, path=None, full_page=None, clip=None):
        self.calls.append(("page", full_page, clip))
        Path(path).write_bytes(b"\x89PNG")

    def locator(self, sel):
        page = self

        class _L:
            @property
            def first(self):
                class _E:
                    def screenshot(self, path=None):
                        page.calls.append(("elem", sel))
                        Path(path).write_bytes(b"\x89PNG")
                return _E()
        return _L()


def test_capture_shot_viewport_default(tmp_path):
    cl = _leak()
    page = _FakePage()
    rel = cl._capture_shot(page, {}, tmp_path, "/account")
    assert rel == "evidence/cache_account.png"
    assert (tmp_path / "evidence" / "cache_account.png").exists()
    assert page.calls == [("page", False, None)]          # viewport (full_page=False)


def test_capture_shot_selector_and_clip(tmp_path):
    cl = _leak()
    p1 = _FakePage()
    cl._capture_shot(p1, {"selector": ".panel"}, tmp_path, "/x")
    assert p1.calls == [("elem", ".panel")]               # crop to the element
    p2 = _FakePage()
    cl._capture_shot(p2, {"clip": {"x": 0, "y": 0, "width": 10, "height": 10}}, tmp_path, "/y")
    assert p2.calls[0][0] == "page" and p2.calls[0][2]["width"] == 10   # crop to a region


def test_capture_shot_disabled_or_no_dir(tmp_path):
    cl = _leak()
    assert cl._capture_shot(_FakePage(), {"screenshot": False}, tmp_path, "/x") == ""
    assert cl._capture_shot(_FakePage(), {}, None, "/x") == ""


def test_cache_timeout_is_skipped_not_finding():
    # Timeout/unreachable on a cache check is a skip (ok=True), NOT a security finding.
    cl = _leak()
    sess = _LeakSess({"/account": TimeoutError("timed out")})
    res = cl.check_cache(sess, "http://t", ["/account"])
    assert len(res) == 1
    row = res[0]
    assert row["ok"] is True and row["status"] == -1
    assert row["note"].startswith("skip:")


def test_cache_public_flagged_and_no_store_ok():
    cl = _leak()
    sess = _LeakSess({
        "/exposed": _LeakResp(200, {"Cache-Control": "public, max-age=60"}),
        "/aman": _LeakResp(200, {"Cache-Control": "no-store"}),
    })
    res = cl.check_cache(sess, "http://t", ["/exposed", "/aman"])
    by = {r["label"]: r for r in res}
    assert by["cache response /exposed"]["ok"] is False
    assert by["cache response /aman"]["ok"] is True


def test_files_spa_fallback_not_treated_as_exposed():
    # An SPA returns index.html (200, html Content-Type) for any path;
    # this must NOT count as an exposed file.
    cl = _leak()
    sess = _LeakSess({".env": _LeakResp(200, {"Content-Type": "text/html"}, b"<!doctype html>")})
    res = cl.check_files(sess, "http://t", [".env"])
    assert len(res) == 1 and res[0]["ok"] is True


def test_files_real_exposure_flagged():
    cl = _leak()
    sess = _LeakSess({".env": _LeakResp(200, {"Content-Type": "text/plain"}, b"SECRET=1")})
    res = cl.check_files(sess, "http://t", [".env"])
    assert res[0]["ok"] is False and "exposed" in res[0]["label"].lower()


def test_files_timeout_skipped_silently():
    # An exception while probing a file is skipped and adds no finding.
    cl = _leak()
    sess = _LeakSess({".env": ConnectionError("boom")})
    res = cl.check_files(sess, "http://t", [".env"])
    assert res == []


def test_collect_reads_client_leak_skip_rows(tmp_path):
    # report.collect must treat skip rows (status -1, ok True) as passed.
    (tmp_path / "client_leak.json").write_text(json.dumps({
        "module": "client-leak", "failures": 1, "results": [
            {"kind": "cache", "label": "cache response /account", "status": -1,
             "ok": True, "note": "skip: timed out"},
            {"kind": "file", "label": "File exposed: .env", "status": 200,
             "ok": False, "note": "12 byte dapat diunduh publik"},
        ]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    by = {f["title"]: f for f in findings}
    assert by["cache response /account"]["passed"] is True
    leak = by["File exposed: .env"]
    assert leak["passed"] is False and leak["kind"] == "info-exposure"


# HTML tags from external sources (ZAP/trivy/testssl) must not leak as text

def test_plain_text_strips_tags_and_entities():
    assert RP.plain_text("&lt;p&gt;Header  hilang&lt;/p&gt;") == "Header hilang"
    assert RP.plain_text("<p>a</p><p>b &amp; c</p>") == "a b & c"
    assert RP.plain_text("&amp;lt;b&amp;gt;x&amp;lt;/b&amp;gt;") == "x"      # double-encoded entity
    assert RP.plain_text("x" * 50, 10) == "x" * 10
    assert RP.plain_text(None) == ""


def test_zap_desc_html_does_not_leak(tmp_path):
    (tmp_path / "zap-baseline.json").write_text(json.dumps({"site": [{"alerts": [{
        "alert": "Anti-clickjacking &lt;b&gt;Header&lt;/b&gt; Missing",
        "riskdesc": "Medium (High)",
        "desc": "&lt;p&gt;Response tidak melindungi dari ClickJacking.&lt;/p&gt;",
        "instances": [{"uri": "http://t/"}],
    }]}]}), encoding="utf-8")
    findings = RP.collect(tmp_path)
    counts = RP.summarize(findings)
    RP.write_md(tmp_path / "m.md", findings, counts, "2026-01-01", [])
    RP.write_html(tmp_path / "m.html", findings, counts, "2026-01-01", [])
    md = (tmp_path / "m.md").read_text(encoding="utf-8")
    h = (tmp_path / "m.html").read_text(encoding="utf-8")
    for doc in (md, h):
        assert "&lt;p&gt;" not in doc and "<p>Response" not in doc
        assert "Response tidak melindungi dari ClickJacking." in doc
    assert "<b>Header</b>" not in md and "Anti-clickjacking *Header* Missing" in md   # terms are italicized in Markdown
