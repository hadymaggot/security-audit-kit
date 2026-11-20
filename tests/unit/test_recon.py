"""Unit test modul recon — murni, tanpa jaringan/binari (run_tool & whicher di-stub)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "run_recon_t", ROOT / "tests" / "recon" / "run_recon.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RC = _load()


def _whicher_all(_exe):
    return "/usr/bin/" + _exe   # semua binari "terpasang"


def _whicher_none(_exe):
    return None                  # tidak ada binari terpasang


def make_run_tool(outputs):
    """outputs: dict nama-binari -> stdout. Mencatat perintah yang dipanggil."""
    calls = []

    def run_tool(cmd, timeout=600, stdin=None):
        calls.append(cmd)
        exe = Path(cmd[0]).name
        return 0, outputs.get(exe, "")

    run_tool.calls = calls
    return run_tool


def _cfg(**kw):
    base = {"target": "contoh.example", "base_url": "https://contoh.example",
            "depth": "infra", "mode": "fast"}
    base.update(kw)
    return base


# ── expand() ────────────────────────────────────────────────────────────────
def test_expand_env(monkeypatch):
    monkeypatch.setenv("RECON_T", "contoh.example")
    assert RC.expand("${RECON_T}") == "contoh.example"
    assert RC.expand({"target": "${RECON_T}"})["target"] == "contoh.example"
    assert RC.expand("${MISSING_XYZ}") == ""


# ── gating: default (osint, tak ada fase aktif) ──────────────────────────────
def test_osint_only_no_active_tools():
    sub = "api.contoh.example\nwww.contoh.example\n"
    hx = json.dumps({"url": "https://api.contoh.example", "status_code": 200,
                     "tech": ["nginx", "php"]})
    rt = make_run_tool({"subfinder": sub, "httpx": hx})
    results = RC.orchestrate(_cfg(depth="osint"), run_tool=rt, whicher=_whicher_all)
    # naabu/nuclei tidak boleh dipanggil pada depth osint
    assert not any("naabu" in c[0] or "nuclei" in c[0] for c in rt.calls)
    assert any(r["kind"] == "recon-subdomain" for r in results)


def test_infra_active_off_skips_naabu():
    rt = make_run_tool({"subfinder": "x.contoh.example\n", "httpx": ""})
    results = RC.orchestrate(_cfg(depth="infra", active={"enabled": False}),
                             run_tool=rt, whicher=_whicher_all)
    assert not any("naabu" in c[0] for c in rt.calls)        # tidak dipanggil
    assert any("dilewati" in (r.get("note") or "") and r["ok"] for r in results)


def test_full_active_off_skips_nuclei():
    rt = make_run_tool({"subfinder": "", "httpx": ""})
    results = RC.orchestrate(_cfg(depth="full", active={"enabled": False}),
                             run_tool=rt, whicher=_whicher_all)
    assert not any("nuclei" in c[0] for c in rt.calls)
    assert any("nuclei" in (r.get("check") or "") and r["ok"] for r in results)


# ── gating ON: naabu + nuclei berjalan ───────────────────────────────────────
def test_naabu_parses_sensitive_port():
    naabu = json.dumps({"host": "contoh.example", "port": 22})
    rt = make_run_tool({"subfinder": "", "httpx": "", "naabu": naabu})
    results = RC.orchestrate(
        _cfg(depth="infra", active={"enabled": True, "naabu": True}),
        run_tool=rt, whicher=_whicher_all)
    assert any("naabu" in c[0] for c in rt.calls)
    port = [r for r in results if "port 22" in r["check"]]
    assert port and port[0]["severity"] == "medium" and not port[0]["ok"]


def test_nuclei_severity_honored():
    vuln = json.dumps({"info": {"name": "RCE X", "severity": "critical",
                                "tags": ["cve", "cve-2026-9999", "rce"]},
                       "matched-at": "https://contoh.example/x",
                       "template-id": "rce-x"})
    hx = json.dumps({"url": "https://contoh.example", "status_code": 200})
    rt = make_run_tool({"subfinder": "", "httpx": hx, "nuclei": vuln})
    results = RC.orchestrate(
        _cfg(depth="full", mode="owasp", active={"enabled": True, "nuclei": True}),
        run_tool=rt, whicher=_whicher_all)
    nf = [r for r in results if r.get("kind") == "recon-finding"]
    assert nf and nf[0]["severity"] == "critical"
    assert "CVE-2026-9999" in nf[0]["cve"]
    # mode owasp => severity list memuat 'low'
    ncall = [c for c in rt.calls if "nuclei" in c[0]][0]
    assert "low,medium,high,critical" in ncall


# ── binari tidak terpasang → skip, tidak crash ───────────────────────────────
def test_missing_binaries_graceful():
    rt = make_run_tool({})
    results = RC.orchestrate(
        _cfg(depth="full", active={"enabled": True, "naabu": True, "nuclei": True}),
        run_tool=rt, whicher=_whicher_none)
    assert rt.calls == []                      # tak ada binari dipanggil
    assert all(r["ok"] for r in results)       # semua jadi skip/lulus
    assert any("tidak terpasang" in (r.get("note") or "") for r in results)


# ── failures hanya menghitung temuan nyata (bukan info) ──────────────────────
def test_failures_excludes_info():
    rows = [{"ok": False, "severity": "info"}, {"ok": False, "severity": "high"},
            {"ok": True, "severity": "passed"}, {"ok": False, "severity": "medium"}]
    assert RC._failures(rows) == 2


# ── amass digabung dengan subfinder ──────────────────────────────────────────
def test_amass_merged_with_subfinder():
    rt = make_run_tool({"subfinder": "a.contoh.example\n",
                        "amass": "b.contoh.example\nc.contoh.example\n", "httpx": ""})
    res, _ = RC.phase_osint(_cfg(), rt, _whicher_all)
    sub = [r for r in res if r["kind"] == "recon-subdomain"
           and "subdomain enumeration" in r["check"]][0]
    assert "subfinder+amass" in sub["note"]
    assert "a.contoh.example" in sub["note"] and "b.contoh.example" in sub["note"]


# ── gau/waybackurls → ringkasan URL historis (pasif) ─────────────────────────
def test_historical_urls_summary():
    rt = make_run_tool({"subfinder": "", "httpx": "",
                        "gau": "https://contoh.example/a\nhttps://contoh.example/b\n",
                        "waybackurls": "https://contoh.example/b\nhttps://contoh.example/c\n"})
    res, alive = RC.phase_osint(_cfg(), rt, _whicher_all)
    hist = [r for r in res if "URL historis" in r["check"]]
    assert hist and "gau+waybackurls" in hist[0]["note"]
    # 3 URL unik (a,b,c) ikut masuk pool untuk nuclei
    assert any("/c" in u for u in alive)


# ── trufflehog: secret di code_path (pasif) ──────────────────────────────────
def test_trufflehog_secret_verified_high():
    th = json.dumps({"DetectorName": "AWS", "Verified": True,
                     "SourceMetadata": {"Data": {"Filesystem": {"file": "app/cfg.py"}}}})
    rt = make_run_tool({"trufflehog": th})
    res = RC.phase_secrets(_cfg(code_path="."), rt, _whicher_all)
    sec = [r for r in res if r["kind"] == "leaked-secret"]
    assert sec and sec[0]["severity"] == "high" and "app/cfg.py" in sec[0]["url"]


def test_secrets_skipped_without_code_path():
    rt = make_run_tool({})
    assert RC.phase_secrets(_cfg(), rt, _whicher_all) == []   # tanpa code_path: lewati diam-diam


# ── katana & ffuf hanya jalan saat di-gate aktif ─────────────────────────────
def test_katana_ffuf_gated_off():
    rt = make_run_tool({"subfinder": "", "httpx": ""})
    RC.orchestrate(_cfg(depth="full", active={"enabled": False}), run_tool=rt,
                   whicher=_whicher_all)
    assert not any("katana" in c[0] or "ffuf" in c[0] for c in rt.calls)


def test_ffuf_needs_wordlist():
    rt = make_run_tool({})
    res = RC.phase_fuzz(_cfg(), [], rt, _whicher_all)   # ffuf ada tapi wordlist kosong
    assert res[0]["ok"] and "wordlist" in res[0]["note"]


def test_ffuf_parses_hits():
    out = json.dumps({"results": [{"url": "https://contoh.example/admin", "status": 200},
                                  {"url": "https://contoh.example/old", "status": 403}]})
    rt = make_run_tool({"ffuf": out})
    res = RC.phase_fuzz(_cfg(ffuf_wordlist="/wl.txt"), ["https://contoh.example"], rt,
                        _whicher_all)
    hit = [r for r in res if "/admin" in r["check"]]
    assert hit and hit[0]["severity"] == "medium"


def test_katana_expands_urls():
    out = "https://contoh.example/x\nhttps://contoh.example/y\n"
    rt = make_run_tool({"katana": out})
    urls, res = RC.phase_crawl(_cfg(), ["https://contoh.example"], rt, _whicher_all)
    assert "https://contoh.example/x" in urls and res and "crawl katana" in res[0]["check"]


# ── load_config: tanpa file tetap jalan bila target di-override ───────────────
def test_load_config_no_file():
    cfg = RC.load_config(str(ROOT / "tests" / "recon" / "tidak-ada.yml"),
                         {"target": "x.example", "depth": None, "mode": None})
    assert cfg["target"] == "x.example"
