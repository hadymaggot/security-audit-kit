"""Unit test modul ssrf — canary asli pada loopback, target palsu (tanpa jaringan eksternal)."""
import importlib.util
import json
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SS = _load("run_ssrf_t", "tests/ssrf/run_ssrf.py")
RP = _load("report_ss_t", "report.py")
WHERE = "GET http://t/api/fetch (param url)"


# ── varian payload ──────────────────────────────────────────────────────────
def test_ip_variants():
    v = dict(SS.ip_variants("127.0.0.1"))
    assert v["desimal"] == "2130706433" and v["heksadesimal"] == "0x7f000001"
    assert v["oktal"] == "0177.00.00.01" and v["IPv6-mapped"] == "[::ffff:127.0.0.1]"
    assert SS.ip_variants("contoh.example") == [] and SS.ip_variants("::1") == []


def test_build_variants_lengkap_dan_tanpa_varian():
    full = dict(SS.build_variants("http://10.0.0.5:18999", "TKN", True))
    assert full["langsung"] == "http://10.0.0.5:18999/TKN"
    assert full["IP desimal"] == "http://167772165:18999/TKN"
    assert full["userinfo (@)"] == "http://allowed.example@10.0.0.5:18999/TKN"
    assert full["redirect"] == "http://10.0.0.5:18999/redir/TKN"
    only = SS.build_variants("http://10.0.0.5:18999", "TKN", False)
    assert [n for n, _ in only] == ["langsung"]
    hostname = [n for n, _ in SS.build_variants("http://host.docker.internal:18999", "T", True)]
    assert hostname == ["langsung", "userinfo (@)", "redirect"]          # bukan IPv4 -> tanpa varian IP


# ── evaluasi ────────────────────────────────────────────────────────────────
def test_evaluate_tanpa_hit_lolos():
    r = SS.evaluate("fetch", "langsung", "u", "T", [], WHERE)
    assert r["ok"] is True and r["kind"] == "ssrf"


def test_evaluate_hit_langsung_gagal():
    r = SS.evaluate("fetch", "langsung", "u", "T",
                    [{"path": "/T", "ua": "Guzzle/7", "from": "10.0.0.9"}], WHERE)
    assert r["ok"] is False and "SSRF terkonfirmasi" in r["note"] and "Guzzle/7" in r["note"]


def test_evaluate_redirect_hop2_dan_hop1_saja():
    both = SS.evaluate("f", "redirect", "u", "T", [{"path": "/redir/T"}, {"path": "/hop2/T"}], WHERE)
    assert both["ok"] is False and "hop kedua" in both["note"]
    only1 = SS.evaluate("f", "redirect", "u", "T", [{"path": "/redir/T"}], WHERE)
    assert only1["ok"] is False and "redirect tidak diikuti" in only1["note"]
    assert SS.evaluate("f", "redirect", "u", "T", [], WHERE)["ok"] is True


# ── canary asli ─────────────────────────────────────────────────────────────
def test_canary_mencatat_hit_dan_redirect():
    c = SS.Canary("127.0.0.1", 0).start()
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{c.port}/tokenA", timeout=5).read()
        urllib.request.urlopen(f"http://127.0.0.1:{c.port}/redir/tokenB", timeout=5).read()
        assert [h["path"] for h in c.hits_for("tokenA")] == ["/tokenA"]
        assert [h["path"] for h in c.hits_for("tokenB")] == ["/redir/tokenB", "/hop2/tokenB"]
        assert c.hits_for("tidak-ada") == []
    finally:
        c.stop()


# ── run end-to-end dengan target palsu ──────────────────────────────────────
class FakeTarget:
    """Meniru endpoint 'ambil URL': mode vuln menembak URL; mode aman memblokir alamat privat."""

    def __init__(self, mode):
        self.mode, self.verify, self.headers, self.cookies = mode, True, {}, {}
        self.calls = []

    @staticmethod
    def _client_url(target):
        """Meniru klien HTTP nyata: buang userinfo ('user@') lalu hubungi host sebenarnya."""
        from urllib.parse import urlparse
        u = urlparse(target)
        host = f"[{u.hostname}]" if ":" in (u.hostname or "") else u.hostname
        return f"{u.scheme}://{host}:{u.port}{u.path}" if u.port else f"{u.scheme}://{host}{u.path}"

    def request(self, method, url, params=None, json=None, data=None, headers=None, **kw):  # noqa: A002
        target = (params or json or data or {}).get("url")
        self.calls.append((method, url, target))

        class R:
            status_code = 200
        if self.mode == "vuln" and target:
            try:
                urllib.request.urlopen(self._client_url(target), timeout=3).read()   # menembak URL
            except Exception:  # noqa: BLE001
                pass
        elif self.mode == "vuln-no-redirect" and target:
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            try:
                urllib.request.build_opener(NoRedir).open(target, timeout=3).read()
            except Exception:  # noqa: BLE001
                pass
        return R()


CFG = {"base_url": "http://t", "variants": True,
       "callback": {"bind": "127.0.0.1", "wait_seconds": 0.3},
       "targets": [{"name": "fetch", "method": "GET", "path": "/api/fetch", "param": "url"}]}


def test_run_server_rentan_terdeteksi():
    rows = SS.run(CFG, sess=FakeTarget("vuln"))
    by = {r["check"]: r for r in rows}
    assert by["ssrf: fetch — langsung"]["ok"] is False
    assert by["ssrf: fetch — redirect"]["ok"] is False and "hop kedua" in by["ssrf: fetch — redirect"]["note"]
    assert by["ssrf: fetch — userinfo (@)"]["ok"] is False
    assert all(r["status"] == 200 for r in rows)


def test_run_server_aman_tidak_menembak():
    rows = SS.run(CFG, sess=FakeTarget("secure"))
    assert rows and all(r["ok"] for r in rows)


def test_run_server_rentan_tapi_tak_ikut_redirect():
    rows = SS.run(CFG, sess=FakeTarget("vuln-no-redirect"))
    by = {r["check"]: r for r in rows}
    assert by["ssrf: fetch — langsung"]["ok"] is False
    assert "redirect tidak diikuti" in by["ssrf: fetch — redirect"]["note"]


def test_send_payload_lokasi_query_json_form():
    s = FakeTarget("secure")
    for loc in ("query", "json", "form"):
        SS.send_payload(s, "http://t", {"path": "/p", "param": "url", "location": loc,
                                        "method": "POST", "extra": {"a": 1}}, "http://x/y")
    assert [c[2] for c in s.calls] == ["http://x/y"] * 3


def test_endpoint_tak_merespons_di_skip():
    class Down:
        verify, headers, cookies = True, {}, {}

        def request(self, *a, **k):
            raise OSError("down")
    rows = SS.run({**CFG, "variants": False}, sess=Down())
    assert len(rows) == 1 and rows[0]["ok"] is True and "skip" in rows[0]["note"]


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_ssrf(tmp_path):
    rows = [SS.evaluate("fetch", "langsung", "u", "T", [{"path": "/T", "ua": "x", "from": "1.2.3.4"}],
                        WHERE)]
    (tmp_path / "ssrf.json").write_text(json.dumps(
        {"module": "ssrf", "failures": 1, "results": rows}), encoding="utf-8")
    failed = [x for x in RP.collect(tmp_path) if not x["passed"]]
    assert failed and failed[0]["kind"] == "ssrf" and failed[0]["severity"] == "high"
    assert RP.cvss_for("ssrf", "high")[0] == 8.5 and "ssrf" in RP.KIND_LABEL
