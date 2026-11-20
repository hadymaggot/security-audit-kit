"""Unit test modul response-leak — murni, tanpa jaringan."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RL = _load("run_response_leak_t", "tests/response-leak/run_response_leak.py")
RP = _load("report_rl_t", "report.py")
URL = "http://t.example/api/x"


def _rows(body, status=200, probe=False, cfg=None, ctype="application/json"):
    text = body if isinstance(body, str) else json.dumps(body)
    return RL.evaluate_response("ep", "GET", URL, status, text, ctype, cfg or {}, probe)


def _by(rows):
    return {r["check"].split(": ", 1)[1]: r for r in rows}


# ── kunci sensitif ──────────────────────────────────────────────────────────
def test_kunci_sensitif_terdeteksi_tanpa_membocorkan_nilai():
    rows = _by(_rows({"data": {"id": 1, "password": "hunter2-rahasia",
                               "two_factor_secret": "ABCDEF123456"}}))
    r = rows["kunci sensitif"]
    assert r["ok"] is False and r["kind"] == "sensitive-data-exposure"
    assert "data.password" in r["note"] and "data.two_factor_secret" in r["note"]
    assert "hunter2-rahasia" not in r["note"] and "ABCDEF123456" not in r["note"]
    assert "panjang nilai 15" in r["note"]


def test_nilai_kosong_topeng_dan_boolean_diabaikan():
    rows = _by(_rows({"password": "********", "remember_token": None, "secret": "",
                      "api_key": "[REDACTED]", "has_password": True}))
    assert rows["kunci sensitif"]["ok"] is True


def test_metadata_berakhiran_at_atau_flag_diabaikan():
    rows = _by(_rows({"password_changed_at": "2026-01-01", "two_factor_enabled": "yes",
                      "password_expires": "x", "password_policy": "kuat"}))
    assert rows["kunci sensitif"]["ok"] is True


def test_allow_keys_dan_sensitive_keys_config():
    assert _by(_rows({"csrf_secret": "abc"}, cfg={"allow_keys": ["csrf_secret"]}))[
        "kunci sensitif"]["ok"] is True
    r = _by(_rows({"nik": "3171234567890001"}, cfg={"sensitive_keys": ["nik"]}))
    assert r["kunci sensitif"]["ok"] is False


def test_walk_json_array_bersarang():
    rows = _by(_rows({"items": [{"name": "a"}, {"api_key": "k-123456"}]}))
    assert "items[1].api_key" in rows["kunci sensitif"]["note"]


# ── pola secret ─────────────────────────────────────────────────────────────
def test_pola_secret_di_isi_respons():
    rows = _by(_rows({"x": "AKIAABCDEFGHIJKLMNOP"}))
    r = rows["pola secret"]
    assert r["ok"] is False and "AWS access key" in r["note"]
    assert "AKIAABCDEFGHIJKLMNOP" not in r["note"]
    pk = _by(_rows("-----BEGIN RSA PRIVATE KEY-----\nxxx", ctype="text/plain"))
    assert pk["pola secret"]["ok"] is False


# ── debug / verbose ─────────────────────────────────────────────────────────
def test_stack_trace_dan_sql_terdeteksi():
    r = _by(_rows("Stack trace:\n#0 /var/www/app/Http/X.php(10)\nSQLSTATE[42S02]",
                  status=500, ctype="text/html"))["response verbose/debug"]
    assert r["ok"] is False and r["kind"] == "verbose-error"
    assert "stack trace" in r["note"] and "pesan SQL" in r["note"]


def test_halaman_error_bersih_lolos_pada_probe():
    r = _by(_rows({"message": "Not Found"}, status=404, probe=True))["response verbose/debug"]
    assert r["ok"] is True and "tidak expose" in r["note"]
    assert "kunci sensitif" not in _by(_rows({"message": "x"}, status=404, probe=True))


# ── IP internal ─────────────────────────────────────────────────────────────
def test_ip_internal():
    rows = _by(_rows({"upstream": "http://10.1.2.3:8080/api", "x": "172.20.0.5"}))
    assert rows["alamat internal"]["ok"] is False
    assert "10.1.2.3" in rows["alamat internal"]["note"]
    assert "alamat internal" not in _by(_rows({"ip": "8.8.8.8"}))
    assert "alamat internal" not in _by(_rows({"u": "10.1.2.3"}, cfg={"check_internal_ips": False}))


# ── run_checks dengan session palsu ─────────────────────────────────────────
class _Resp:
    def __init__(self, status, body, ctype="application/json"):
        self.status_code, self.text = status, body
        self.headers = {"Content-Type": ctype}


class _Sess:
    def __init__(self, routes):
        self.routes, self.verify, self.headers = routes, True, {}

    def get(self, url, **kw):
        for p, (st, body) in self.routes.items():
            if url.endswith(p):
                return _Resp(st, body)
        return _Resp(404, json.dumps({"message": "Not Found"}))


def test_run_checks_endpoint_dan_probe():
    sess = _Sess({"/api/me": (200, json.dumps({"data": {"name": "A", "password": "xx-yy-zz"}}))})
    cfg = {"base_url": "http://t.example", "endpoints": [{"name": "me", "path": "/api/me"}]}
    res = RL.run_checks(cfg, sess=sess, anon=_Sess({}))
    failed = [r for r in res if not r["ok"]]
    assert len(failed) == 1 and failed[0]["check"] == "me: kunci sensitif"
    assert any(r["check"].startswith("probe error /") and r["ok"] for r in res)


def test_header_stateful_hanya_pada_request_terautentikasi(monkeypatch):
    seen = []

    class _Rec(_Sess):
        def get(self, url, **kw):
            seen.append((self.tag, url, dict(kw.get("headers") or {})))
            return super().get(url, **kw)

    auth, anon = _Rec({}), _Rec({})
    auth.tag, anon.tag = "auth", "anon"
    monkeypatch.setattr(RL, "_session", lambda cfg: (auth, "http://t.example"))
    cfg = {"base_url": "http://t.example", "random_404_probe": False,
           "endpoints": [{"name": "me", "path": "/api/me"},
                         {"name": "pub", "path": "/api/pub", "anonymous": True}]}
    RL.run_checks(cfg, anon=anon)
    by_tag = {(t, u.rsplit("/", 1)[-1]): h for t, u, h in seen}
    assert by_tag[("auth", "me")].get("Origin") == "http://t.example"
    assert "Origin" not in by_tag[("anon", "pub")]


def test_run_checks_endpoint_ditolak_di_skip():
    sess = _Sess({"/api/admin": (403, "{}")})
    cfg = {"base_url": "http://t.example", "random_404_probe": False,
           "endpoints": [{"name": "admin", "path": "/api/admin"}]}
    res = RL.run_checks(cfg, sess=sess, anon=_Sess({}))
    assert res[0]["ok"] is True and "skip" in res[0]["note"]


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_response_leak(tmp_path):
    rows = _rows({"password": "abc-123-xyz", "upstream": "http://10.0.0.9"})
    (tmp_path / "response_leak.json").write_text(json.dumps(
        {"module": "response-leak", "failures": 2, "results": rows}), encoding="utf-8")
    f = RP.collect(tmp_path)
    by = {x["title"]: x for x in f}
    assert by["ep: kunci sensitif"]["kind"] == "sensitive-data-exposure"
    assert by["ep: kunci sensitif"]["severity"] == "high"
    assert by["ep: alamat internal"]["kind"] == "internal-info-leak"
    assert by["ep: alamat internal"]["severity"] == "low"
    assert RP.cvss_for("verbose-error", "medium")[0] == 5.3
    assert {"sensitive-data-exposure", "verbose-error", "internal-info-leak"} <= set(RP.KIND_LABEL)
