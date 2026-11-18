"""Unit test runner authz: base_url per endpoint & forged_headers berbentuk list.

Tanpa jaringan — requests.Session diganti tiruan yang menjawab per URL.
"""
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load_authz():
    path = ROOT / "tests" / "authz-matrix" / "run_authz_matrix.py"
    spec = importlib.util.spec_from_file_location("run_authz_matrix_t", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AZ = _load_authz()


class _Resp:
    def __init__(self, status):
        self.status_code = status


class _Jar(dict):
    pass


class _Sess:
    """requests.Session tiruan: status ditentukan tabel {url: status}, default 403."""

    table = {}
    calls = []

    def __init__(self):
        self.cookies = _Jar()

    def get(self, url, headers=None, timeout=None):
        _Sess.calls.append(("GET", url, dict(headers or {})))
        return _Resp(204)

    def request(self, method, url, json=None, headers=None, timeout=None,
                allow_redirects=None):
        _Sess.calls.append((method, url, dict(headers or {})))
        return _Resp(_Sess.table.get((method, url), 403))


# --- forged_blocks ---

def test_forged_blocks_single_dict_needs_enabled():
    # Format lama: dict tanpa enabled: true tetap diabaikan.
    assert AZ.forged_blocks({"as_role": "low"}) == []
    assert AZ.forged_blocks({"enabled": True, "as_role": "low"}) == [
        {"enabled": True, "as_role": "low"}]
    assert AZ.forged_blocks(None) == []


def test_forged_blocks_list_default_enabled():
    blocks = AZ.forged_blocks([
        {"as_role": "low"},
        {"as_role": "anon", "enabled": False},
        {"inject": {}},                       # tanpa as_role → dibuang
    ])
    assert [b["as_role"] for b in blocks] == ["low"]


def test_example_configs_parse_and_have_forged_blocks():
    # Contoh config harus tetap terbaca runner (tak diam-diam rusak).
    ex = ROOT / "tests" / "authz-matrix"
    plain = yaml.safe_load((ex / "authz_matrix.example.yml").read_text(encoding="utf-8"))
    traefik = yaml.safe_load(
        (ex / "authz_matrix.traefik-sanctum.example.yml").read_text(encoding="utf-8"))
    assert len(AZ.forged_blocks(plain.get("forged_headers"))) == 1
    blocks = AZ.forged_blocks(traefik.get("forged_headers"))
    assert [b["as_role"] for b in blocks] == ["user_rendah", "anon"]
    assert any(ep.get("base_url") for ep in traefik["endpoints"])   # contoh bypass
    for cfg in (plain, traefik):
        roles = set(cfg["auth"]["roles"])
        for ep in cfg["endpoints"]:
            assert set(ep["expect"]) <= roles, ep["name"]
        for b in AZ.forged_blocks(cfg.get("forged_headers")):
            assert b["as_role"] in roles


# --- Session.request: base_url override ---

def test_request_base_url_override():
    s = AZ.Session("anon", {"anonymous": True}, "http://gw")
    s.sess = _Sess()
    _Sess.calls = []
    s.request("GET", "/api/x")
    s.request("GET", "/api/x", base_url="http://svc:8002/")
    assert [c[1] for c in _Sess.calls] == ["http://gw/api/x", "http://svc:8002/api/x"]


# --- main(): gateway + port langsung dalam satu matriks ---

CFG = {
    "base_url": "http://gw",
    "auth": {
        "mode": "session_cookie",
        "login": {"method": "POST", "path": "/api/login",
                  "body": {"email": "{username}", "password": "{password}"}},
        "roles": {"low": {"username": "u", "password": "p"},
                  "anon": {"anonymous": True}},
    },
    "endpoints": [
        {"name": "admin via gateway", "path": "/api/admin",
         "expect": {"low": "deny", "anon": "deny"}},
        {"name": "admin langsung ke service", "path": "/api/admin",
         "base_url": "http://svc:8002", "expect": {"anon": "deny"}},
    ],
    "forged_headers": [
        {"as_role": "low", "inject": {"X-Auth-Roles": "admin"},
         "endpoints": [{"path": "/api/admin"}]},
        {"as_role": "anon", "base_url": "http://svc:8002",
         "inject": {"X-Auth-Roles": "admin"},
         "endpoints": [{"path": "/api/admin"}]},
    ],
}


def _run(tmp_path, monkeypatch, table):
    cfg = tmp_path / "m.yml"
    cfg.write_text(yaml.safe_dump(CFG), encoding="utf-8")
    out = tmp_path / "out.json"
    _Sess.table = {("POST", "http://gw/api/login"): 204, **table}
    _Sess.calls = []
    monkeypatch.setattr(AZ.requests, "Session", _Sess)
    monkeypatch.setattr(sys, "argv", ["x", "--config", str(cfg), "--json", str(out)])
    rc = AZ.main()
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_main_all_denied_passes(tmp_path, monkeypatch):
    rc, res = _run(tmp_path, monkeypatch, {})
    assert rc == 0 and all(r["ok"] for r in res)
    hit = {c[1] for c in _Sess.calls}
    assert "http://svc:8002/api/admin" in hit and "http://gw/api/admin" in hit
    labels = [r["endpoint"] for r in res]
    assert "[forged] /api/admin" in labels                       # lewat gateway
    assert "[forged] http://svc:8002/api/admin" in labels        # bypass gateway


def test_main_flags_direct_port_forged_bypass(tmp_path, monkeypatch):
    # Service mempercayai X-Auth-* mentah di port langsung → harus jadi temuan.
    rc, res = _run(tmp_path, monkeypatch, {("GET", "http://svc:8002/api/admin"): 200})
    assert rc == 1
    bad = {r["endpoint"] for r in res if not r["ok"]}
    assert "[forged] http://svc:8002/api/admin" in bad
    assert "admin langsung ke service" in bad
    assert "[forged] /api/admin" not in bad                      # gateway tetap aman
