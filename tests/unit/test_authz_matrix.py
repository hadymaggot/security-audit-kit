"""Unit tests for the authz runner: per-endpoint base_url and list-shaped forged_headers.

No network: requests.Session is replaced by a fake that answers per URL.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest
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
    """Fake requests.Session: status comes from the {url: status} table, default 403."""

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
    # Legacy format: a dict without enabled: true is still ignored.
    assert AZ.forged_blocks({"as_role": "low"}) == []
    assert AZ.forged_blocks({"enabled": True, "as_role": "low"}) == [
        {"enabled": True, "as_role": "low"}]
    assert AZ.forged_blocks(None) == []


def test_forged_blocks_list_default_enabled():
    blocks = AZ.forged_blocks([
        {"as_role": "low"},
        {"as_role": "anon", "enabled": False},
        {"inject": {}},                       # no as_role -> dropped
    ])
    assert [b["as_role"] for b in blocks] == ["low"]


def test_example_configs_parse_and_have_forged_blocks():
    # Example configs must stay parseable by the runner (no silent breakage).
    ex = ROOT / "tests" / "authz-matrix"
    plain = yaml.safe_load((ex / "authz_matrix.example.yml").read_text(encoding="utf-8"))
    traefik = yaml.safe_load(
        (ex / "authz_matrix.traefik-sanctum.example.yml").read_text(encoding="utf-8"))
    assert len(AZ.forged_blocks(plain.get("forged_headers"))) == 1
    blocks = AZ.forged_blocks(traefik.get("forged_headers"))
    assert [b["as_role"] for b in blocks] == ["low_user", "anon"]
    assert any(ep.get("base_url") for ep in traefik["endpoints"])   # bypass example
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


# --- main(): gateway + direct port in one matrix ---

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
    assert "[forged] /api/admin" in labels                       # via gateway
    assert "[forged] http://svc:8002/api/admin" in labels        # gateway bypass


def test_main_flags_direct_port_forged_bypass(tmp_path, monkeypatch):
    # Service trusts raw X-Auth-* on the direct port -> must be a finding.
    rc, res = _run(tmp_path, monkeypatch, {("GET", "http://svc:8002/api/admin"): 200})
    assert rc == 1
    bad = {r["endpoint"] for r in res if not r["ok"]}
    assert "[forged] http://svc:8002/api/admin" in bad
    assert "admin langsung ke service" in bad
    assert "[forged] /api/admin" not in bad                      # gateway stays safe


# --- login: static token and HTTP 429 ---

class _LoginResp:
    def __init__(self, status, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body or {}

    def json(self):
        return self._body


class _LoginSess:
    cookies = _Jar()

    def __init__(self, seq):
        self.seq = list(seq)
        self.calls = 0

    def request(self, method, url, json=None, headers=None, timeout=None, allow_redirects=None):
        self.calls += 1
        return self.seq.pop(0)


_LOGIN = {"path": "/api/login", "body": {"u": "{username}", "p": "{password}"}, "token_field": "token"}


def test_login_static_token_sends_no_request():
    s = AZ.Session("r", {}, "http://gw")
    s.sess = _LoginSess([])
    s.login(_LOGIN, {"username": "x", "password": "y", "token": "abc"}, "bearer")
    assert s.bearer == "abc" and s.sess.calls == 0


def test_login_waits_for_retry_after_on_429(monkeypatch):
    sleeps = []
    monkeypatch.setattr(AZ.time, "sleep", sleeps.append)
    s = AZ.Session("r", {}, "http://gw")
    s.sess = _LoginSess([_LoginResp(429, {"Retry-After": "7"}), _LoginResp(200, body={"token": "t"})])
    s.login(_LOGIN, {"username": "x", "password": "y"}, "bearer")
    assert s.bearer == "t" and sleeps == [9]                   # Retry-After 7 s + 2 s margin


def test_login_429_retry_can_be_disabled(monkeypatch):
    monkeypatch.setattr(AZ.time, "sleep", lambda s: pytest.fail("must not wait"))
    s = AZ.Session("r", {}, "http://gw")
    s.sess = _LoginSess([_LoginResp(429, {"Retry-After": "7"})])
    with pytest.raises(RuntimeError, match="HTTP 429"):
        s.login({**_LOGIN, "retry_429": False}, {"username": "x", "password": "y"}, "bearer")
