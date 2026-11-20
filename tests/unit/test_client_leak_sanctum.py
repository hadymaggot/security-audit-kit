"""Unit tests for Sanctum login in the browser cache probe (client-leak): fake session, no browser."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))


def _load():
    spec = importlib.util.spec_from_file_location("run_client_leak_sn",
                                                  ROOT / "tests" / "client-leak" / "run_client_leak.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CL = _load()
BASE, ORIGIN = "http://t.example", "http://t.example"


class _C:
    def __init__(self, n, v):
        self.name, self.value = n, v


class _Cookies(list):
    def get(self, name):
        return next((c.value for c in self if c.name == name), None)


class _Resp:
    def __init__(self, status=200):
        self.status_code = status


class FakeSession:
    login_status = 200
    calls = []

    def __init__(self):
        self.cookies = _Cookies()

    def get(self, url, **kw):                       # prime_csrf
        FakeSession.calls.append(("GET", url, kw.get("headers")))
        self.cookies.extend([_C("XSRF-TOKEN", "tok%3D"), _C("app-session", "sess1")])
        return _Resp(204)

    def request(self, method, url, json=None, headers=None, **kw):       # noqa: A002
        FakeSession.calls.append((method, url, headers))
        return _Resp(FakeSession.login_status)


@pytest.fixture(autouse=True)
def _reset():
    FakeSession.calls, FakeSession.login_status = [], 200
    yield


CFG = {"auth": {"sanctum": {"enabled": True, "origin": ORIGIN},
                "login": {"method": "POST", "path": "/api/login",
                          "body": {"email": "e@x", "password": "p"}}}}


def test_no_sanctum_no_cookies():
    assert CL.sanctum_cookies({}, BASE, ORIGIN, http=FakeSession) == []
    assert CL.sanctum_cookies({"auth": {"header": "Authorization", "value": "x"}}, BASE, ORIGIN,
                              http=FakeSession) == []
    assert CL.sanctum_cookies({"auth": {"sanctum": {"enabled": False}}}, BASE, ORIGIN,
                              http=FakeSession) == []


def test_sanctum_login_yields_cookies_for_origin():
    cookies = CL.sanctum_cookies(CFG, BASE, ORIGIN, http=FakeSession)
    assert {"name": "app-session", "value": "sess1", "url": ORIGIN} in cookies
    assert any(c["name"] == "XSRF-TOKEN" for c in cookies)
    login = [c for c in FakeSession.calls if c[0] == "POST"][0]
    assert login[1] == BASE + "/api/login"
    assert login[2]["Origin"] == ORIGIN and login[2]["X-XSRF-TOKEN"] == "tok="       # stateful header + CSRF


def test_login_failure_raises():
    FakeSession.login_status = 401
    with pytest.raises(RuntimeError, match="HTTP 401"):
        CL.sanctum_cookies(CFG, BASE, ORIGIN, http=FakeSession)


def test_csrf_only_without_login_block():
    cfg = {"auth": {"sanctum": {"enabled": True, "origin": ORIGIN}}}
    cookies = CL.sanctum_cookies(cfg, BASE, ORIGIN, http=FakeSession)
    assert cookies and not [c for c in FakeSession.calls if c[0] == "POST"]
