"""Unit tests for the disposable test-account fixture: fake HTTP session, no network."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
FX = _load("_fixture_t", "tests/_fixture.py")
RB = _load("_rollback_t", "tests/_rollback.py")

BASE = "http://t.example"
CFG = {
    "admin_auth": {"sanctum": {"enabled": True, "origin": BASE},
                   "login": {"method": "POST", "path": "/api/login",
                             "body": {"email": "adm", "password": "x"}}},
    "email_template": "kit-probe-{rand}@contoh.example",
    "create": {"method": "POST", "path": "/api/users",
               "body": {"name": "Kit {rand}", "email": "{email}", "password": "{password}",
                        "roles": ["rendah"]}, "id_path": "data.id"},
    "delete": {"method": "DELETE", "path": "/api/users/{id}"},
    "login": {"method": "POST", "path": "/api/login",
              "body": {"email": "{email}", "password": "{password}"}},
}


class _Resp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._b, self.text = status, body, text or json.dumps(body or {})
        self.headers = {}

    def json(self):
        return self._b if self._b is not None else {}


class _Cookies(dict):
    pass


class FakeHttp:
    """Records every request; behavior is set via `routes` per (method, path)."""
    calls = []
    routes = {}

    def __init__(self):
        self.cookies = _Cookies({"XSRF-TOKEN": "tok"})
        self.headers = {}

    def get(self, url, **kw):
        FakeHttp.calls.append(("GET", url, None))
        return _Resp(204)

    def request(self, method, url, json=None, headers=None, **kw):       # noqa: A002
        path = url.replace(BASE, "")
        FakeHttp.calls.append((method, path, json))
        h = FakeHttp.routes.get((method, path)) or FakeHttp.routes.get((method, path.rsplit("/", 1)[0] + "/*"))
        return h(json) if callable(h) else _Resp(200, {"data": {"id": "u1"}})


@pytest.fixture(autouse=True)
def _reset():
    FakeHttp.calls, FakeHttp.routes = [], {}
    yield


# --- templating ---
def test_render_is_recursive_and_keeps_unknown_placeholders():
    v = {"email": "a@x", "password": "pw", "id": "7", "rand": "r"}
    assert FX.render({"a": ["{email}", {"b": "{password}-{id}"}], "c": "{tak-dikenal}"}, v) == \
        {"a": ["a@x", {"b": "pw-7"}], "c": "{tak-dikenal}"}


def test_dig_and_strong_password():
    assert FX.dig({"data": {"id": "z"}}, "data.id") == "z"
    assert FX.dig({"data": 1}, "data.id") is None
    p = FX.strong_password()
    assert len(p) >= 12 and any(c.isupper() for c in p) and any(c.isdigit() for c in p)
    assert FX.strong_password() != p


# --- lifecycle ---
def test_create_login_delete_and_journal(tmp_path):
    with FX.DisposableAccount(BASE, CFG, tmp_path, tmp_path / "c.yml", http=FakeHttp) as acc:
        assert acc.id == "u1" and acc.email.startswith("kit-probe-") and acc.password
        create = [c for c in FakeHttp.calls if c[0] == "POST" and c[1] == "/api/users"][0]
        assert create[2]["email"] == acc.email and create[2]["password"] == acc.password
        pend = RB.pending(tmp_path)                       # journal is written right after creation
        assert len(pend) == 1 and pend[0]["action"]["path"] == "/api/users/u1"
        assert pend[0]["action"]["fixture_config"].endswith("c.yml")
        s, r = acc.new_session()
        assert r.status_code == 200
    assert ("DELETE", "/api/users/u1", None) in FakeHttp.calls     # deleted on exit
    assert RB.pending(tmp_path) == []                              # journal entry marked done


def test_account_deleted_even_when_test_raises(tmp_path):
    with pytest.raises(ValueError):
        with FX.DisposableAccount(BASE, CFG, tmp_path, None, http=FakeHttp):
            raise ValueError("uji gagal")
    assert any(c[0] == "DELETE" for c in FakeHttp.calls)


def test_login_as_fictional_identity_uses_that_email():
    acc = FX.DisposableAccount(BASE, CFG, None, None, http=FakeHttp)
    acc.login_as("nobody@x", "salah", None)
    last = FakeHttp.calls[-1]
    assert last[0] == "POST" and last[1] == "/api/login"
    assert last[2] == {"email": "nobody@x", "password": "salah"}


def test_failed_creation_leaves_no_journal(tmp_path):
    FakeHttp.routes[("POST", "/api/users")] = lambda b: _Resp(422, {"message": "x"})
    with pytest.raises(RuntimeError, match="membuat akun uji gagal"):
        with FX.DisposableAccount(BASE, CFG, tmp_path, None, http=FakeHttp):
            pass
    assert RB.pending(tmp_path) == []
    assert not any(c[0] == "DELETE" for c in FakeHttp.calls)


def test_missing_id_reports_email_for_manual_cleanup(tmp_path):
    FakeHttp.routes[("POST", "/api/users")] = lambda b: _Resp(201, {"data": {}})
    with pytest.raises(RuntimeError, match="id tidak ditemukan"):
        with FX.DisposableAccount(BASE, CFG, tmp_path, None, http=FakeHttp):
            pass


def test_failed_delete_stays_in_journal(tmp_path):
    FakeHttp.routes[("DELETE", "/api/users/*")] = lambda b: _Resp(500)
    with FX.DisposableAccount(BASE, CFG, tmp_path, None, http=FakeHttp):
        pass
    assert len(RB.pending(tmp_path)) == 1                           # still recorded for rollback


def test_restore_entry_deletes_with_admin_session(tmp_path, monkeypatch):
    cfgfile = tmp_path / "m.yml"
    import yaml
    cfgfile.write_text(yaml.safe_dump({"base_url": BASE, "fixture": CFG}), encoding="utf-8")
    entry = {"action": {"method": "DELETE", "path": "/api/users/u9",
                        "fixture_config": str(cfgfile)}}
    ok, note = FX.restore_entry(entry, http=FakeHttp)
    assert ok and note == "dihapus"
    assert ("DELETE", "/api/users/u9", None) in FakeHttp.calls
    assert FX.restore_entry({"action": {"fixture_config": str(tmp_path / "tidak-ada.yml")}},
                            http=FakeHttp)[0] is False
