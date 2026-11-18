"""Unit test dukungan auth Sanctum (tests/_sanctum.py) + integrasinya di runner
authz — tanpa jaringan. Memakai session tiruan yang merekam panggilan.

Jalankan dari root repo: pytest -q
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

import _sanctum as S  # noqa: E402


class FakeJar:
    def __init__(self):
        self._d = {}

    def get(self, name):
        return self._d.get(name)


class FakeResp:
    def __init__(self, status):
        self.status_code = status

    def json(self):
        return {}


class FakeSession:
    """Meniru requests.Session secukupnya untuk menguji alur Sanctum."""

    def __init__(self, csrf_value="tok%3Dval%3D%3D"):
        self.cookies = FakeJar()
        self.calls = []
        self._csrf_value = csrf_value

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, dict(headers or {})))
        if "csrf-cookie" in url:
            self.cookies._d["XSRF-TOKEN"] = self._csrf_value
        return FakeResp(204)

    def request(self, method, url, json=None, headers=None, timeout=None,
                allow_redirects=None):
        self.calls.append((method, url, dict(headers or {}), json))
        return FakeResp(200)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


# --- helper murni ---

def test_stateful_headers():
    h = S.stateful_headers("http://localhost:18880")
    assert h == {"Origin": "http://localhost:18880",
                 "Referer": "http://localhost:18880/"}
    assert S.stateful_headers("") == {}


def test_xsrf_header_url_decoded():
    sess = FakeSession()
    sess.cookies._d["XSRF-TOKEN"] = "tok%3Dval%3D%3D"      # ter-URL-encode di cookie
    assert S.xsrf_header(sess) == {"X-XSRF-TOKEN": "tok=val=="}


def test_xsrf_header_absent():
    assert S.xsrf_header(FakeSession()) == {}              # belum ada cookie


def test_prime_csrf_hits_endpoint_with_origin():
    sess = FakeSession()
    headers = S.prime_csrf(sess, "http://t", {"origin": "http://t"})
    assert sess.calls[0][0] == "GET"
    assert sess.calls[0][1] == "http://t/sanctum/csrf-cookie"
    assert sess.calls[0][2]["Origin"] == "http://t"
    assert headers == {"Origin": "http://t", "Referer": "http://t/"}


def test_prime_csrf_custom_path():
    sess = FakeSession()
    S.prime_csrf(sess, "http://t", {"origin": "http://t", "csrf_path": "/csrf"})
    assert sess.calls[0][1] == "http://t/csrf"


# --- integrasi dengan runner authz ---

def _load_authz():
    path = ROOT / "tests" / "authz-matrix" / "run_authz_matrix.py"
    spec = importlib.util.spec_from_file_location("run_authz_matrix", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AZ = _load_authz()
SANCTUM = {"enabled": True, "origin": "http://t"}
LOGIN = {"method": "POST", "path": "/api/login",
         "body": {"email": "{username}", "password": "{password}"}}
CREDS = {"username": "admin@t", "password": "pw"}


def test_session_login_primes_csrf_then_posts_with_xsrf():
    s = AZ.Session("admin", CREDS, "http://t", sanctum=SANCTUM)
    s.sess = FakeSession()
    s.login(LOGIN, CREDS, "session_cookie")
    # Panggilan 1: csrf-cookie. Panggilan 2: login dengan X-XSRF-TOKEN + Origin.
    assert s.sess.calls[0][1].endswith("/sanctum/csrf-cookie")
    method, url, headers, body = s.sess.calls[1]
    assert method == "POST" and url == "http://t/api/login"
    assert headers["Origin"] == "http://t"
    assert headers["X-XSRF-TOKEN"] == "tok=val=="
    assert body == {"email": "admin@t", "password": "pw"}  # template terisi


def test_session_request_carries_sanctum_headers():
    s = AZ.Session("admin", CREDS, "http://t", sanctum=SANCTUM)
    s.sess = FakeSession()
    s.login(LOGIN, CREDS, "session_cookie")
    s.request("GET", "/api/users")
    _, url, headers = s.sess.calls[-1][:3]
    assert url == "http://t/api/users"
    assert headers["X-XSRF-TOKEN"] == "tok=val==" and headers["Origin"] == "http://t"


def test_forged_header_overrides_sanctum_header():
    # Header uji (X-Auth-* palsu) harus menimpa, bukan ditimpa, header Sanctum.
    s = AZ.Session("low", CREDS, "http://t", sanctum=SANCTUM)
    s.sess = FakeSession()
    s.login(LOGIN, CREDS, "session_cookie")
    s.request("GET", "/api/users", extra_headers={"X-Auth-Roles": "admin"})
    headers = s.sess.calls[-1][2]
    assert headers["X-Auth-Roles"] == "admin"
    assert headers["X-XSRF-TOKEN"] == "tok=val=="   # tetap ada


def test_no_sanctum_means_no_extra_headers():
    s = AZ.Session("admin", CREDS, "http://t")       # tanpa sanctum
    s.sess = FakeSession()
    s.login(LOGIN, CREDS, "session_cookie")
    # Tak ada panggilan csrf-cookie; login langsung POST.
    assert all("csrf-cookie" not in c[1] for c in s.sess.calls)
    login_headers = s.sess.calls[0][2]
    assert "X-XSRF-TOKEN" not in login_headers and "Origin" not in login_headers
