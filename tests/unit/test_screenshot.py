"""Unit test helper screenshot — tanpa browser nyata (sync_playwright di-stub)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SS = _load("_screenshot_t", "tests/_screenshot.py")


# ── stub Playwright ───────────────────────────────────────────────────────────
class FakePage:
    def __init__(self):
        self.goto_url = None

    def goto(self, url, timeout=None):
        self.goto_url = url

    def screenshot(self, path=None, full_page=False, clip=None):
        Path(path).write_bytes(b"\x89PNG\r\n")

    def locator(self, sel):
        return self

    @property
    def first(self):
        return self


class FakeCtx:
    def __init__(self):
        self.cookies = None

    def add_cookies(self, c):
        self.cookies = c

    def new_page(self):
        return FakePage()


class FakeBrowser:
    def __init__(self):
        self.closed = False
        self.headers = None

    def new_context(self, extra_http_headers=None):
        self.headers = extra_http_headers
        return FakeCtx()

    def close(self):
        self.closed = True


class FakePW:
    def __call__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    class _Chromium:
        def launch(self):
            return FakeBrowser()

    @property
    def chromium(self):
        return FakePW._Chromium()


# ── capture_page ──────────────────────────────────────────────────────────────
def test_capture_page_writes_file(tmp_path):
    rel = SS.capture_page(FakePage(), tmp_path, "admin/users", prefix="authz")
    assert rel == "evidence/authz_admin_users.png"
    assert (tmp_path / "evidence" / "authz_admin_users.png").exists()


def test_capture_page_no_reports_dir():
    assert SS.capture_page(FakePage(), None, "x") == ""


# ── capture_url (dengan stub) ────────────────────────────────────────────────
def test_capture_url_with_stub(tmp_path):
    rel = SS.capture_url("https://x.example/admin", tmp_path, "admin", prefix="authz",
                         headers={"Authorization": "Bearer t"}, _pw=FakePW())
    assert rel == "evidence/authz_admin.png"
    assert (tmp_path / "evidence" / "authz_admin.png").exists()


def test_capture_url_graceful_without_playwright(tmp_path):
    # _pw=None → coba import playwright; di CI tak terpasang → "" (graceful, tak crash)
    out = SS.capture_url("https://x.example", tmp_path, "t")
    assert out == "" or out.startswith("evidence/")   # kosong bila playwright absen


def test_capture_url_no_url(tmp_path):
    assert SS.capture_url("", tmp_path, "t", _pw=FakePW()) == ""


# ── cookies_from_requests ─────────────────────────────────────────────────────
def test_cookies_from_requests():
    class _C:
        def __init__(self, n, v, d="x.example", p="/"):
            self.name, self.value, self.domain, self.path = n, v, d, p

    class _Sess:
        cookies = [_C("session", "abc")]

    out = SS.cookies_from_requests(_Sess(), "https://x.example/a")
    assert out and out[0]["name"] == "session" and out[0]["value"] == "abc"


# ── authz: _evidence_shot mati secara default ────────────────────────────────
def test_authz_shot_disabled_by_default():
    AZ = _load("authz_t", "tests/authz-matrix/run_authz_matrix.py")

    class _S:
        bearer = "t"
        sess = None
    # shot_cfg.enabled=False → langsung "" tanpa menyentuh browser
    assert AZ._evidence_shot({"enabled": False}, "/tmp", _S(), "GET",
                             "https://x.example/a", None, "tag") == ""
