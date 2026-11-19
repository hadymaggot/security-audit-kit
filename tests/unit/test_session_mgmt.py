"""Unit test modul session-mgmt — akun dan session palsu, tanpa jaringan."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SM = _load("run_session_mgmt_t", "tests/session-mgmt/run_session_mgmt.py")
RP = _load("report_sm_t", "report.py")
URL = "GET http://t/api/me"


# ── evaluator murni ─────────────────────────────────────────────────────────
def test_row_logout():
    assert SM.row_logout(401, URL)["ok"] is True
    bad = SM.row_logout(200, URL)
    assert bad["ok"] is False and bad["kind"] == "logout-no-invalidate" and "MASIH berlaku" in bad["note"]


def test_row_other_sessions_dan_old_password():
    assert SM.row_other_sessions(401, URL)["ok"] is True
    r = SM.row_other_sessions(200, URL)
    assert r["ok"] is False and r["kind"] == "session-not-revoked"
    assert SM.row_old_password(401, URL)["ok"] is True
    o = SM.row_old_password(200, URL)
    assert o["ok"] is False and o["kind"] == "old-password-accepted"


def test_is_valid_dan_cookie_snapshot():
    assert SM.is_valid(200) and SM.is_valid(204) and not SM.is_valid(401) and not SM.is_valid(None)

    class C:
        def __init__(self, n, v):
            self.name, self.value = n, v
    assert SM.cookie_snapshot([C("a", "1"), C("b", "2")]) == {"a": "1", "b": "2"}
    assert SM.cookie_snapshot({"x": "y"}) == {"x": "y"}


# ── alur dengan akun/session palsu ──────────────────────────────────────────
class World:
    """Model server sederhana: sesi hidup disimpan di set; opsi perilaku bisa diatur."""

    def __init__(self, revoke_on_logout=True, revoke_others=True, old_pw_valid=False):
        self.live, self.n = set(), 0
        self.revoke_on_logout, self.revoke_others, self.old_pw_valid = \
            revoke_on_logout, revoke_others, old_pw_valid


class Sess:
    def __init__(self, world, sid=None):
        self.w, self.cookies = world, {}
        if sid:
            self.cookies["sid"] = sid

    def update_cookies(self, d):
        self.cookies.update(d)

    def request(self, method, url, json=None, headers=None, **kw):       # noqa: A002
        path = url.replace("http://t", "")
        sid = self.cookies.get("sid")

        class R:
            pass
        r = R()
        r.status_code, r.text, r.headers = 200, "{}", {}
        if path == "/api/me":
            r.status_code = 200 if sid in self.w.live else 401
        elif path == "/api/logout":
            if self.w.revoke_on_logout:
                self.w.live.discard(sid)
        elif path == "/api/auth/change-password":
            if self.w.revoke_others:
                self.w.live = {sid}
        return r


class Replay(Sess):
    """Sesi baru tempat cookie disalin (via .cookies.update)."""


class Acc:
    def __init__(self, world):
        self.w, self.email, self.password, self.new_password = world, "e@x", "LAMA", "BARU"

    def new_session(self):
        self.w.n += 1
        sid = f"s{self.w.n}"
        self.w.live.add(sid)

        class R:
            status_code = 200
        return Sess(self.w, sid), R()

    def render(self, obj):
        return obj

    def login_attempt(self, pw, session=None):
        class R:
            status_code = 200 if (pw == self.password and self.w.old_pw_valid) else 401
        return R()

    def login_as(self, email, pw, session=None):
        class R:
            status_code = 200 if pw == self.new_password else 401
        return R()


CFG = {"fixture": {"admin_auth": {"sanctum": {"origin": "http://t"}}},
       "session": {"me_path": "/api/me", "logout": {"path": "/api/logout"},
                   "change_password": {"path": "/api/auth/change-password", "body": {}}}}


def _run(world):
    return SM.run_session_checks(Acc(world), CFG, "http://t", http=lambda: Replay(world),
                                 sleep=lambda s: None)


def test_server_sehat_semua_lolos():
    rows = _run(World())
    by = {r["check"]: r for r in rows}
    assert by["logout: sesi dicabut di server"]["ok"] is True
    assert by["ganti sandi: sesi lain dicabut"]["ok"] is True
    assert by["ganti sandi: sandi lama ditolak"]["ok"] is True
    assert by["ganti sandi: sandi baru diterima"]["ok"] is True
    assert not [r for r in rows if not r["ok"]]


def test_sesi_lain_tak_dicabut_setelah_ganti_sandi():
    rows = _run(World(revoke_others=False))
    bad = [r for r in rows if not r["ok"]]
    assert len(bad) == 1 and bad[0]["kind"] == "session-not-revoked"
    assert bad[0]["check"] == "ganti sandi: sesi lain dicabut"


def test_logout_tak_mencabut_sesi_server():
    rows = _run(World(revoke_on_logout=False))
    bad = [r for r in rows if not r["ok"]]
    assert len(bad) == 1 and bad[0]["kind"] == "logout-no-invalidate"


def test_sandi_lama_masih_diterima():
    rows = _run(World(old_pw_valid=True))
    bad = [r for r in rows if not r["ok"]]
    assert len(bad) == 1 and bad[0]["kind"] == "old-password-accepted"


def test_tanpa_konfigurasi_logout_dan_ganti_sandi_di_skip():
    cfg = {"fixture": CFG["fixture"], "session": {"me_path": "/api/me"}}
    rows = SM.run_session_checks(Acc(World()), cfg, "http://t", http=lambda: Replay(World()),
                                 sleep=lambda s: None)
    assert len(rows) == 2 and all(r["ok"] and "skip" in r["note"] for r in rows)


def test_login_akun_uji_gagal_di_skip():
    class BadAcc(Acc):
        def new_session(self):
            class R:
                status_code = 429
            return Sess(self.w, "x"), R()
    rows = SM.run_session_checks(BadAcc(World()), CFG, "http://t", http=lambda: Replay(World()),
                                 sleep=lambda s: None)
    assert len(rows) == 1 and rows[0]["ok"] is True and "login akun uji gagal" in rows[0]["note"]


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_session_mgmt(tmp_path):
    rows = _run(World(revoke_others=False, revoke_on_logout=False))
    (tmp_path / "session_mgmt.json").write_text(json.dumps(
        {"module": "session-mgmt", "failures": 2, "results": rows}), encoding="utf-8")
    by = {x["judul"]: x for x in RP.collect(tmp_path)}
    assert by["ganti sandi: sesi lain dicabut"]["kind"] == "session-not-revoked"
    assert by["ganti sandi: sesi lain dicabut"]["severity"] == "medium"
    assert by["logout: sesi dicabut di server"]["kind"] == "logout-no-invalidate"
    assert RP.cvss_for("old-password-accepted", "high")[0] == 8.1
    assert {"session-not-revoked", "logout-no-invalidate", "old-password-accepted"} <= set(RP.KIND_LABEL)
