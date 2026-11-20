"""Unit test modul ratelimit — evaluator murni dan alur lockout dengan fixture palsu."""
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


RL = _load("run_ratelimit_t", "tests/ratelimit/run_ratelimit.py")
RP = _load("report_rl2_t", "report.py")
URL = "POST http://t/api/login"


# ── burst ───────────────────────────────────────────────────────────────────
def test_burst_dengan_429_lolos():
    r = RL.evaluate_burst("login", URL, [401, 401, 401, 429, 429], False)
    assert r["ok"] is True and "request ke-4" in r["note"] and r["status"] == 429


def test_burst_tanpa_pembatasan_gagal():
    r = RL.evaluate_burst("login", URL, [401] * 20, False)
    assert r["ok"] is False and r["kind"] == "no-rate-limit" and "401x20" in r["note"]


def test_burst_retry_after_dianggap_pembatasan():
    assert RL.evaluate_burst("x", URL, [200, 200], True)["ok"] is True


def test_burst_galat_jaringan_di_skip():
    r = RL.evaluate_burst("x", URL, [None, None], False)
    assert r["ok"] is True and "skip" in r["note"]


# ── lockout ─────────────────────────────────────────────────────────────────
CFG = {"max_attempts": 5, "lock_statuses": [423], "max_lock_minutes": 60}
LOCKMSG = "Akun dikunci sementara. Coba lagi dalam 15 menit."


def _seq(n_401, lock=True):
    a = [(401, "salah")] * n_401
    if lock:
        a.append((423, LOCKMSG))
    return a


def test_lockout_normal_semua_lolos():
    rows = RL.evaluate_lockout(_seq(4), (423, LOCKMSG), CFG, URL)
    assert all(r["ok"] for r in rows) and len(rows) == 3
    by = {r["check"]: r for r in rows}
    assert "ke-5" in by["lockout: penguncian setelah password salah"]["note"]
    assert "15 menit" in by["lockout: durasi kunci"]["note"]


def test_tidak_pernah_terkunci_gagal():
    rows = RL.evaluate_lockout([(401, "x")] * 7, None, CFG, URL)
    assert rows[0]["ok"] is False and rows[0]["kind"] == "weak-lockout"
    assert "TIDAK terkunci" in rows[0]["note"]


def test_terkunci_terlalu_lambat_gagal():
    rows = RL.evaluate_lockout(_seq(9), None, {**CFG, "tolerance": 1}, URL)
    assert rows[0]["ok"] is False and "melebihi ambang" in rows[0]["note"]


def test_sandi_benar_berhasil_saat_terkunci_adalah_bypass():
    rows = RL.evaluate_lockout(_seq(4), (200, "ok"), CFG, URL)
    bypass = [r for r in rows if r["check"] == "lockout: password benar saat akun terkunci"][0]
    assert bypass["ok"] is False and bypass["kind"] == "lockout-bypass"


def test_durasi_tak_wajar_dan_tak_diumumkan():
    long = RL.evaluate_lockout([(401, "x")] * 4 + [(423, "terkunci 9999 menit")], None, CFG, URL)
    assert [r for r in long if r["check"].endswith("durasi kunci")][0]["ok"] is False
    none = RL.evaluate_lockout([(401, "x")] * 4 + [(423, "terkunci")], None, CFG, URL)
    d = [r for r in none if r["check"].endswith("durasi kunci")][0]
    assert d["ok"] is True and "tidak diumumkan" in d["note"]


def test_terhalang_rate_limit_gateway_di_skip():
    rows = RL.evaluate_lockout([(401, "x"), (401, "x"), (429, "Too Many")], None, CFG, URL)
    assert len(rows) == 1 and rows[0]["ok"] is True and "terhalang rate limit" in rows[0]["note"]


def test_lock_signal_lewat_pesan():
    assert RL.lock_signal(401, "Akun terkunci", {}) is True
    assert RL.lock_signal(401, "password salah", {}) is False
    assert RL.parse_lock_minutes("coba lagi dalam 15 menit") == 15
    assert RL.parse_lock_minutes("tanpa angka") is None


# ── enumerasi ───────────────────────────────────────────────────────────────
def test_enumerasi_terdeteksi_423_vs_401():
    rows = RL.evaluate_enumeration((401, "Email salah"), (401, "Email salah"),
                                   (423, LOCKMSG), (401, "Email salah"), URL)
    by = {r["check"]: r for r in rows}
    assert by["enumerasi akun: response gagal pertama"]["ok"] is True
    last = by["enumerasi akun: response setelah ambang percobaan"]
    assert last["ok"] is False and last["kind"] == "user-enumeration" and "423" in last["note"]


def test_enumerasi_tak_ada_bila_identik():
    rows = RL.evaluate_enumeration((401, "x 1"), (401, "x 2"), (401, "x"), (401, "x"), URL)
    assert all(r["ok"] for r in rows)          # angka dinormalisasi


# ── alur run_lockout dengan fixture palsu ───────────────────────────────────
class _Acc:
    def __init__(self, lock_after):
        self.lock_after, self.n, self.email, self.password = lock_after, 0, "e@x", "BENAR"
        self.fake_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login_attempt(self, pw, session=None):
        class R:
            pass
        r = R()
        if pw == self.password:
            r.status_code, r.text = 423, LOCKMSG
            return r
        self.n += 1
        r.status_code, r.text = (423, LOCKMSG) if self.n >= self.lock_after else (401, "salah")
        return r

    def login_as(self, email, pw, session=None):
        class R:
            status_code, text = 401, "salah"
        self.fake_calls += 1
        return R()


def test_run_lockout_alur_lengkap(monkeypatch):
    acc = _Acc(5)
    monkeypatch.setattr(RL._fixture, "DisposableAccount", lambda *a, **k: acc)
    cfg = {"fixture": {"login": {"path": "/api/login"}},
           "lockout": {"max_attempts": 5, "delay_seconds": 0}}
    rows = RL.run_lockout(cfg, "http://t", sleep=lambda s: None)
    by = {r["check"]: r for r in rows}
    assert by["lockout: penguncian setelah password salah"]["ok"] is True
    assert by["lockout: password benar saat akun terkunci"]["ok"] is True
    assert by["enumerasi akun: response setelah ambang percobaan"]["ok"] is False   # 423 vs 401
    assert acc.fake_calls == 5                       # identitas fiktif dicoba sebanyak percobaan nyata


def test_run_lockout_dilewati_tanpa_fixture():
    assert RL.run_lockout({"lockout": {"enabled": True}}, "http://t") == []
    assert RL.run_lockout({"fixture": {}, "lockout": {"enabled": False}}, "http://t") == []


# ── run_burst dengan session palsu ──────────────────────────────────────────
class _S:
    def __init__(self, seq):
        self.seq, self.cookies, self.headers = list(seq), {}, {}

    def request(self, *a, **k):
        class R:
            headers = {}
        r = R()
        r.status_code = self.seq.pop(0)
        return r


def test_run_burst():
    cfg = {"burst": [{"name": "login", "path": "/api/login", "count": 4}]}
    rows = RL.run_burst(cfg, "http://t", sess_factory=lambda c: _S([401, 401, 429, 429]),
                        sleep=lambda s: None)
    assert rows[0]["ok"] is True and "request ke-3" in rows[0]["note"]


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_ratelimit(tmp_path):
    rows = RL.evaluate_enumeration((401, "a"), (401, "a"), (423, LOCKMSG), (401, "a"), URL)
    rows += [RL.evaluate_burst("login", URL, [401] * 5, False)]
    (tmp_path / "ratelimit.json").write_text(json.dumps(
        {"module": "ratelimit", "failures": 2, "results": rows}), encoding="utf-8")
    by = {x["title"]: x for x in RP.collect(tmp_path)}
    assert by["enumerasi akun: response setelah ambang percobaan"]["kind"] == "user-enumeration"
    assert by["enumerasi akun: response setelah ambang percobaan"]["severity"] == "low"
    assert by["laju: login"]["kind"] == "no-rate-limit" and by["laju: login"]["severity"] == "medium"
    assert {"no-rate-limit", "weak-lockout", "lockout-bypass", "user-enumeration"} <= set(RP.KIND_LABEL)
    assert RP.cvss_for("lockout-bypass", "high")[0] == 7.5
