"""Unit test runner upload-safety & auth-policy — tanpa jaringan."""
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AP = _load("run_auth_policy_t", "tests/auth-policy/run_auth_policy.py")
UP = _load("run_upload_safety_t", "tests/upload-safety/run_upload_safety.py")


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.content = json.dumps(body).encode() if body is not None else b""

    def json(self):
        if self._body is None:
            raise ValueError("bukan JSON")
        return self._body


class _Sess:
    """requests.Session tiruan; `responder(method, url, kw)` menentukan respons."""

    responder = None
    calls = []

    def __init__(self):
        self.cookies = {}

    def get(self, url, headers=None, timeout=None):
        _Sess.calls.append(("GET", url, {}))
        return _Resp(204)

    def request(self, method, url, **kw):
        _Sess.calls.append((method, url, kw))
        return _Sess.responder(method, url, kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def _main(mod, tmp_path, monkeypatch, cfg, responder):
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    out = tmp_path / "o.json"
    _Sess.responder = staticmethod(responder)
    _Sess.calls = []
    monkeypatch.setattr(mod.requests, "Session", _Sess)
    monkeypatch.setattr(sys, "argv", ["x", "--config", str(p), "--json", str(out)])
    rc = mod.main()
    return rc, json.loads(out.read_text(encoding="utf-8"))["results"]


# --- auth-policy: password_error ---

def test_password_error_requires_error_on_password_field():
    assert AP.password_error(_Resp(422, {"errors": {"password": ["lemah"]}}), "password")
    # 422 karena field lain ≠ kebijakan sandi ditegakkan.
    assert not AP.password_error(_Resp(422, {"errors": {"email": ["wajib"]}}), "password")
    assert not AP.password_error(_Resp(200, {}), "password")
    assert AP.password_error(_Resp(422), "password")        # non-JSON → status saja


def test_password_checks_keeps_legacy_register_first():
    cfg = {"register": {"path": "/r"}, "password_checks": [{"name": "c", "path": "/c"}]}
    assert [c["path"] for c in AP.password_checks(cfg)] == ["/r", "/c"]
    assert AP.password_checks({}) == []


AP_CFG = {
    "base_url": "http://t",
    "login": {"path": "/api/login", "body": {"email": "u", "password": "p"}},
    "password_checks": [{
        "name": "ganti password", "path": "/api/auth/change-password", "authenticated": True,
        "template": {"current_password": "salah"},
        "password_field": "password", "confirm_field": "password_confirmation",
    }],
    "weak_passwords": ["12345678", "Password123!", "aaaaaaaaaaaa"],
    "strong_password": "Zq7!vR2#mK9$wL4p",
}


def _policy(method, url, kw):
    if url.endswith("/api/login"):
        return _Resp(200, {})
    pw = (kw.get("json") or {}).get("password")
    if pw == "aaaaaaaaaaaa":
        return _Resp(429, {})                                   # kena rate limit
    if pw == "Password123!":
        return _Resp(422, {"errors": {"current_password": ["salah"]}})  # HIBP tak jalan
    if pw == AP_CFG["strong_password"]:
        return _Resp(422, {"errors": {"current_password": ["salah"]}})
    return _Resp(422, {"errors": {"password": ["terlalu pendek"]}})


def test_auth_policy_flags_weak_accepted_and_skips_429(tmp_path, monkeypatch):
    rc, res = _main(AP, tmp_path, monkeypatch, AP_CFG, _policy)
    by = {r["check"]: r for r in res}
    assert by["ganti password password lemah 12345678"]["ok"] is True
    # Lolos validasi sandi (hanya gagal di current_password) = sandi lemah diterima.
    assert by["ganti password password lemah Password123!"]["ok"] is False
    skip = by["ganti password password lemah aaaaaaaaaaaa"]
    assert skip["ok"] is True and skip["note"].startswith("skip")
    assert by["ganti password kontrol password kuat"]["ok"] is True
    assert rc == 1
    # Konfirmasi sandi ikut dikirim & sesi login dipakai untuk endpoint ber-auth.
    sent = [c[2]["json"] for c in _Sess.calls if c[1].endswith("change-password")]
    assert all(b["password"] == b["password_confirmation"] for b in sent)


def test_auth_policy_strong_control_detects_meaningless_test(tmp_path, monkeypatch):
    # Endpoint menolak sandi APA PUN di field sandi → kontrol harus gagal.
    def always_pw_error(method, url, kw):
        if url.endswith("/api/login"):
            return _Resp(200, {})
        return _Resp(422, {"errors": {"password": ["x"]}})
    rc, res = _main(AP, tmp_path, monkeypatch, AP_CFG, always_pw_error)
    ctrl = [r for r in res if "kontrol" in r["check"]][0]
    assert ctrl["ok"] is False and rc == 1


# --- upload-safety ---

UP_CFG = {
    "base_url": "http://t",
    "endpoint": {"path": "/api/r/1/attachments", "field": "file", "data": {"type": "lainnya"}},
    "max_bytes": 2048,
    "cleanup": {"method": "DELETE", "path": "/api/r/1/attachments/{id}", "id_field": "data.id"},
}


def _upload(method, url, kw):
    if method == "DELETE":
        return _Resp(204)
    name, fobj, _ = kw["files"]["file"]
    body = fobj.read()
    # Server hanya mendeteksi MIME: PDF ber-JS & PDF sah diterima, sisanya ditolak.
    if body.startswith(b"%PDF") and len(body) < 2048 and not name.endswith(".php") \
            and "/" not in name:
        return _Resp(201, {"data": {"id": f"att-{name}"}})
    return _Resp(422, {"errors": {"file": ["x"]}})


def test_upload_flags_pdf_js_and_cleans_up_accepted(tmp_path, monkeypatch):
    rc, res = _main(UP, tmp_path, monkeypatch, UP_CFG, _upload)
    by = {r["case"]: r for r in res}
    assert by["PDF berisi JavaScript"]["ok"] is False                 # temuan
    assert "cleanup ok" in by["PDF berisi JavaScript"]["note"]
    assert by["PDF sah (kontrol)"]["ok"] is True
    assert "cleanup ok" in by["PDF sah (kontrol)"]["note"]
    for case in ("Polyglot GIF+PHP", "Ekstensi ganda berakhir .php", "Melebihi batas ukuran"):
        assert by[case]["ok"] is True
    assert rc == 1
    deletes = [c[1] for c in _Sess.calls if c[0] == "DELETE"]
    assert "http://t/api/r/1/attachments/att-a.pdf" in deletes
    posts = [c[2] for c in _Sess.calls if c[0] == "POST"]
    assert all(p["data"] == {"type": "lainnya"} for p in posts)       # field form ikut


def test_traversal_name_sanitized_is_ok_but_echoed_is_finding(tmp_path, monkeypatch):
    def accept_all(echo):
        def responder(method, url, kw):
            if method == "DELETE":
                return _Resp(204)
            name = kw["files"]["file"][0]
            stored = name if echo else name.replace("../", "")
            return _Resp(201, {"id": "x", "file_name": stored})
        return responder

    _, res = _main(UP, tmp_path, monkeypatch, UP_CFG, accept_all(echo=False))
    trav = [r for r in res if r["case"] == UP.TRAVERSAL][0]
    assert trav["ok"] is True and "disanitasi" in trav["note"]

    _, res = _main(UP, tmp_path, monkeypatch, UP_CFG, accept_all(echo=True))
    trav = [r for r in res if r["case"] == UP.TRAVERSAL][0]
    assert trav["ok"] is False


def test_cleanup_without_id_asks_manual():
    note = UP.cleanup_accepted(None, "http://t", {"path": "/x/{id}"}, _Resp(201, {}), {})
    assert "hapus manual" in note
