"""Unit test modul jwt — server model (aman vs rentan), tanpa jaringan."""
import importlib.util
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


JW = _load("run_jwt_t", "tests/jwt/run_jwt.py")
RP = _load("report_jw_t", "report.py")
URL = "GET http://t/api/me"
STRONG = "k9$Zq!vN2#kLm9wXp-4rT8yUe3Ba7"


def _token(secret=STRONG, alg="HS256", payload=None, header=None):
    h = {"alg": alg, "typ": "JWT", **(header or {})}
    p = payload if payload is not None else {"sub": "42", "iat": int(time.time()),
                                              "exp": int(time.time()) + 3600}
    si = f"{JW.b64e(json.dumps(h, separators=(',', ':')).encode())}." \
         f"{JW.b64e(json.dumps(p, separators=(',', ':')).encode())}"
    return f"{si}.{JW.sign(alg, secret, si)}"


# ── utilitas ────────────────────────────────────────────────────────────────
def test_parse_dan_build_roundtrip():
    h, p, parts = JW.parse(_token())
    assert h["alg"] == "HS256" and p["sub"] == "42" and len(parts) == 3
    assert JW.parse("bukan.jwt") is None and JW.parse("") is None
    assert JW.parse(JW.build({"alg": "none"}, {"a": 1}, "")) is not None


def test_crack_hs_menemukan_secret_lemah():
    assert JW.crack_hs(_token("secret"), JW.BUILTIN_WEAK) == "secret"
    assert JW.crack_hs(_token(STRONG), JW.BUILTIN_WEAK) is None
    assert JW.crack_hs(_token("nama-perusahaan"), JW.BUILTIN_WEAK + ["nama-perusahaan"]) \
        == "nama-perusahaan"
    assert JW.mask("supersecret") == "s***t (panjang 11)"


# ── analisis statis ─────────────────────────────────────────────────────────
def _static(token, cfg=None, now=None):
    h, p, _ = JW.parse(token)
    return {r["check"]: r for r in JW.static_rows(h, p, token, cfg or {}, URL, now)}


def test_token_sehat_lolos_semua():
    rows = _static(_token())
    assert all(r["ok"] for r in rows.values())
    assert "simetris" in rows["jwt: algoritma"]["note"]


def test_alg_none_gagal():
    t = JW.build({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": int(time.time()) + 60}, "")
    assert _static(t)["jwt: algoritma"]["ok"] is False


def test_exp_hilang_dan_terlalu_panjang():
    assert _static(_token(payload={"sub": "1"}))["jwt: masa berlaku (exp)"]["ok"] is False
    now = time.time()
    long = _token(payload={"sub": "1", "iat": now, "exp": now + 90 * 86400})
    r = _static(long, now=now)["jwt: masa berlaku (exp)"]
    assert r["ok"] is False and "melebihi" in r["note"] and r["kind"] == "jwt-weak-config"
    assert _static(long, {"max_lifetime_hours": 24 * 100}, now=now)["jwt: masa berlaku (exp)"]["ok"]


def test_klaim_sensitif_dan_header_berisiko():
    t = _token(payload={"sub": "1", "exp": int(time.time()) + 60, "password": "x"},
               header={"kid": "../../dev/null"})
    rows = _static(t)
    assert rows["jwt: klaim sensitif"]["ok"] is False and "password" in rows["jwt: klaim sensitif"]["note"]
    assert "kid" in rows["jwt: header berisiko"]["note"]


def test_secret_lemah_terdeteksi_tanpa_mencetak_utuh():
    r = _static(_token("changeme"))["jwt: secret tanda tangan"]
    assert r["ok"] is False and r["kind"] == "jwt-weak-secret"
    assert "changeme" not in r["note"] and "c***e" in r["note"]
    assert _static(_token(STRONG))["jwt: secret tanda tangan"]["ok"] is True


def test_algoritma_asimetris_tidak_dikrak():
    t = JW.build({"alg": "RS256"}, {"sub": "1", "exp": int(time.time()) + 60}, "abc")
    assert "jwt: secret tanda tangan" not in _static(t)


# ── probe pemalsuan: server model ───────────────────────────────────────────
def _server(mode, secret=STRONG):
    """Kembalikan send(token)->status untuk server model (memverifikasi dengan `secret`)."""
    def send(token):
        p = JW.parse(token)
        if not p:
            return 401
        header, payload, parts = p
        alg = str(header.get("alg", ""))
        si = f"{parts[0]}.{parts[1]}"
        if mode == "no-verify":                            # tidak memeriksa tanda tangan sama sekali
            return 200
        if alg.lower() == "none":                          # menerima alg=none
            return 200 if mode == "accepts-none" else 401
        if alg.upper() in JW.HS:
            ok = JW.sign(alg.upper(), secret, si) == parts[2]
            return 200 if ok else 401
        return 401
    return send


def test_server_aman_menolak_semua_pemalsuan():
    rows = JW.probe_rows(_token(), _server("secure"), {}, URL)
    assert len(rows) == 5 and all(r["ok"] for r in rows)


def test_server_menerima_alg_none():
    rows = JW.probe_rows(_token(), _server("accepts-none"), {}, URL)
    bad = [r for r in rows if not r["ok"]]
    assert len(bad) == 3 and all("alg=" in r["check"] for r in bad)
    assert bad[0]["kind"] == "jwt-forgery" and "DITERIMA" in bad[0]["note"]


def test_server_tanpa_verifikasi_menerima_semua():
    rows = JW.probe_rows(_token(), _server("no-verify"), {}, URL)
    assert len([r for r in rows if not r["ok"]]) == 5


def test_baseline_ditolak_di_skip():
    rows = JW.probe_rows(_token(), lambda t: 401, {}, URL)
    assert len(rows) == 1 and rows[0]["ok"] is True and "skip" in rows[0]["note"]


def test_varian_forge_berisi_perubahan_yang_benar():
    h, p, parts = JW.parse(_token())
    v = dict(JW.forged_variants(h, p, parts))
    assert JW.parse(v["alg=none tanpa tanda tangan"])[0]["alg"] == "none"
    assert v["tanda tangan dibuang"].endswith(".") and v["tanda tangan dibuang"].count(".") == 2
    tam = JW.parse(v["payload diubah, tanda tangan lama"])
    assert tam[1]["admin"] is True and tam[1]["sub"] == "0" and tam[2][2] == parts[2]


# ── token + sender + run ────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._b, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._b


class _Http:
    def __init__(self, token, mode="secure", secret=STRONG):
        self.token, self.server, self.calls = token, _server(mode, secret), []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if url.endswith("/api/login"):
            return _Resp(200, {"data": {"token": self.token}})
        h = kw.get("headers") or {}
        tok = h.get("Authorization", "").replace("Bearer ", "") or \
            (kw.get("cookies") or {}).get("tok", "")
        return _Resp(self.server(tok))


CFG = {"base_url": "http://t", "login": {"path": "/api/login", "token_path": "data.token"},
       "protected": {"path": "/api/me"}}


def test_run_lengkap_server_aman():
    rows = JW.run(CFG, http=_Http(_token()))
    assert all(r["ok"] for r in rows) and len(rows) >= 9


def test_run_menangkap_server_rentan_dan_secret_lemah():
    rows = JW.run(CFG, http=_Http(_token("secret"), mode="accepts-none", secret="secret"))
    kinds = {r["kind"] for r in rows if not r["ok"]}
    assert {"jwt-weak-secret", "jwt-forgery"} <= kinds


def test_run_tanpa_jwt_di_skip():
    class _Opaque(_Http):
        def request(self, method, url, **kw):
            if url.endswith("/api/login"):
                return _Resp(200, {"data": {"token": "1|abcdefOpaqueSanctumToken"}})
            return _Resp(200)
    rows = JW.run(CFG, http=_Opaque("x"))
    assert len(rows) == 1 and rows[0]["ok"] is True and "Sanctum" in rows[0]["note"]


def test_obtain_token_dari_config_dan_cookie_sender():
    assert JW.obtain_token({"token": "abc"}, "http://t") == "abc"
    h = _Http(_token())
    JW.make_sender({**CFG, "cookie": "tok"}, "http://t", h)(_token())
    assert h.calls[-1][2]["cookies"] == {"tok": _token()} or "cookies" in h.calls[-1][2]


# ── integrasi report ────────────────────────────────────────────────────────
def test_report_memuat_jwt(tmp_path):
    rows = JW.run(CFG, http=_Http(_token("secret"), mode="accepts-none", secret="secret"))
    (tmp_path / "jwt.json").write_text(json.dumps(
        {"module": "jwt", "failures": 1, "results": rows}), encoding="utf-8")
    failed = [x for x in RP.collect(tmp_path) if not x["passed"]]
    kinds = {x["kind"]: x["severity"] for x in failed}
    assert kinds["jwt-forgery"] == "critical" and kinds["jwt-weak-secret"] == "critical"
    assert RP.cvss_for("jwt-forgery", "critical")[0] == 9.8
    assert {"jwt-forgery", "jwt-weak-secret", "jwt-weak-config"} <= set(RP.KIND_LABEL)
