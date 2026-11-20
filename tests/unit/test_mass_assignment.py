"""Unit test runner mass-assignment — tanpa jaringan.

Memakai requests.Session tiruan: GET pertama = snapshot, GET kedua = keadaan setelah
inject. Memastikan deteksi temuan, jurnal rollback tercatat (tanpa restore inline),
dan bukti endpoint ikut.
"""
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


MA = _load("run_mass_assignment_t", "tests/mass-assignment/run_mass_assignment.py")
RB = _load("_rollback_t2", "tests/_rollback.py")


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _Sess:
    """GET mengembalikan body dari antrean per-path; request (PATCH) mencatat & 200."""

    def __init__(self, get_queue, patch_status=200):
        self.headers = {}
        self.cookies = {}
        self._q = list(get_queue)
        self._patch_status = patch_status
        self.writes = []

    def get(self, url, headers=None, timeout=None):
        return _Resp(200, self._q.pop(0) if self._q else {})

    def request(self, method, url, json=None, headers=None, timeout=None, **kw):
        self.writes.append((method, url, json))
        return _Resp(self._patch_status)


CFG = {
    "base_url": "http://t",
    "auth": {},                       # tanpa sanctum → tak ada login/jaringan
    "targets": [{
        "name": "Eskalasi role via profil",
        "get": {"path": "/api/me"}, "data_path": "data",
        "update": {"method": "PATCH", "path": "/api/me"},
        "inject": {"role": "admin", "is_admin": True},
        "fields": ["role", "is_admin"],
    }],
}


def _run(tmp_path, monkeypatch, get_queue, patch_status=200):
    cfg = dict(CFG)
    cfg["reports_dir"] = str(tmp_path)
    p = tmp_path / "ma.yml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    out = tmp_path / "ma.json"
    sess = _Sess(get_queue, patch_status)
    monkeypatch.setattr(MA.requests, "Session", lambda: sess)
    monkeypatch.setattr(sys, "argv", ["x", "--config", str(p), "--json", str(out)])
    rc = MA.main()
    results = json.loads(out.read_text(encoding="utf-8"))["results"]
    journal = RB.load(tmp_path)
    return rc, results, journal, sess


def test_flags_accepted_injection_and_journals(tmp_path, monkeypatch):
    # snapshot: role=member; setelah inject: role=admin (DITERIMA → temuan).
    snap = {"data": {"role": "member", "is_admin": False}}
    after = {"data": {"role": "admin", "is_admin": True}}
    rc, res, journal, sess = _run(tmp_path, monkeypatch, [snap, after])
    assert rc == 1
    r = res[0]
    assert r["ok"] is False and "role" in r["note"] and "is_admin" in r["note"]
    assert "PATCH http://t/api/me" in r["url"]
    # Jurnal mencatat pemulihan ke nilai ASLI, dan BELUM dipulihkan (restore pasca-laporan).
    assert len(journal) == 1
    act = journal[0]["action"]
    assert act["json"] == {"role": "member", "is_admin": False}
    assert journal[0]["done"] is False
    # Runner hanya menulis SEKALI (inject); tak ada restore inline.
    assert len(sess.writes) == 1 and sess.writes[0][2] == {"role": "admin", "is_admin": True}


def test_server_ignores_injection_is_ok(tmp_path, monkeypatch):
    # Server mengabaikan field terlarang: nilai tetap seperti semula → bukan temuan.
    snap = {"data": {"role": "member", "is_admin": False}}
    after = {"data": {"role": "member", "is_admin": False}}
    rc, res, journal, _ = _run(tmp_path, monkeypatch, [snap, after])
    assert rc == 0 and res[0]["ok"] is True
    # Tetap mencatat jurnal (crash-safe); restore ke nilai asli = aman/no-op.
    assert len(journal) == 1 and journal[0]["action"]["json"]["role"] == "member"


def test_snapshot_unreadable_skips(tmp_path, monkeypatch):
    rc, res, journal, _ = _run(tmp_path, monkeypatch, [{"data": "bukan-objek"}])
    assert res[0]["ok"] is True and "skip" in res[0]["note"]
    assert journal == []            # tak menulis apa pun → tak ada yang perlu di-rollback


def test_rollback_restores_via_journal(tmp_path, monkeypatch):
    # Setelah temuan, replay jurnal harus mengirim PATCH nilai asli.
    snap = {"data": {"role": "member", "is_admin": False}}
    after = {"data": {"role": "admin", "is_admin": True}}
    _, _, _, _ = _run(tmp_path, monkeypatch, [snap, after])
    sent = []

    def do_restore(e):
        sent.append(e["action"]["json"])
        return True, "ok"

    RB.replay(tmp_path, do_restore)
    assert sent == [{"role": "member", "is_admin": False}]
    assert RB.pending(tmp_path) == []        # semua dipulihkan
