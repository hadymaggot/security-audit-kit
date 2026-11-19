"""Unit test snapshot data — runner palsu, tanpa Docker."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SN = _load("_snapshot_t", "tests/_snapshot.py")
RB = _load("_rollback_sn_t", "tests/_rollback.py")
AU = _load("audit_sn_t", "audit.py")

PG = {"preset": "postgres-docker", "container": "pg", "user": "u", "databases": ["iam", "emission"]}


class FakeRunner:
    """Mencatat perintah; backup menulis isi ke stdout_to; restore dapat disuruh gagal."""

    def __init__(self, fail_backup=None, fail_restore=None, empty=False):
        self.calls, self.fail_backup, self.fail_restore, self.empty = [], fail_backup, fail_restore, empty

    def __call__(self, cmd, stdin_path=None, stdout_path=None, timeout=1800):
        self.calls.append((list(cmd), stdin_path, stdout_path))
        if stdout_path:                                           # langkah backup
            if self.fail_backup and self.fail_backup in " ".join(cmd):
                return 1, "pg_dump: error"
            Path(stdout_path).write_bytes(b"" if self.empty else b"DATA:" + cmd[-1].encode())
            return 0, ""
        if self.fail_restore and self.fail_restore in " ".join(cmd):   # langkah restore
            return 2, "pg_restore: error"
        return 0, ""


# ── preset & backup ─────────────────────────────────────────────────────────
def test_expand_preset_postgres_docker():
    steps = SN.expand_preset(PG)
    assert [s["name"] for s in steps] == ["postgres iam", "postgres emission"]
    assert steps[0]["backup"]["cmd"][:4] == ["docker", "exec", "pg", "pg_dump"]
    assert "-Fc" in steps[0]["backup"]["cmd"] and steps[0]["backup"]["cmd"][-1] == "iam"
    r = steps[1]["restore"]
    assert r["cmd"][:4] == ["docker", "exec", "-i", "pg"] and "--single-transaction" in r["cmd"]
    assert r["stdin_from"] == "{dir}/emission.dump"
    assert SN.expand_preset({"steps": [{"name": "x"}]}) == [{"name": "x"}]


def test_backup_membuat_berkas_dan_manifest(tmp_path):
    m = SN.backup(PG, tmp_path / "s1", FakeRunner())
    assert [s["name"] for s in m["steps"]] == ["postgres iam", "postgres emission"]
    assert all(Path(s["file"]).exists() and s["bytes"] > 0 for s in m["steps"])
    assert m["steps"][0]["restore"]["stdin_from"] == m["steps"][0]["file"]       # {dir} terisi
    assert "{dir}" not in str(m)


def test_backup_gagal_atau_kosong_melempar(tmp_path):
    with pytest.raises(SN.SnapshotError, match="gagal"):
        SN.backup(PG, tmp_path / "a", FakeRunner(fail_backup="emission"))
    with pytest.raises(SN.SnapshotError, match="berkas kosong"):
        SN.backup(PG, tmp_path / "b", FakeRunner(empty=True))
    with pytest.raises(SN.SnapshotError, match="tidak ada langkah"):
        SN.backup({"preset": "postgres-docker", "container": "c", "user": "u"}, tmp_path / "c",
                  FakeRunner())


# ── restore ─────────────────────────────────────────────────────────────────
def test_restore_menjalankan_semua_langkah_walau_satu_gagal(tmp_path):
    m = SN.backup(PG, tmp_path / "s", FakeRunner())
    runner = FakeRunner(fail_restore="iam")
    res = SN.restore(m, runner)
    assert [(n, ok) for n, ok, _ in res] == [("postgres iam", False), ("postgres emission", True)]
    assert runner.calls[-1][1].endswith("emission.dump")                    # stdin dari berkas dump


# ── Guard ───────────────────────────────────────────────────────────────────
def _guard(tmp_path, runner, cfg=PG, **kw):
    lines = []
    return SN.Guard(cfg, tmp_path, "ZAP full", runner=runner, echo=lines.append, **kw), lines


def test_guard_backup_lalu_restore_dan_bersih(tmp_path):
    runner = FakeRunner()
    g, lines = _guard(tmp_path, runner)
    with g:
        assert len(RB.pending(tmp_path)) == 1                                # jurnal dicatat SEBELUM scan
        pend = RB.pending(tmp_path)[0]
        assert pend["module"] == "snapshot" and "snapshot_manifest" in pend["action"]
    assert g.ok is True and RB.pending(tmp_path) == []                       # selesai -> ditandai done
    assert not list((tmp_path / "snapshots").rglob("*.dump"))                # berkas dihapus (keep: false)
    kinds = ["pg_dump" in c[0] for c in runner.calls if c[2]]
    assert all(kinds) and any("pg_restore" in " ".join(c[0]) for c in runner.calls)
    assert any("Snapshot data sebelum ZAP full" in l for l in lines)


def test_guard_keep_mempertahankan_berkas(tmp_path):
    g, _ = _guard(tmp_path, FakeRunner(), {**PG, "keep": True})
    with g:
        pass
    assert list((tmp_path / "snapshots").rglob("*.dump"))


def test_guard_restore_tetap_jalan_saat_scan_melempar(tmp_path):
    runner = FakeRunner()
    g, _ = _guard(tmp_path, runner)
    with pytest.raises(ValueError):
        with g:
            raise ValueError("scan gagal")
    assert any("pg_restore" in " ".join(c[0]) for c in runner.calls)
    assert g.ok is True and RB.pending(tmp_path) == []


def test_guard_backup_gagal_membatalkan_tanpa_restore_dan_tanpa_jurnal(tmp_path):
    runner = FakeRunner(fail_backup="pg_dump")
    g, _ = _guard(tmp_path, runner)
    with pytest.raises(SN.SnapshotError):
        with g:
            pytest.fail("scan tidak boleh jalan")
    assert RB.pending(tmp_path) == [] and not any("pg_restore" in " ".join(c[0]) for c in runner.calls)


def test_guard_restore_gagal_tetap_di_jurnal(tmp_path):
    g, lines = _guard(tmp_path, FakeRunner(fail_restore="emission"))
    with g:
        pass
    assert g.ok is False and len(RB.pending(tmp_path)) == 1
    assert any("PERINGATAN" in l for l in lines)
    assert list((tmp_path / "snapshots").rglob("*.dump"))                    # berkas dipertahankan


def test_guard_tanpa_konfigurasi_tidak_melakukan_apa_apa(tmp_path):
    runner = FakeRunner()
    with SN.Guard(None, tmp_path, "x", runner=runner) as g:
        pass
    assert runner.calls == [] and g.ok is True and RB.pending(tmp_path) == []


def test_restore_entry_dari_jurnal_untuk_audit_rollback(tmp_path):
    g, _ = _guard(tmp_path, FakeRunner(fail_restore="emission"))
    with g:
        pass
    entry = RB.pending(tmp_path)[0]
    ok, note = SN.restore_entry(entry, FakeRunner())                         # pemulihan ulang berhasil
    assert ok and "postgres iam: dipulihkan" in note
    assert not list((tmp_path / "snapshots").rglob("*.dump"))
    assert SN.restore_entry({"action": {"snapshot_manifest": str(tmp_path / "x.json")}},
                            FakeRunner())[0] is False


# ── integrasi mod_zap ───────────────────────────────────────────────────────
def test_zap_scan_opts_exclude_dan_menit():
    o = AU.zap_scan_opts({"zap_exclude": [".*/logout.*", ".*/delete.*"], "zap_spider_minutes": 3,
                          "zap_timeout_minutes": 20})
    assert o[:4] == ["-m", "3", "-T", "20"] and o[4] == "-z"
    assert "url(0).regex=.*/logout.*" in o[5] and "url(1).enabled=true" in o[5]
    assert AU.zap_scan_opts({}) == []


def test_zap_scan_cmd():
    assert AU.zap_scan_cmd({"base_url": "http://t"}, "full")[:3] == ["zap-full-scan.py", "-t", "http://t"]
    assert AU.zap_scan_cmd({"openapi": "http://t/o.json"}, "api")[:2] == ["zap-api-scan.py", "-t"]


def test_mod_zap_full_dibungkus_snapshot(monkeypatch, tmp_path):
    order = []
    monkeypatch.setattr(AU, "have_docker", lambda: True)
    monkeypatch.setattr(AU, "reports_dir", lambda: tmp_path)
    monkeypatch.setattr(AU, "run", lambda cmd: order.append("zap") or 0)
    runner = FakeRunner()
    import _snapshot as real                       # modul yang sama dengan yang dipakai audit.mod_zap
    real_guard = real.Guard
    monkeypatch.setattr(real, "Guard",
                        lambda cfg, rd, label, **k: real_guard(cfg, rd, label, runner=runner,
                                                               echo=lambda s: order.append("g")))
    rc = AU.mod_zap({"base_url": "http://t", "snapshot": PG}, "full")
    assert rc == 0 and order.count("zap") == 1
    assert any("pg_restore" in " ".join(c[0]) for c in runner.calls)         # restore dijalankan


def test_mod_zap_full_dibatalkan_bila_backup_gagal(monkeypatch, tmp_path):
    ran = []
    monkeypatch.setattr(AU, "have_docker", lambda: True)
    monkeypatch.setattr(AU, "reports_dir", lambda: tmp_path)
    monkeypatch.setattr(AU, "run", lambda cmd: ran.append(cmd) or 0)
    runner = FakeRunner(fail_backup="pg_dump")
    import _snapshot as real
    real_guard = real.Guard
    monkeypatch.setattr(real, "Guard",
                        lambda cfg, rd, label, **k: real_guard(cfg, rd, label, runner=runner,
                                                               echo=lambda s: None))
    assert AU.mod_zap({"base_url": "http://t", "snapshot": PG}, "full") == 2
    assert ran == []                                                         # ZAP tidak dijalankan


def test_mod_zap_baseline_tanpa_snapshot(monkeypatch):
    ran = []
    monkeypatch.setattr(AU, "have_docker", lambda: True)
    monkeypatch.setattr(AU, "run", lambda cmd: ran.append(cmd) or 0)
    assert AU.mod_zap({"base_url": "http://t", "snapshot": PG}, "baseline") == 0
    assert "zap-baseline.py" in ran[0]
