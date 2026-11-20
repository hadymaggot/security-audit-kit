"""Unit test jurnal rollback (tests/_rollback.py) — tanpa jaringan."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("_rollback_t", ROOT / "tests" / "_rollback.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RB = _load()


def _entry(label="x"):
    return {"label": label, "module": "mass-assignment",
            "action": {"method": "PATCH", "path": "/api/me", "json": {"role": "user"}}}


def test_record_and_load(tmp_path):
    RB.record(tmp_path, _entry("a"))
    RB.record(tmp_path, _entry("b"))
    data = RB.load(tmp_path)
    assert [e["label"] for e in data] == ["a", "b"]
    assert all(e["done"] is False for e in data)
    assert len(RB.pending(tmp_path)) == 2


def test_load_missing_is_empty(tmp_path):
    assert RB.load(tmp_path) == [] and RB.pending(tmp_path) == []


def test_replay_marks_done_and_writes_log(tmp_path):
    RB.record(tmp_path, _entry("a"))
    RB.record(tmp_path, _entry("b"))
    calls = []

    def do_restore(e):
        calls.append(e["label"])
        return (e["label"] == "a"), ("ok" if e["label"] == "a" else "HTTP 500")

    res = RB.replay(tmp_path, do_restore)
    assert calls == ["a", "b"]
    assert {r["label"]: r["ok"] for r in res} == {"a": True, "b": False}
    # 'a' done, 'b' masih pending (gagal dipulihkan).
    assert [e["label"] for e in RB.pending(tmp_path)] == ["b"]
    log = json.loads((tmp_path / RB.LOG).read_text(encoding="utf-8"))
    assert log["restored"] == 1 and log["failed"] == 1


def test_replay_skips_already_done(tmp_path):
    RB.record(tmp_path, _entry("a"))
    RB.replay(tmp_path, lambda e: (True, "ok"))
    # replay kedua: tak ada yang dikerjakan lagi.
    seen = []
    RB.replay(tmp_path, lambda e: seen.append(e) or (True, "ok"))
    assert seen == []


def test_replay_catches_exception(tmp_path):
    RB.record(tmp_path, _entry("a"))

    def boom(e):
        raise RuntimeError("putus")

    res = RB.replay(tmp_path, boom)
    assert res[0]["ok"] is False and "putus" in res[0]["note"]
    assert len(RB.pending(tmp_path)) == 1          # tetap pending, bisa diulang


def test_clear(tmp_path):
    RB.record(tmp_path, _entry())
    RB.clear(tmp_path)
    assert RB.load(tmp_path) == []
