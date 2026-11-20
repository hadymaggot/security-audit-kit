"""Unit test runner injection (SQLi) — tanpa jaringan."""
import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "run_injection_t", ROOT / "tests" / "injection" / "run_injection.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


IJ = _load()


class _R:
    def __init__(self, text="ok", status=200, elapsed=0.1):
        self.text = text
        self.status_code = status
        self.elapsed_seconds = elapsed
        self.elapsed = dt.timedelta(seconds=elapsed)


# --- helper ---

def test_sql_error_signatures():
    assert IJ.sql_error("You have an error in your SQL syntax near '''")
    assert IJ.sql_error("ORA-01756: quoted string not properly terminated")
    assert not IJ.sql_error("Halaman tidak ditemukan")
    assert not IJ.sql_error("")


def test_similar():
    assert IJ.similar("a" * 100, "a" * 105) is True
    assert IJ.similar("a" * 100, "a" * 200) is False


# --- probe: error-based ---

def test_probe_detects_error_based():
    def send(v):
        return _R("DB error: SQL syntax near") if v.endswith("'") else _R("hasil normal")
    found = IJ.probe(send, "test", {})
    assert any(k == "error-based" for k, _, _ in found)


def test_probe_no_error_when_baseline_already_errors():
    # Kalau baseline sudah memunculkan 'error' (mis. kata itu memang ada di halaman),
    # jangan klaim error-based.
    def send(v):
        return _R("mengandung kata SQL syntax di konten biasa")
    found = IJ.probe(send, "test", {})
    assert not any(k == "error-based" for k, _, _ in found)


# --- probe: boolean-based ---

def test_probe_detects_boolean_based():
    base = "A" * 500

    def send(v):
        if "1'='1" in v or "1=1" in v:
            return _R(base)                 # TRUE → mirip baseline
        if "1'='2" in v or "1=2" in v:
            return _R("kosong")             # FALSE → berbeda jauh
        return _R(base)                     # baseline
    found = IJ.probe(send, "x", {})
    assert any(k == "boolean-based" for k, _, _ in found)


def test_probe_clean_param_no_finding():
    # Param aman: semua payload menghasilkan response identik, tak ada error.
    def send(v):
        return _R("response sama untuk apa pun")
    assert IJ.probe(send, "x", {}) == []


# --- probe: time-based (opt-in) ---

def test_probe_time_based_only_when_enabled():
    def send(v):
        slow = any(t in v for t in ("SLEEP", "pg_sleep", "WAITFOR"))
        return _R("ok", elapsed=5.0 if slow else 0.1)
    assert IJ.probe(send, "x", {}) == [] or all(
        k != "time-based" for k, _, _ in IJ.probe(send, "x", {}))   # default off
    found = IJ.probe(send, "x", {"time_based": True, "time_threshold": 4})
    assert any(k == "time-based" for k, _, _ in found)


# --- main() end-to-end ---

class _Sess:
    def __init__(self, responder):
        self.headers = {}
        self.cookies = {}
        self._resp = responder

    def request(self, method, url, **kw):
        val = ((kw.get("params") or kw.get("json") or kw.get("data")) or {}).get("q", "")
        return self._resp(val)


def test_main_writes_finding(tmp_path, monkeypatch):
    cfg = {"base_url": "http://t", "auth": {},
           "targets": [{"name": "cari q", "method": "GET", "path": "/api/s",
                        "location": "query", "param": "q", "baseline": "test"}]}
    p = tmp_path / "i.yml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    out = tmp_path / "i.json"

    def responder(v):
        return _R("SQL syntax error") if v.endswith("'") else _R("normal")
    monkeypatch.setattr(IJ.requests, "Session", lambda: _Sess(responder))
    monkeypatch.setattr(sys, "argv", ["x", "--config", str(p), "--json", str(out)])
    rc = IJ.main()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert rc == 1 and data["module"] == "injection"
    r = data["results"][0]
    assert r["ok"] is False and "error-based" in r["note"]
    assert "GET http://t/api/s" in r["url"]
