"""Unit tests for the browser cache check (Playwright) in run_client_leak.py.

Real Chromium runs against a local HTTP server; skipped automatically when
Playwright/Chromium is not installed (e.g. in the python-slim CI image).
"""
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import report as RP  # noqa: E402


def _load():
    path = ROOT / "tests" / "client-leak" / "run_client_leak.py"
    spec = importlib.util.spec_from_file_location("run_client_leak", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CL = _load()

# path -> Cache-Control sent by the test server.
ROUTES = {
    "/": "no-store",
    "/api/public": "public, max-age=600",
    "/api/nostore": "no-store",
    "/api/pnc": "private, no-cache",  # passes the header check, yet the browser still stores it
    "/api/empty": None,  # no header + Last-Modified -> heuristic caching
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path not in ROUTES:
            self.send_response(404)
            self.end_headers()
            return
        body = b"<html></html>" if self.path == "/" else b'{"user":"rahasia"}'
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else "application/json")
        if ROUTES[self.path]:
            self.send_header("Cache-Control", ROUTES[self.path])
        else:
            self.send_header("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_skip_when_playwright_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    res = CL.check_browser_cache({}, "http://t", ["/api/x"])
    assert len(res) == 1 and res[0]["ok"] and res[0]["note"].startswith("skip:")


def test_report_maps_browser_cache_to_client_cache(tmp_path):
    (tmp_path / "client_leak.json").write_text(json.dumps({"module": "client-leak", "results": [
        {"kind": "browser-cache", "label": "cache browser /api/me", "status": 200,
         "ok": False, "note": "tersimpan di cache browser"}]}), encoding="utf-8")
    f = RP.collect(tmp_path)
    assert [x["kind"] for x in f] == ["client-cache"]
    assert f[0]["severity"] == "medium"


def test_real_browser_cache(server):
    pytest.importorskip("playwright.sync_api")
    res = CL.check_browser_cache({"browser_cache": {"enabled": True}}, server,
                                 ["/api/public", "/api/nostore", "/api/pnc", "/api/empty"])
    if len(res) == 1 and res[0]["note"].startswith("skip:"):
        pytest.skip(res[0]["note"])  # Chromium not installed
    by = {r["label"]: r for r in res}
    assert not by["cache browser /api/public"]["ok"]   # public -> stored
    assert by["cache browser /api/nostore"]["ok"]      # no-store -> not stored
    assert not by["cache browser /api/empty"]["ok"]   # no header -> heuristic caching
    # no-cache only forces revalidation; the body is still stored on the browser disk.
    assert not by["cache browser /api/pnc"]["ok"]
    assert "public, max-age=600" in by["cache browser /api/public"]["note"]


def test_unreachable_target_is_skip():
    pytest.importorskip("playwright.sync_api")
    # Unreachable target (closed port) -> cannot be tested, not a finding.
    res = CL.check_browser_cache({"browser_cache": {"start_path": "/"}},
                                 "http://127.0.0.1:9", ["/api/public"])
    assert all(r["ok"] and r["note"].startswith("skip:") for r in res)
