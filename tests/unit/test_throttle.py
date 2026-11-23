"""Unit tests for transport-level scope enforcement and rate limiting (tests/_throttle.py, _guarded.py)
and their wiring in audit.py. Uses a local HTTP server on 127.0.0.1 only; clock and sleep are faked."""
import http.client
import http.server
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import _scope as S  # noqa: E402
import _throttle as T  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AU = _load("audit_throttle_t", "audit.py")


class FakeClock:
    """Clock that only moves when the code under test sleeps."""

    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def _clean():
    yield
    T.uninstall()
    AU.SCOPE = None
    os.environ.pop("SAK_SCOPE_JSON", None)


@pytest.fixture
def server():
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.headers.get("Host", ""), self.path))
            if self.path == "/redir":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{self.server.server_port}/final")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.hits = hits
    yield srv
    srv.shutdown()
    srv.server_close()


def local_scope(**kw):
    kw.setdefault("in_scope", ["127.0.0.1"])
    return S.Scope(**kw)


# RateLimiter
def test_rate_limiter_spaces_requests_evenly():
    fc = FakeClock()
    rl = T.RateLimiter(2, fc.clock, fc.sleep)
    for _ in range(4):
        rl.wait()
    assert fc.sleeps == [0.5, 0.5, 0.5]            # first is free, then one slot every 0.5 s


def test_rate_limiter_does_not_sleep_when_traffic_is_slower_than_the_limit():
    fc = FakeClock()
    rl = T.RateLimiter(10, fc.clock, fc.sleep)
    rl.wait()
    fc.now += 5
    assert rl.wait() == 0
    assert fc.sleeps == []


def test_rate_limiter_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        T.RateLimiter(0)


def test_rate_limiter_is_thread_safe_and_never_exceeds_rate():
    fc = FakeClock()
    rl = T.RateLimiter(4, fc.clock, lambda s: None)  # sleep is a no-op: slots are what we compare
    slots = []
    lock = threading.Lock()

    def work():
        for _ in range(25):
            rl.wait()
            with lock:
                slots.append(1)

    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(slots) == 100
    assert abs(rl._next - 100 * rl.interval) < 1e-6   # exactly 100 distinct slots were handed out


# install / uninstall
def test_nothing_is_patched_until_install():
    assert not T.active()
    assert http.client.HTTPConnection.putrequest.__module__ == "http.client"


def test_install_then_uninstall_restores_the_standard_library():
    orig_put, orig_cc = http.client.HTTPConnection.putrequest, socket.create_connection
    T.install(local_scope())
    assert T.active()
    assert http.client.HTTPConnection.putrequest is not orig_put
    T.uninstall()
    assert not T.active()
    assert http.client.HTTPConnection.putrequest is orig_put
    assert socket.create_connection is orig_cc


def test_install_twice_does_not_stack_wrappers():
    orig_put = http.client.HTTPConnection.putrequest
    T.install(local_scope())
    T.install(local_scope())
    T.uninstall()
    assert http.client.HTTPConnection.putrequest is orig_put


# requests / urllib enforcement
def test_in_scope_request_succeeds_and_is_paced(server):
    fc = FakeClock()
    T.install(local_scope(max_rps=2), fc.clock, fc.sleep)
    s = requests.Session()
    for _ in range(3):
        assert s.get(f"http://127.0.0.1:{server.server_port}/", timeout=5).text == "ok"
    assert fc.sleeps == [0.5, 0.5]
    assert len(server.hits) == 3


def test_out_of_scope_request_is_blocked_before_it_is_sent(server):
    T.install(local_scope())
    with pytest.raises(requests.exceptions.ConnectionError) as e:
        requests.get(f"http://localhost:{server.server_port}/", timeout=5)
    assert "di luar scope" in str(e.value)
    assert server.hits == []


def test_redirect_to_out_of_scope_host_is_blocked(server):
    T.install(local_scope())
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get(f"http://127.0.0.1:{server.server_port}/redir", timeout=5)
    assert [p for _h, p in server.hits] == ["/redir"]      # the redirect target was never requested


def test_every_redirect_hop_counts_toward_the_rate(server):
    fc = FakeClock()
    T.install(S.Scope(["127.0.0.1", "localhost"], max_rps=1), fc.clock, fc.sleep)
    requests.get(f"http://127.0.0.1:{server.server_port}/redir", timeout=5)
    assert [p for _h, p in server.hits] == ["/redir", "/final"]
    assert fc.sleeps == [1.0]                               # two requests -> one wait


def test_urllib_is_covered_too(server):
    T.install(local_scope())
    with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as r:
        assert r.read() == b"ok"
    with pytest.raises(OSError) as e:
        urllib.request.urlopen(f"http://localhost:{server.server_port}/", timeout=5)
    assert "di luar scope" in str(e.value)


def test_wildcard_scope_is_honored_by_the_guard(server):
    T.install(S.Scope(["*.localhost"]))
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get(f"http://127.0.0.1:{server.server_port}/", timeout=5)


def test_raw_socket_connections_are_scope_checked(server):
    T.install(local_scope())
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=5):
        pass
    with pytest.raises(T.ScopeViolation):
        socket.create_connection(("localhost", server.server_port), timeout=5)


def test_absolute_url_for_plain_http_proxy_uses_the_url_host():
    conn = http.client.HTTPConnection("proxy.internal", 3128)
    assert T._target_host(conn, "http://target.example.com/x") == "target.example.com"
    assert T._target_host(conn, "/x") == "proxy.internal"
    conn._tunnel_host = "target.example.com"
    assert T._target_host(conn, "/x") == "target.example.com"


# Playwright context guard
class FakeContext:
    def __init__(self):
        self.pattern = self.handler = None

    def route(self, pattern, handler):
        self.pattern, self.handler = pattern, handler


class FakeRoute:
    def __init__(self, url):
        self.request = type("R", (), {"url": url})()
        self.action = None

    def continue_(self):
        self.action = "continue"

    def abort(self):
        self.action = "abort"


def test_guard_context_is_a_noop_outside_bounty_mode():
    ctx = FakeContext()
    assert T.guard_context(ctx) is ctx
    assert ctx.handler is None


def test_guard_context_aborts_out_of_scope_and_paces_in_scope():
    fc = FakeClock()
    T.install(S.Scope(["app.example.com"], max_rps=1), fc.clock, fc.sleep)
    ctx = T.guard_context(FakeContext())
    assert ctx.pattern == "**/*"
    results = {}
    for url in ("https://app.example.com/a", "https://app.example.com/b", "https://cdn.evil.io/x.js",
                "data:text/plain,hi"):
        r = FakeRoute(url)
        ctx.handler(r)
        results[url] = r.action
    assert results == {"https://app.example.com/a": "continue", "https://app.example.com/b": "continue",
                       "https://cdn.evil.io/x.js": "abort", "data:text/plain,hi": "continue"}
    assert fc.sleeps == [1.0]


def test_screenshot_capture_routes_the_browser_through_the_guard():
    import _screenshot

    calls = {}

    class Ctx(FakeContext):
        def new_page(self):
            raise RuntimeError("stop after routing")     # capture_url swallows errors and returns ""

        def add_cookies(self, c):
            pass

    class Browser:
        def new_context(self, **kw):
            calls["ctx"] = Ctx()
            return calls["ctx"]

        def close(self):
            pass

    class PW:
        chromium = type("C", (), {"launch": staticmethod(lambda: Browser())})()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    T.install(local_scope())
    assert _screenshot.capture_url("http://127.0.0.1/x", "out", "t", _pw=lambda: PW()) == ""
    assert calls["ctx"].handler is not None


def test_clientleak_browser_cache_check_is_off_in_bounty_mode():
    mod = _load("run_client_leak_throttle_t", "tests/client-leak/run_client_leak.py")
    T.install(local_scope())
    res = mod.check_browser_cache({}, "http://127.0.0.1", ["/"])
    assert res[0]["ok"] and "mode bounty" in res[0]["note"]


# launcher (subprocess)
def _runner(tmp_path, body):
    p = tmp_path / "runner.py"
    p.write_text(body, encoding="utf-8")
    return p


def _guarded(runner, *args, scope=None, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "SAK_SCOPE_JSON"}
    if scope is not None:
        env["SAK_SCOPE_JSON"] = json.dumps(scope.to_dict())
    env.update(extra_env or {})
    return subprocess.run([sys.executable, str(ROOT / "tests" / "_guarded.py"), str(runner), *args],
                          capture_output=True, text=True, env=env, timeout=60)


def test_launcher_fails_closed_without_scope(tmp_path):
    marker = tmp_path / "ran.txt"
    r = _runner(tmp_path, f"open({str(marker)!r}, 'w').write('x')\n")
    p = _guarded(r)
    assert p.returncode == 2 and not marker.exists()
    assert "tidak dijalankan" in p.stderr


def test_launcher_fails_closed_on_broken_scope(tmp_path):
    marker = tmp_path / "ran.txt"
    r = _runner(tmp_path, f"open({str(marker)!r}, 'w').write('x')\n")
    for bad in ("not json", json.dumps({"in_scope": []}), json.dumps([1])):
        p = _guarded(r, extra_env={"SAK_SCOPE_JSON": bad})
        assert p.returncode == 2 and not marker.exists()


def test_launcher_passes_args_and_exit_code(tmp_path):
    out = tmp_path / "argv.json"
    r = _runner(tmp_path, "import json, sys\n"
                          f"json.dump(sys.argv[1:], open({str(out)!r}, 'w'))\n"
                          "sys.exit(5)\n")
    p = _guarded(r, "--config", "c.yml", scope=local_scope())
    assert p.returncode == 5
    assert json.loads(out.read_text(encoding="utf-8")) == ["--config", "c.yml"]


def test_launcher_enforces_scope_inside_the_runner(tmp_path):
    r = _runner(tmp_path,
                "import http.client, sys, _throttle\n"
                "try:\n"
                "    http.client.HTTPConnection('evil.io').putrequest('GET', '/')\n"
                "except _throttle.ScopeViolation:\n"
                "    sys.exit(7)\n"
                "sys.exit(0)\n")
    assert _guarded(r, scope=local_scope()).returncode == 7


# audit.py wiring
def test_guarded_is_identity_without_bounty_mode():
    AU.SCOPE = None
    cmd = [sys.executable, "runner.py", "--config", "c.yml"]
    assert AU.guarded(cmd) == cmd


def test_guarded_wraps_runner_and_exports_scope_in_bounty_mode():
    AU.SCOPE = S.Scope(["a.example.com"], max_rps=3)
    out = AU.guarded([sys.executable, "runner.py", "--config", "c.yml"])
    assert out[0] == sys.executable
    assert Path(out[1]) == ROOT / "tests" / "_guarded.py"
    assert out[2:] == ["runner.py", "--config", "c.yml"]
    assert S.Scope.from_dict(json.loads(os.environ["SAK_SCOPE_JSON"])).max_rps == 3


def test_mod_py_runs_through_the_guard_only_in_bounty_mode(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yml"
    cfg.write_text('base_url: "https://a.example.com"\n', encoding="utf-8")
    seen = []
    monkeypatch.setattr(AU, "run", lambda cmd: seen.append(cmd) or 0)
    monkeypatch.setattr(AU, "reports_dir", lambda: tmp_path)
    AU.SCOPE = None
    AU.mod_py(Path("runner.py"), cfg, "x.json")
    AU.SCOPE = S.Scope(["a.example.com"])
    AU.mod_py(Path("runner.py"), cfg, "x.json")
    assert "_guarded.py" not in " ".join(seen[0])
    assert Path(seen[1][1]).name == "_guarded.py"


def test_scope_to_dict_roundtrip():
    sc = S.Scope(["*.a.com", "b.com"], ["x.a.com"], 2, ["injection"])
    again = S.Scope.from_dict(sc.to_dict())
    assert again.to_dict() == sc.to_dict()
    with pytest.raises(S.ScopeError):
        S.Scope.from_dict("nope")
