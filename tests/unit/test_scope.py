"""Unit tests for the bug bounty scope guard (tests/_scope.py), its gate in audit.py and the recon
integration. Pure: no network, Docker or installed binaries."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import _scope as S  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AU = _load("audit_scope_t", "audit.py")
RC = _load("run_recon_scope_t", "tests/recon/run_recon.py")


def make_scope(**kw):
    kw.setdefault("in_scope", ["app.example.com", "*.example.com"])
    return S.Scope(**kw)


@pytest.fixture(autouse=True)
def _reset_scope():
    yield
    AU.SCOPE = None


# host matching
def test_host_of_strips_scheme_port_path_and_case():
    assert S.host_of("HTTPS://App.Example.com:8443/a/b?x=1") == "app.example.com"
    assert S.host_of("app.example.com:8080") == "app.example.com"
    assert S.host_of("app.example.com.") == "app.example.com"
    assert S.host_of("") == ""


def test_wildcard_matches_subdomains_but_not_apex():
    sc = S.Scope(["*.example.com"])
    assert sc.allows_host("a.example.com")
    assert sc.allows_host("a.b.example.com")
    assert not sc.allows_host("example.com")


def test_lookalike_domains_are_out_of_scope():
    sc = make_scope()
    assert not sc.allows_host("evilexample.com")
    assert not sc.allows_host("app.example.com.evil.io")
    assert not sc.allows_host("example.com.evil.io")


def test_out_of_scope_wins_over_wildcard():
    sc = make_scope(out_of_scope=["admin.example.com", "*.internal.example.com"])
    assert sc.allows_host("www.example.com")
    assert not sc.allows_host("admin.example.com")
    assert not sc.allows_host("x.internal.example.com")


def test_empty_or_invalid_host_is_never_in_scope():
    sc = make_scope()
    assert not sc.allows_host("")
    assert not sc.allows_host(None)


def test_partition_keeps_order():
    sc = make_scope()
    kept, dropped = sc.partition(["https://a.example.com/x", "evil.io", "b.example.com"])
    assert kept == ["https://a.example.com/x", "b.example.com"]
    assert dropped == ["evil.io"]


# validation and active gating
def test_empty_in_scope_is_rejected():
    with pytest.raises(S.ScopeError):
        S.Scope([])


@pytest.mark.parametrize("rps", [0, -1, "abc"])
def test_invalid_max_rps_is_rejected(rps):
    with pytest.raises(S.ScopeError):
        make_scope(max_rps=rps)


def test_unknown_allow_active_is_rejected():
    with pytest.raises(S.ScopeError):
        make_scope(allow_active=["nope"])


def test_active_names_need_explicit_allow():
    sc = make_scope()
    assert not sc.allows_active("injection")
    assert not sc.allows_active("zap-full")
    assert not sc.allows_active("recon-active")
    assert sc.allows_active("cors")                  # passive module
    assert make_scope(allow_active=["injection"]).allows_active("injection")


def test_default_rate_limit():
    assert make_scope().max_rps == S.DEFAULT_MAX_RPS
    assert make_scope(max_rps=2).max_rps == 2


def test_load_requires_enabled_block():
    assert S.load({}) is None
    assert S.load({"bounty": {"enabled": False, "in_scope": ["a.com"]}}) is None
    assert S.load({"bounty": {"enabled": True, "in_scope": ["a.com"]}}).allows_host("a.com")


def test_load_enabled_without_in_scope_fails():
    with pytest.raises(S.ScopeError):
        S.load({"bounty": {"enabled": True}})


# audit.py gate
def test_gate_is_off_without_bounty_mode():
    AU.SCOPE = None
    assert AU.scope_block("injection", "https://anything.io") is None


def test_gate_blocks_active_module_and_foreign_host():
    AU.SCOPE = make_scope()
    assert "injection" in AU.scope_block("injection", "https://app.example.com")
    assert "di luar scope" in AU.scope_block("cors", "https://evil.io")
    assert AU.scope_block("cors", "https://app.example.com") is None


def test_gate_allows_active_module_when_listed():
    AU.SCOPE = make_scope(allow_active=["injection"])
    assert AU.scope_block("injection", "https://app.example.com") is None


def test_py_module_block_reads_base_url_from_config(tmp_path):
    AU.SCOPE = make_scope()
    ok = tmp_path / "ok.yml"
    ok.write_text('base_url: "https://app.example.com"\n', encoding="utf-8")
    bad = tmp_path / "bad.yml"
    bad.write_text('base_url: "https://evil.io"\n', encoding="utf-8")
    assert AU.py_module_block("cors", ok) is None
    assert "di luar scope" in AU.py_module_block("cors", bad)
    assert "injection" in AU.py_module_block("injection", ok)


def test_zap_api_and_full_are_blocked_but_baseline_is_not():
    AU.SCOPE = make_scope()
    assert AU.mod_zap({"base_url": "https://app.example.com", "openapi": "x"}, "full") == 2
    assert AU.mod_zap({"base_url": "https://app.example.com", "openapi": "x"}, "api") == 2
    assert AU.scope_block("zap", "https://app.example.com") is None


def test_headers_and_tls_refuse_out_of_scope_hosts():
    AU.SCOPE = make_scope()
    assert AU.mod_headers({"base_url": "https://evil.io"}) == 2
    assert AU.mod_tls({"tls_host": "evil.io"}) == 2


def test_scope_command(capsys):
    AU.SCOPE = None
    assert AU.mod_scope({}, "baseline") == 2
    AU.SCOPE = make_scope(out_of_scope=["admin.example.com"])
    assert AU.mod_scope({}, "baseline") == 0
    assert AU.mod_scope({}, "https://app.example.com/x") == 0
    assert AU.mod_scope({}, "admin.example.com") == 1
    assert "OUT OF SCOPE" in capsys.readouterr().out


def test_init_scope_rejects_invalid_block(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "targets.yml").write_text("bounty:\n  enabled: true\n", encoding="utf-8")
    AU.PROJECT = tmp_path
    try:
        with pytest.raises(SystemExit) as e:
            AU.init_scope()
        assert e.value.code == 2
    finally:
        AU.PROJECT = AU.ROOT


def test_init_scope_loads_valid_block(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "targets.yml").write_text(
        'bounty:\n  enabled: true\n  in_scope: ["a.example.com"]\n', encoding="utf-8")
    AU.PROJECT = tmp_path
    try:
        AU.init_scope()
        assert AU.SCOPE.allows_host("a.example.com")
    finally:
        AU.PROJECT = AU.ROOT


# recon integration
def _run_tool(outputs):
    calls = []

    def run_tool(cmd, timeout=600, stdin=None):
        calls.append((cmd, stdin))
        return 0, outputs.get(Path(cmd[0]).name, "")

    run_tool.calls = calls
    return run_tool


def _all_installed(exe):
    return "/usr/bin/" + exe


def test_recon_drops_out_of_scope_subdomains_before_probing():
    scope = make_scope(max_rps=3)
    run = _run_tool({"subfinder": "a.example.com\nadmin.evil.io\nb.example.com\n"})
    cfg = {"target": "app.example.com", "tools": {}, "scope_guard": scope}
    results, _ = RC.phase_osint(cfg, run, _all_installed)
    httpx_cmd, httpx_stdin = next(c for c in run.calls if Path(c[0][0]).name == "httpx")
    assert "admin.evil.io" not in httpx_stdin
    assert "a.example.com" in httpx_stdin
    assert httpx_cmd[httpx_cmd.index("-rl") + 1] == "3"
    assert any("di luar scope" in r["check"] for r in results)


def test_recon_without_scope_is_unchanged():
    run = _run_tool({"subfinder": "a.example.com\nx.evil.io\n"})
    RC.phase_osint({"target": "app.example.com", "tools": {}}, run, _all_installed)
    httpx_cmd, httpx_stdin = next(c for c in run.calls if Path(c[0][0]).name == "httpx")
    assert "x.evil.io" in httpx_stdin
    assert "-rl" not in httpx_cmd


def test_recon_forces_osint_in_bounty_mode():
    run = _run_tool({})
    cfg = {"target": "app.example.com", "tools": {}, "depth": "full", "scope_guard": make_scope(),
           "active": {"enabled": True, "naabu": True, "nuclei": True}}
    RC.orchestrate(cfg, run, _all_installed)
    exes = {Path(c[0][0]).name for c in run.calls}
    assert not exes & {"naabu", "nuclei", "katana", "ffuf"}


def test_recon_active_runs_when_allowed():
    run = _run_tool({})
    cfg = {"target": "app.example.com", "tools": {}, "depth": "infra",
           "scope_guard": make_scope(allow_active=["recon-active"]),
           "active": {"enabled": True, "naabu": True}}
    RC.orchestrate(cfg, run, _all_installed)
    assert "naabu" in {Path(c[0][0]).name for c in run.calls}


def test_recon_main_refuses_out_of_scope_target(tmp_path, capsys):
    targets = tmp_path / "targets.yml"
    targets.write_text('bounty:\n  enabled: true\n  in_scope: ["app.example.com"]\n', encoding="utf-8")
    rc = RC.main(["evil.io", "--scope-file", str(targets), "--json", str(tmp_path / "r.json")])
    assert rc == 2
    assert "di luar scope" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_recon_main_rejects_broken_scope_file(tmp_path, capsys):
    targets = tmp_path / "targets.yml"
    targets.write_text("bounty:\n  enabled: true\n", encoding="utf-8")
    assert RC.main(["app.example.com", "--scope-file", str(targets)]) == 2


def test_recon_main_passes_scope_to_orchestrate(tmp_path, monkeypatch):
    targets = tmp_path / "targets.yml"
    targets.write_text('bounty:\n  enabled: true\n  in_scope: ["*.example.com"]\n', encoding="utf-8")
    seen = {}
    monkeypatch.setattr(RC, "orchestrate", lambda cfg: seen.update(cfg=cfg) or [])
    out = tmp_path / "r.json"
    assert RC.main(["app.example.com", "--scope-file", str(targets), "--json", str(out)]) == 0
    assert seen["cfg"]["scope_guard"].allows_host("x.example.com")
    assert json.loads(out.read_text(encoding="utf-8"))["module"] == "recon"
