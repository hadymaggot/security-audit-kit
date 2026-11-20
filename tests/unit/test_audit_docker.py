"""Unit test opsi docker_network pada audit.py — tanpa menjalankan Docker (run di-stub)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("audit_t", ROOT / "audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AU = _load()


def test_net_args_kosong_bila_tak_diset():
    assert AU.docker_net_args({}) == []
    assert AU.docker_net_args({"docker_network": ""}) == []
    assert AU.docker_net_args({"docker_network": "   "}) == []
    assert AU.docker_net_args(None) == []


def test_net_args_nilai_diteruskan():
    assert AU.docker_net_args({"docker_network": "host"}) == ["--network", "host"]
    assert AU.docker_net_args({"docker_network": "container:app-traefik-1"}) == \
        ["--network", "container:app-traefik-1"]
    assert AU.docker_net_args({"docker_network": "app_net_public"}) == \
        ["--network", "app_net_public"]


def _capture(monkeypatch):
    calls = []
    monkeypatch.setattr(AU, "have_docker", lambda: True)
    monkeypatch.setattr(AU, "run", lambda cmd: calls.append(cmd) or 0)
    return calls


def test_zap_baseline_memakai_network(monkeypatch):
    calls = _capture(monkeypatch)
    tgt = {"base_url": "http://localhost:8080", "docker_network": "container:gw"}
    AU.mod_zap(tgt, "baseline")
    cmd = calls[0]
    i = cmd.index("--network")
    assert cmd[i + 1] == "container:gw"
    assert cmd[:3] == ["docker", "run", "--rm"]          # --network ditaruh sebelum image
    assert cmd.index("--network") < cmd.index("zap-baseline.py")


def test_zap_full_dan_api_memakai_network(monkeypatch):
    # Scan AKTIF (full) dan API scan memakai base yang sama dengan baseline.
    calls = _capture(monkeypatch)
    tgt = {"base_url": "http://localhost:8080", "openapi": "http://localhost:8080/o.json",
           "docker_network": "container:gw"}
    AU.mod_zap(tgt, "full")
    AU.mod_zap(tgt, "api")
    for cmd in calls:
        assert cmd[cmd.index("--network") + 1] == "container:gw"
    assert "zap-full-scan.py" in calls[0] and "zap-api-scan.py" in calls[1]


def test_zap_baseline_tanpa_network_bila_tak_diset(monkeypatch):
    calls = _capture(monkeypatch)
    AU.mod_zap({"base_url": "http://x.example"}, "baseline")
    assert "--network" not in calls[0]


def test_tls_memakai_network(monkeypatch):
    calls = _capture(monkeypatch)
    AU.mod_tls({"tls_host": "x.example", "docker_network": "host"})
    cmd = calls[0]
    assert cmd[cmd.index("--network") + 1] == "host"
    assert cmd[-1] == "x.example"                          # host tetap argumen terakhir
