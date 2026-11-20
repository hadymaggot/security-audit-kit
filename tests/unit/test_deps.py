"""Unit test deps per tool + ingest gitleaks/semgrep ke laporan — tanpa Docker."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AU = _load("audit_deps_t", "audit.py")
RP = _load("report_deps_t", "report.py")


# ── pemilihan tool ──────────────────────────────────────────────────────────
def test_deps_selection():
    assert AU.deps_selection("gitleaks") == ("gitleaks",)
    assert AU.deps_selection("semgrep") == ("semgrep",)
    assert AU.deps_selection("trivy") == ("trivy",)
    assert AU.deps_selection("all") == ("gitleaks", "semgrep", "trivy")
    assert AU.deps_selection("baseline") == ("gitleaks", "semgrep", "trivy")   # default argparse


def _run_deps(monkeypatch, tmp_path, sub):
    calls = []
    monkeypatch.setattr(AU, "have_docker", lambda: True)
    monkeypatch.setattr(AU, "reports_dir", lambda: tmp_path)
    monkeypatch.setattr(AU, "run", lambda cmd: calls.append(cmd) or 0)
    monkeypatch.setattr(AU, "run_semgrep",
                        lambda tgt, repo, out, runner=None: calls.append(AU.semgrep_cmd(tgt, repo, out, "n")) or 0)
    # Cache trivy ke folder sementara: test tidak boleh menyentuh ~/.cache/sak-trivy atau ikut
    # mengantre pada kunci milik audit sungguhan yang sedang menjalankan trivy.
    rc = AU.mod_deps({"code_path": str(tmp_path), "trivy_cache_dir": str(tmp_path / "trivy-cache")}, sub)
    return rc, calls


def test_satu_tool_saja_dijalankan(monkeypatch, tmp_path):
    for tool, image in (("gitleaks", "gitleaks"), ("semgrep", "semgrep"), ("trivy", "trivy")):
        rc, calls = _run_deps(monkeypatch, tmp_path, tool)
        assert rc == 0 and calls, tool
        joined = " ".join(" ".join(c) for c in calls)
        assert image in joined
        others = {"gitleaks", "semgrep", "trivy"} - {tool}
        assert not any(o in joined for o in others), f"{tool} tak boleh menjalankan {others}"


def test_semua_tool_bila_tanpa_pilihan(monkeypatch, tmp_path):
    rc, calls = _run_deps(monkeypatch, tmp_path, "all")
    joined = " ".join(" ".join(c) for c in calls)
    assert all(t in joined for t in ("gitleaks", "semgrep", "trivy"))
    assert len(calls) == 4                                     # gitleaks, semgrep, trivy tabel + json


def test_json_gitleaks_dan_semgrep_ditulis_ke_out(monkeypatch, tmp_path):
    _, g = _run_deps(monkeypatch, tmp_path, "gitleaks")
    c = g[0]
    assert "--report-path" in c and c[c.index("--report-path") + 1] == "/out/gitleaks.json"
    assert any(x.endswith(":/out") for x in c)                 # volume keluaran terpasang
    _, s = _run_deps(monkeypatch, tmp_path, "semgrep")
    script = s[0][-1]
    assert "--json-output /out/semgrep.json" in script and "/out" in " ".join(s[0])


def test_repo_dipasang_read_only(monkeypatch, tmp_path):
    _, calls = _run_deps(monkeypatch, tmp_path, "all")
    assert all(any(x.endswith(":ro") for x in c) for c in calls)


# ── ingest laporan ──────────────────────────────────────────────────────────
def test_report_memuat_gitleaks(tmp_path):
    (tmp_path / "gitleaks.json").write_text(json.dumps([
        {"RuleID": "aws-access-token", "File": "app/cfg.py", "StartLine": 12, "Commit": "abcdef123456",
         "Description": "AWS Access Key", "Secret": "REDACTED"}]), encoding="utf-8")
    f = RP.collect(tmp_path)
    assert len(f) == 1
    g = f[0]
    assert g["kind"] == "leaked-secret" and g["severity"] == "high" and not g["passed"]
    assert "app/cfg.py:12" in g["title"] and "abcdef12" in g["evidence"]
    assert "tidak dicantumkan" in g["evidence"] and "REDACTED" not in g["evidence"]


def test_report_memuat_semgrep_dengan_cwe_dan_severity(tmp_path):
    (tmp_path / "semgrep.json").write_text(json.dumps({"results": [
        {"check_id": "php.laravel.security.sql-injection", "path": "app/Ctl.php",
         "start": {"line": 40}, "extra": {"severity": "ERROR", "message": "<p>Query rentan</p>",
                                           "metadata": {"cwe": ["CWE-89: SQL Injection"]}}},
        {"check_id": "x.y.warn-rule", "path": "a.js", "start": {"line": 3},
         "extra": {"severity": "WARNING", "message": "perhatian"}}]}), encoding="utf-8")
    f = {x["title"]: x for x in RP.collect(tmp_path)}
    sql = f["sql-injection — app/Ctl.php:40"]
    assert sql["kind"] == "sast-finding" and sql["severity"] == "high" and sql["cve"] == ["CWE-89"]
    assert "<p>" not in sql["evidence"] and "Query rentan" in sql["evidence"]
    assert f["warn-rule — a.js:3"]["severity"] == "medium"
    assert "sast-finding" in RP.KIND_LABEL and RP.cvss_for("sast-finding", "medium")[0] == 5.3


def test_report_toleran_json_rusak_atau_kosong(tmp_path):
    (tmp_path / "gitleaks.json").write_text("{bukan list", encoding="utf-8")
    (tmp_path / "semgrep.json").write_text(json.dumps({"results": None}), encoding="utf-8")
    assert RP.collect(tmp_path) == []


# ── semgrep: opsi path/exclude dan batas waktu ──────────────────────────────
def test_semgrep_cmd_menyalin_path_lalu_memindai_di_container():
    c = AU.semgrep_cmd({"semgrep_paths": ["services/iam/app", "frontend-vue/src"],
                        "semgrep_exclude": ["legacy"]}, "R", "O", "sak-x")
    assert c[c.index("--name") + 1] == "sak-x" and "--entrypoint" in c and c[c.index("--entrypoint") + 1] == "sh"
    script = c[-1]
    # salin hanya path terpilih (tar) ke /tmp/scan lalu pindai di sana (bukan dari akar repo bind mount)
    assert "tar -C /src" in script and "services/iam/app" in script and "frontend-vue/src" in script
    assert "-C /tmp/scan -xf -" in script and "cd /tmp/scan" in script and "-w /src" not in " ".join(c)
    for e in ("vendor", "node_modules", "dist", "docs", "legacy"):
        assert f"--exclude={e}" in script and f"--exclude {e}" in script
    assert "--no-git-ignore" in script and "--timeout 20" in script
    assert AU.semgrep_cmd({}, "R", "O", "n")[-1].count(" .") >= 1               # default memindai "."


def test_semgrep_cmd_mengutip_path_berspasi():
    script = AU.semgrep_cmd({"semgrep_paths": ["dir dengan spasi/app"]}, "R", "O", "n")[-1]
    assert "'dir dengan spasi/app'" in script


def test_run_semgrep_timeout_menghentikan_container(monkeypatch):
    import subprocess
    rm = []
    monkeypatch.setattr(subprocess, "call", lambda cmd, **k: rm.append(cmd) or 0)

    def runner(cmd, timeout):
        assert timeout == 0.6                                              # 0,01 menit
        raise subprocess.TimeoutExpired(cmd, timeout)
    rc = AU.run_semgrep({"semgrep_timeout_minutes": 0.01}, "R", "O", runner=runner)
    assert rc == 1 and rm and rm[0][:3] == ["docker", "rm", "-f"]


def test_run_semgrep_sukses_mengembalikan_rc(monkeypatch):
    class R:
        returncode = 0
    assert AU.run_semgrep({}, "R", "O", runner=lambda cmd, timeout: R()) == 0
