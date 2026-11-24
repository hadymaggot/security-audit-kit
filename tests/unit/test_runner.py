"""Unit tests for runner.py, the autonomous audit runner (config handling, matrix, naming, leak scan)."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("runner_t", ROOT / "runner.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["runner_t"] = mod
    spec.loader.exec_module(mod)
    return mod


RN = _load()
EXAMPLE = yaml.safe_load((ROOT / "config" / "runner.example.yml").read_text(encoding="utf-8"))


def _cfg(data=None, tmp=None):
    return RN.Config(data if data is not None else EXAMPLE, (tmp or ROOT) / "audit.config.yml", tmp or ROOT)


# --- config validation ---

def test_example_config_is_valid():
    assert RN.validate_config(EXAMPLE) == []


def test_validate_reports_missing_login_and_unknown_module():
    data = json.loads(json.dumps(EXAMPLE))
    del data["api"]["login"]["path"]
    data["pipeline"].append("no-such-module")
    problems = RN.validate_config(data)
    assert any("api.login.path" in p for p in problems)
    assert any("no-such-module" in p for p in problems)


def test_validate_flags_module_pointing_at_missing_target():
    data = json.loads(json.dumps(EXAMPLE))
    data["modules"]["cors"]["targets"] = ["staging"]
    assert any("staging" in p for p in RN.validate_config(data))


def test_validate_remote_target_needs_env_file_and_url_key():
    data = json.loads(json.dumps(EXAMPLE))
    data["targets"]["dev"] = {"kind": "remote"}
    assert any("env_file" in p for p in RN.validate_config(data))


def test_validate_flags_unknown_stack_step_and_target_kind():
    data = json.loads(json.dumps(EXAMPLE))
    data["stack"]["up"].append({"type": "teleport"})
    data["targets"]["odd"] = {"kind": "cloud"}
    problems = RN.validate_config(data)
    assert any("teleport" in p for p in problems) and any("targets.odd.kind" in p for p in problems)


def test_validate_requires_pipeline_modules_to_be_defined():
    data = json.loads(json.dumps(EXAMPLE))
    del data["modules"]["jwt"]
    assert any("modules.jwt" in p for p in RN.validate_config(data))


# --- config access ---

def test_module_merges_by_target_override():
    cfg = _cfg()
    assert cfg.module("injection", "local")["time_based"] is True
    assert cfg.module("injection", "dev")["time_based"] is False
    assert "by_target" not in cfg.module("injection", "local")


def test_module_enabled_follows_targets_list():
    cfg = _cfg()
    assert cfg.module_enabled("tls", "dev") and not cfg.module_enabled("tls", "local")
    assert not cfg.module_enabled("not-defined", "local")


def test_unknown_target_is_a_clear_error():
    with pytest.raises(RN.AuditError, match="Target tidak dikenal"):
        _cfg().target("production")


def test_config_key_defaults_to_slug_of_name():
    data = {"project": {"name": "My Great App!"}}
    assert _cfg(data).key == "my-great-app"
    assert _cfg(EXAMPLE).key == "example-app"


# --- helpers ---

def test_fill_replaces_known_placeholders_only():
    out = RN.fill({"a": "{username}-{other}", "b": ["{password}"]}, {"username": "u", "password": "p"})
    assert out == {"a": "u-{other}", "b": ["p"]}


def test_deep_merge_overrides_nested_keys_without_touching_the_base():
    base = {"a": {"x": 1, "y": 2}, "b": 1}
    merged = RN.deep_merge(base, {"a": {"y": 3}})
    assert merged == {"a": {"x": 1, "y": 3}, "b": 1} and base["a"]["y"] == 2


def test_dig_follows_dotted_paths():
    assert RN.dig({"data": {"token": "t"}}, "data.token") == "t"
    assert RN.dig({"data": {}}, "data.token") is None


def test_env_name_is_shell_safe():
    assert RN.env_name("SAK_TOK_", "senior-editor") == "SAK_TOK_SENIOR_EDITOR"


def test_read_env_strips_quotes_and_ignores_comments(tmp_path):
    f = tmp_path / ".env"
    f.write_text('# comment\nA=1\nB="two words"\nC=\'x\'\nbad line\n', encoding="utf-8")
    assert RN.read_env(f) == {"A": "1", "B": "two words", "C": "x"}


# --- access matrix ---

def _sess(role, perms, token="tok"):
    return RN.Session(role, role + "-user", token, role, perms, 3600)


def test_authz_matrix_is_generated_from_real_permissions():
    sessions = {"admin": _sess("admin", ["users.read", "users.delete"], "a"), "user": _sess("user", [], "u")}
    cfg, env = RN.authz_matrix(sessions, EXAMPLE["api"], EXAMPLE["modules"]["authz"]["endpoints"])
    cases = {c["name"]: c["expect"] for c in cfg["endpoints"]}
    assert cases["List users"] == {"admin": "allow", "user": "deny", "anon": "deny"}
    # A write endpoint is never sent to an authorized role.
    assert cases["Delete user"] == {"user": "deny", "anon": "deny"}
    assert env == {"SAK_TOK_ADMIN": "a", "SAK_TOK_USER": "u"}
    assert cfg["auth"]["roles"]["admin"]["token"] == "${SAK_TOK_ADMIN}"
    assert cfg["auth"]["roles"]["anon"] == {"anonymous": True}


def test_authz_matrix_uses_login_settings_of_the_project():
    cfg, _ = RN.authz_matrix({"a": _sess("a", [])}, EXAMPLE["api"], [])
    assert cfg["auth"]["login"]["path"] == "/api/auth/login" and cfg["auth"]["login"]["token_field"] == "data.accessToken"


# --- template expansion in the stack section ---

def _stack(tmp_path, env=None):
    ctx = SimpleNamespace(cfg=_cfg(tmp=tmp_path), stack_env=env or {}, repo=tmp_path, work=tmp_path / "work", base="http://x")
    return RN.Stack(ctx)


def test_expand_env_repo_work_and_base_url(tmp_path):
    st = _stack(tmp_path, {"KEY": "v"})
    assert st.expand("${env:KEY}") == "v"
    assert st.expand("${repo}|${work}|{base_url}") == f"{tmp_path.as_posix()}|{(tmp_path / 'work').as_posix()}|http://x"


def test_expand_file_reads_a_value_with_a_regex_and_falls_back(tmp_path):
    (tmp_path / "schema.ts").write_text("export const DIM = 2048;", encoding="utf-8")
    st = _stack(tmp_path, {"DIM": "1536"})
    assert st.expand("${file:schema.ts|||DIM = ([0-9]+)|||9}") == "2048"
    assert st.expand("${file:missing.ts|||DIM = ([0-9]+)|||${env:DIM}}") == "1536"


def test_expand_works_inside_dicts_and_lists(tmp_path):
    st = _stack(tmp_path, {"K": "1"})
    assert st.expand({"a": ["${env:K}"], "b": 5}) == {"a": ["1"], "b": 5}


# --- login pacing ---

def test_login_waits_for_retry_after_then_succeeds(monkeypatch):
    seq = [(429, {"retry-after": "5"}, {}), (200, {}, {"data": {"accessToken": "t"}})]
    monkeypatch.setattr(RN, "http", lambda *a, **k: seq.pop(0))
    slept = []
    monkeypatch.setattr(RN.time, "sleep", slept.append)
    status, data = RN.Login("http://x", EXAMPLE["api"]).sign_in("u", "p")
    assert status == 200 and data["data"]["accessToken"] == "t" and slept == [8]


def test_ensure_quota_waits_for_the_window_to_reset(monkeypatch):
    monkeypatch.setattr(RN, "http", lambda *a, **k: (401, {"ratelimit": "limit=20, remaining=1, reset=40"}, {}))
    slept = []
    monkeypatch.setattr(RN.time, "sleep", slept.append)
    RN.Login("http://x", EXAMPLE["api"]).ensure_quota(5)
    assert slept == [43]


# --- session check rule for stateless JWT ---

def test_access_token_check_accepts_short_lived_tokens_and_flags_long_ones():
    ctx = SimpleNamespace(cfg=_cfg(), base="http://x")
    check = RN.SessionCheck(ctx, {"reasonable_ttl_seconds": 3600})
    check.access_token_check("revoked", 401, 7200)
    check.access_token_check("short", 200, 900)
    check.access_token_check("long", 200, 86400)
    assert [r["ok"] for r in check.results] == [True, True, False]


# --- secret scan ---

def test_scan_secrets_finds_known_secrets_and_jwt_like_tokens(tmp_path):
    (tmp_path / "a.md").write_text("nothing here", encoding="utf-8")
    (tmp_path / "b.md").write_text("password is S3cr3t-Value", encoding="utf-8")
    (tmp_path / "c.md").write_text("token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", encoding="utf-8")
    assert sorted(RN.scan_secrets(tmp_path, {"S3cr3t-Value", "x"})) == ["b.md", "c.md"]


# --- run naming, history and finish ---

class _FakeCtx:
    """Just enough of Context for finish(): the kit call is replaced by a function writing fake reports."""

    def __init__(self, tmp):
        self.cfg = _cfg(tmp=tmp)
        self.repo = tmp
        self.args = SimpleNamespace(out=None)
        self.target_name = "local"
        self.project = tmp / "kit-project"
        self.summary = [("authz", "selesai", "ok")]
        self.sessions = {}
        self.base = "http://localhost"
        self.level = "local"
        self.secrets = set()

    def audit(self, project, args, extra_env=None, name="", timeout=0):
        reports = self.project / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "laporan.md").write_text("# report", encoding="utf-8")
        (reports / "laporan.html").write_text("<html></html>", encoding="utf-8")
        (reports / "laporan-slides.html").write_text("Laporan lengkap: laporan.html", encoding="utf-8")
        (reports / "authz.json").write_text("{}", encoding="utf-8")
        return 0, "Total 1 item, 0 perlu tindak lanjut, 0 CVE.\n  Critical 0 | High 0"


def test_run_name_has_prefix_project_target_and_time():
    ctx = SimpleNamespace(cfg=_cfg(), target_name="Local Dev")
    assert RN.run_name(ctx, "20261125-101500") == "security-audit-kit_example-app_local-dev_20261125-101500"


def test_finish_keeps_earlier_runs_and_names_files_uniquely(tmp_path, monkeypatch):
    monkeypatch.setattr(RN.time, "strftime", lambda fmt, *a: "20261125-101500" if fmt == "%Y%m%d-%H%M%S" else "t")
    ctx = _FakeCtx(tmp_path)
    assert RN.finish(ctx) == 0
    assert RN.finish(ctx) == 0                     # same second: must not overwrite the first run
    base = tmp_path / "docs" / "security-audit"
    runs = sorted(p.name for p in base.iterdir() if p.is_dir())
    assert runs == ["security-audit-kit_example-app_local_20261125-101500",
                    "security-audit-kit_example-app_local_20261125-101500-2"]
    first = base / runs[0]
    assert (first / f"{runs[0]}.md").exists() and (first / f"{runs[0]}.html").exists()
    assert (first / f"{runs[0]}-slides.html").exists() and (first / f"{runs[0]}-ringkasan.md").exists()
    assert not (first / "laporan.md").exists()
    assert (first / "data" / "authz.json").exists() and not (first / "authz.json").exists()   # raw output is tucked away
    assert (first / "data" / "README.md").read_text(encoding="utf-8") == RN.DATA_README   # static, same for every run
    assert f"{runs[0]}.html" in (first / f"{runs[0]}-slides.html").read_text(encoding="utf-8")
    assert len((base / "RIWAYAT.md").read_text(encoding="utf-8").splitlines()) == 6     # header + 2 runs


def test_finish_removes_only_the_leaking_run(tmp_path, monkeypatch):
    stamps = iter(["20261125-101500", "20261125-101600"])
    monkeypatch.setattr(RN.time, "strftime", lambda fmt, *a: next(stamps) if fmt == "%Y%m%d-%H%M%S" else "t")
    ctx = _FakeCtx(tmp_path)
    RN.finish(ctx)
    ctx.secrets = {"# report"}                     # the fake report text contains this string
    with pytest.raises(RN.AuditError, match="Pemindaian rahasia GAGAL"):
        RN.finish(ctx)
    runs = [p.name for p in (tmp_path / "docs" / "security-audit").iterdir() if p.is_dir()]
    assert runs == ["security-audit-kit_example-app_local_20261125-101500"]


# --- target level and prepare_target ---

def test_remote_prod_target_runs_only_passive_modules(tmp_path):
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / ".env.dev").write_text("TARGET_BASE_URL=https://app.example\nTARGET_ENV=prod\n"
                                                 "APP_USER_ADMIN=a\nAPP_PASS_ADMIN=pw-admin\n", encoding="utf-8")
    data = json.loads(json.dumps(EXAMPLE))
    data["targets"]["dev"]["env_file"] = "audit/.env.dev"
    cfg = _cfg(data, tmp_path)
    args = argparse.Namespace(target="dev", repo_root=str(tmp_path), work_dir=str(tmp_path / "work"), only=None, skip=None,
                              no_up=True, roles_limit=None, force_active=False, env_file=None)
    ctx = RN.Context(cfg, args)
    ctx.prepare_target()
    assert ctx.level == "prod" and "authz" in ctx.skip and "headers" not in ctx.skip
    assert not ctx.selected("authz") and ctx.selected("headers")
    assert ctx.accounts == {"admin": ("a", "pw-admin")} and "pw-admin" in ctx.secrets


def test_remote_target_requires_level_value(tmp_path):
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / ".env.dev").write_text("TARGET_BASE_URL=https://app.example\nTARGET_ENV=whatever\n", encoding="utf-8")
    data = json.loads(json.dumps(EXAMPLE))
    data["targets"]["dev"]["env_file"] = "audit/.env.dev"
    args = argparse.Namespace(target="dev", repo_root=str(tmp_path), work_dir=str(tmp_path / "work"), only=None, skip=None,
                              no_up=True, roles_limit=None, force_active=False, env_file=None)
    ctx = RN.Context(_cfg(data, tmp_path), args)
    with pytest.raises(RN.AuditError, match="TARGET_ENV"):
        ctx.prepare_target()


# --- init and check commands ---

def test_init_creates_a_valid_config_and_never_overwrites(tmp_path):
    target = tmp_path / "sec" / "audit.config.yml"
    assert RN.command_init(argparse.Namespace(config=str(target))) == 0
    assert RN.validate_config(yaml.safe_load(target.read_text(encoding="utf-8"))) == []
    with pytest.raises(RN.AuditError, match="sudah ada"):
        RN.command_init(argparse.Namespace(config=str(target)))


def test_check_command_returns_2_on_an_invalid_config(tmp_path):
    bad = tmp_path / "audit.config.yml"
    bad.write_text("project: {name: X}\n", encoding="utf-8")
    assert RN.command_check(argparse.Namespace(config=str(bad))) == 2
    good = tmp_path / "good.yml"
    good.write_text((ROOT / "config" / "runner.example.yml").read_text(encoding="utf-8"), encoding="utf-8")
    assert RN.command_check(argparse.Namespace(config=str(good))) == 0


# --- environments without git ---

def _no_git(*args, **kwargs):
    raise FileNotFoundError("git")


def test_kit_version_falls_back_when_git_is_missing(monkeypatch):
    monkeypatch.setattr(RN, "run", _no_git)
    assert RN.kit_version() == "tidak diketahui"


def test_finish_works_without_git(tmp_path, monkeypatch):
    """A zip download or a minimal CI image has no git; the report must still be built and copied."""
    monkeypatch.setattr(RN, "run", _no_git)
    ctx = _FakeCtx(tmp_path)
    assert RN.finish(ctx) == 0
    summary = next((tmp_path / "docs" / "security-audit").glob("*/*-ringkasan.md"))
    assert "tidak diketahui" in summary.read_text(encoding="utf-8")


# --- config location: inside the kit or in the application repo ---

def _write_config(path, repo=None):
    data = json.loads(json.dumps(EXAMPLE))
    data["project"].pop("repo", None)
    if repo:
        data["project"]["repo"] = repo
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_config_in_the_kit_needs_project_repo(tmp_path, monkeypatch):
    kit = tmp_path / "kit"
    (kit / ".git").mkdir(parents=True)
    monkeypatch.setattr(RN, "KIT", kit)
    path = _write_config(kit / "projects" / "app" / "audit.config.yml")
    with pytest.raises(RN.AuditError, match="project.repo"):
        RN.Config.load(path)


def test_project_repo_can_be_absolute_or_relative_to_the_config(tmp_path, monkeypatch):
    kit = tmp_path / "kit"
    (kit / ".git").mkdir(parents=True)
    monkeypatch.setattr(RN, "KIT", kit)
    app = tmp_path / "app"
    app.mkdir()
    absolute = RN.Config.load(_write_config(kit / "projects" / "a" / "audit.config.yml", app.as_posix()))
    relative = RN.Config.load(_write_config(kit / "projects" / "b" / "audit.config.yml", "../../../app"))
    assert absolute.repo == app and relative.repo == app.resolve()


def test_config_in_the_application_repo_uses_the_nearest_git_root(tmp_path):
    (tmp_path / ".git").mkdir()
    cfg = RN.Config.load(_write_config(tmp_path / "security-audit" / "audit.config.yml"))
    assert cfg.repo == tmp_path


def test_resolve_path_prefers_the_file_next_to_the_config(tmp_path):
    repo, cfg_dir = tmp_path / "repo", tmp_path / "cfg"
    repo.mkdir()
    cfg_dir.mkdir()
    (cfg_dir / ".env.dev").write_text("A=1", encoding="utf-8")
    (repo / ".env.dev").write_text("A=2", encoding="utf-8")
    ctx = SimpleNamespace(cfg=SimpleNamespace(path=cfg_dir / "audit.config.yml"), repo=repo)
    assert RN.Context.resolve_path(ctx, ".env.dev") == cfg_dir / ".env.dev"
    (cfg_dir / ".env.dev").unlink()
    assert RN.Context.resolve_path(ctx, ".env.dev") == repo / ".env.dev"
    assert RN.Context.resolve_path(ctx, str(tmp_path / "abs.env")) == tmp_path / "abs.env"


def test_finish_keeps_the_evidence_folder_at_the_top_level(tmp_path, monkeypatch):
    """The report links evidence images by relative path, so only loose raw files go to data/."""
    ctx = _FakeCtx(tmp_path)
    original = ctx.audit

    def with_evidence(*args, **kwargs):
        result = original(*args, **kwargs)
        shot = ctx.project / "reports" / "evidence"
        shot.mkdir(exist_ok=True)
        (shot / "a.png").write_bytes(b"x")
        return result

    ctx.audit = with_evidence
    RN.finish(ctx)
    run = next((tmp_path / "docs" / "security-audit").glob("security-audit-kit_*"))
    assert (run / "evidence" / "a.png").exists() and not (run / "data" / "evidence").exists()
