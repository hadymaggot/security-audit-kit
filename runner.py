#!/usr/bin/env python3
"""Autonomous audit runner for the Security Audit Kit.

One command runs the whole flow with no manual steps and no AI involved:
  1. check prerequisites and load the project config,
  2. (target kind "stack") start the application stack,
  3. log in every test account, pacing around the login rate limit,
  4. generate the module configs and the access matrix from the permissions the server really grants,
  5. run the scans and the dynamic tests,
  6. build the report, scan it for leaked secrets, and copy it to the project output folder.

Everything that depends on the project lives in one YAML file (see config/runner.example.yml).
The runner itself holds no project specific value, so it works for existing and future projects.

Examples:
  python runner.py init --config security-audit/audit.config.yml
  python runner.py check --config security-audit/audit.config.yml
  python runner.py run --config security-audit/audit.config.yml --target local
  python runner.py down --config security-audit/audit.config.yml

Standard library plus PyYAML only (already required by the kit).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KIT = Path(__file__).resolve().parent
USER_AGENT = "security-audit-kit/1.0"
IS_WINDOWS = os.name == "nt"
DEFAULT_CONFIG_NAMES = ["audit.config.yml", "security-audit/audit.config.yml", "scripts/security-audit/audit.config.yml"]
EXAMPLE_CONFIG = KIT / "config" / "runner.example.yml"

KNOWN_MODULES = [
    "deps", "headers", "tls", "webstack", "cookie-flags", "authz", "cors", "response-leak", "injection",
    "clientleak", "openapi-coverage", "open-redirect", "jwt", "upload", "mass-assignment", "ssrf", "session",
    "auth-policy", "zap", "ratelimit",
]
KNOWN_STEPS_UP = {"compose", "docker_run", "node_deps", "run", "seed_if_empty", "process", "web"}
KNOWN_STEPS_DOWN = {"compose_down", "docker_rm", "process_stop"}
# Modules that init needs a per module example config for (the others use targets.yml only).
INIT_MODULES = ("authz,cors,cookie-flags,open-redirect,response-leak,openapi-coverage,jwt,injection,upload,"
                "ratelimit,mass-assignment,ssrf,auth-policy,clientleak,webstack")


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


class AuditError(Exception):
    """An error that stops the whole run with a clear message for the user."""


# ── generic helpers ─────────────────────────────────────────────────────────

def read_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            result[m.group(1)] = value
    return result


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None, timeout: int | None = None,
        check: bool = True) -> subprocess.CompletedProcess:
    """Run a command without a shell. Output is decoded as UTF-8."""
    exe = shutil.which(cmd[0])
    if exe:
        cmd = [exe] + cmd[1:]
    done = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    if check and done.returncode != 0:
        tail = (done.stdout + done.stderr).strip().splitlines()[-8:]
        raise AuditError(f"Perintah gagal ({' '.join(cmd[:4])} ...): " + " | ".join(tail))
    return done


def http(method: str, url: str, body=None, token: str | None = None, timeout: int = 30):
    """HTTP request with an identifying User-Agent. Returns (status, lowercase headers, json)."""
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data, headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        status, hdr, raw = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        status, hdr, raw = e.code, e.headers, e.read()
    except Exception:
        return 0, {}, {}
    try:
        payload = json.loads(raw or b"{}")
    except Exception:
        payload = {}
    return status, {k.lower(): v for k, v in hdr.items()}, payload


def wait_for(condition, limit: int, interval: float = 3.0) -> bool:
    end = time.time() + limit
    while time.time() < end:
        try:
            if condition():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def dig(obj, dotted: str):
    """Value at a dotted path such as data.accessToken, or None."""
    for part in dotted.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def fill(obj, values: dict):
    """Replace {key} placeholders with the given values, recursively. Unknown placeholders stay as they are."""
    if isinstance(obj, str):
        for key, value in values.items():
            obj = obj.replace("{" + key + "}", str(value))
        return obj
    if isinstance(obj, list):
        return [fill(x, values) for x in obj]
    if isinstance(obj, dict):
        return {k: fill(v, values) for k, v in obj.items()}
    return obj


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def env_name(prefix: str, role: str) -> str:
    return prefix + re.sub(r"[^A-Z0-9]", "_", role.upper())


# ── config ──────────────────────────────────────────────────────────────────

def validate_config(data: dict) -> list[str]:
    """Return the problems found in a config. An empty list means it is usable."""
    problems: list[str] = []
    if not isinstance(data, dict):
        return ["config bukan pemetaan YAML"]
    if not (data.get("project") or {}).get("name"):
        problems.append("project.name wajib diisi")
    api = data.get("api") or {}
    if not (api.get("login") or {}).get("path"):
        problems.append("api.login.path wajib diisi")
    if not (api.get("login") or {}).get("token_field"):
        problems.append("api.login.token_field wajib diisi")
    if not (api.get("me") or {}).get("path"):
        problems.append("api.me.path wajib diisi")
    targets = data.get("targets") or {}
    if not targets:
        problems.append("targets kosong: definisikan minimal satu target")
    for name, tgt in targets.items():
        kind = (tgt or {}).get("kind")
        if kind not in ("stack", "remote"):
            problems.append(f"targets.{name}.kind harus stack atau remote")
        if kind == "remote" and not (tgt.get("env_file") and tgt.get("base_url_key")):
            problems.append(f"targets.{name}: kind remote butuh env_file dan base_url_key")
        if kind == "stack" and not tgt.get("base_url"):
            problems.append(f"targets.{name}: kind stack butuh base_url")
    pipeline = data.get("pipeline")
    if not isinstance(pipeline, list) or not pipeline:
        problems.append("pipeline harus berupa daftar modul")
    else:
        for module in pipeline:
            if module not in KNOWN_MODULES:
                problems.append(f"pipeline memuat modul tak dikenal: {module} (dikenal: {', '.join(KNOWN_MODULES)})")
            elif module not in (data.get("modules") or {}):
                problems.append(f"modules.{module} belum didefinisikan")
    modules = data.get("modules") or {}
    for module, settings in modules.items():
        for tgt in (settings or {}).get("targets", []):
            if tgt not in targets:
                problems.append(f"modules.{module}.targets menyebut target yang tidak ada: {tgt}")
    stack = data.get("stack") or {}
    for step in stack.get("up", []):
        if step.get("type") not in KNOWN_STEPS_UP:
            problems.append(f"stack.up: tipe langkah tak dikenal: {step.get('type')}")
    for step in stack.get("down", []):
        if step.get("type") not in KNOWN_STEPS_DOWN:
            problems.append(f"stack.down: tipe langkah tak dikenal: {step.get('type')}")
    if any((t or {}).get("kind") == "stack" for t in targets.values()):
        if not stack.get("up"):
            problems.append("ada target kind stack tetapi stack.up kosong")
        if not (data.get("accounts") or {}).get("stack", {}).get("query"):
            problems.append("target kind stack butuh accounts.stack.query")
    return problems


class Config:
    def __init__(self, data: dict, path: Path, repo: Path):
        self.data = data
        self.path = path
        self.repo = repo

    @classmethod
    def load(cls, path: Path, repo: Path | None = None) -> "Config":
        if not path.exists():
            raise AuditError(f"Config tidak ditemukan: {path}. Buat dengan: python runner.py init --config {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(data, path.resolve(), repo or find_repo_root(path.resolve().parent))

    def get(self, dotted: str, default=None):
        value = dig(self.data, dotted)
        return default if value is None else value

    def target(self, name: str) -> dict:
        targets = self.data.get("targets") or {}
        if name not in targets:
            raise AuditError(f"Target tidak dikenal: {name}. Tersedia: {', '.join(targets)}")
        return targets[name]

    def module(self, module: str, target: str) -> dict:
        """Module settings merged with the by_target override of the given target."""
        settings = copy.deepcopy((self.data.get("modules") or {}).get(module) or {})
        override = (settings.pop("by_target", None) or {}).get(target) or {}
        return deep_merge(settings, override)

    def module_enabled(self, module: str, target: str) -> bool:
        return target in ((self.data.get("modules") or {}).get(module) or {}).get("targets", [])

    @property
    def key(self) -> str:
        explicit = self.get("project.key")
        return explicit or re.sub(r"[^a-z0-9]+", "-", str(self.get("project.name", "project")).lower()).strip("-")


def find_repo_root(start: Path) -> Path:
    for p in [start, *start.parents]:
        if (p / ".git").exists():
            return p
    return start


def find_config(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    for name in DEFAULT_CONFIG_NAMES:
        if Path(name).exists():
            return Path(name)
    raise AuditError("Config tidak ditemukan. Berikan --config atau buat dengan: python runner.py init")


# ── login and rate limit ───────────────────────────────────────────────────

class Login:
    """Login that waits for Retry-After on a rate limit instead of failing."""

    def __init__(self, base: str, api: dict):
        self.base = base.rstrip("/")
        self.cfg = api["login"]
        self.probe = api.get("login_probe") or {"username": "sak-probe", "password": "x"}

    def body(self, username: str, password: str) -> dict:
        return fill(self.cfg.get("body") or {"username": "{username}", "password": "{password}"},
                    {"username": username, "password": password})

    def sign_in(self, username: str, password: str, max_waits: int = 6) -> tuple[int, dict]:
        waits = 0
        while True:
            status, hdr, payload = http("POST", self.base + self.cfg["path"], self.body(username, password))
            if status == 429 and waits < max_waits:
                delay = int(hdr.get("retry-after", "60")) + 3
                log(f"  login dibatasi (429), menunggu {delay} detik")
                time.sleep(delay)
                waits += 1
                continue
            return status, payload

    def remaining_quota(self) -> tuple[int, int]:
        """Send one invalid login to read the RateLimit header. Returns (remaining, seconds to reset)."""
        status, hdr, _ = http("POST", self.base + self.cfg["path"],
                              self.body(self.probe["username"], self.probe["password"]))
        if status == 429:
            return 0, int(hdr.get("retry-after", "60"))
        m = re.search(r"remaining=(\d+).*reset=(\d+)", hdr.get("ratelimit", ""))
        return (int(m.group(1)), int(m.group(2))) if m else (99, 0)

    def ensure_quota(self, needed: int) -> None:
        remaining, reset = self.remaining_quota()
        if remaining < needed:
            log(f"  kuota login tinggal {remaining}, menunggu {reset + 3} detik agar jendela reset")
            time.sleep(reset + 3)


@dataclass
class Session:
    role: str
    username: str
    token: str
    role_code: str
    permissions: list[str]
    ttl: int
    created: float = field(default_factory=time.time)


# ── run context ─────────────────────────────────────────────────────────────

class Context:
    def __init__(self, cfg: Config, args: argparse.Namespace):
        self.cfg = cfg
        self.args = args
        self.target_name = args.target
        self.target = cfg.target(args.target)
        self.repo = Path(args.repo_root).resolve() if getattr(args, "repo_root", None) else cfg.repo
        self.work = Path(args.work_dir).resolve() if getattr(args, "work_dir", None) else cfg.path.parent / "work"
        (self.work / "log").mkdir(parents=True, exist_ok=True)
        key = cfg.key
        self.project = KIT / "projects" / f"{key}-{args.target}"
        self.project_zap = KIT / "projects" / f"{key}-{args.target}-zap"
        self.project_locks = KIT / "projects" / f"{key}-{args.target}-locks"
        self.stack_env = read_env(self.repo / cfg.get("stack.env_file", ".env.none")) if cfg.get("stack.env_file") else {}
        self.accounts: dict[str, tuple[str, str]] = {}
        self.sessions: dict[str, Session] = {}
        self.summary: list[tuple[str, str, str]] = []
        self.secrets: set[str] = set()
        self.base = ""
        self.level = "local"
        self.login: Login | None = None
        self.only = set(args.only.split(",")) if getattr(args, "only", None) else None
        self.skip = set(args.skip.split(",")) if getattr(args, "skip", None) else set()

    # -- prerequisites --
    def preflight(self) -> None:
        log("Memeriksa prasyarat")
        if sys.version_info < (3, 10):
            raise AuditError("Butuh Python 3.10 atau lebih baru.")
        if not shutil.which("docker"):
            raise AuditError("Docker tidak ditemukan. Docker dibutuhkan oleh ZAP, testssl, trivy, semgrep, dan gitleaks.")
        if run(["docker", "info", "--format", "{{.ServerVersion}}"], check=False).returncode != 0:
            raise AuditError("Docker belum berjalan. Nyalakan Docker lalu ulangi.")
        version = run(["git", "-C", str(KIT), "log", "-1", "--format=%h %s"], check=False).stdout.strip()
        log(f"  toolkit: {KIT} ({version})")

    # -- target --
    def prepare_target(self) -> None:
        kind = self.target["kind"]
        if kind == "stack":
            self.base = fill(self.target["base_url"], {}).rstrip("/")
            self.level = "local"
            if not self.args.no_up:
                Stack(self).up()
            else:
                log("Melewati penyalaan stack (--no-up); memakai layanan yang sudah berjalan")
            self.check_health()
            self.accounts = self.stack_accounts()
        else:
            env_file = Path(self.args.env_file) if getattr(self.args, "env_file", None) else self.repo / self.target["env_file"]
            if not env_file.exists():
                raise AuditError(f"Berkas env target tidak ada: {env_file}. Salin contohnya lalu isi.")
            env = read_env(env_file)
            self.base = env.get(self.target["base_url_key"], "").rstrip("/")
            if not self.base.startswith("http"):
                raise AuditError(f"{self.target['base_url_key']} belum diisi pada {env_file.name}.")
            level_key = self.target.get("level_key")
            self.level = (env.get(level_key, "") if level_key else "dev").lower()
            if level_key and self.level not in ("dev", "staging", "prod"):
                raise AuditError(f"{level_key} wajib diisi: dev, staging, atau prod.")
            passive = self.cfg.get("safety.passive_levels", ["prod"])
            if self.level in passive and not self.args.force_active:
                allowed = set(self.cfg.get("safety.passive_modules", []))
                log(f"Tingkat {self.level}: hanya modul pasif yang dijalankan ({', '.join(sorted(allowed))})")
                self.skip |= {m for m in KNOWN_MODULES if m not in allowed}
            remote = self.cfg.get("accounts.remote", {})
            up, pp = remote.get("user_prefix", "APP_USER_"), remote.get("pass_prefix", "APP_PASS_")
            ignore = {i.lower() for i in remote.get("ignore", [])}
            for key, value in env.items():
                if key.startswith(up):
                    role = key[len(up):]
                    if pp + role in env and role.lower() not in ignore:
                        self.accounts[role.lower()] = (value, env[pp + role])
            for key in self.target.get("secret_keys", []):
                if env.get(key):
                    self.secrets.add(env[key])
            self.secrets |= {v[1] for v in self.accounts.values()}
        self.login = Login(self.base, self.cfg.get("api"))
        limit = self.args.roles_limit if self.args.roles_limit is not None else self.target.get("max_accounts")
        if limit and len(self.accounts) > limit:
            order = [r for r in self.cfg.get("accounts.priority", []) if r in self.accounts]
            order += [r for r in sorted(self.accounts) if r not in order]
            self.accounts = {r: self.accounts[r] for r in order[:limit]}
        log(f"Target {self.target_name}: {self.base} ({self.level}), {len(self.accounts)} akun")

    def check_health(self) -> None:
        for url in self.target.get("healthy", []):
            status, _, _ = http("GET", fill(url, {"base_url": self.base}))
            if status != 200:
                raise AuditError(f"Layanan belum sehat: {url} (HTTP {status}). Jalankan tanpa --no-up atau nyalakan stack.")

    def secret_from(self, spec: dict) -> str:
        if spec.get("key"):
            return read_env(self.repo / spec["file"]).get(spec["key"], "")
        m = re.search(spec["regex"], (self.repo / spec["file"]).read_text(encoding="utf-8"))
        return m.group(1) if m else ""

    def stack_accounts(self) -> dict[str, tuple[str, str]]:
        rules = self.cfg.get("accounts.stack.passwords", [])
        rows = Stack(self).sql(self.cfg.get("accounts.stack.query"))
        accounts: dict[str, tuple[str, str]] = {}
        for row in rows:
            role, user = row.split("|")[:2]
            password = ""
            for rule in rules:
                if user in rule.get("users", []):
                    password = self.secret_from(rule)
                    break
            else:
                default = next((r for r in rules if r.get("default")), None)
                password = self.secret_from(default) if default else ""
            if not password:
                raise AuditError(f"Kata sandi akun {user} tidak ditemukan (periksa accounts.stack.passwords).")
            self.secrets.add(password)
            accounts[role] = (user, password)
        if not accounts:
            raise AuditError("Kueri akun tidak mengembalikan baris. Periksa accounts.stack.query dan data uji.")
        return accounts

    # -- toolkit calls --
    def audit(self, project: Path, args: list[str], extra_env: dict | None = None, name: str = "",
              timeout: int = 3600) -> tuple[int, str]:
        env = os.environ.copy()
        env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "TARGET_BASE_URL": self.base})
        env.update(extra_env or {})
        cmd = [sys.executable, str(KIT / "audit.py"), "--project", str(project)] + args
        try:
            done = subprocess.run(cmd, cwd=str(KIT), env=env, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=timeout)
            code, output = done.returncode, (done.stdout or "") + (done.stderr or "")
        except subprocess.TimeoutExpired:
            code, output = 124, f"melewati batas waktu {timeout} detik"
        (self.work / "log" / f"{name or '-'.join(args)}.log").write_text(output, encoding="utf-8")
        return code, output

    def write(self, project: Path, relative: str, content: str) -> None:
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def write_yaml(self, project: Path, relative: str, data: dict) -> None:
        self.write(project, relative, yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=200))

    def note(self, module: str, status: str, detail: str = "") -> None:
        self.summary.append((module, status, detail))
        log(f"  => {module}: {status}" + (f" ({detail})" if detail else ""))

    def selected(self, module: str) -> bool:
        return (self.only is None or module in self.only) and module not in self.skip

    # -- sessions and tokens --
    def collect_sessions(self, roles: list[str] | None = None) -> None:
        api = self.cfg.get("api")
        me = api["me"]
        unique: dict[str, Session] = {}
        for role in roles or list(self.accounts):
            username, password = self.accounts[role]
            if username in unique:
                self.sessions[role] = unique[username]
                continue
            status, data = self.login.sign_in(username, password)
            token = dig(data, api["login"]["token_field"])
            if status != 200 or not token:
                log(f"  login {role}: gagal HTTP {status}")
                continue
            s2, _, profile = http("GET", self.base + me["path"], token=token)
            sess = Session(role, username, token, dig(profile, me.get("role_field", "")) or role,
                           dig(profile, me.get("permissions_field", "")) or [],
                           int(dig(data, api["login"].get("ttl_field", "")) or api["login"].get("default_ttl", 3600)))
            unique[username] = sess
            self.sessions[role] = sess
            self.secrets.add(token)
        log(f"  sesi aktif: {len({id(s) for s in self.sessions.values()})} akun")

    def token(self, *roles: str) -> str | None:
        """Fresh bearer token for the first available role. Logs in again when the token is about to expire."""
        for role in roles:
            if role in self.accounts:
                sess = self.sessions.get(role)
                if sess is None or time.time() - sess.created > sess.ttl - 900:
                    self.login.ensure_quota(3)
                    self.collect_sessions([role])
                    sess = self.sessions.get(role)
                if sess:
                    return sess.token
        return None

    def _available(self) -> list[str]:
        return [r for r in self.accounts if not self.sessions or r in self.sessions]

    def user_role(self, kind: str) -> str | None:
        names = self.cfg.get(f"accounts.{kind}_roles", [])
        available = self._available()
        found = next((r for r in names if r in available), None)
        return found or (available[0] if kind == "low" and available else None)

    def can_write_local(self) -> bool:
        return self.target["kind"] == "stack" and self.user_role("strong") is not None


# ── stack ───────────────────────────────────────────────────────────────────

class Stack:
    """Starts and stops the application stack from the steps in the config."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.cfg = ctx.cfg

    @property
    def db(self) -> dict:
        return self.cfg.get("stack.database", {})

    def sql(self, statement: str) -> list[str]:
        env = self.ctx.stack_env
        db = self.db
        if not db.get("container"):
            raise AuditError("stack.database.container belum diisi.")
        done = run(["docker", "exec", "-e", "PGPASSWORD=" + env.get(db.get("password_key", ""), ""), db["container"],
                    "psql", "-U", env.get(db.get("user_key", ""), "postgres"), "-d", env.get(db.get("db_key", ""), "postgres"),
                    "-At", "-c", statement])
        return [line for line in done.stdout.splitlines() if line.strip()]

    def expand(self, value):
        """Expand ${env:KEY}, ${repo}, ${work}, ${sql:QUERY|||REGEX|||FALLBACK} and ${file:PATH|||REGEX|||FALLBACK}."""
        if isinstance(value, dict):
            return {k: self.expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.expand(v) for v in value]
        if not isinstance(value, str):
            return value

        def sql_value(inner: str) -> str:
            query, _, rest = inner.partition("|||")
            pattern, _, fallback = rest.partition("|||")
            try:
                for row in self.sql(query):
                    m = re.search(pattern, row) if pattern else None
                    if m:
                        return m.group(1)
                    if not pattern:
                        return row
            except AuditError:
                pass
            return fallback

        out = value
        while True:
            m = re.search(r"\$\{sql:((?:[^{}]|\{[^{}]*\})*)\}", out)
            if not m:
                break
            out = out[:m.start()] + sql_value(m.group(1)) + out[m.end():]
        def file_value(m) -> str:
            path, _, rest = m.group(1).partition("|||")
            pattern, _, fallback = rest.partition("|||")
            try:
                found = re.search(pattern, (self.ctx.repo / path).read_text(encoding="utf-8"))
                return found.group(1) if found else fallback
            except OSError:
                return fallback

        out = re.sub(r"\$\{file:((?:[^{}]|\{[^{}]*\})*)\}", file_value, out)
        out = re.sub(r"\$\{env:([^}]+)\}", lambda m: self.ctx.stack_env.get(m.group(1), ""), out)
        out = out.replace("${repo}", self.ctx.repo.as_posix()).replace("${work}", self.ctx.work.as_posix())
        return fill(out, {"base_url": self.ctx.base})

    def up(self) -> None:
        env_file = self.cfg.get("stack.env_file")
        if env_file and not (self.ctx.repo / env_file).exists():
            raise AuditError(f"{env_file} belum ada. Salin dari contohnya lalu sesuaikan.")
        log("Menyalakan stack")
        for key in self.cfg.get("stack.secret_keys", []):
            if self.ctx.stack_env.get(key):
                self.ctx.secrets.add(self.ctx.stack_env[key])
        for step in self.cfg.get("stack.up", []):
            getattr(self, "step_" + step["type"])(step)

    def down(self) -> None:
        log("Mematikan stack")
        for step in self.cfg.get("stack.down", []):
            getattr(self, "step_" + step["type"])(step)

    # -- steps --
    def _dir(self, step: dict) -> Path:
        return (self.ctx.repo / step.get("dir", ".")).resolve()

    def step_compose(self, step: dict) -> None:
        cmd = ["docker", "compose"]
        for f in step.get("files", []):
            cmd += ["-f", f]
        cmd += ["up", "-d"] + step.get("services", [])
        env = os.environ.copy()
        env.update({k: str(self.expand(v)) for k, v in (step.get("env") or {}).items()})
        run(cmd, cwd=self._dir(step), env=env)
        if step.get("wait_healthy"):
            ok = wait_for(lambda: "healthy" in run(["docker", "inspect", "-f", "{{.State.Health.Status}}",
                                                    step["wait_healthy"]], check=False).stdout, 120)
            if not ok:
                raise AuditError(f"Container {step['wait_healthy']} tidak menjadi sehat dalam 120 detik.")
        if step.get("health_url"):
            url = self.expand(step["health_url"])
            if not wait_for(lambda: http("GET", url)[0] == 200, 90):
                raise AuditError(f"{url} tidak sehat dalam 90 detik.")

    def step_docker_run(self, step: dict) -> None:
        name = step["name"]
        if "true" in run(["docker", "inspect", "-f", "{{.State.Running}}", name], check=False).stdout:
            return
        log(f"  menyalakan container {name}")
        run(["docker", "rm", "-f", name], check=False)
        cmd = ["docker", "run", "-d", "--name", name]
        if step.get("network"):
            cmd += ["--network", step["network"]]
        for port in step.get("ports", []):
            cmd += ["-p", port]
        for key, value in (step.get("env") or {}).items():
            expanded = str(self.expand(value))
            if not expanded:
                raise AuditError(f"Nilai env {key} untuk container {name} kosong (periksa stack.env_file).")
            self.ctx.secrets.add(expanded)
            cmd += ["-e", f"{key}={expanded}"]
        cmd += [step["image"]] + step.get("args", [])
        run(cmd)
        if step.get("health_url") and not wait_for(lambda: http("GET", step["health_url"])[0] == 200, 60):
            raise AuditError(f"Container {name} tidak sehat dalam 60 detik.")

    def step_node_deps(self, step: dict) -> None:
        d = self._dir(step)
        if not (d / "node_modules").exists():
            log("  memasang dependency (npm ci)")
            run(["npm", "ci"], cwd=d, timeout=1800)
        pkg = json.loads((d / "package.json").read_text(encoding="utf-8"))
        missing = []
        for name in step.get("complete", []):
            version = (pkg.get("dependencies") or {}).get(name) or (pkg.get("devDependencies") or {}).get(name)
            if version and not (d / "node_modules" / name / "package.json").exists():
                missing.append(f"{name}@{version}")
        if missing:
            log(f"  melengkapi dependency yang belum terpasang: {', '.join(missing)}")
            run(["npm", "install", "--no-save", "--no-package-lock"] + missing, cwd=d, timeout=900)

    def step_run(self, step: dict) -> None:
        log("  menjalankan: " + " ".join(step["command"]))
        run(step["command"], cwd=self._dir(step), timeout=step.get("timeout", 900))

    def step_seed_if_empty(self, step: dict) -> None:
        count = int((self.sql(step["check_sql"]) or ["0"])[0])
        if count == 0:
            log("  data kosong: menjalankan seeder")
            for cmd in step["commands"]:
                run(cmd, cwd=self._dir(step), timeout=1800)

    def step_process(self, step: dict) -> None:
        url = self.expand(step["health_url"])
        if http("GET", url)[0] == 200:
            if step.get("warn_if_running"):
                log("  " + step["warn_if_running"])
            return
        log(f"  menyalakan proses {step['name']}")
        env = os.environ.copy()
        env.update({k: str(self.expand(v)) for k, v in (step.get("env") or {}).items()})
        log_file = open(self.ctx.work / "log" / f"{step['name']}.log", "w", encoding="utf-8")
        flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW) if IS_WINDOWS else 0
        cmd = [shutil.which(step["command"][0]) or step["command"][0]] + step["command"][1:]
        if IS_WINDOWS and cmd[0].lower().endswith((".cmd", ".bat")):
            cmd = ["cmd.exe", "/c"] + cmd              # npm and npx are .cmd scripts and need a shell to start
        proc = subprocess.Popen(cmd, cwd=str(self._dir(step)), env=env, stdout=log_file, stderr=subprocess.STDOUT,
                                creationflags=flags)
        (self.ctx.work / f"{step['name']}.pid").write_text(str(proc.pid))
        if not wait_for(lambda: http("GET", url)[0] == 200, step.get("wait", 180), 4):
            raise AuditError(f"Proses {step['name']} tidak sehat dalam {step.get('wait', 180)} detik. "
                             f"Lihat {self.ctx.work / 'log' / (step['name'] + '.log')}")

    def step_web(self, step: dict) -> None:
        url = self.expand(step["health_url"])
        if http("GET", url)[0] == 200:
            log("  web sudah berjalan")
            return
        out = Path(str(self.expand(step["output"])))
        d = self._dir(step)
        if not (out / "index.html").exists() or self.ctx.args.rebuild:
            log("  membangun frontend ke direktori kerja")
            pm = ["pnpm"] if shutil.which("pnpm") else ["corepack", "pnpm"]
            if not (d / "node_modules").exists() and step.get("install"):
                run(pm + step["install"], cwd=d, timeout=1800)
            run(pm + fill(step["build"], {"output": str(out)}), cwd=d, timeout=1800)
        env = os.environ.copy()
        env.update({k: str(self.expand(v)) for k, v in (step.get("env") or {}).items()})
        log("  menyalakan web")
        run(["docker", "compose", "-f", step["compose_file"], "up", "-d"], cwd=d, env=env)
        if not wait_for(lambda: http("GET", url)[0] == 200, 90):
            raise AuditError("Web tidak sehat dalam 90 detik.")

    def step_compose_down(self, step: dict) -> None:
        cmd = ["docker", "compose"]
        if step.get("file"):
            cmd += ["-f", step["file"]]
        run(cmd + ["down"], cwd=self._dir(step), check=False)

    def step_docker_rm(self, step: dict) -> None:
        run(["docker", "rm", "-f", step["name"]], check=False)

    def step_process_stop(self, step: dict) -> None:
        pid_file = self.ctx.work / f"{step['name']}.pid"
        if not pid_file.exists():
            log(f"  tidak ada {pid_file.name}: proses yang dinyalakan manual tidak dimatikan")
            return
        pid = int(pid_file.read_text().strip() or 0)
        if pid:
            if IS_WINDOWS:
                run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
            else:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except OSError:
                    pass
        pid_file.unlink()


# ── generated module configs ────────────────────────────────────────────────

def authz_matrix(sessions: dict[str, Session], api: dict, endpoints: list[dict]) -> tuple[dict, dict[str, str]]:
    """Access matrix from the permissions each account really has. Returns (config, token env vars)."""
    env: dict[str, str] = {}
    roles: dict = {}
    for role, sess in sessions.items():
        var = env_name("SAK_TOK_", role)
        env[var] = sess.token
        roles[role] = {"username": "x", "password": "x", "token": "${%s}" % var}
    roles["anon"] = {"anonymous": True}
    cases = []
    for ep in endpoints:
        expect = {}
        for role, sess in sessions.items():
            has = any(p in set(sess.permissions) for p in ep.get("permissions", []))
            if has and not ep.get("read", True):
                continue                      # write endpoints are never sent to authorized roles
            expect[role] = "allow" if has else "deny"
        expect["anon"] = "deny"
        case = {"name": ep["name"], "method": ep.get("method", "GET"), "path": ep["path"]}
        if "body" in ep:
            case["body"] = ep["body"]
        case["expect"] = expect
        cases.append(case)
    login = api["login"]
    cfg = {"base_url": "${TARGET_BASE_URL}",
           "auth": {"mode": "bearer",
                    "login": {"method": "POST", "path": login["path"], "body": login.get("body"),
                              "token_field": login["token_field"]},
                    "roles": roles},
           "endpoints": cases, "forged_headers": {"enabled": False}, "screenshot": {"enabled": False}}
    return cfg, env


def bearer_auth(var: str) -> dict:
    return {"header": "Authorization", "value": "${%s}" % var}


# ── module runner ───────────────────────────────────────────────────────────

class Modules:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.project = ctx.project
        self.stack_target = ctx.target["kind"] == "stack"
        self.spec = ""

    def settings(self, module: str) -> dict:
        return self.ctx.cfg.module(module, self.ctx.target_name)

    def prepare_project(self) -> None:
        ctx = self.ctx
        for d in (ctx.project, ctx.project_zap, ctx.project_locks):
            shutil.rmtree(d / "reports", ignore_errors=True)
        ctx.audit(ctx.project, ["init", INIT_MODULES], name="init")
        self.spec = self.openapi_location()
        targets = {"name": f"{ctx.cfg.get('project.name')} ({ctx.target_name})", "base_url": ctx.base,
                   "openapi": self.spec, "tls_host": "" if self.stack_target else re.sub(r"^https?://", "", ctx.base).split("/")[0],
                   "header_probe_path": "/"}
        if self.stack_target:
            targets["code_path"] = ctx.repo.as_posix()
            semgrep = ctx.cfg.module("deps", ctx.target_name).get("semgrep") or {}
            if semgrep.get("paths"):
                targets["semgrep_paths"] = semgrep["paths"]
            if semgrep.get("exclude"):
                targets["semgrep_exclude"] = semgrep["exclude"]
            targets["semgrep_timeout_minutes"] = semgrep.get("timeout_minutes", 25)
        ctx.write_yaml(ctx.project, "config/targets.yml", targets)

    def openapi_location(self) -> str:
        ctx = self.ctx
        if ctx.args.openapi:
            return ctx.args.openapi
        url = ctx.cfg.get("api.openapi.local_url")
        if url:
            status, _, payload = http("GET", url)
            if status == 200 and "paths" in payload:
                target = ctx.work / "openapi.json"
                target.write_text(json.dumps(payload), encoding="utf-8")
                return target.as_posix()
        return ""

    def run_module(self, module: str, args: list[str], files: dict[str, dict] | None = None,
                   env: dict | None = None, timeout: int = 3600) -> tuple[int, str]:
        for relative, data in (files or {}).items():
            self.ctx.write_yaml(self.project, relative, data)
        return self.ctx.audit(self.project, args, env, name=module, timeout=timeout)

    def finish(self, module: str, code: int, output: str) -> None:
        tail = [ln for ln in output.strip().splitlines() if re.search(r"temuan|cek,|gagal|Total:", ln)]
        detail = tail[-1].strip()[:120] if tail else ""
        self.ctx.note(module, "selesai" if code == 0 else ("ada temuan" if code == 1 else "galat"), detail)

    def token_env(self, kind: str) -> dict:
        role = self.ctx.user_role(kind)
        token = self.ctx.token(role) if role else None
        return {"SAK_TOKEN_" + kind.upper(): "Bearer " + token} if token else {}

    def auth_for(self, kind: str) -> dict:
        return bearer_auth("SAK_TOKEN_" + kind.upper())

    # -- modules --
    def do_deps(self) -> None:
        ctx = self.ctx
        s = self.settings("deps")
        code, out = ctx.audit(ctx.project, ["deps", "gitleaks"], name="deps-gitleaks")
        self.finish("deps/gitleaks", code, out)
        code, out = ctx.audit(ctx.project, ["deps", "semgrep"], name="deps-semgrep")
        self.finish("deps/semgrep", code, out)
        # Trivy only on lockfiles: scanning a whole repo over a Windows bind mount exceeds the time limit.
        locks = ctx.work / "lockscan"
        shutil.rmtree(locks, ignore_errors=True)
        locks.mkdir(parents=True)
        for rel in (s.get("trivy") or {}).get("lockfiles", []):
            if (ctx.repo / rel).exists():
                (locks / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ctx.repo / rel, locks / rel)
        ctx.audit(ctx.project_locks, ["init", "webstack"], name="init-locks")
        ctx.write_yaml(ctx.project_locks, "config/targets.yml",
                       {"name": "lockfiles", "base_url": ctx.base, "openapi": "", "tls_host": "", "code_path": locks.as_posix()})
        code, out = ctx.audit(ctx.project_locks, ["deps", "trivy"], name="deps-trivy")
        trivy = ctx.project_locks / "reports" / "trivy.json"
        if trivy.exists():
            (ctx.project / "reports").mkdir(exist_ok=True)
            shutil.copy2(trivy, ctx.project / "reports" / "trivy.json")
        self.finish("deps/trivy", 0 if trivy.exists() else 2, out)

    def do_headers(self) -> None:
        self.finish("headers", *self.run_module("headers", ["headers"]))

    def do_tls(self) -> None:
        if self.stack_target:
            self.ctx.note("tls", "dilewati", "target stack memakai HTTP tanpa sertifikat")
            return
        self.finish("tls", *self.run_module("tls", ["tls"]))

    def do_webstack(self) -> None:
        self.finish("webstack", *self.run_module("webstack", ["webstack"]))

    def do_cookie_flags(self) -> None:
        s = self.settings("cookie-flags")
        cfg = {"base_url": "${TARGET_BASE_URL}", "probe_paths": s.get("probe_paths", ["/"]),
               "httponly_exempt": s.get("httponly_exempt", []), "max_session_days": s.get("max_session_days", 30)}
        self.finish("cookie-flags", *self.run_module("cookie-flags", ["cookie-flags"],
                                                      {"tests/cookie-flags/cookie_flags.yml": cfg}))

    def do_authz(self) -> None:
        ctx = self.ctx
        if len(ctx.sessions) < 2:
            ctx.note("authz", "dilewati", "kurang dari dua sesi login")
            return
        cfg, env = authz_matrix(ctx.sessions, ctx.cfg.get("api"), self.settings("authz").get("endpoints", []))
        self.finish("authz", *self.run_module("authz", ["authz"], {"tests/authz-matrix/authz_matrix.yml": cfg}, env))

    def do_cors(self) -> None:
        s = self.settings("cors")
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": self.auth_for(s.get("user", "low")),
               "evil_origin": s.get("evil_origin", "https://evil.example"), "paths": s.get("paths", [])}
        self.finish("cors", *self.run_module("cors", ["cors"], {"tests/cors/cors.yml": cfg},
                                              self.token_env(s.get("user", "low"))))

    def do_response_leak(self) -> None:
        s = self.settings("response-leak")
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": self.auth_for(s.get("user", "strong")),
               "endpoints": s.get("endpoints", []), "allow_keys": s.get("allow_keys", []),
               "random_404_probe": True, "check_internal_ips": True}
        self.finish("response-leak", *self.run_module("response-leak", ["response-leak"],
                                                       {"tests/response-leak/response_leak.yml": cfg},
                                                       self.token_env(s.get("user", "strong"))))

    def do_injection(self) -> None:
        s = self.settings("injection")
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": self.auth_for(s.get("user", "strong")),
               "options": {"time_based": bool(s.get("time_based", False)), "time_threshold": 4},
               "targets": s.get("cases", [])}
        self.finish("injection", *self.run_module("injection", ["injection"], {"tests/injection/injection.yml": cfg},
                                                   self.token_env(s.get("user", "strong"))))

    def do_clientleak(self) -> None:
        s = self.settings("clientleak")
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": self.auth_for(s.get("user", "strong")),
               "sensitive_paths": s.get("sensitive_paths", []), "browser_cache": {"enabled": False}, "js_assets": [],
               "auto_discover_js": bool(s.get("auto_discover_js", True)),
               "internal_endpoints": s.get("internal_endpoints", []), "scan_html": bool(s.get("scan_html", True)),
               "probe_sensitive_files": True, "sensitive_files": []}
        self.finish("clientleak", *self.run_module("clientleak", ["clientleak"], {"tests/client-leak/client_leak.yml": cfg},
                                                    self.token_env(s.get("user", "strong"))))

    def do_openapi_coverage(self) -> None:
        if not self.spec:
            self.ctx.note("openapi-coverage", "dilewati", "spesifikasi OpenAPI tidak tersedia (api.openapi.local_url atau --openapi)")
            return
        s = self.settings("openapi-coverage")
        cfg = {"openapi": self.spec, "base_url": "${TARGET_BASE_URL}", "max_requests": s.get("max_requests", 400),
               "delay_seconds": s.get("delay_seconds", 0), "public_allowlist": s.get("public_allowlist", [])}
        self.finish("openapi-coverage", *self.run_module("openapi-coverage", ["openapi-coverage"],
                                                          {"tests/openapi-coverage/openapi_coverage.yml": cfg}))

    def do_open_redirect(self) -> None:
        s = self.settings("open-redirect")
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": self.auth_for(s.get("user", "low")),
               "evil_target": s.get("evil_target", "https://evil.example"), "paths": s.get("paths", []),
               "params": s.get("params", [])}
        self.finish("open-redirect", *self.run_module("open-redirect", ["open-redirect"],
                                                       {"tests/open-redirect/open_redirect.yml": cfg},
                                                       self.token_env(s.get("user", "low"))))

    def do_jwt(self) -> None:
        ctx = self.ctx
        s = self.settings("jwt")
        role = ctx.user_role(s.get("user", "low"))
        if not role:
            ctx.note("jwt", "dilewati", "tidak ada akun")
            return
        ctx.login.ensure_quota(3)
        login = ctx.cfg.get("api.login")
        cfg = {"base_url": "${TARGET_BASE_URL}",
               "login": {"method": "POST", "path": login["path"],
                         "body": fill(login.get("body"), {"username": "${SAK_JWT_USER}", "password": "${SAK_JWT_PASS}"}),
                         "token_path": login["token_field"]},
               "protected": s.get("protected", {"method": "GET", "path": ctx.cfg.get("api.me.path")}),
               "auth_header": "Authorization", "auth_prefix": "Bearer ",
               "max_lifetime_hours": s.get("max_lifetime_hours", 24)}
        user, password = ctx.accounts[role]
        self.finish("jwt", *self.run_module("jwt", ["jwt"], {"tests/jwt/jwt.yml": cfg},
                                             {"SAK_JWT_USER": user, "SAK_JWT_PASS": password}))

    def owner(self, s: dict) -> tuple[str, str] | None:
        """Account that owns a data row, so it may upload to it or edit it. The query returns (username, entity id)."""
        query = s.get("owner_query") or self.settings(s["owner_from"]).get("owner_query") if s.get("owner_from") or s.get("owner_query") else None
        if not query:
            return None
        rows = Stack(self.ctx).sql(query)
        if not rows:
            return None
        user, entity = (rows[0].split("|") + [""])[:2]
        return user, entity

    def owner_login(self, module: str, user: str) -> str | None:
        ctx = self.ctx
        password = next((p for (u, p) in ctx.accounts.values() if u != self._strong_user()), "")
        rule = next((r for r in ctx.cfg.get("accounts.stack.passwords", []) if r.get("default")), None)
        if rule:
            password = ctx.secret_from(rule)
        ctx.login.ensure_quota(3)
        status, data = ctx.login.sign_in(user, password)
        token = dig(data, ctx.cfg.get("api.login.token_field"))
        if status != 200 or not token:
            ctx.note(module, "dilewati", f"login pemilik data gagal (HTTP {status})")
            return None
        ctx.secrets.add(token)
        return token

    def _strong_user(self) -> str:
        role = self.ctx.user_role("strong")
        return self.ctx.accounts[role][0] if role else ""

    def do_upload(self) -> None:
        ctx = self.ctx
        s = self.settings("upload")
        owner = self.owner(s) if self.stack_target else None
        if not owner:
            ctx.note("upload", "dilewati", "butuh target stack dan owner_query yang menghasilkan baris")
            return
        user, entity = owner
        token = self.owner_login("upload", user)
        if not token:
            return
        ep = s["endpoint"]
        max_bytes = s.get("max_bytes") or int(ctx.stack_env.get(s.get("max_bytes_env", ""), 0) or 2097152)
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": bearer_auth("SAK_TOKEN_OWNER"),
               "endpoint": {"method": ep.get("method", "POST"), "path": ep["path"], "field": ep.get("field", "file"),
                            "data": fill(s.get("data", {}), {"entity_id": entity})},
               "allow_only": s.get("allow_only", [".pdf"]), "max_bytes": max_bytes}
        if s.get("cleanup"):
            cfg["cleanup"] = s["cleanup"]
        self.finish("upload", *self.run_module("upload", ["upload"], {"tests/upload-safety/upload_safety.yml": cfg},
                                                {"SAK_TOKEN_OWNER": "Bearer " + token}))

    def do_mass_assignment(self) -> None:
        ctx = self.ctx
        s = self.settings("mass-assignment")
        owner = self.owner(s) if self.stack_target else None
        if not owner:
            ctx.note("mass-assignment", "dilewati", "butuh target stack dan owner_query yang menghasilkan baris")
            return
        user, _ = owner
        if s.get("prepare_sql"):
            Stack(ctx).sql(fill(s["prepare_sql"], {"owner": user}))
        token = self.owner_login("mass-assignment", user)
        if not token:
            return
        _, _, profile = http("GET", ctx.base + s["get_path"], token=token)
        data = dig(profile, s.get("data_path", "")) if s.get("data_path") else profile
        required = {f: (data or {}).get(f) for f in s.get("required_fields", [])}
        if any(v in (None, "") for v in required.values()):
            ctx.note("mass-assignment", "dilewati", "profil akun belum lengkap (field wajib kosong)")
            return
        inject = dict(required, **s.get("forbidden_fields", {}))
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": bearer_auth("SAK_TOKEN_OWNER"),
               "targets": [{"name": "Privilege escalation via own profile update", "get": {"path": s["get_path"]},
                            "data_path": s.get("data_path", "data"),
                            "update": {"method": s["update"].get("method", "PUT"), "path": s["update"]["path"]},
                            "inject": inject, "fields": list(inject)}]}
        self.finish("mass-assignment", *self.run_module("mass-assignment", ["mass-assignment"],
                                                         {"tests/mass-assignment/mass_assignment.yml": cfg},
                                                         {"SAK_TOKEN_OWNER": "Bearer " + token}))

    def do_ssrf(self) -> None:
        ctx = self.ctx
        s = self.settings("ssrf")
        role = ctx.user_role(s.get("user", "strong"))
        token = ctx.token(role) if role else None
        if not token or not self.stack_target:
            ctx.note("ssrf", "dilewati", "butuh target stack dan akun berhak tinggi")
            return
        status, _, payload = http("GET", ctx.base + s["list"], token=token)
        rows = payload.get("data") if isinstance(payload.get("data"), list) else []
        if status != 200 or not rows:
            ctx.note("ssrf", "dilewati", "tidak ada item untuk diuji pada endpoint daftar")
            return
        original = rows[0]
        path = fill(s["item"], {"id": original["id"]})
        restore_flag = s.get("restore_flag")

        def body(url: str, flag) -> dict:
            result = {k: original.get(k) for k in s.get("copy_from_item", [])}
            result[s["param"]] = url
            result.update(s.get("static", {}))
            if restore_flag:
                result[restore_flag] = flag
            return result
        canary = s.get("canary", {})
        extra = {k: original.get(k) for k in s.get("copy_from_item", []) if k != s["param"]}
        extra.update(s.get("static", {}))
        cfg = {"base_url": "${TARGET_BASE_URL}", "auth": bearer_auth("SAK_TOKEN_STRONG"),
               "callback": {"bind": "0.0.0.0", "port": canary.get("port", 18999),
                            "public_url": canary.get("public_url", "http://host.docker.internal:18999"), "wait_seconds": 4},
               "variants": True,
               "targets": [{"name": "Endpoint that accepts a URL", "method": "PUT", "path": path, "param": s["param"],
                            "location": "json", "extra": extra}]}
        try:
            code, out = self.run_module("ssrf", ["ssrf"], {"tests/ssrf/ssrf.yml": cfg}, {"SAK_TOKEN_STRONG": "Bearer " + token})
        finally:
            # The item is always restored to its original values.
            http("PUT", ctx.base + path, body(original.get(s["param"]), original.get(restore_flag) if restore_flag else None), token=token)
        _, _, check = http("GET", ctx.base + s["list"], token=token)
        now = (check.get("data") or [{}])[0]
        if now.get(s["param"]) != original.get(s["param"]):
            ctx.note("ssrf-restore", "galat", "item tidak kembali ke nilai semula; pulihkan manual")
        self.finish("ssrf", code, out)

    def do_auth_policy(self) -> None:
        s = self.settings("auth-policy")
        reg = s.get("register")
        if not reg or not self.stack_target:
            self.ctx.note("auth-policy", "dilewati", "membuat akun pendaftaran baru; hanya untuk target stack")
            return
        cfg = {"base_url": "${TARGET_BASE_URL}",
               "register": {"path": reg["path"], "template": reg["template"], "password_field": reg.get("password_field", "password")},
               "weak_passwords": s.get("weak_passwords", [])}
        self.finish("auth-policy", *self.run_module("auth-policy", ["auth-policy"], {"tests/auth-policy/auth_policy.yml": cfg}))

    def do_session(self) -> None:
        result = SessionCheck(self.ctx, self.settings("session")).run()
        if result is None:
            return
        out = self.project / "reports" / "session_mgmt.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        failed = sum(1 for r in result if not r["ok"])
        out.write_text(json.dumps({"module": "session-mgmt", "failures": failed, "results": result}, indent=2,
                                  ensure_ascii=False), encoding="utf-8")
        self.ctx.note("session", "ada temuan" if failed else "selesai", f"{len(result)} cek, {failed} temuan")

    def do_zap(self) -> None:
        ctx = self.ctx
        s = self.settings("zap")
        if not self.stack_target:
            ctx.note("zap", "dilewati", "scan aktif hanya untuk target stack yang punya snapshot database")
            return
        db, env = ctx.cfg.get("stack.database", {}), ctx.stack_env
        targets = {"name": "zap", "base_url": s["internal_base_url"], "openapi": s["internal_openapi"],
                   "tls_host": "", "header_probe_path": "/", "docker_network": s["network"],
                   "snapshot": {"preset": "postgres-docker", "container": db.get("container"),
                                "user": env.get(db.get("user_key", ""), "postgres"),
                                "databases": [env.get(db.get("db_key", ""), "postgres")], "keep": False,
                                "timeout_seconds": 1800},
                   "zap_exclude": s.get("exclude", []), "zap_spider_minutes": s.get("spider_minutes", 1),
                   "zap_timeout_minutes": s.get("timeout_minutes", 20)}
        ctx.audit(ctx.project_zap, ["init", "webstack"], name="init-zap")
        ctx.write_yaml(ctx.project_zap, "config/targets.yml", targets)
        code, out = ctx.audit(ctx.project_zap, ["zap", "baseline"], name="zap-baseline", timeout=1800)
        self.finish("zap/baseline", code, out)
        role = ctx.user_role(s.get("user", "strong"))
        token = ctx.token(role) if role else None
        if not token:
            ctx.note("zap/api", "dilewati", "butuh akun berhak tinggi untuk scan aktif berautentikasi")
        else:
            code, out = ctx.audit(ctx.project_zap, ["zap", "api"], {"ZAP_AUTH_HEADER": "Authorization: Bearer " + token},
                                  name="zap-api", timeout=3600)
            self.finish("zap/api", code, out)
        self.ensure_restored(ctx.project_zap)
        (ctx.project / "reports").mkdir(exist_ok=True)
        for name in ("zap-baseline.json", "zap-baseline.html", "zap-api.json", "zap-api.html"):
            src = ctx.project_zap / "reports" / name
            if src.exists():
                shutil.copy2(src, ctx.project / "reports" / name)

    def ensure_restored(self, project: Path) -> None:
        """Make sure no database snapshot is left unrestored. Runs the kit rollback when one is."""
        journal = project / "reports" / "rollback_journal.json"

        def pending() -> int:
            if not journal.exists():
                return 0
            try:
                return sum(1 for e in json.loads(journal.read_text(encoding="utf-8")) if not e.get("done"))
            except Exception:
                return 1
        if pending():
            log("  ada snapshot belum dipulihkan: menjalankan rollback")
            self.ctx.audit(project, ["rollback"], name="rollback")
        if pending():
            self.ctx.note("zap-restore", "galat", "database belum pulih; jalankan rollback manual pada project zap")
        else:
            self.ctx.note("zap-restore", "selesai", "database dipulihkan dari snapshot")

    def do_ratelimit(self) -> None:
        s = self.settings("ratelimit")
        cfg = {"base_url": "${TARGET_BASE_URL}", "burst": s.get("burst", []), "pause_after_burst_seconds": 0,
               "lockout": {"enabled": False}}
        self.finish("ratelimit", *self.run_module("ratelimit", ["ratelimit"], {"tests/ratelimit/ratelimit.yml": cfg}))


# ── session checks for bearer authentication ────────────────────────────────

class SessionCheck:
    """Session tests for JWT: change password, logout, refresh token rotation.

    The kit's session-mgmt runner only supports cookie sessions, so these checks run here and write
    their result in the same format so report.py reads them.
    """

    DENIED = (400, 401, 403)

    def __init__(self, ctx: Context, settings: dict):
        self.ctx = ctx
        self.s = settings
        self.base = ctx.base
        self.api = ctx.cfg.get("api")
        self.results: list[dict] = []

    def rec(self, check: str, status: int, ok: bool, note: str, kind: str | None = None) -> None:
        self.results.append({"check": check, "status": status, "ok": ok, "note": note, "url": self.base,
                             "kind": kind or ("logout-no-invalidate" if check.startswith("logout") else "session-not-revoked")})

    def call(self, key: str, token: str | None = None, **values):
        spec = self.api[key]
        return http("POST", self.base + spec["path"], fill(spec.get("body"), values), token)

    def run(self) -> list[dict] | None:
        import secrets
        ctx, s = self.ctx, self.s
        create = s.get("create_user")
        role = ctx.user_role("strong")
        if not create or not role:
            ctx.note("session", "dilewati", "butuh create_user dan akun berhak tinggi")
            return None
        ctx.login.ensure_quota(10)
        admin = ctx.token(role)
        role_id = s.get("role_id")
        if role_id is None and create.get("role_query") and ctx.target["kind"] == "stack":
            rows = Stack(ctx).sql(create["role_query"])
            role_id = int(rows[0]) if rows else None
        if role_id is None:
            ctx.note("session", "dilewati", "role untuk akun uji tidak ditemukan (role_id atau role_query)")
            return None
        username = "kit.probe." + secrets.token_hex(3)
        old = "Kp-" + secrets.token_urlsafe(9) + "7aQ!"
        new = "Kp-" + secrets.token_urlsafe(9) + "8bR!"
        ctx.secrets |= {old, new}
        nik = "32" + "".join(secrets.choice("0123456789") for _ in range(14))
        status, _, data = http("POST", self.base + create["path"],
                               fill(create["body"], {"username": username, "password": old, "role_id": role_id, "nik": nik}),
                               admin)
        if status not in (200, 201):
            ctx.note("session", "dilewati", f"gagal membuat akun uji (HTTP {status})")
            return None
        uid = dig(data, create.get("id_field", "data.id"))
        login_cfg = self.api["login"]

        def sign_in(password: str):
            st, d = ctx.login.sign_in(username, password)
            return st, d

        def tokens(d: dict) -> tuple[str, str]:
            access, refresh = dig(d, login_cfg["token_field"]) or "", dig(d, login_cfg.get("refresh_field", "")) or ""
            ctx.secrets |= {access, refresh}
            return access, refresh

        try:
            _, d1 = sign_in(old)
            _, d2 = sign_in(old)
            a_access, _ = tokens(d1)
            b_access, b_refresh = tokens(d2)
            ttl = int(dig(d1, login_cfg.get("ttl_field", "")) or login_cfg.get("default_ttl", 3600))
            st, _, _ = http("GET", self.base + self.api["me"]["path"], token=b_access)
            self.rec("baseline: sesi aktif", st, st == 200, "")
            st, _, _ = self.call("change_password", a_access, old=old, new=new)
            self.rec("ganti password: pelaksanaan", st, st == 200, "")
            st, _, _ = self.call("refresh", None, refresh_token=b_refresh)
            self.rec("ganti password: refresh token sesi lain dicabut", st, st in self.DENIED,
                     "sesi lain yang mungkin dicuri tidak boleh bertahan")
            st, _, _ = http("GET", self.base + self.api["me"]["path"], token=b_access)
            self.access_token_check("ganti password: access token sesi lain", st, ttl)
            st, _ = sign_in(old)
            self.rec("ganti password: password lama ditolak", st, st in self.DENIED, "", "old-password-accepted")
            st, d3 = sign_in(new)
            self.rec("ganti password: password baru diterima", st, st == 200, "", "old-password-accepted")
            if st == 200:
                c_access, c_refresh = tokens(d3)
                st2, _, _ = self.call("logout", None, refresh_token=c_refresh)
                self.rec("logout: pelaksanaan", st2, st2 in (200, 204), "")
                st2, _, _ = self.call("refresh", None, refresh_token=c_refresh)
                self.rec("logout: refresh token dicabut", st2, st2 in self.DENIED, "")
                st2, _, _ = http("GET", self.base + self.api["me"]["path"], token=c_access)
                self.access_token_check("logout: access token setelah logout", st2, ttl)
            st, d4 = sign_in(new)
            if st == 200:
                _, e_refresh = tokens(d4)
                s1, _, rotated = self.call("refresh", None, refresh_token=e_refresh)
                self.rec("rotasi: refresh pertama berhasil", s1, s1 == 200, "")
                s2, _, _ = self.call("refresh", None, refresh_token=e_refresh)
                self.rec("rotasi: refresh token lama dipakai ulang ditolak", s2, s2 in self.DENIED, "")
                fresh = dig(rotated, login_cfg.get("refresh_field", ""))
                if fresh:
                    s3, _, _ = self.call("refresh", None, refresh_token=fresh)
                    self.rec("rotasi: pemakaian ulang mencabut seluruh sesi", s3, s3 in self.DENIED,
                             "token baru ikut dicabut" if s3 in self.DENIED else "token baru masih berlaku")
        finally:
            delete = s.get("delete_user") or {}
            if delete.get("path") and uid is not None:
                http("DELETE", self.base + fill(delete["path"], {"id": uid}), token=admin)
        return self.results

    def access_token_check(self, check: str, status: int, ttl: int) -> None:
        """A JWT access token is stateless and stays valid until it expires. That is acceptable when it is short lived."""
        reasonable = int(self.s.get("reasonable_ttl_seconds", 3600))
        if status in self.DENIED:
            self.rec(check, status, True, "access token dicabut")
        elif ttl <= reasonable:
            self.rec(check, status, True, f"access token tetap berlaku sampai kedaluwarsa (TTL {ttl} detik); "
                                          "diterima sebagai konsekuensi JWT stateless berumur pendek")
        else:
            self.rec(check, status, False, f"access token tetap berlaku dan umurnya panjang (TTL {ttl} detik)")


# ── finish: report, secret scan, copy ───────────────────────────────────────

def scan_secrets(folder: Path, secrets: set[str]) -> list[str]:
    """Names of files under the folder that contain a known secret or a JWT-like token."""
    needles = {s for s in secrets if s and len(s) >= 6}
    leaked = []
    for path in folder.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            if any(n in text for n in needles) or re.search(r"eyJ[A-Za-z0-9_-]{20,}\.", text):
                leaked.append(path.name)
    return leaked


def run_name(ctx: Context, stamp: str) -> str:
    """Unique name of one run: security-audit-kit_<project>_<target>_<timestamp>. Never reused, so reruns keep history."""
    target = re.sub(r"[^a-z0-9]+", "-", ctx.target_name.lower()).strip("-")
    return f"security-audit-kit_{ctx.cfg.key}_{target}_{stamp}"


def write_summary(ctx: Context, out: Path, name: str) -> None:
    version = run(["git", "-C", str(KIT), "log", "-1", "--format=%h %s"], check=False).stdout.strip()
    lines = [f"# Ringkasan eksekusi audit {ctx.target_name}", "",
             f"- Proyek: {ctx.cfg.get('project.name')}", f"- Waktu: {time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"- Target: {ctx.base} ({ctx.level})", f"- Security Audit Kit: {version}",
             f"- Jumlah akun login: {len({id(s) for s in ctx.sessions.values()})}", "",
             "| Modul | Status | Catatan |", "|---|---|---|"]
    lines += [f"| {m} | {s} | {c} |" for m, s, c in ctx.summary]
    lines += ["", f"Hasil per modul dan temuan ada di {name}.md. Berkas ini dibuat otomatis oleh runner.py."]
    (out / f"{name}-ringkasan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_history(base: Path, name: str, ctx: Context, totals: list[str]) -> None:
    """One line per run in RIWAYAT.md, newest last, so earlier runs stay easy to find and compare."""
    history = base / "RIWAYAT.md"
    if not history.exists():
        history.write_text("# Riwayat audit\n\n| Run | Target | Ringkasan |\n|---|---|---|\n", encoding="utf-8")
    summary = " ".join(t.replace("|", "/") for t in totals) or "-"
    with history.open("a", encoding="utf-8") as f:
        f.write(f"| [{name}]({name}/{name}.md) | {ctx.target_name} | {summary} |\n")


def finish(ctx: Context) -> int:
    log("Menyusun report")
    code, out = ctx.audit(ctx.project, ["report"], name="report")
    reports = ctx.project / "reports"
    if code != 0 or not (reports / "laporan.md").exists():
        raise AuditError("Report gagal disusun. Lihat log/report.log pada folder kerja.")
    totals = [ln.strip() for ln in out.splitlines() if ln.strip().startswith(("Total", "Critical"))]
    base = Path(ctx.args.out) if getattr(ctx.args, "out", None) else Path(ctx.cfg.get("project.output", "docs/security-audit"))
    if not base.is_absolute():
        base = ctx.repo / base
    name = run_name(ctx, time.strftime("%Y%m%d-%H%M%S"))
    out_dir = base / name
    suffix = 2
    while out_dir.exists():                      # two runs in the same second must not collide
        out_dir = base / f"{name}-{suffix}"
        suffix += 1
    name = out_dir.name
    out_dir.mkdir(parents=True)
    skip = {"snapshots", "__pycache__", "zap_auth_hook.py", "zap.yaml"}
    renamed = {"laporan.md": f"{name}.md", "laporan.html": f"{name}.html", "laporan-slides.html": f"{name}-slides.html"}
    for src in reports.iterdir():
        if src.name in skip:
            continue
        if src.is_dir():
            shutil.copytree(src, out_dir / src.name)
        else:
            shutil.copy2(src, out_dir / renamed.get(src.name, src.name))
    slides = out_dir / renamed["laporan-slides.html"]
    if slides.exists():                          # the slides mention the full report by file name
        slides.write_text(slides.read_text(encoding="utf-8").replace("laporan.html", f"{name}.html"), encoding="utf-8")
    leaked = scan_secrets(out_dir, ctx.secrets)
    if leaked:
        shutil.rmtree(out_dir)                   # only this run; earlier runs are never touched
        raise AuditError(f"Pemindaian rahasia GAGAL: {', '.join(leaked)} memuat kredensial. Hasil dihapus, tidak disalin.")
    write_summary(ctx, out_dir, name)
    append_history(base, name, ctx, totals)
    log(f"Report disalin ke {out_dir}")
    for line in totals:
        log("  " + line)
    return 0


# ── main flow ───────────────────────────────────────────────────────────────

HANDLERS = {
    "deps": "do_deps", "headers": "do_headers", "tls": "do_tls", "webstack": "do_webstack",
    "cookie-flags": "do_cookie_flags", "authz": "do_authz", "cors": "do_cors", "response-leak": "do_response_leak",
    "injection": "do_injection", "clientleak": "do_clientleak", "openapi-coverage": "do_openapi_coverage",
    "open-redirect": "do_open_redirect", "jwt": "do_jwt", "upload": "do_upload", "mass-assignment": "do_mass_assignment",
    "ssrf": "do_ssrf", "session": "do_session", "auth-policy": "do_auth_policy", "zap": "do_zap", "ratelimit": "do_ratelimit",
}
# Modules that need logged-in sessions before they run.
NEEDS_SESSION = {"authz", "cors", "response-leak", "injection", "clientleak", "open-redirect", "jwt", "upload",
                 "mass-assignment", "ssrf", "session", "zap"}


def execute(ctx: Context) -> int:
    ctx.preflight()
    ctx.prepare_target()
    modules = Modules(ctx)
    modules.prepare_project()
    have_sessions = False
    for module in ctx.cfg.get("pipeline", []):
        if not ctx.cfg.module_enabled(module, ctx.target_name):
            ctx.note(module, "dilewati", f"tidak diaktifkan untuk target {ctx.target_name}")
            continue
        if not ctx.selected(module):
            if module in ctx.skip:
                ctx.note(module, "dilewati", "diminta --skip atau tidak diizinkan pada tingkat target ini")
            continue
        if module in NEEDS_SESSION and not have_sessions and not ctx.sessions:
            log("Mengambil token seluruh akun (dengan pacing rate limit login)")
            ctx.collect_sessions()
            have_sessions = True
        log(f"Modul {module}")
        try:
            getattr(modules, HANDLERS[module])()
        except AuditError as e:
            ctx.note(module, "galat", str(e)[:140])
        except Exception as e:  # noqa: BLE001  one failing module must not stop the others
            ctx.note(module, "galat", f"{type(e).__name__}: {e}"[:140])
    return finish(ctx)


def command_init(args: argparse.Namespace) -> int:
    target = Path(args.config or DEFAULT_CONFIG_NAMES[1])
    if target.exists():
        raise AuditError(f"{target} sudah ada; tidak ditimpa.")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(EXAMPLE_CONFIG, target)
    log(f"Kerangka config dibuat: {target}")
    log("Langkah berikutnya: sesuaikan isinya dengan project, lalu jalankan: python runner.py check --config " + str(target))
    return 0


def command_check(args: argparse.Namespace) -> int:
    cfg = Config.load(find_config(args.config))
    problems = validate_config(cfg.data)
    for p in problems:
        log("MASALAH: " + p)
    if problems:
        return 2
    targets = ", ".join(cfg.data["targets"])
    log(f"Config valid: {cfg.get('project.name')}; target: {targets}; modul pada pipeline: {len(cfg.get('pipeline'))}")
    return 0


def command_run(args: argparse.Namespace) -> int:
    cfg = Config.load(find_config(args.config))
    problems = validate_config(cfg.data)
    if problems:
        raise AuditError("Config tidak valid:\n  - " + "\n  - ".join(problems))
    ctx = Context(cfg, args)
    try:
        return execute(ctx)
    finally:
        if ctx.target["kind"] == "stack" and args.down_after:
            Stack(ctx).down()


def command_stack(args: argparse.Namespace) -> int:
    cfg = Config.load(find_config(args.config))
    name = args.target or next((n for n, t in cfg.data["targets"].items() if t.get("kind") == "stack"), None)
    if not name:
        raise AuditError("Tidak ada target kind stack pada config.")
    args.target = name
    for attr, value in (("no_up", False), ("only", None), ("skip", None), ("rebuild", getattr(args, "rebuild", False))):
        setattr(args, attr, value)
    ctx = Context(cfg, args)
    ctx.base = fill(ctx.target["base_url"], {}).rstrip("/")
    if args.command == "up":
        Stack(ctx).up()
        log("Stack siap. Hentikan dengan: python runner.py down --config " + str(cfg.path))
    else:
        Stack(ctx).down()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Runner audit otonom untuk Security Audit Kit.")
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p, target_required=False):
        p.add_argument("--config", help="berkas config project (bawaan: audit.config.yml, security-audit/ atau scripts/security-audit/)")
        p.add_argument("--repo-root", help="akar repo project (bawaan: folder .git terdekat dari config)")
        p.add_argument("--work-dir", help="folder kerja sementara (bawaan: <folder config>/work)")
        p.add_argument("--target", required=target_required, help="nama target pada config")

    init = sub.add_parser("init", help="buat kerangka config untuk project baru")
    init.add_argument("--config")
    check = sub.add_parser("check", help="validasi config")
    check.add_argument("--config")
    r = sub.add_parser("run", help="jalankan seluruh alur: scan, uji dinamis, report")
    common(r, True)
    r.add_argument("--env-file", help="target remote: berkas env pengganti")
    r.add_argument("--out", help="folder induk keluaran; tiap run dibuat di subfolder bernama unik (bawaan: project.output)")
    r.add_argument("--only", help="daftar modul dipisah koma")
    r.add_argument("--skip", help="daftar modul yang dilewati dipisah koma")
    r.add_argument("--roles-limit", type=int, default=None, help="batasi jumlah akun yang dipakai")
    r.add_argument("--no-up", action="store_true", help="target stack: pakai layanan yang sudah berjalan")
    r.add_argument("--down-after", action="store_true", help="target stack: matikan stack setelah selesai")
    r.add_argument("--rebuild", action="store_true", help="bangun ulang frontend")
    r.add_argument("--openapi", help="lokasi spesifikasi OpenAPI (URL atau berkas)")
    r.add_argument("--force-active", action="store_true", help="izinkan modul aktif walau tingkat target pasif")
    up = sub.add_parser("up", help="nyalakan stack target kind stack")
    common(up)
    up.add_argument("--rebuild", action="store_true")
    down = sub.add_parser("down", help="matikan stack target kind stack")
    common(down)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            return command_init(args)
        if args.command == "check":
            return command_check(args)
        if args.command == "run":
            return command_run(args)
        return command_stack(args)
    except AuditError as e:
        log(f"GALAT: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
