#!/usr/bin/env python3
"""Cross-platform entry point for Security Audit Kit.

All orchestration is in Python and calls official Docker images, so it behaves the same on
Windows and Linux/macOS and does not depend on the shell.

Usage:
    python audit.py all                      # run all modules from config/targets.yml
    python audit.py zap baseline
    python audit.py zap api
    python audit.py tls
    python audit.py headers
    python audit.py deps
    python audit.py authz
    python audit.py upload
    python audit.py auth-policy

Target config lives in config/targets.yml (see config/targets.example.yml).
Credentials and tokens come from environment variables, never from files.

Multi-project (parallel): one kit install, many project folders. Each project has its own
config/targets.yml, tests/<module>/<module>.yml and reports/, so several projects can be
audited at once from different terminals without overwriting each other:
    python audit.py --project my-app init authz,upload   # create projects/my-app/
    python audit.py --project my-app all
    python audit.py --project D:/audit/client-b headers          # any folder
    SAK_PROJECT_DIR=... python audit.py all                    # same as --project
Without --project / SAK_PROJECT_DIR the kit folder itself is used (legacy behavior).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("Butuh PyYAML: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parent      # kit code (runners, report.py, example config)
PROJECT = ROOT                              # project data: config/, tests/<module>/*.yml, reports/
SCOPE = None                                # _scope.Scope when `bounty.enabled` is set in targets.yml
sys.path.insert(0, str(ROOT / "tests"))
import _color as C  # noqa: E402  (ANSI colors; auto-off for pipes/CI, honors NO_COLOR)
import glossary  # noqa: E402  (per-language technical glossary)
import _scope  # noqa: E402  (bug bounty scope guard)
import _throttle  # noqa: E402  (scope + rate limit enforced at the HTTP transport)
ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def resolve_project(value: str | None) -> Path:
    """Resolve the project folder from --project / SAK_PROJECT_DIR.

    - empty        -> the kit folder (legacy single-project behavior)
    - bare name (no path separator, e.g. "my-app") -> <kit>/projects/<name>
    - path         -> that path; relative paths resolve against SAK_CALLER_CWD (set by the
      audit.ps1 wrapper, which changes into the kit folder), else the working directory."""
    if not value or not str(value).strip():
        return ROOT
    v = str(value).strip()
    if "/" not in v and "\\" not in v and v not in (".", "..") and not Path(v).is_absolute():
        return (ROOT / "projects" / v).resolve()
    p = Path(v).expanduser()
    if not p.is_absolute():
        p = Path(os.environ.get("SAK_CALLER_CWD") or os.getcwd()) / p
    return p.resolve()


def set_project(path: Path) -> Path:
    """Set the active project and pass it to subprocesses (runners, report.py) via env."""
    global PROJECT
    PROJECT = Path(path)
    os.environ["SAK_PROJECT_DIR"] = str(PROJECT)
    return PROJECT


def pop_project_arg(argv: list[str]) -> tuple[str | None, list[str]]:
    """Pull `--project X` / `--project=X` out of argv (any position), before argparse and
    the 'recon' interception that forwards free-form args."""
    out, val, i = [], None, 0
    while i < len(argv):
        a = argv[i]
        if a == "--project" and i + 1 < len(argv):
            val, i = argv[i + 1], i + 2
            continue
        if a.startswith("--project="):
            val, i = a.split("=", 1)[1], i + 1
            continue
        out.append(a)
        i += 1
    return val, out


COLOR_MODES = ("auto", "always", "never")


def pop_color_arg(argv: list[str]) -> tuple[str | None, list[str]]:
    """Pull `--color [auto|always|never]` / `--color=...` / `--no-color` out of argv (any position).

    Invalid value -> exit 2. A bare `--color` means `always`."""
    out, val, i = [], None, 0
    while i < len(argv):
        a = argv[i]
        if a == "--no-color":
            val, i = "never", i + 1
            continue
        if a == "--color" or a.startswith("--color="):
            if "=" in a:
                v, i = a.split("=", 1)[1], i + 1
            elif i + 1 < len(argv) and argv[i + 1] in COLOR_MODES:
                v, i = argv[i + 1], i + 2
            else:
                v, i = "always", i + 1
            if v not in COLOR_MODES:
                print(f"--color: pilihan tidak valid '{v}' (auto|always|never)", file=sys.stderr)
                sys.exit(2)
            val = v
            continue
        out.append(a)
        i += 1
    return val, out


def pop_lang_arg(argv: list[str]) -> tuple[str | None, list[str]]:
    """Pull `--lang X` / `--lang=X` out of argv; exit 2 if X is not a glossary language."""
    out, val, i = [], None, 0
    while i < len(argv):
        a = argv[i]
        if a == "--lang" and i + 1 < len(argv):
            val, i = argv[i + 1].lower(), i + 2
        elif a.startswith("--lang="):
            val, i = a.split("=", 1)[1].lower(), i + 1
        else:
            out.append(a)
            i += 1
    if val is not None and val not in glossary.languages():
        print(f"--lang: pilihan tidak valid '{val}' ({'|'.join(glossary.languages())})", file=sys.stderr)
        sys.exit(2)
    return val, out


def project_cfg(*parts: str) -> Path:
    """Config path inside the active project, e.g. project_cfg("config", "targets.yml")."""
    return PROJECT.joinpath(*parts)


def project_label() -> str:
    return "" if PROJECT == ROOT else f" (project: {PROJECT})"


def load_targets():
    path = project_cfg("config", "targets.yml")
    if not path.exists():
        print(f"{path} belum ada{project_label()}. Salin dari config/targets.example.yml "
              "atau jalankan `python audit.py --project <nama> init`.", file=sys.stderr)
        sys.exit(2)
    with open(path, encoding="utf-8") as f:
        return expand(yaml.safe_load(f))


# ---- bug bounty scope gate (active only when targets.yml has `bounty.enabled: true`) ----

def scope_block(name, host=None):
    """Reason to refuse `name` (module, `zap-api`, ...) or a host in bounty mode; None when allowed."""
    if SCOPE is None:
        return None
    if not SCOPE.allows_active(name):
        return (f"mode bounty: '{name}' mengirim trafik aktif dan tidak diizinkan. Jalankan hanya jika "
                f"aturan program mengizinkan, lalu tambahkan \"{name}\" ke bounty.allow_active.")
    if host is not None and not SCOPE.allows_host(host):
        return f"mode bounty: host '{_scope.host_of(host) or host}' di luar scope (bounty.in_scope/out_of_scope)."
    return None


def refuse(reason):
    print(C.bad("DITOLAK ") + reason, file=sys.stderr)
    return 2


def py_module_block(name, cfg_path):
    """Scope reason for a Python module: the module itself and the base_url in its own config."""
    if SCOPE is None:
        return None
    host = None
    try:
        with open(cfg_path, encoding="utf-8") as f:
            host = (expand(yaml.safe_load(f)) or {}).get("base_url")
    except (OSError, yaml.YAMLError):
        pass
    return scope_block(name, host or None)


def init_scope():
    """Load the bounty scope from the project's targets.yml when it exists; exit 2 if it is invalid."""
    global SCOPE
    path = project_cfg("config", "targets.yml")
    SCOPE = None
    if not path.exists():
        return
    try:
        with open(path, encoding="utf-8") as f:
            SCOPE = _scope.load(expand(yaml.safe_load(f)))
    except (yaml.YAMLError, _scope.ScopeError) as exc:
        print(f"targets.yml: blok bounty tidak valid: {exc}", file=sys.stderr)
        sys.exit(2)
    if SCOPE is not None:
        print(C.dim(f"[bounty] {SCOPE.describe()}"))


def guarded(cmd):
    """In bounty mode run a Python runner through tests/_guarded.py, which enforces the scope on every
    HTTP request and paces the traffic to max_rps; otherwise return `cmd` unchanged.
    `cmd` is [python, runner.py, args...]."""
    if SCOPE is None:
        return cmd
    os.environ["SAK_SCOPE_JSON"] = json.dumps(SCOPE.to_dict())
    return [cmd[0], str(ROOT / "tests" / "_guarded.py"), *cmd[1:]]


def mod_scope(tgt, sub):
    """`python audit.py scope [host-or-url]`: show the scope, or check one host against it."""
    if SCOPE is None:
        print("targets.yml belum punya blok `bounty` dengan enabled: true.", file=sys.stderr)
        return 2
    if sub == "baseline":                     # no host given
        print(SCOPE.describe())
        return 0
    ok = SCOPE.allows_host(sub)
    print(f"{C.good('IN SCOPE') if ok else C.bad('OUT OF SCOPE')}  {sub}")
    return 0 if ok else 1


def docker_net_args(tgt):
    """`--network` args for `docker run`, from 'docker_network' in targets.yml.

    Needed when the target is only reachable from a specific Docker network, e.g. a `localhost`
    target (which inside a container points at the container itself). Values:
      "host"              -> host network
      "<network-name>"    -> join that Docker network (e.g. compose)
      "container:<name>"  -> share another container's network namespace (e.g. a gateway/reverse
                             proxy) so `localhost` is that container.
    Empty/unset -> no --network (default behavior)."""
    net = str((tgt or {}).get("docker_network") or "").strip()
    return ["--network", net] if net else []


def have_docker():
    if shutil.which("docker") is None:
        print("Docker tidak ditemukan di PATH — modul scanner butuh Docker.", file=sys.stderr)
        return False
    return True


def dockervol(host_path: Path) -> str:
    """Volume path accepted by Docker on both Windows (Docker Desktop) and Linux."""
    p = host_path.resolve()
    # Docker Desktop on Windows accepts both 'C:\dir' and 'C:/dir' styles.
    return str(p).replace("\\", "/")


def run(cmd: list[str]) -> int:
    print(C.dim("+ " + " ".join(cmd)))
    # shell=False: safe and identical on every OS, no shell expansion.
    return subprocess.call(cmd)


def reports_dir() -> Path:
    d = PROJECT / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---- scanner modules (Docker) ----

def mod_zap(tgt, sub="baseline"):
    reason = scope_block(f"zap-{sub}" if sub != "baseline" else "zap", tgt.get("base_url"))
    if reason:
        return refuse(reason)
    warn_unthrottled("ZAP")
    if not have_docker():
        return 2
    image = os.environ.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    out = dockervol(reports_dir())
    base = (["docker", "run", "--rm"] + docker_net_args(tgt)
            + ["-v", f"{out}:/zap/wrk:rw", image])
    extra = []
    hdr = os.environ.get("ZAP_AUTH_HEADER")  # e.g. "Authorization: Bearer xxx"
    if hdr:
        name, _, val = hdr.partition(":")
        val = val.strip()
        extra = [
            "-config", "replacer.full_list(0).description=auth",
            "-config", "replacer.full_list(0).enabled=true",
            "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
            "-config", f"replacer.full_list(0).matchstr={name.strip()}",
            "-config", f"replacer.full_list(0).replacement={val}",
        ]
    if sub == "baseline":
        return run(base + ["zap-baseline.py", "-t", tgt["base_url"],
                           "-r", "zap-baseline.html", "-J", "zap-baseline.json", "-I"] + extra)
    if sub in ("api", "full"):
        # An active scan writes to the target at random: wrap it in a data snapshot when configured.
        if sub == "api" and not tgt.get("openapi"):
            print("targets.yml belum punya 'openapi' untuk ZAP API scan.", file=sys.stderr)
            return 2
        print("ACTIVE SCAN — hanya ke dev/staging milik sendiri.", file=sys.stderr)
        if not tgt.get("snapshot"):
            print("PERINGATAN: tidak ada blok 'snapshot' di targets.yml — perubahan data oleh scan "
                  "aktif TIDAK dapat dipulihkan otomatis.", file=sys.stderr)
        sys.path.insert(0, str(ROOT / "tests"))
        import _snapshot  # noqa: E402
        try:
            with _snapshot.Guard(tgt.get("snapshot"), reports_dir(), f"ZAP {sub}") as g:
                rc = run(base + zap_scan_cmd(tgt, sub) + zap_scan_opts(tgt) + extra)
        except _snapshot.SnapshotError as exc:
            print(f"Snapshot gagal — scan DIBATALKAN: {exc}", file=sys.stderr)
            return 2
        return rc | (0 if g.ok else 1)
    print(f"subperintah zap tak dikenal: {sub}", file=sys.stderr)
    return 2


def zap_scan_cmd(tgt, sub):
    """ZAP script args for an active scan (full/api)."""
    if sub == "api":
        return ["zap-api-scan.py", "-t", tgt["openapi"], "-f", "openapi",
                "-r", "zap-api.html", "-J", "zap-api.json", "-I"]
    return ["zap-full-scan.py", "-t", tgt["base_url"], "-r", "zap-full.html", "-J", "zap-full.json",
            "-I"]


def zap_scan_opts(tgt):
    """Extra active-scan options from targets.yml: zap_exclude (URL regexes to skip, e.g. logout/delete),
    zap_spider_minutes (-m) and zap_timeout_minutes (-T)."""
    opts = []
    if tgt.get("zap_spider_minutes"):
        opts += ["-m", str(int(tgt["zap_spider_minutes"]))]
    if tgt.get("zap_timeout_minutes"):
        opts += ["-T", str(int(tgt["zap_timeout_minutes"]))]
    excl = [e for e in tgt.get("zap_exclude", []) if e]
    if excl:
        parts = []
        for i, rx in enumerate(excl):
            parts += [f"-config globalexcludeurl.url_list.url({i}).regex={rx}",
                      f"-config globalexcludeurl.url_list.url({i}).enabled=true"]
        opts += ["-z", " ".join(parts)]
    return opts


def warn_unthrottled(tool):
    """Docker scanners run outside this process, so the rate limit cannot be enforced on them."""
    if SCOPE is not None:
        print(C.dim(f"[bounty] {tool} berjalan di Docker: scope dicek, tetapi max_rps tidak dapat "
                    "dipaksakan pada tool ini."), file=sys.stderr)


def mod_tls(tgt):
    reason = scope_block("tls", tgt.get("tls_host"))
    if reason:
        return refuse(reason)
    warn_unthrottled("testssl")
    if not have_docker():
        return 2
    out = dockervol(reports_dir())
    return run(["docker", "run", "--rm"] + docker_net_args(tgt)
               + ["-v", f"{out}:/out",
                "drwetter/testssl.sh:latest", "--protocols", "--vulnerable",
                "--severity", "HIGH", "--jsonfile", "/out/testssl.json",
                tgt["tls_host"]])


def mod_headers(tgt):
    reason = scope_block("headers", tgt.get("base_url"))
    if reason:
        return refuse(reason)
    # Pure Python: no Docker needed.
    import urllib.request
    import ssl
    url = tgt["base_url"].rstrip("/") + tgt.get("header_probe_path", "/")
    ctx = ssl.create_default_context()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception as exc:  # noqa: BLE001
        # Headers can still be read from an error response.
        if hasattr(exc, "headers") and exc.headers:
            headers = {k.lower(): v for k, v in exc.headers.items()}
        else:
            print(f"gagal mengambil response header: {exc}", file=sys.stderr)
            return 2
    want = ["strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "referrer-policy"]
    leak = ["server", "x-powered-by"]
    miss = 0
    results = []
    print(f"== Security header ({url}) ==")
    for h in want:
        if h in headers:
            print(f"{C.good('ok')}   {h}: diset")
            results.append({"label": f"Header {h}", "status": None, "ok": True, "note": ""})
        else:
            print(f"{C.bad('MISS')} {h}: tidak diset")
            miss += 1
            results.append({"label": f"Header hilang: {h}", "status": None, "ok": False,
                            "note": f"header {h} tidak diset pada response"})
    for h in leak:
        if h in headers and headers[h]:
            print(f"{C.bad('LEAK')} {h}: information disclosure ({headers[h]})")
            miss += 1
            results.append({"label": f"Header information disclosure: {h}", "status": None,
                            "ok": False, "note": f"{h}: {headers[h]}"})
        else:
            print(f"{C.good('ok')}   {h}: tanpa information disclosure")
            results.append({"label": f"Header {h} tanpa information disclosure", "status": None,
                            "ok": True, "note": ""})
    import json
    with open(reports_dir() / "headers.json", "w", encoding="utf-8") as f:
        json.dump({"module": "headers", "failures": miss, "results": results},
                  f, ensure_ascii=False, indent=2)
    return 1 if miss else 0


DEPS_TOOLS = ("gitleaks", "semgrep", "trivy")


def semgrep_cmd(tgt, repo, out, name):
    """Docker command for semgrep. Optional targets.yml keys: semgrep_paths (source subdirectories
    to scan; default the whole repo) and semgrep_exclude (extra patterns).

    The selected sources are COPIED (tar) into the container filesystem and scanned there: scanning
    the repo root through a Windows bind mount is extremely slow (minutes to never finishing), while
    copy + scan of a 104-file PHP directory takes only seconds."""
    import shlex
    excl = ["vendor", "node_modules", "dist", "build", "docs"] + list(tgt.get("semgrep_exclude", []))
    paths = list(tgt.get("semgrep_paths") or ["."])
    tar_ex = " ".join(f"--exclude={shlex.quote(e)}" for e in excl)
    sg_ex = " ".join(f"--exclude {shlex.quote(e)}" for e in excl)
    script = (f"mkdir -p /tmp/scan && tar -C /src {tar_ex} -cf - {' '.join(shlex.quote(p) for p in paths)} "
              f"| tar -C /tmp/scan -xf - && cd /tmp/scan && "
              "semgrep scan --config p/owasp-top-ten --config p/security-audit --severity ERROR "
              "--metrics=off --no-git-ignore --timeout 20 --json-output /out/semgrep.json "
              f"{sg_ex} .")
    return ["docker", "run", "--rm", "--name", name, "-v", f"{repo}:/src:ro", "-v", f"{out}:/out",
            "-e", "SEMGREP_SEND_METRICS=off", "--entrypoint", "sh", "semgrep/semgrep:latest", "-c", script]


def run_semgrep(tgt, repo, out, runner=None):
    """Run semgrep under a wall-clock limit (semgrep_timeout_minutes, default 25).

    On timeout the container is killed and the result is reported as incomplete (rc 1), never hanging."""
    import subprocess
    name = f"sak-semgrep-{os.getpid()}"
    cmd = semgrep_cmd(tgt, repo, out, name)
    minutes = float(tgt.get("semgrep_timeout_minutes", 25))
    print(C.dim("+ " + " ".join(cmd)))
    try:
        return (runner or subprocess.run)(cmd, timeout=minutes * 60).returncode
    except subprocess.TimeoutExpired:
        subprocess.call(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"semgrep melewati batas {minutes:g} menit dan dihentikan — persempit `semgrep_paths` "
              "di targets.yml (mis. [\"services/iam/app\", \"frontend-vue/src\"]).", file=sys.stderr)
        return 1


def deps_selection(sub):
    """Tools to run: just `sub` if it names one, otherwise all (light -> heavy order)."""
    return (sub,) if sub in DEPS_TOOLS else DEPS_TOOLS


def mod_deps(tgt, sub="all"):
    """Code/dependency scanners. `python audit.py deps [gitleaks|semgrep|trivy]` runs one tool
    per invocation (saves memory); with no argument all three run in sequence."""
    if not have_docker():
        return 2
    repo = dockervol(Path(tgt.get("code_path", ".")))
    out = dockervol(reports_dir())
    rc = 0
    sel = deps_selection(sub)
    if "gitleaks" in sel:
        print("== gitleaks ==")
        rc |= run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro", "-v", f"{out}:/out",
                   "-w", "/repo", "zricethezav/gitleaks:latest", "detect", "--source", "/repo",
                   "--redact", "--no-banner", "--exit-code", "0", "--log-opts=--no-renames",
                   "--report-format", "json", "--report-path", "/out/gitleaks.json"])
    if "semgrep" in sel:
        print("== semgrep ==")
        rc |= run_semgrep(tgt, repo, out)
    if "trivy" in sel:
        print("== trivy (CVE dependency & rahasia) ==")
        cache_dir = trivy_cache_dir(tgt)
        cache = dockervol(cache_dir)
        # The trivy DB cache is shared across projects (saves hundreds of MB); trivy itself does not
        # allow two processes on the same cache, so parallel runs are queued here.
        with file_lock(cache_dir / ".sak-trivy.lock", "trivy project lain"):
            # Table to the console for direct reading.
            rc |= run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro",
                       "-v", f"{cache}:/root/.cache/trivy", "aquasec/trivy:latest",
                       "fs", "/repo", "--scanners", "vuln,secret",
                       "--severity", "HIGH,CRITICAL", "--ignore-unfixed"])
            # Full JSON (all severities) for the CVE report.
            run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro",
                 "-v", f"{cache}:/root/.cache/trivy", "-v", f"{out}:/out",
                 "aquasec/trivy:latest", "fs", "/repo", "--scanners", "vuln",
                 "--format", "json", "--output", "/out/trivy.json"])
    return 0  # informational; never fails the run


def trivy_cache_dir(tgt) -> Path:
    """Trivy cache folder: 'trivy_cache_dir' in targets.yml, default ~/.cache/sak-trivy (shared)."""
    raw = (tgt or {}).get("trivy_cache_dir") or (Path.home() / ".cache" / "sak-trivy")
    d = Path(str(raw)).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


class file_lock:
    """Exclusive cross-process file lock (Windows: msvcrt, POSIX: fcntl).

    Blocks until acquired; prints a message once if it has to wait for another process."""

    def __init__(self, path: Path, holder: str = "proses lain", poll: float = 2.0):
        self.path, self.holder, self.poll, self.fh = Path(path), holder, poll, None

    def _lock(self, unlock=False) -> bool:
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def __enter__(self):
        import time
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+b")
        waited = False
        while not self._lock():
            if not waited:
                print(f"  menunggu {self.holder} selesai (kunci {self.path.name})...", flush=True)
                waited = True
            time.sleep(self.poll)
        return self

    def __exit__(self, *exc):
        try:
            self._lock(unlock=True)
        finally:
            self.fh.close()
        return False


def mod_py(script: Path, config: Path, json_name: str | None = None):
    if not config.exists():
        print(f"{config} belum ada — salin dari contoh .example-nya.", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), "--config", str(config)]
    if json_name:
        cmd += ["--json", str(reports_dir() / json_name)]
    return run(guarded(cmd))


def mod_recon(extra):
    """Recon orchestrator. Forwards free-form args (target, -d, -m, --active) to the runner.

    Optional config: tests/recon/recon.yml (copy from its .example)."""
    script = ROOT / "tests" / "recon" / "run_recon.py"
    cfg = project_cfg("tests", "recon", "recon.yml")
    cmd = [sys.executable, str(script), "--json", str(reports_dir() / "recon.json")]
    if cfg.exists():
        cmd += ["--config", str(cfg)]
    if SCOPE is not None:
        cmd += ["--scope-file", str(project_cfg("config", "targets.yml"))]
    cmd += list(extra)
    rc = run(cmd)
    mod_report()
    return rc


def mod_report():
    """Merge all JSON in reports/ into one HTML + Markdown report."""
    return run([sys.executable, str(ROOT / "report.py"), "--dir", str(reports_dir())])


def mod_rollback():
    """Automatically undo every destructive action recorded in the rollback journal.

    Runs as the LAST phase (after the report) so the target returns to its original state.
    Can also be invoked manually: `python audit.py rollback`.
    """
    import importlib.util

    sys.path.insert(0, str(ROOT / "tests"))
    import _fixture  # noqa: E402
    import _rollback  # noqa: E402
    import _sanctum  # noqa: E402
    import _snapshot  # noqa: E402

    reports = reports_dir()
    if not _rollback.pending(reports):
        return 0
    ctx = {}

    def ma_ctx():
        """Auth session from the mass-assignment config (built lazily, only when an entry needs it)."""
        if ctx:
            return ctx
        cfg_path = project_cfg("tests", "mass-assignment", "mass_assignment.yml")
        if not cfg_path.exists():
            raise RuntimeError("config auth mass-assignment tak ditemukan — pulihkan manual")
        spec = importlib.util.spec_from_file_location(
            "run_mass_assignment", ROOT / "tests" / "mass-assignment" / "run_mass_assignment.py")
        ma = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ma)
        import yaml
        with open(cfg_path, encoding="utf-8") as f:
            cfg = ma.expand(yaml.safe_load(f))
        base = cfg["base_url"].rstrip("/")
        sess, sanctum = ma.build_session(base, cfg.get("auth") or {})
        ctx.update(base=base, sess=sess, sanctum=sanctum)
        return ctx

    def do_restore(entry):
        a = entry["action"]
        if a.get("fixture_config"):               # throwaway test account -> delete via the admin session
            return _fixture.restore_entry(entry)
        if a.get("snapshot_manifest"):            # data snapshot (active scan) -> restore from file
            return _snapshot.restore_entry(entry)
        c = ma_ctx()
        url = (a.get("base_url") or c["base"]).rstrip("/") + a["path"]
        hdr = (_sanctum.auth_headers(c["sess"], c["sanctum"].get("origin"))
               if c["sanctum"] else {})
        r = c["sess"].request(a.get("method", "PATCH"), url, json=a.get("json"),
                              headers=hdr, timeout=20)
        ok = 200 <= r.status_code < 400
        return ok, ("dipulihkan" if ok else f"HTTP {r.status_code} — pulihkan manual")

    print("== Rollback (memulihkan keadaan target) ==")
    res = _rollback.replay(reports, do_restore)
    failed = sum(1 for r in res if not r["ok"])
    for r in res:
        print(f"  {C.good('ok') if r['ok'] else C.bad('XX')} {r['label']}  {r['note']}")
    print(f"{len(res) - failed}/{len(res)} dipulihkan.")
    return 1 if failed else 0


# Python-runner test modules: CLI name -> (folder under tests/, runner, config, json).
# Runners and example configs live in the kit (ROOT); live per-project configs live in PROJECT.
# Dict order = execution order for `all` (a module runs only if its config exists).
PY_MODULES = {
    "authz": ("authz-matrix", "run_authz_matrix.py", "authz_matrix.yml", "authz.json"),
    "upload": ("upload-safety", "run_upload_safety.py", "upload_safety.yml", "upload.json"),
    "auth-policy": ("auth-policy", "run_auth_policy.py", "auth_policy.yml", "auth_policy.json"),
    "clientleak": ("client-leak", "run_client_leak.py", "client_leak.yml", "client_leak.json"),
    "cors": ("cors", "run_cors.py", "cors.yml", "cors.json"),
    "open-redirect": ("open-redirect", "run_open_redirect.py", "open_redirect.yml", "open_redirect.json"),
    "webstack": ("webstack", "run_webstack.py", "webstack.yml", "webstack.json"),
    "injection": ("injection", "run_injection.py", "injection.yml", "injection.json"),
    "cookie-flags": ("cookie-flags", "run_cookie_flags.py", "cookie_flags.yml", "cookie_flags.json"),
    "response-leak": ("response-leak", "run_response_leak.py", "response_leak.yml", "response_leak.json"),
    "openapi-coverage": ("openapi-coverage", "run_openapi_coverage.py", "openapi_coverage.yml",
                         "openapi_coverage.json"),
    "ratelimit": ("ratelimit", "run_ratelimit.py", "ratelimit.yml", "ratelimit.json"),
    "session-mgmt": ("session-mgmt", "run_session_mgmt.py", "session_mgmt.yml", "session_mgmt.json"),
    "captcha": ("captcha", "run_captcha.py", "captcha.yml", "captcha.json"),
    "jwt": ("jwt", "run_jwt.py", "jwt.yml", "jwt.json"),
    "ssrf": ("ssrf", "run_ssrf.py", "ssrf.yml", "ssrf.json"),
    "mass-assignment": ("mass-assignment", "run_mass_assignment.py", "mass_assignment.yml",
                        "mass_assignment.json"),
}
# Modules that create/modify data: roll back afterwards (cleans leftovers if interrupted).
ROLLBACK_AFTER = {"ratelimit", "session-mgmt", "mass-assignment"}


def py_module_paths(name):
    folder, script, cfg, jn = PY_MODULES[name]
    return ROOT / "tests" / folder / script, project_cfg("tests", folder, cfg), jn


def run_py_module(name):
    script, cfg, jn = py_module_paths(name)
    reason = py_module_block(name, cfg)
    if reason:
        return refuse(reason)
    return mod_py(script, cfg, jn)


def mod_init(modules_csv: str):
    """Set up the project folder: config/targets.yml (from the example), reports/ and the config
    of the requested modules (e.g. "authz,upload"). Existing files are never overwritten."""
    if PROJECT == ROOT and not os.environ.get("SAK_ALLOW_INIT_ROOT"):
        print("Pakai `--project <nama|folder>` untuk init (mis. `python audit.py --project "
              "my-app init authz,upload`).", file=sys.stderr)
        return 2
    wanted = [m.strip() for m in (modules_csv or "").split(",") if m.strip() and m != "baseline"]
    unknown = [m for m in wanted if m not in PY_MODULES and m != "recon"]
    if unknown:
        print(f"Modul tak dikenal: {', '.join(unknown)}. Pilihan: {', '.join(PY_MODULES)}, recon",
              file=sys.stderr)
        return 2
    pairs = [(ROOT / "config" / "targets.example.yml", project_cfg("config", "targets.yml"))]
    for m in wanted:
        folder, _s, cfg, _j = PY_MODULES[m] if m != "recon" else ("recon", "", "recon.yml", "")
        pairs.append((ROOT / "tests" / folder / cfg.replace(".yml", ".example.yml"),
                      project_cfg("tests", folder, cfg)))
    reports_dir()
    for src, dst in pairs:
        if dst.exists():
            print(f"  ada   {dst}")
            continue
        if not src.exists():
            print(f"  lewati {dst.name}: contoh {src} tidak ada", file=sys.stderr)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        print(f"  dibuat {dst}")
    print(f"Project siap di {PROJECT}. Isi base_url & kredensial (lewat env var) lalu jalankan "
          f"`python audit.py --project {PROJECT} all`.")
    return 0


def mod_clean():
    """Delete files in the active project's reports/ (subfolders such as evidence/ and snapshots/ are kept)."""
    d = reports_dir()
    n = 0
    for f in d.iterdir():
        if f.is_file() and f.name != ".gitkeep":
            f.unlink()
            n += 1
    print(f"{d} dibersihkan ({n} file).")
    return 0


def main(argv=None):
    project, argv = pop_project_arg(list(sys.argv[1:] if argv is None else argv))
    color, argv = pop_color_arg(argv)
    if color:
        os.environ["SAK_COLOR"] = color        # inherited by runners and report.py
    lang, argv = pop_lang_arg(argv)
    if lang:
        os.environ["SAK_LANG"] = lang
        glossary.reset_cache()
    set_project(resolve_project(project or os.environ.get("SAK_PROJECT_DIR")))
    if PROJECT != ROOT:
        print(C.dim(f"[project] {PROJECT}"))
    init_scope()
    if SCOPE is not None:
        _throttle.install(SCOPE)    # this process too (headers, rollback): same scope + rate limit
    # 'recon' forwards free-form args (target, -d, -m, --active) to its runner,
    # so it is intercepted before the strict argparse.
    if argv and argv[0] == "recon":
        return mod_recon(argv[1:])
    ap = argparse.ArgumentParser(
        description="Security Audit Kit — lintas-platform",
        epilog="Opsi global: --project <nama|folder> (atau env SAK_PROJECT_DIR) untuk memakai "
               "config & reports milik project tsb; nama saja = <kit>/projects/<nama>. "
               "--color auto|always|never (atau --no-color; env SAK_COLOR / NO_COLOR) mengatur "
               "warna keluaran; bawaan auto = hanya di terminal interaktif. "
               "--lang id|en|de (atau env SAK_LANG) memilih glosarium istilah teknis; bawaan en.")
    ap.add_argument("module", choices=["all", "init", "zap", "tls", "headers", "deps", *PY_MODULES,
                                       "recon", "rollback", "report", "clean", "scope"])
    ap.add_argument("sub", nargs="?", default="baseline",
                    help="subperintah: 'zap' baseline|api|full; 'deps' gitleaks|semgrep|trivy "
                         "(satu tool); 'init' daftar modul dipisah koma (mis. authz,upload)")
    args = ap.parse_args(argv)

    if args.module == "init":
        return mod_init("" if args.sub == "baseline" else args.sub)
    if args.module == "rollback":
        return mod_rollback()
    if args.module == "report":
        return mod_report()
    if args.module == "clean":
        return mod_clean()

    tgt = load_targets()
    if args.module == "zap":
        return mod_zap(tgt, args.sub)
    if args.module == "tls":
        return mod_tls(tgt)
    if args.module == "headers":
        return mod_headers(tgt)
    if args.module == "deps":
        return mod_deps(tgt, args.sub)
    if args.module == "scope":
        return mod_scope(tgt, args.sub)
    if args.module in PY_MODULES:
        rc = run_py_module(args.module)
        mod_report()
        if args.module in ROLLBACK_AFTER:
            mod_rollback()      # last phase: restore target state / leftover test accounts
        return rc
    if args.module == "all":
        rc = 0
        rc |= mod_headers(tgt)
        rc |= mod_deps(tgt)
        rc |= mod_zap(tgt, "baseline")
        # Test modules run only when their config exists in the project.
        for name in PY_MODULES:
            script, cfg, jn = py_module_paths(name)
            if cfg.exists():
                reason = py_module_block(name, cfg)
                if reason:                      # bounty mode: skip, keep going with the rest
                    rc |= refuse(reason)
                    continue
                rc |= mod_py(script, cfg, jn)
        recon_cfg = project_cfg("tests", "recon", "recon.yml")
        if recon_cfg.exists():
            rc |= mod_recon([])
        mod_report()
        mod_rollback()          # last phase: undo destructive actions
        return rc
    return 2


if __name__ == "__main__":
    sys.exit(main())
