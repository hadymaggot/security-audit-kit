#!/usr/bin/env python3
"""Pintu masuk lintas-platform untuk Security Audit Kit.

Berjalan sama di Windows (PowerShell/cmd) maupun Linux/macOS — semua orkestrasi
dilakukan di Python, memanggil image Docker resmi; tidak bergantung pada shell.

Pakai:
    python audit.py all                      # jalankan semua modul dari config/targets.yml
    python audit.py zap baseline
    python audit.py zap api
    python audit.py tls
    python audit.py headers
    python audit.py deps
    python audit.py authz
    python audit.py upload
    python audit.py auth-policy

Konfigurasi target di config/targets.yml (lihat config/targets.example.yml).
Kredensial & token diambil dari environment variable, bukan dari file.
"""
from __future__ import annotations

import argparse
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

ROOT = Path(__file__).resolve().parent
ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def load_targets():
    path = ROOT / "config" / "targets.yml"
    if not path.exists():
        print("config/targets.yml belum ada. Salin dari config/targets.example.yml.",
              file=sys.stderr)
        sys.exit(2)
    with open(path, encoding="utf-8") as f:
        return expand(yaml.safe_load(f))


def have_docker():
    if shutil.which("docker") is None:
        print("Docker tidak ditemukan di PATH — modul scanner butuh Docker.", file=sys.stderr)
        return False
    return True


def dockervol(host_path: Path) -> str:
    """Path volume Docker yang diterima baik di Windows (Docker Desktop) maupun Linux."""
    p = host_path.resolve()
    # Docker Desktop di Windows menerima path gaya 'C:\dir' maupun 'C:/dir'.
    return str(p).replace("\\", "/")


def run(cmd: list[str]) -> int:
    print("+ " + " ".join(cmd))
    # shell=False → aman & identik di semua OS; tanpa ekspansi shell.
    return subprocess.call(cmd)


def reports_dir() -> Path:
    d = ROOT / "reports"
    d.mkdir(exist_ok=True)
    return d


# ---- modul scanner (Docker) ----

def mod_zap(tgt, sub="baseline"):
    if not have_docker():
        return 2
    image = os.environ.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    out = dockervol(reports_dir())
    base = ["docker", "run", "--rm", "-v", f"{out}:/zap/wrk:rw", image]
    extra = []
    hdr = os.environ.get("ZAP_AUTH_HEADER")  # mis. "Authorization: Bearer xxx"
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
    if sub == "api":
        spec = tgt.get("openapi")
        if not spec:
            print("targets.yml belum punya 'openapi' untuk ZAP API scan.", file=sys.stderr)
            return 2
        return run(base + ["zap-api-scan.py", "-t", spec, "-f", "openapi",
                           "-r", "zap-api.html", "-J", "zap-api.json", "-I"] + extra)
    if sub == "full":
        print("ACTIVE SCAN — hanya ke dev/staging milik sendiri.", file=sys.stderr)
        return run(base + ["zap-full-scan.py", "-t", tgt["base_url"],
                           "-r", "zap-full.html", "-J", "zap-full.json", "-I"] + extra)
    print(f"subperintah zap tak dikenal: {sub}", file=sys.stderr)
    return 2


def mod_tls(tgt):
    if not have_docker():
        return 2
    out = dockervol(reports_dir())
    return run(["docker", "run", "--rm", "-v", f"{out}:/out",
                "drwetter/testssl.sh:latest", "--protocols", "--vulnerable",
                "--severity", "HIGH", "--jsonfile", "/out/testssl.json",
                tgt["tls_host"]])


def mod_headers(tgt):
    # Murni Python — tak perlu Docker, jalan di mana saja.
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
        # Header tetap bisa dibaca dari respons error.
        if hasattr(exc, "headers") and exc.headers:
            headers = {k.lower(): v for k, v in exc.headers.items()}
        else:
            print(f"gagal ambil header: {exc}", file=sys.stderr)
            return 2
    want = ["strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "referrer-policy"]
    leak = ["server", "x-powered-by"]
    miss = 0
    results = []
    print(f"== Security header ({url}) ==")
    for h in want:
        if h in headers:
            print(f"ok   {h}")
            results.append({"label": f"Header {h}", "status": None, "ok": True, "note": ""})
        else:
            print(f"MISS {h}")
            miss += 1
            results.append({"label": f"Header hilang: {h}", "status": None, "ok": False,
                            "note": f"header {h} tak diset pada respons"})
    for h in leak:
        if h in headers and headers[h]:
            print(f"LEAK {h}: {headers[h]}")
            miss += 1
            results.append({"label": f"Header pembocor info: {h}", "status": None,
                            "ok": False, "note": f"{h}: {headers[h]}"})
        else:
            print(f"ok   {h} tidak dibocorkan")
            results.append({"label": f"Header {h} tidak dibocorkan", "status": None,
                            "ok": True, "note": ""})
    import json
    with open(reports_dir() / "headers.json", "w", encoding="utf-8") as f:
        json.dump({"module": "headers", "failures": miss, "results": results},
                  f, ensure_ascii=False, indent=2)
    return 1 if miss else 0


def mod_deps(tgt):
    if not have_docker():
        return 2
    repo = dockervol(Path(tgt.get("code_path", ".")))
    rc = 0
    print("== gitleaks ==")
    rc |= run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro", "-w", "/repo",
               "zricethezav/gitleaks:latest", "detect", "--source", "/repo",
               "--redact", "--no-banner", "--exit-code", "0",
               "--log-opts=--no-renames"])
    print("== semgrep ==")
    rc |= run(["docker", "run", "--rm", "-v", f"{repo}:/src:ro", "-w", "/src",
               "-e", "SEMGREP_SEND_METRICS=off", "semgrep/semgrep:latest",
               "semgrep", "scan", "--config", "p/owasp-top-ten",
               "--config", "p/security-audit", "--severity", "ERROR",
               "--metrics=off", "--exclude", "vendor", "--exclude", "node_modules"])
    print("== trivy (CVE dependensi & rahasia) ==")
    cache = dockervol(Path.home() / ".cache" / "sak-trivy")
    (Path.home() / ".cache" / "sak-trivy").mkdir(parents=True, exist_ok=True)
    out = dockervol(reports_dir())
    # Tabel ke konsol untuk dibaca langsung.
    rc |= run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro",
               "-v", f"{cache}:/root/.cache/trivy", "aquasec/trivy:latest",
               "fs", "/repo", "--scanners", "vuln,secret",
               "--severity", "HIGH,CRITICAL", "--ignore-unfixed"])
    # JSON lengkap (semua severity) untuk laporan CVE.
    run(["docker", "run", "--rm", "-v", f"{repo}:/repo:ro",
         "-v", f"{cache}:/root/.cache/trivy", "-v", f"{out}:/out",
         "aquasec/trivy:latest", "fs", "/repo", "--scanners", "vuln",
         "--format", "json", "--output", "/out/trivy.json"])
    return 0  # informatif; tak menggagalkan


def mod_py(script: Path, config: Path, json_name: str | None = None):
    if not config.exists():
        print(f"{config} belum ada — salin dari contoh .example-nya.", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(script), "--config", str(config)]
    if json_name:
        cmd += ["--json", str(reports_dir() / json_name)]
    return run(cmd)


def mod_recon(extra):
    """Recon orchestrator. Meneruskan argumen bebas (target, -d, -m, --active) ke
    runner. Config opsional: tests/recon/recon.yml (salin dari .example-nya)."""
    script = ROOT / "tests" / "recon" / "run_recon.py"
    cfg = ROOT / "tests" / "recon" / "recon.yml"
    cmd = [sys.executable, str(script), "--json", str(reports_dir() / "recon.json")]
    if cfg.exists():
        cmd += ["--config", str(cfg)]
    cmd += list(extra)
    rc = run(cmd)
    mod_report()
    return rc


def mod_report():
    """Gabungkan semua JSON di reports/ jadi satu laporan HTML + Markdown."""
    return run([sys.executable, str(ROOT / "report.py")])


def mod_rollback():
    """Pulihkan otomatis semua aksi destruktif yang tercatat di jurnal rollback.

    Dijalankan sebagai fase TERAKHIR (setelah laporan) supaya target kembali ke
    keadaan semula — 'rasa non-destruktif'. Juga bisa dipanggil manual:
    `python audit.py rollback`.
    """
    import importlib.util

    sys.path.insert(0, str(ROOT / "tests"))
    import _rollback  # noqa: E402
    import _sanctum  # noqa: E402

    reports = reports_dir()
    if not _rollback.pending(reports):
        return 0
    # Auth memakai config modul destruktif (mass-assignment satu-satunya saat ini).
    cfg_path = ROOT / "tests" / "mass-assignment" / "mass_assignment.yml"
    if not cfg_path.exists():
        print("Jurnal rollback ada tapi config auth tak ditemukan — pulihkan manual.",
              file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location(
        "run_mass_assignment", ROOT / "tests" / "mass-assignment" / "run_mass_assignment.py")
    ma = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ma)
    import yaml
    with open(cfg_path, encoding="utf-8") as f:
        cfg = ma.expand(yaml.safe_load(f))
    base = cfg["base_url"].rstrip("/")
    sess, sanctum = ma.build_session(base, cfg.get("auth") or {})

    def headers():
        return _sanctum.auth_headers(sess, sanctum.get("origin")) if sanctum else {}

    def do_restore(entry):
        a = entry["action"]
        url = (a.get("base_url") or base).rstrip("/") + a["path"]
        r = sess.request(a.get("method", "PATCH"), url, json=a.get("json"),
                         headers=headers(), timeout=20)
        ok = 200 <= r.status_code < 400
        return ok, ("dipulihkan" if ok else f"HTTP {r.status_code} — pulihkan manual")

    print("== Rollback (memulihkan keadaan target) ==")
    res = _rollback.replay(reports, do_restore)
    gagal = sum(1 for r in res if not r["ok"])
    for r in res:
        print(f"  {'ok ' if r['ok'] else 'XX '}{r['label']}  {r['note']}")
    print(f"{len(res) - gagal}/{len(res)} dipulihkan.")
    return 1 if gagal else 0


def main():
    # 'recon' meneruskan argumen bebas (target, -d, -m, --active) ke runner-nya,
    # jadi di-intercept sebelum argparse yang ketat.
    if len(sys.argv) > 1 and sys.argv[1] == "recon":
        return mod_recon(sys.argv[2:])
    ap = argparse.ArgumentParser(description="Security Audit Kit — lintas-platform")
    ap.add_argument("module", choices=["all", "zap", "tls", "headers", "deps",
                                       "authz", "upload", "auth-policy", "clientleak",
                                       "cors", "open-redirect", "mass-assignment",
                                       "webstack", "injection", "recon", "rollback", "report"])
    ap.add_argument("sub", nargs="?", default="baseline",
                    help="subperintah untuk 'zap': baseline|api|full")
    args = ap.parse_args()
    tgt = load_targets()

    if args.module == "zap":
        return mod_zap(tgt, args.sub)
    if args.module == "tls":
        return mod_tls(tgt)
    if args.module == "headers":
        return mod_headers(tgt)
    if args.module == "deps":
        return mod_deps(tgt)
    if args.module == "authz":
        rc = mod_py(ROOT / "tests" / "authz-matrix" / "run_authz_matrix.py",
                    ROOT / "tests" / "authz-matrix" / "authz_matrix.yml", "authz.json")
        mod_report()
        return rc
    if args.module == "upload":
        rc = mod_py(ROOT / "tests" / "upload-safety" / "run_upload_safety.py",
                    ROOT / "tests" / "upload-safety" / "upload_safety.yml", "upload.json")
        mod_report()
        return rc
    if args.module == "auth-policy":
        rc = mod_py(ROOT / "tests" / "auth-policy" / "run_auth_policy.py",
                    ROOT / "tests" / "auth-policy" / "auth_policy.yml", "auth_policy.json")
        mod_report()
        return rc
    if args.module == "clientleak":
        rc = mod_py(ROOT / "tests" / "client-leak" / "run_client_leak.py",
                    ROOT / "tests" / "client-leak" / "client_leak.yml", "client_leak.json")
        mod_report()
        return rc
    if args.module == "cors":
        rc = mod_py(ROOT / "tests" / "cors" / "run_cors.py",
                    ROOT / "tests" / "cors" / "cors.yml", "cors.json")
        mod_report()
        return rc
    if args.module == "open-redirect":
        rc = mod_py(ROOT / "tests" / "open-redirect" / "run_open_redirect.py",
                    ROOT / "tests" / "open-redirect" / "open_redirect.yml", "open_redirect.json")
        mod_report()
        return rc
    if args.module == "webstack":
        rc = mod_py(ROOT / "tests" / "webstack" / "run_webstack.py",
                    ROOT / "tests" / "webstack" / "webstack.yml", "webstack.json")
        mod_report()
        return rc
    if args.module == "injection":
        rc = mod_py(ROOT / "tests" / "injection" / "run_injection.py",
                    ROOT / "tests" / "injection" / "injection.yml", "injection.json")
        mod_report()
        return rc
    if args.module == "mass-assignment":
        rc = mod_py(ROOT / "tests" / "mass-assignment" / "run_mass_assignment.py",
                    ROOT / "tests" / "mass-assignment" / "mass_assignment.yml",
                    "mass_assignment.json")
        mod_report()
        mod_rollback()          # fase terakhir: pulihkan keadaan target.
        return rc
    if args.module == "rollback":
        return mod_rollback()
    if args.module == "report":
        return mod_report()
    if args.module == "all":
        rc = 0
        rc |= mod_headers(tgt)
        rc |= mod_deps(tgt)
        rc |= mod_zap(tgt, "baseline")
        # Modul pengujian hanya jalan bila config-nya ada.
        for script, cfg, jn in (
            (ROOT / "tests/authz-matrix/run_authz_matrix.py", ROOT / "tests/authz-matrix/authz_matrix.yml", "authz.json"),
            (ROOT / "tests/upload-safety/run_upload_safety.py", ROOT / "tests/upload-safety/upload_safety.yml", "upload.json"),
            (ROOT / "tests/auth-policy/run_auth_policy.py", ROOT / "tests/auth-policy/auth_policy.yml", "auth_policy.json"),
            (ROOT / "tests/client-leak/run_client_leak.py", ROOT / "tests/client-leak/client_leak.yml", "client_leak.json"),
            (ROOT / "tests/cors/run_cors.py", ROOT / "tests/cors/cors.yml", "cors.json"),
            (ROOT / "tests/open-redirect/run_open_redirect.py", ROOT / "tests/open-redirect/open_redirect.yml", "open_redirect.json"),
            (ROOT / "tests/webstack/run_webstack.py", ROOT / "tests/webstack/webstack.yml", "webstack.json"),
            (ROOT / "tests/injection/run_injection.py", ROOT / "tests/injection/injection.yml", "injection.json"),
            (ROOT / "tests/mass-assignment/run_mass_assignment.py", ROOT / "tests/mass-assignment/mass_assignment.yml", "mass_assignment.json"),
            (ROOT / "tests/recon/run_recon.py", ROOT / "tests/recon/recon.yml", "recon.json"),
        ):
            if cfg.exists():
                rc |= mod_py(script, cfg, jn)
        mod_report()
        mod_rollback()          # fase terakhir: pulihkan aksi destruktif ke semula.
        return rc
    return 2


if __name__ == "__main__":
    sys.exit(main())
