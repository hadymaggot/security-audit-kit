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


def mod_report():
    """Gabungkan semua JSON di reports/ jadi satu laporan HTML + Markdown."""
    return run([sys.executable, str(ROOT / "report.py")])


def main():
    ap = argparse.ArgumentParser(description="Security Audit Kit — lintas-platform")
    ap.add_argument("module", choices=["all", "zap", "tls", "headers", "deps",
                                       "authz", "upload", "auth-policy", "clientleak",
                                       "report"])
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
        ):
            if cfg.exists():
                rc |= mod_py(script, cfg, jn)
        mod_report()
        return rc
    return 2


if __name__ == "__main__":
    sys.exit(main())
