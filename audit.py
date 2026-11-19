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


def docker_net_args(tgt):
    """Argumen `--network` untuk `docker run` dari 'docker_network' di targets.yml.

    Berguna saat target hanya terjangkau dari jaringan Docker tertentu — mis. target
    `localhost` (yang di dalam container menunjuk ke container itu sendiri). Nilai:
      "host"                  -> jaringan host
      "<nama-jaringan>"       -> bergabung ke jaringan Docker tsb (mis. compose)
      "container:<nama>"      -> berbagi network namespace container lain (mis. gateway/
                                 reverse proxy) sehingga `localhost` = container itu.
    Kosong/tidak diset -> tanpa --network (perilaku bawaan)."""
    net = str((tgt or {}).get("docker_network") or "").strip()
    return ["--network", net] if net else []


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
    base = (["docker", "run", "--rm"] + docker_net_args(tgt)
            + ["-v", f"{out}:/zap/wrk:rw", image])
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
    if sub in ("api", "full"):
        # Scan AKTIF menulis ke target secara acak -> wajib dibungkus snapshot data bila dikonfigurasi.
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
    """Argumen skrip ZAP untuk scan aktif (full/api)."""
    if sub == "api":
        return ["zap-api-scan.py", "-t", tgt["openapi"], "-f", "openapi",
                "-r", "zap-api.html", "-J", "zap-api.json", "-I"]
    return ["zap-full-scan.py", "-t", tgt["base_url"], "-r", "zap-full.html", "-J", "zap-full.json",
            "-I"]


def zap_scan_opts(tgt):
    """Opsi tambahan scan aktif dari targets.yml: zap_exclude (regex URL yang dilewati, mis. logout/hapus),
    zap_spider_minutes (-m), dan zap_timeout_minutes (-T)."""
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


def mod_tls(tgt):
    if not have_docker():
        return 2
    out = dockervol(reports_dir())
    return run(["docker", "run", "--rm"] + docker_net_args(tgt)
               + ["-v", f"{out}:/out",
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


DEPS_TOOLS = ("gitleaks", "semgrep", "trivy")


def semgrep_cmd(tgt, repo, out, name):
    """Perintah docker semgrep. targets.yml (opsional): semgrep_paths (subdirektori sumber yang
    dipindai; default seluruh repo), semgrep_exclude (pola tambahan)."""
    excl = ["vendor", "node_modules", "dist", "build", "docs"] + list(tgt.get("semgrep_exclude", []))
    cmd = ["docker", "run", "--rm", "--name", name, "-v", f"{repo}:/src:ro", "-v", f"{out}:/out",
           "-w", "/src", "-e", "SEMGREP_SEND_METRICS=off", "semgrep/semgrep:latest",
           "semgrep", "scan", "--config", "p/owasp-top-ten", "--config", "p/security-audit",
           "--severity", "ERROR", "--metrics=off", "--json-output", "/out/semgrep.json"]
    for e in excl:
        cmd += ["--exclude", e]
    return cmd + list(tgt.get("semgrep_paths") or ["."])


def run_semgrep(tgt, repo, out, runner=None):
    """Jalankan semgrep dengan batas waktu dinding (semgrep_timeout_minutes, default 25): bila lewat,
    container dihentikan dan hasil dilaporkan sebagai tidak lengkap (rc 1) — tidak menggantung."""
    import subprocess
    name = f"sak-semgrep-{os.getpid()}"
    cmd = semgrep_cmd(tgt, repo, out, name)
    minutes = float(tgt.get("semgrep_timeout_minutes", 25))
    print("+ " + " ".join(cmd))
    try:
        return (runner or subprocess.run)(cmd, timeout=minutes * 60).returncode
    except subprocess.TimeoutExpired:
        subprocess.call(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"semgrep melewati batas {minutes:g} menit dan dihentikan — persempit `semgrep_paths` "
              "di targets.yml (mis. [\"services/iam/app\", \"frontend-vue/src\"]).", file=sys.stderr)
        return 1


def deps_selection(sub):
    """Tool yang dijalankan: satu tool bila `sub` salah satunya, selain itu semua (urutan ringan->berat)."""
    return (sub,) if sub in DEPS_TOOLS else DEPS_TOOLS


def mod_deps(tgt, sub="all"):
    """Scanner kode/dependensi. `python audit.py deps [gitleaks|semgrep|trivy]` — satu tool per
    jalan (hemat memori); tanpa argumen menjalankan ketiganya berurutan."""
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
        print("== trivy (CVE dependensi & rahasia) ==")
        cache = dockervol(Path.home() / ".cache" / "sak-trivy")
        (Path.home() / ".cache" / "sak-trivy").mkdir(parents=True, exist_ok=True)
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
    import _fixture  # noqa: E402
    import _rollback  # noqa: E402
    import _sanctum  # noqa: E402
    import _snapshot  # noqa: E402

    reports = reports_dir()
    if not _rollback.pending(reports):
        return 0
    ctx = {}

    def ma_ctx():
        """Sesi auth dari config mass-assignment (dibuat malas — hanya bila entri butuh)."""
        if ctx:
            return ctx
        cfg_path = ROOT / "tests" / "mass-assignment" / "mass_assignment.yml"
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
        if a.get("fixture_config"):               # akun uji sekali pakai -> hapus pakai sesi admin
            return _fixture.restore_entry(entry)
        if a.get("snapshot_manifest"):            # snapshot data (scan aktif) -> pulihkan dari berkas
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
                                       "webstack", "injection", "cookie-flags", "response-leak", "openapi-coverage", "ratelimit", "session-mgmt", "captcha", "jwt", "ssrf", "recon", "rollback", "report"])
    ap.add_argument("sub", nargs="?", default="baseline",
                    help="subperintah: 'zap' baseline|api|full; 'deps' gitleaks|semgrep|trivy (satu tool)")
    args = ap.parse_args()
    tgt = load_targets()

    if args.module == "zap":
        return mod_zap(tgt, args.sub)
    if args.module == "tls":
        return mod_tls(tgt)
    if args.module == "headers":
        return mod_headers(tgt)
    if args.module == "deps":
        return mod_deps(tgt, args.sub)
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
    if args.module == "ssrf":
        rc = mod_py(ROOT / "tests" / "ssrf" / "run_ssrf.py",
                    ROOT / "tests" / "ssrf" / "ssrf.yml", "ssrf.json")
        mod_report()
        return rc
    if args.module == "jwt":
        rc = mod_py(ROOT / "tests" / "jwt" / "run_jwt.py",
                    ROOT / "tests" / "jwt" / "jwt.yml", "jwt.json")
        mod_report()
        return rc
    if args.module == "captcha":
        rc = mod_py(ROOT / "tests" / "captcha" / "run_captcha.py",
                    ROOT / "tests" / "captcha" / "captcha.yml", "captcha.json")
        mod_report()
        return rc
    if args.module == "session-mgmt":
        rc = mod_py(ROOT / "tests" / "session-mgmt" / "run_session_mgmt.py",
                    ROOT / "tests" / "session-mgmt" / "session_mgmt.yml", "session_mgmt.json")
        mod_report()
        mod_rollback()          # bersihkan sisa akun uji bila proses terputus di tengah.
        return rc
    if args.module == "ratelimit":
        rc = mod_py(ROOT / "tests" / "ratelimit" / "run_ratelimit.py",
                    ROOT / "tests" / "ratelimit" / "ratelimit.yml", "ratelimit.json")
        mod_report()
        mod_rollback()          # bersihkan sisa akun uji bila proses terputus di tengah.
        return rc
    if args.module == "openapi-coverage":
        rc = mod_py(ROOT / "tests" / "openapi-coverage" / "run_openapi_coverage.py",
                    ROOT / "tests" / "openapi-coverage" / "openapi_coverage.yml",
                    "openapi_coverage.json")
        mod_report()
        return rc
    if args.module == "response-leak":
        rc = mod_py(ROOT / "tests" / "response-leak" / "run_response_leak.py",
                    ROOT / "tests" / "response-leak" / "response_leak.yml", "response_leak.json")
        mod_report()
        return rc
    if args.module == "cookie-flags":
        rc = mod_py(ROOT / "tests" / "cookie-flags" / "run_cookie_flags.py",
                    ROOT / "tests" / "cookie-flags" / "cookie_flags.yml", "cookie_flags.json")
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
            (ROOT / "tests/cookie-flags/run_cookie_flags.py", ROOT / "tests/cookie-flags/cookie_flags.yml", "cookie_flags.json"),
            (ROOT / "tests/response-leak/run_response_leak.py", ROOT / "tests/response-leak/response_leak.yml", "response_leak.json"),
            (ROOT / "tests/openapi-coverage/run_openapi_coverage.py", ROOT / "tests/openapi-coverage/openapi_coverage.yml", "openapi_coverage.json"),
            (ROOT / "tests/ratelimit/run_ratelimit.py", ROOT / "tests/ratelimit/ratelimit.yml", "ratelimit.json"),
            (ROOT / "tests/session-mgmt/run_session_mgmt.py", ROOT / "tests/session-mgmt/session_mgmt.yml", "session_mgmt.json"),
            (ROOT / "tests/captcha/run_captcha.py", ROOT / "tests/captcha/captcha.yml", "captcha.json"),
            (ROOT / "tests/jwt/run_jwt.py", ROOT / "tests/jwt/jwt.yml", "jwt.json"),
            (ROOT / "tests/ssrf/run_ssrf.py", ROOT / "tests/ssrf/ssrf.yml", "ssrf.json"),
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
