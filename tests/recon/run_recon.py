#!/usr/bin/env python3
"""Modul recon — orkestrasi passive OSINT + (opsional) port scan & vuln scan.

Fase (dikendalikan `depth` di config):
  osint : subfinder (subdomain) -> dnsx (resolve) -> httpx (alive/tech)   [non-intrusif]
  infra : + naabu (port scan)                                            [AKTIF, gated]
  full  : + nuclei (vuln scan; mode fast/stealth/full/owasp)             [AKTIF, gated]

Fase aktif (naabu/nuclei/ffuf) HANYA berjalan bila di config:
  active.enabled: true  DAN  toggle tool terkait bernilai true.
Default semua off (aman). Hanya untuk target yang Anda miliki/berwenang uji.

Binari ProjectDiscovery dipanggil via subprocess (shell=False). Jika sebuah
binari tidak terpasang, fase-nya dilewati dengan catatan (tidak menggagalkan run).
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
    yaml = None

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(x):
    """Substitusi ${ENV_VAR} dari environment (rekursif)."""
    if isinstance(x, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), x)
    if isinstance(x, dict):
        return {k: expand(v) for k, v in x.items()}
    if isinstance(x, list):
        return [expand(v) for v in x]
    return x


DEPTHS = ("osint", "infra", "full")
MODES = ("fast", "stealth", "full", "owasp")

# Mapping mode -> (tags, severity) nuclei — diselaraskan dengan hunter.fish.
_NUCLEI = {
    "fast": ("cve,rce,lfi,sqli,ssti,ssrf,default-logins,auth-bypass,cors,headers,misconfig",
             "medium,high,critical"),
    "stealth": ("cve,rce,lfi,sqli,ssti,ssrf,default-logins,auth-bypass,cors,headers,misconfig",
                "medium,high,critical"),
    "full": ("cve,rce,sqli,lfi,ssti,ssrf,xxe,nosqli,cmdi,idor,jwt,cors,headers,"
             "default-logins,auth-bypass,oauth,deserialization,misconfig,s3,error-page,"
             "info-disclosure,exposed-panels,owasp",
             "medium,high,critical"),
    "owasp": ("cve,rce,sqli,lfi,ssti,ssrf,xxe,idor,jwt,cors,headers,default-logins,"
              "auth-bypass,oauth,deserialization,misconfig,s3,error-page,info-disclosure,owasp",
              "low,medium,high,critical"),
}

# Port yang dianggap sensitif bila terbuka ke publik (severity medium).
_SENSITIVE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 445: "smb",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def default_run_tool(cmd, timeout=600, stdin=None):
    """Jalankan binari, kembalikan (returncode, stdout). Injectable untuk test."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           shell=False, input=stdin)
        return p.returncode, p.stdout or ""
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def _bin(tools, name, whicher=shutil.which):
    """Nama binari dari config (atau default), None bila tidak terpasang."""
    exe = (tools or {}).get(name, name)
    return exe if whicher(exe) else None


def _jsonl(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def _lines(text):
    return [l.strip() for l in (text or "").splitlines() if l.strip()]


def phase_osint(cfg, run_tool, whicher=shutil.which):
    """Enumerasi subdomain + resolve + probe HTTP. Non-intrusif.

    Mengembalikan (results, alive_urls)."""
    results = []
    target = cfg["target"]
    tools = cfg.get("tools", {})

    timeout = cfg.get("timeout", 600)

    # subdomain: subfinder + amass (keduanya pasif, hasil digabung)
    subs = {target}
    used = []
    sf = _bin(tools, "subfinder", whicher)
    if sf:
        _, out = run_tool([sf, "-silent", "-d", target], timeout)
        subs |= set(_lines(out))
        used.append("subfinder")
    am = _bin(tools, "amass", whicher)
    if am:
        _, out = run_tool([am, "enum", "-passive", "-silent", "-d", target], timeout)
        subs |= set(_lines(out))
        used.append("amass")
    subs = sorted(subs)
    if used:
        results.append({"check": f"subdomain enumeration ({len(subs)})", "ok": False,
                        "severity": "info", "kind": "recon-subdomain",
                        "note": f"[{'+'.join(used)}] " + ", ".join(subs[:20])
                                + (" ..." if len(subs) > 20 else ""),
                        "url": target})
    else:
        results.append({"check": "subdomain enumeration", "ok": True, "severity": "lulus",
                        "note": "skip: subfinder/amass tidak terpasang", "url": target})

    # httpx: probe alive + tech-detect atas semua subdomain.
    alive_urls = []
    hx = _bin(tools, "httpx", whicher)
    if hx:
        rc, out = run_tool([hx, "-silent", "-json", "-status-code", "-tech-detect",
                           "-title", "-no-color"], cfg.get("timeout", 600),
                          stdin="\n".join(subs))
        for obj in _jsonl(out):
            url = obj.get("url") or obj.get("input") or ""
            if not url:
                continue
            alive_urls.append(url)
            tech = obj.get("tech") or obj.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            server = obj.get("webserver") or ""
            note = f"HTTP {obj.get('status_code', '?')}"
            if server:
                note += f" · {server}"
            if tech:
                note += " · " + ", ".join(tech[:8])
            results.append({"check": f"host aktif {url}", "ok": False, "severity": "info",
                           "kind": "recon-subdomain", "note": note, "url": url})
    else:
        results.append({"check": "probe HTTP (httpx)", "ok": True, "severity": "lulus",
                        "note": "skip: httpx tidak terpasang"})
        # tanpa httpx, seed URL dari target agar fase lanjut tetap bisa jalan
        alive_urls = [cfg.get("base_url") or f"https://{target}"]

    # URL historis dari arsip: gau + waybackurls (pasif)
    hist, hused = set(), []
    gau = _bin(tools, "gau", whicher)
    if gau:
        _, out = run_tool([gau, target], timeout)
        hist |= set(_lines(out))
        hused.append("gau")
    wb = _bin(tools, "waybackurls", whicher)
    if wb:
        _, out = run_tool([wb], timeout, stdin=target)
        hist |= set(_lines(out))
        hused.append("waybackurls")
    if hused:
        hist = sorted(hist)
        results.append({"check": f"URL historis ({len(hist)})", "ok": False,
                        "severity": "info", "kind": "recon-subdomain",
                        "note": f"[{'+'.join(hused)}] {len(hist)} URL dari arsip; contoh: "
                                + ", ".join(hist[:5]), "url": target})
        # seed sebagian ke pool agar nuclei ikut memindai (dibatasi 50)
        alive_urls = list(dict.fromkeys(alive_urls + hist[:50]))

    return results, alive_urls


def phase_secrets(cfg, run_tool, whicher=shutil.which):
    """Scan rahasia (trufflehog) atas code_path lokal. Pasif; hanya bila code_path diset."""
    code = cfg.get("code_path")
    if not code:
        return []
    th = _bin(cfg.get("tools", {}), "trufflehog", whicher)
    if not th:
        return [{"check": "secret scan (trufflehog)", "ok": True, "severity": "lulus",
                 "note": "skip: trufflehog tidak terpasang", "url": code}]
    _, out = run_tool([th, "filesystem", code, "--json", "--no-update"],
                      cfg.get("timeout", 600))
    results = []
    for obj in _jsonl(out):
        det = obj.get("DetectorName") or "secret"
        verified = bool(obj.get("Verified"))
        where = ""
        try:
            where = (obj.get("SourceMetadata") or {}).get("Data", {}) \
                .get("Filesystem", {}).get("file", "")
        except AttributeError:
            where = ""
        results.append({"check": f"secret: {det}", "ok": False,
                        "severity": "high" if verified else "medium",
                        "kind": "leaked-secret",
                        "note": ("terverifikasi" if verified else "potensial")
                                + f" di {where or code}", "url": where or code})
    if not results:
        results.append({"check": "secret scan", "ok": True, "severity": "lulus",
                        "note": "Tidak ada secret terdeteksi trufflehog.", "url": code})
    return results


def phase_crawl(cfg, alive_urls, run_tool, whicher=shutil.which):
    """Crawl (katana) untuk memperluas daftar URL. AKTIF — gated."""
    target = cfg["target"]
    kt = _bin(cfg.get("tools", {}), "katana", whicher)
    if not kt:
        return [], [{"check": "crawl (katana)", "ok": True, "severity": "lulus",
                     "note": "skip: katana tidak terpasang", "url": target}]
    if not alive_urls:
        return [], []
    _, out = run_tool([kt, "-silent", "-jc", "-d", "2", "-u", ",".join(alive_urls[:20])],
                      cfg.get("timeout", 600))
    urls = _lines(out)
    res = []
    if urls:
        res.append({"check": f"crawl katana ({len(urls)})", "ok": False, "severity": "info",
                    "kind": "recon-subdomain",
                    "note": f"{len(urls)} URL ditemukan via crawl.", "url": target})
    return urls, res


def phase_fuzz(cfg, alive_urls, run_tool, whicher=shutil.which):
    """Content discovery (ffuf). AKTIF — gated. Butuh ffuf_wordlist."""
    target = cfg["target"]
    ff = _bin(cfg.get("tools", {}), "ffuf", whicher)
    wl = cfg.get("ffuf_wordlist")
    if not ff:
        return [{"check": "content discovery (ffuf)", "ok": True, "severity": "lulus",
                 "note": "skip: ffuf tidak terpasang", "url": target}]
    if not wl:
        return [{"check": "content discovery (ffuf)", "ok": True, "severity": "lulus",
                 "note": "skip: ffuf_wordlist tidak diset", "url": target}]
    base = (alive_urls[0] if alive_urls else cfg.get("base_url") or f"https://{target}")
    _, out = run_tool([ff, "-u", base.rstrip("/") + "/FUZZ", "-w", wl,
                      "-mc", "200,301,403", "-of", "json", "-o", "/dev/stdout", "-s"],
                      cfg.get("timeout", 600))
    res = []
    try:
        data = json.loads(out) if (out or "").strip() else {}
    except ValueError:
        data = {}
    for r in (data.get("results", []) if isinstance(data, dict) else []):
        st, url = r.get("status"), r.get("url", "")
        res.append({"check": f"path {url} ({st})", "ok": False,
                    "severity": "medium" if st in (200, 301) else "info",
                    "kind": "exposed-service",
                    "note": f"Path ditemukan ffuf, HTTP {st}.", "url": url})
    if not res:
        res.append({"check": "content discovery ffuf", "ok": True, "severity": "lulus",
                    "note": "Tidak ada path ditemukan.", "url": target})
    return res


def phase_ports(cfg, run_tool, whicher=shutil.which):
    """Port scan via naabu. AKTIF — hanya jalan bila di-gate aktif."""
    target = cfg["target"]
    tools = cfg.get("tools", {})
    nb = _bin(tools, "naabu", whicher)
    if not nb:
        return [{"check": "port scan (naabu)", "ok": True, "severity": "lulus",
                 "note": "skip: naabu tidak terpasang", "url": target}]
    args = [nb, "-silent", "-json", "-host", target]
    if (cfg.get("mode") == "stealth"):
        args += ["-rate", "100"]
    rc, out = run_tool(args, cfg.get("timeout", 600))
    results, open_any = [], False
    for obj in _jsonl(out):
        port = obj.get("port")
        if port is None:
            continue
        open_any = True
        svc = _SENSITIVE_PORTS.get(int(port))
        if svc:
            results.append({"check": f"port {port}/tcp terbuka ({svc})", "ok": False,
                           "severity": "medium", "kind": "exposed-service",
                           "note": f"Layanan {svc} terekspos ke publik pada {obj.get('host', target)}.",
                           "url": f"{obj.get('host', target)}:{port}"})
        else:
            results.append({"check": f"port {port}/tcp terbuka", "ok": False,
                           "severity": "info", "kind": "exposed-service",
                           "note": f"Port {port} terbuka pada {obj.get('host', target)}.",
                           "url": f"{obj.get('host', target)}:{port}"})
    if not open_any:
        results.append({"check": "port scan", "ok": True, "severity": "lulus",
                        "note": "Tidak ada port terbuka terdeteksi.", "url": target})
    return results


def phase_vuln(cfg, alive_urls, run_tool, whicher=shutil.which):
    """Vuln scan via nuclei. AKTIF — hanya jalan bila di-gate aktif."""
    tools = cfg.get("tools", {})
    nu = _bin(tools, "nuclei", whicher)
    target = cfg["target"]
    if not nu:
        return [{"check": "vuln scan (nuclei)", "ok": True, "severity": "lulus",
                 "note": "skip: nuclei tidak terpasang", "url": target}]
    if not alive_urls:
        return [{"check": "vuln scan (nuclei)", "ok": True, "severity": "lulus",
                 "note": "skip: tidak ada URL hidup untuk dipindai", "url": target}]
    mode = cfg.get("mode", "fast")
    tags, sev = _NUCLEI.get(mode, _NUCLEI["fast"])
    args = [nu, "-silent", "-no-color", "-jsonl", "-tags", tags, "-severity", sev]
    if mode == "stealth":
        args += ["-rate-limit", "15", "-bulk-size", "1",
                 "-header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
    args += ["-u", ",".join(alive_urls)]
    rc, out = run_tool(args, cfg.get("timeout", 1800))
    results = []
    worst = False
    for obj in _jsonl(out):
        info = obj.get("info", {}) or {}
        s = (info.get("severity") or "info").lower()
        if s not in ("info", "low", "medium", "high", "critical"):
            s = "info"
        if s in ("medium", "high", "critical"):
            worst = True
        tags_l = info.get("tags") or []
        cves = [t.upper() for t in tags_l if isinstance(t, str) and t.lower().startswith("cve-")]
        name = info.get("name") or obj.get("template-id") or "temuan nuclei"
        at = obj.get("matched-at") or obj.get("host") or ""
        results.append({"check": f"nuclei: {name}", "ok": False, "severity": s,
                       "kind": "recon-finding", "cve": cves,
                       "note": (info.get("description") or "").strip()[:300]
                               or f"Template {obj.get('template-id', '?')} cocok.",
                       "url": at})
    if not results:
        results.append({"check": "vuln scan nuclei", "ok": True, "severity": "lulus",
                        "note": "Tidak ada temuan nuclei pada severity yang dipindai.",
                        "url": target})
    elif not worst:
        results.append({"check": "severity vuln", "ok": True, "severity": "lulus",
                        "note": "Tidak ada temuan nuclei medium/high/critical.", "url": target})
    return results


def orchestrate(cfg, run_tool=default_run_tool, whicher=shutil.which):
    """Jalankan fase sesuai depth + gating aktif. Mengembalikan daftar results."""
    depth = cfg.get("depth", "infra")
    if depth not in DEPTHS:
        depth = "infra"
    active = cfg.get("active", {}) or {}
    active_on = bool(active.get("enabled"))

    results, alive = phase_osint(cfg, run_tool, whicher)
    results += phase_secrets(cfg, run_tool, whicher)   # pasif; hanya bila code_path diset

    if depth in ("infra", "full"):
        if active_on and active.get("naabu"):
            results += phase_ports(cfg, run_tool, whicher)
        else:
            results.append({"check": "port scan (naabu)", "ok": True, "severity": "lulus",
                            "note": "dilewati — fase aktif tidak diaktifkan "
                                    "(active.enabled & active.naabu).",
                            "url": cfg["target"]})

    if depth == "full":
        # crawl & fuzz (aktif, gated) memperluas URL sebelum nuclei
        if active_on and active.get("katana"):
            crawled, cres = phase_crawl(cfg, alive, run_tool, whicher)
            results += cres
            alive = list(dict.fromkeys(alive + crawled))
        if active_on and active.get("ffuf"):
            results += phase_fuzz(cfg, alive, run_tool, whicher)
        if active_on and active.get("nuclei"):
            results += phase_vuln(cfg, alive, run_tool, whicher)
        else:
            results.append({"check": "vuln scan (nuclei)", "ok": True, "severity": "lulus",
                            "note": "dilewati — fase aktif tidak diaktifkan "
                                    "(active.enabled & active.nuclei).",
                            "url": cfg["target"]})

    return results


def _failures(results):
    """Hitung temuan nyata (bukan info/lulus) sebagai penentu exit code."""
    return sum(1 for r in results
               if not r.get("ok", True) and (r.get("severity") or "info").lower()
               in ("low", "medium", "high", "critical"))


def load_config(path, overrides):
    if yaml is None:
        print("PyYAML tidak terpasang.", file=sys.stderr)
        raise SystemExit(2)
    cfg = {}
    if path and Path(path).exists():
        cfg = expand(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    # Tanpa file config pun tetap jalan bila target diberikan via CLI.
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    if not cfg.get("target"):
        bu = cfg.get("base_url", "")
        cfg["target"] = re.sub(r"^https?://", "", bu).split("/")[0] if bu else ""
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(description="Recon orchestrator (OSINT/infra/vuln).")
    ap.add_argument("--config", default=str(Path(__file__).with_name("recon.yml")))
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("target", nargs="?", help="domain/host (override config)")
    ap.add_argument("-d", "--depth", choices=DEPTHS)
    ap.add_argument("-m", "--mode", choices=MODES)
    ap.add_argument("--active", action="store_true",
                    help="aktifkan fase intrusif (naabu & nuclei) untuk run ini")
    args = ap.parse_args(argv)

    cfg = load_config(args.config, {"target": args.target, "depth": args.depth,
                                    "mode": args.mode})
    if args.active:
        act = cfg.setdefault("active", {})
        act["enabled"] = True
        act.setdefault("naabu", True)
        act.setdefault("nuclei", True)

    if not cfg.get("target"):
        print("target tidak diset (argumen, config.target, atau config.base_url).",
              file=sys.stderr)
        return 2

    results = orchestrate(cfg)
    failures = _failures(results)
    envelope = {"module": "recon", "failures": failures, "results": results}

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(envelope, indent=2, ensure_ascii=False),
                                       encoding="utf-8")

    for r in results:
        mark = "PASS" if r.get("ok", True) else (r.get("severity", "info").upper())
        print(f"[{mark}] {r.get('check')} — {r.get('note', '')}")
    print(f"\n{failures} temuan nyata, {len(results)} baris total.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
