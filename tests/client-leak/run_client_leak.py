#!/usr/bin/env python3
"""Deteksi kebocoran sisi klien: cache respons sensitif & rahasia di bundle JS.

Dua pemeriksaan (non-destruktif, hanya GET):

A. Cache respons sensitif — respons terautentikasi HARUS melarang cache
   (Cache-Control: no-store/private). Bila cacheable → temuan 'client-cache'.

B. Kebocoran di JavaScript klien — unduh aset JS (dari konfigurasi atau hasil
   parsing <script src> pada halaman), lalu sisir:
     - rahasia (API key/token/JWT yang ter-hardcode),
     - endpoint internal/admin,
     - source map (.map) yang dapat diakses publik.
   (Ini pola yang dipakai penguji BSSN: membaca JS untuk menemukan endpoint admin.)

Opsional (browser_cache.enabled): konfirmasi lewat Chromium sungguhan (Playwright)
bahwa respons sensitif memang tersimpan di cache browser, bukan cuma dari header.

Konfigurasi di client_leak.yml. Pakai:
    python run_client_leak.py --config client_leak.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse

import requests
import yaml

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


# Pola rahasia yang umum ter-hardcode. Sengaja konservatif agar sedikit false positive.
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Generic secret assignment",
     re.compile(r"""(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['"][^'"]{8,}['"]""")),
]
SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_SENSITIVE_RE = re.compile(
    r"(?i)\b(todo|fixme|password|passwd|secret|api[_-]?key|token|debug|hardcode|"
    r"backdoor|internal|do not|jangan|sandi|rahasia)\b")

# File/path sensitif yang umum ter-ekspos — tak butuh JS, berlaku lintas-stack.
DEFAULT_SENSITIVE_FILES = [
    ".env", ".env.local", ".env.backup", ".git/config", ".git/HEAD",
    ".svn/entries", "composer.json", "package.json", "docker-compose.yml",
    "backup.zip", "backup.sql", "dump.sql", "database.sql", "web.config",
    "phpinfo.php", ".DS_Store", "server-status", "actuator/env",
]


def session_with_auth(cfg):
    s = requests.Session()
    a = cfg.get("auth") or {}
    if a.get("header") and a.get("value"):
        s.headers[a["header"]] = a["value"]
    s.headers.setdefault("User-Agent", "security-audit-kit")
    return s


def check_cache(s, base, paths):
    out = []
    for p in paths:
        url = urljoin(base + "/", p.lstrip("/"))
        try:
            r = s.get(url, timeout=20, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            # Tak terjangkau/timeout = tak bisa diuji, bukan temuan keamanan.
            out.append({"kind": "cache", "label": f"cache {p}", "status": -1,
                        "ok": True, "note": f"skip: {exc}"})
            continue
        cc = (r.headers.get("Cache-Control", "") or "").lower()
        # Aman bila melarang penyimpanan.
        safe = ("no-store" in cc) or ("private" in cc and "no-cache" in cc)
        cacheable_public = ("public" in cc) or (cc == "")
        ok = safe and not cacheable_public
        note = "" if ok else f"Cache-Control: '{r.headers.get('Cache-Control','(kosong)')}'"
        out.append({"kind": "cache", "label": f"cache respons {p}", "status": r.status_code,
                    "ok": ok, "note": note})
    return out


# Dijalankan di dalam halaman: fetch biasa (mengisi cache), lalu fetch ulang dengan
# cache 'only-if-cached' — hanya berhasil bila respons benar-benar tersimpan di
# cache HTTP browser (disk/memori), terlepas dari kedaluwarsa.
BROWSER_PROBE_JS = """async (u) => {
  let status = -1, cc = "";
  try {
    const r = await fetch(u, {credentials: "include"});
    status = r.status; cc = r.headers.get("cache-control") || "";
    await r.arrayBuffer();
  } catch (e) { return {status: -1, cc: "", cached: false, err: String(e)}; }
  try {
    await fetch(u, {cache: "only-if-cached", mode: "same-origin", credentials: "include"});
    return {status, cc, cached: true, err: ""};
  } catch (e) { return {status, cc, cached: false, err: ""}; }
}"""


def check_browser_cache(cfg, base, paths):
    """Konfirmasi via browser sungguhan (Playwright/Chromium) bahwa respons sensitif
    benar-benar tersimpan di cache browser — cek header saja belum membuktikannya.

    Opsional: butuh `pip install playwright` + `python -m playwright install chromium`.
    Bila tak terpasang/tak bisa jalan, hasilnya 'skip', bukan temuan.
    """
    def skip(note):
        return [{"kind": "browser-cache", "label": "cache browser (Playwright)",
                 "status": -1, "ok": True, "note": f"skip: {note}"}]

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return skip("playwright tak terpasang (pip install playwright && "
                    "python -m playwright install chromium)")

    bc = cfg.get("browser_cache") or {}
    a = cfg.get("auth") or {}
    headers = {a["header"]: a["value"]} if a.get("header") and a.get("value") else {}
    start = urljoin(base + "/", (bc.get("start_path") or "/").lstrip("/"))
    origin = "{0.scheme}://{0.netloc}".format(urlparse(start))
    out = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                # Jangan pasang page.route(): di Playwright, routing menonaktifkan cache HTTP.
                ctx = browser.new_context(
                    extra_http_headers=headers or None,
                    ignore_https_errors=os.environ.get("SAK_INSECURE_TLS") == "1")
                page = ctx.new_page()
                page.goto(start, timeout=30000)
                landed = "{0.scheme}://{0.netloc}".format(urlparse(page.url))
                if landed != origin:
                    return skip(f"{start} dialihkan ke {page.url} — set "
                                "browser_cache.start_path ke halaman se-origin")
                for p in paths:
                    url = urljoin(base + "/", p.lstrip("/"))
                    if "{0.scheme}://{0.netloc}".format(urlparse(url)) != origin:
                        out.append({"kind": "browser-cache", "label": f"cache browser {p}",
                                    "status": -1, "ok": True,
                                    "note": "skip: beda origin dengan start_path"})
                        continue
                    r = page.evaluate(BROWSER_PROBE_JS, url)
                    if r["status"] == -1:
                        out.append({"kind": "browser-cache", "label": f"cache browser {p}",
                                    "status": -1, "ok": True, "note": f"skip: {r['err']}"})
                        continue
                    cc = r["cc"] or "(kosong)"
                    out.append({"kind": "browser-cache", "label": f"cache browser {p}",
                                "status": r["status"], "ok": not r["cached"],
                                "note": (f"tersimpan di cache browser (Chromium, fetch "
                                         f"only-if-cached berhasil); Cache-Control: '{cc}'")
                                        if r["cached"] else ""})
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001
        # Chromium belum di-install, target tak terjangkau, dsb. — tak bisa diuji.
        return skip(str(exc).splitlines()[0][:200])
    return out


def discover_js(s, base):
    """Ambil <script src=...> dari halaman utama."""
    try:
        r = s.get(base, timeout=20)
    except Exception:  # noqa: BLE001
        return []
    srcs = re.findall(r"""<script[^>]+src=['"]([^'"]+)['"]""", r.text, re.I)
    urls = []
    for src in srcs:
        if src.endswith(".js") or ".js?" in src:
            urls.append(urljoin(base + "/", src))
    return urls


def check_js(s, base, js_urls, internal_hints):
    out = []
    for url in js_urls:
        try:
            r = s.get(url, timeout=30)
            body = r.text
        except Exception as exc:  # noqa: BLE001
            out.append({"kind": "js", "label": f"ambil {url}", "status": -1,
                        "ok": False, "note": f"galat: {exc}"})
            continue
        name = urlparse(url).path.rsplit("/", 1)[-1]

        # Rahasia.
        for label, pat in SECRET_PATTERNS:
            if pat.search(body):
                out.append({"kind": "js", "label": f"Rahasia di {name}: {label}",
                            "status": r.status_code, "ok": False,
                            "note": "pola rahasia ditemukan dalam bundle JS — verifikasi"})

        # Endpoint internal/admin (dari petunjuk konfigurasi).
        for hint in internal_hints:
            if hint and hint in body:
                out.append({"kind": "js", "label": f"Endpoint '{hint}' tersingkap di {name}",
                            "status": r.status_code, "ok": False,
                            "note": "endpoint internal/admin tertera di JS klien"})

        # Source map.
        m = SOURCEMAP_RE.search(body)
        if m:
            map_url = urljoin(url, m.group(1).strip())
            accessible = False
            if map_url.startswith("http"):
                try:
                    accessible = s.get(map_url, timeout=20).status_code == 200
                except Exception:  # noqa: BLE001
                    accessible = False
            out.append({"kind": "js",
                        "label": f"Source map di {name}",
                        "status": r.status_code, "ok": not accessible,
                        "note": f"{map_url} dapat diakses publik" if accessible
                                else f"referensi {m.group(1)} (map tak terakses)"})
    return out


def check_html(s, base, paths, internal_hints):
    """Sisir HALAMAN HTML (untuk app tanpa JS): komentar, rahasia inline, endpoint."""
    out = []
    pages = [base] + [urljoin(base + "/", p.lstrip("/")) for p in paths]
    for url in dict.fromkeys(pages):
        try:
            r = s.get(url, timeout=20)
            ctype = r.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue
            body = r.text
        except Exception:  # noqa: BLE001
            continue
        name = urlparse(url).path or "/"
        # Komentar HTML yang mencurigakan.
        for c in HTML_COMMENT_RE.findall(body):
            if COMMENT_SENSITIVE_RE.search(c):
                snippet = " ".join(c.split())[:80]
                out.append({"kind": "html", "label": f"Komentar HTML sensitif di {name}",
                            "status": r.status_code, "ok": False,
                            "note": f"'{snippet}' — tinjau sebelum rilis"})
                break
        # Rahasia inline (mis. config di <script>window.__CONFIG__=...).
        for label, pat in SECRET_PATTERNS:
            if pat.search(body):
                out.append({"kind": "html", "label": f"Rahasia inline di {name}: {label}",
                            "status": r.status_code, "ok": False,
                            "note": "pola rahasia di HTML — verifikasi"})
        # Endpoint internal tertera di HTML.
        for hint in internal_hints:
            if hint and hint in body:
                out.append({"kind": "html", "label": f"Endpoint '{hint}' tersingkap di {name}",
                            "status": r.status_code, "ok": False,
                            "note": "endpoint internal/admin tertera di HTML"})
    return out


def check_files(s, base, files):
    """Probe file sensitif yang umum ter-ekspos (hanya GET)."""
    out = []
    for rel in files:
        url = urljoin(base + "/", rel.lstrip("/"))
        try:
            r = s.get(url, timeout=15, allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        # Terekspos bila 200 dan bukan halaman HTML error/SPA fallback.
        exposed = (r.status_code == 200 and r.content
                   and "html" not in r.headers.get("Content-Type", "").lower())
        if exposed:
            out.append({"kind": "file", "label": f"File terekspos: {rel}",
                        "status": r.status_code, "ok": False,
                        "note": f"{len(r.content)} byte dapat diunduh publik"})
        else:
            out.append({"kind": "file", "label": f"File {rel}",
                        "status": r.status_code, "ok": True, "note": ""})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="client_leak.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    s = session_with_auth(cfg)

    results = []
    results += check_cache(s, base, cfg.get("sensitive_paths", []))
    if (cfg.get("browser_cache") or {}).get("enabled"):
        results += check_browser_cache(cfg, base, cfg.get("sensitive_paths", []))

    js_urls = list(cfg.get("js_assets", []))
    if cfg.get("auto_discover_js", True):
        js_urls += discover_js(s, base)
    js_urls = [urljoin(base + "/", u) if not u.startswith("http") else u
               for u in dict.fromkeys(js_urls)]  # unik, pertahankan urutan
    hints = cfg.get("internal_endpoints", [])
    results += check_js(s, base, js_urls, hints)

    # Jalur non-JS: sisir HTML + probe file sensitif.
    if cfg.get("scan_html", True):
        results += check_html(s, base, cfg.get("sensitive_paths", []), hints)
    if cfg.get("probe_sensitive_files", True):
        files = cfg.get("sensitive_files") or DEFAULT_SENSITIVE_FILES
        results += check_files(s, base, files)

    failures = sum(1 for r in results if not r["ok"])
    print(f"{'PEMERIKSAAN':<52} {'HTTP':>5}  HASIL")
    print("-" * 80)
    for r in results:
        mark = "ok " if r["ok"] else "XX "
        print(f"{r['label'][:52]:<52} {str(r['status']):>5}  {mark}{r['note']}")
    print(f"\n{len(results)} cek, {failures} temuan.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "client-leak", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
