#!/usr/bin/env python3
"""Detect web server version/stack and map it to known CVEs (non-destructive).

Only reads what the server announces (`Server`, `X-Powered-By`, `Alt-Svc` headers as an
HTTP/2|HTTP/3 hint, and HTTP/2 support via ALPN); no exploit payloads are sent. Two finding types:

  1. Version disclosure: the server leaks its version in a banner (eases fingerprinting).
  2. Known-vulnerable version: the banner version matches the `known_vulnerable` list
     (e.g. Apache mod_http2 CVE-2026-119618, NGINX HTTP/2 CVE-2026-123633). Medium
     confidence: banner-based, so confirm against the vendor advisory before pinning.

RCE/DoS CVEs like these are NOT actively tested because they have no safe reverse;
passive detection is the right approach.

Usage: python run_webstack.py --config webstack.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from urllib.parse import urlparse

import requests
import yaml
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _color as C  # noqa: E402  (shared ANSI console colors)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
# Product name + version in a banner, e.g. "Apache/2.4.70", "nginx/1.30.6".
BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*)/(\d+(?:\.\d+){1,3})")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def ver_tuple(s):
    """'2.4.70' -> (2,4,70); parsing stops at the first non-numeric part."""
    out = []
    for part in str(s).split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


def less_than(a, b):
    """Return a < b, padding the version tuples to equal length."""
    ta, tb = ver_tuple(a), ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


def parse_banner(value):
    """Return the first (lowercase name, version) from a banner header, else (lowercase text, '')."""
    if not value:
        return "", ""
    m = BANNER_RE.search(value)
    if m:
        return m.group(1).lower(), m.group(2)
    return value.strip().lower(), ""


def supports_http2(url):
    """Best-effort ALPN h2 negotiation over TLS (https only); returns True/False/None."""
    u = urlparse(url)
    if u.scheme != "https":
        return None
    host = u.hostname
    port = u.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:  # pragma: no cover
        return None
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.selected_alpn_protocol() == "h2"
    except Exception:  # noqa: BLE001
        return None


def check_target(sess, url, known, http2_probe=supports_http2):
    """Return the result rows for one target URL."""
    out = []
    try:
        r = sess.get(url, timeout=20, allow_redirects=True)
    except Exception as exc:  # noqa: BLE001
        return [{"check": f"webstack {url}", "status": -1, "ok": True,
                 "note": f"skip: {exc}", "url": f"GET {url}"}]

    server = r.headers.get("Server", "") or ""
    powered = r.headers.get("X-Powered-By", "") or ""
    altsvc = r.headers.get("Alt-Svc", "") or ""
    name, ver = parse_banner(server)

    # 1. Version disclosure.
    leak = []
    if ver:
        leak.append(f"Server: {server}")
    if powered:
        leak.append(f"X-Powered-By: {powered}")
    out.append({
        "check": f"Version disclosure {urlparse(url).netloc}",
        "status": r.status_code, "ok": not leak,
        "note": "" if not leak else "banner expose versi: " + "; ".join(leak),
        "url": f"GET {url}",
    })

    # 2. Known-vulnerable version: check the Server AND X-Powered-By banners against a
    #    min_version-max_version range (supports multi-branch backports, e.g. PHP2Shell).
    h2 = http2_probe(url)
    if altsvc and "h2" in altsvc.lower() and h2 is None:
        h2 = True
    candidates = []
    if name:
        candidates.append(("Server", name, ver))
    pname, pver = parse_banner(powered)
    if pname:
        candidates.append(("X-Powered-By", pname, pver))
    flagged = set()
    for kv in known:
        kname = str(kv.get("server", "")).lower()
        if not kname:
            continue
        for src, cname, cver in candidates:
            if kname not in cname or not cver:
                continue
            mn, mx = kv.get("min_version"), kv.get("max_version")
            if mn and less_than(cver, mn):
                continue                   # below the vulnerable range
            if mx and not less_than(cver, mx):
                continue                   # already at the fixed version
            key = kv.get("cve") or kname
            if key in flagged:
                continue
            flagged.add(key)
            h2note = " HTTP/2 aktif (ALPN h2)." if h2 else ""
            rng = f"{mn}–<{mx}" if mn else (f"< {mx}" if mx else "(semua versi)")
            out.append({
                "check": f"Versi rentan: {cname} {cver}",
                "status": r.status_code, "ok": False,
                "note": (f"{cname}/{cver} ({src}) dalam rentang rentan {rng} — "
                         f"{kv.get('cve', '?')}. {kv.get('note') or kv.get('catatan', '')}.{h2note} "
                         "Konfirmasi ke advisory vendor."),
                "url": f"GET {url}",
                "cve": [kv["cve"]] if kv.get("cve") else [],
            })
            break                          # one finding per known_vulnerable entry
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="webstack.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    targets = [cfg["base_url"].rstrip("/")] + [t.rstrip("/") for t in cfg.get("extra_targets", [])]
    known = cfg.get("known_vulnerable", [])
    sess = requests.Session()
    a = cfg.get("auth") or {}
    if a.get("header") and a.get("value"):
        sess.headers[a["header"]] = a["value"]
    sess.headers.setdefault("User-Agent", "security-audit-kit")

    results = []
    print(f"{'PEMERIKSAAN':<44} {'HTTP':>5}  HASIL")
    print("-" * 78)
    for url in dict.fromkeys(targets):
        for row in check_target(sess, url, known):
            results.append(row)
            mark = f"{C.good('ok')} " if row["ok"] else f"{C.bad('XX')} "
            print(f"{row['check'][:44]:<44} {str(row['status']):>5}  {mark}{row['note']}")

    failures = sum(1 for r in results if not r["ok"])
    print(f"\n{failures} temuan.")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "webstack", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
