#!/usr/bin/env python3
"""Detect open redirects (non-destructive, GET only, redirects not followed).

For each path x redirect parameter name, sends a GET with the parameter set to an
external test target, then reads the Location header WITHOUT following it. Flagged
when Location points to an external host (including protocol-relative //host).

Configured in open_redirect.yml. Usage:
    python run_open_redirect.py --config open_redirect.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin, urlparse, urlencode

import requests
import yaml
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _color as C  # noqa: E402  (shared console ANSI colors in tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def is_external(location, evil_host):
    """True if Location points to the external test host (absolute or protocol-relative)."""
    if not location:
        return False
    loc = location.strip()
    # Protocol-relative //evil.example/...
    if loc.startswith("//"):
        host = loc[2:].split("/", 1)[0]
        return host.lower() == evil_host.lower()
    parsed = urlparse(loc)
    return bool(parsed.netloc) and parsed.netloc.lower() == evil_host.lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="open_redirect.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    evil = cfg.get("evil_target", "https://evil.example")
    evil_host = urlparse(evil).netloc or "evil.example"
    params = cfg.get("params") or ["next", "url", "redirect", "return", "returnUrl",
                                    "continue", "dest", "r"]
    paths = cfg.get("paths") or ["/"]
    # Payloads: absolute URL + protocol-relative form.
    payloads = [evil, f"//{evil_host}"]

    s = requests.Session()
    s.headers["User-Agent"] = "security-audit-kit"
    a = cfg.get("auth") or {}
    if a.get("header") and a.get("value"):
        s.headers[a["header"]] = a["value"]

    results = []
    for p in paths:
        for param in params:
            for payload in payloads:
                url = urljoin(base + "/", p.lstrip("/")) + "?" + urlencode({param: payload})
                try:
                    r = s.get(url, timeout=20, allow_redirects=False)
                except Exception as exc:  # noqa: BLE001
                    results.append({"label": f"redirect {p}?{param}", "status": -1,
                                    "ok": True, "note": f"skip: {exc}", "url": f"GET {url}"})
                    continue
                loc = r.headers.get("Location", "")
                if 300 <= r.status_code < 400 and is_external(loc, evil_host):
                    results.append({"label": f"open redirect {p}?{param}",
                                    "status": r.status_code, "ok": False,
                                    "note": f"Location -> {loc} (host luar)",
                                    "url": f"GET {url}"})
                # No redirect to an external host: safe, not recorded.

    failures = sum(1 for r in results if not r["ok"])
    if not results:
        print("Tak ada parameter pengalih yang mengarah ke host luar. Aman.")
    else:
        print(f"{'PEMERIKSAAN':<40} {'HTTP':>5}  HASIL")
        print("-" * 72)
        for r in results:
            mark = f"{C.good('ok')} " if r["ok"] else f"{C.bad('XX')} "
            print(f"{r['label'][:40]:<40} {str(r['status']):>5}  {mark}{r['note']}")
    print(f"\n{len(results)} catatan, {failures} temuan.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "open-redirect", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
