#!/usr/bin/env python3
"""Audit cookie security attributes (passive, non-destructive).

Collects Set-Cookie headers from several requests (landing page, Sanctum CSRF
endpoint, and login if configured), then checks each cookie:
  - HttpOnly  : session/auth cookies must not be readable by JavaScript
                (except those the SPA must read, e.g. XSRF-TOKEN).
  - Secure    : cookie sent over HTTPS only (applies only to HTTPS targets).
  - SameSite  : Lax/Strict (None must be paired with Secure); CSRF mitigation.
  - Session cookie lifetime is not excessive (default <= 30 days).

Configured in cookie_flags.yml. Usage:
    python run_cookie_flags.py --config cookie_flags.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _sanctum  # noqa: E402
import _color as C  # noqa: E402  (shared console ANSI colors in tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
SENSITIVE_RE = re.compile(r"(sess|sid|token|auth|jwt|login|remember)", re.I)


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def parse_set_cookie(header):
    """Parse one Set-Cookie header into {name, value, attrs{lowercase: str|True}}."""
    parts = [p.strip() for p in (header or "").split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, eq, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if eq else True
    return {"name": name.strip(), "value": value, "attrs": attrs}


def set_cookie_headers(resp):
    """All Set-Cookie headers of a response (requests merges them in .headers)."""
    try:
        raw = resp.raw.headers
        if hasattr(raw, "getlist"):
            got = raw.getlist("Set-Cookie")
            if got:
                return list(got)
    except Exception:  # noqa: BLE001
        pass
    one = resp.headers.get("Set-Cookie")
    return [one] if one else []


def _lifetime_days(attrs, now=None):
    """Cookie lifetime in days (None for a session cookie or unknown)."""
    now = now or datetime.now(timezone.utc)
    ma = attrs.get("max-age")
    if isinstance(ma, str) and re.fullmatch(r"-?\d+", ma):
        return int(ma) / 86400.0
    ex = attrs.get("expires")
    if isinstance(ex, str):
        try:
            dt = parsedate_to_datetime(ex)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (dt - now).total_seconds() / 86400.0
        except Exception:  # noqa: BLE001
            return None
    return None


def evaluate(cookie, origin_url, cfg, where="", status=None, now=None):
    """Check one cookie. Returns result rows (ok=True means pass)."""
    name, attrs = cookie["name"], cookie["attrs"]
    exempt = {n.lower() for n in cfg.get("httponly_exempt", ["XSRF-TOKEN"])}
    sensitive = bool(SENSITIVE_RE.search(name)) and name.lower() not in exempt
    is_https = origin_url.lower().startswith("https://")
    require_secure = cfg.get("require_secure")
    if require_secure is None:
        require_secure = is_https
    max_days = float(cfg.get("max_session_days", 30))
    url = f"GET {origin_url}{where}"
    rows = []

    def row(flag, ok, note):
        rows.append({"check": f"cookie {name}: {flag}", "status": status, "ok": ok,
                     "note": note, "url": url})

    # HttpOnly
    if name.lower() in exempt:
        row("HttpOnly", True, "dikecualikan (cookie ini memang dibaca JavaScript SPA)")
    elif "httponly" in attrs:
        row("HttpOnly", True, "HttpOnly aktif")
    else:
        row("HttpOnly", False, "atribut HttpOnly tidak ada — cookie terbaca JavaScript "
            "(dampak XSS: pencurian session)" + ("" if sensitive else " [cookie non-sesi]"))

    # Secure
    if "secure" in attrs:
        row("Secure", True, "Secure aktif")
    elif not require_secure:
        row("Secure", True, "skip: target HTTP — atribut Secure baru bermakna di HTTPS "
            "(periksa kembali di staging/produksi)")
    else:
        row("Secure", False, "atribut Secure tidak ada — cookie dapat terkirim lewat HTTP")

    # SameSite
    ss = attrs.get("samesite")
    ssv = str(ss).lower() if isinstance(ss, str) else ""
    if ssv in ("lax", "strict"):
        row("SameSite", True, f"SameSite={ss}")
    elif ssv == "none":
        if "secure" in attrs:
            row("SameSite", True, "SameSite=None dengan Secure (cross-site disengaja)")
        else:
            row("SameSite", False, "SameSite=None tanpa Secure — ditolak browser modern")
    else:
        row("SameSite", False, "SameSite tidak diset eksplisit — bergantung default browser "
            "(mitigasi CSRF tidak terjamin)")

    # Session cookie lifetime
    if sensitive:
        days = _lifetime_days(attrs, now)
        if days is None:
            row("masa berlaku", True, "cookie session (hilang saat browser ditutup)")
        elif days <= max_days:
            row("masa berlaku", True, f"{days:.1f} hari (batas {max_days:g})")
        else:
            row("masa berlaku", False, f"{days:.0f} hari melebihi batas {max_days:g} hari "
                "untuk cookie session/autentikasi")
    return rows


def evaluate_all(cookies_seen, origin_url, cfg):
    """cookies_seen: list of (cookie, where, status). Deduplicated by cookie name (first seen wins)."""
    seen, rows = set(), []
    for cookie, where, status in cookies_seen:
        if cookie["name"] in seen:
            continue
        seen.add(cookie["name"])
        rows.extend(evaluate(cookie, origin_url, cfg, where, status))
    return rows


def collect(cfg, sess=None):
    """Collect cookies from the probe requests. Returns (cookies_seen, notes)."""
    base = cfg["base_url"].rstrip("/")
    s = sess or requests.Session()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        s.verify = False
    seen, notes = [], []

    def grab(resp, where):
        for h in set_cookie_headers(resp):
            c = parse_set_cookie(h)
            if c:
                seen.append((c, where, resp.status_code))

    # 1) probe pages/paths (GET)
    for path in cfg.get("probe_paths", ["/"]):
        try:
            grab(s.get(base + path, timeout=20, allow_redirects=False), path)
        except Exception as exc:  # noqa: BLE001
            notes.append({"check": f"probe {path}", "status": -1, "ok": True,
                          "note": f"skip: {exc}", "url": f"GET {base}{path}"})

    # 2) Optional Sanctum + login: the session cookie is issued on authentication.
    auth = cfg.get("auth") or {}
    san = auth.get("sanctum") if (auth.get("sanctum") or {}).get("enabled") else None
    login = auth.get("login")
    if san:
        try:
            origin = san.get("origin")
            csrf_path = san.get("csrf_path", "/sanctum/csrf-cookie")
            r = s.get(base + csrf_path, headers=_sanctum.stateful_headers(origin), timeout=20)
            grab(r, csrf_path)
            if login:
                r = s.request(login.get("method", "POST"), base + login["path"],
                              json=login.get("body") or {},
                              headers=_sanctum.auth_headers(s, origin), timeout=20)
                grab(r, login["path"])
                if r.status_code >= 400:
                    notes.append({"check": "login untuk cookie session", "status": r.status_code,
                                  "ok": True, "note": f"skip: login gagal HTTP {r.status_code}",
                                  "url": f"{login.get('method', 'POST')} {base}{login['path']}"})
        except Exception as exc:  # noqa: BLE001
            notes.append({"check": "sanctum/login", "status": -1, "ok": True,
                          "note": f"skip: {exc}", "url": base})
    return seen, notes


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit atribut keamanan cookie (pasif).")
    ap.add_argument("--config", default=str(Path(__file__).with_name("cookie_flags.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url"):
        print("base_url wajib diisi di config.", file=sys.stderr)
        return 2

    seen, notes = collect(cfg)
    results = evaluate_all(seen, cfg["base_url"].rstrip("/"), cfg) + notes
    if not seen:
        results.append({"check": "cookie ditemukan", "status": None, "ok": True,
                        "note": "Tidak ada header Set-Cookie pada request pantau.",
                        "url": cfg["base_url"]})
    failures = sum(1 for r in results if not r["ok"])

    for r in results:
        print(f"[{C.tag('PASS' if r['ok'] else 'FAIL')}] {r['check']} — {r['note']}")
    print(f"\n{len(results)} cek, {failures} temuan.")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps({"module": "cookie-flags", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
