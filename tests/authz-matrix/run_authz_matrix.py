#!/usr/bin/env python3
"""Role-based access control regression test.

Reads authz_matrix.yml, logs in as each role, hits each endpoint, and compares the
actual status with the expectation (allow/deny). Exits non-zero on any mismatch, so
it can gate CI.

Defensive: mainly checks that what SHOULD BE DENIED is denied. Nothing is exploited;
it only sends plain requests and reads status codes.

Usage:
    python run_authz_matrix.py --config authz_matrix.yml [--json hasil.json]
"""
from __future__ import annotations

import time
import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _sanctum  # noqa: E402  (shared Sanctum auth helper in tests/)
import _screenshot  # noqa: E402  (shared evidence screenshot helper in tests/)
import _color as C  # noqa: E402  (shared console ANSI colors in tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(value):
    """Replace ${VAR} with the environment variable, recursing into dicts/lists."""
    if isinstance(value, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def dig(obj, dotted):
    """Get a nested value via 'a.b.c'."""
    for part in dotted.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


class Session:
    """Credentials for one role: cookies (incl. Sanctum session) or a bearer token."""

    def __init__(self, role, auth_cfg, base_url, sanctum=None):
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.sess = requests.Session()
        self.bearer = None
        self.anonymous = bool(auth_cfg.get("anonymous"))
        # Optional 'sanctum' block for session_cookie mode: {enabled, origin, csrf_path}.
        self.sanctum = sanctum if (sanctum and sanctum.get("enabled")) else None

    def _sanctum_headers(self):
        return _sanctum.auth_headers(self.sess, self.sanctum.get("origin")) if self.sanctum else {}

    def login(self, login_cfg, creds, mode):
        if self.anonymous:
            return
        # Static token (bearer mode): the role carries a ready-made `token`, so no login request is
        # sent. Useful when the login endpoint is rate limited and many roles are under test.
        if mode == "bearer" and creds.get("token"):
            self.bearer = creds["token"]
            return
        # Sanctum SPA: fetch the CSRF + session cookies first, send a stateful Origin.
        if self.sanctum:
            _sanctum.prime_csrf(self.sess, self.base_url, self.sanctum)
        body = {}
        for k, v in (login_cfg.get("body") or {}).items():
            v = v.replace("{username}", creds.get("username", ""))
            v = v.replace("{password}", creds.get("password", ""))
            body[k] = v
        url = self.base_url + login_cfg["path"]
        resp = self.sess.request(login_cfg.get("method", "POST"), url, json=body,
                                 headers=self._sanctum_headers(), timeout=20)
        # Login rate limit (HTTP 429): wait for Retry-After and try again instead of failing the whole
        # run. `retry_429: false` disables it; `retry_429_max_wait` (seconds, default 1200) caps one wait.
        retries = 0
        while resp.status_code == 429 and login_cfg.get("retry_429", True) and retries < 3:
            try:
                wait = int(resp.headers.get("Retry-After", "60"))
            except ValueError:
                wait = 60
            wait = min(wait, int(login_cfg.get("retry_429_max_wait", 1200))) + 2
            print(f"  login '{self.role}': HTTP 429, menunggu {wait} detik (Retry-After)", flush=True)
            time.sleep(wait)
            retries += 1
            resp = self.sess.request(login_cfg.get("method", "POST"), url, json=body,
                                     headers=self._sanctum_headers(), timeout=20)
        if resp.status_code >= 400:
            raise RuntimeError(f"login role '{self.role}' gagal: HTTP {resp.status_code}")
        if mode == "bearer":
            field = login_cfg.get("token_field", "token")
            token = dig(resp.json(), field)
            if not token:
                raise RuntimeError(f"token tak ditemukan di '{field}' untuk role '{self.role}'")
            self.bearer = token

    def request(self, method, path, body=None, extra_headers=None, base_url=None):
        # Stateful + X-XSRF-TOKEN headers first; test headers (e.g. forged X-Auth-*)
        # override them on conflict so the forged-header test is sent as-is.
        headers = self._sanctum_headers()
        headers.update(extra_headers or {})
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        # Per-endpoint base_url, e.g. the service port directly to test gateway bypass.
        url = (base_url or self.base_url).rstrip("/") + path
        resp = self.sess.request(method, url, json=body, headers=headers, timeout=20, allow_redirects=False)
        # HTTP 429 is the rate limiter, not an access control verdict: wait for Retry-After and try again
        # (at most 3 times, 120 s each) so a busy limiter does not turn into false findings.
        retries = 0
        while resp.status_code == 429 and retries < 3:
            try:
                wait = min(int(resp.headers.get("Retry-After", "30")), 120) + 1
            except (ValueError, AttributeError):
                wait = 31
            time.sleep(wait)
            retries += 1
            resp = self.sess.request(method, url, json=body, headers=headers, timeout=20, allow_redirects=False)
        return resp


def forged_blocks(fh):
    """Normalize 'forged_headers' into a list of active blocks.

    A single dict (legacy format) is active only with enabled: true; each list
    item is active unless it sets enabled: false.
    """
    if isinstance(fh, list):
        return [b for b in fh if b.get("enabled", True) and b.get("as_role")]
    fh = fh or {}
    return [fh] if fh.get("enabled") and fh.get("as_role") else []


def classify(expected, status):
    """Return (ok, note) for one expectation vs the actual status."""
    allow_ok = 200 <= status < 400
    deny_ok = status in (401, 403)
    if expected == "allow":
        return allow_ok, "" if allow_ok else "diharapkan lolos tapi ditolak/error"
    if expected == "deny":
        if deny_ok:
            return True, ""
        if status == 404:
            return False, "404 — mungkin disembunyikan, konfirmasi bukan information disclosure"
        if allow_ok:
            return False, "DITOLAK GAGAL — endpoint sensitif bisa diakses role ini"
        return False, f"status tak terduga {status}"
    return False, f"harapan tak dikenal '{expected}'"


def _evidence_shot(shot_cfg, reports_dir, sess_obj, method, full_url, extra_headers, tag):
    """Capture a screenshot of a page that got through (gated, fails gracefully). Returns path or ''."""
    if not (shot_cfg.get("enabled") and reports_dir and (method or "GET").upper() == "GET"):
        return ""
    headers = dict(extra_headers or {})
    if getattr(sess_obj, "bearer", None):
        headers.setdefault("Authorization", f"Bearer {sess_obj.bearer}")
    cookies = _screenshot.cookies_from_requests(getattr(sess_obj, "sess", None), full_url) \
        if getattr(sess_obj, "sess", None) else []
    return _screenshot.capture_url(full_url, reports_dir, tag, prefix="authz",
                                   headers=headers, cookies=cookies,
                                   full_page=bool(shot_cfg.get("full_page")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="authz_matrix.yml")
    ap.add_argument("--json", help="tulis hasil ke file JSON")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base_url = cfg["base_url"]
    auth = cfg["auth"]
    mode = auth.get("mode", "bearer")
    sanctum = auth.get("sanctum")  # optional; used in session_cookie mode
    # Optional screenshot evidence (off by default): capture pages an unauthorized role
    # GOT THROUGH via headless Chromium. No-op if Playwright/Chromium is missing.
    shot_cfg = cfg.get("screenshot") or {}
    reports_dir = str(Path(args.json).resolve().parent) if args.json else None

    # Log in all roles first.
    sessions = {}
    for role, creds in auth["roles"].items():
        s = Session(role, creds, base_url, sanctum=sanctum)
        try:
            s.login(auth["login"], creds, mode)
        except Exception as exc:  # noqa: BLE001
            print(f"[SETUP] {exc}", file=sys.stderr)
            return 2
        sessions[role] = s

    results = []
    failures = 0

    for ep in cfg["endpoints"]:
        for role, expected in ep["expect"].items():
            s = sessions.get(role)
            if not s:
                continue
            try:
                resp = s.request(ep.get("method", "GET"), ep["path"], ep.get("body"),
                                 base_url=ep.get("base_url"))
                status = resp.status_code
            except Exception as exc:  # noqa: BLE001
                status = -1
                note = f"request error: {exc}"
                ok = False
            else:
                ok, note = classify(expected, status)
            if not ok:
                failures += 1
            full = (ep.get("base_url") or base_url).rstrip("/") + ep["path"]
            shot = ""
            if not ok and isinstance(status, int) and 200 <= status < 300:
                shot = _evidence_shot(shot_cfg, reports_dir, s, ep.get("method", "GET"),
                                      full, None, f"{role}_{ep['name']}")
            results.append({
                "endpoint": ep["name"], "role": role, "expected": expected,
                "status": status, "ok": ok, "note": note,
                "url": f"{ep.get('method', 'GET')} {full}", "screenshot": shot,
            })

    # Forged-header test. One block or a list, e.g. via the gateway as a low role and
    # straight to the service port as anon (gateway bypass).
    for fh in forged_blocks(cfg.get("forged_headers")):
        s = sessions.get(fh["as_role"])
        for ep in fh.get("endpoints", []):
            base = ep.get("base_url") or fh.get("base_url")
            try:
                resp = s.request(ep.get("method", "GET"), ep["path"],
                                 extra_headers=fh.get("inject"), base_url=base)
                status = resp.status_code
            except Exception as exc:  # noqa: BLE001
                status = -1
            # Forged headers must NOT raise privileges, so the request must stay denied.
            ok = status in (401, 403)
            if not ok:
                failures += 1
            full = (base or base_url).rstrip("/") + ep["path"]
            target = f"{base.rstrip('/')}{ep['path']}" if base else ep["path"]
            inj = ",".join(sorted(fh.get("inject", {}))) or "-"
            shot = ""
            if not ok and isinstance(status, int) and 200 <= status < 300:
                shot = _evidence_shot(shot_cfg, reports_dir, s, ep.get("method", "GET"),
                                      full, fh.get("inject"), f"forged_{fh['as_role']}")
            results.append({
                "endpoint": f"[forged] {target}", "role": fh["as_role"],
                "expected": "deny", "status": status, "ok": ok,
                "note": "" if ok else "HEADER PALSU TEMBUS — X-Auth-* klien dipercaya",
                "url": f"{ep.get('method', 'GET')} {full}  (inject: {inj})", "screenshot": shot,
            })

    # Report.
    width = max((len(r["endpoint"]) for r in results), default=20)
    print(f"\n{'ENDPOINT':<{width}}  {'ROLE':<12} {'EXP':<6} {'HTTP':>5}  RESULT")
    print("-" * (width + 40))
    for r in results:
        mark = f"{C.good('ok')} " if r["ok"] else f"{C.bad('XX')} "
        line = (f"{r['endpoint']:<{width}}  {r['role']:<12} {r['expected']:<6} "
                f"{r['status']:>5}  {mark}{r['note']}")
        print(line)

    print(f"\nTotal: {len(results)} cek, {failures} gagal.")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
