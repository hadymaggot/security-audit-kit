"""Reusable cross-module evidence screenshot helper (Playwright/Chromium).

Two entry points:
  capture_page(page, ...) — capture from an already open Playwright page
                            (used by modules that run a browser anyway, e.g. client-leak).
  capture_url(url, ...)   — launch headless Chromium, open url (optional headers/cookies),
                            then capture (used by requests-based modules, e.g. authz).

Both are GRACEFUL: they return "" if Playwright/Chromium is not installed or fails, so the
module still runs without a screenshot. The returned path is relative to reports_dir
(e.g. "evidence/authz_admin_users.png") so it can be embedded in the report directly.

Optional: needs `pip install playwright` + `python -m playwright install chromium`.
"""
from __future__ import annotations

import re
from pathlib import Path

import _throttle


def _slug(name, prefix):
    base = re.sub(r"[^A-Za-z0-9]+", "_", name or "").strip("_")[:48] or "root"
    return f"{prefix}_{base}.png"


def capture_page(page, reports_dir, name, prefix="shot",
                 selector=None, clip=None, full_page=False):
    """Capture from an already open Playwright page. Returns a relative path or ''."""
    if not reports_dir:
        return ""
    try:
        ssdir = Path(reports_dir) / "evidence"
        ssdir.mkdir(parents=True, exist_ok=True)
        fpath = ssdir / _slug(name, prefix)
        if selector:                                   # crop to a specific element
            page.locator(selector).first.screenshot(path=str(fpath))
        elif clip:                                     # crop to an x/y/width/height region
            page.screenshot(path=str(fpath), clip=clip)
        else:                                          # viewport (default) or full_page
            page.screenshot(path=str(fpath), full_page=bool(full_page))
        return "evidence/" + fpath.name
    except Exception:  # noqa: BLE001
        return ""


def capture_url(url, reports_dir, name, prefix="shot", headers=None, cookies=None,
                full_page=False, timeout=20000, _pw=None):
    """Launch headless Chromium, open url (optional auth headers/cookies) and capture.

    headers: dict of extra headers (e.g. {"Authorization": "Bearer ..."}).
    cookies: list of Playwright cookies (e.g. the result of _cookies_from_requests()).
    _pw    : for tests, injects a replacement for sync_playwright.
    Returns a path relative to reports_dir, or '' (graceful)."""
    if not reports_dir or not url:
        return ""
    pwf = _pw
    if pwf is None:
        try:
            from playwright.sync_api import sync_playwright as pwf
        except ImportError:
            return ""
    try:
        with pwf() as pw:
            browser = pw.chromium.launch()
            try:
                ctx = browser.new_context(extra_http_headers=headers or {})
                _throttle.guard_context(ctx)       # bounty mode: scope check + rate limit per request
                if cookies:
                    ctx.add_cookies(cookies)
                page = ctx.new_page()
                page.goto(url, timeout=timeout)
                return capture_page(page, reports_dir, name, prefix=prefix,
                                    full_page=full_page)
            finally:
                browser.close()
    except Exception:  # noqa: BLE001
        return ""


def cookies_from_requests(sess, url):
    """Convert requests.Session cookies to the Playwright cookie format (best-effort)."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        out = []
        for c in sess.cookies:
            out.append({"name": c.name, "value": c.value,
                        "domain": c.domain or host, "path": c.path or "/"})
        return out
    except Exception:  # noqa: BLE001
        return []
