"""Helper screenshot bukti reusable lintas-modul (Playwright/Chromium).

Dua entry point:
  capture_page(page, ...) — tangkap dari page Playwright yang sudah terbuka
                            (dipakai modul yang memang menjalankan browser, mis. client-leak).
  capture_url(url, ...)   — luncurkan Chromium headless, buka url (opsional headers/cookies),
                            lalu tangkap (dipakai modul berbasis requests, mis. authz).

Keduanya GRACEFUL: mengembalikan "" bila Playwright/Chromium tidak terpasang atau gagal,
sehingga modul tetap jalan tanpa screenshot. Path yang dikembalikan relatif terhadap
reports_dir (mis. "evidence/authz_admin_users.png") agar langsung bisa disematkan di laporan.

Opsional: butuh `pip install playwright` + `python -m playwright install chromium`.
"""
from __future__ import annotations

import re
from pathlib import Path


def _slug(name, prefix):
    base = re.sub(r"[^A-Za-z0-9]+", "_", name or "").strip("_")[:48] or "root"
    return f"{prefix}_{base}.png"


def capture_page(page, reports_dir, name, prefix="shot",
                 selector=None, clip=None, full_page=False):
    """Tangkap dari page Playwright yang sudah terbuka. Return path relatif / ''."""
    if not reports_dir:
        return ""
    try:
        ssdir = Path(reports_dir) / "evidence"
        ssdir.mkdir(parents=True, exist_ok=True)
        fpath = ssdir / _slug(name, prefix)
        if selector:                                   # crop ke elemen tertentu
            page.locator(selector).first.screenshot(path=str(fpath))
        elif clip:                                     # crop ke region x/y/width/height
            page.screenshot(path=str(fpath), clip=clip)
        else:                                          # viewport (default) atau full_page
            page.screenshot(path=str(fpath), full_page=bool(full_page))
        return "evidence/" + fpath.name
    except Exception:  # noqa: BLE001
        return ""


def capture_url(url, reports_dir, name, prefix="shot", headers=None, cookies=None,
                full_page=False, timeout=20000, _pw=None):
    """Luncurkan Chromium headless, buka url (opsional headers/cookies auth), tangkap.

    headers: dict header tambahan (mis. {"Authorization": "Bearer ..."}).
    cookies: list cookie Playwright (mis. hasil _cookies_from_requests()).
    _pw    : untuk test — inject pengganti sync_playwright.
    Return path relatif terhadap reports_dir, atau '' (graceful)."""
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
    """Ubah cookie dari requests.Session jadi format cookie Playwright (best-effort)."""
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
