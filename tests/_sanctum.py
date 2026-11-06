"""Dukungan auth Laravel Sanctum (SPA — session cookie + CSRF), lintas-modul.

Dipakai runner authz/upload/auth-policy untuk menguji aplikasi di belakang reverse
proxy (mis. Traefik ForwardAuth) yang autentikasinya berbasis cookie, bukan Bearer.

Alur Sanctum SPA:
  1. GET /sanctum/csrf-cookie → server men-set cookie XSRF-TOKEN (+ session).
     Request HARUS membawa header Origin yang cocok dengan SANCTUM_STATEFUL_DOMAINS;
     bila tidak, backend memperlakukannya sebagai request token (stateless) dan
     Auth::login gagal dengan 500 "Session store not set on request.".
  2. Tiap request berikutnya: sertakan Origin/Referer + header X-XSRF-TOKEN yang
     berisi nilai cookie XSRF-TOKEN setelah di-URL-decode.

Tak ada jaringan di modul ini — hanya menyusun header & memanggil session yang
diberikan pemanggil, jadi mudah diuji unit.
"""
from __future__ import annotations

from urllib.parse import unquote


def stateful_headers(origin):
    """Origin + Referer agar backend memperlakukan request sebagai stateful (SPA)."""
    if not origin:
        return {}
    return {"Origin": origin, "Referer": origin.rstrip("/") + "/"}


def xsrf_header(session):
    """Header X-XSRF-TOKEN dari cookie XSRF-TOKEN (di-URL-decode).

    Laravel menyimpan XSRF-TOKEN ter-URL-encode di cookie; header harus berisi
    nilai yang sudah di-decode agar lolos VerifyCsrfToken.
    """
    tok = session.cookies.get("XSRF-TOKEN")
    return {"X-XSRF-TOKEN": unquote(tok)} if tok else {}


def auth_headers(session, origin):
    """Gabungan header stateful + X-XSRF-TOKEN untuk satu request."""
    h = stateful_headers(origin)
    h.update(xsrf_header(session))
    return h


def prime_csrf(session, base_url, cfg):
    """Ambil cookie XSRF-TOKEN & session dari endpoint csrf-cookie.

    `cfg`: blok 'sanctum' dari config. Kunci yang dipakai:
      origin    — Origin yang cocok SANCTUM_STATEFUL_DOMAINS (wajib agar stateful).
      csrf_path — default '/sanctum/csrf-cookie'.
    Mengembalikan header stateful (Origin/Referer) untuk dipakai ulang pemanggil.
    """
    origin = cfg.get("origin")
    headers = stateful_headers(origin)
    path = cfg.get("csrf_path", "/sanctum/csrf-cookie")
    session.get(base_url.rstrip("/") + path, headers=headers, timeout=20)
    return headers
