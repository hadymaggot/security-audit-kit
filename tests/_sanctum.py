"""Cross-module Laravel Sanctum auth support (SPA: session cookie + CSRF).

Used by the authz/upload/auth-policy runners to test apps behind a reverse proxy
(e.g. Traefik ForwardAuth) whose authentication is cookie-based, not Bearer.

Sanctum SPA flow:
  1. GET /sanctum/csrf-cookie → the server sets the XSRF-TOKEN cookie (+ session).
     The request MUST carry an Origin header matching SANCTUM_STATEFUL_DOMAINS; otherwise
     the backend treats it as a token (stateless) request and Auth::login fails with
     500 "Session store not set on request.".
  2. Every later request: send Origin/Referer + an X-XSRF-TOKEN header holding the
     URL-decoded value of the XSRF-TOKEN cookie.

No network in this module: it only builds headers and calls the session passed in by the
caller, so it is easy to unit test.
"""
from __future__ import annotations

from urllib.parse import unquote


def stateful_headers(origin):
    """Origin + Referer so the backend treats the request as stateful (SPA)."""
    if not origin:
        return {}
    return {"Origin": origin, "Referer": origin.rstrip("/") + "/"}


def xsrf_header(session):
    """X-XSRF-TOKEN header built from the XSRF-TOKEN cookie (URL-decoded).

    Laravel stores XSRF-TOKEN URL-encoded in the cookie; the header must carry the
    decoded value to pass VerifyCsrfToken.
    """
    tok = session.cookies.get("XSRF-TOKEN")
    return {"X-XSRF-TOKEN": unquote(tok)} if tok else {}


def auth_headers(session, origin):
    """Stateful headers + X-XSRF-TOKEN combined for one request."""
    h = stateful_headers(origin)
    h.update(xsrf_header(session))
    return h


def prime_csrf(session, base_url, cfg):
    """Fetch the XSRF-TOKEN and session cookies from the csrf-cookie endpoint.

    `cfg`: the 'sanctum' block from config. Keys used:
      origin    - Origin matching SANCTUM_STATEFUL_DOMAINS (required to be stateful).
      csrf_path - default '/sanctum/csrf-cookie'.
    Returns the stateful headers (Origin/Referer) for the caller to reuse.
    """
    origin = cfg.get("origin")
    headers = stateful_headers(origin)
    path = cfg.get("csrf_path", "/sanctum/csrf-cookie")
    session.get(base_url.rstrip("/") + path, headers=headers, timeout=20)
    return headers
