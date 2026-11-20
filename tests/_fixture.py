"""Cross-module throwaway test-account fixture for destructive tests that can be rolled back.

Tests such as lockout or password change mutate account state. Instead of using a real account,
this fixture CREATES a throwaway test account through the admin API, provides its credentials,
then DELETES it at the end (always, even when the test fails). The deletion is also recorded in
the rollback journal (crash-safe) so `python audit.py rollback` can clean up if the process
dies midway.

Config (`fixture:` block in the module config):
  admin_auth: { sanctum: {enabled, csrf_path, origin}, login: {method, path, body} }
              atau { header, value }
  create:     { method, path, body, id_path }      # id_path: where the id is in the response (e.g. data.id)
  delete:     { method, path }                      # path may contain {id}
  login:      { method, path, body }                # log in as the test account (body may contain {email}/{password})
  email_template: "kit-probe-{rand}@contoh.example"
Supported placeholders in string values: {email} {password} {id} {rand}.

No network at this module's level except through the session passed in, so the templating and
lifecycle logic are easy to unit test.
"""
from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _rollback  # noqa: E402
import _sanctum  # noqa: E402

PLACEHOLDER_RE = re.compile(r"\{(email|password|new_password|id|rand)\}")


def render(obj, vars_):
    """Recursively replace the {email}/{password}/{id}/{rand} placeholders."""
    if isinstance(obj, str):
        return PLACEHOLDER_RE.sub(lambda m: str(vars_.get(m.group(1), m.group(0))), obj)
    if isinstance(obj, dict):
        return {k: render(v, vars_) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render(v, vars_) for v in obj]
    return obj


def dig(obj, dotted):
    cur = obj
    for part in (dotted or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def strong_password():
    """Random password that meets common policies (upper/lower case, digit, symbol, >12 chars)."""
    return "Kp-" + secrets.token_urlsafe(9) + "7aQ!"


def admin_session(base, auth_cfg, http=requests.Session):
    """Authenticated admin session (Sanctum or static header). Returns (session, origin)."""
    s = http()
    origin = None
    if auth_cfg.get("header") and auth_cfg.get("value"):
        s.headers[auth_cfg["header"]] = auth_cfg["value"]
    san = auth_cfg.get("sanctum") if (auth_cfg.get("sanctum") or {}).get("enabled") else None
    if san:
        origin = san.get("origin")
        _sanctum.prime_csrf(s, base, san)
        login = auth_cfg.get("login")
        if login:
            r = s.request(login.get("method", "POST"), base + login["path"],
                          json=login.get("body") or {},
                          headers=_sanctum.auth_headers(s, origin), timeout=20)
            if r.status_code >= 400:
                raise RuntimeError(f"login admin fixture gagal: HTTP {r.status_code}")
    return s, origin


def _h(s, origin):
    return _sanctum.auth_headers(s, origin) if origin else {}


class DisposableAccount:
    """Context manager: create the test account -> yield self -> delete it (always)."""

    def __init__(self, base, fx_cfg, reports_dir=None, config_path=None, http=requests.Session):
        self.base = base.rstrip("/")
        self.cfg = fx_cfg
        self.reports_dir = reports_dir
        self.config_path = str(config_path) if config_path else None
        self.http = http
        self.id = None
        self.rand = secrets.token_hex(4)
        tpl = fx_cfg.get("email_template", "kit-probe-{rand}@contoh.example")
        self.email = render(tpl, {"rand": self.rand})
        self.password = strong_password()
        self.new_password = strong_password()     # for the password-change test
        self._admin = None
        self._origin = None
        self._entry = None

    def _vars(self):
        return {"email": self.email, "password": self.password,
                "new_password": self.new_password, "id": self.id or "", "rand": self.rand}

    def render(self, obj):
        """Render placeholders with this test account's values."""
        return render(obj, self._vars())

    def __enter__(self):
        self._admin, self._origin = admin_session(self.base, self.cfg["admin_auth"], self.http)
        c = self.cfg["create"]
        r = self._admin.request(c.get("method", "POST"), self.base + c["path"],
                                json=render(c.get("body") or {}, self._vars()),
                                headers=_h(self._admin, self._origin), timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"membuat akun uji gagal: HTTP {r.status_code}")
        try:
            body = r.json()
        except ValueError:
            body = {}
        self.id = dig(body, c.get("id_path", "data.id"))
        if not self.id:
            raise RuntimeError("akun uji dibuat tetapi id tidak ditemukan di response "
                               f"(id_path={c.get('id_path', 'data.id')}) — bersihkan manual: "
                               f"{self.email}")
        # Record the rollback IMMEDIATELY once the account exists (crash-safe).
        if self.reports_dir:
            d = self.cfg["delete"]
            self._entry = _rollback.record(self.reports_dir, {
                "label": f"fixture: hapus akun uji {self.email}",
                "module": "fixture",
                "action": {"method": d.get("method", "DELETE"),
                           "path": render(d["path"], self._vars()),
                           "fixture_config": self.config_path},
            })
        return self

    def new_session(self):
        """New session already logged in as the test account. Returns (session, login_response)."""
        lg = self.cfg["login"]
        s = self.http()
        san = (self.cfg["admin_auth"].get("sanctum") or {})
        origin = san.get("origin")
        if san.get("enabled"):
            _sanctum.prime_csrf(s, self.base, san)
        r = s.request(lg.get("method", "POST"), self.base + lg["path"],
                      json=render(lg.get("body") or {}, self._vars()),
                      headers=_h(s, origin), timeout=20)
        return s, r

    def login_as(self, email, password, session=None):
        """One login attempt for a given identity/password, including a fictitious identity
        (for lockout and account enumeration tests). Returns the response."""
        lg = self.cfg["login"]
        s = session or self.http()
        san = (self.cfg["admin_auth"].get("sanctum") or {})
        origin = san.get("origin")
        if san.get("enabled") and not s.cookies.get("XSRF-TOKEN"):
            _sanctum.prime_csrf(s, self.base, san)
        v = self._vars()
        v["email"], v["password"] = email, password
        return s.request(lg.get("method", "POST"), self.base + lg["path"],
                         json=render(lg.get("body") or {}, v),
                         headers=_h(s, origin), timeout=20)

    def login_attempt(self, password, session=None):
        """Login attempt for this test account with a given password."""
        return self.login_as(self.email, password, session)

    def delete(self):
        """Delete the test account (idempotent). Returns (ok, note)."""
        if self.id is None or self._admin is None:
            return True, "tak ada akun"
        d = self.cfg["delete"]
        try:
            r = self._admin.request(d.get("method", "DELETE"),
                                    self.base + render(d["path"], self._vars()),
                                    headers=_h(self._admin, self._origin), timeout=30)
            ok = 200 <= r.status_code < 400 or r.status_code == 404
            note = "dihapus" if ok else f"HTTP {r.status_code}"
        except Exception as exc:  # noqa: BLE001
            ok, note = False, f"error: {exc}"
        if ok and self._entry is not None and self.reports_dir:
            self._mark_done()
        self.id = None if ok else self.id
        return ok, note

    def _mark_done(self):
        data = _rollback.load(self.reports_dir)
        for e in data:
            if e.get("label") == self._entry.get("label") and not e.get("done"):
                e["done"] = True
        _rollback._write(self.reports_dir, data)

    def __exit__(self, exc_type, exc, tb):
        ok, note = self.delete()
        if not ok:
            print(f"[FIXTURE] gagal menghapus akun uji {self.email}: {note} — "
                  "jalankan `python audit.py rollback` atau hapus manual.", file=sys.stderr)
        return False


def restore_entry(entry, http=requests.Session):
    """Called by mod_rollback for fixture entries: delete the test account using the admin session from config."""
    import yaml
    a = entry["action"]
    cfg_path = a.get("fixture_config")
    if not cfg_path or not Path(cfg_path).exists():
        return False, "config fixture tak ditemukan — hapus akun uji manual"
    import os
    env_re = re.compile(r"\$\{([A-Z0-9_]+)\}")

    def expand(v):
        if isinstance(v, str):
            return env_re.sub(lambda m: os.environ.get(m.group(1), ""), v)
        if isinstance(v, dict):
            return {k: expand(x) for k, x in v.items()}
        if isinstance(v, list):
            return [expand(x) for x in v]
        return v

    cfg = expand(yaml.safe_load(Path(cfg_path).read_text(encoding="utf-8")) or {})
    base = cfg["base_url"].rstrip("/")
    s, origin = admin_session(base, cfg["fixture"]["admin_auth"], http)
    r = s.request(a.get("method", "DELETE"), base + a["path"], headers=_h(s, origin), timeout=30)
    ok = 200 <= r.status_code < 400 or r.status_code == 404
    return ok, ("dihapus" if ok else f"HTTP {r.status_code} — hapus manual")
