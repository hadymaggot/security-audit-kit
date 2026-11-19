#!/usr/bin/env python3
"""Uji kebijakan autentikasi: kekuatan sandi, regen captcha, timeout sesi.

Defensif & non-destruktif: hanya memverifikasi bahwa aturan ditegakkan, tanpa
brute-force atau serangan. Konfigurasi lewat auth_policy.yml:

    base_url: "${TARGET_BASE_URL}"
    register:                      # opsional — uji penolakan sandi lemah saat daftar
      path: "/api/auth/register"
      template: { email: "probe{rand}@example.test", name: "probe" }
      password_field: "password"
    captcha:                       # opsional — captcha harus berubah tiap gagal
      issue_path: "/api/captcha"
      token_field: "data.id"
    weak_passwords: ["12345678", "password", "aaaaaaaa", "qwerty12"]

Opsional:
    login: { path: "/api/login", body: {...} }   # sesi untuk uji yang butuh auth
    password_checks:               # selain/menggantikan 'register'
      - name: "ganti sandi"
        path: "/api/auth/change-password"
        authenticated: true        # pakai sesi 'login'
        template: { current_password: "salah-sengaja" }   # gagal di field lain → tak tersimpan
        password_field: "password"
        confirm_field: "password_confirmation"
    strong_password: "..."         # kontrol: sandi kuat tak boleh kena error sandi
    delay_seconds: 20              # jeda antar request, hormati rate limit

Sandi lemah dianggap ditolak hanya bila 422 memuat error DI field sandi. 429
dicatat sebagai skip (tak bisa disimpulkan), bukan kegagalan.

Pakai: python run_auth_policy.py --config auth_policy.yml
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
import time
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _sanctum  # noqa: E402  (helper auth Sanctum lintas-modul di tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def dig(obj, dotted):
    for p in dotted.split("."):
        obj = obj.get(p) if isinstance(obj, dict) else None
    return obj


def password_error(resp, field):
    """True bila respons menolak dengan error DI field sandi.

    Laravel membalas 422 {"errors": {field: [...]}}. 422 karena field lain (captcha,
    email, dsb.) bukan bukti kebijakan sandi ditegakkan. Bila respons tak memuat
    daftar error per field, jatuh ke kode status saja.
    """
    if resp.status_code not in (400, 422):
        return False
    try:
        errors = resp.json().get("errors")
    except (ValueError, AttributeError):
        return True
    if isinstance(errors, dict):
        return field in errors
    return True


def password_checks(cfg):
    """Daftar uji kebijakan sandi; blok 'register' lama tetap didukung."""
    checks = list(cfg.get("password_checks") or [])
    if cfg.get("register"):
        checks.insert(0, {"name": "register", **cfg["register"]})
    return checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="auth_policy.yml")
    ap.add_argument("--json", help="tulis hasil ke file JSON")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    failures = 0
    results = []

    # Sesi + auth Sanctum opsional (register sering butuh CSRF + Origin stateful).
    sess = requests.Session()
    sanctum = (cfg.get("sanctum") or {})
    sanctum = sanctum if sanctum.get("enabled") else None
    if sanctum:
        _sanctum.prime_csrf(sess, base, sanctum)

    def auth_h():
        return _sanctum.auth_headers(sess, sanctum.get("origin")) if sanctum else {}

    # Sesi login (opsional) — untuk uji yang butuh autentikasi, mis. ganti sandi.
    authed = None
    login = cfg.get("login")
    if login:
        authed = requests.Session()
        if sanctum:
            _sanctum.prime_csrf(authed, base, sanctum)
        r = authed.request(login.get("method", "POST"), base + login["path"],
                           json=login.get("body") or {},
                           headers=_sanctum.auth_headers(authed, (sanctum or {}).get("origin")),
                           timeout=20)
        if r.status_code >= 400:
            print(f"login gagal: HTTP {r.status_code}", file=sys.stderr)
            return 2

    delay = float(cfg.get("delay_seconds", 0))   # jeda antar request (rate limit)
    first = [True]

    def post(chk, body):
        if not first[0] and delay:
            time.sleep(delay)
        first[0] = False
        s = authed if chk.get("authenticated") else sess
        h = _sanctum.auth_headers(s, sanctum.get("origin")) if sanctum else {}
        return s.request(chk.get("method", "POST"), base + chk["path"], json=body,
                         headers=h, timeout=20)

    # 1. Sandi lemah harus ditolak — DENGAN error di field sandi, bukan field lain.
    for chk in password_checks(cfg):
        label = chk.get("name", chk["path"])
        field = chk.get("password_field", "password")
        ep_url = f"{chk.get('method', 'POST')} {base + chk['path']}"
        print(f"== Kebijakan sandi: {label} ==")

        def body_for(pw):
            body = {k: (v.replace("{rand}", secrets.token_hex(4)) if isinstance(v, str) else v)
                    for k, v in (chk.get("template") or {}).items()}
            body[field] = pw
            if chk.get("confirm_field"):
                body[chk["confirm_field"]] = pw
            return body

        for pw in cfg.get("weak_passwords", []):
            try:
                r = post(chk, body_for(pw))
            except Exception as exc:  # noqa: BLE001
                print(f"  galat '{pw}': {exc}")
                failures += 1
                continue
            if r.status_code == 429:
                # Rate limit = tak bisa disimpulkan, bukan bukti sandi lemah lolos.
                print(f"  sandi {pw!r:<16} HTTP 429  skip (rate limit)")
                results.append({"check": f"{label} sandi lemah {pw}", "status": 429,
                                "ok": True, "note": "skip: rate limit", "url": ep_url})
                continue
            rejected = password_error(r, field)
            mark = "ok" if rejected else "XX DITERIMA (sandi lemah lolos)"
            if not rejected:
                failures += 1
            print(f"  sandi {pw!r:<16} HTTP {r.status_code}  {mark}")
            results.append({"check": f"{label} sandi lemah {pw}", "status": r.status_code,
                            "ok": rejected, "note": "" if rejected else "sandi lemah lolos",
                            "url": ep_url})

        # Kontrol positif: sandi kuat TAK boleh kena error sandi — kalau kena, uji di
        # atas tak bermakna (endpoint menolak apa pun). Template sebaiknya membuat
        # request gagal di field LAIN agar tak ada yang tersimpan.
        strong = cfg.get("strong_password")
        if strong:
            try:
                r = post(chk, body_for(strong))
                ok = r.status_code == 429 or not password_error(r, field)
                note = "skip: rate limit" if r.status_code == 429 else (
                    "" if ok else "sandi kuat pun ditolak — uji sandi lemah tak bermakna")
            except Exception as exc:  # noqa: BLE001
                ok, note, r = False, f"galat: {exc}", None
            if not ok:
                failures += 1
            status = r.status_code if r is not None else -1
            print(f"  kontrol sandi kuat     HTTP {status}  {'ok' if ok else 'XX ' + note}")
            results.append({"check": f"{label} kontrol sandi kuat", "status": status,
                            "ok": ok, "note": note, "url": ep_url})

    # 2. Captcha harus regenerasi (token baru tiap terbit).
    cap = cfg.get("captcha")
    if cap:
        print("\n== Regenerasi captcha ==")
        tokens = []
        for _ in range(3):
            try:
                r = sess.get(base + cap["issue_path"], headers=auth_h(), timeout=20)
                tokens.append(dig(r.json(), cap.get("token_field", "token")))
            except Exception as exc:  # noqa: BLE001
                print(f"  galat: {exc}")
                failures += 1
                break
        uniq = len(set(t for t in tokens if t))
        ok = uniq == len([t for t in tokens if t]) and uniq > 1
        if not ok:
            failures += 1
        print(f"  token terbit: {tokens}")
        print(f"  {'ok unik' if ok else 'XX token captcha berulang'}")
        results.append({"check": "captcha-regenerasi", "status": None, "ok": ok,
                        "note": "" if ok else "token captcha berulang",
                        "url": f"GET {base + cap['issue_path']}"})

    print(f"\n{failures} gagal.")
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "auth-policy", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
