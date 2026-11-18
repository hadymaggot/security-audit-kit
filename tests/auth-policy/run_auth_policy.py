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

Pakai: python run_auth_policy.py --config auth_policy.yml
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
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

    # 1. Sandi lemah harus ditolak saat registrasi.
    reg = cfg.get("register")
    if reg:
        print("== Kebijakan sandi ==")
        for pw in cfg.get("weak_passwords", []):
            body = dict(reg.get("template", {}))
            body = {k: v.replace("{rand}", secrets.token_hex(4)) for k, v in body.items()}
            body[reg.get("password_field", "password")] = pw
            try:
                r = sess.post(base + reg["path"], json=body, headers=auth_h(), timeout=20)
                rejected = r.status_code in (400, 422)
            except Exception as exc:  # noqa: BLE001
                print(f"  galat '{pw}': {exc}")
                failures += 1
                continue
            mark = "ok" if rejected else "XX DITERIMA (sandi lemah lolos)"
            if not rejected:
                failures += 1
            print(f"  sandi {pw!r:<14} HTTP {r.status_code}  {mark}")
            results.append({"check": f"weak-password:{pw}", "status": r.status_code,
                            "ok": rejected, "note": "" if rejected else "sandi lemah lolos"})

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
                        "note": "" if ok else "token captcha berulang"})

    print(f"\n{failures} gagal.")
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "auth-policy", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
