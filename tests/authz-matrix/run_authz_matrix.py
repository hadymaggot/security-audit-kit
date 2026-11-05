#!/usr/bin/env python3
"""Regresi kontrol akses berbasis role.

Membaca authz_matrix.yml, login sebagai tiap role, memukul tiap endpoint, lalu
membandingkan status sebenarnya dengan harapan (allow/deny). Keluar dengan kode != 0
bila ada ketidakcocokan — jadi bisa jadi gerbang CI.

Prinsipnya defensif: yang dicek terutama bahwa yang SEHARUSNYA DITOLAK memang ditolak.
Tidak meng-eksploitasi apa pun; hanya mengirim request biasa dan membaca kode status.

Pakai:
    python run_authz_matrix.py --config authz_matrix.yml [--json hasil.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import requests
import yaml

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(value):
    """Ganti ${VAR} dengan environment variable, rekursif untuk dict/list."""
    if isinstance(value, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def dig(obj, dotted):
    """Ambil nilai bersarang via 'a.b.c'."""
    for part in dotted.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


class Session:
    """Kredensial satu role: menyimpan cookie atau bearer token."""

    def __init__(self, role, auth_cfg, base_url):
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.sess = requests.Session()
        self.bearer = None
        self.anonymous = bool(auth_cfg.get("anonymous"))

    def login(self, login_cfg, creds, mode):
        if self.anonymous:
            return
        body = {}
        for k, v in (login_cfg.get("body") or {}).items():
            v = v.replace("{username}", creds.get("username", ""))
            v = v.replace("{password}", creds.get("password", ""))
            body[k] = v
        url = self.base_url + login_cfg["path"]
        resp = self.sess.request(login_cfg.get("method", "POST"), url, json=body, timeout=20)
        if resp.status_code >= 400:
            raise RuntimeError(f"login role '{self.role}' gagal: HTTP {resp.status_code}")
        if mode == "bearer":
            field = login_cfg.get("token_field", "token")
            token = dig(resp.json(), field)
            if not token:
                raise RuntimeError(f"token tak ditemukan di '{field}' untuk role '{self.role}'")
            self.bearer = token

    def request(self, method, path, body=None, extra_headers=None):
        headers = dict(extra_headers or {})
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        url = self.base_url + path
        return self.sess.request(method, url, json=body, headers=headers,
                                 timeout=20, allow_redirects=False)


def classify(expected, status):
    """Kembalikan (ok, catatan) untuk satu harapan vs status nyata."""
    allow_ok = 200 <= status < 400
    deny_ok = status in (401, 403)
    if expected == "allow":
        return allow_ok, "" if allow_ok else "diharapkan lolos tapi ditolak/galat"
    if expected == "deny":
        if deny_ok:
            return True, ""
        if status == 404:
            return False, "404 — mungkin disembunyikan, konfirmasi bukan bocor info"
        if allow_ok:
            return False, "DITOLAK GAGAL — endpoint sensitif bisa diakses role ini"
        return False, f"status tak terduga {status}"
    return False, f"harapan tak dikenal '{expected}'"


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

    # Login semua role lebih dulu.
    sessions = {}
    for role, creds in auth["roles"].items():
        s = Session(role, creds, base_url)
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
                resp = s.request(ep.get("method", "GET"), ep["path"], ep.get("body"))
                status = resp.status_code
            except Exception as exc:  # noqa: BLE001
                status = -1
                note = f"request galat: {exc}"
                ok = False
            else:
                ok, note = classify(expected, status)
            if not ok:
                failures += 1
            results.append({
                "endpoint": ep["name"], "role": role, "expected": expected,
                "status": status, "ok": ok, "note": note,
            })

    # Uji header palsu.
    fh = cfg.get("forged_headers") or {}
    if fh.get("enabled"):
        s = sessions.get(fh["as_role"])
        for ep in fh.get("endpoints", []):
            try:
                resp = s.request(ep.get("method", "GET"), ep["path"],
                                 extra_headers=fh.get("inject"))
                status = resp.status_code
            except Exception as exc:  # noqa: BLE001
                status = -1
            # Header palsu harus TIDAK menaikkan hak akses → tetap ditolak.
            ok = status in (401, 403)
            if not ok:
                failures += 1
            results.append({
                "endpoint": f"[forged] {ep['path']}", "role": fh["as_role"],
                "expected": "deny", "status": status, "ok": ok,
                "note": "" if ok else "HEADER PALSU TEMBUS — gateway tak menimpa X-Auth-*",
            })

    # Laporan.
    width = max((len(r["endpoint"]) for r in results), default=20)
    print(f"\n{'ENDPOINT':<{width}}  {'ROLE':<12} {'EXP':<6} {'HTTP':>5}  RESULT")
    print("-" * (width + 40))
    for r in results:
        mark = "ok " if r["ok"] else "XX "
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
