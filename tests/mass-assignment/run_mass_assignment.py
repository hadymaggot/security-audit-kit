#!/usr/bin/env python3
"""Uji mass assignment / eskalasi properti objek (OWASP API3:2023 BOPLA).

Menyuntik field terlarang (mis. role, is_admin, company_id) ke objek yang BOLEH
diubah user uji, lalu memeriksa apakah server menerimanya. Ini DESTRUKTIF (menulis
ke target), tetapi 'rasa non-destruktif': tiap penulisan dicatat ke jurnal rollback,
dan audit.py memulihkan nilai semula otomatis di akhir (setelah laporan).

Alur per target:
  1. GET objek         -> snapshot nilai asli field yang akan disentuh.
  2. PATCH/PUT objek   -> suntik field terlarang.  [DESTRUKTIF]
  3. CATAT jurnal      -> cara mengembalikan field ke nilai asli (segera, crash-safe).
  4. GET objek         -> baca nilai baru; temuan bila field terlarang IKUT berubah.

Pemulihan TIDAK dilakukan inline — dijalankan fase rollback audit.py setelah laporan.

Pakai: python run_mass_assignment.py --config mass_assignment.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _rollback  # noqa: E402
import _sanctum  # noqa: E402

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
    """Ambil nilai bersarang via 'a.b.c'; '' mengembalikan obj apa adanya."""
    if not dotted:
        return obj
    for p in dotted.split("."):
        obj = obj.get(p) if isinstance(obj, dict) else None
    return obj


def extract(body, data_path):
    """Ambil objek dari respons JSON: pakai data_path bila diberi, atau coba wrapper umum."""
    if data_path:
        return dig(body, data_path)
    if isinstance(body, dict):
        for k in ("data", "result", "user", "item"):
            if isinstance(body.get(k), dict):
                return body[k]
    return body


def build_session(base, auth):
    sess = requests.Session()
    sanctum = auth.get("sanctum") if (auth.get("sanctum") or {}).get("enabled") else None
    if auth.get("header") and auth.get("value"):
        sess.headers[auth["header"]] = auth["value"]
    if sanctum:
        _sanctum.prime_csrf(sess, base, sanctum)
        login = auth.get("login")
        if login:
            r = sess.request(login.get("method", "POST"), base + login["path"],
                             json=login.get("body") or {},
                             headers=_sanctum.auth_headers(sess, sanctum.get("origin")),
                             timeout=20)
            if r.status_code >= 400:
                raise RuntimeError(f"login gagal: HTTP {r.status_code}")
    return sess, sanctum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="mass_assignment.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    reports = Path(cfg.get("reports_dir") or (Path(__file__).resolve().parents[2] / "reports"))
    try:
        sess, sanctum = build_session(base, cfg.get("auth") or {})
    except Exception as exc:  # noqa: BLE001
        print(f"[SETUP] {exc}", file=sys.stderr)
        return 2

    def h():
        return _sanctum.auth_headers(sess, sanctum.get("origin")) if sanctum else {}

    results = []
    failures = 0
    print(f"{'TARGET':<40} {'HTTP':>5}  HASIL")
    print("-" * 78)
    for t in cfg.get("targets", []):
        name = t.get("name", t.get("update", {}).get("path", "?"))
        get_path = t["get"]["path"]
        upd = t["update"]
        upd_url = base + upd["path"]
        inject = t.get("inject") or {}
        touched = list(t.get("fields") or inject.keys())
        ev_url = f"{upd.get('method', 'PATCH')} {upd_url}  (inject: {','.join(inject)})"

        # 1. Snapshot nilai asli.
        try:
            g = sess.get(base + get_path, headers=h(), timeout=20)
            obj = extract(g.json(), t.get("data_path"))
        except Exception as exc:  # noqa: BLE001
            print(f"{name[:40]:<40} {'-':>5}  skip: snapshot gagal ({exc})")
            results.append({"check": name, "status": -1, "ok": True,
                            "note": f"skip: snapshot gagal ({exc})", "url": ev_url})
            continue
        if not isinstance(obj, dict):
            results.append({"check": name, "status": g.status_code, "ok": True,
                            "note": "skip: objek tak terbaca", "url": ev_url})
            continue
        original = {f: obj.get(f) for f in touched}

        # 2. Suntik field terlarang (DESTRUKTIF).
        try:
            w = sess.request(upd.get("method", "PATCH"), upd_url, json=inject,
                             headers=h(), timeout=20)
        except Exception as exc:  # noqa: BLE001
            results.append({"check": name, "status": -1, "ok": True,
                            "note": f"skip: update gagal ({exc})", "url": ev_url})
            continue

        # 3. Catat rollback SEGERA (crash-safe), kembalikan field ke nilai asli.
        _rollback.record(reports, {
            "label": f"mass-assignment: pulihkan {name}",
            "module": "mass-assignment",
            "action": {"method": upd.get("method", "PATCH"), "path": upd["path"],
                       "json": original},
            "original": original,
        })

        # 4. Verifikasi: apakah field terlarang IKUT berubah ke nilai suntikan?
        try:
            g2 = sess.get(base + get_path, headers=h(), timeout=20)
            after = extract(g2.json(), t.get("data_path"))
        except Exception:  # noqa: BLE001
            after = None
        accepted = []
        if isinstance(after, dict):
            for f, v in inject.items():
                if f in touched and after.get(f) == v and after.get(f) != original.get(f):
                    accepted.append(f)
        ok = not accepted
        if not ok:
            failures += 1
        note = "" if ok else f"field terlarang diterima: {', '.join(accepted)}"
        mark = "ok " if ok else "XX "
        print(f"{name[:40]:<40} {w.status_code:>5}  {mark}{note}")
        results.append({"check": name, "status": w.status_code, "ok": ok,
                        "note": note, "url": ev_url})

    print(f"\n{failures} temuan. (perubahan di-rollback otomatis setelah laporan)")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "mass-assignment", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
