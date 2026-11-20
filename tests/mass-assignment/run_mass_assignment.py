#!/usr/bin/env python3
"""Mass assignment / object property escalation test (OWASP API3:2023 BOPLA).

Injects forbidden fields (e.g. role, is_admin, company_id) into an object the test user
MAY modify, then checks whether the server accepted them. This is DESTRUCTIVE (writes
to the target) but made safe: every write is recorded in the rollback journal, and
audit.py restores the original values automatically at the end (after the report).

Flow per target:
  1. GET object        -> snapshot the original values of the fields to be touched.
  2. PATCH/PUT object  -> inject the forbidden fields.  [DESTRUCTIVE]
  3. RECORD journal    -> how to restore the fields to original values (immediately, crash-safe).
  4. GET object        -> read the new values; a finding if a forbidden field CHANGED too.

Restoring is NOT done inline; the rollback phase of audit.py runs it after the report.

Usage: python run_mass_assignment.py --config mass_assignment.yml [--json out.json]
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
import _color as C  # noqa: E402  (shared console ANSI colors in tests/)

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
    """Get a nested value via 'a.b.c'; an empty path returns obj unchanged."""
    if not dotted:
        return obj
    for p in dotted.split("."):
        obj = obj.get(p) if isinstance(obj, dict) else None
    return obj


def extract(body, data_path):
    """Extract the object from a JSON response: use data_path if given, else try common wrappers."""
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
    # Rollback journal dir: explicit reports_dir > --json folder (active project) > <kit>/reports.
    reports = Path(cfg.get("reports_dir")
                   or (Path(args.json).parent if args.json else None)
                   or (Path(__file__).resolve().parents[2] / "reports"))
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

        # 1. Snapshot the original values.
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

        # 2. Inject the forbidden fields (DESTRUCTIVE).
        try:
            w = sess.request(upd.get("method", "PATCH"), upd_url, json=inject,
                             headers=h(), timeout=20)
        except Exception as exc:  # noqa: BLE001
            results.append({"check": name, "status": -1, "ok": True,
                            "note": f"skip: update gagal ({exc})", "url": ev_url})
            continue

        # 3. Record the rollback IMMEDIATELY (crash-safe); it restores the original values.
        _rollback.record(reports, {
            "label": f"mass-assignment: pulihkan {name}",
            "module": "mass-assignment",
            "action": {"method": upd.get("method", "PATCH"), "path": upd["path"],
                       "json": original},
            "original": original,
        })

        # 4. Verify: did a forbidden field change to the injected value?
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
        mark = f"{C.good('ok')} " if ok else f"{C.bad('XX')} "
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
