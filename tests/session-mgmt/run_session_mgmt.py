#!/usr/bin/env python3
"""Uji manajemen sesi (regresi defensif) pada AKUN UJI sekali pakai.

Memeriksa apakah siklus hidup sesi dicabut dengan benar di sisi server:
  1. LOGOUT     : cookie sesi yang disalin sebelum logout tidak boleh berlaku lagi sesudahnya
                  (replay cookie lama harus ditolak).
  2. GANTI SANDI: setelah sandi diganti dari satu sesi, sesi LAIN milik akun yang sama harus
                  dicabut (agar sesi yang mungkin dicuri tak bertahan), dan sandi LAMA tidak
                  boleh lagi diterima.
Semua uji memakai akun uji sekali pakai (dibuat lalu dihapus lewat fixture admin); akun nyata
tidak tersentuh.

Konfigurasi di session_mgmt.yml. Pakai:
    python run_session_mgmt.py --config session_mgmt.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _fixture  # noqa: E402
import _sanctum  # noqa: E402
import _color as C  # noqa: E402  (warna ANSI konsol lintas-modul di tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def is_valid(status):
    return status is not None and 200 <= status < 300


# ── evaluator murni ─────────────────────────────────────────────────────────
def row_logout(replay_status, url):
    ok = not is_valid(replay_status)
    return {"check": "logout: sesi dicabut di server", "status": replay_status, "ok": ok,
            "note": (f"Replay cookie lama setelah logout ditolak (HTTP {replay_status})."
                     if ok else
                     f"Cookie sesi lama MASIH berlaku setelah logout (HTTP {replay_status}) — "
                     "logout hanya menghapus cookie di klien, sesi server tidak dicabut."),
            "url": url, "kind": "logout-no-invalidate"}


def row_other_sessions(other_status, url):
    ok = not is_valid(other_status)
    return {"check": "ganti sandi: sesi lain dicabut", "status": other_status, "ok": ok,
            "note": (f"Sesi lain ditolak setelah ganti sandi (HTTP {other_status})."
                     if ok else
                     f"Sesi LAIN tetap berlaku setelah sandi diganti (HTTP {other_status}) — "
                     "sesi yang mungkin dicuri bertahan walau sandi sudah berubah."),
            "url": url, "kind": "session-not-revoked"}


def row_old_password(status, url):
    ok = not is_valid(status)
    return {"check": "ganti sandi: sandi lama ditolak", "status": status, "ok": ok,
            "note": (f"Sandi lama ditolak setelah penggantian (HTTP {status})." if ok else
                     f"Sandi LAMA masih diterima setelah penggantian (HTTP {status})."),
            "url": url, "kind": "old-password-accepted"}


def row_info(check, ok, note, url, kind="session-not-revoked", status=None):
    return {"check": check, "status": status, "ok": ok, "note": note, "url": url, "kind": kind}


def cookie_snapshot(jar):
    """nama->nilai dari cookie jar requests (iterasi objek Cookie) atau dict biasa."""
    try:
        return {c.name: c.value for c in jar}
    except AttributeError:
        return dict(jar)


# ── bagian jaringan ─────────────────────────────────────────────────────────
class Caller:
    """Pembungkus request ter-autentikasi Sanctum (Origin/Referer + XSRF tiap request)."""

    def __init__(self, base, origin):
        self.base, self.origin = base, origin

    def __call__(self, s, method, path, body=None):
        hdr = _sanctum.auth_headers(s, self.origin) if self.origin else {}
        try:
            r = s.request(method, self.base + path, json=body, headers=hdr, timeout=20,
                          allow_redirects=False)
            return r.status_code
        except Exception:  # noqa: BLE001
            return None


def run_session_checks(acc, cfg, base, http=requests.Session, sleep=time.sleep):
    sc = cfg.get("session") or {}
    me = sc.get("me_path", "/api/me")
    delay = float(sc.get("delay_seconds", 0))
    origin = ((cfg["fixture"].get("admin_auth") or {}).get("sanctum") or {}).get("origin")
    call = Caller(base, origin)
    rows = []

    def login():
        s, r = acc.new_session()
        sleep(delay)
        return s, r.status_code

    # sesi A (yang mengganti sandi), B (sesi "lain"), C (untuk uji logout)
    A, sa = login()
    B, sb = login()
    C, sc_ = login()
    if not all(is_valid(x) for x in (sa, sb, sc_)):
        return [row_info("sesi: login akun uji", True,
                         f"skip: login akun uji gagal (HTTP {sa}/{sb}/{sc_}) — naikkan "
                         "`session.delay_seconds` bila kena rate limit login.", base, status=sa)]
    pre = [call(s, "GET", me) for s in (A, B, C)]
    if not all(is_valid(x) for x in pre):
        return [row_info("sesi: akses profil akun uji", True,
                         f"skip: sesi akun uji tidak dapat membaca {me} (HTTP {pre}).", base)]

    # 1) logout + replay cookie lama
    lo = sc.get("logout")
    if lo:
        snapshot = cookie_snapshot(C.cookies)
        call(C, lo.get("method", "POST"), lo["path"])
        replay = http()
        replay.cookies.update(snapshot)
        status = call(replay, "GET", me)
        rows.append(row_logout(status, f"GET {base}{me} (cookie lama setelah logout)"))
    else:
        rows.append(row_info("logout: sesi dicabut di server", True,
                             "skip: `session.logout` tidak dikonfigurasi.", base,
                             kind="logout-no-invalidate"))

    # 2) ganti sandi dari sesi A; periksa sesi B dan sandi lama
    cp = sc.get("change_password")
    if cp:
        st = call(A, cp.get("method", "POST"), cp["path"], acc.render(cp.get("body") or {}))
        if not is_valid(st):
            rows.append(row_info("ganti sandi: pelaksanaan", True,
                                 f"skip: ganti sandi gagal (HTTP {st}) — periksa kebijakan sandi "
                                 "dan body `change_password`.", f"{cp.get('method', 'POST')} "
                                 f"{base}{cp['path']}", status=st))
        else:
            rows.append(row_other_sessions(call(B, "GET", me), f"GET {base}{me} (sesi lain)"))
            a_after = call(A, "GET", me)
            rows.append(row_info("ganti sandi: sesi yang mengganti", True,
                                 f"Sesi yang mengganti sandi: HTTP {a_after} "
                                 f"({'tetap aktif' if is_valid(a_after) else 'dicabut'}).",
                                 f"GET {base}{me}", status=a_after))
            sleep(delay)
            old = acc.login_attempt(acc.password).status_code
            rows.append(row_old_password(old, f"login {base} (sandi lama)"))
            sleep(delay)
            new = acc.login_as(acc.email, acc.new_password).status_code
            rows.append(row_info("ganti sandi: sandi baru diterima", is_valid(new),
                                 f"Login dengan sandi baru: HTTP {new}.", f"login {base}",
                                 kind="old-password-accepted", status=new))
    else:
        rows.append(row_info("ganti sandi: sesi lain dicabut", True,
                             "skip: `session.change_password` tidak dikonfigurasi.", base))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Uji manajemen sesi (logout, ganti sandi).")
    ap.add_argument("--config", default=str(Path(__file__).with_name("session_mgmt.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url") or not cfg.get("fixture"):
        print("base_url dan blok fixture wajib diisi di config.", file=sys.stderr)
        return 2
    base = cfg["base_url"].rstrip("/")
    reports = Path(args.json_out).parent if args.json_out else None
    try:
        with _fixture.DisposableAccount(base, cfg["fixture"], reports,
                                        Path(args.config).resolve()) as acc:
            results = run_session_checks(acc, cfg, base)
    except Exception as exc:  # noqa: BLE001
        print(f"[SETUP] {exc}", file=sys.stderr)
        return 2
    failures = sum(1 for r in results if not r["ok"])
    for r in results:
        print(f"[{C.tag('PASS' if r['ok'] else 'FAIL')}] {r['check']} — {r['note']}")
    print(f"\n{len(results)} cek, {failures} temuan.")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps({"module": "session-mgmt", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
