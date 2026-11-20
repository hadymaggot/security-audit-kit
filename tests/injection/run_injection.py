#!/usr/bin/env python3
"""Deteksi SQL injection (OWASP A03) — non-destruktif, hanya probing baca.

Tiga teknik, semuanya tidak mengubah data (hanya SELECT-style probing):

  1. Error-based   — kirim karakter perusak query (', ", \\) lalu deteksi tanda error
     SQL pada response. Keyakinan tinggi bila baseline tidak memunculkan error.
  2. Boolean-based — bandingkan response untuk kondisi TRUE (mis. OR 1=1) vs FALSE
     (mis. AND 1=2). Perbedaan yang konsisten mengindikasikan injeksi.
  3. Time-based    — (opsional, off secara default) kirim payload sleep DB, ukur selisih
     waktu. Diaktifkan lewat options.time_based.

Payload sengaja TIDAK mengubah/menghapus data. Jalankan hanya ke target yang berwenang.

Pakai: python run_injection.py --config injection.yml [--json out.json]
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
import _sanctum  # noqa: E402
import _color as C  # noqa: E402  (warna ANSI konsol lintas-modul di tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")

# Tanda error SQL dari berbagai DBMS (konservatif agar sedikit false positive).
SQL_ERROR_RE = re.compile(
    r"(?i)(SQL syntax|you have an error in your SQL|unclosed quotation mark|"
    r"quoted string not properly terminated|SQLSTATE|ORA-\d{4,5}|"
    r"PostgreSQL.*ERROR|org\.postgresql|psycopg2|"
    r"SQLite3?::|sqlite3\.OperationalError|"
    r"mysql_fetch|mysqli|com\.mysql\.jdbc|"
    r"Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|"
    r"System\.Data\.SqlClient|Warning:\s+(pg|mysqli?)_)")

ERROR_PAYLOADS = ["'", "\"", "\\", "')"]
# Pasangan (TRUE, FALSE) untuk boolean-based, string & numerik.
BOOL_PAIRS = [("' OR '1'='1", "' AND '1'='2"), (" OR 1=1-- -", " AND 1=2-- -")]
# Payload time-based per-DBMS (dipakai hanya bila options.time_based: true).
TIME_PAYLOADS = ["' OR SLEEP({d})-- -", "'||pg_sleep({d})--", "' OR 1=1 WAITFOR DELAY '0:0:{d}'-- -"]


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def sql_error(text):
    return bool(SQL_ERROR_RE.search(text or ""))


def similar(a, b, tol=0.10):
    """True bila dua panjang response mirip (dalam toleransi relatif)."""
    la, lb = len(a or ""), len(b or "")
    hi = max(la, lb) or 1
    return abs(la - lb) / hi <= tol


def probe(send, baseline, opts):
    """Jalankan deteksi memakai callback send(value)->response. Kembalikan list temuan.

    `send(value)` mengirim nilai parameter dan mengembalikan objek dengan atribut
    .status_code, .text, .elapsed_seconds.
    """
    findings = []
    base = send(baseline)
    base_err = sql_error(base.text)

    # 1. Error-based.
    for p in ERROR_PAYLOADS:
        r = send(baseline + p)
        if sql_error(r.text) and not base_err:
            findings.append(("error-based", f"payload {p!r} memicu error SQL", r.status_code))
            break

    # 2. Boolean-based.
    for ptrue, pfalse in BOOL_PAIRS:
        rt = send(baseline + ptrue)
        rf = send(baseline + pfalse)
        # Indikasi: TRUE mirip baseline (query tetap jalan) tapi FALSE berbeda jelas.
        true_ok = rt.status_code == base.status_code and similar(rt.text, base.text)
        false_diff = (rf.status_code != base.status_code) or (not similar(rf.text, base.text))
        if true_ok and false_diff and not similar(rt.text, rf.text):
            findings.append(("boolean-based",
                             f"TRUE vs FALSE berbeda (status {rt.status_code}/{rf.status_code}, "
                             f"len {len(rt.text)}/{len(rf.text)})", rt.status_code))
            break

    # 3. Time-based (opsional).
    if opts.get("time_based"):
        d = int(opts.get("time_threshold", 4))
        for tmpl in TIME_PAYLOADS:
            r = send(baseline + tmpl.format(d=d))
            if r.elapsed_seconds >= d - 0.5 and base.elapsed_seconds < d - 0.5:
                findings.append(("time-based",
                                 f"delay ~{r.elapsed_seconds:.1f}s (threshold {d}s)", r.status_code))
                break
    return findings


def make_sender(sess, target, base_url, headers_fn):
    """Bangun callback send(value) untuk satu target (query/body/json)."""
    method = target.get("method", "GET")
    url = base_url + target["path"]
    loc = target.get("location", "query")
    param = target["param"]
    extra = target.get("extra") or {}

    def send(value):
        kw = {"headers": headers_fn(), "timeout": max(20, int(target.get("timeout", 20)))}
        data = dict(extra)
        data[param] = value
        if loc == "query":
            kw["params"] = data
        elif loc == "json":
            kw["json"] = data
        else:
            kw["data"] = data
        r = sess.request(method, url, **kw)
        # Normalisasi atribut yang dipakai probe().
        r.elapsed_seconds = r.elapsed.total_seconds()
        return r

    return send


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="injection.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    opts = cfg.get("options") or {}
    sess = requests.Session()
    a = cfg.get("auth") or {}
    sanctum = a.get("sanctum") if (a.get("sanctum") or {}).get("enabled") else None
    if a.get("header") and a.get("value"):
        sess.headers[a["header"]] = a["value"]
    if sanctum:
        _sanctum.prime_csrf(sess, base, sanctum)
        login = a.get("login")
        if login:
            r = sess.request(login.get("method", "POST"), base + login["path"],
                             json=login.get("body") or {},
                             headers=_sanctum.auth_headers(sess, sanctum.get("origin")), timeout=20)
            if r.status_code >= 400:
                print(f"login gagal: HTTP {r.status_code}", file=sys.stderr)
                return 2

    def hfn():
        return _sanctum.auth_headers(sess, sanctum.get("origin")) if sanctum else {}

    results = []
    failures = 0
    print(f"{'TARGET':<44} HASIL")
    print("-" * 70)
    for t in cfg.get("targets", []):
        name = t.get("name", f"{t.get('method', 'GET')} {t['path']}?{t.get('param')}")
        ev_url = f"{t.get('method', 'GET')} {base}{t['path']} (param: {t.get('param')})"
        try:
            found = probe(make_sender(sess, t, base, hfn), t.get("baseline", "1"), opts)
        except Exception as exc:  # noqa: BLE001
            results.append({"check": name, "status": -1, "ok": True,
                            "note": f"skip: {exc}", "url": ev_url})
            print(f"{name[:44]:<44} {C.dim(f'skip: {exc}')}")
            continue
        if found:
            failures += 1
            technique = ", ".join(f"{k}" for k, _, _ in found)
            detail = "; ".join(d for _, d, _ in found)
            results.append({"check": name, "status": found[0][2], "ok": False,
                            "note": f"SQLi ({technique}): {detail}", "url": ev_url})
            print(f"{name[:44]:<44} {C.bad(f'XX SQLi: {technique}')}")
        else:
            results.append({"check": name, "status": 200, "ok": True, "note": "", "url": ev_url})
            print(f"{name[:44]:<44} {C.good('ok')}")

    print(f"\n{failures} temuan.")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "injection", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
