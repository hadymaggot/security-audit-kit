#!/usr/bin/env python3
"""Deteksi CORS misconfiguration (non-destruktif, cuma GET dengan header Origin).

Buat tiap path, kirim request dengan Origin uji lalu baca Access-Control-Allow-Origin
(ACAO) dan Access-Control-Allow-Credentials (ACAC). Ditandai kalau:
  - ACAO memantulkan Origin uji yang asing (reflected arbitrary origin), apalagi + ACAC true
  - ACAO '*' dipadu ACAC true
  - Origin 'null' diterima (ACAO: null)

Konfigurasi di cors.yml. Pakai:
    python run_cors.py --config cors.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin

import requests
import yaml

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def probe(s, url, origin):
    """Kembalikan (acao, acac) untuk satu Origin uji."""
    try:
        r = s.get(url, headers={"Origin": origin}, timeout=20, allow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc)
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower()
    return acao, acac, None


def evaluate(path, s, url, evil_origin):
    results = []

    # 1. Reflected arbitrary origin.
    acao, acac, err = probe(s, url, evil_origin)
    if err:
        results.append({"label": f"CORS {path}", "status": -1, "ok": True,
                        "note": f"skip: {err}"})
        return results
    if acao == evil_origin:
        cred = " + credentials" if acac == "true" else ""
        results.append({"label": f"CORS reflektif {path}", "status": 200, "ok": False,
                        "note": f"ACAO memantulkan Origin asing ({evil_origin}){cred}"})
    elif acao == "*" and acac == "true":
        results.append({"label": f"CORS wildcard+creds {path}", "status": 200, "ok": False,
                        "note": "ACAO '*' dipadu Allow-Credentials: true"})
    else:
        results.append({"label": f"CORS {path}", "status": 200, "ok": True, "note": ""})

    # 2. Origin 'null' diterima.
    acao2, acac2, err2 = probe(s, url, "null")
    if not err2 and acao2 == "null":
        cred = " + credentials" if acac2 == "true" else ""
        results.append({"label": f"CORS origin-null {path}", "status": 200, "ok": False,
                        "note": f"Origin 'null' diterima{cred}"})
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="cors.yml")
    ap.add_argument("--json")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    base = cfg["base_url"].rstrip("/")
    evil = cfg.get("evil_origin", "https://evil.example")
    s = requests.Session()
    s.headers["User-Agent"] = "security-audit-kit"
    a = cfg.get("auth") or {}
    if a.get("header") and a.get("value"):
        s.headers[a["header"]] = a["value"]

    paths = cfg.get("paths") or ["/"]
    results = []
    for p in paths:
        url = urljoin(base + "/", p.lstrip("/"))
        results += evaluate(p, s, url, evil)

    failures = sum(1 for r in results if not r["ok"])
    print(f"{'PEMERIKSAAN':<44} {'HTTP':>5}  HASIL")
    print("-" * 74)
    for r in results:
        mark = "ok " if r["ok"] else "XX "
        print(f"{r['label'][:44]:<44} {str(r['status']):>5}  {mark}{r['note']}")
    print(f"\n{len(results)} cek, {failures} temuan.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "cors", "failures": failures, "results": results},
                      f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
