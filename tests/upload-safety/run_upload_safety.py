#!/usr/bin/env python3
"""Uji bahwa endpoint upload MENOLAK file berbahaya.

Defensif: mengirim file uji yang seharusnya ditolak dan memastikan server menolak
(bukan menerima). Payload sengaja jinak — penanda, bukan kode berbahaya sungguhan —
cukup untuk menguji validasi tipe/isi/nama file.

Konfigurasi lewat upload_safety.yml:

    base_url: "${TARGET_BASE_URL}"
    auth: { header: "Authorization", value: "${UPLOAD_TOKEN}" }
    endpoint: { method: POST, path: "/api/upload", field: "file" }
    allow_only: [".pdf"]          # ekstensi yang sah menurut aplikasi
    max_bytes: 2097152            # batas ukuran; file lebih besar harus ditolak

Pakai: python run_upload_safety.py --config upload_safety.yml
"""
from __future__ import annotations

import argparse
import io
import os
import re
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


# PDF jinak dengan aksi JavaScript sekadar penanda — untuk menguji apakah server
# membersihkan/menolak PDF ber-JS. Tidak melakukan apa pun yang berbahaya.
PDF_WITH_JS = (
    b"%PDF-1.3\n"
    b"1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(/*probe*/)>>/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
HTML_AS_PDF = b"<html><body><script>/*probe*/</script></body></html>"
SVG_FILE = b'<svg xmlns="http://www.w3.org/2000/svg"><text>probe</text></svg>'


def build_cases(cfg):
    """(nama, nama_berkas, konten, content_type, harus_ditolak?)"""
    cases = [
        ("PDF berisi JavaScript", "a.pdf", PDF_WITH_JS, "application/pdf", True),
        ("HTML dengan ekstensi .pdf", "a.pdf", HTML_AS_PDF, "application/pdf", True),
        ("SVG (bisa bawa skrip)", "a.svg", SVG_FILE, "image/svg+xml", True),
        ("Ekstensi ganda", "a.pdf.html", HTML_AS_PDF, "text/html", True),
        ("Nama file path traversal", "../../a.pdf", b"%PDF-1.3\n%%EOF\n", "application/pdf", True),
    ]
    mx = cfg.get("max_bytes")
    if mx:
        big = b"%PDF-1.3\n" + b"0" * (int(mx) + 1024) + b"\n%%EOF\n"
        cases.append(("Melebihi batas ukuran", "big.pdf", big, "application/pdf", True))
    # Kontrol positif: file sah harus DITERIMA (memastikan uji tak selalu "tolak").
    cases.append(("PDF sah (kontrol)", "ok.pdf", b"%PDF-1.3\n%%EOF\n", "application/pdf", False))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="upload_safety.yml")
    ap.add_argument("--json", help="tulis hasil ke file JSON")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = expand(yaml.safe_load(f))

    ep = cfg["endpoint"]
    base = cfg["base_url"].rstrip("/")
    url = base + ep["path"]
    sess = requests.Session()
    a = cfg.get("auth") or {}
    sanctum = a.get("sanctum") if (a.get("sanctum") or {}).get("enabled") else None
    static_headers = {}
    if a.get("header") and a.get("value"):
        static_headers[a["header"]] = a["value"]
    # Auth Sanctum (opsional): ambil cookie CSRF + sesi, lalu login bila disediakan.
    if sanctum:
        _sanctum.prime_csrf(sess, base, sanctum)
        login = a.get("login")
        if login:
            r = sess.request(login.get("method", "POST"), base + login["path"],
                             json=login.get("body") or {},
                             headers=_sanctum.auth_headers(sess, sanctum.get("origin")),
                             timeout=20)
            if r.status_code >= 400:
                print(f"login gagal: HTTP {r.status_code}", file=sys.stderr)
                return 2

    def req_headers():
        h = dict(static_headers)
        if sanctum:
            h.update(_sanctum.auth_headers(sess, sanctum.get("origin")))
        return h

    failures = 0
    results = []
    print(f"{'KASUS':<34} {'HTTP':>5}  HASIL")
    print("-" * 70)
    for name, fname, content, ctype, should_reject in build_cases(cfg):
        files = {ep.get("field", "file"): (fname, io.BytesIO(content), ctype)}
        try:
            r = sess.post(url, files=files, headers=req_headers(), timeout=20)
            status = r.status_code
        except Exception as exc:  # noqa: BLE001
            print(f"{name:<34} {'-':>5}  galat: {exc}")
            failures += 1
            results.append({"case": name, "status": -1, "ok": False, "note": str(exc)})
            continue
        accepted = 200 <= status < 300
        ok = (not accepted) if should_reject else accepted
        if not ok:
            failures += 1
        verdict = "ok" if ok else ("XX DITERIMA padahal harus ditolak" if should_reject
                                   else "XX ditolak padahal file sah")
        print(f"{name:<34} {status:>5}  {verdict}")
        results.append({"case": name, "status": status, "ok": ok,
                        "note": "" if ok else verdict})

    print(f"\n{failures} gagal.")
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "upload-safety", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
