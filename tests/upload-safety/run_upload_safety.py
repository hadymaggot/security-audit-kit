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
# Polyglot: header GIF valid + penanda kode server — menguji apakah validasi hanya
# melihat magic byte. Penanda tak dieksekusi apa pun.
POLYGLOT_GIF_PHP = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php /*probe*/ ?>"
PDF_OK = b"%PDF-1.3\n%%EOF\n"
TRAVERSAL = "Nama file path traversal"


def sanitized(case, resp):
    """Kasus nama berkas: diterima tapi nama tersimpan bersih = aman (tolak ATAU sanitasi)."""
    return case == TRAVERSAL and b".." not in (resp.content or b"")


def dig(obj, dotted):
    """Ambil nilai bersarang via 'a.b.c'."""
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def build_cases(cfg):
    """(nama, nama_berkas, konten, content_type, harus_ditolak?)"""
    cases = [
        ("PDF berisi JavaScript", "a.pdf", PDF_WITH_JS, "application/pdf", True),
        ("HTML dengan ekstensi .pdf", "a.pdf", HTML_AS_PDF, "application/pdf", True),
        ("SVG (bisa bawa skrip)", "a.svg", SVG_FILE, "image/svg+xml", True),
        ("Ekstensi ganda", "a.pdf.html", HTML_AS_PDF, "text/html", True),
        ("Ekstensi ganda berakhir .php", "a.pdf.php", PDF_OK, "application/pdf", True),
        ("Polyglot GIF+PHP", "a.pdf", POLYGLOT_GIF_PHP, "application/pdf", True),
        (TRAVERSAL, "../../a.pdf", PDF_OK, "application/pdf", True),
    ]
    mx = cfg.get("max_bytes")
    if mx:
        big = b"%PDF-1.3\n" + b"0" * (int(mx) + 1024) + b"\n%%EOF\n"
        cases.append(("Melebihi batas ukuran", "big.pdf", big, "application/pdf", True))
    # Kontrol positif: file sah harus DITERIMA (memastikan uji tak selalu "tolak").
    cases.append(("PDF sah (kontrol)", "ok.pdf", PDF_OK, "application/pdf", False))
    return cases


def cleanup_accepted(sess, base, cleanup, resp, headers):
    """Hapus berkas uji yang terlanjur diterima. Kembalikan catatan singkat.

    `cleanup`: {method, path (berisi {id}), id_field (dotted di respons JSON)}.
    """
    try:
        file_id = dig(resp.json(), cleanup.get("id_field", "id"))
    except ValueError:
        file_id = None
    if not file_id:
        return "cleanup: id tak ditemukan di respons — hapus manual"
    path = cleanup["path"].replace("{id}", str(file_id))
    try:
        r = sess.request(cleanup.get("method", "DELETE"), base + path,
                         headers=headers, timeout=20)
    except Exception as exc:  # noqa: BLE001
        return f"cleanup gagal ({exc}) — hapus manual id {file_id}"
    if 200 <= r.status_code < 300:
        return f"cleanup ok (id {file_id})"
    return f"cleanup HTTP {r.status_code} — hapus manual id {file_id}"


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
    form = ep.get("data") or {}         # field form tambahan, mis. jenis dokumen
    cleanup = cfg.get("cleanup")        # hapus berkas uji yang terlanjur diterima
    for name, fname, content, ctype, should_reject in build_cases(cfg):
        files = {ep.get("field", "file"): (fname, io.BytesIO(content), ctype)}
        evidence_url = f"{ep.get('method', 'POST')} {url}  (file={fname!r}, type={ctype})"
        try:
            r = sess.post(url, files=files, data=form, headers=req_headers(), timeout=20)
            status = r.status_code
        except Exception as exc:  # noqa: BLE001
            print(f"{name:<34} {'-':>5}  galat: {exc}")
            failures += 1
            results.append({"case": name, "status": -1, "ok": False,
                            "note": str(exc), "url": evidence_url})
            continue
        accepted = 200 <= status < 300
        ok = (not accepted) if should_reject else accepted
        clean = accepted and should_reject and sanitized(name, r)
        ok = ok or clean
        if not ok:
            failures += 1
        verdict = "ok" if ok else ("XX DITERIMA padahal harus ditolak" if should_reject
                                   else "XX ditolak padahal file sah")
        note = "diterima, nama berkas disanitasi" if clean else ("" if ok else verdict)
        if accepted and cleanup:
            done = cleanup_accepted(sess, base, cleanup, r, req_headers())
            note = f"{note}; {done}" if note else done
        print(f"{name:<34} {status:>5}  {C.status(verdict)}" + (f"  [{note}]" if accepted and cleanup else ""))
        results.append({"case": name, "status": status, "ok": ok, "note": note,
                        "url": evidence_url})

    print(f"\n{failures} gagal.")
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"module": "upload-safety", "failures": failures,
                       "results": results}, f, ensure_ascii=False, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
