#!/usr/bin/env python3
"""Test that the upload endpoint REJECTS dangerous files.

Defensive: sends test files that should be rejected and verifies the server rejects them.
Payloads are deliberately harmless markers, not real malicious code; they are enough to
exercise type/content/filename validation.

Config via upload_safety.yml:

    base_url: "${TARGET_BASE_URL}"
    auth: { header: "Authorization", value: "${UPLOAD_TOKEN}" }
    endpoint: { method: POST, path: "/api/upload", field: "file" }
    allow_only: [".pdf"]          # extensions the app considers valid
    max_bytes: 2097152            # size limit; larger files must be rejected

Usage: python run_upload_safety.py --config upload_safety.yml
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
import _sanctum  # noqa: E402  (shared Sanctum auth helper)
import _color as C  # noqa: E402  (shared ANSI console colors)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


# Harmless PDF with a JavaScript action as a marker, to see whether the server sanitizes or
# rejects PDFs with JS. It does nothing dangerous.
PDF_WITH_JS = (
    b"%PDF-1.3\n"
    b"1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(/*probe*/)>>/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
HTML_AS_PDF = b"<html><body><script>/*probe*/</script></body></html>"
SVG_FILE = b'<svg xmlns="http://www.w3.org/2000/svg"><text>probe</text></svg>'
# Polyglot: valid GIF header + server-side code marker, to see whether validation only checks
# magic bytes. The marker is never executed.
POLYGLOT_GIF_PHP = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php /*probe*/ ?>"
PDF_OK = b"%PDF-1.3\n%%EOF\n"
TRAVERSAL = "Nama file path traversal"


def sanitized(case, resp):
    """Filename case: accepted but stored with a clean name is safe (reject OR sanitize)."""
    return case == TRAVERSAL and b".." not in (resp.content or b"")


def dig(obj, dotted):
    """Get a nested value via 'a.b.c'."""
    for part in dotted.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def build_cases(cfg):
    """Return (name, filename, content, content_type, should_reject) tuples."""
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
    # Positive control: a valid file must be ACCEPTED (so the test is not always "reject").
    cases.append(("PDF sah (kontrol)", "ok.pdf", PDF_OK, "application/pdf", False))
    return cases


def cleanup_accepted(sess, base, cleanup, resp, headers):
    """Delete a test file that was accepted and return a short note.

    `cleanup`: {method, path (contains {id}), id_field (dotted path in the JSON response)}.
    """
    try:
        file_id = dig(resp.json(), cleanup.get("id_field", "id"))
    except ValueError:
        file_id = None
    if not file_id:
        return "cleanup: id tak ditemukan di response — hapus manual"
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
    # Optional Sanctum auth: fetch the CSRF + session cookies, then log in if configured.
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
    form = ep.get("data") or {}         # extra form fields, e.g. document type
    cleanup = cfg.get("cleanup")        # delete test files that were accepted
    for name, fname, content, ctype, should_reject in build_cases(cfg):
        files = {ep.get("field", "file"): (fname, io.BytesIO(content), ctype)}
        evidence_url = f"{ep.get('method', 'POST')} {url}  (file={fname!r}, type={ctype})"
        try:
            r = sess.post(url, files=files, data=form, headers=req_headers(), timeout=20)
            status = r.status_code
        except Exception as exc:  # noqa: BLE001
            print(f"{name:<34} {'-':>5}  error: {exc}")
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
        note = "diterima, nama file disanitasi" if clean else ("" if ok else verdict)
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
