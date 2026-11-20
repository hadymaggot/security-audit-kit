#!/usr/bin/env python3
"""Local-canary SSRF (Server-Side Request Forgery) tests (defensive).

For endpoints that ACCEPT a URL (webhook, link preview, import from URL, etc.), this module
runs a small HTTP listener of your own (the canary) and sends the canary URL as a parameter
value. If the target server actually fetches it, SSRF is confirmed; since the canary sits on a
private/loopback address, a correct endpoint SHOULD block it.

Variants tested per target:
  - direct                : http://<canary host>:<port>/<token>
  - decimal/hex/octal IP  : bypasses string-based blocklists on IPv4 addresses
  - userinfo (@)          : http://allowed.example@<canary host>:<port>/<token>
  - redirect              : canary replies 302 to a second path; a second hop means the
                            server follows redirects to an unvalidated destination

No internal host scanning and no cloud metadata calls; the only outbound request triggered
is to your own canary listener.

Config in ssrf.yml. Usage:
    python run_ssrf.py --config ssrf.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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


# ── canary listener ─────────────────────────────────────────────────────────
class Canary:
    """HTTP listener that records every incoming request (path, UA, source address)."""

    def __init__(self, bind="0.0.0.0", port=0):
        self.hits, self._lock = [], threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def _do(self):
                with outer._lock:
                    outer.hits.append({"path": self.path, "ua": self.headers.get("User-Agent", ""),
                                       "from": self.client_address[0], "t": time.time()})
                if self.path.startswith("/redir/"):          # second hop for the redirect test
                    self.send_response(302)
                    self.send_header("Location", self.path.replace("/redir/", "/hop2/", 1))
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = do_HEAD = do_PUT = _do

            def log_message(self, *a):        # silent
                pass

        self.server = ThreadingHTTPServer((bind, port), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def hits_for(self, token):
        with self._lock:
            return [h for h in self.hits if token in h["path"]]


# ── payload variants (pure) ──────────────────────────────────────────────────
def ip_variants(ip):
    """Alternate representations of an IPv4 address (decimal, hex, octal, mapped); [] if not IPv4."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if a.version != 4:
        return []
    n = int(a)
    o = [int(x) for x in ip.split(".")]
    return [("desimal", str(n)), ("heksadesimal", hex(n)),
            ("oktal", ".".join("0" + format(x, "o") for x in o)),
            ("IPv6-mapped", f"[::ffff:{ip}]")]


def build_variants(public_url, token, variants=True):
    """Return [(name, url)] for one target; public_url is the listener URL as the server sees it."""
    u = urlparse(public_url)
    host, port = u.hostname or "", u.port
    hp = f"{host}:{port}" if port else host
    base = f"{u.scheme or 'http'}://"
    out = [("langsung", f"{base}{hp}/{token}")]
    if variants:
        for name, alt in ip_variants(host):
            altp = f"{alt}:{port}" if port else alt
            out.append((f"IP {name}", f"{base}{altp}/{token}"))
        out.append(("userinfo (@)", f"{base}allowed.example@{hp}/{token}"))
        out.append(("redirect", f"{base}{hp}/redir/{token}"))
    return out


# ── evaluation (pure) ────────────────────────────────────────────────────────
def evaluate(target_name, variant, url_sent, token, hits, where):
    """Return one result row; hits are the canary hits for this token."""
    paths = [h["path"] for h in hits]
    if variant == "redirect":
        hop2 = [p for p in paths if p.startswith("/hop2/")]
        first = [p for p in paths if p.startswith("/redir/")]
        if hop2:
            return {"check": f"ssrf: {target_name} — {variant}", "status": None, "ok": False,
                    "note": "Server mengikuti redirect dari canary ke jalur kedua tanpa validasi "
                            "tujuan baru (hop kedua teramati).", "url": where, "kind": "ssrf"}
        if first:
            return {"check": f"ssrf: {target_name} — {variant}", "status": None, "ok": False,
                    "note": "Server menembak URL canary (alamat privat) — SSRF terkonfirmasi "
                            "(redirect tidak diikuti).", "url": where, "kind": "ssrf"}
    elif hits:
        ua = hits[0].get("ua") or "-"
        return {"check": f"ssrf: {target_name} — {variant}", "status": None, "ok": False,
                "note": f"Server menembak URL canary yang dikendalikan penguji (asal "
                        f"{hits[0].get('from')}, User-Agent '{ua[:60]}') — SSRF terkonfirmasi; "
                        "alamat privat seharusnya diblokir.", "url": where, "kind": "ssrf"}
    return {"check": f"ssrf: {target_name} — {variant}", "status": None, "ok": True,
            "note": "Tidak ada request keluar ke canary — URL privat diblokir atau tidak dipakai.",
            "url": where, "kind": "ssrf"}


# ── sending ──────────────────────────────────────────────────────────────
def send_payload(sess, base, target, url, origin=None):
    """Send one URL to the target endpoint; return the status or None."""
    param, loc = target["param"], target.get("location", "query")
    full = base + target["path"]
    kw = {"timeout": 20, "allow_redirects": False}
    hdr = dict(target.get("headers") or {})
    if origin:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import _sanctum
        hdr.update(_sanctum.auth_headers(sess, origin))
    kw["headers"] = hdr
    extra = dict(target.get("extra") or {})
    if loc == "query":
        kw["params"] = {**extra, param: url}
    elif loc == "json":
        kw["json"] = {**extra, param: url}
    else:
        kw["data"] = {**extra, param: url}
    try:
        return sess.request(target.get("method", "GET"), full, **kw).status_code
    except Exception:  # noqa: BLE001
        return None


def run(cfg, canary=None, sess=None, sleep=time.sleep):
    base = cfg["base_url"].rstrip("/")
    cb = cfg.get("callback") or {}
    own = canary is None
    if own:
        canary = Canary(cb.get("bind", "0.0.0.0"), int(cb.get("port", 0))).start()
    public = cb.get("public_url") or f"http://127.0.0.1:{canary.port}"
    wait = float(cb.get("wait_seconds", 4))
    sess = sess or requests.Session()
    origin = None
    auth = cfg.get("auth") or {}
    if auth.get("header") and auth.get("value"):
        sess.headers[auth["header"]] = auth["value"]
    san = auth.get("sanctum") if (auth.get("sanctum") or {}).get("enabled") else None
    rows = []
    try:
        if san:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            import _sanctum
            origin = san.get("origin")
            _sanctum.prime_csrf(sess, base, san)
            lg = auth.get("login")
            if lg:
                r = sess.request(lg.get("method", "POST"), base + lg["path"],
                                 json=lg.get("body") or {},
                                 headers=_sanctum.auth_headers(sess, origin), timeout=20)
                if r.status_code >= 400:
                    raise RuntimeError(f"login gagal: HTTP {r.status_code}")
        for t in cfg.get("targets", []):
            name = t.get("name", t["path"])
            where = f"{t.get('method', 'GET')} {base}{t['path']} (param {t['param']})"
            for vname, tmpl in build_variants(public, "{token}", cfg.get("variants", True)):
                token = "k" + secrets.token_hex(6)           # unique token per request
                url = tmpl.replace("{token}", token)
                status = send_payload(sess, base, t, url, origin)
                if status is None:
                    rows.append({"check": f"ssrf: {name} — {vname}", "status": None, "ok": True,
                                 "note": "skip: endpoint tidak merespons.", "url": where,
                                 "kind": "ssrf"})
                    continue
                deadline = time.time() + wait
                while time.time() < deadline and not canary.hits_for(token):
                    sleep(0.2)
                sleep(0.3 if canary.hits_for(token) else 0)        # leave time for the second hop
                row = evaluate(name, vname, url, token, canary.hits_for(token), where)
                row["status"] = status
                rows.append(row)
    finally:
        if own:
            canary.stop()
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Uji SSRF berbasis canary lokal.")
    ap.add_argument("--config", default=str(Path(__file__).with_name("ssrf.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url") or not cfg.get("targets"):
        print("base_url dan targets wajib diisi di config.", file=sys.stderr)
        return 2
    try:
        results = run(cfg)
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
            json.dumps({"module": "ssrf", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
