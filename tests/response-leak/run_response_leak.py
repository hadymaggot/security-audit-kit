#!/usr/bin/env python3
"""Deteksi kebocoran data di respons API (pasif, hanya GET).

Untuk tiap endpoint yang dikonfigurasi, respons dipindai untuk:
  - kunci JSON sensitif yang berisi nilai (password, secret, api_key, token akses,
    two_factor_secret, recovery_codes, ...). NILAI TIDAK PERNAH dicetak ke laporan —
    hanya path kunci dan panjang nilai.
  - pola secret di isi respons (AWS key, private key, token GitHub/Slack/Google).
  - jejak debug / stack trace / pesan SQL pada respons (terutama respons error).
  - alamat IP internal (RFC1918) atau hostname internal yang bocor.
Tambahan: probe error (path acak -> 404, dsb.) untuk memeriksa halaman error verbose.

Konfigurasi di response_leak.yml. Pakai:
    python run_response_leak.py --config response_leak.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _sanctum  # noqa: E402
import _color as C  # noqa: E402  (warna ANSI konsol lintas-modul di tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
MAX_BODY = 2_000_000

# Kunci yang dianggap sensitif (substring, huruf kecil). Kunci berakhiran _at/_confirmation dll.
# dikecualikan karena umumnya metadata (timestamp/flag), bukan nilai rahasia.
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|api_?key|private_?key|access_?token|refresh_?token|"
    r"remember_?token|recovery_codes|cvv|card_?number)")
KEY_SAFE_SUFFIX = ("_at", "_confirmation", "_required", "_policy", "_version", "_expires",
                   "_enabled", "_set", "_changed", "_length", "_hint")
MASKED_RE = re.compile(r"^[\*•xX#\.\-]{3,}$|^\[?redacted\]?$|^<hidden>$", re.I)

SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "token GitHub": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "token Slack": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "API key Google": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
}
DEBUG_MARKERS = [
    ("stack trace", re.compile(r"Stack trace:|Traceback \(most recent call last\)|"
                               r"\bat [A-Za-z_$][\w$.]*\([\w.]+:\d+\)")),
    ("path berkas server", re.compile(r"(?:/var/www|/app/|/home/\w+/|[A-Z]:\\\\?[\w\\ ]+)"
                                      r"[\w/\\.\-]*\.(?:php|py|rb|js|java)(?::\d+| on line \d+)?")),
    ("kerangka debug", re.compile(r"Whoops!|APP_DEBUG|Illuminate\\\\|vendor/laravel|"
                                  r"Symfony\\\\Component|django\.core|werkzeug", re.I)),
    ("pesan SQL", re.compile(r"SQLSTATE\[|PDOException|QueryException|syntax error at or near|"
                             r"You have an error in your SQL syntax|ORA-\d{5}", re.I)),
]
INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def walk_json(obj, path=""):
    """Yield (path, key, value) untuk setiap pasangan kunci/nilai pada JSON bersarang."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, str(k), v
            yield from walk_json(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):               # batasi agar respons besar tak berat
            yield from walk_json(v, f"{path}[{i}]")


def _is_secretish_value(v):
    if v is None or isinstance(v, bool):
        return False
    if isinstance(v, (dict, list)):
        return bool(v)                                   # objek/array berisi = ada data
    s = str(v).strip()
    return bool(s) and not MASKED_RE.match(s)


def find_sensitive_keys(data, cfg):
    """[(path, panjang_nilai)] untuk kunci sensitif yang berisi nilai."""
    allow = {a.lower() for a in cfg.get("allow_keys", [])}
    extra = [e.lower() for e in cfg.get("sensitive_keys", [])]
    out = []
    for path, key, val in walk_json(data):
        k = key.lower()
        if k in allow:
            continue
        hit = bool(SENSITIVE_KEY_RE.search(k)) and not k.endswith(KEY_SAFE_SUFFIX)
        hit = hit or any(e == k for e in extra)
        if hit and _is_secretish_value(val):
            n = len(json.dumps(val)) if isinstance(val, (dict, list)) else len(str(val))
            out.append((path, n))
    return out


def find_secret_patterns(text):
    return [name for name, rx in SECRET_PATTERNS.items() if rx.search(text or "")]


def find_debug(text):
    return [name for name, rx in DEBUG_MARKERS if rx.search(text or "")]


def find_internal_ips(text):
    return sorted(set(INTERNAL_IP_RE.findall(text or "")))[:5]


def evaluate_response(name, method, url, status, body, content_type, cfg, is_probe=False):
    """Periksa satu respons -> daftar baris hasil. (Pure — tanpa jaringan.)"""
    rows = []
    where = f"{method} {url}"

    def row(check, ok, note, kind):
        rows.append({"check": f"{name}: {check}", "status": status, "ok": ok,
                     "note": note, "url": where, "kind": kind})

    text = body if isinstance(body, str) else ""
    data = None
    if "json" in (content_type or "").lower() or text.lstrip()[:1] in ("{", "["):
        try:
            data = json.loads(text)
        except ValueError:
            data = None

    # 1) kunci JSON sensitif (hanya untuk respons data, bukan probe error)
    if data is not None and not is_probe:
        hits = find_sensitive_keys(data, cfg)
        if hits:
            desc = "; ".join(f"{p} (panjang nilai {n})" for p, n in hits[:6])
            row("kunci sensitif", False,
                f"{len(hits)} kunci sensitif berisi nilai di respons: {desc}. "
                "Nilai tidak dicantumkan.", "sensitive-data-exposure")
        else:
            row("kunci sensitif", True, "Tidak ada kunci sensitif berisi nilai.",
                "sensitive-data-exposure")

    # 2) pola secret pada isi respons
    pats = find_secret_patterns(text)
    if pats:
        row("pola secret", False, "Pola secret terdeteksi di isi respons: "
            + ", ".join(pats) + ". Nilai tidak dicantumkan.", "sensitive-data-exposure")
    elif not is_probe:
        row("pola secret", True, "Tidak ada pola secret di isi respons.",
            "sensitive-data-exposure")

    # 3) jejak debug/verbose
    dbg = find_debug(text)
    if dbg:
        row("respons verbose/debug", False, "Jejak debug di respons: " + ", ".join(dbg)
            + " — detail implementasi server terekspos.", "verbose-error")
    else:
        row("respons verbose/debug", True,
            "Tidak ada jejak debug/stack trace." if not is_probe
            else f"Respons error (HTTP {status}) tidak membocorkan detail implementasi.",
            "verbose-error")

    # 4) alamat IP internal
    if cfg.get("check_internal_ips", True):
        ips = find_internal_ips(text)
        if ips:
            row("alamat internal", False, "Alamat IP internal di respons: "
                + ", ".join(ips), "internal-info-leak")
    return rows


def _session(cfg):
    s = requests.Session()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        s.verify = False
    auth = cfg.get("auth") or {}
    base = cfg["base_url"].rstrip("/")
    san = auth.get("sanctum") if (auth.get("sanctum") or {}).get("enabled") else None
    sanctum_h = {}
    if auth.get("header") and auth.get("value"):
        s.headers[auth["header"]] = auth["value"]
    if san:
        sanctum_h = _sanctum.prime_csrf(s, base, san)
        login = auth.get("login")
        if login:
            r = s.request(login.get("method", "POST"), base + login["path"],
                          json=login.get("body") or {},
                          headers=_sanctum.auth_headers(s, san.get("origin")), timeout=20)
            if r.status_code >= 400:
                raise RuntimeError(f"login gagal: HTTP {r.status_code}")
    return s, (san or {}).get("origin") if san else None


def run_checks(cfg, sess=None, anon=None):
    base = cfg["base_url"].rstrip("/")
    if sess is None:
        sess, origin = _session(cfg)
    else:
        origin = None
    anon = anon or requests.Session()
    results = []

    def fetch(sx, path, stateful=False):
        # Sanctum SPA: Origin/Referer wajib di SETIAP request agar sesi cookie dianggap stateful.
        hdr = _sanctum.stateful_headers(origin) if (stateful and origin) else {}
        r = sx.get(base + path, headers=hdr, timeout=20, allow_redirects=False)
        return r.status_code, (r.text or "")[:MAX_BODY], r.headers.get("Content-Type", "")

    for ep in cfg.get("endpoints", []):
        name = ep.get("name", ep["path"])
        use = anon if ep.get("anonymous") else sess
        try:
            status, body, ctype = fetch(use, ep["path"], stateful=(use is sess))
        except Exception as exc:  # noqa: BLE001
            results.append({"check": f"{name}: akses endpoint", "status": -1, "ok": True,
                            "note": f"skip: {exc}", "url": f"GET {base}{ep['path']}",
                            "kind": "sensitive-data-exposure"})
            continue
        if status >= 400 and ep.get("expect_error") is not True and status in (401, 403, 404):
            results.append({"check": f"{name}: akses endpoint", "status": status, "ok": True,
                            "note": f"skip: HTTP {status} (endpoint tak dapat diakses oleh sesi ini)",
                            "url": f"GET {base}{ep['path']}", "kind": "sensitive-data-exposure"})
            # tetap periksa halaman error untuk jejak debug
            results.extend(evaluate_response(name, "GET", base + ep["path"], status, body, ctype,
                                             cfg, is_probe=True))
            continue
        results.extend(evaluate_response(name, "GET", base + ep["path"], status, body, ctype, cfg))

    # probe error: path acak -> 404, dan path khusus dari config
    probes = list(cfg.get("error_probes", []))
    if cfg.get("random_404_probe", True):
        probes.append(f"/{uuid.uuid4().hex[:12]}")
        probes.append(f"/api/{uuid.uuid4().hex[:12]}")
    for p in probes:
        try:
            status, body, ctype = fetch(anon, p)
        except Exception as exc:  # noqa: BLE001
            results.append({"check": f"probe error {p}: akses", "status": -1, "ok": True,
                            "note": f"skip: {exc}", "url": f"GET {base}{p}", "kind": "verbose-error"})
            continue
        results.extend(evaluate_response(f"probe error {p}", "GET", base + p, status, body,
                                         ctype, cfg, is_probe=True))
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deteksi kebocoran data di respons API (pasif).")
    ap.add_argument("--config", default=str(Path(__file__).with_name("response_leak.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url"):
        print("base_url wajib diisi di config.", file=sys.stderr)
        return 2
    try:
        results = run_checks(cfg)
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
            json.dumps({"module": "response-leak", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
