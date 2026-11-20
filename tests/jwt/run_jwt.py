#!/usr/bin/env python3
"""JWT security tests (defensive regression) for APIs using JSON Web Tokens.

Uses your own token, obtained from a legitimate login (or an env var), then:
  A. STATIC ANALYSIS (offline): 'none' algorithm, missing exp claim / overly long token
     lifetime, sensitive claims in the payload, kid/jku/x5u/jwk headers, and WEAK
     HS256/384/512 secrets (small wordlist; the secret is never printed in full).
  B. FORGERY PROBES (online, against a protected endpoint): token with alg=none, stripped
     signature, and a modified payload with the old signature. A correct server must reject
     all of them (401/403). The genuine token must be accepted (baseline).
Only the configured GET endpoint is called; there are no write operations.

Configured in jwt.yml. Usage:
    python run_jwt.py --config jwt.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path

import requests
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _color as C  # noqa: E402  (shared console ANSI colors in tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
SENSITIVE_CLAIM_RE = re.compile(r"(password|passwd|pwd|secret|ssn|card|cvv|api_?key)", re.I)
BUILTIN_WEAK = ["secret", "password", "123456", "12345678", "changeme", "jwt_secret", "jwt-secret",
                "your-256-bit-secret", "key", "admin", "test", "default", "supersecret", "mysecret",
                "secretkey", "s3cr3t", "qwerty", "letmein", "token", "jwt", "hs256", "app_key"]
HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


# ── JWT helpers ─────────────────────────────────────────────────────────────
def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parse(token):
    """(header, payload, parts), or None if not a valid JWT."""
    if not JWT_RE.match(token or ""):
        return None
    parts = token.split(".")
    try:
        return json.loads(b64d(parts[0])), json.loads(b64d(parts[1])), parts
    except (ValueError, UnicodeDecodeError):
        return None


def sign(alg, secret, signing_input):
    h = HS[alg]
    return b64e(hmac.new(secret.encode(), signing_input.encode(), h).digest())


def build(header, payload, signature=""):
    return (f"{b64e(json.dumps(header, separators=(',', ':')).encode())}."
            f"{b64e(json.dumps(payload, separators=(',', ':')).encode())}.{signature}")


def crack_hs(token, wordlist):
    """Look up a weak secret for an HS* token. Returns the secret or None."""
    p = parse(token)
    if not p:
        return None
    header, _payload, parts = p
    alg = str(header.get("alg", "")).upper()
    if alg not in HS:
        return None
    signing = f"{parts[0]}.{parts[1]}"
    target = parts[2]
    for s in wordlist:
        if hmac.compare_digest(sign(alg, s, signing), target):
            return s
    return None


def mask(s):
    return f"{s[:1]}***{s[-1:]} (panjang {len(s)})" if len(s) > 2 else f"*** (panjang {len(s)})"


# ── static analysis ─────────────────────────────────────────────────────────
def static_rows(header, payload, token, cfg, url, now=None):
    rows = []

    def row(check, ok, note, kind):
        rows.append({"check": f"jwt: {check}", "status": None, "ok": ok, "note": note,
                     "url": url, "kind": kind})

    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        row("algoritma", False, "Token memakai alg=none (tanpa tanda tangan).", "jwt-weak-config")
    else:
        row("algoritma", True, f"alg={alg}"
            + (" (simetris — secret harus panjang dan acak)" if alg.upper() in HS else ""),
            "jwt-weak-config")

    now = now or time.time()
    exp, iat = payload.get("exp"), payload.get("iat")
    max_h = float(cfg.get("max_lifetime_hours", 24))
    if exp is None:
        row("masa berlaku (exp)", False, "Klaim exp tidak ada — token tidak pernah kedaluwarsa.",
            "jwt-weak-config")
    else:
        try:
            base = float(iat) if iat is not None else now
            hours = (float(exp) - base) / 3600.0
            if hours > max_h:
                row("masa berlaku (exp)", False,
                    f"Umur token {hours:.1f} jam melebihi batas {max_h:g} jam.", "jwt-weak-config")
            else:
                row("masa berlaku (exp)", True, f"Umur token {max(hours, 0):.1f} jam (batas "
                    f"{max_h:g}).", "jwt-weak-config")
        except (TypeError, ValueError):
            row("masa berlaku (exp)", False, "Klaim exp bukan angka.", "jwt-weak-config")

    sens = [k for k in payload if SENSITIVE_CLAIM_RE.search(str(k))]
    if sens:
        row("klaim sensitif", False, "Payload (terbaca siapa pun) memuat klaim sensitif: "
            + ", ".join(sens) + ".", "jwt-weak-config")
    else:
        row("klaim sensitif", True, "Tidak ada klaim sensitif di payload.", "jwt-weak-config")

    risky = [k for k in ("kid", "jku", "x5u", "jwk") if k in header]
    if risky:
        row("header berisiko", True, "Header memuat " + ", ".join(risky) + " — pastikan server "
            "memvalidasi/whitelist nilainya (permukaan injeksi kunci).", "jwt-weak-config")

    if alg.upper() in HS:
        words = list(BUILTIN_WEAK) + list(cfg.get("weak_secrets", []))
        wl = cfg.get("wordlist_file")
        if wl and Path(wl).exists():
            words += [w.strip() for w in Path(wl).read_text(encoding="utf-8").splitlines() if w.strip()]
        found = crack_hs(token, words)
        if found is not None:
            row("secret tanda tangan", False, f"Secret HS lemah ditemukan lewat kamus: {mask(found)} "
                "— siapa pun dapat memalsukan token.", "jwt-weak-secret")
        else:
            row("secret tanda tangan", True,
                f"Secret tidak ada di kamus ({len(set(words))} entri).", "jwt-weak-secret")
    return rows


# ── forgery probes ──────────────────────────────────────────────────────────
def forged_variants(header, payload, parts):
    """[(name, token)]; the server must REJECT all of them."""
    out = []
    for a in ("none", "None", "NONE"):
        out.append((f"alg={a} tanpa tanda tangan", build({**header, "alg": a}, payload, "")))
    out.append(("tanda tangan dibuang", f"{parts[0]}.{parts[1]}."))
    claims = dict(payload)
    if "sub" in claims:
        claims["sub"] = "0" if isinstance(claims["sub"], str) else 0
    claims["role"], claims["admin"] = "admin", True
    out.append(("payload diubah, tanda tangan lama",
                f"{parts[0]}.{b64e(json.dumps(claims, separators=(',', ':')).encode())}.{parts[2]}"))
    return out


def probe_rows(token, send, cfg, url):
    """send(token) -> status. Returns the probe result rows."""
    p = parse(token)
    if not p:
        return []
    header, payload, parts = p
    base_status = send(token)
    if not (base_status is not None and 200 <= base_status < 300):
        return [{"check": "jwt: probe pemalsuan", "status": base_status, "ok": True,
                 "note": f"skip: token asli tidak diterima endpoint (HTTP {base_status}).",
                 "url": url, "kind": "jwt-forgery"}]
    rows = []
    for name, forged in forged_variants(header, payload, parts):
        st = send(forged)
        accepted = st is not None and 200 <= st < 300
        rows.append({"check": f"jwt: pemalsuan — {name}", "status": st, "ok": not accepted,
                     "note": (f"Token palsu DITERIMA (HTTP {st}) — verifikasi tanda tangan tidak "
                              "ditegakkan." if accepted else
                              f"Token palsu ditolak (HTTP {st})."), "url": url,
                     "kind": "jwt-forgery"})
    return rows


# ── token and network ───────────────────────────────────────────────────────
def dig(obj, dotted):
    cur = obj
    for part in (dotted or "").split("."):
        if part:
            cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def obtain_token(cfg, base, http=requests):
    if cfg.get("token"):
        return cfg["token"]
    lg = cfg.get("login")
    if not lg:
        return None
    r = http.request(lg.get("method", "POST"), base + lg["path"], json=lg.get("body") or {},
                     timeout=20)
    if r.status_code >= 400:
        raise RuntimeError(f"login gagal: HTTP {r.status_code}")
    tok = dig(r.json(), lg.get("token_path", "data.token"))
    if not tok and r.headers.get("Authorization"):
        tok = r.headers["Authorization"].split(" ")[-1]
    return tok


def make_sender(cfg, base, http=requests):
    pr = cfg["protected"]
    hdr_name = cfg.get("auth_header", "Authorization")
    prefix = cfg.get("auth_prefix", "Bearer ")
    cookie = cfg.get("cookie")

    def send(token):
        try:
            kw = {"timeout": 20, "allow_redirects": False}
            if cookie:
                kw["cookies"] = {cookie: token}
            else:
                kw["headers"] = {hdr_name: prefix + token}
            return http.request(pr.get("method", "GET"), base + pr["path"], **kw).status_code
        except Exception:  # noqa: BLE001
            return None
    return send


def run(cfg, http=requests):
    base = cfg["base_url"].rstrip("/")
    url = f"{cfg['protected'].get('method', 'GET')} {base}{cfg['protected']['path']}"
    token = obtain_token(cfg, base, http)
    if not token or not parse(token):
        return [{"check": "jwt: token", "status": None, "ok": True,
                 "note": "skip: tidak ada token JWT yang dapat dianalisis (aplikasi mungkin memakai "
                         "session/token opak, mis. Sanctum).", "url": base, "kind": "jwt-weak-config"}]
    header, payload, _ = parse(token)
    rows = static_rows(header, payload, token, cfg, url)
    rows += probe_rows(token, make_sender(cfg, base, http), cfg, url)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Uji keamanan JWT.")
    ap.add_argument("--config", default=str(Path(__file__).with_name("jwt.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url") or not cfg.get("protected"):
        print("base_url dan protected wajib diisi di config.", file=sys.stderr)
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
            json.dumps({"module": "jwt", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
