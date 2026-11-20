#!/usr/bin/env python3
"""Cakupan autentikasi berdasarkan spesifikasi OpenAPI (non-destruktif).

Membaca spesifikasi OpenAPI 3.x (URL atau berkas), memetakan tiap operasi apakah spesifikasi
mendeklarasikan autentikasi (`security`), lalu — HANYA untuk operasi GET — mengirim request
ANONIM (tanpa kredensial) dan membandingkannya:
  - dilindungi menurut spesifikasi tetapi TERBUKA tanpa login        -> celah penegakan auth
  - tidak mendeklarasikan auth, bukan allowlist publik, dan terbuka   -> perlu ditinjau
  - tidak mendeklarasikan auth tetapi sebenarnya menolak anonim       -> spesifikasi tak akurat
Operasi tulis (POST/PUT/PATCH/DELETE) TIDAK pernah dikirim — hanya dianalisis statis.

Konfigurasi di openapi_coverage.yml. Pakai:
    python run_openapi_coverage.py --config openapi_coverage.yml [--json out.json]
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
import _color as C  # noqa: E402  (warna ANSI konsol lintas-modul di tests/)

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
DEFAULT_PUBLIC = ["/login", "/register", "/captcha", "/forgot-password", "/reset-password",
                  "/health", "/up", "/docs", "/csrf-cookie", "/two-factor", "/email/verify",
                  "/auth/claim-email", "/metrics"]
PLACEHOLDER_ID = "00000000000000000000000000"


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def load_spec(src, sess=None):
    """Muat spesifikasi dari URL atau berkas (JSON/YAML)."""
    if re.match(r"^https?://", src or ""):
        r = (sess or requests).get(src, timeout=30)
        r.raise_for_status()
        text = r.text
    else:
        text = Path(src).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        return yaml.safe_load(text)


def is_protected(security):
    """True bila daftar 'security' mewajibkan autentikasi (tidak kosong, tak ada requirement {})."""
    if not security:
        return False
    return not any(isinstance(req, dict) and not req for req in security)


def operations(spec):
    """Daftar operasi: {method, path, declared(bool), explicit_public(bool)}."""
    global_sec = spec.get("security")
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for m in HTTP_METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            if "security" in op:
                sec, explicit = op["security"], True
            else:
                sec, explicit = global_sec, False
            ops.append({"method": m.upper(), "path": path,
                        "declared": is_protected(sec),
                        "explicit_public": explicit and not is_protected(sec)})
    return ops


def is_public_allowed(path, allowlist):
    low = path.lower()
    return any(a.lower() in low for a in allowlist)


def fill_path(path, params):
    def sub(m):
        name = m.group(1)
        if name in params:
            return str(params[name])
        return PLACEHOLDER_ID if re.search(r"(id|uuid|ulid)$", name, re.I) else "x"
    return re.sub(r"\{([^}]+)\}", sub, path)


def classify(status):
    """Hasil probe anonim -> 'enforced' | 'open' | 'error' | 'inconclusive'."""
    if status in (401, 403):
        return "enforced"
    if status is not None and 200 <= status < 300:
        return "open"
    if status is not None and status >= 500:
        return "error"
    return "inconclusive"


def analyze(ops, send, cfg, label=""):
    """Jalankan probe anonim untuk operasi GET. `send(url)` -> status int / None.

    Mengembalikan daftar baris hasil. (Inti murni — `send` diinjeksi agar mudah diuji.)"""
    allow = cfg.get("public_allowlist", DEFAULT_PUBLIC)
    params = cfg.get("path_params", {})
    max_req = int(cfg.get("max_requests", 400))
    delay = float(cfg.get("delay_seconds", 0))
    base = cfg["base_url"].rstrip("/")
    tag = f"[{label}] " if label else ""
    rows = []

    total = len(ops)
    declared = sum(1 for o in ops if o["declared"])
    gets = [o for o in ops if o["method"] == "GET"]
    rows.append({"check": f"{tag}cakupan spesifikasi", "status": None, "ok": True,
                 "note": f"{total} operasi: {declared} mendeklarasikan security, "
                         f"{total - declared} tanpa deklarasi; {len(gets)} operasi GET diuji "
                         "secara dinamis (operasi tulis tidak dikirim).",
                 "url": base, "kind": "spec-mismatch"})

    enforced = open_ok = inconclusive = sent = 0
    mismatch = []                      # tak dideklarasikan, tetapi menolak anonim
    pub_mismatch = []                  # publik (allowlist), tetapi spesifikasi bilang terlindungi
    errors = []                        # galat 5xx pada request anonim
    for o in gets:
        if sent >= max_req:
            break
        url = base + fill_path(o["path"], params)
        status = send(url)
        sent += 1
        if delay:
            time.sleep(delay)
        res = classify(status)
        where = f"GET {url}"
        if res == "enforced":
            enforced += 1
            if not o["declared"] and not o["explicit_public"]:
                mismatch.append(o["path"])
        elif res == "open":
            if o["declared"] and is_public_allowed(o["path"], allow):
                # Publik by design (allowlist) tetapi spesifikasi mewajibkan auth -> dokumentasi keliru.
                pub_mismatch.append(o["path"])
                open_ok += 1
            elif o["declared"]:
                rows.append({"check": f"{tag}GET {o['path']}: dilindungi menurut spesifikasi "
                                      "tetapi terbuka", "status": status, "ok": False,
                             "note": "Spesifikasi mewajibkan autentikasi, namun request anonim "
                                     f"dijawab HTTP {status}.", "url": where,
                             "kind": "auth-coverage-gap"})
            elif is_public_allowed(o["path"], allow):
                open_ok += 1
            else:
                rows.append({"check": f"{tag}GET {o['path']}: terbuka tanpa autentikasi",
                             "status": status, "ok": False,
                             "note": "Tidak mendeklarasikan security, tidak ada di allowlist "
                                     f"publik, dan request anonim dijawab HTTP {status} — "
                                     "tinjau apakah memang publik.", "url": where,
                             "kind": "unauthenticated-endpoint"})
        elif res == "error":
            errors.append((o["path"], status, where))
        else:
            inconclusive += 1

    rows.append({"check": f"{tag}penegakan autentikasi (GET)", "status": None, "ok": True,
                 "note": f"{sent} request anonim: {enforced} ditolak 401/403, "
                         f"{open_ok} publik (allowlist), {inconclusive} tak dapat dipastikan "
                         f"(404/405/422 dll.), {len(errors)} error 5xx.", "url": base,
                 "kind": "auth-coverage-gap"})
    if pub_mismatch:
        sample = ", ".join(pub_mismatch[:8]) + (" ..." if len(pub_mismatch) > 8 else "")
        rows.append({"check": f"{tag}spesifikasi tak akurat: endpoint publik dideklarasikan "
                              "terlindungi", "status": None, "ok": False,
                     "note": f"{len(pub_mismatch)} operasi GET publik (allowlist) memakai "
                             f"security global di spesifikasi padahal terbuka tanpa login: "
                             f"{sample}. Tandai dengan `security: []`.", "url": base,
                     "kind": "spec-mismatch"})
    for path, st, where in errors:
        rows.append({"check": f"{tag}GET {path}: error server pada request anonim",
                     "status": st, "ok": False,
                     "note": f"Request anonim memicu HTTP {st} — kemungkinan validasi/penanganan "
                             "error belum ditegakkan sebelum autentikasi.", "url": where,
                     "kind": "anon-server-error"})
    if mismatch:
        sample = ", ".join(mismatch[:8]) + (" ..." if len(mismatch) > 8 else "")
        rows.append({"check": f"{tag}spesifikasi tak akurat: auth tak dideklarasikan",
                     "status": None, "ok": False,
                     "note": f"{len(mismatch)} operasi GET tidak mendeklarasikan security di "
                             f"spesifikasi tetapi menolak anonim (dokumentasi tidak akurat): "
                             f"{sample}", "url": base, "kind": "spec-mismatch"})
    return rows


def run_spec(spec_cfg, sess=None):
    """Satu spesifikasi: muat -> analisis -> baris hasil."""
    cfg = dict(spec_cfg)
    sess = sess or requests.Session()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        sess.verify = False
    spec = load_spec(cfg["openapi"], sess)
    if not cfg.get("base_url"):
        servers = spec.get("servers") or []
        if not servers:
            raise ValueError("base_url tidak diset dan spesifikasi tak punya 'servers'.")
        cfg["base_url"] = servers[0].get("url", "")
    anon = requests.Session()
    anon.verify = sess.verify
    retried = {"n": 0}

    def send(url):
        try:
            r = anon.get(url, timeout=20, allow_redirects=False)
            if r.status_code == 429 and retried["n"] < 20:        # backoff sekali
                retried["n"] += 1
                time.sleep(2)
                r = anon.get(url, timeout=20, allow_redirects=False)
            return r.status_code
        except Exception:  # noqa: BLE001
            return None

    return analyze(operations(spec), send, cfg, cfg.get("name", ""))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cakupan autentikasi berbasis OpenAPI.")
    ap.add_argument("--config",
                    default=str(Path(__file__).with_name("openapi_coverage.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    specs = cfg.get("specs") or ([cfg] if cfg.get("openapi") else [])
    if not specs:
        print("Isi 'openapi' (atau daftar 'specs') di config.", file=sys.stderr)
        return 2

    results = []
    for sc in specs:
        merged = {**{k: v for k, v in cfg.items() if k != "specs"}, **sc}
        try:
            results.extend(run_spec(merged))
        except Exception as exc:  # noqa: BLE001
            results.append({"check": f"{sc.get('name', 'spec')}: muat spesifikasi",
                            "status": -1, "ok": True, "note": f"skip: {exc}",
                            "url": sc.get("openapi", ""), "kind": "spec-mismatch"})
    failures = sum(1 for r in results if not r["ok"])
    for r in results:
        print(f"[{C.tag('PASS' if r['ok'] else 'FAIL')}] {r['check']} — {r['note']}")
    print(f"\n{len(results)} baris, {failures} temuan.")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps({"module": "openapi-coverage", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
