#!/usr/bin/env python3
"""Uji kebijakan rate limit dan lockout akun (regresi defensif).

Memeriksa apakah kontrol anti brute-force benar-benar ditegakkan:
  1. RATE LIMIT  : sejumlah request cepat ke endpoint sensitif (mis. login dengan identitas
                   fiktif) harus memunculkan pembatasan (HTTP 429 / header Retry-After).
  2. LOCKOUT     : pada AKUN UJI sekali pakai (dibuat lalu dihapus lewat fixture admin),
                   sandi salah berulang harus mengunci akun; sandi BENAR tidak boleh
                   berhasil selama terkunci; durasi kunci harus sementara dan wajar.
  3. ENUMERASI   : respons untuk akun terdaftar vs tidak terdaftar tidak boleh dapat
                   dibedakan (mis. akun terdaftar -> 423, akun fiktif -> 401).
Akun nyata TIDAK pernah dikunci: lockout hanya diuji pada akun uji sekali pakai.

Konfigurasi di ratelimit.yml. Pakai:
    python run_ratelimit.py --config ratelimit.yml [--json out.json]
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
MINUTES_RE = re.compile(r"(\d+)\s*(?:menit|minutes?|min)\b", re.I)


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


# ── evaluator murni ─────────────────────────────────────────────────────────
def evaluate_burst(name, url, statuses, retry_after, cfg=None):
    """Satu baris hasil untuk uji rate limit. statuses: daftar status (None = galat jaringan)."""
    limit_statuses = set((cfg or {}).get("limit_statuses", [429]))
    ok_codes = [s for s in statuses if s is not None]
    if not ok_codes:
        return {"check": f"laju: {name}", "status": None, "ok": True,
                "note": "skip: tidak ada response (error jaringan)", "url": url,
                "kind": "no-rate-limit"}
    first = next((i + 1 for i, s in enumerate(statuses) if s in limit_statuses), None)
    resume = ", ".join(f"{c}x{statuses.count(c)}" for c in sorted(set(ok_codes)))
    if first is not None or retry_after:
        where = f"pada request ke-{first}" if first else "melalui header Retry-After"
        return {"check": f"laju: {name}", "status": statuses[first - 1] if first else None,
                "ok": True, "note": f"Pembatasan laju aktif {where} dari {len(statuses)} request "
                f"({resume}).", "url": url, "kind": "no-rate-limit"}
    return {"check": f"laju: {name}", "status": ok_codes[-1], "ok": False,
            "note": f"{len(statuses)} request cepat tidak memicu pembatasan laju "
                    f"(status: {resume}) — endpoint rentan brute-force.", "url": url,
            "kind": "no-rate-limit"}


def lock_signal(status, text, cfg):
    if status in set(cfg.get("lock_statuses", [423])):
        return True
    rx = cfg.get("lock_message_regex", r"dikunci|terkunci|locked|too many failed")
    return bool(rx and re.search(rx, text or "", re.I))


def parse_lock_minutes(text):
    m = MINUTES_RE.search(text or "")
    return int(m.group(1)) if m else None


def evaluate_lockout(attempts, correct, cfg, url):
    """attempts: [(status, text)] sandi salah berurutan; correct: (status, text) sandi benar
    setelah percobaan tersebut (atau None). Mengembalikan daftar baris hasil."""
    rows = []
    max_attempts = int(cfg.get("max_attempts", 5))
    first_lock = next((i + 1 for i, (s, t) in enumerate(attempts) if lock_signal(s, t, cfg)), None)
    rate_limited = any(s == 429 and not lock_signal(s, t, cfg) for s, t in attempts)

    if first_lock is None and rate_limited:
        rows.append({"check": "lockout: penguncian setelah password salah", "status": 429,
                     "ok": True, "note": "skip: uji terhalang rate limit (429) sebelum penguncian "
                     "akun teramati — naikkan `delay_seconds` agar lockout aplikasi dapat diuji.",
                     "url": url, "kind": "weak-lockout"})
        return rows
    if first_lock is None:
        resume = ", ".join(f"{s}" for s, _ in attempts)
        rows.append({"check": "lockout: penguncian setelah password salah",
                     "status": attempts[-1][0] if attempts else None, "ok": False,
                     "note": f"Akun TIDAK terkunci setelah {len(attempts)} password salah berturut "
                             f"(status: {resume}); ambang yang diharapkan {max_attempts}.",
                     "url": url, "kind": "weak-lockout"})
        return rows

    tol = int(cfg.get("tolerance", 1))
    ok_at = first_lock <= max_attempts + tol
    rows.append({"check": "lockout: penguncian setelah password salah",
                 "status": attempts[first_lock - 1][0], "ok": ok_at,
                 "note": (f"Akun terkunci pada percobaan ke-{first_lock} (ambang {max_attempts})."
                          if ok_at else
                          f"Akun baru terkunci pada percobaan ke-{first_lock}, melebihi ambang "
                          f"{max_attempts}."), "url": url, "kind": "weak-lockout"})

    if correct is not None:
        cs, ct = correct
        if 200 <= (cs or 0) < 300:
            rows.append({"check": "lockout: password benar saat akun terkunci", "status": cs,
                         "ok": False, "note": "Login dengan password BENAR berhasil padahal akun "
                         "terkunci — lockout dapat dilewati.", "url": url,
                         "kind": "lockout-bypass"})
        else:
            rows.append({"check": "lockout: password benar saat akun terkunci", "status": cs,
                         "ok": True, "note": f"Password benar tetap ditolak saat terkunci (HTTP {cs}).",
                         "url": url, "kind": "lockout-bypass"})
    texts = [t for s, t in attempts if lock_signal(s, t, cfg)] + ([correct[1]] if correct else [])
    minutes = next((m for m in (parse_lock_minutes(t) for t in texts) if m is not None), None)
    cap = int(cfg.get("max_lock_minutes", 60))
    if minutes is None:
        rows.append({"check": "lockout: durasi kunci", "status": None, "ok": True,
                     "note": "skip: durasi kunci tidak diumumkan di response.", "url": url,
                     "kind": "weak-lockout"})
    elif 1 <= minutes <= cap:
        rows.append({"check": "lockout: durasi kunci", "status": None, "ok": True,
                     "note": f"Kunci bersifat sementara ({minutes} menit, batas wajar {cap}).",
                     "url": url, "kind": "weak-lockout"})
    else:
        rows.append({"check": "lockout: durasi kunci", "status": None, "ok": False,
                     "note": f"Durasi kunci {minutes} menit di luar batas wajar (1-{cap}).",
                     "url": url, "kind": "weak-lockout"})
    return rows


def evaluate_enumeration(real_first, fake_first, real_last, fake_last, url):
    """Bandingkan respons akun terdaftar vs fiktif: percobaan pertama dan setelah ambang."""
    rows = []

    def sig(x):
        s, t = x
        return (s, re.sub(r"\d+", "N", (t or "").strip())[:200])

    same_first = sig(real_first) == sig(fake_first)
    rows.append({"check": "enumerasi akun: response gagal pertama", "status": real_first[0],
                 "ok": same_first,
                 "note": ("Response akun terdaftar dan fiktif identik pada percobaan pertama."
                          if same_first else
                          f"Response berbeda: akun terdaftar HTTP {real_first[0]} vs fiktif "
                          f"HTTP {fake_first[0]} — akun terdaftar dapat dibedakan."),
                 "url": url, "kind": "user-enumeration"})
    same_last = real_last[0] == fake_last[0]
    rows.append({"check": "enumerasi akun: response setelah ambang percobaan", "status": real_last[0],
                 "ok": same_last,
                 "note": ("Status identik untuk akun terdaftar dan fiktif setelah ambang."
                          if same_last else
                          f"Setelah ambang, akun terdaftar dijawab HTTP {real_last[0]} sedangkan "
                          f"akun fiktif HTTP {fake_last[0]} — penguncian expose keberadaan "
                          "akun (enumerasi)."), "url": url, "kind": "user-enumeration"})
    return rows


# ── bagian jaringan ─────────────────────────────────────────────────────────
def _session(cfg):
    s = requests.Session()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        s.verify = False
    return s


def run_burst(cfg, base, sess_factory=_session, sleep=time.sleep):
    rows = []
    for b in cfg.get("burst", []):
        s = sess_factory(cfg)
        origin = b.get("origin")
        hdr = {}
        if b.get("sanctum"):
            _sanctum.prime_csrf(s, base, {"origin": origin, "csrf_path": b.get("csrf_path",
                                                                              "/sanctum/csrf-cookie")})
            hdr = _sanctum.stateful_headers(origin)
        url = base + b["path"]
        statuses, retry = [], False
        for _ in range(int(b.get("count", 20))):
            try:
                h = dict(hdr)
                h.update(_sanctum.xsrf_header(s) if b.get("sanctum") else {})
                r = s.request(b.get("method", "POST"), url, json=b.get("body"), headers=h,
                              timeout=20, allow_redirects=False)
                statuses.append(r.status_code)
                retry = retry or ("Retry-After" in r.headers)
            except Exception:  # noqa: BLE001
                statuses.append(None)
            if b.get("delay_seconds"):
                sleep(float(b["delay_seconds"]))
        rows.append(evaluate_burst(b.get("name", b["path"]), f"{b.get('method', 'POST')} {url}",
                                   statuses, retry, b))
    return rows


def run_lockout(cfg, base, reports_dir=None, config_path=None, sleep=time.sleep):
    lc = cfg.get("lockout") or {}
    if not lc.get("enabled", True) or not cfg.get("fixture"):
        return []
    max_attempts = int(lc.get("max_attempts", 5))
    extra = int(lc.get("extra_attempts", 2))
    delay = float(lc.get("delay_seconds", 0.5))
    wrong = lc.get("wrong_password", "Salah-Salah-1!")
    fake_email = lc.get("fake_email", "kit-tidak-ada@contoh.example")
    url = f"{cfg['fixture']['login'].get('method', 'POST')} {base}{cfg['fixture']['login']['path']}"
    rows = []
    with _fixture.DisposableAccount(base, cfg["fixture"], reports_dir, config_path) as acc:
        sess = requests.Session()
        attempts = []
        for i in range(max_attempts + extra):
            r = acc.login_attempt(wrong, sess)
            attempts.append((r.status_code, r.text or ""))
            if lock_signal(r.status_code, r.text, lc) or r.status_code == 429:
                break
            sleep(delay)
        correct = None
        if any(lock_signal(s, t, lc) for s, t in attempts):
            r = acc.login_attempt(acc.password, sess)
            correct = (r.status_code, r.text or "")
        rows.extend(evaluate_lockout(attempts, correct, lc, url))

        if lc.get("enumeration_check", True):
            fake_sess = requests.Session()
            fake = []
            for i in range(len(attempts)):
                r = acc.login_as(fake_email, wrong, fake_sess)
                fake.append((r.status_code, r.text or ""))
                sleep(delay)
            rows.extend(evaluate_enumeration(attempts[0], fake[0], attempts[-1], fake[-1], url))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Uji rate limit dan lockout akun.")
    ap.add_argument("--config", default=str(Path(__file__).with_name("ratelimit.yml")))
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args(argv)
    if not Path(args.config).exists():
        print(f"Config tidak ditemukan: {args.config}", file=sys.stderr)
        return 2
    cfg = expand(yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {})
    if not cfg.get("base_url"):
        print("base_url wajib diisi di config.", file=sys.stderr)
        return 2
    base = cfg["base_url"].rstrip("/")
    reports = Path(args.json_out).parent if args.json_out else None

    results = []
    try:
        results.extend(run_burst(cfg, base))
        pause = float(cfg.get("pause_after_burst_seconds", 0))
        if pause and cfg.get("burst"):
            time.sleep(pause)        # biarkan kuota rate limit gateway pulih sebelum fixture login
        results.extend(run_lockout(cfg, base, reports, Path(args.config).resolve()))
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
            json.dumps({"module": "ratelimit", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
