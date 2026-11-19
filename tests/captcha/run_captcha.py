#!/usr/bin/env python3
"""Deteksi kebocoran jawaban pada captcha (analisis statis, non-destruktif).

Mengambil tantangan captcha (GET) lalu memeriksa apakah RESPONS-nya sendiri sudah membocorkan
jawabannya sehingga captcha dapat dilewati tanpa "melihat" gambar:
  1. kunci JSON bernama answer/solution/target/expected/x_position/... yang berisi angka;
  2. captcha slider berbasis SVG: offset `translate(-X,-Y)` pada lapisan puzzle (dan
     `translate(X,Y)` pada latar) mengungkap posisi target X, terutama bila Y sama dengan
     `y_position` yang memang dikirim ke klien;
  3. posisi target yang tetap (tidak acak) antar tantangan.
Modul ini TIDAK menyelesaikan atau mengirim jawaban captcha — hanya menganalisis tantangan.

Konfigurasi di captcha.yml. Pakai:
    python run_captcha.py --config captcha.yml [--json out.json]
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
ANSWER_KEY_RE = re.compile(r"(answer|solution|jawaban|expected|correct|target|gap_?x|x_?pos(ition)?)",
                           re.I)
SAFE_KEY_RE = re.compile(r"(width|height|size|y_?pos|captcha_?key|token|id$|message)", re.I)
TRANSLATE_RE = re.compile(r"translate\(\s*(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)\s*\)")


def expand(v):
    if isinstance(v, str):
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, str(k), v
            yield from walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            yield from walk(v, f"{path}[{i}]")


def find_answer_keys(data):
    """[(path, nilai)] kunci yang tampak seperti jawaban dan berisi angka."""
    out = []
    for path, key, val in walk(data):
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            continue
        if ANSWER_KEY_RE.search(key) and not SAFE_KEY_RE.search(key):
            out.append((path, val))
    return out


def decode_svg_layers(data):
    """{path: teks_svg} untuk string base64/data-URI/mentah yang berisi SVG."""
    layers = {}
    for path, _key, val in walk(data):
        if not isinstance(val, str) or len(val) < 40:
            continue
        txt = None
        s = val.split(",", 1)[1] if val.startswith("data:") and "," in val else val
        if "<svg" in s:
            txt = s
        else:
            try:
                dec = base64.b64decode(s, validate=False).decode("utf-8", "ignore")
                if "<svg" in dec:
                    txt = dec
            except (binascii.Error, ValueError):
                txt = None
        if txt:
            layers[path] = txt
    return layers


def translates(svg_text):
    return [(float(x), float(y)) for x, y in TRANSLATE_RE.findall(svg_text or "")]


def find_translate_leak(layers, data):
    """Cari pasangan translate(-X,-Y) pada satu lapisan dan translate(X,Y) pada lapisan lain
    (atau Y == salah satu nilai numerik di respons, mis. y_position). Return daftar kandidat."""
    numbers = {float(v) for _p, _k, v in walk(data)
               if isinstance(v, (int, float)) and not isinstance(v, bool)}
    img_w = next((float(v) for _p, k, v in walk(data)
                  if re.search(r"image_?width|^width$", k, re.I) and isinstance(v, (int, float))),
                 None)
    pos = {p: translates(t) for p, t in layers.items()}
    found = []
    for p_neg, lst in pos.items():
        for x, y in lst:
            if x >= 0 or y > 0:                       # kandidat lapisan puzzle: offset negatif
                continue
            cx, cy = -x, -y
            if cx <= 0 or (img_w and cx > img_w):
                continue
            counter = [q for q, other in pos.items() if q != p_neg and (cx, cy) in other]
            y_matches = cy in numbers
            if counter or y_matches:
                found.append({"x": cx, "y": cy, "layer": p_neg, "mirror": counter,
                              "y_position": y_matches})
    return found


def analyze_challenge(data):
    """Baris hasil untuk satu tantangan (pure)."""
    rows = []
    keys = find_answer_keys(data)
    if keys:
        rows.append({"check": "kunci jawaban di respons", "status": 200, "ok": False,
                     "note": "Respons memuat kunci yang tampak seperti jawaban: "
                             + ", ".join(f"{p}={v}" for p, v in keys[:5]) + ".",
                     "url": "", "kind": "captcha-answer-leak"})
    else:
        rows.append({"check": "kunci jawaban di respons", "status": 200, "ok": True,
                     "note": "Tidak ada kunci jawaban eksplisit di respons.", "url": "",
                     "kind": "captcha-answer-leak"})

    layers = decode_svg_layers(data)
    leaks = find_translate_leak(layers, data)
    if leaks:
        l = leaks[0]
        mirror = (f" dan translate({l['x']:g},{l['y']:g}) pada {', '.join(l['mirror'])}"
                  if l["mirror"] else "")
        ypos = f"; Y={l['y']:g} sama dengan y_position yang dikirim" if l["y_position"] else ""
        rows.append({"check": "SVG membocorkan posisi target", "status": 200, "ok": False,
                     "note": f"Offset translate(-{l['x']:g},-{l['y']:g}) pada lapisan "
                             f"'{l['layer']}'{mirror}{ypos} — posisi target X={l['x']:g} dapat "
                             "dibaca langsung dari SVG tanpa melihat gambar.",
                     "url": "", "kind": "captcha-answer-leak", "x": l["x"]})
    else:
        rows.append({"check": "SVG membocorkan posisi target", "status": 200, "ok": True,
                     "note": f"Tidak ditemukan offset yang membocorkan posisi pada "
                             f"{len(layers)} lapisan SVG." if layers else
                             "Tidak ada lapisan SVG untuk dianalisis.",
                     "url": "", "kind": "captcha-answer-leak"})
    return rows


def evaluate_randomness(xs):
    """xs: daftar posisi target hasil bocor dari beberapa tantangan."""
    if len(xs) < 2:
        return None
    if len(set(xs)) == 1:
        return {"check": "posisi target tetap antar tantangan", "status": 200, "ok": False,
                "note": f"Posisi target identik ({xs[0]:g}) pada {len(xs)} tantangan berturut — "
                        "tidak acak.", "url": "", "kind": "captcha-answer-leak"}
    return {"check": "posisi target tetap antar tantangan", "status": 200, "ok": True,
            "note": f"Posisi target bervariasi antar tantangan ({', '.join(f'{x:g}' for x in xs)}).",
            "url": "", "kind": "captcha-answer-leak"}


def fetch(cfg, sess=None):
    ep = cfg.get("endpoint") or {"method": "GET", "path": "/api/captcha"}
    s = sess or requests.Session()
    if os.environ.get("SAK_INSECURE_TLS") == "1":
        s.verify = False
    r = s.request(ep.get("method", "GET"), cfg["base_url"].rstrip("/") + ep["path"], timeout=20)
    if r.status_code >= 400:
        raise RuntimeError(f"endpoint captcha HTTP {r.status_code}")
    body = r.json()
    dp = cfg.get("data_path", "data")
    cur = body
    for part in (dp or "").split("."):
        if part:
            cur = cur.get(part) if isinstance(cur, dict) else None
    return cur if cur is not None else body, f"{ep.get('method', 'GET')} {cfg['base_url'].rstrip('/')}{ep['path']}"


def run(cfg, sess=None, sleep=lambda s: None):
    samples = int(cfg.get("samples", 2))
    rows, xs, url = [], [], ""
    for i in range(samples):
        data, url = fetch(cfg, sess)
        r = analyze_challenge(data)
        for row in r:
            row["url"] = url
        if i == 0:
            rows.extend(r)
        for row in r:
            if row.get("x") is not None:
                xs.append(row["x"])
        sleep(float(cfg.get("delay_seconds", 0)))
    rnd = evaluate_randomness(xs)
    if rnd:
        rnd["url"] = url
        rows.append(rnd)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deteksi kebocoran jawaban captcha (statis).")
    ap.add_argument("--config", default=str(Path(__file__).with_name("captcha.yml")))
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
        results = run(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"[SETUP] {exc}", file=sys.stderr)
        return 2
    failures = sum(1 for r in results if not r["ok"])
    for r in results:
        print(f"[{'PASS' if r['ok'] else 'FAIL'}] {r['check']} — {r['note']}")
    print(f"\n{len(results)} cek, {failures} temuan.")
    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps({"module": "captcha", "failures": failures, "results": results},
                       indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
