#!/usr/bin/env python3
"""Gabungkan hasil semua modul di reports/ menjadi satu laporan yang dapat
dipertanggungjawabkan: metodologi, bukti, justifikasi severity, rekomendasi +
contoh solusi per temuan, daftar CVE, dan batasan.

Menghasilkan reports/laporan.html dan reports/laporan.md. Lintas-platform (stdlib).

Membaca JSON yang ditulis modul:
  authz.json, upload.json, auth_policy.json   (runner pengujian kit ini)
  zap-baseline.json / zap-api.json / zap-full.json  (OWASP ZAP)
  trivy.json                                   (CVE dependensi)
  testssl.json                                 (TLS, sebagian ber-CVE)

Pakai: python report.py [--dir reports]
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
from pathlib import Path

import remediation as R

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "lulus": 5}
SEV_COLOR = {"critical": "#7c1313", "high": "#b4232a", "medium": "#c67b00",
             "low": "#2d7d46", "info": "#555", "lulus": "#2d7d46"}


def load(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


CLIENT_LEAK_KIND = {"cache": "client-cache", "js": "js-leak",
                    "html": "info-exposure", "file": "info-exposure"}


def norm(modul, judul, status, evidence, lulus, override_sev=None, cve=None, kind_hint=None):
    kind = kind_hint or R.classify(modul, judul)
    kb = R.lookup(kind)
    sev = "lulus" if lulus else (override_sev or kb["severity"]).lower()
    return {
        "modul": modul, "judul": judul, "kind": kind, "lulus": lulus,
        "severity": sev, "status": status, "evidence": evidence,
        "cve": cve or [], "kb": kb,
    }


def collect(d: Path):
    findings = []

    # --- runner kit ---
    for name, modul in (("authz.json", "authz-matrix"),
                        ("upload.json", "upload-safety"),
                        ("auth_policy.json", "auth-policy"),
                        ("client_leak.json", "client-leak"),
                        ("headers.json", "headers")):
        data = load(d / name)
        if not data:
            continue
        rows = data.get("results", data) if isinstance(data, dict) else data
        for r in rows:
            ok = r.get("ok", True)
            label = (r.get("endpoint") or r.get("case") or r.get("check")
                     or r.get("label") or "?")
            role = r.get("role")
            ev = r.get("note") or ""
            if r.get("status") not in (None, ""):
                ev = (f"Role '{role}', " if role else "") + f"respons HTTP {r.get('status')}. " + ev
            hint = None
            if modul == "client-leak":
                hint = CLIENT_LEAK_KIND.get(r.get("kind"))
            elif modul == "headers":
                hint = "missing-header"
            findings.append(norm(modul, label, r.get("status"), ev.strip(), ok, kind_hint=hint))

    # --- OWASP ZAP ---
    for zf in ("zap-baseline.json", "zap-api.json", "zap-full.json"):
        data = load(d / zf)
        if not data:
            continue
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = (alert.get("riskdesc", "info").split(" ")[0] or "info").lower()
                inst = alert.get("instances", [])
                ev = f"{len(inst)} instance. " + html.unescape(alert.get("desc", ""))[:300]
                cwe = alert.get("cweid")
                findings.append(norm("zap", alert.get("alert", "?"), None, ev,
                                     lulus=False,
                                     override_sev=risk if risk in SEV_ORDER else "info",
                                     cve=[f"CWE-{cwe}"] if cwe and cwe != "-1" else []))

    # --- CVE dependensi (trivy) ---
    data = load(d / "trivy.json")
    if data:
        for res in data.get("Results", []) or []:
            tgt = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                sev = (v.get("Severity", "UNKNOWN") or "info").lower()
                sev = sev if sev in SEV_ORDER else "info"
                pkg = v.get("PkgName", "?")
                fixed = v.get("FixedVersion") or "belum ada perbaikan"
                ev = (f"Paket {pkg} {v.get('InstalledVersion','?')} di {tgt}. "
                      f"Perbaikan: {fixed}. {html.unescape(v.get('Title',''))[:200]}")
                findings.append(norm("trivy-cve", f"{v.get('VulnerabilityID')} — {pkg}",
                                     None, ev, lulus=False, override_sev=sev,
                                     cve=[v.get("VulnerabilityID")]))

    # --- testssl (sebagian ber-CVE) ---
    data = load(d / "testssl.json")
    if data and isinstance(data, list):
        for item in data:
            sev = (item.get("severity", "INFO") or "info").lower()
            if sev in ("ok", "info", "low", "") or sev not in SEV_ORDER:
                continue
            cve = item.get("cve") or ""
            findings.append(norm("testssl", item.get("id", "TLS"), None,
                                 html.unescape(str(item.get("finding", "")))[:200],
                                 lulus=False, override_sev=sev,
                                 cve=[c for c in cve.split() if c.startswith("CVE")]))
    return findings


def kind_fix(kind):
    """Remediasi untuk CVE dependensi memakai entri khusus."""
    if kind == "trivy-cve":
        return R.lookup("vuln-dependency")
    return R.lookup(kind)


def summarize(findings):
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


METODOLOGI = (
    "Testing dijalankan otomatis dan non-destruktif ke target yang berwenang diuji. "
    "Acuannya OWASP Top 10 2021, OWASP ASVS, dan OWASP Risk Rating Methodology "
    "(severity = Likelihood x Impact). Tooling-nya OWASP ZAP, Trivy, dan testssl.sh, "
    "ditambah rangkaian regression test buat access control, upload, dan password policy."
)
BATASAN = (
    "Laporan ini hasil automation, bukan pengganti pentest manual. Temuan scanner "
    "(misalnya ZAP) bisa false positive dan wajib diverifikasi sebelum severity final "
    "dikunci. Celah logika bisnis cuma ketangkep kalau test-nya ditulis khusus. "
    "Cakupannya sebatas target & endpoint yang di-config pas dijalanin."
)


def write_md(path, findings, counts, when, cves):
    gagal = sorted([f for f in findings if not f["lulus"]],
                   key=lambda x: SEV_ORDER.get(x["severity"], 9))
    L = [
        "# Laporan Hasil Uji Keamanan (Otomatis)",
        "", f"> Dibuat: {when} · Dihasilkan oleh Security Audit Kit", "",
        "## 1. Metodologi", "", METODOLOGI, "",
        "## 2. Ringkasan Temuan", "",
        "| Severity | Jumlah |", "|---|---|",
        f"| Critical | {counts['critical']} |", f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |", f"| Low | {counts['low']} |",
        f"| Info | {counts['info']} |", f"| Lulus (kontrol OK) | {counts['lulus']} |",
        "", f"Total CVE terdeteksi: **{len(cves)}**.", "",
        "## 3. Rincian Temuan & Rekomendasi", "",
    ]
    if not gagal:
        L.append("_Tidak ada temuan gagal — semua kontrol yang diuji lolos._")
    for i, f in enumerate(gagal, 1):
        kb = kind_fix(f["kind"])
        L += [
            f"### {i}. {f['judul']}  `{f['severity'].upper()}`", "",
            f"- **Modul:** {f['modul']}",
            f"- **Deskripsi:** {kb['deskripsi']}",
            f"- **Bukti:** {f['evidence']}",
            (f"- **CVE/CWE:** {', '.join(f['cve'])}" if f["cve"] else "- **CVE/CWE:** -"),
            f"- **Dampak:** {kb['dampak']}",
            f"- **Justifikasi severity:** {kb['severity_dasar']}",
            "- **Rekomendasi & contoh solusi:**",
        ]
        for rec in kb["rekomendasi"]:
            if "\n" in rec or "    " in rec:
                L += ["", "  ```", *("  " + ln for ln in rec.splitlines()), "  ```", ""]
            else:
                L.append(f"  - {rec}")
        L.append(f"- **Referensi:** {'; '.join(kb['referensi'])}")
        L.append("")
    if cves:
        L += ["## 4. Daftar CVE", "", "| CVE | Paket/Lokasi | Severity |", "|---|---|---|"]
        for c in cves:
            L.append(f"| {c['id']} | {c['where']} | {c['sev'].upper()} |")
        L.append("")
    L += ["## 5. Batasan & Pertanggungjawaban", "", BATASAN, ""]
    path.write_text("\n".join(L), encoding="utf-8")


def write_html(path, findings, counts, when, cves):
    gagal = sorted([f for f in findings if not f["lulus"]],
                   key=lambda x: SEV_ORDER.get(x["severity"], 9))
    cards = "".join(
        f"<div class='card' style='border-color:{SEV_COLOR[s]}'><div class='n'>{counts[s]}</div>"
        f"<div class='l'>{s.upper()}</div></div>" for s in SEV_ORDER)

    def esc(x):
        return html.escape(str(x))

    blocks = ""
    for i, f in enumerate(gagal, 1):
        kb = kind_fix(f["kind"])
        recs = ""
        for rec in kb["rekomendasi"]:
            if "\n" in rec or "    " in rec:
                recs += f"<pre>{esc(rec)}</pre>"
            else:
                recs += f"<li>{esc(rec)}</li>"
        cve = ", ".join(f["cve"]) if f["cve"] else "-"
        blocks += f"""
        <div class="finding">
          <h3><span class="badge" style="background:{SEV_COLOR[f['severity']]}">{esc(f['severity'].upper())}</span>
              {i}. {esc(f['judul'])}</h3>
          <p><b>Modul:</b> {esc(f['modul'])} &nbsp;·&nbsp; <b>CVE/CWE:</b> {esc(cve)}</p>
          <p><b>Deskripsi.</b> {esc(kb['deskripsi'])}</p>
          <p><b>Bukti.</b> {esc(f['evidence'])}</p>
          <p><b>Dampak.</b> {esc(kb['dampak'])}</p>
          <p><b>Justifikasi severity.</b> {esc(kb['severity_dasar'])}</p>
          <p><b>Rekomendasi & contoh solusi.</b></p><ul>{recs}</ul>
          <p class="ref"><b>Referensi:</b> {esc('; '.join(kb['referensi']))}</p>
        </div>"""
    if not blocks:
        blocks = "<p>Tidak ada temuan gagal — semua kontrol yang diuji lolos.</p>"

    cve_rows = "".join(
        f"<tr><td><a href='https://nvd.nist.gov/vuln/detail/{esc(c['id'])}' "
        f"target='_blank' rel='noopener'>{esc(c['id'])}</a></td><td>{esc(c['where'])}</td>"
        f"<td style='color:{SEV_COLOR.get(c['sev'],'#555')}'>{esc(c['sev'].upper())}</td></tr>"
        for c in cves) or "<tr><td colspan='3'>Tidak ada CVE terdeteksi.</td></tr>"

    doc = f"""<!doctype html><html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Laporan Uji Keamanan</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24;line-height:1.5}}
 header{{background:#14233b;color:#fff;padding:24px 20px}} h1{{margin:0;font-size:20px}}
 .sub{{opacity:.8;font-size:13px;margin-top:4px}} main{{max-width:1000px;margin:0 auto;padding:20px}}
 h2{{border-bottom:2px solid #e3e7ec;padding-bottom:6px;margin-top:32px}}
 .note{{background:#fff;border-left:4px solid #14233b;padding:12px 14px;border-radius:6px;font-size:14px}}
 .cards{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
 .card{{flex:1;min-width:110px;background:#fff;border-left:5px solid;border-radius:8px;padding:12px 14px;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:11px;letter-spacing:.05em;color:#555}}
 .finding{{background:#fff;border-radius:8px;padding:14px 16px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
 .finding h3{{margin:0 0 8px;font-size:16px}} .finding p{{margin:6px 0;font-size:14px}}
 .badge{{color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;margin-right:8px;vertical-align:middle}}
 pre{{background:#0f1b2d;color:#e6edf3;padding:10px 12px;border-radius:6px;overflow:auto;font-size:13px}}
 .ref{{color:#555;font-size:12px}} table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #eceff3;font-size:14px}} th{{background:#eef1f5;font-size:12px;text-transform:uppercase}}
</style>
<header><h1>Laporan Hasil Uji Keamanan (Otomatis)</h1>
<div class="sub">Dibuat {when} · Security Audit Kit</div></header>
<main>
<h2>1. Metodologi</h2><div class="note">{html.escape(METODOLOGI)}</div>
<h2>2. Ringkasan Temuan</h2><div class="cards">{cards}</div>
<p>Total CVE terdeteksi: <b>{len(cves)}</b>.</p>
<h2>3. Rincian Temuan & Rekomendasi</h2>{blocks}
<h2>4. Daftar CVE</h2>
<table><thead><tr><th>CVE</th><th>Paket/Lokasi</th><th>Severity</th></tr></thead><tbody>{cve_rows}</tbody></table>
<h2>5. Batasan & Pertanggungjawaban</h2><div class="note">{html.escape(BATASAN)}</div>
</main></html>"""
    path.write_text(doc, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="reports")
    args = ap.parse_args()
    d = Path(args.dir)
    d.mkdir(exist_ok=True)
    when = dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    findings = collect(d)
    counts = summarize(findings)
    # Kumpulan CVE unik untuk tabel.
    cves = []
    seen = set()
    for f in findings:
        for c in f["cve"]:
            if c and c.startswith("CVE") and c not in seen:
                seen.add(c)
                cves.append({"id": c, "where": f["judul"], "sev": f["severity"]})

    write_md(d / "laporan.md", findings, counts, when, cves)
    write_html(d / "laporan.html", findings, counts, when, cves)

    gagal = sum(1 for f in findings if not f["lulus"])
    print(f"Laporan: {d/'laporan.html'} & {d/'laporan.md'}")
    print(f"Total {len(findings)} item, {gagal} perlu tindak lanjut, {len(cves)} CVE.")
    print(f"  Critical {counts['critical']} · High {counts['high']} · "
          f"Medium {counts['medium']} · Low {counts['low']} · Info {counts['info']}")
    return 0


if __name__ == "__main__":
    main()
