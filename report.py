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
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡",
             "low": "🟢", "info": "⚪", "lulus": "✅"}


def load(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


CLIENT_LEAK_KIND = {"cache": "client-cache", "browser-cache": "client-cache", "js": "js-leak",
                    "html": "info-exposure", "file": "info-exposure"}


def norm(modul, judul, status, evidence, lulus, override_sev=None, cve=None,
         kind_hint=None, url=None):
    kind = kind_hint or R.classify(modul, judul)
    kb = R.lookup(kind)
    sev = "lulus" if lulus else (override_sev or kb["severity"]).lower()
    return {
        "modul": modul, "judul": judul, "kind": kind, "lulus": lulus,
        "severity": sev, "status": status, "evidence": evidence,
        "url": url or "", "cve": cve or [], "kb": kb,
    }


def collect(d: Path):
    findings = []

    # --- runner kit ---
    for name, modul in (("authz.json", "authz-matrix"),
                        ("upload.json", "upload-safety"),
                        ("auth_policy.json", "auth-policy"),
                        ("client_leak.json", "client-leak"),
                        ("cors.json", "cors"),
                        ("open_redirect.json", "open-redirect"),
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
            findings.append(norm(modul, label, r.get("status"), ev.strip(), ok,
                                 kind_hint=hint, url=r.get("url")))

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
                uri = inst[0].get("uri") if inst and isinstance(inst[0], dict) else None
                findings.append(norm("zap", alert.get("alert", "?"), None, ev,
                                     lulus=False,
                                     override_sev=risk if risk in SEV_ORDER else "info",
                                     cve=[f"CWE-{cwe}"] if cwe and cwe != "-1" else [],
                                     url=uri))

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

# Kredit pembuat kit — selalu ikut di SETIAP laporan, apa pun yang memakainya.
# Tanamkan di sini (bukan di config) supaya tak bisa dihapus lewat konfigurasi.
KIT_NAME = "Security Audit Kit"
KIT_AUTHOR = "hadymaggot"
KIT_URL = "https://github.com/hadymaggot/security-audit-kit"
CREDIT = f"{KIT_NAME} — dibuat oleh {KIT_AUTHOR} · {KIT_URL}"

# Nama alert yang terbaca manusia per 'kind' (gaya ZAP: satu alert, banyak instance).
KIND_LABEL = {
    "broken-access": "Kontrol akses rusak (role rendah membuka area terbatas)",
    "forged-header": "Header identitas (X-Auth-*) dipercaya dari klien",
    "idor": "IDOR — akses objek milik entitas lain",
    "info-exposure": "Berkas/informasi sensitif terekspos",
    "client-cache": "Respons sensitif dapat di-cache",
    "js-leak": "Kebocoran rahasia/endpoint di aset klien",
    "upload-accepted": "Upload berkas berbahaya diterima",
    "weak-password": "Kebijakan sandi lemah",
    "captcha-static": "Captcha tidak regenerasi",
    "missing-header": "Header keamanan tidak diset",
    "tls-weak": "Konfigurasi TLS lemah",
    "vuln-dependency": "Dependensi dengan kerentanan (CVE)",
    "cors-misconfig": "CORS salah konfigurasi",
    "open-redirect": "Open redirect",
    "zap-generic": "Temuan pemindai pasif (ZAP)",
}


def _confidence(moduls):
    """Keyakinan: pemeriksaan deterministik (request/response langsung) = Tinggi;
    temuan pemindai pasif (ZAP) = Sedang (perlu verifikasi manual)."""
    return "Sedang" if moduls == {"zap"} else "Tinggi"


def group_alerts(gagal):
    """Kelompokkan temuan per 'kind' jadi alert ala ZAP (satu alert, banyak instance).

    Urut dari severity tertinggi; dalam satu severity, alert dengan instance terbanyak
    didahulukan. Tiap alert: {kind, nama, kb, severity, keyakinan, instances, cve, moduls}.
    """
    groups = {}
    for f in gagal:
        groups.setdefault(f["kind"], []).append(f)
    alerts = []
    for kind, items in groups.items():
        sev = min((i["severity"] for i in items), key=lambda s: SEV_ORDER.get(s, 9))
        moduls = {i["modul"] for i in items}
        cve = []
        for i in items:
            for c in i["cve"]:
                if c and c not in cve:
                    cve.append(c)
        nama = KIND_LABEL.get(kind) or (items[0]["judul"] if len(items) == 1 else kind)
        alerts.append({
            "kind": kind, "nama": nama, "kb": R.lookup(kind), "severity": sev,
            "keyakinan": _confidence(moduls), "instances": items,
            "cve": cve, "moduls": sorted(moduls),
        })
    alerts.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 9), -len(a["instances"])))
    return alerts


def write_md(path, findings, counts, when, cves):
    gagal = [f for f in findings if not f["lulus"]]
    alerts = group_alerts(gagal)
    L = [
        "# Laporan Hasil Uji Keamanan (Otomatis)",
        "", f"> Dibuat: {when} · {CREDIT}", "",
        "## 1. Metodologi", "", METODOLOGI, "",
        "## 2. Ringkasan Temuan", "",
        "| Severity | Jumlah instance |", "|---|---|",
        f"| {SEV_EMOJI['critical']} Critical | {counts['critical']} |",
        f"| {SEV_EMOJI['high']} High | {counts['high']} |",
        f"| {SEV_EMOJI['medium']} Medium | {counts['medium']} |",
        f"| {SEV_EMOJI['low']} Low | {counts['low']} |",
        f"| {SEV_EMOJI['info']} Info | {counts['info']} |",
        f"| {SEV_EMOJI['lulus']} Lulus (kontrol OK) | {counts['lulus']} |",
        "", f"Total alert: **{len(alerts)}** · Total CVE terdeteksi: **{len(cves)}**.", "",
    ]
    # Daftar alert (ringkas) — gaya ZAP: nama alert, risiko, keyakinan, jumlah instance.
    if alerts:
        L += ["### Daftar Alert", "",
              "| # | Alert | Risiko | Keyakinan | Instance |", "|---|---|---|---|---|"]
        for i, a in enumerate(alerts, 1):
            L.append(f"| {i} | {a['nama']} | {SEV_EMOJI.get(a['severity'], '')} "
                     f"{a['severity'].upper()} | {a['keyakinan']} | {len(a['instances'])} |")
        L.append("")

    L += ["## 3. Rincian Temuan & Rekomendasi", ""]
    if not alerts:
        L.append("_Tidak ada temuan gagal — semua kontrol yang diuji lolos._")
    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        L += [
            f"### {i}. {SEV_EMOJI.get(a['severity'], '')} {a['nama']}  `{a['severity'].upper()}`", "",
            f"- **Risiko:** {a['severity'].upper()} &nbsp; **Keyakinan:** {a['keyakinan']}",
            f"- **Sumber/plugin:** {', '.join(a['moduls'])} (`{a['kind']}`)",
            f"- **Deskripsi:** {kb['deskripsi']}",
            f"- **Jumlah instance:** {len(a['instances'])}", "",
            "  | # | Endpoint diuji | Konteks | HTTP | Bukti |",
            "  |---|---|---|---|---|",
        ]
        for j, inst in enumerate(a["instances"], 1):
            ctx = inst.get("judul", "")
            st = inst["status"] if inst["status"] not in (None, "") else "-"
            ev = (inst.get("evidence") or "").replace("|", "\\|").replace("\n", " ")[:160]
            url = (inst.get("url") or "-").replace("|", "\\|")
            L.append(f"  | {j} | `{url}` | {ctx} | {st} | {ev} |")
        L += [
            "",
            (f"- **CVE/CWE:** {', '.join(a['cve'])}" if a["cve"] else "- **CVE/CWE:** -"),
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

    # Kontrol yang lolos — perinci apa yang diuji & berperilaku benar (angka 'Lulus').
    lulus = [f for f in findings if f["lulus"]]
    if lulus:
        L += [f"### Kontrol yang Lolos (LULUS: {len(lulus)})", "",
              "Pemeriksaan yang diuji dan berperilaku benar (bukan temuan) — bukti cakupan uji.", "",
              "| Pemeriksaan | Modul | Endpoint diuji | HTTP |", "|---|---|---|---|"]
        for f in lulus:
            url = (f.get("url") or "-").replace("|", "\\|")
            st = f["status"] if f["status"] not in (None, "") else "-"
            L.append(f"| {f['judul']} | {f['modul']} | `{url}` | {st} |")
        L.append("")
    if cves:
        L += ["## 4. Daftar CVE", "", "| CVE | Paket/Lokasi | Severity |", "|---|---|---|"]
        for c in cves:
            L.append(f"| {c['id']} | {c['where']} | {SEV_EMOJI.get(c['sev'], '')} {c['sev'].upper()} |")
        L.append("")
    L += ["## 5. Batasan & Pertanggungjawaban", "", BATASAN, "",
          "---", "", f"_{CREDIT}_", ""]
    path.write_text("\n".join(L), encoding="utf-8")


def write_html(path, findings, counts, when, cves):
    def esc(x):
        return html.escape(str(x))

    gagal = [f for f in findings if not f["lulus"]]
    alerts = group_alerts(gagal)

    cards = "".join(
        f"<div class='card{' zero' if not counts[s] else ''}' style='border-color:{SEV_COLOR[s]}'>"
        f"<div class='n' style='color:{SEV_COLOR[s]}'>{counts[s]}</div>"
        f"<div class='l'>{s.upper()}</div></div>" for s in SEV_ORDER)

    # Daftar alert (ToC, gaya ZAP): nama, risiko, keyakinan, jumlah instance.
    toc_rows = "".join(
        f"<tr><td>{i}</td><td><a href='#alert-{i}'>{esc(a['nama'])}</a></td>"
        f"<td><span class='badge' style='background:{SEV_COLOR[a['severity']]}'>"
        f"{esc(a['severity'].upper())}</span></td><td>{esc(a['keyakinan'])}</td>"
        f"<td>{len(a['instances'])}</td></tr>"
        for i, a in enumerate(alerts, 1)) or \
        "<tr><td colspan='5'>Tidak ada temuan gagal — semua kontrol yang diuji lolos.</td></tr>"

    blocks = ""
    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        recs = ""
        for rec in kb["rekomendasi"]:
            recs += (f"<pre>{esc(rec)}</pre>" if ("\n" in rec or "    " in rec)
                     else f"<li>{esc(rec)}</li>")
        inst_rows = "".join(
            f"<tr><td>{j}</td><td><code>{esc(inst.get('url') or '-')}</code></td>"
            f"<td>{esc(inst.get('judul', ''))}</td>"
            f"<td>{esc(inst['status'] if inst['status'] not in (None, '') else '-')}</td>"
            f"<td>{esc(inst.get('evidence') or '')}</td></tr>"
            for j, inst in enumerate(a["instances"], 1))
        cve = ", ".join(a["cve"]) if a["cve"] else "-"
        col = SEV_COLOR[a["severity"]]
        blocks += f"""
        <div class="finding" id="alert-{i}" style="border-left:5px solid {col}">
          <h3><span class="badge" style="background:{col}">{esc(a['severity'].upper())}</span>
              {i}. {esc(a['nama'])}</h3>
          <p><b>Risiko:</b> {esc(a['severity'].upper())} &nbsp;·&nbsp;
             <b>Keyakinan:</b> {esc(a['keyakinan'])} &nbsp;·&nbsp;
             <b>Sumber/plugin:</b> {esc(', '.join(a['moduls']))} (<code>{esc(a['kind'])}</code>)
             &nbsp;·&nbsp; <b>CVE/CWE:</b> {esc(cve)}</p>
          <p><b>Deskripsi.</b> {esc(kb['deskripsi'])}</p>
          <p><b>Instance diuji ({len(a['instances'])}):</b></p>
          <table class="inst"><thead><tr><th>#</th><th>Endpoint diuji (bukti)</th>
            <th>Konteks</th><th>HTTP</th><th>Catatan</th></tr></thead>
            <tbody>{inst_rows}</tbody></table>
          <p><b>Dampak.</b> {esc(kb['dampak'])}</p>
          <p><b>Justifikasi severity.</b> {esc(kb['severity_dasar'])}</p>
          <p><b>Solusi & contoh.</b></p><ul>{recs}</ul>
          <p class="ref"><b>Referensi:</b> {esc('; '.join(kb['referensi']))}</p>
        </div>"""
    if not alerts:
        blocks = "<p>Tidak ada temuan gagal — semua kontrol yang diuji lolos.</p>"

    lulus = [f for f in findings if f["lulus"]]
    lulus_rows = "".join(
        f"<tr><td>{esc(f['judul'])}</td><td>{esc(f['modul'])}</td>"
        f"<td><code>{esc(f.get('url') or '-')}</code></td>"
        f"<td>{esc(f['status'] if f['status'] not in (None, '') else '-')}</td></tr>"
        for f in lulus)
    lulus_section = (
        f"<h2>Kontrol yang Lolos (LULUS: {len(lulus)})</h2>"
        f"<p>Pemeriksaan yang diuji dan berperilaku benar — bukan temuan; bukti cakupan uji.</p>"
        f"<table><thead><tr><th>Pemeriksaan</th><th>Modul</th>"
        f"<th>Endpoint diuji</th><th>HTTP</th></tr></thead><tbody>{lulus_rows}</tbody></table>"
    ) if lulus else ""

    cve_rows = "".join(
        f"<tr><td><a href='https://nvd.nist.gov/vuln/detail/{esc(c['id'])}' "
        f"target='_blank' rel='noopener'>{esc(c['id'])}</a></td><td>{esc(c['where'])}</td>"
        f"<td><span class='badge' style='background:{SEV_COLOR.get(c['sev'],'#555')}'>{esc(c['sev'].upper())}</span></td></tr>"
        for c in cves) or "<tr><td colspan='3'>Tidak ada CVE terdeteksi.</td></tr>"

    credit_html = (f"{esc(KIT_NAME)} — dibuat oleh <b>{esc(KIT_AUTHOR)}</b> · "
                   f"<a href='{esc(KIT_URL)}' target='_blank' rel='noopener'>{esc(KIT_URL)}</a>")

    doc = f"""<!doctype html><html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Laporan Uji Keamanan</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24;line-height:1.5}}
 header{{background:#14233b;color:#fff;padding:24px 20px}} h1{{margin:0;font-size:20px}}
 .sub{{opacity:.85;font-size:13px;margin-top:4px}} .sub a{{color:#9ec5ff}}
 main{{max-width:1000px;margin:0 auto;padding:20px}}
 h2{{border-bottom:2px solid #e3e7ec;padding-bottom:6px;margin-top:32px}}
 .note{{background:#fff;border-left:4px solid #14233b;padding:12px 14px;border-radius:6px;font-size:14px}}
 .cards{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
 .card{{flex:1;min-width:110px;background:#fff;border-left:5px solid;border-radius:8px;padding:12px 14px;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
 .card .n{{font-size:26px;font-weight:700}} .card .l{{font-size:11px;letter-spacing:.05em;color:#555}}
 .card.zero{{opacity:.45}}
 .finding{{background:#fff;border-radius:8px;padding:14px 16px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
 .finding h3{{margin:0 0 8px;font-size:16px}} .finding p{{margin:6px 0;font-size:14px}}
 .badge{{color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;margin-right:8px;vertical-align:middle}}
 pre{{background:#0f1b2d;color:#e6edf3;padding:10px 12px;border-radius:6px;overflow:auto;font-size:13px}}
 code{{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}}
 .ref{{color:#555;font-size:12px}} table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.06);margin:8px 0}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #eceff3;font-size:14px;vertical-align:top}} th{{background:#eef1f5;font-size:12px;text-transform:uppercase}}
 table.inst td{{font-size:13px}} table.inst code{{background:#f3f5f8}}
 footer{{max-width:1000px;margin:0 auto;padding:16px 20px 40px;color:#555;font-size:12px;border-top:1px solid #e3e7ec}}
 footer a{{color:#14233b}}
</style>
<header><h1>Laporan Hasil Uji Keamanan (Otomatis)</h1>
<div class="sub">Dibuat {esc(when)} · {credit_html}</div></header>
<main>
<h2>1. Metodologi</h2><div class="note">{html.escape(METODOLOGI)}</div>
<h2>2. Ringkasan Risiko</h2><div class="cards">{cards}</div>
<p>Total alert: <b>{len(alerts)}</b> · Total CVE terdeteksi: <b>{len(cves)}</b>.</p>
<table><thead><tr><th>#</th><th>Alert</th><th>Risiko</th><th>Keyakinan</th><th>Instance</th></tr></thead>
<tbody>{toc_rows}</tbody></table>
<h2>3. Rincian Temuan & Rekomendasi</h2>{blocks}
{lulus_section}
<h2>4. Daftar CVE</h2>
<table><thead><tr><th>CVE</th><th>Paket/Lokasi</th><th>Severity</th></tr></thead><tbody>{cve_rows}</tbody></table>
<h2>5. Batasan & Pertanggungjawaban</h2><div class="note">{html.escape(BATASAN)}</div>
</main>
<footer>{credit_html}</footer>
</html>"""
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
