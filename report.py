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
                        ("mass_assignment.json", "mass-assignment"),
                        ("auth_policy.json", "auth-policy"),
                        ("client_leak.json", "client-leak"),
                        ("cors.json", "cors"),
                        ("open_redirect.json", "open-redirect"),
                        ("webstack.json", "webstack"),
                        ("injection.json", "injection"),
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
    "Pengujian dijalankan secara otomatis dan non-destruktif terhadap target yang "
    "berwenang diuji. Acuannya OWASP Top 10 2021, OWASP ASVS, dan OWASP Risk Rating "
    "Methodology (severity = Likelihood x Impact). Tooling yang digunakan OWASP ZAP, "
    "Trivy, dan testssl.sh, ditambah rangkaian regression test untuk access control, "
    "upload, dan password policy."
)
BATASAN = (
    "Laporan ini merupakan hasil automation, bukan pengganti pentest manual. Temuan "
    "scanner (misalnya ZAP) dapat berupa false positive dan wajib diverifikasi sebelum "
    "severity final ditetapkan. Celah logika bisnis hanya terdeteksi apabila test-nya "
    "ditulis secara khusus. Cakupan pengujian terbatas pada target dan endpoint yang "
    "dikonfigurasi saat dijalankan. "
    "Uji destruktif (mis. mass-assignment) menulis ke target lalu DIPULIHKAN otomatis "
    "ke keadaan semula sebagai fase terakhir setelah laporan ini dibuat; log pemulihan "
    "ada di reports/rollback.json, dan `python audit.py rollback` memulihkan ulang bila perlu."
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
    "mass-assignment": "Mass assignment / eskalasi properti objek (BOPLA)",
    "weak-password": "Kebijakan sandi lemah",
    "captcha-static": "Captcha tidak regenerasi",
    "missing-header": "Header keamanan tidak diset",
    "tls-weak": "Konfigurasi TLS lemah",
    "server-vuln": "Web server versi rentan (CVE diketahui)",
    "sql-injection": "SQL Injection (A03)",
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


KLASIFIKASI = "RAHASIA / CONFIDENTIAL"
TOOLS = ["OWASP ZAP (DAST)", "Trivy (SCA/CVE)", "semgrep (SAST)", "gitleaks (secret)",
         "testssl.sh (TLS)",
         "runner internal Security Audit Kit (authz, mass-assignment, upload, auth-policy, "
         "client-leak, cors, open-redirect, webstack, injection)"]
# Rentang CVSS v3.1 indikatif per severity (pemetaan kualitatif OWASP Risk Rating).
CVSS_BAND = {"critical": "9.0–10.0", "high": "7.0–8.9", "medium": "4.0–6.9",
             "low": "0.1–3.9", "info": "0.0", "lulus": "—"}


def cvss_band(sev):
    return CVSS_BAND.get(sev, "—")


def finding_id(i):
    return f"AHZ-{i:03d}"


def read_target():
    """Baca nama & base_url target dari config/targets.yml (best-effort)."""
    try:
        import yaml
        p = Path(__file__).resolve().parent / "config" / "targets.yml"
        cfg = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
        return (cfg or {}).get("name") or "-", (cfg or {}).get("base_url") or "-"
    except Exception:  # noqa: BLE001
        return "-", "-"


def exec_summary(alerts, counts):
    """Ringkasan eksekutif ringkas, bahasa manajemen (non-teknis)."""
    total = sum(counts[s] for s in ("critical", "high", "medium", "low", "info"))
    if total == 0:
        return ("Tidak ditemukan temuan pada cakupan yang diuji; seluruh kontrol yang diuji "
                "berperilaku sesuai harapan. Pemeriksaan yang lolos dirinci pada bagian "
                "Kontrol yang Lolos sebagai bukti cakupan uji.")
    per = ", ".join(f"{counts[s]} {s.capitalize()}" for s in
                    ("critical", "high", "medium", "low", "info") if counts[s])
    top = "; ".join(a["nama"] for a in alerts[:3])
    prioritas = ("Critical dan High" if (counts["critical"] or counts["high"])
                 else "Medium dan Low")
    return (f"Pengujian menemukan {total} instance temuan ({per}) yang tergolong dalam "
            f"{len(alerts)} jenis alert. Temuan berisiko tertinggi: {top}. Perbaikan "
            f"disarankan memprioritaskan temuan {prioritas} terlebih dahulu. Rincian teknis, "
            "bukti endpoint, dan rekomendasi tersedia pada bagian Rincian Temuan.")


def write_md(path, findings, counts, when, cves):
    gagal = [f for f in findings if not f["lulus"]]
    alerts = group_alerts(gagal)
    tgt_name, tgt_url = read_target()
    moduls = sorted({f["modul"] for f in findings})
    L = [
        "# Laporan Hasil Uji Keamanan",
        "", f"**Klasifikasi:** {KLASIFIKASI}", "",
        "| | |", "|---|---|",
        f"| Dibuat | {when} |",
        f"| Disusun oleh | {CREDIT} |",
        f"| Target | {tgt_name} ({tgt_url}) |",
        f"| Versi dokumen | 1.0 |", "",
        "## 1. Ringkasan Eksekutif", "", exec_summary(alerts, counts), "",
        "| Severity | Jumlah instance |", "|---|---|",
        f"| {SEV_EMOJI['critical']} Critical | {counts['critical']} |",
        f"| {SEV_EMOJI['high']} High | {counts['high']} |",
        f"| {SEV_EMOJI['medium']} Medium | {counts['medium']} |",
        f"| {SEV_EMOJI['low']} Low | {counts['low']} |",
        f"| {SEV_EMOJI['info']} Info | {counts['info']} |",
        f"| {SEV_EMOJI['lulus']} Lulus (kontrol OK) | {counts['lulus']} |",
        "", f"Total alert: **{len(alerts)}** · Total CVE: **{len(cves)}**.", "",
        "## 2. Ruang Lingkup & Metodologi", "",
        f"- **Target:** {tgt_name} ({tgt_url}).",
        f"- **Modul/teknik yang dijalankan:** {', '.join(moduls) if moduls else '-'}.",
        "- **Metodologi:** " + METODOLOGI, "",
        "## 3. Ringkasan Risiko", "",
    ]
    # Daftar alert (ToC) dengan ID temuan, risiko, CVSS indikatif, keyakinan, instance.
    if alerts:
        L += ["| ID | Alert | Risiko | CVSS (indikatif) | Keyakinan | Instance |",
              "|---|---|---|---|---|---|"]
        for i, a in enumerate(alerts, 1):
            L.append(f"| {finding_id(i)} | {a['nama']} | {SEV_EMOJI.get(a['severity'], '')} "
                     f"{a['severity'].upper()} | {cvss_band(a['severity'])} | "
                     f"{a['keyakinan']} | {len(a['instances'])} |")
        L.append("")
    else:
        L += ["_Tidak ada temuan — seluruh kontrol yang diuji lolos._", ""]

    L += ["## 4. Rincian Temuan", ""]
    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        L += [
            f"### {finding_id(i)} — {SEV_EMOJI.get(a['severity'], '')} {a['nama']}", "",
            f"- **Severity:** {a['severity'].upper()} &nbsp; **CVSS (indikatif):** "
            f"{cvss_band(a['severity'])} &nbsp; **Keyakinan:** {a['keyakinan']} &nbsp; "
            f"**Status:** Terbuka",
            f"- **Sumber/plugin:** {', '.join(a['moduls'])} (`{a['kind']}`)",
            f"- **Deskripsi:** {kb['deskripsi']}",
            f"- **Instance yang diuji ({len(a['instances'])}):**", "",
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

    # Kontrol yang lolos — bukti cakupan uji.
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
        L += ["## 5. Daftar CVE", "", "| CVE | Paket/Lokasi | Severity |", "|---|---|---|"]
        for c in cves:
            L.append(f"| {c['id']} | {c['where']} | {SEV_EMOJI.get(c['sev'], '')} {c['sev'].upper()} |")
        L.append("")
    L += [
        "## 6. Lampiran", "",
        "**Tooling & acuan.** " + "; ".join(TOOLS) + ". Acuan: OWASP Top 10 2021, OWASP API "
        "Security Top 10 2023, OWASP ASVS, OWASP Risk Rating Methodology.", "",
        "**Catatan CVSS.** Skor CVSS bersifat indikatif (pemetaan kualitatif dari OWASP Risk "
        "Rating); vektor CVSS final perlu diverifikasi manual per temuan.", "",
        "**Batasan & pertanggungjawaban.** " + BATASAN, "",
        "---", "", f"_{CREDIT}_", "",
    ]
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

    tgt_name, tgt_url = read_target()
    moduls = sorted({f["modul"] for f in findings})

    # Daftar alert (ToC): ID temuan, risiko, CVSS indikatif, keyakinan, instance.
    toc_rows = "".join(
        f"<tr><td><a href='#alert-{i}'>{esc(finding_id(i))}</a></td><td>{esc(a['nama'])}</td>"
        f"<td><span class='badge' style='background:{SEV_COLOR[a['severity']]}'>"
        f"{esc(a['severity'].upper())}</span></td><td>{esc(cvss_band(a['severity']))}</td>"
        f"<td>{esc(a['keyakinan'])}</td><td>{len(a['instances'])}</td></tr>"
        for i, a in enumerate(alerts, 1)) or \
        "<tr><td colspan='6'>Tidak ada temuan — semua kontrol yang diuji lolos.</td></tr>"

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
              {esc(finding_id(i))} — {esc(a['nama'])}</h3>
          <p><b>Severity:</b> {esc(a['severity'].upper())} &nbsp;·&nbsp;
             <b>CVSS (indikatif):</b> {esc(cvss_band(a['severity']))} &nbsp;·&nbsp;
             <b>Keyakinan:</b> {esc(a['keyakinan'])} &nbsp;·&nbsp;
             <b>Status:</b> Terbuka</p>
          <p><b>Sumber/plugin:</b> {esc(', '.join(a['moduls']))} (<code>{esc(a['kind'])}</code>)
             &nbsp;·&nbsp; <b>CVE/CWE:</b> {esc(cve)}</p>
          <p><b>Deskripsi.</b> {esc(kb['deskripsi'])}</p>
          <p><b>Instance yang diuji ({len(a['instances'])}):</b></p>
          <table class="inst"><thead><tr><th>#</th><th>Endpoint diuji (bukti)</th>
            <th>Konteks</th><th>HTTP</th><th>Catatan</th></tr></thead>
            <tbody>{inst_rows}</tbody></table>
          <p><b>Dampak.</b> {esc(kb['dampak'])}</p>
          <p><b>Justifikasi severity.</b> {esc(kb['severity_dasar'])}</p>
          <p><b>Rekomendasi & contoh solusi.</b></p><ul>{recs}</ul>
          <p class="ref"><b>Referensi:</b> {esc('; '.join(kb['referensi']))}</p>
        </div>"""
    if not alerts:
        blocks = "<p>Tidak ada temuan — semua kontrol yang diuji lolos.</p>"

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
 .klas{{display:inline-block;background:#b4232a;color:#fff;font-size:11px;font-weight:700;letter-spacing:.08em;padding:3px 10px;border-radius:4px;margin-top:8px}}
 .meta td{{font-size:13px}} .meta td:first-child{{color:#555;width:160px;white-space:nowrap}}
 .exec{{background:#fff;border-left:4px solid #14233b;padding:14px 16px;border-radius:6px;font-size:14px}}
</style>
<header><h1>Laporan Hasil Uji Keamanan</h1>
<div class="sub">Dibuat {esc(when)}</div>
<div class="klas">{esc(KLASIFIKASI)}</div></header>
<main>
<table class="meta"><tbody>
<tr><td>Disusun oleh</td><td>{credit_html}</td></tr>
<tr><td>Target</td><td>{esc(tgt_name)} (<code>{esc(tgt_url)}</code>)</td></tr>
<tr><td>Versi dokumen</td><td>1.0</td></tr>
</tbody></table>
<h2>1. Ringkasan Eksekutif</h2>
<div class="exec">{esc(exec_summary(alerts, counts))}</div>
<div class="cards">{cards}</div>
<p>Total alert: <b>{len(alerts)}</b> · Total CVE: <b>{len(cves)}</b>.</p>
<h2>2. Ruang Lingkup &amp; Metodologi</h2>
<div class="note"><p><b>Target.</b> {esc(tgt_name)} (<code>{esc(tgt_url)}</code>)</p>
<p><b>Modul/teknik.</b> {esc(', '.join(moduls) if moduls else '-')}</p>
<p><b>Metodologi.</b> {html.escape(METODOLOGI)}</p></div>
<h2>3. Ringkasan Risiko</h2>
<table><thead><tr><th>ID</th><th>Alert</th><th>Risiko</th><th>CVSS (indikatif)</th><th>Keyakinan</th><th>Instance</th></tr></thead>
<tbody>{toc_rows}</tbody></table>
<h2>4. Rincian Temuan</h2>{blocks}
{lulus_section}
<h2>5. Daftar CVE</h2>
<table><thead><tr><th>CVE</th><th>Paket/Lokasi</th><th>Severity</th></tr></thead><tbody>{cve_rows}</tbody></table>
<h2>6. Lampiran</h2>
<div class="note"><p><b>Tooling &amp; acuan.</b> {esc('; '.join(TOOLS))}. Acuan: OWASP Top 10 2021, OWASP API Security Top 10 2023, OWASP ASVS, OWASP Risk Rating Methodology.</p>
<p><b>Catatan CVSS.</b> Skor CVSS bersifat indikatif (pemetaan kualitatif dari OWASP Risk Rating); vektor CVSS final perlu diverifikasi manual per temuan.</p>
<p><b>Batasan &amp; pertanggungjawaban.</b> {html.escape(BATASAN)}</p></div>
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
    # Sertakan zona waktu (offset UTC) agar waktu laporan tak ambigu lintas-wilayah.
    now = dt.datetime.now().astimezone()
    off = now.strftime("%z")                     # mis. +0700
    off_fmt = f"UTC{off[:3]}:{off[3:]}" if off else "UTC"
    tzname = now.strftime("%Z")
    when = now.strftime("%Y-%m-%d %H:%M") + f" ({off_fmt}" + (f" {tzname}" if tzname else "") + ")"

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
