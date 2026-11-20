#!/usr/bin/env python3
"""Merge all module results in reports/ into one defensible report.

Covers methodology, evidence, severity justification, per-finding recommendation + sample fix,
CVE list and limitations. Writes reports/laporan.html and reports/laporan.md (cross-platform, stdlib).

Reads the JSON written by the modules:
  authz.json, upload.json, auth_policy.json   (this kit's test runners)
  zap-baseline.json / zap-api.json / zap-full.json  (OWASP ZAP)
  trivy.json                                   (dependency CVEs)
  testssl.json                                 (TLS, partly CVE-tagged)

Usage: python report.py [--dir reports]
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import sys
from pathlib import Path

import glossary
import remediation as R

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
import _color as C  # noqa: E402  (console ANSI colors; terminal summary only)

_TAG_RE = re.compile(r"</?[A-Za-z][^>]*>")


def plain_text(s, limit=None):
    """Plain text from a string that may contain HTML entities/tags (e.g. a ZAP alert description
    '&lt;p&gt;...&lt;/p&gt;'): unescape, strip tags, collapse whitespace, so raw tags do not leak
    into the Markdown/HTML/slide report."""
    t = str(s or "")
    for _ in range(3):                        # double-encoded entities (&amp;lt;) -> repeat until stable
        u = html.unescape(t)
        if u == t:
            break
        t = u
    t = _TAG_RE.sub(" ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit] if limit else t


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "passed": 5}
SEV_COLOR = {"critical": "#c0392b", "high": "#e8710a", "medium": "#d4a017",
             "low": "#2f6feb", "info": "#6b7280", "passed": "#1f9d57"}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡",
             "low": "🔵", "info": "⚪", "passed": "🟢"}
# Severity labels shown to the reader (passed control = PASS).
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
             "low": "LOW", "info": "INFO", "passed": "PASS"}
def sev_label(s):
    return SEV_LABEL.get(s, str(s).upper())


def load(path: Path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


CLIENT_LEAK_KIND = {"cache": "client-cache", "browser-cache": "client-cache", "js": "js-leak",
                    "html": "info-exposure", "file": "info-exposure"}


def norm(module, title, status, evidence, passed, override_sev=None, cve=None,
         kind_hint=None, url=None, screenshot=None):
    kind = kind_hint or R.classify(module, title)
    kb = R.lookup(kind)
    sev = "passed" if passed else (override_sev or kb["severity"]).lower()
    return {
        "module": module, "title": title, "kind": kind, "passed": passed,
        "severity": sev, "status": status, "evidence": evidence,
        "url": url or "", "screenshot": screenshot or "", "cve": cve or [], "kb": kb,
    }


def collect(d: Path):
    findings = []

    # --- kit runners ---
    for name, module in (("authz.json", "authz-matrix"),
                        ("upload.json", "upload-safety"),
                        ("mass_assignment.json", "mass-assignment"),
                        ("auth_policy.json", "auth-policy"),
                        ("client_leak.json", "client-leak"),
                        ("cors.json", "cors"),
                        ("open_redirect.json", "open-redirect"),
                        ("webstack.json", "webstack"),
                        ("injection.json", "injection"),
                        ("cookie_flags.json", "cookie-flags"),
                        ("response_leak.json", "response-leak"),
                        ("openapi_coverage.json", "openapi-coverage"),
                        ("ratelimit.json", "ratelimit"),
                        ("session_mgmt.json", "session-mgmt"),
                        ("captcha.json", "captcha"),
                        ("jwt.json", "jwt"),
                        ("ssrf.json", "ssrf"),
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
                ev = (f"Role '{role}', " if role else "") + f"response HTTP {r.get('status')}. " + ev
            hint = None
            if module == "client-leak":
                hint = CLIENT_LEAK_KIND.get(r.get("kind"))
            elif module in ("response-leak", "openapi-coverage", "ratelimit", "session-mgmt",
                           "captcha", "jwt", "ssrf"):
                hint = r.get("kind")
            elif module == "headers":
                hint = "missing-header"
            findings.append(norm(module, label, r.get("status"), ev.strip(), ok,
                                 kind_hint=hint, url=r.get("url"),
                                 screenshot=r.get("screenshot")))

    # --- OWASP ZAP ---
    for zf in ("zap-baseline.json", "zap-api.json", "zap-full.json"):
        data = load(d / zf)
        if not data:
            continue
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = (alert.get("riskdesc", "info").split(" ")[0] or "info").lower()
                inst = alert.get("instances", [])
                ev = f"{len(inst)} instance. " + plain_text(alert.get("desc", ""), 300)
                cwe = alert.get("cweid")
                uri = inst[0].get("uri") if inst and isinstance(inst[0], dict) else None
                findings.append(norm("zap", plain_text(alert.get("alert", "?")), None, ev,
                                     passed=False,
                                     override_sev=risk if risk in SEV_ORDER else "info",
                                     cve=[f"CWE-{cwe}"] if cwe and cwe != "-1" else [],
                                     url=uri))

    # --- dependency CVEs (trivy) ---
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
                      f"Perbaikan: {fixed}. {plain_text(v.get('Title',''), 200)}")
                findings.append(norm("trivy-cve", f"{v.get('VulnerabilityID')} — {pkg}",
                                     None, ev, passed=False, override_sev=sev,
                                     cve=[v.get("VulnerabilityID")]))

    # --- gitleaks (secrets in code/git history; values are already redacted by gitleaks) ---
    data = load(d / "gitleaks.json")
    if isinstance(data, list):
        for g in data:
            where = f"{g.get('File', '?')}:{g.get('StartLine', '?')}"
            ev = (f"Aturan {g.get('RuleID', '?')} cocok di {where}"
                  + (f" (commit {str(g.get('Commit'))[:8]})" if g.get("Commit") else "") + ". "
                  + plain_text(g.get("Description", ""), 160) + " Nilai secret tidak dicantumkan.")
            findings.append(norm("gitleaks", f"{g.get('RuleID', 'secret')} — {where}", None, ev,
                                 passed=False, override_sev="high", kind_hint="leaked-secret",
                                 url=where))

    # --- semgrep (SAST) ---
    data = load(d / "semgrep.json")
    if isinstance(data, dict):
        sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
        for r in data.get("results", []) or []:
            ex = r.get("extra", {}) or {}
            where = f"{r.get('path', '?')}:{(r.get('start') or {}).get('line', '?')}"
            short = str(r.get("check_id", "?")).split(".")[-1]
            cwe = ex.get("metadata", {}).get("cwe", []) if isinstance(ex.get("metadata"), dict) else []
            cwe = [cwe] if isinstance(cwe, str) else list(cwe or [])
            cwe = [re.match(r"CWE-\d+", c).group(0) for c in cwe if re.match(r"CWE-\d+", str(c))]
            findings.append(norm("semgrep", f"{short} — {where}", None,
                                 plain_text(ex.get("message", ""), 300), passed=False,
                                 override_sev=sev_map.get(str(ex.get("severity", "")).upper(), "medium"),
                                 cve=cwe, kind_hint="sast-finding", url=where))

    # --- testssl (partly CVE-tagged) ---
    data = load(d / "testssl.json")
    if data and isinstance(data, list):
        for item in data:
            sev = (item.get("severity", "INFO") or "info").lower()
            if sev in ("ok", "info", "low", "") or sev not in SEV_ORDER:
                continue
            cve = item.get("cve") or ""
            findings.append(norm("testssl", item.get("id", "TLS"), None,
                                 plain_text(item.get("finding", ""), 200),
                                 passed=False, override_sev=sev,
                                 cve=[c for c in cve.split() if c.startswith("CVE")]))

    # --- recon (OSINT/infra/vuln; severity is carried per row) ---
    data = load(d / "recon.json")
    if data:
        for r in data.get("results", data) if isinstance(data, dict) else data:
            ok = r.get("ok", True)
            sev = (r.get("severity", "info") or "info").lower()
            sev = sev if sev in SEV_ORDER else "info"
            findings.append(norm("recon", r.get("check") or r.get("label") or "?",
                                 r.get("status"), (r.get("note") or "").strip(), ok,
                                 override_sev=None if ok else sev,
                                 cve=r.get("cve") or [], kind_hint=r.get("kind"),
                                 url=r.get("url")))
    return findings


def summarize(findings):
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


METHODOLOGY = (
    "Pengujian dijalankan secara otomatis dan non-destruktif terhadap target yang "
    "berwenang diuji. Acuannya OWASP Top 10 2021, OWASP ASVS, dan OWASP Risk Rating "
    "Methodology (severity = Likelihood x Impact). Tooling yang digunakan OWASP ZAP, "
    "Trivy, dan testssl.sh, ditambah rangkaian regression test untuk access control, "
    "upload, dan password policy."
)
LIMITATIONS = (
    "Laporan ini merupakan hasil automation, bukan pengganti pentest manual. Temuan "
    "scanner (misalnya ZAP) dapat berupa false positive dan wajib diverifikasi sebelum "
    "severity final ditetapkan. Celah logika bisnis hanya terdeteksi apabila test-nya "
    "ditulis secara khusus. Cakupan pengujian terbatas pada target dan endpoint yang "
    "dikonfigurasi saat dijalankan. "
    "Uji destruktif (mis. mass-assignment) menulis ke target lalu DIPULIHKAN otomatis "
    "ke keadaan semula sebagai fase terakhir setelah laporan ini dibuat; log pemulihan "
    "ada di reports/rollback.json, dan `python audit.py rollback` memulihkan ulang bila perlu."
)

# Kit author credit: included in EVERY report (the "Alat" row and footer) regardless of who uses
# it. Hardcoded here, not in config, so configuration cannot remove it.
# The report preparer (tester/organization) is separate and dynamic: see report_meta().
KIT_NAME = "Security Audit Kit"
KIT_AUTHOR = "hadymaggot"
KIT_URL = "https://github.com/hadymaggot/security-audit-kit"
CREDIT = f"{KIT_NAME} — dibuat oleh {KIT_AUTHOR} · {KIT_URL}"

# Default report preparer, organization and contact; override per project in targets.yml
# (`report:` block) or via env SAK_REPORT_AUTHOR / SAK_REPORT_ORG / SAK_REPORT_CONTACT.
# DEFAULT_CONTACT applies only when the organization is also DEFAULT_ORG (it is that organization's contact).
DEFAULT_AUTHOR = "Sapto Hadi"
DEFAULT_ORG = "PT. Wahana Reka Tekindo"
DEFAULT_CONTACT = "wahanarekatekindo@gmail.com"

# Human-readable alert name per 'kind' (ZAP style: one alert, many instances).
KIND_LABEL = {
    "broken-access": "Access control rusak (role rendah membuka area terbatas)",
    "forged-header": "Header identitas (X-Auth-*) dipercaya dari klien",
    "idor": "IDOR — akses objek milik entitas lain",
    "info-exposure": "File/informasi sensitif exposed",
    "client-cache": "Response sensitif dapat di-cache",
    "js-leak": "Exposure secret/endpoint di aset klien",
    "upload-accepted": "Upload file berbahaya diterima",
    "mass-assignment": "Mass assignment / eskalasi properti objek (BOPLA)",
    "weak-password": "Kebijakan password lemah",
    "captcha-static": "Captcha tidak regenerasi",
    "missing-header": "Header keamanan tidak diset",
    "tls-weak": "Konfigurasi TLS lemah",
    "server-vuln": "Web server versi rentan (CVE diketahui)",
    "sql-injection": "SQL Injection (A03)",
    "vuln-dependency": "Dependency dengan kerentanan (CVE)",
    "cors-misconfig": "CORS salah konfigurasi",
    "open-redirect": "Open redirect",
    "cookie-flags": "Atribut keamanan cookie tidak lengkap",
    "ssrf": "Server-Side Request Forgery (server menembak URL yang dikendalikan penyerang)",
    "jwt-forgery": "Server menerima JWT yang dipalsukan",
    "jwt-weak-secret": "Secret JWT lemah dapat ditebak",
    "jwt-weak-config": "Konfigurasi JWT tidak aman",
    "captcha-answer-leak": "Captcha expose jawabannya di response",
    "session-not-revoked": "Session lain tidak dicabut setelah ganti password",
    "logout-no-invalidate": "Logout tidak mencabut session di server",
    "old-password-accepted": "Password lama masih diterima setelah penggantian",
    "no-rate-limit": "Tidak ada pembatasan laju pada endpoint sensitif",
    "weak-lockout": "Penguncian akun tidak sesuai kebijakan",
    "lockout-bypass": "Penguncian akun dapat dilewati dengan password benar",
    "user-enumeration": "Akun terdaftar dapat dibedakan dari response (enumerasi akun)",
    "auth-coverage-gap": "Endpoint terlindungi menurut spesifikasi namun terbuka tanpa login",
    "unauthenticated-endpoint": "Endpoint terbuka tanpa autentikasi (perlu ditinjau)",
    "spec-mismatch": "Spesifikasi OpenAPI tidak akurat terhadap perilaku nyata",
    "anon-server-error": "Error server (5xx) pada request anonim",
    "sensitive-data-exposure": "Data sensitif exposed di response API",
    "verbose-error": "Response verbose/debug expose detail implementasi",
    "internal-info-leak": "Alamat/hostname internal exposed di response",
    "recon-subdomain": "Aset/subdomain terpetakan (recon)",
    "exposed-service": "Port/layanan exposed ke publik",
    "leaked-secret": "Kredensial/secret exposed di source/aset",
    "recon-finding": "Temuan recon aktif (nuclei)",
    "sast-finding": "Temuan analisis statis kode (SAST/semgrep)",
    "zap-generic": "Temuan pemindai pasif (ZAP)",
}


def _confidence(modules):
    """Confidence: deterministic checks (direct request/response) = Tinggi; passive scanner
    findings (ZAP) = Sedang (need manual verification)."""
    return "Sedang" if modules == {"zap"} else "Tinggi"


def group_alerts(failed):
    """Group findings by 'kind' into ZAP-style alerts (one alert, many instances).

    Sorted by highest severity, then by most instances. Each alert:
    {kind, nama, kb, severity, keyakinan, instances, cve, moduls}.
    """
    groups = {}
    for f in failed:
        groups.setdefault(f["kind"], []).append(f)
    alerts = []
    for kind, items in groups.items():
        sev = min((i["severity"] for i in items), key=lambda s: SEV_ORDER.get(s, 9))
        modules = {i["module"] for i in items}
        cve = []
        for i in items:
            for c in i["cve"]:
                if c and c not in cve:
                    cve.append(c)
        name = KIND_LABEL.get(kind) or (items[0]["title"] if len(items) == 1 else kind)
        alerts.append({
            "kind": kind, "name": name, "kb": R.lookup(kind), "severity": sev,
            "confidence": _confidence(modules), "instances": items,
            "cve": cve, "modules": sorted(modules),
        })
    alerts.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 9), -len(a["instances"])))
    return alerts


CLASSIFICATION = "RAHASIA / CONFIDENTIAL"
TOOLS = ["OWASP ZAP (DAST)", "Trivy (SCA/CVE)", "semgrep (SAST)", "gitleaks (secret)",
         "testssl.sh (TLS)",
         "runner internal Security Audit Kit (authz, mass-assignment, upload, auth-policy, "
         "client-leak, cors, open-redirect, webstack, injection)"]
# Indicative CVSS v3.1: representative score + vector per finding kind. A starting point only;
# the final vector must still be verified in the target's context.
KIND_CVSS = {
    "broken-access": (9.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"),
    "forged-header": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "idor": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "sql-injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "upload-accepted": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "mass-assignment": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "leaked-secret": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    "server-vuln": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "vuln-dependency": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "exposed-service": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "recon-finding": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "sast-finding": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "cors-misconfig": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "open-redirect": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "tls-weak": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "weak-password": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "info-exposure": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "js-leak": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "recon-subdomain": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "client-cache": (4.3, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "cookie-flags": (4.2, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "ssrf": (8.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"),
    "jwt-forgery": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "jwt-weak-secret": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "jwt-weak-config": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "captcha-answer-leak": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "session-not-revoked": (6.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "logout-no-invalidate": (6.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "old-password-accepted": (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "no-rate-limit": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "weak-lockout": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "lockout-bypass": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "user-enumeration": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "auth-coverage-gap": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "unauthenticated-endpoint": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "spec-mismatch": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "anon-server-error": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
    "sensitive-data-exposure": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "verbose-error": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "internal-info-leak": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "missing-header": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "captcha-static": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
}
# Representative fallback per severity when the kind is not registered.
CVSS_REP = {"critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "high": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
            "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "low": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "info": (0.0, "-"), "passed": (0.0, "-")}


def cvss_for(kind, severity):
    """Indicative CVSS v3.1 (score, vector) for a finding."""
    if kind in KIND_CVSS:
        return KIND_CVSS[kind]
    return CVSS_REP.get((severity or "info").lower(), (0.0, "-"))


def cvss_score(kind, severity):
    return f"{cvss_for(kind, severity)[0]:.1f}"


def cvss_full(kind, severity):
    score, vector = cvss_for(kind, severity)
    return f"{score:.1f} — {vector}" if vector and vector != "-" else f"{score:.1f}"


def finding_id(i):
    return f"SAK-{i:03d}"


def targets_path():
    """config/targets.yml of the active project (SAK_PROJECT_DIR from `audit.py --project`),
    or of the kit folder when unset."""
    base = os.environ.get("SAK_PROJECT_DIR") or Path(__file__).resolve().parent
    return Path(base) / "config" / "targets.yml"


def read_config():
    """Contents of targets.yml (best-effort; {} if missing or broken)."""
    try:
        import yaml
        p = targets_path()
        cfg = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def read_target():
    """Target name and base_url from the active project's targets.yml (best-effort)."""
    cfg = read_config()
    return cfg.get("name") or "-", cfg.get("base_url") or "-"


def report_meta(cfg=None):
    """Report preparer and organization, dynamic per project.

    Sources (by priority): env SAK_REPORT_AUTHOR / SAK_REPORT_ORG / SAK_REPORT_CONTACT, then the
    `report:` block in targets.yml (prepared_by, organization, contact, version). The organization
    defaults to DEFAULT_ORG when not set at all; set an empty string to hide it. The contact
    defaults to DEFAULT_CONTACT only when the organization is DEFAULT_ORG and no contact is set."""
    rc = ((read_config() if cfg is None else cfg) or {}).get("report") or {}
    rc = rc if isinstance(rc, dict) else {}

    def pick(env, key, default=""):
        if env in os.environ:
            return os.environ[env].strip()
        return str(rc[key]).strip() if key in rc and rc[key] is not None else default

    by = pick("SAK_REPORT_AUTHOR", "prepared_by", DEFAULT_AUTHOR)
    org = pick("SAK_REPORT_ORG", "organization", DEFAULT_ORG)
    contact = pick("SAK_REPORT_CONTACT", "contact", DEFAULT_CONTACT if org == DEFAULT_ORG else "")
    line = " — ".join(x for x in (by, org) if x)
    if line and contact:
        line = f"{line} ({contact})"
    return {"by": by, "org": org, "line": line, "version": str(rc.get("version") or "1.0"),
            "custom": bool(line)}


def exec_summary(alerts, counts):
    """Short executive summary in non-technical, management language."""
    total = sum(counts[s] for s in ("critical", "high", "medium", "low", "info"))
    if total == 0:
        return ("Tidak ditemukan temuan pada cakupan yang diuji; seluruh kontrol yang diuji "
                "berperilaku sesuai harapan. Pemeriksaan yang lolos dirinci pada bagian "
                "Kontrol yang Lolos sebagai bukti cakupan uji.")
    per = ", ".join(f"{counts[s]} {s.capitalize()}" for s in
                    ("critical", "high", "medium", "low", "info") if counts[s])
    top = "; ".join(a["name"] for a in alerts[:3])
    priority = ("Critical dan High" if (counts["critical"] or counts["high"])
                 else "Medium dan Low")
    return (f"Pengujian menemukan {total} instance temuan ({per}) yang tergolong dalam "
            f"{len(alerts)} jenis alert. Temuan berisiko tertinggi: {top}. Perbaikan "
            f"disarankan memprioritaskan temuan {priority} terlebih dahulu. Rincian teknis, "
            "bukti endpoint, dan rekomendasi tersedia pada bagian Rincian Temuan.")


def write_md(path, findings, counts, when, cves):
    I = glossary.italic_md  # technical terms in *italics*; see glosarium.yml
    failed = [f for f in findings if not f["passed"]]
    alerts = group_alerts(failed)
    tgt_name, tgt_url = read_target()
    meta = report_meta()
    modules = sorted({f["module"] for f in findings})
    L = [
        "# Laporan Hasil Uji Keamanan",
        "", f"**Klasifikasi:** {CLASSIFICATION}", "",
        "| | |", "|---|---|",
        f"| Dibuat | {when} |",
        f"| Disusun oleh | {meta['line'] or CREDIT} |",
    ] + ([f"| Alat | {CREDIT} |"] if meta["custom"] else []) + [
        f"| Target | {tgt_name} ({tgt_url}) |",
        f"| Versi dokumen | {meta['version']} |", "",
        "## 1. Ringkasan Eksekutif", "", I(exec_summary(alerts, counts)), "",
        "| Severity | Jumlah instance |", "|---|---|",
        f"| {SEV_EMOJI['critical']} Critical | {counts['critical']} |",
        f"| {SEV_EMOJI['high']} High | {counts['high']} |",
        f"| {SEV_EMOJI['medium']} Medium | {counts['medium']} |",
        f"| {SEV_EMOJI['low']} Low | {counts['low']} |",
        f"| {SEV_EMOJI['info']} Info | {counts['info']} |",
        f"| {SEV_EMOJI['passed']} PASS (kontrol lolos) | {counts['passed']} |",
        "", f"Total alert: **{len(alerts)}** · Total CVE: **{len(cves)}**.", "",
        "## 2. Ruang Lingkup & Metodologi", "",
        f"- **Target:** {tgt_name} ({tgt_url}).",
        f"- **Modul/teknik yang dijalankan:** {', '.join(modules) if modules else '-'}.",
        "- **Metodologi:** " + I(METHODOLOGY), "",
        "## 3. Ringkasan Risiko", "",
    ]
    # Alert list (ToC): finding ID, risk, indicative CVSS, confidence, instances.
    if alerts:
        L += ["| ID | Alert | Risiko | CVSS v3.1 | Keyakinan | Instance |",
              "|---|---|---|---|---|---|"]
        for i, a in enumerate(alerts, 1):
            L.append(f"| {finding_id(i)} | {I(a['name'])} | {SEV_EMOJI.get(a['severity'], '')} "
                     f"{a['severity'].upper()} | {cvss_score(a['kind'], a['severity'])} | "
                     f"{a['confidence']} | {len(a['instances'])} |")
        L.append("")
    else:
        L += ["_Tidak ada temuan — seluruh kontrol yang diuji lolos._", ""]

    L += ["## 4. Rincian Temuan", ""]
    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        L += [
            f"### {finding_id(i)} — {SEV_EMOJI.get(a['severity'], '')} {I(a['name'])}", "",
            f"- **Severity:** {a['severity'].upper()} &nbsp; **CVSS v3.1 (indikatif):** "
            f"{cvss_full(a['kind'], a['severity'])} &nbsp; **Keyakinan:** {a['confidence']} &nbsp; "
            f"**Status:** Terbuka",
            f"- **Sumber/plugin:** {', '.join(a['modules'])} (`{a['kind']}`)",
            f"- **Deskripsi:** {I(kb['description'])}",
            f"- **Instance yang diuji ({len(a['instances'])}):**", "",
            "  | # | Endpoint diuji | Konteks | HTTP | Bukti |",
            "  |---|---|---|---|---|",
        ]
        for j, inst in enumerate(a["instances"], 1):
            ctx = I(inst.get("title", ""))
            st = inst["status"] if inst["status"] not in (None, "") else "-"
            ev = (inst.get("evidence") or "").replace("|", "\\|").replace("\n", " ")[:160]
            if inst.get("screenshot"):
                ev = (ev + f" ![bukti]({inst['screenshot']})").strip()
            url = (inst.get("url") or "-").replace("|", "\\|")
            L.append(f"  | {j} | `{url}` | {ctx} | {st} | {ev} |")
        L += [
            "",
            (f"- **CVE/CWE:** {', '.join(a['cve'])}" if a["cve"] else "- **CVE/CWE:** -"),
            f"- **Dampak:** {I(kb['impact'])}",
            f"- **Justifikasi severity:** {I(kb['severity_basis'])}",
            "- **Rekomendasi & contoh solusi:**",
        ]
        for rec in kb["recommendation"]:
            if "\n" in rec or "    " in rec:
                L += ["", "  ```", *("  " + ln for ln in rec.splitlines()), "  ```", ""]
            else:
                L.append(f"  - {I(rec)}")
        L.append(f"- **Referensi:** {'; '.join(kb['references'])}")
        L.append("")

    # Passed controls: evidence of test coverage.
    passed = [f for f in findings if f["passed"]]
    if passed:
        L += [f"### Kontrol yang Lolos (PASS: {len(passed)})", "",
              "Pemeriksaan yang diuji dan berperilaku benar (bukan temuan) — bukti cakupan uji.", "",
              "| Pemeriksaan | Modul | Endpoint diuji | HTTP |", "|---|---|---|---|"]
        for f in passed:
            url = (f.get("url") or "-").replace("|", "\\|")
            st = f["status"] if f["status"] not in (None, "") else "-"
            L.append(f"| {I(f['title'])} | {f['module']} | `{url}` | {st} |")
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
        "Rating + vektor v3.1 representatif per jenis temuan); skor+vektor final tetap perlu diverifikasi manual per konteks target.", "",
        "**Batasan & pertanggungjawaban.** " + I(LIMITATIONS), "",
        "---", "", f"_{CREDIT}_", "",
    ]
    path.write_text("\n".join(L), encoding="utf-8")


def write_html(path, findings, counts, when, cves):
    def esc(x):
        return html.escape(str(x))

    def rich(x):
        return glossary.italic_html(esc(x))

    failed = [f for f in findings if not f["passed"]]
    alerts = group_alerts(failed)

    cards = "".join(
        f"<div class='card{' zero' if not counts[s] else ''}'>"
        f"<div class='n' style='color:{SEV_COLOR[s]}'>{counts[s]}</div>"
        f"<div class='l'>{sev_label(s)}</div></div>" for s in SEV_ORDER)

    tgt_name, tgt_url = read_target()
    modules = sorted({f["module"] for f in findings})

    # Alert list (ToC): finding ID, risk, indicative CVSS, confidence, instances.
    toc_rows = "".join(
        f"<tr><td><a href='#alert-{i}'>{esc(finding_id(i))}</a></td><td>{rich(a['name'])}</td>"
        f"<td><span class='badge' style='background:{SEV_COLOR[a['severity']]}'>"
        f"{esc(a['severity'].upper())}</span></td><td>{esc(cvss_score(a['kind'], a['severity']))}</td>"
        f"<td>{esc(a['confidence'])}</td><td>{len(a['instances'])}</td></tr>"
        for i, a in enumerate(alerts, 1)) or \
        "<tr><td colspan='6'>Tidak ada temuan — semua kontrol yang diuji lolos.</td></tr>"

    blocks = ""
    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        recs = ""
        for rec in kb["recommendation"]:
            recs += (f"<pre>{esc(rec)}</pre>" if ("\n" in rec or "    " in rec)
                     else f"<li>{rich(rec)}</li>")
        def _cell(inst):
            cell = esc(inst.get("evidence") or "")
            ss = inst.get("screenshot")
            if ss:
                cell += (f"<div class='shotwrap'><a href='{esc(ss)}' target='_blank' "
                         f"rel='noopener'><img class='shot' src='{esc(ss)}' alt='bukti'></a></div>")
            return cell
        inst_rows = "".join(
            f"<tr><td>{j}</td><td><code>{esc(inst.get('url') or '-')}</code></td>"
            f"<td>{rich(inst.get('title', ''))}</td>"
            f"<td>{esc(inst['status'] if inst['status'] not in (None, '') else '-')}</td>"
            f"<td>{_cell(inst)}</td></tr>"
            for j, inst in enumerate(a["instances"], 1))
        cve = ", ".join(a["cve"]) if a["cve"] else "-"
        col = SEV_COLOR[a["severity"]]
        blocks += f"""
        <div class="finding" id="alert-{i}">
          <h3><span class="badge" style="background:{col}">{esc(a['severity'].upper())}</span>
              {esc(finding_id(i))} — {rich(a['name'])}</h3>
          <p><b>Severity:</b> {esc(a['severity'].upper())} &nbsp;·&nbsp;
             <b>CVSS v3.1 (indikatif):</b> {esc(cvss_full(a['kind'], a['severity']))} &nbsp;·&nbsp;
             <b>Keyakinan:</b> {esc(a['confidence'])} &nbsp;·&nbsp;
             <b>Status:</b> Terbuka</p>
          <p><b>Sumber/plugin:</b> {esc(', '.join(a['modules']))} (<code>{esc(a['kind'])}</code>)
             &nbsp;·&nbsp; <b>CVE/CWE:</b> {esc(cve)}</p>
          <p><b>Deskripsi.</b> {rich(kb['description'])}</p>
          <p><b>Instance yang diuji ({len(a['instances'])}):</b></p>
          <table class="inst"><thead><tr><th>#</th><th>Endpoint diuji (bukti)</th>
            <th>Konteks</th><th>HTTP</th><th>Catatan</th></tr></thead>
            <tbody>{inst_rows}</tbody></table>
          <p><b>Dampak.</b> {rich(kb['impact'])}</p>
          <p><b>Justifikasi severity.</b> {rich(kb['severity_basis'])}</p>
          <p><b>Rekomendasi & contoh solusi.</b></p><ul>{recs}</ul>
          <p class="ref"><b>Referensi:</b> {esc('; '.join(kb['references']))}</p>
        </div>"""
    if not alerts:
        blocks = "<p>Tidak ada temuan — semua kontrol yang diuji lolos.</p>"

    passed = [f for f in findings if f["passed"]]
    passed_rows = "".join(
        f"<tr><td>{rich(f['title'])}</td><td>{esc(f['module'])}</td>"
        f"<td><code>{esc(f.get('url') or '-')}</code></td>"
        f"<td>{esc(f['status'] if f['status'] not in (None, '') else '-')}</td></tr>"
        for f in passed)
    passed_section = (
        f"<h2>Kontrol yang Lolos (PASS: {len(passed)})</h2>"
        f"<p>Pemeriksaan yang diuji dan berperilaku benar — bukan temuan; bukti cakupan uji.</p>"
        f"<table><thead><tr><th>Pemeriksaan</th><th>Modul</th>"
        f"<th>Endpoint diuji</th><th>HTTP</th></tr></thead><tbody>{passed_rows}</tbody></table>"
    ) if passed else ""

    cve_rows = "".join(
        f"<tr><td><a href='https://nvd.nist.gov/vuln/detail/{esc(c['id'])}' "
        f"target='_blank' rel='noopener'>{esc(c['id'])}</a></td><td>{esc(c['where'])}</td>"
        f"<td><span class='badge' style='background:{SEV_COLOR.get(c['sev'],'#555')}'>{esc(c['sev'].upper())}</span></td></tr>"
        for c in cves) or "<tr><td colspan='3'>Tidak ada CVE terdeteksi.</td></tr>"

    credit_html = (f"{esc(KIT_NAME)} — dibuat oleh <b>{esc(KIT_AUTHOR)}</b> · "
                   f"<a href='{esc(KIT_URL)}' target='_blank' rel='noopener'>{esc(KIT_URL)}</a>")
    meta = report_meta()
    author_rows = (f"<tr><td>Disusun oleh</td><td>{esc(meta['line'])}</td></tr>"
                   f"<tr><td>Alat</td><td>{credit_html}</td></tr>"
                   if meta["custom"] else f"<tr><td>Disusun oleh</td><td>{credit_html}</td></tr>")

    doc = f"""<!doctype html><html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Laporan Uji Keamanan</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24;line-height:1.5}}
 header{{background:#14233b;color:#fff;padding:24px 20px}} h1{{margin:0;font-size:20px}}
 .sub{{opacity:.85;font-size:13px;margin-top:4px}} .sub a{{color:#9ec5ff}}
 main{{max-width:1000px;margin:0 auto;padding:20px}}
 h2{{border-bottom:2px solid #e3e7ec;padding-bottom:6px;margin-top:32px}}
 .note{{background:#fff;border:1px solid #e3e7ec;padding:12px 14px;border-radius:6px;font-size:14px}}
 .cards{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
 .card{{flex:1;min-width:110px;background:#fff;border:1px solid #e3e7ec;border-radius:8px;padding:12px 14px;box-shadow:0 1px 2px rgba(0,0,0,.06)}}
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
 .shot{{max-width:280px;max-height:170px;border:1px solid #ccd;border-radius:6px;margin-top:6px;display:block}}
 .shotwrap{{margin-top:4px}}
 footer{{max-width:1000px;margin:0 auto;padding:16px 20px 40px;color:#555;font-size:12px;border-top:1px solid #e3e7ec}}
 footer a{{color:#14233b}}
 .klas{{display:inline-block;background:#b4232a;color:#fff;font-size:11px;font-weight:700;letter-spacing:.08em;padding:3px 10px;border-radius:4px;margin-top:8px}}
 .meta td{{font-size:13px}} .meta td:first-child{{color:#555;width:160px;white-space:nowrap}}
 .exec{{background:#fff;border:1px solid #e3e7ec;padding:14px 16px;border-radius:6px;font-size:14px}}
</style>
<header><h1>Laporan Hasil Uji Keamanan</h1>
<div class="sub">{(esc(meta['org']) + ' · ') if meta['org'] else ''}Dibuat {esc(when)}</div>
<div class="klas">{esc(CLASSIFICATION)}</div></header>
<main>
<table class="meta"><tbody>
{author_rows}
<tr><td>Target</td><td>{esc(tgt_name)} (<code>{esc(tgt_url)}</code>)</td></tr>
<tr><td>Versi dokumen</td><td>{esc(meta['version'])}</td></tr>
</tbody></table>
<h2>1. Ringkasan Eksekutif</h2>
<div class="exec">{rich(exec_summary(alerts, counts))}</div>
<div class="cards">{cards}</div>
<p>Total alert: <b>{len(alerts)}</b> · Total CVE: <b>{len(cves)}</b>.</p>
<h2>2. Ruang Lingkup &amp; Metodologi</h2>
<div class="note"><p><b>Target.</b> {esc(tgt_name)} (<code>{esc(tgt_url)}</code>)</p>
<p><b>Modul/teknik.</b> {esc(', '.join(modules) if modules else '-')}</p>
<p><b>Metodologi.</b> {glossary.italic_html(html.escape(METHODOLOGY))}</p></div>
<h2>3. Ringkasan Risiko</h2>
<table><thead><tr><th>ID</th><th>Alert</th><th>Risiko</th><th>CVSS v3.1</th><th>Keyakinan</th><th>Instance</th></tr></thead>
<tbody>{toc_rows}</tbody></table>
<h2>4. Rincian Temuan</h2>{blocks}
{passed_section}
<h2>5. Daftar CVE</h2>
<table><thead><tr><th>CVE</th><th>Paket/Lokasi</th><th>Severity</th></tr></thead><tbody>{cve_rows}</tbody></table>
<h2>6. Lampiran</h2>
<div class="note"><p><b>Tooling &amp; acuan.</b> {esc('; '.join(TOOLS))}. Acuan: OWASP Top 10 2021, OWASP API Security Top 10 2023, OWASP ASVS, OWASP Risk Rating Methodology.</p>
<p><b>Catatan CVSS.</b> Skor CVSS bersifat indikatif (pemetaan kualitatif dari OWASP Risk Rating + vektor v3.1 representatif per jenis temuan); skor+vektor final tetap perlu diverifikasi manual per konteks target.</p>
<p><b>Batasan &amp; pertanggungjawaban.</b> {glossary.italic_html(html.escape(LIMITATIONS))}</p></div>
</main>
<footer>{credit_html}</footer>
</html>"""
    path.write_text(doc, encoding="utf-8")


def write_slides(path, findings, counts, when, cves):
    """Report variant as a standalone slide deck (inline HTML+CSS+JS, no dependencies).

    Navigate with the left/right arrows or by clicking. Meant for a short stakeholder
    presentation; the full report stays in laporan.html.
    """
    def esc(x):
        return html.escape(str(x))

    def rich(x):
        return glossary.italic_html(esc(x))

    alerts = group_alerts([f for f in findings if not f["passed"]])
    tgt_name, tgt_url = read_target()
    meta = report_meta()
    by_html = f"<p class='meta'>Disusun oleh {esc(meta['line'])}</p>" if meta["custom"] else ""
    total = sum(counts[s] for s in ("critical", "high", "medium", "low", "info"))

    slides = [f"""<section class="slide cover">
      <div class="klas">{esc(CLASSIFICATION)}</div>
      <h1>Laporan Hasil Uji Keamanan</h1>
      <p class="tgt">{esc(tgt_name)} <span class="u">{esc(tgt_url)}</span></p>
      <p class="meta">{esc(when)}</p>{by_html}
      <p class="credit">{esc(CREDIT)}</p></section>"""]

    cards = "".join(
        f"<div class='scard'>"
        f"<div class='n' style='color:{SEV_COLOR[s]}'>{counts[s]}</div>"
        f"<div class='l'>{sev_label(s)}</div></div>"
        for s in ("critical", "high", "medium", "low", "info"))
    slides.append(f"""<section class="slide"><h2>Ringkasan Risiko</h2>
      <div class="scards">{cards}</div>
      <p class="big">{total} instance temuan · {len(alerts)} alert · {len(cves)} CVE · {counts['passed']} kontrol lolos</p></section>""")

    slides.append(f"""<section class="slide"><h2>Ringkasan Eksekutif</h2>
      <p class="exec">{rich(exec_summary(alerts, counts))}</p></section>""")

    for i, a in enumerate(alerts, 1):
        kb = a["kb"]
        rec1 = rich(kb["recommendation"][0]) if kb.get("recommendation") else ""
        col = SEV_COLOR[a["severity"]]
        shot = next((inst["screenshot"] for inst in a["instances"]
                     if inst.get("screenshot")), "")
        shot_html = (f"<div class='shotwrap'><img class='shot' src='{esc(shot)}' "
                     f"alt='bukti'></div>" if shot else "")
        slides.append(f"""<section class="slide" style="border-top:7px solid {col}">
          <div class="fid">{esc(finding_id(i))} &nbsp;·&nbsp;
            <span class="badge" style="background:{col}">{esc(a['severity'].upper())}</span>
            &nbsp;·&nbsp; CVSS {esc(cvss_score(a['kind'], a['severity']))} &nbsp;·&nbsp;
            {len(a['instances'])} instance</div>
          <h2>{rich(a['name'])}</h2>
          <p><b>Dampak.</b> {rich(kb['impact'])}</p>
          <p><b>Rekomendasi utama.</b> {rec1}</p>{shot_html}</section>""")

    slides.append(f"""<section class="slide cover"><h2>Terima kasih</h2>
      <p class="meta">Laporan lengkap: <code>laporan.html</code>. Dokumen bersifat {esc(CLASSIFICATION)}.</p>
      <p class="credit">{esc(CREDIT)}</p></section>""")

    deck = "".join(slides)
    doc = f"""<!doctype html><html lang="id"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Laporan Uji Keamanan — Presentasi</title>
<style>
 *{{box-sizing:border-box}} body{{margin:0;font-family:system-ui,Segoe UI,sans-serif;background:#0b1626;color:#1b1f24;overflow:hidden}}
 .slide{{display:none;position:fixed;inset:0;padding:6vh 8vw;flex-direction:column;justify-content:center;background:#f6f7f9}}
 .slide.active{{display:flex}}
 .slide.cover{{background:#14233b;color:#fff;align-items:flex-start}}
 .slide.cover h1{{font-size:5vh;margin:.2em 0}} .slide h2{{font-size:4.2vh;margin:.1em 0 .4em}}
 .slide p{{font-size:2.6vh;line-height:1.5;max-width:60ch}} .slide .big{{font-size:3vh;font-weight:600}}
 .klas{{display:inline-block;background:#b4232a;color:#fff;font-size:1.8vh;font-weight:700;letter-spacing:.08em;padding:4px 12px;border-radius:4px}}
 .tgt{{font-size:3vh;font-weight:600}} .tgt .u{{opacity:.7;font-weight:400;font-size:2.2vh}}
 .meta{{opacity:.8}} .credit{{opacity:.75;font-size:2vh}}
 .scards{{display:flex;gap:2vw;margin:3vh 0}}
 .scard{{flex:1;background:#fff;border:1px solid #e3e7ec;border-radius:10px;padding:2.5vh 2vw;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,.08)}}
 .scard .n{{font-size:6vh;font-weight:800}} .scard .l{{font-size:1.6vh;letter-spacing:.05em;color:#555}}
 .badge{{color:#fff;font-size:1.8vh;padding:2px 10px;border-radius:12px}}
 .fid{{font-size:2vh;color:#555;margin-bottom:1vh}} code{{background:#0003;padding:1px 6px;border-radius:4px}}
 #nav{{position:fixed;bottom:2vh;right:3vw;color:#8aa;font-size:1.8vh;z-index:9}}
 #nav button{{background:#ffffff22;color:inherit;border:1px solid #ffffff44;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:1.8vh}}
 .shot{{max-height:34vh;max-width:70vw;border:1px solid #ccd;border-radius:8px;margin-top:2vh}} .shotwrap{{margin-top:1vh}}
</style>
<div id="deck">{deck}</div>
<div id="nav"><button onclick="go(-1)">‹</button> <span id="pg"></span> <button onclick="go(1)">›</button></div>
<script>
 var s=[].slice.call(document.querySelectorAll('.slide')),i=0;
 function show(n){{i=Math.max(0,Math.min(s.length-1,n));s.forEach(function(e,k){{e.classList.toggle('active',k===i)}});document.getElementById('pg').textContent=(i+1)+' / '+s.length}}
 function go(d){{show(i+d)}}
 document.addEventListener('keydown',function(e){{if(e.key==='ArrowRight'||e.key===' ')go(1);if(e.key==='ArrowLeft')go(-1)}});
 document.getElementById('deck').addEventListener('click',function(e){{if(e.target.tagName!=='BUTTON'&&!e.target.closest('a'))go(1)}});
 show(0);
</script></html>"""
    path.write_text(doc, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(Path(os.environ.get("SAK_PROJECT_DIR") or ".") / "reports"))
    args = ap.parse_args()
    d = Path(args.dir)
    d.mkdir(parents=True, exist_ok=True)
    # Include the UTC offset so the report time is unambiguous across regions.
    now = dt.datetime.now().astimezone()
    off = now.strftime("%z")                     # e.g. +0700
    off_fmt = f"UTC{off[:3]}:{off[3:]}" if off else "UTC"
    tzname = now.strftime("%Z")
    when = now.strftime("%Y-%m-%d %H:%M") + f" ({off_fmt}" + (f" {tzname}" if tzname else "") + ")"

    findings = collect(d)
    counts = summarize(findings)
    # Unique CVEs for the table.
    cves = []
    seen = set()
    for f in findings:
        for c in f["cve"]:
            if c and c.startswith("CVE") and c not in seen:
                seen.add(c)
                cves.append({"id": c, "where": f["title"], "sev": f["severity"]})

    write_md(d / "laporan.md", findings, counts, when, cves)
    write_html(d / "laporan.html", findings, counts, when, cves)
    write_slides(d / "laporan-slides.html", findings, counts, when, cves)

    failed = sum(1 for f in findings if not f["passed"])
    print(f"Laporan: {d/'laporan.html'} & {d/'laporan.md'} & {d/'laporan-slides.html'}")
    needs_action = C.bad(failed) if failed else C.good(failed)
    print(f"Total {len(findings)} item, {needs_action} perlu tindak lanjut, {len(cves)} CVE.")
    # Color a severity only when it has findings; dim the zero ones.
    summary_text = " · ".join(
        C.severity(s, f"{s.capitalize()} {counts[s]}") if counts[s] else C.dim(f"{s.capitalize()} {counts[s]}")
        for s in ("critical", "high", "medium", "low", "info"))
    print(f"  {summary_text}")
    return 0


if __name__ == "__main__":
    main()
