/**
 * Security Audit Kit — open scanner (Cloudflare Worker).
 *
 * ONLY PASSIVE/observational checks on responses already served publicly (like
 * SSL Labs / securityheaders.com): security headers, cookie flags, CORS misconfig, and
 * Server/X-Powered-By banners -> known CVEs. NO attack payloads, NO data writes, NO
 * brute force. Active modules (injection, authz, upload, mass-assignment, auth-policy,
 * etc.) are deliberately NOT included here; they are for self-owned targets via the CLI only.
 *
 * Safeguards: anti-SSRF (reject private/loopback/link-local IPs and cloud metadata, only
 * http/https on standard ports), per-IP rate limit (KV), subrequest cap, and timeout.
 */

export interface Env {
  RL: KVNamespace;            // rate-limit counter (create with: wrangler kv namespace create RL)
  ALLOW_ORIGIN?: string;      // Pages origin allowed to call (e.g. https://hadymaggot.github.io)
  RATE_PER_MIN?: string;      // default 10
}

const PROBE_ORIGIN = "https://sak-cors-probe.example";
const FETCH_TIMEOUT_MS = 10_000;

// Compact list of vulnerable versions (banner-based, confidence "Sedang"). Keep in sync with
// the webstack module when needed.
const KNOWN_VULNERABLE: Array<{
  server: string; min?: string; max?: string; cve: string; note: string;
}> = [
  { server: "apache", max: "2.4.71", cve: "CVE-2026-119618", note: "Apache mod_http2 RCE" },
  { server: "nginx", min: "1.9.5", max: "1.30.7", cve: "CVE-2026-123007", note: "NGINX HTTP/2 RCE" },
  { server: "nginx", min: "1.9.5", max: "1.30.7", cve: "CVE-2026-123633", note: "NGINX HTTP/2 RCE" },
  { server: "php", min: "8.5.0", max: "8.5.12", cve: "CVE-2026-109618", note: "PHP2Shell RCE" },
  { server: "php", min: "8.4.0", max: "8.4.27", cve: "CVE-2026-109618", note: "PHP2Shell RCE" },
  { server: "php", min: "8.3.0", max: "8.3.36", cve: "CVE-2026-109618", note: "PHP2Shell RCE" },
  { server: "php", min: "8.2.0", max: "8.2.35", cve: "CVE-2026-109618", note: "PHP2Shell RCE" },
];

type Finding = {
  module: string; check: string; severity: string; ok: boolean; note: string;
  cve?: string[];
};

function verTuple(s: string): number[] {
  const out: number[] = [];
  for (const part of String(s).split(".")) {
    const m = part.match(/^\d+/);
    if (!m) break;
    out.push(parseInt(m[0], 10));
  }
  return out;
}

function lessThan(a: string, b: string): boolean {
  const ta = verTuple(a), tb = verTuple(b);
  const n = Math.max(ta.length, tb.length);
  while (ta.length < n) ta.push(0);
  while (tb.length < n) tb.push(0);
  for (let i = 0; i < n; i++) {
    if (ta[i] !== tb[i]) return ta[i] < tb[i];
  }
  return false;
}

function parseBanner(value: string): [string, string] {
  const m = (value || "").match(/([A-Za-z][A-Za-z0-9_+.-]*)\/(\d+(?:\.\d+){1,3})/);
  if (m) return [m[1].toLowerCase(), m[2]];
  return [(value || "").trim().toLowerCase(), ""];
}

// --- anti-SSRF ---------------------------------------------------------------

function ipv4Private(h: string): boolean {
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;          // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function blockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") ||
      h.endsWith(".internal") || h === "metadata.google.internal") return true;
  if (ipv4Private(h)) return true;
  // IPv6 loopback / unique-local / link-local / unspecified / IPv4-mapped private.
  if (h === "::1" || h === "::" || h.startsWith("fc") || h.startsWith("fd") ||
      h.startsWith("fe80") || h.includes("::ffff:")) return true;
  return false;
}

function validateTarget(raw: string): { url?: URL; error?: string } {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { error: "URL tidak valid." };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { error: "Hanya http/https yang diizinkan." };
  }
  if (url.port && !["80", "443", "8080", "8443"].includes(url.port)) {
    return { error: "Hanya port standar (80/443/8080/8443) yang diizinkan." };
  }
  if (blockedHost(url.hostname)) {
    return { error: "Host privat/loopback/metadata diblokir (anti-SSRF)." };
  }
  return { url };
}

// --- rate limit --------------------------------------------------------------

async function rateLimited(env: Env, ip: string): Promise<boolean> {
  const limit = parseInt(env.RATE_PER_MIN || "10", 10);
  const key = `rl:${ip}:${Math.floor(Date.now() / 60_000)}`;
  const cur = parseInt((await env.RL.get(key)) || "0", 10);
  if (cur >= limit) return true;
  await env.RL.put(key, String(cur + 1), { expirationTtl: 90 });
  return false;
}

// --- checks (passive) --------------------------------------------------------

async function timedFetch(url: string, init: RequestInit): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: ctl.signal, redirect: "manual" });
  } finally {
    clearTimeout(t);
  }
}

function checkHeaders(h: Headers): Finding[] {
  const out: Finding[] = [];
  const want: Array<[string, string]> = [
    ["content-security-policy", "Content-Security-Policy"],
    ["strict-transport-security", "Strict-Transport-Security (HSTS)"],
    ["x-content-type-options", "X-Content-Type-Options"],
    ["x-frame-options", "X-Frame-Options"],
    ["referrer-policy", "Referrer-Policy"],
  ];
  for (const [key, label] of want) {
    const present = h.has(key);
    out.push({
      module: "headers", check: label, severity: present ? "lulus" : "low",
      ok: present, note: present ? "" : "header keamanan tidak diset",
    });
  }
  const setCookie = h.get("set-cookie") || "";
  if (setCookie) {
    const lc = setCookie.toLowerCase();
    const flags = ["secure", "httponly", "samesite"].filter((f) => !lc.includes(f));
    out.push({
      module: "headers", check: "Cookie flags", severity: flags.length ? "low" : "lulus",
      ok: flags.length === 0,
      note: flags.length ? `flag kurang: ${flags.join(", ")}` : "",
    });
  }
  const server = h.get("server") || "";
  const powered = h.get("x-powered-by") || "";
  if (/\/\d/.test(server) || powered) {
    out.push({
      module: "headers", check: "Version disclosure", severity: "low", ok: false,
      note: `banner membocorkan versi: ${[server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join("; ")}`,
    });
  }
  return out;
}

function checkWebstack(h: Headers): Finding[] {
  const out: Finding[] = [];
  const candidates: Array<[string, string]> = [];
  const [sn, sv] = parseBanner(h.get("server") || "");
  if (sn) candidates.push([sn, sv]);
  const [pn, pv] = parseBanner(h.get("x-powered-by") || "");
  if (pn) candidates.push([pn, pv]);
  const flagged = new Set<string>();
  for (const kv of KNOWN_VULNERABLE) {
    for (const [cname, cver] of candidates) {
      if (!cname.includes(kv.server) || !cver) continue;
      if (kv.min && lessThan(cver, kv.min)) continue;
      if (kv.max && !lessThan(cver, kv.max)) continue;
      if (flagged.has(kv.cve)) continue;
      flagged.add(kv.cve);
      out.push({
        module: "webstack", check: `Versi rentan: ${cname} ${cver}`, severity: "high",
        ok: false, note: `${kv.cve} — ${kv.note}. Konfirmasi ke advisory vendor.`,
        cve: [kv.cve],
      });
    }
  }
  return out;
}

async function checkCors(target: string): Promise<Finding[]> {
  try {
    const r = await timedFetch(target, { method: "GET", headers: { Origin: PROBE_ORIGIN } });
    const acao = r.headers.get("access-control-allow-origin") || "";
    const acac = (r.headers.get("access-control-allow-credentials") || "").toLowerCase();
    if (acao === PROBE_ORIGIN) {
      return [{ module: "cors", check: "CORS reflektif", severity: "medium", ok: false,
        note: `ACAO memantulkan Origin asing${acac === "true" ? " + credentials" : ""}` }];
    }
    if (acao === "*" && acac === "true") {
      return [{ module: "cors", check: "CORS wildcard+credentials", severity: "medium",
        ok: false, note: "ACAO '*' dipadu Allow-Credentials: true" }];
    }
    return [{ module: "cors", check: "CORS", severity: "lulus", ok: true, note: "" }];
  } catch {
    return [{ module: "cors", check: "CORS", severity: "lulus", ok: true, note: "skip" }];
  }
}

// PASSIVE clientleak: analyzes HTML that is ALREADY served publicly (no extra fetches /
// file probing) for secret patterns and source map references. Reads only what any browser
// sees, so it is non-intrusive.
function checkClientleak(body: string): Finding[] {
  const out: Finding[] = [];
  const b = (body || "").slice(0, 500_000);
  const patterns: Array<[RegExp, string, string]> = [
    [/AKIA[0-9A-Z]{16}/, "AWS Access Key ID", "high"],
    [/AIza[0-9A-Za-z_\-]{35}/, "Google API Key", "high"],
    [/gh[pousr]_[0-9A-Za-z]{30,}/, "GitHub token", "high"],
    [/xox[baprs]-[0-9A-Za-z-]{10,}/, "Slack token", "high"],
    [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "Private key block", "high"],
    [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, "JWT terekspos", "medium"],
    [/(?:secret|password|passwd|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"'\s]{8,}["']/i,
      "Kredensial ter-hardcode (kemungkinan)", "medium"],
  ];
  const seen = new Set<string>();
  for (const [re, label, sev] of patterns) {
    if (re.test(b) && !seen.has(label)) {
      seen.add(label);
      out.push({ module: "clientleak", check: label, severity: sev, ok: false,
        note: "pola rahasia terdeteksi pada HTML publik — verifikasi manual" });
    }
  }
  if (/sourceMappingURL\s*=/.test(b)) {
    out.push({ module: "clientleak", check: "Source map terekspos", severity: "low", ok: false,
      note: "referensi sourceMappingURL di aset publik (bisa membocorkan kode sumber)" });
  }
  if (out.length === 0) {
    out.push({ module: "clientleak", check: "Secret/source map di HTML", severity: "lulus", ok: true, note: "" });
  }
  return out;
}

// --- handler -----------------------------------------------------------------

function cors(env: Env, req: Request): Record<string, string> {
  const allow = env.ALLOW_ORIGIN || "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(body: unknown, status: number, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ch = cors(env, request);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: ch });
    const url = new URL(request.url);
    if (url.pathname !== "/scan") return json({ error: "not found" }, 404, ch);
    if (request.method !== "POST") return json({ error: "gunakan POST /scan" }, 405, ch);

    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    if (await rateLimited(env, ip)) {
      return json({ error: "Rate limit tercapai, coba lagi sebentar lagi." }, 429, ch);
    }

    let target = "";
    try {
      target = (await request.json<{ url?: string }>()).url || "";
    } catch {
      return json({ error: "body JSON {url} wajib." }, 400, ch);
    }
    const v = validateTarget(target);
    if (v.error || !v.url) return json({ error: v.error }, 400, ch);

    const findings: Finding[] = [];
    try {
      const r = await timedFetch(v.url.toString(), { method: "GET" });
      findings.push(...checkHeaders(r.headers));
      findings.push(...checkWebstack(r.headers));
      const ct = (r.headers.get("content-type") || "").toLowerCase();
      if (r.status >= 200 && r.status < 300 &&
          /(text\/html|application\/javascript|text\/javascript|application\/json)/.test(ct)) {
        let body = "";
        try { body = await r.text(); } catch { body = ""; }
        findings.push(...checkClientleak(body));
      }
    } catch {
      return json({ error: "Target tidak dapat dijangkau." }, 502, ch);
    }
    findings.push(...(await checkCors(v.url.toString())));

    return json({
      target: v.url.toString(),
      scanned_at: new Date().toISOString(),
      modules: ["headers", "webstack", "cors", "clientleak"],
      notice: "Pemeriksaan PASIF non-intrusif saja. Untuk uji mendalam (injection, " +
        "access control, upload, dll.) gunakan CLI pada target yang Anda miliki.",
      findings,
    }, 200, ch);
  },
};
