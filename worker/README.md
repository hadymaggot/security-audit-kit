# Open Scanner (Cloudflare Worker)

Backend **pasif** untuk demo open scanner di GitHub Pages. Hanya memeriksa respons yang
sudah dilayani publik — **security headers, cookie flags, CORS misconfig, dan banner
`Server`/`X-Powered-By` → CVE** — seperti SSL Labs / securityheaders.com. **Tidak ada**
payload serangan, penulisan data, atau brute-force.

Modul aktif/intrusif (injection, access control, upload, mass-assignment, auth-policy,
dll.) **sengaja tidak ada di sini** — gunakan CLI pada target yang Anda miliki.

## Pengaman bawaan
- **Anti-SSRF:** menolak host privat/loopback/link-local & metadata cloud, hanya
  `http`/`https` dengan port standar.
- **Rate limit** per IP (KV) + **cap subrequest** + **timeout** per request.
- **CORS** dibatasi ke origin Pages Anda (`ALLOW_ORIGIN`).

> Catatan: Worker tidak dapat me-resolve DNS untuk mendeteksi hostname yang menunjuk ke
> IP privat (risiko DNS-rebinding sisa). Untuk produksi, lengkapi dengan Cloudflare WAF /
> Rate Limiting rules di dashboard.

## Deploy (butuh akun Cloudflare Anda)

```
cd worker
npm install
npx wrangler login
npx wrangler kv namespace create RL     # salin "id" ke kv_namespaces di wrangler.jsonc
# sesuaikan vars.ALLOW_ORIGIN ke origin Pages Anda (mis. https://hadymaggot.github.io)
npx wrangler deploy
```

Setelah deploy, catat URL Worker (mis. `https://security-audit-kit-scanner.<akun>.workers.dev`)
lalu isi di `docs/scan.html` (konstanta `WORKER_URL`) atau lewat query `?api=<url>`.

## Endpoint
`POST /scan` dengan body `{"url": "https://target-anda.example"}` → JSON `{target, findings, notice}`.
