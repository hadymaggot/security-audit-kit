# Open Scanner (Cloudflare Worker)

Backend pasif untuk halaman open scanner di GitHub Pages. Worker hanya membaca response yang sudah dilayani publik, seperti SSL Labs atau securityheaders.com. Tidak ada payload serangan, penulisan data, atau brute-force.

Pemeriksaan: security header, cookie flags, versi dari banner `Server`/`X-Powered-By` dipetakan ke CVE, CORS, dan secret/source map di HTML. Modul aktif (injection, access control, upload, dan lainnya) sengaja tidak ada di sini; gunakan CLI pada target milik sendiri.

## Pengaman bawaan

- Anti-SSRF: host privat, loopback, link-local, dan metadata cloud ditolak. Hanya `http`/`https` dengan port 80, 443, 8080, atau 8443.
- Rate limit per IP (KV), `RATE_PER_MIN` request per menit, bawaan 10.
- Timeout 10 detik per request dan dua request keluar per scan.
- CORS dibatasi ke `ALLOW_ORIGIN`; jika kosong, semua origin diizinkan.

Worker tidak dapat me-resolve DNS, sehingga hostname yang menunjuk ke IP privat (DNS rebinding) masih lolos. Untuk production, tambahkan aturan WAF atau Rate Limiting di dashboard Cloudflare.

## Deploy

Butuh akun Cloudflare dan Node.js.

1. Instal dependency dan login.

   ```
   cd worker
   npm install
   npx wrangler login
   ```

2. Buat KV namespace untuk rate limit, lalu salin `id` dari output ke `kv_namespaces` di `wrangler.jsonc`, menggantikan `GANTI_DENGAN_KV_ID`.

   ```
   npx wrangler kv namespace create RL
   ```

3. Atur variabel di blok `vars` pada `wrangler.jsonc`.

   | Variabel | Isi | Bawaan |
   |---|---|---|
   | `ALLOW_ORIGIN` | Origin situs Pages yang boleh memanggil Worker, tanpa path | `https://hadymaggot.github.io` |
   | `RATE_PER_MIN` | Batas request per IP per menit | `10` |

4. Deploy dan catat URL Worker, misalnya `https://security-audit-kit-scanner.<akun>.workers.dev`.

   ```
   npx wrangler deploy
   ```

## Uji dengan curl

```
curl -X POST https://security-audit-kit-scanner.<akun>.workers.dev/scan -H "Content-Type: application/json" -d '{"url": "https://dev.example.com"}'
```

Response `200` berisi JSON `{target, scanned_at, modules, notice, findings}`. Kode lain: `400` untuk URL tidak valid atau host yang diblokir, `405` jika bukan `POST`, `429` jika rate limit tercapai, `502` jika target tidak terjangkau.

## Hubungkan ke situs

Situs memanggil Worker lewat konstanta `WORKER_URL` di `site/scan.template.html`. Ubah nilainya ke URL Worker Anda, lalu bangun ulang situs:

```
python scripts/build_site.py
```

Untuk uji tanpa membangun ulang, buka halaman scan dengan query `?api=<url-worker>`.
