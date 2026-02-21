# Botnet Guard Worker (Cloudflare Free-Tier Friendly)

This repo now includes a Cloudflare Worker that:

1. Monitors requests across your full site
2. Tracks per-IP request volume (normal window + burst window) in KV
3. Scores bot signatures (suspicious paths, bad/missing user-agent)
4. Blocks abusive IPs for a temporary TTL
5. Lets you manually block/unblock/check IPs via admin endpoints

It does not require paid Cloudflare WAF rate-limiting features.

## Files

- `src/worker.js` - Worker logic
- `wrangler.toml` - Worker config
- `scripts/upload-cloudflare-ips.js` - legacy helper script (optional)

## 1) Install and create KV namespace

```bash
npm install
npx wrangler kv namespace create BOTNET_KV
npx wrangler kv namespace create BOTNET_KV --preview
```

Copy the printed `id` values into `wrangler.toml` under `[[kv_namespaces]]`.

## 2) Set admin token (required for admin endpoints)

```bash
npx wrangler secret put BOTNET_ADMIN_TOKEN
```

## 3) Deploy

```bash
npm run deploy
```

Then attach the Worker to your domain route in Cloudflare (for example `example.com/*`).

## Config knobs (`wrangler.toml` `[vars]`)

- `RATE_WINDOW_SECONDS` - counter window (default `60`)
- `RATE_MAX_REQUESTS` - max allowed requests per IP per window (default `180`)
- `BURST_WINDOW_SECONDS` - short burst window (default `10`)
- `BURST_MAX_REQUESTS` - max requests allowed in burst window (default `30`)
- `BLOCK_TTL_SECONDS` - block duration after threshold hit (default `3600`)
- `PROTECTED_PATH_PREFIXES` - comma-separated list of path prefixes to inspect
  - Default: `*` (inspect all requests)
  - Use `*` to inspect all requests
- `ADMIN_PATH_PREFIX` - admin API prefix (default `/__botnet`)
- `ALLOWLIST_IPS` - comma-separated IPs that should never be blocked
- `SUSPICIOUS_PATH_PATTERNS` - comma-separated path fragments that increase bot score
- `BAD_USER_AGENT_PATTERNS` - comma-separated user-agent fragments that increase bot score
- `BOT_SCORE_TTL_SECONDS` - bot score decay window (default `900`)
- `BOT_SCORE_BLOCK_THRESHOLD` - score that triggers block (default `6`)
- `BOT_SCORE_PATH_WEIGHT` - score added for suspicious path hit (default `3`)
- `BOT_SCORE_USER_AGENT_WEIGHT` - score added for bad or missing user-agent (default `2`)

## Admin API

Auth header:

```text
Authorization: Bearer <BOTNET_ADMIN_TOKEN>
```

Block IP:

```bash
curl -X POST "https://your-domain.com/__botnet/block" \
  -H "Authorization: Bearer $BOTNET_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","reason":"manual","ttlSeconds":86400}'
```

Unblock IP:

```bash
curl -X POST "https://your-domain.com/__botnet/unblock" \
  -H "Authorization: Bearer $BOTNET_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'
```

Check IP status:

```bash
curl "https://your-domain.com/__botnet/status?ip=1.2.3.4" \
  -H "Authorization: Bearer $BOTNET_ADMIN_TOKEN"
```

## Local dev

```bash
npm run dev
```

## Notes

- KV counters are eventually consistent, so this is best-effort protection.
- Start with conservative thresholds and tighten after reviewing real traffic.
- Keep `ALLOWLIST_IPS` updated for monitors, office VPNs, and trusted integrations.
