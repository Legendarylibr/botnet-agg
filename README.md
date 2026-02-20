# Cloudflare IP Uploader (Script-Only)

This repo contains a single script for:

1. Collecting IPs from public blocklist APIs (or local input)
2. Writing a merged blocklist text file
3. Writing per-IP CSV results
4. Optionally uploading those IPs to Cloudflare firewall access rules

Script path:

- `scripts/upload-cloudflare-ips.js`

## Requirements

- Node.js 18+ (for built-in `fetch`)

## Quick Start

Run with public sources and generate outputs:

```bash
node scripts/upload-cloudflare-ips.js --public
```

This writes:

- `output/blocklist.txt`
- `output/upload-results.csv`

## Optional Cloudflare Upload

If these env vars are set, the script will upload IPs to Cloudflare:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`

Example:

```bash
CLOUDFLARE_API_TOKEN=... \
CLOUDFLARE_ZONE_ID=... \
node scripts/upload-cloudflare-ips.js --public
```

## Use Local Input Instead Of Public Sources

```bash
node scripts/upload-cloudflare-ips.js ./ips.txt
```

or

```bash
cat ./ips.txt | node scripts/upload-cloudflare-ips.js
```

## CSV Output

Set output CSV path:

```bash
node scripts/upload-cloudflare-ips.js --public --csv ./output/upload-results.csv
```

CSV columns:

- `ip`
- `status`
- `http_status`
- `sources`
- `detail`

## Useful Flags

- `--public` fetch from public sources
- `--source <url>` add/override a source URL (repeatable)
- `--out <path>` set blocklist output path
- `--csv <path>` set CSV output path
- `--no-upload` skip Cloudflare upload even if creds are set
- `--help` show usage
