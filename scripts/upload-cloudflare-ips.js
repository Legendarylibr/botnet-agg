#!/usr/bin/env node
const { readFile, writeFile, mkdir } = require('node:fs/promises');
const { isIP } = require('node:net');
const path = require('node:path');

const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? '';
const zoneId = process.env.CLOUDFLARE_ZONE_ID ?? '';
const blockMode = process.env.CLOUDFLARE_BLOCK_MODE ?? 'block';
const notesPrefix = process.env.CLOUDFLARE_BLOCK_NOTES_PREFIX ?? 'botnet-tracker:script';

const DEFAULT_PUBLIC_SOURCES = [
  { name: 'abusech_feodo', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt' },
  { name: 'emergingthreats_compromised', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' }
];

const usage = `
Usage:
  node scripts/upload-cloudflare-ips.js <path-to-ips.txt>
  cat ips.txt | node scripts/upload-cloudflare-ips.js
  node scripts/upload-cloudflare-ips.js --public

Options:
  --csv <path>      Write per-IP results CSV (default: ./output/upload-results.csv)
  --out <path>      Write merged IP blocklist text (default: ./output/blocklist.txt)
  --public          Fetch IPs from public sources (default when no file/stdin input)
  --source <url>    Add/override a public source URL (can repeat)
  --no-upload       Skip Cloudflare upload even if credentials exist

Env (optional for upload):
  CLOUDFLARE_API_TOKEN
  CLOUDFLARE_ZONE_ID
  CLOUDFLARE_BLOCK_MODE=block
  CLOUDFLARE_BLOCK_NOTES_PREFIX=botnet-tracker:script
`;

const readStdin = async () => {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
};

const extractIps = (raw) => {
  const tokens = raw
    .split(/[^0-9a-fA-F:.]+/g)
    .map((value) => value.trim())
    .filter(Boolean);

  const ips = [];
  for (const token of tokens) {
    if (isIP(token) !== 0) {
      ips.push(token);
    }
  }
  return ips;
};

const toCsvCell = (value) => {
  const text = value == null ? '' : String(value);
  if (!/[",\n]/.test(text)) {
    return text;
  }
  return `"${text.replace(/"/g, '""')}"`;
};

const args = process.argv.slice(2);
let sourcePath;
let csvPath = 'output/upload-results.csv';
let outPath = 'output/blocklist.txt';
let publicMode = false;
let noUpload = false;
const sourceUrls = [];

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];

  if (arg === '--help' || arg === '-h') {
    console.log(usage.trim());
    process.exit(0);
  }

  if (arg === '--csv') {
    const value = args[index + 1];
    if (!value) {
      console.error('Missing value for --csv');
      process.exit(1);
    }
    csvPath = value;
    index += 1;
    continue;
  }

  if (arg.startsWith('--csv=')) {
    csvPath = arg.slice('--csv='.length);
    continue;
  }

  if (arg === '--out') {
    const value = args[index + 1];
    if (!value) {
      console.error('Missing value for --out');
      process.exit(1);
    }
    outPath = value;
    index += 1;
    continue;
  }

  if (arg.startsWith('--out=')) {
    outPath = arg.slice('--out='.length);
    continue;
  }

  if (arg === '--public') {
    publicMode = true;
    continue;
  }

  if (arg === '--no-upload') {
    noUpload = true;
    continue;
  }

  if (arg === '--source') {
    const value = args[index + 1];
    if (!value) {
      console.error('Missing value for --source');
      process.exit(1);
    }
    sourceUrls.push(value);
    index += 1;
    continue;
  }

  if (arg.startsWith('--source=')) {
    sourceUrls.push(arg.slice('--source='.length));
    continue;
  }

  if (arg.startsWith('--')) {
    console.error(`Unknown option: ${arg}`);
    process.exit(1);
  }

  if (!sourcePath) {
    sourcePath = arg;
    continue;
  }

  console.error(`Unexpected argument: ${arg}`);
  process.exit(1);
}

const fetchPublicIps = async () => {
  const sources = sourceUrls.length
    ? sourceUrls.map((url, idx) => ({ name: `custom_${idx + 1}`, url }))
    : DEFAULT_PUBLIC_SOURCES;

  const sourceMap = new Map();
  const sourceErrors = [];
  const allIps = [];

  for (const source of sources) {
    try {
      const response = await fetch(source.url);
      if (!response.ok) {
        sourceErrors.push(`${source.name}:${response.status}`);
        continue;
      }
      const text = await response.text();
      const ips = extractIps(text);
      for (const ip of ips) {
        allIps.push(ip);
        if (!sourceMap.has(ip)) {
          sourceMap.set(ip, new Set());
        }
        sourceMap.get(ip).add(source.name);
      }
    } catch (error) {
      sourceErrors.push(`${source.name}:fetch-error`);
    }
  }

  return { ips: allIps, sourceMap, sourceErrors };
};

const readInputIps = async () => {
  if (sourcePath) {
    const raw = await readFile(sourcePath, 'utf8');
    return { ips: extractIps(raw), sourceMap: new Map(), sourceErrors: [] };
  }

  if (publicMode) {
    return fetchPublicIps();
  }

  if (!process.stdin.isTTY) {
    const raw = await readStdin();
    if (raw.trim().length > 0) {
      return { ips: extractIps(raw), sourceMap: new Map(), sourceErrors: [] };
    }
  }

  return fetchPublicIps();
};

const uploadToCloudflare = async (ips, sourceMap) => {
  const csvRows = [];
  const endpoint = `https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/access_rules/rules`;

  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const ip of ips) {
    const sources = sourceMap.has(ip) ? [...sourceMap.get(ip)].join('|') : 'input';
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        mode: blockMode,
        configuration: { target: 'ip', value: ip },
        notes: `${notesPrefix}:${new Date().toISOString()}`
      })
    });

    if (response.ok) {
      created += 1;
      csvRows.push({ ip, status: 'created', httpStatus: response.status, sources, detail: '' });
      continue;
    }

    const body = await response.text();
    const duplicate = response.status === 409 || body.toLowerCase().includes('already exists');
    if (duplicate) {
      skipped += 1;
      csvRows.push({ ip, status: 'skipped', httpStatus: response.status, sources, detail: 'already exists' });
      continue;
    }

    failed += 1;
    const detail = body.replace(/\s+/g, ' ').trim().slice(0, 800);
    csvRows.push({ ip, status: 'failed', httpStatus: response.status, sources, detail });
    console.error(`Failed ${ip} (${response.status}): ${detail}`);
  }

  return { csvRows, created, skipped, failed };
};

const main = async () => {
  const { ips, sourceMap, sourceErrors } = await readInputIps();
  const uniqueIps = [...new Set(ips)];

  if (!uniqueIps.length) {
    console.error('No valid IPs found from input/public sources');
    if (sourceErrors.length) {
      console.error(`Source errors: ${sourceErrors.join(', ')}`);
    }
    process.exit(1);
  }

  await mkdir(path.dirname(outPath), { recursive: true });
  await writeFile(outPath, `${uniqueIps.join('\n')}\n`, 'utf8');

  const canUpload = Boolean(apiToken && zoneId) && !noUpload;
  let created = 0;
  let skipped = 0;
  let failed = 0;
  let csvRows = [];

  if (canUpload) {
    const outcome = await uploadToCloudflare(uniqueIps, sourceMap);
    csvRows = outcome.csvRows;
    created = outcome.created;
    skipped = outcome.skipped;
    failed = outcome.failed;
  } else {
    csvRows = uniqueIps.map((ip) => ({
      ip,
      status: 'collected',
      httpStatus: '',
      sources: sourceMap.has(ip) ? [...sourceMap.get(ip)].join('|') : 'input',
      detail: apiToken || zoneId ? 'upload disabled (--no-upload)' : 'cloudflare credentials not set'
    }));
  }

  await mkdir(path.dirname(csvPath), { recursive: true });
  const header = 'ip,status,http_status,sources,detail';
  const lines = csvRows.map((row) =>
    [toCsvCell(row.ip), toCsvCell(row.status), toCsvCell(row.httpStatus), toCsvCell(row.sources), toCsvCell(row.detail)].join(',')
  );
  await writeFile(csvPath, `${header}\n${lines.join('\n')}\n`, 'utf8');

  const summary = {
    collected: uniqueIps.length,
    uploaded: canUpload,
    created,
    skipped,
    failed,
    blocklistPath: outPath,
    csvPath,
    sourceErrors
  };

  console.log(JSON.stringify(summary, null, 2));
  if (failed > 0) {
    process.exit(1);
  }
};

void main();
