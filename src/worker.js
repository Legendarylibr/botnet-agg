const DEFAULTS = Object.freeze({
  rateWindowSeconds: 60,
  rateMaxRequests: 180,
  burstWindowSeconds: 10,
  burstMaxRequests: 30,
  blockTtlSeconds: 3600,
  protectedPathPrefixes: ['*'],
  adminPathPrefix: '/__botnet',
  suspiciousPathPatterns: ['/wp-login.php', '/xmlrpc.php', '/wp-admin', '/.env', '/cgi-bin', '/boaform'],
  badUserAgentPatterns: ['python-requests', 'curl/', 'wget/', 'sqlmap', 'masscan', 'nmap', 'zgrab', 'go-http-client'],
  botScoreTtlSeconds: 900,
  botScoreBlockThreshold: 6,
  botScorePathWeight: 3,
  botScoreUserAgentWeight: 2
});

const BLOCK_KEY_PREFIX = 'blocked:';
const COUNTER_KEY_PREFIX = 'count:';
const BOT_SCORE_KEY_PREFIX = 'score:';

export default {
  async fetch(request, env) {
    const config = readConfig(env);
    const url = new URL(request.url);

    if (url.pathname.startsWith(config.adminPathPrefix)) {
      return handleAdminRequest(request, env, config, url);
    }

    if (!env.BOTNET_KV) {
      return fetch(request);
    }

    const ip = getClientIp(request);
    if (!ip || !isValidIp(ip) || config.allowlistIps.has(ip)) {
      return fetch(request);
    }

    try {
      const blocked = await getBlockedIpRecord(env.BOTNET_KV, ip);
      if (blocked) {
        return blockedResponse(ip, blocked);
      }

      if (shouldInspectPath(url.pathname, config.protectedPathPrefixes)) {
        const windowCount = await incrementCounter(env.BOTNET_KV, ip, 'window', config.rateWindowSeconds);
        if (windowCount > config.rateMaxRequests) {
          const blockRecord = {
            reason: 'rate_limit_window',
            blockedAt: new Date().toISOString(),
            windowSeconds: config.rateWindowSeconds,
            maxRequests: config.rateMaxRequests,
            observedCount: windowCount,
            path: url.pathname
          };
          await blockIp(env.BOTNET_KV, ip, blockRecord, config.blockTtlSeconds);
          return blockedResponse(ip, blockRecord);
        }

        const burstCount = await incrementCounter(env.BOTNET_KV, ip, 'burst', config.burstWindowSeconds);
        if (burstCount > config.burstMaxRequests) {
          const blockRecord = {
            reason: 'rate_limit_burst',
            blockedAt: new Date().toISOString(),
            windowSeconds: config.burstWindowSeconds,
            maxRequests: config.burstMaxRequests,
            observedCount: burstCount,
            path: url.pathname
          };
          await blockIp(env.BOTNET_KV, ip, blockRecord, config.blockTtlSeconds);
          return blockedResponse(ip, blockRecord);
        }

        const scoreOutcome = await maybeScoreBotSignals(request, url, env.BOTNET_KV, ip, config);
        if (scoreOutcome.shouldBlock) {
          await blockIp(env.BOTNET_KV, ip, scoreOutcome.record, config.blockTtlSeconds);
          return blockedResponse(ip, scoreOutcome.record);
        }
      }
    } catch (error) {
      // Fail open to avoid taking down healthy traffic when KV has issues.
      console.error('Botnet guard error', error);
    }

    return fetch(request);
  }
};

function readConfig(env) {
  return {
    rateWindowSeconds: parsePositiveInteger(env.RATE_WINDOW_SECONDS, DEFAULTS.rateWindowSeconds),
    rateMaxRequests: parsePositiveInteger(env.RATE_MAX_REQUESTS, DEFAULTS.rateMaxRequests),
    burstWindowSeconds: parsePositiveInteger(env.BURST_WINDOW_SECONDS, DEFAULTS.burstWindowSeconds),
    burstMaxRequests: parsePositiveInteger(env.BURST_MAX_REQUESTS, DEFAULTS.burstMaxRequests),
    blockTtlSeconds: parsePositiveInteger(env.BLOCK_TTL_SECONDS, DEFAULTS.blockTtlSeconds),
    protectedPathPrefixes: parsePathPrefixes(env.PROTECTED_PATH_PREFIXES),
    adminPathPrefix: normalizePathPrefix(env.ADMIN_PATH_PREFIX || DEFAULTS.adminPathPrefix),
    allowlistIps: new Set(parseCsvList(env.ALLOWLIST_IPS)),
    suspiciousPathPatterns: parseStringPatterns(env.SUSPICIOUS_PATH_PATTERNS, DEFAULTS.suspiciousPathPatterns),
    badUserAgentPatterns: parseStringPatterns(env.BAD_USER_AGENT_PATTERNS, DEFAULTS.badUserAgentPatterns),
    botScoreTtlSeconds: parsePositiveInteger(env.BOT_SCORE_TTL_SECONDS, DEFAULTS.botScoreTtlSeconds),
    botScoreBlockThreshold: parsePositiveInteger(env.BOT_SCORE_BLOCK_THRESHOLD, DEFAULTS.botScoreBlockThreshold),
    botScorePathWeight: parsePositiveInteger(env.BOT_SCORE_PATH_WEIGHT, DEFAULTS.botScorePathWeight),
    botScoreUserAgentWeight: parsePositiveInteger(env.BOT_SCORE_USER_AGENT_WEIGHT, DEFAULTS.botScoreUserAgentWeight)
  };
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseCsvList(value) {
  if (!value) {
    return [];
  }
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parsePathPrefixes(value) {
  if (!value) {
    return DEFAULTS.protectedPathPrefixes;
  }
  const parsed = parseCsvList(value).map(normalizePathPrefix);
  if (!parsed.length) {
    return DEFAULTS.protectedPathPrefixes;
  }
  return parsed;
}

function parseStringPatterns(value, fallback) {
  if (!value) {
    return fallback;
  }
  const parsed = parseCsvList(value).map((item) => item.toLowerCase());
  return parsed.length ? parsed : fallback;
}

function normalizePathPrefix(prefix) {
  if (!prefix) {
    return '/';
  }
  if (prefix === '*') {
    return '*';
  }
  return prefix.startsWith('/') ? prefix : `/${prefix}`;
}

function shouldInspectPath(pathname, prefixes) {
  if (prefixes.includes('*')) {
    return true;
  }
  return prefixes.some((prefix) => pathname.startsWith(prefix));
}

function getClientIp(request) {
  const cfIp = request.headers.get('CF-Connecting-IP');
  if (cfIp) {
    return cfIp.trim();
  }
  return '';
}

function isValidIp(ip) {
  return isValidIpv4(ip) || isValidIpv6(ip);
}

function isValidIpv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const value = Number.parseInt(part, 10);
    return value >= 0 && value <= 255;
  });
}

function isValidIpv6(ip) {
  if (!ip.includes(':')) {
    return false;
  }
  return /^[0-9a-fA-F:]+$/.test(ip);
}

function blockedKey(ip) {
  return `${BLOCK_KEY_PREFIX}${ip}`;
}

function counterKey(ip, scope, windowId) {
  return `${COUNTER_KEY_PREFIX}${scope}:${ip}:${windowId}`;
}

function botScoreKey(ip) {
  return `${BOT_SCORE_KEY_PREFIX}${ip}`;
}

async function getBlockedIpRecord(kv, ip) {
  const raw = await kv.get(blockedKey(ip));
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return { reason: 'manual', detail: raw };
  }
}

async function blockIp(kv, ip, record, ttlSeconds) {
  const body = JSON.stringify(record);
  await kv.put(blockedKey(ip), body, { expirationTtl: ttlSeconds });
}

async function incrementCounter(kv, ip, scope, windowSeconds) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowId = Math.floor(nowSeconds / windowSeconds);
  const key = counterKey(ip, scope, windowId);

  const currentRaw = await kv.get(key);
  const current = currentRaw ? Number.parseInt(currentRaw, 10) : 0;
  const next = Number.isNaN(current) ? 1 : current + 1;

  await kv.put(key, String(next), { expirationTtl: windowSeconds + 5 });
  return next;
}

async function maybeScoreBotSignals(request, url, kv, ip, config) {
  let scoreDelta = 0;
  const signals = [];

  const lowerPath = url.pathname.toLowerCase();
  if (matchesAnyPattern(lowerPath, config.suspiciousPathPatterns)) {
    scoreDelta += config.botScorePathWeight;
    signals.push('suspicious_path');
  }

  const userAgent = (request.headers.get('user-agent') || '').toLowerCase();
  if (!userAgent || matchesAnyPattern(userAgent, config.badUserAgentPatterns)) {
    scoreDelta += config.botScoreUserAgentWeight;
    signals.push(!userAgent ? 'missing_user_agent' : 'bad_user_agent');
  }

  if (scoreDelta <= 0) {
    return { shouldBlock: false };
  }

  const score = await incrementBotScore(kv, ip, scoreDelta, config.botScoreTtlSeconds);
  if (score < config.botScoreBlockThreshold) {
    return { shouldBlock: false };
  }

  return {
    shouldBlock: true,
    record: {
      reason: 'bot_signature',
      blockedAt: new Date().toISOString(),
      score,
      blockThreshold: config.botScoreBlockThreshold,
      scoreDelta,
      signals,
      path: url.pathname
    }
  };
}

function matchesAnyPattern(target, patterns) {
  return patterns.some((pattern) => target.includes(pattern));
}

async function incrementBotScore(kv, ip, delta, ttlSeconds) {
  const key = botScoreKey(ip);
  const currentRaw = await kv.get(key);
  const current = currentRaw ? Number.parseInt(currentRaw, 10) : 0;
  const next = (Number.isNaN(current) ? 0 : current) + delta;
  await kv.put(key, String(next), { expirationTtl: ttlSeconds });
  return next;
}

async function getBotScore(kv, ip) {
  const raw = await kv.get(botScoreKey(ip));
  if (!raw) {
    return 0;
  }
  const value = Number.parseInt(raw, 10);
  return Number.isNaN(value) ? 0 : value;
}

function blockedResponse(ip, details) {
  return jsonResponse(
    {
      ok: false,
      blocked: true,
      ip,
      details
    },
    403
  );
}

async function handleAdminRequest(request, env, config, url) {
  if (!env.BOTNET_KV) {
    return jsonResponse({ ok: false, error: 'BOTNET_KV binding is missing' }, 500);
  }

  if (request.method === 'GET' && url.pathname === `${config.adminPathPrefix}/health`) {
    return jsonResponse({ ok: true, service: 'botnet-guard' }, 200);
  }

  if (!isAuthorized(request, env.BOTNET_ADMIN_TOKEN)) {
    return jsonResponse({ ok: false, error: 'unauthorized' }, 401);
  }

  if (request.method === 'GET' && url.pathname === `${config.adminPathPrefix}/status`) {
    const ip = url.searchParams.get('ip') || '';
    if (!isValidIp(ip)) {
      return jsonResponse({ ok: false, error: 'valid ip is required' }, 400);
    }
    const details = await getBlockedIpRecord(env.BOTNET_KV, ip);
    const score = await getBotScore(env.BOTNET_KV, ip);
    return jsonResponse(
      {
        ok: true,
        ip,
        blocked: Boolean(details),
        details,
        botScore: score
      },
      200
    );
  }

  if (request.method === 'POST' && url.pathname === `${config.adminPathPrefix}/block`) {
    const body = await readJsonBody(request);
    if (!body || typeof body !== 'object') {
      return jsonResponse({ ok: false, error: 'invalid json body' }, 400);
    }

    const ip = typeof body.ip === 'string' ? body.ip.trim() : '';
    if (!isValidIp(ip)) {
      return jsonResponse({ ok: false, error: 'valid ip is required' }, 400);
    }

    const ttlSeconds = parsePositiveInteger(body.ttlSeconds, config.blockTtlSeconds);
    const record = {
      reason: typeof body.reason === 'string' && body.reason.trim() ? body.reason.trim() : 'manual',
      blockedAt: new Date().toISOString(),
      actor: 'admin_api'
    };

    await blockIp(env.BOTNET_KV, ip, record, ttlSeconds);
    return jsonResponse({ ok: true, blocked: true, ip, ttlSeconds, details: record }, 200);
  }

  if (
    (request.method === 'POST' || request.method === 'DELETE') &&
    url.pathname === `${config.adminPathPrefix}/unblock`
  ) {
    const body = await readJsonBody(request);
    const ip = body && typeof body.ip === 'string' ? body.ip.trim() : '';
    if (!isValidIp(ip)) {
      return jsonResponse({ ok: false, error: 'valid ip is required' }, 400);
    }

    await env.BOTNET_KV.delete(blockedKey(ip));
    await env.BOTNET_KV.delete(botScoreKey(ip));
    return jsonResponse({ ok: true, blocked: false, ip }, 200);
  }

  return jsonResponse({ ok: false, error: 'not_found' }, 404);
}

function isAuthorized(request, expectedToken) {
  if (!expectedToken) {
    return false;
  }
  const authHeader = request.headers.get('Authorization') || '';
  const prefix = 'Bearer ';
  if (!authHeader.startsWith(prefix)) {
    return false;
  }
  const providedToken = authHeader.slice(prefix.length).trim();
  return providedToken.length > 0 && providedToken === expectedToken;
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
}
