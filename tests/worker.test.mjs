import test from 'node:test';
import assert from 'node:assert/strict';
import workerModule from '../src/worker.js';

const worker = workerModule;

class MockKV {
  constructor() {
    this.store = new Map();
  }

  async get(key) {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAtMs !== null && Date.now() >= entry.expiresAtMs) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(key, value, options = {}) {
    const ttl = Number.parseInt(options.expirationTtl, 10);
    const expiresAtMs = Number.isNaN(ttl) ? null : Date.now() + ttl * 1000;
    this.store.set(key, { value, expiresAtMs });
  }

  async delete(key) {
    this.store.delete(key);
  }
}

function createEnv(overrides = {}) {
  return {
    BOTNET_KV: new MockKV(),
    BOTNET_ADMIN_TOKEN: 'test-token',
    RATE_WINDOW_SECONDS: '60',
    RATE_MAX_REQUESTS: '2',
    BURST_WINDOW_SECONDS: '10',
    BURST_MAX_REQUESTS: '100',
    BLOCK_TTL_SECONDS: '120',
    PROTECTED_PATH_PREFIXES: '/api',
    SUSPICIOUS_PATH_PATTERNS: '/wp-login.php,/xmlrpc.php',
    BAD_USER_AGENT_PATTERNS: 'curl/,python-requests',
    BOT_SCORE_TTL_SECONDS: '900',
    BOT_SCORE_BLOCK_THRESHOLD: '6',
    BOT_SCORE_PATH_WEIGHT: '3',
    BOT_SCORE_USER_AGENT_WEIGHT: '2',
    ADMIN_PATH_PREFIX: '/__botnet',
    ALLOWLIST_IPS: '',
    ...overrides
  };
}

function createRequest(url, { method = 'GET', ip = '1.2.3.4', token, body, userAgent = 'Mozilla/5.0 test' } = {}) {
  const headers = new Headers();
  headers.set('CF-Connecting-IP', ip);
  if (userAgent) {
    headers.set('User-Agent', userAgent);
  }
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  let payload;
  if (body !== undefined) {
    headers.set('Content-Type', 'application/json');
    payload = JSON.stringify(body);
  }
  return new Request(url, { method, headers, body: payload });
}

async function readJson(response) {
  return JSON.parse(await response.text());
}

test('rate limit auto-blocks after threshold is exceeded', async () => {
  const env = createEnv();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('origin-ok', { status: 200 });

  try {
    const first = await worker.fetch(createRequest('https://example.com/api/login'), env);
    assert.equal(first.status, 200);

    const second = await worker.fetch(createRequest('https://example.com/api/login'), env);
    assert.equal(second.status, 200);

    const third = await worker.fetch(createRequest('https://example.com/api/login'), env);
    assert.equal(third.status, 403);
    const body = await readJson(third);
    assert.equal(body.blocked, true);
    assert.equal(body.details.reason, 'rate_limit_window');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('bot signature scoring blocks suspicious scanner traffic', async () => {
  const env = createEnv({
    RATE_MAX_REQUESTS: '100',
    BURST_MAX_REQUESTS: '100',
    BOT_SCORE_BLOCK_THRESHOLD: '5',
    PROTECTED_PATH_PREFIXES: '*'
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('origin-ok', { status: 200 });

  try {
    const response = await worker.fetch(
      createRequest('https://example.com/wp-login.php', {
        ip: '9.9.9.9',
        userAgent: 'curl/8.0.1'
      }),
      env
    );

    assert.equal(response.status, 403);
    const body = await readJson(response);
    assert.equal(body.details.reason, 'bot_signature');
    assert.equal(body.blocked, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('admin API can block and unblock an IP', async () => {
  const env = createEnv();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('origin-ok', { status: 200 });

  try {
    const blockResponse = await worker.fetch(
      createRequest('https://example.com/__botnet/block', {
        method: 'POST',
        token: 'test-token',
        body: { ip: '8.8.8.8', reason: 'manual-test', ttlSeconds: 300 }
      }),
      env
    );
    assert.equal(blockResponse.status, 200);

    const blockedRequest = await worker.fetch(createRequest('https://example.com/any', { ip: '8.8.8.8' }), env);
    assert.equal(blockedRequest.status, 403);

    const statusResponse = await worker.fetch(
      createRequest('https://example.com/__botnet/status?ip=8.8.8.8', {
        method: 'GET',
        token: 'test-token'
      }),
      env
    );
    assert.equal(statusResponse.status, 200);
    const statusBody = await readJson(statusResponse);
    assert.equal(statusBody.blocked, true);

    const unblockResponse = await worker.fetch(
      createRequest('https://example.com/__botnet/unblock', {
        method: 'POST',
        token: 'test-token',
        body: { ip: '8.8.8.8' }
      }),
      env
    );
    assert.equal(unblockResponse.status, 200);

    const afterUnblock = await worker.fetch(createRequest('https://example.com/any', { ip: '8.8.8.8' }), env);
    assert.equal(afterUnblock.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('admin endpoints reject unauthorized requests', async () => {
  const env = createEnv();
  const unauthorized = await worker.fetch(
    createRequest('https://example.com/__botnet/status?ip=1.2.3.4', {
      method: 'GET',
      token: 'wrong-token'
    }),
    env
  );

  assert.equal(unauthorized.status, 401);
  const body = await readJson(unauthorized);
  assert.equal(body.error, 'unauthorized');
});
