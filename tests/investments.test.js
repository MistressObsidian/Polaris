import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import { coinbaseConfig, seal, unseal, createMarketFeed, readCoinbaseAccounts, normalizeHoldings, registerInvestmentRoutes } from '../src/investments.js';

const env = { COINBASE_CLIENT_ID: 'test-client', COINBASE_CLIENT_SECRET: 'test-secret', COINBASE_REDIRECT_URI: 'http://localhost:4000/api/investments/coinbase/callback', INVESTMENT_TOKEN_KEY: 'a'.repeat(64), NODE_ENV: 'development' };
const cfg = coinbaseConfig(env);
const response = data => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });

test('Coinbase requires complete server config and HTTPS outside local development', () => {
  assert.equal(coinbaseConfig({}), null);
  assert.ok(cfg);
  assert.equal(coinbaseConfig({ ...env, NODE_ENV: 'production' }), null);
  assert.equal(coinbaseConfig({ ...env, COINBASE_REDIRECT_URI: 'https://example.com/wrong' }), null);
  assert.ok(coinbaseConfig({ ...env, NODE_ENV: 'production', COINBASE_REDIRECT_URI: 'https://example.com/api/investments/coinbase/callback' }));
});

test('encrypted credentials cannot be read under a different customer, key, or modified ciphertext', () => {
  const token = { access: 'private-access', refresh: 'private-refresh' };
  const encrypted = seal(token, cfg.key, 'one@example.com');
  assert.deepEqual(unseal(encrypted, cfg.key, 'one@example.com'), token);
  assert.ok(!encrypted.includes(token.access));
  assert.throws(() => unseal(encrypted, cfg.key, 'two@example.com'));
  assert.throws(() => unseal(encrypted, Buffer.alloc(32), 'one@example.com'));
  const parts = encrypted.split('.'); const bytes = Buffer.from(parts[2], 'base64url'); bytes[0] ^= 1; parts[2] = bytes.toString('base64url');
  assert.throws(() => unseal(parts.join('.'), cfg.key, 'one@example.com'));
});

test('unknown USD valuation stays unavailable, zero positions and fiat are excluded, no invented P&L', () => {
  const account = (id, code, amount, type = 'wallet') => ({ id, type, currency: { code, name: code }, balance: { currency: code, amount } });
  const holdings = normalizeHoldings([account('1', 'BTC', '0.5'), account('2', 'NEW', '1'), account('3', 'USD', '30', 'fiat'), account('4', 'ETH', '0')], { BTC: 0.00001 });
  assert.equal(holdings.length, 2);
  assert.ok(Math.abs(holdings[0].value - 50000) < 0.01);
  assert.equal(holdings[1].value, null);
  assert.equal(holdings[0].pnl, null);
  assert.throws(() => normalizeHoldings([account('1', 'BTC', 'invalid')], {}));
});

test('market feeds fail independently and cache only completed public quotes', async () => {
  let calls = 0;
  const feed = createMarketFeed(async (url, opts) => {
    calls++; assert.equal(opts.headers?.Authorization, undefined);
    if (url.includes('coinbase')) return response({ last: '100', open: '80' });
    if (url.includes('frankfurter')) return response({ base: 'EUR', quote: 'USD', rate: 1.1, date: '2026-10-15' });
    throw new Error('Futures unavailable');
  });
  const data = await feed();
  assert.equal(data.quotes[0].change, 25);
  assert.equal(data.quotes[1].frequency, 'Daily reference');
  assert.equal(data.quotes[2].price, null);
  assert.equal(data.quotes[2].available, false);
  await feed(); assert.equal(calls, 3);
});

test('private account pagination never sends credentials to another host or follows a loop', async () => {
  let calls = 0;
  await assert.rejects(readCoinbaseAccounts('secret', async (url, opts) => {
    calls++; assert.ok(url.startsWith('https://api.coinbase.com/v2/accounts'));
    assert.equal(opts.redirect, 'error');
    return response({ data: [], pagination: { next_uri: 'https://example.com/collect' } });
  }), /pagination/);
  assert.equal(calls, 1);
  await assert.rejects(readCoinbaseAccounts('secret', async () => response({ data: [], pagination: { next_uri: '/v2/accounts?limit=100' } })), /pagination/);
});

function database() {
  const states = new Map(), connections = new Map();
  const pool = {
    async query(sql, params = []) {
      if (sql.startsWith('INSERT INTO coinbase_oauth_states')) states.set(params[0], { user_email: params[1], browser_hash: params[2], verifier_cipher: params[3] });
      if (sql.startsWith('DELETE FROM coinbase_oauth_states WHERE state_hash')) {
        const state = states.get(params[0]);
        if (!state || state.browser_hash !== params[1]) return { rows: [] };
        states.delete(params[0]); return { rows: [state] };
      }
      if (sql.startsWith('SELECT token_cipher')) return { rows: connections.has(params[0]) ? [{ token_cipher: connections.get(params[0]) }] : [] };
      if (sql.startsWith('INSERT INTO coinbase_connections') || sql.startsWith('UPDATE coinbase_connections')) connections.set(params[0], params[1]);
      if (sql.startsWith('DELETE FROM coinbase_connections')) connections.delete(params[0]);
      return { rows: [] };
    },
    async connect() { return { query: pool.query, release() {} }; },
  };
  return { pool, states, connections };
}
async function server(t, { configured = true, fetcher, db = database() } = {}) {
  const app = express();
  const auth = (req, res, next) => { const id = req.headers.authorization?.replace('Bearer ', ''); if (!['one@example.com', 'two@example.com'].includes(id)) return res.sendStatus(401); req.userId = id; next(); };
  registerInvestmentRoutes(app, { getPool: () => db.pool, auth, config: () => configured ? cfg : null, fetcher });
  const listener = app.listen(0, '127.0.0.1');
  await new Promise(resolve => listener.once('listening', resolve));
  t.after(() => new Promise(resolve => { listener.closeAllConnections(); listener.close(resolve); }));
  const origin = `http://127.0.0.1:${listener.address().port}`;
  return { db, request: (path, options = {}) => fetch(origin + path, { redirect: 'manual', ...options }) };
}
const auth = owner => ({ Authorization: `Bearer ${owner}` });

test('unconfigured Coinbase fails clearly without accessing the database; auth is mandatory', async t => {
  const app = await server(t, { configured: false, db: { pool: { query() { throw new Error('Must not query'); } } } });
  assert.equal((await app.request('/api/investments/portfolio')).status, 401);
  const portfolio = await app.request('/api/investments/portfolio', { headers: auth('one@example.com') });
  assert.equal((await portfolio.json()).status, 'configuration_required');
  assert.equal(portfolio.headers.get('cache-control'), 'private, no-store');
  assert.equal((await app.request('/api/investments/coinbase/connect', { method: 'POST', headers: auth('one@example.com') })).status, 503);
});

test('OAuth requires matching browser state, uses PKCE and read-only scopes, and consumes state once', async t => {
  let exchanges = 0, verifier;
  const app = await server(t, { fetcher: async (url, opts) => {
    assert.equal(url, 'https://login.coinbase.com/oauth2/token');
    exchanges++; verifier = new URLSearchParams(opts.body).get('code_verifier');
    return response({ access_token: 'private-access', refresh_token: 'private-refresh', expires_in: 3600, scope: 'wallet:accounts:read offline_access' });
  } });
  const start = await app.request('/api/investments/coinbase/connect', { method: 'POST', headers: auth('one@example.com') });
  const cookie = start.headers.get('set-cookie').split(';')[0];
  assert.match(start.headers.get('set-cookie'), /HttpOnly/);
  const url = new URL((await start.json()).url), state = url.searchParams.get('state');
  assert.equal(url.searchParams.get('scope'), 'wallet:accounts:read offline_access');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  const path = `/api/investments/coinbase/callback?state=${state}&code=authorization-code`;
  assert.match((await app.request(path)).headers.get('location'), /failed/); assert.equal(exchanges, 0);
  assert.match((await app.request(path, { headers: { Cookie: cookie } })).headers.get('location'), /connected/);
  assert.equal(crypto.createHash('sha256').update(verifier).digest('base64url'), url.searchParams.get('code_challenge'));
  const encrypted = app.db.connections.get('one@example.com');
  assert.ok(encrypted && !encrypted.includes('private-access'));
  assert.equal(app.db.connections.has('two@example.com'), false);
  assert.match((await app.request(path, { headers: { Cookie: cookie } })).headers.get('location'), /failed/);
  assert.equal(exchanges, 1);
});

test('portfolios use only the signed-in customer token and never expose credentials', async t => {
  const db = database();
  db.connections.set('one@example.com', seal({ access: 'one-access', refresh: 'one-refresh', expires: Date.now() + 3600000 }, cfg.key, 'one@example.com'));
  const app = await server(t, { db, fetcher: async (url, opts) => {
    if (url.includes('/accounts')) { assert.equal(opts.headers.Authorization, 'Bearer one-access'); return response({ data: [{ id: 'btc', type: 'wallet', currency: { code: 'BTC' }, balance: { amount: '0.1', currency: 'BTC' } }], pagination: { next_uri: null } }); }
    assert.equal(opts.headers?.Authorization, undefined);
    return response({ data: { currency: 'USD', rates: { BTC: '0.00001' } } });
  } });
  const result = await (await app.request('/api/investments/portfolio', { headers: auth('one@example.com') })).json();
  assert.equal(result.status, 'connected'); assert.ok(Math.abs(result.total - 10000) < 0.01);
  assert.ok(!JSON.stringify(result).includes('one-access'));
  const other = await (await app.request('/api/investments/portfolio', { headers: auth('two@example.com') })).json();
  assert.equal(other.status, 'disconnected'); assert.equal(other.total, null);
});

test('expired token rotates before fetching holdings and saves the replacement encrypted', async t => {
  const db = database();
  db.connections.set('one@example.com', seal({ access: 'expired', refresh: 'refresh-once', expires: 1 }, cfg.key, 'one@example.com'));
  const app = await server(t, { db, fetcher: async (url, opts) => {
    if (url.includes('/token')) { assert.equal(new URLSearchParams(opts.body).get('refresh_token'), 'refresh-once'); return response({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600, scope: 'wallet:accounts:read' }); }
    if (url.includes('/accounts')) { assert.equal(opts.headers.Authorization, 'Bearer new-access'); return response({ data: [], pagination: {} }); }
    return response({ data: { currency: 'USD', rates: {} } });
  } });
  const result = await (await app.request('/api/investments/portfolio', { headers: auth('one@example.com') })).json();
  assert.equal(result.total, 0);
  assert.equal(unseal(db.connections.get('one@example.com'), cfg.key, 'one@example.com').refresh, 'new-refresh');
});
