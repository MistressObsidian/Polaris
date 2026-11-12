import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { bech32, bech32m } from '@scure/base';
import { normalizeWalletAddress, readWalletBalance, registerExternalWalletRoutes } from '../src/external-wallets.js';

const btc = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
const eth = '0x52908400098527886E0F7030069857D2E4169EE7';
const mixedEth = '0x5AEDA56215b167893e80B4fE645BA6d5Bab767DE';
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test('mainnet addresses require valid Bitcoin encoding and Ethereum mixed-case checksums', () => {
  assert.equal(normalizeWalletAddress('bitcoin', btc), btc);
  assert.equal(normalizeWalletAddress('ethereum', eth), eth.toLowerCase());
  assert.equal(normalizeWalletAddress('ethereum', mixedEth), mixedEth.toLowerCase());
  const segwit = bech32.encode('bc', [0, ...bech32.toWords(new Uint8Array(20).fill(1))]);
  const taproot = bech32m.encode('bc', [1, ...bech32m.toWords(new Uint8Array(32).fill(2))]);
  assert.equal(normalizeWalletAddress('bitcoin', segwit.toUpperCase()), segwit);
  assert.equal(normalizeWalletAddress('bitcoin', taproot), taproot);
  for (const [network, address] of [
    ['bitcoin', btc.slice(0, -1) + 'b'], ['ethereum', mixedEth.replace('5A', '5a')],
    ['bitcoin', bech32.encode('tb', [0, ...bech32.toWords(new Uint8Array(20))])],
    ['bitcoin', bech32.encode('bc', [1, ...bech32.toWords(new Uint8Array(32))])],
    ['bitcoin', bech32m.encode('bc', [0, ...bech32m.toWords(new Uint8Array(20))])],
    ['bitcoin', bech32.encode('bc', [0, ...bech32.toWords(new Uint8Array(10))])],
    ['ethereum', btc], ['bitcoin', eth], ['solana', btc], ['__proto__', btc],
    ['bitcoin', 'abandon '.repeat(11) + 'about'], ['ethereum', '0x' + 'a'.repeat(64)],
    ['bitcoin', 'https://example.com'], ['ethereum', { address: eth }],
  ]) assert.throws(() => normalizeWalletAddress(network, address), /public address/);
});

test('balances use confirmed Bitcoin outputs and preserve exact Ethereum wei precision', async () => {
  assert.equal(await readWalletBalance('bitcoin', btc, async (url, options) => {
    assert.equal(url, `https://blockstream.info/api/address/${btc}`);
    assert.equal(options.redirect, 'error'); assert.ok(options.signal);
    return json({ address: btc, chain_stats: { funded_txo_sum: 150000001, spent_txo_sum: 50000000 }, mempool_stats: { funded_txo_sum: 900000000 } });
  }), '1.00000001');
  assert.equal(await readWalletBalance('ethereum', eth, async (url, options) => {
    assert.equal(url, 'https://ethereum-rpc.publicnode.com');
    assert.deepEqual(JSON.parse(options.body), { jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [eth.toLowerCase(), 'latest'] });
    return json({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640001' });
  }), '1.000000000000000001');
});

test('malformed, oversized or failed provider replies never become zero balances', async () => {
  for (const result of [{}, { error: 'rate limited' }, { jsonrpc: '2.0', id: 1, result: null }, { jsonrpc: '2.0', id: 2, result: '0x0' }]) {
    await assert.rejects(readWalletBalance('ethereum', eth, async () => json(result)));
  }
  await assert.rejects(readWalletBalance('bitcoin', btc, async () => json({ address: btc, chain_stats: { funded_txo_sum: 1, spent_txo_sum: 2 } })));
  await assert.rejects(readWalletBalance('bitcoin', btc, async () => json({}, 429)));
  await assert.rejects(readWalletBalance('bitcoin', btc, async () => new Response('x'.repeat(131073))), /too large/);
  let calls = 0;
  await assert.rejects(readWalletBalance('bitcoin', 'not an address', async () => { calls++; }));
  assert.equal(calls, 0);
});

function database() {
  const wallets = [], queries = [];
  const pool = {
    async query(sql, values = []) {
      queries.push({ sql, values });
      if (sql.includes('FROM users')) return { rows: [{ user_email: values[0] }] };
      if (sql.startsWith('SELECT') && sql.includes('external_wallets')) return { rows: wallets.filter(w => w.user_email === values[0]).map(({ user_email, ...row }) => row) };
      if (sql.startsWith('INSERT INTO external_wallets')) {
        const [id, user_email, network, address] = values;
        const row = { id, user_email, network, address, created_at: '2026-11-06T12:00:00Z' }; wallets.push(row);
        const { user_email: ignored, ...result } = row; return { rows: [result] };
      }
      if (sql.startsWith('DELETE FROM external_wallets')) {
        const index = wallets.findIndex(w => w.id === values[0] && w.user_email === values[1]);
        return { rows: index === -1 ? [] : wallets.splice(index, 1).map(w => ({ id: w.id })) };
      }
      return { rows: [] };
    },
    async connect() { return { query: pool.query, release() {} }; },
  };
  return { wallets, queries, pool };
}
async function server(t, options = {}) {
  const db = options.db || database(); let enabled = true;
  const app = express(); app.use(express.json());
  registerExternalWalletRoutes(app, { getPool: () => db.pool, auth: (req, res, next) => {
    const owner = req.headers.authorization;
    if (!['one@example.com', 'two@example.com'].includes(owner)) return res.sendStatus(401);
    req.userId = owner; next();
  }, isEnabled: async () => enabled, fetcher: options.fetcher || (async url => {
    if (url.includes('exchange-rates')) return json({ data: { currency: 'USD', rates: { BTC: '0.00001', ETH: '0.0005' } } });
    if (url.includes('blockstream')) return json({ address: btc, chain_stats: { funded_txo_sum: 10000000, spent_txo_sum: 0 } });
    return json({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' });
  }) });
  const listener = app.listen(0, '127.0.0.1'); await new Promise(resolve => listener.once('listening', resolve));
  t.after(() => new Promise(resolve => { listener.closeAllConnections(); listener.close(resolve); }));
  return { db, pause: () => { enabled = false; }, request: (method = 'GET', body, suffix = '', owner = 'one@example.com') => fetch(`http://127.0.0.1:${listener.address().port}/api/investments/wallets${suffix}`, { method, headers: { Authorization: owner, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }) };
}

test('saving, retrieving and removing wallets is authenticated and strictly owner scoped', async t => {
  const app = await server(t);
  assert.equal((await app.request('GET', null, '', '')).status, 401);
  const saved = await app.request('POST', { network: 'bitcoin', address: btc });
  assert.equal(saved.status, 201); const { wallet } = await saved.json();
  assert.equal(wallet.user_email, undefined);
  assert.ok(app.db.queries.some(q => q.sql.includes('FROM users') && q.sql.includes('FOR UPDATE')));
  const response = await app.request(); assert.equal(response.headers.get('cache-control'), 'private, no-store');
  const result = await response.json(); assert.equal(result.wallets[0].quantity, '0.1'); assert.equal(result.wallets[0].value, 10000);
  assert.deepEqual((await (await app.request('GET', null, '', 'two@example.com')).json()).wallets, []);
  assert.equal((await app.request('DELETE', null, `/${wallet.id}`, 'two@example.com')).status, 404);
  assert.equal(app.db.wallets.length, 1);
  assert.equal((await app.request('DELETE', null, `/${wallet.id}`)).status, 200);
  assert.equal(app.db.wallets.length, 0);
});

test('duplicates, secret inputs and unknown fields are rejected without persistence', async t => {
  const app = await server(t);
  assert.equal((await app.request('POST', { network: 'ethereum', address: eth })).status, 201);
  assert.equal((await app.request('POST', { network: 'ethereum', address: eth.toLowerCase() })).status, 409);
  for (const body of [
    { network: 'bitcoin', address: 'abandon '.repeat(11) + 'about' },
    { network: 'ethereum', address: '0x' + 'a'.repeat(64) },
    { network: 'bitcoin', address: btc, user_email: 'two@example.com' },
    { network: 'bitcoin', address: btc, phrase: 'private words' },
  ]) assert.equal((await app.request('POST', body)).status, 400);
  assert.equal(app.db.wallets.length, 1);
  assert.ok(app.db.queries.every(q => !JSON.stringify(q.values).includes('abandon')));
  assert.equal((await app.request('DELETE', null, '/invalid')).status, 400);
});

test('a customer may save at most five addresses', async t => {
  const app = await server(t);
  for (let i = 1; i <= 5; i++) assert.equal((await app.request('POST', { network: 'ethereum', address: `0x${i.toString().padStart(40, '0')}` })).status, 201);
  assert.equal((await app.request('POST', { network: 'ethereum', address: eth })).status, 409);
  assert.equal(app.db.wallets.length, 5);
});

test('admin pause stops additions and provider reads but allows address removal', async t => {
  let calls = 0; const app = await server(t, { fetcher: async () => { calls++; throw new Error('Should not run'); } });
  const { wallet } = await (await app.request('POST', { network: 'bitcoin', address: btc })).json();
  app.pause();
  assert.equal((await app.request('POST', { network: 'ethereum', address: eth })).status, 503);
  const result = await (await app.request()).json();
  assert.equal(result.status, 'paused'); assert.equal(result.wallets[0].quantity, null); assert.equal(calls, 0);
  assert.equal((await app.request('DELETE', null, `/${wallet.id}`)).status, 200);
});

test('provider failure preserves saved addresses and unknown financial values', async t => {
  const app = await server(t, { fetcher: async () => { throw new Error('Offline'); } });
  await app.request('POST', { network: 'bitcoin', address: btc });
  const { wallets } = await (await app.request()).json();
  assert.equal(wallets[0].address, btc); assert.equal(wallets[0].status, 'unavailable');
  assert.equal(wallets[0].quantity, null); assert.equal(wallets[0].value, null);
});

test('balances remain visible when only the USD price provider fails', async t => {
  const app = await server(t, { fetcher: async url => url.includes('exchange-rates') ? json({}, 503) : json({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' }) });
  await app.request('POST', { network: 'ethereum', address: eth });
  const { wallets } = await (await app.request()).json();
  assert.equal(wallets[0].status, 'available'); assert.equal(wallets[0].quantity, '1'); assert.equal(wallets[0].value, null);
});

test('fresh public price fallback values wallets without sharing their addresses', async t => {
  const app = await server(t, { fetcher: async url => {
    if (url.includes('coinbase')) throw new Error('Price service offline');
    if (url.includes('coingecko')) {
      assert.ok(!url.includes(eth.toLowerCase()));
      return json({ bitcoin: { usd: 100000, last_updated_at: Date.now() / 1000 }, ethereum: { usd: 2000, last_updated_at: Date.now() / 1000 } });
    }
    return json({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' });
  } });
  await app.request('POST', { network: 'ethereum', address: eth });
  const { wallets } = await (await app.request()).json();
  assert.equal(wallets[0].value, 2000); assert.equal(wallets[0].priceSource, 'CoinGecko');
});

test('stale fallback prices are not presented as current USD values', async t => {
  const app = await server(t, { fetcher: async url => {
    if (url.includes('coinbase')) throw new Error('Offline');
    if (url.includes('coingecko')) return json({ ethereum: { usd: 2000, last_updated_at: 1 } });
    return json({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' });
  } });
  await app.request('POST', { network: 'ethereum', address: eth });
  const { wallets } = await (await app.request()).json();
  assert.equal(wallets[0].quantity, '1'); assert.equal(wallets[0].value, null);
});
