import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { checkCustomerSession, customerPreferences, recordQuery, requireFeature, auditMutation, registerOperationsRoutes, FEATURE_DEFAULTS } from '../src/admin-operations.js';

const customer = { user_email: 'customer@example.test', suspended: false, session_version: 3 };
const sessionPool = row => ({ query: async (_sql, values) => { assert.equal(values[0], customer.user_email); return { rows: row ? [row] : [] }; } });
test('suspension and revocation invalidate already-issued customer sessions', async () => {
  await checkCustomerSession(sessionPool(customer), customer.user_email, { sv: 3 });
  await assert.rejects(checkCustomerSession(sessionPool({ ...customer, suspended: true }), customer.user_email, { sv: 3 }), { status: 403 });
  await assert.rejects(checkCustomerSession(sessionPool(customer), customer.user_email, { sv: 2 }), { status: 401 });
  await assert.rejects(checkCustomerSession(sessionPool(null), customer.user_email, { sv: 3 }), { status: 401 });
});
test('legacy sessions work only until the first revocation and stream tokens cannot authorize mutations', async () => {
  await checkCustomerSession(sessionPool({ ...customer, session_version: 0 }), customer.user_email, {});
  await assert.rejects(checkCustomerSession(sessionPool(customer), customer.user_email, {}), { status: 401 });
  await assert.rejects(checkCustomerSession(sessionPool(customer), customer.user_email, { sv: 3, stream: true }), { status: 401 });
  await checkCustomerSession(sessionPool(customer), customer.user_email, { sv: 3, stream: true, allowStream: true });
});
test('customers cannot re-enable their own transfers through either preference spelling', () => {
  for (const key of ['transfers_enabled', 'transfersEnabled']) assert.throws(() => customerPreferences({ [key]: true, theme: 'light' }), { status: 403 });
  assert.deepEqual(customerPreferences({ theme: 'light', currency: 'EUR', role: 'admin', suspended: false }), { theme: 'light', currency: 'EUR' });
});
test('record search is parameterized, literal wildcard search is escaped, and pagination reaches every account', () => {
  const result = recordQuery('users', { q: "O'Neil_100%", status: 'suspended', page: '8', limit: '25' });
  assert.ok(!result.sql.includes("O'Neil"));
  assert.deepEqual(result.values, ["%O'Neil\\_100\\%%", 'suspended', 25, 175]);
  assert.match(result.sql, /ORDER BY u.created_at DESC,u.user_email LIMIT \$3 OFFSET \$4/);
  assert.match(result.count, /WHERE.*ILIKE \$1.*=\$2/);
  assert.ok(!result.sql.includes('password_hash'));
  assert.ok(!recordQuery('connections').sql.includes('token_cipher'));
});
test('record queries reject invalid identifiers, states, sizes, and excessively large searches', () => {
  for (const kind of ['__proto__', 'constructor', 'users; DROP TABLE users']) assert.throws(() => recordQuery(kind), { status: 404 });
  for (const query of [{ page: -1 }, { page: 1.5 }, { limit: 101 }, { limit: 'NaN' }, { status: 'not-real' }, { q: 'a'.repeat(121) }]) assert.throws(() => recordQuery('users', query), { status: 400 });
});
test('global feature controls fail closed when paused or missing', async () => {
  await requireFeature({ query: async () => ({ rows: [{ value: FEATURE_DEFAULTS }] }) }, 'transfers_enabled');
  await assert.rejects(requireFeature({ query: async () => ({ rows: [{ value: { transfers_enabled: false } }] }) }, 'transfers_enabled'), { status: 503 });
  await assert.rejects(requireFeature({ query: async () => ({ rows: [] }) }, 'registration_enabled'), { status: 503 });
});
test('audit records intent before an action and stores the actual outcome without credentials', async () => {
  const calls = [];
  const pool = { query: async (sql, values) => { calls.push({ sql, values }); return { rows: [{ id: 'event' }] }; } };
  const req = { method: 'POST', path: '/api/admin/users/customer@example.test/password', admin: { email: 'admin@example.test' }, params: { email: customer.user_email }, body: { password: 'never-log-this' } };
  const res = { statusCode: 400, json: body => body };
  await auditMutation(pool, req, res, async () => { assert.equal(calls.length, 1); await res.json({ error: 'Too short' }); });
  assert.deepEqual(calls[0].values, ['admin@example.test', 'admin', customer.user_email, 'Password changed']);
  assert.deepEqual(calls[1].values, ['event', 'failed', 400, null]);
  assert.ok(!JSON.stringify(calls).includes('never-log-this'));
});
test('an audit storage failure prevents the action from running; reads do not create audit noise', async () => {
  const pool = { query: async () => { throw new Error('Offline'); } };
  await assert.rejects(auditMutation(pool, { method: 'POST', path: '/api/admin/platform', admin: { email: 'admin' } }, {}, () => assert.fail('must not run')), /Offline/);
  let called = false;
  await auditMutation(pool, { method: 'GET' }, {}, () => { called = true; });
  assert.equal(called, true);
});

async function withApi(pool, run) {
  const app = express(); app.use(express.json());
  const auth = (req, res, next) => {
    if (req.headers.authorization !== 'Bearer fixture-admin') return res.status(403).json({ error: 'Admin required' });
    req.admin = { email: 'admin@example.test' }; next();
  };
  registerOperationsRoutes(app, { getPool: () => pool, auth });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const request = async (path, options = {}) => {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/api/admin${path}`, { ...options, headers: { Authorization: 'Bearer fixture-admin', 'Content-Type': 'application/json', ...options.headers } });
    return { status: res.status, data: await res.json(), cache: res.headers.get('cache-control') };
  };
  try { await run(request); } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}
test('every operations endpoint requires admin authorization before touching data', async () => {
  await withApi({ query() { assert.fail('unauthorized database access'); } }, async request => {
    for (const [path, method] of [['/records/users', 'GET'], ['/platform', 'GET'], ['/platform', 'PUT'], ['/users/customer@example.test/revoke-sessions', 'POST'], ['/loans/123/review', 'PATCH']]) {
      const res = await request(path, { method, headers: { Authorization: 'Bearer customer' } }); assert.equal(res.status, 403);
    }
  });
});
test('platform controls reject stale writes and validate all switches before saving', async () => {
  const calls = [];
  await withApi({ query: async (sql, values) => { calls.push({ sql, values }); return { rowCount: 0, rows: [] }; } }, async request => {
    assert.equal((await request('/platform', { method: 'PUT', body: JSON.stringify({ ...FEATURE_DEFAULTS, revision: 4, extra: 'x' }) })).status, 400);
    assert.equal(calls.length, 0);
    const res = await request('/platform', { method: 'PUT', body: JSON.stringify({ ...FEATURE_DEFAULTS, transfers_enabled: false, revision: 4 }) });
    assert.equal(res.status, 409); assert.match(res.data.error, /another session/);
    assert.equal(JSON.parse(calls[0].values[0]).transfers_enabled, false);
    assert.equal(calls[0].values[2], 4);
  });
});
test('session revocation increments only the selected user and handles missing users', async () => {
  let found = true;
  await withApi({ query: async (sql, values) => { assert.match(sql, /session_version=session_version\+1/); assert.deepEqual(values, [customer.user_email]); return { rowCount: found ? 1 : 0, rows: found ? [customer] : [] }; } }, async request => {
    const res = await request(`/users/${customer.user_email}/revoke-sessions`, { method: 'POST' });
    assert.equal(res.status, 200); assert.equal(res.data.user_email, customer.user_email); assert.match(res.cache, /no-store/);
    found = false; assert.equal((await request(`/users/${customer.user_email}/revoke-sessions`, { method: 'POST' })).status, 404);
  });
});
test('loan review is atomic, rejects repeat decisions, and never writes balances or payments', async () => {
  let pending = true; const calls = [];
  const client = { release() {}, query: async (sql, values) => { calls.push({ sql, values }); if (sql.startsWith('UPDATE loans')) return { rowCount: pending ? 1 : 0, rows: pending ? [{ id: '11111111-1111-4111-a111-111111111111', user_email: customer.user_email, status: 'approved' }] : [] }; return { rows: [] }; } };
  await withApi({ connect: async () => client }, async request => {
    const payload = { method: 'PATCH', body: JSON.stringify({ decision: 'approved', reason: 'Reviewed supporting documents' }) };
    const result = await request('/loans/11111111-1111-4111-a111-111111111111/review', payload);
    assert.equal(result.status, 200); assert.match(result.data.message, /No funds/);
    assert.match(calls[1].sql, /status='pending'/); assert.match(calls[2].sql, /INSERT INTO loan_reviews/); assert.equal(calls[3].sql, 'COMMIT');
    assert.ok(calls.every(call => !/UPDATE accounts|INSERT INTO transactions|fee_paid/.test(call.sql)));
    pending = false; calls.length = 0;
    assert.equal((await request('/loans/11111111-1111-4111-a111-111111111111/review', payload)).status, 409);
    assert.equal(calls.at(-1).sql, 'ROLLBACK'); assert.ok(!calls.some(call => call.sql.startsWith('INSERT')));
  });
});
test('record API returns paged results and totals without exposing private tokens', async () => {
  const calls = [];
  await withApi({ query: async (sql, values) => { calls.push({ sql, values }); return { rows: sql.startsWith('SELECT COUNT') ? [{ total: 160 }] : [{ user_email: customer.user_email }] }; } }, async request => {
    const res = await request('/records/users?page=6&limit=25&q=customer');
    assert.equal(res.status, 200); assert.equal(res.data.total, 160); assert.equal(res.data.page, 6); assert.equal(calls[1].values.at(-1), 125);
  });
});
test('the actual admin middleware rejects forged roles and mismatched identities', async () => {
  const source = readFileSync(new URL('../src/server.js', import.meta.url), 'utf8');
  const start = source.indexOf('async function adminAuthMiddleware(');
  const end = source.indexOf('\nasync function ensureAvailableAccount', start);
  assert.ok(start > 0 && end > start);
  const auth = runInNewContext(source.slice(start, end) + '\nadminAuthMiddleware', {
    hasAdminCredentials: () => true, extractBearerToken: req => req.token, verifyJwtToken: token => token,
    ADMIN_USER: 'admin@example.test', auditMutation: async (_pool, _req, _res, next) => next(), pool: {},
  });
  for (const token of [null, { role: 'customer', email: 'admin@example.test' }, { role: 'admin', email: 'attacker@example.test' }]) {
    const res = { status(value) { this.statusCode = value; return this; }, json(body) { return body; }, set() {} };
    await auth({ token }, res, () => assert.fail('must not grant admin access'));
    assert.ok([401, 403].includes(res.statusCode));
  }
  let granted = false;
  await auth({ token: { role: 'admin', email: 'admin@example.test' } }, { set() {} }, () => { granted = true; });
  assert.equal(granted, true);
});
