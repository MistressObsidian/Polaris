import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { escapeHtml, money, direction, transactions, monthlyIncome, balanceHistory } from '../frontend/dashboard-data.js';

test('explicit debit direction takes precedence over a positive bank amount', () => {
  assert.equal(direction({ amount: 250, direction: 'debit', type: 'transfer' }), 'debit');
  assert.equal(direction({ amount: -250, direction: 'credit' }), 'credit');
  assert.equal(direction({ amount: 250, type: 'debit' }), 'debit');
});

test('monthly income excludes pending credits, debits, future dates and other months', () => {
  const now = new Date('2026-10-15T12:00:00');
  const rows = [
    { amount: 100, direction: 'credit', status: 'completed', created_at: '2026-10-10T12:00:00' },
    { amount: 800, direction: 'credit', status: 'pending', created_at: '2026-10-10T12:00:00' },
    { amount: 500, direction: 'debit', created_at: '2026-10-11T12:00:00' },
    { amount: 200, direction: 'credit', created_at: '2026-09-10T12:00:00' },
    { amount: 400, direction: 'credit', created_at: '2026-10-20T12:00:00' },
  ];
  assert.deepEqual(monthlyIncome(rows, now), { total: 100, count: 1 });
});

test('history uses only valid posted balance snapshots within the requested period', () => {
  const now = new Date('2026-10-15T12:00:00');
  const rows = [
    { balance_after: 100, created_at: '2026-08-01T12:00:00' },
    { balance_after: 200, created_at: '2026-10-01T12:00:00' },
    { balance_after: 0, created_at: '2026-10-02T12:00:00' },
    { balance_after: null, created_at: '2026-10-03T12:00:00' },
    { balance_after: 400, created_at: '2026-10-04T12:00:00', status: 'pending' },
    { balance_after: 'invalid', created_at: '2026-10-05T12:00:00' },
  ];
  assert.deepEqual(balanceHistory(rows, '1M', now).map(point => point.balance), [200, 0]);
  assert.deepEqual(balanceHistory(rows, '3M', now).map(point => point.balance), [100, 200, 0]);
});

test('missing financial values remain unavailable instead of being presented as zero', () => {
  assert.equal(money(null), '—');
  assert.equal(money(undefined), '—');
  assert.equal(money('invalid'), '—');
  assert.equal(money(0), '$0.00');
});

const script = readFileSync(new URL('../frontend/dashboard.js', import.meta.url), 'utf8').replace(/^import[^\n]+\n/, '');
async function dashboard({ preview = false, user, fail = false, unauthorized = false, portfolio = {}, marketData = {} } = {}) {
  const elements = new Map();
  const element = key => {
    if (!elements.has(key)) elements.set(key, {
      textContent: '', innerHTML: '', hidden: false, disabled: false, style: {}, dataset: {}, attributes: {}, listeners: {},
      classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
      setAttribute(name, value) { this.attributes[name] = value; }, removeAttribute() {},
      addEventListener(name, handler) { this.listeners[name] = handler; }, querySelector() { return element('svg'); },
      querySelectorAll() { return []; }, focus() {}, showModal() {}, close() {},
    });
    return elements.get(key);
  };
  const requests = [], writes = [], redirects = [], intervals = [];
  const storage = new Map(user ? [['bs-user', JSON.stringify(user)]] : []);
  const context = vm.createContext({
    esc: escapeHtml, money, direction, transactions, monthlyIncome, balanceHistory,
    document: { getElementById: element, querySelector: element, querySelectorAll: () => [], addEventListener() {}, body: element('body'), documentElement: element('html') },
    location: { search: preview ? '?preview=1' : '', replace: url => redirects.push(url), assign: url => redirects.push(url) },
    localStorage: { getItem: key => storage.get(key) ?? null, setItem(key, value) { writes.push(key); storage.set(key, value); }, removeItem: key => storage.delete(key) },
    window: { API_BASE: '/api', addEventListener() {} }, URLSearchParams, URL, AbortSignal, innerWidth: 1280,
    setTimeout: () => 0, clearTimeout() {}, setInterval: callback => { intervals.push(callback); return 1; }, clearInterval() {},
    fetch: async (url, opts) => {
      requests.push({ url, authorization: opts.headers?.Authorization });
      if (fail) throw new Error('Offline');
      if (unauthorized) return { ok: false, status: 401 };
      return { ok: true, status: 200, json: async () => url === '/api/users/me'
        ? { id: 'test@example.com', fullname: 'Test User', available_balance: 500, balances: { accounts: [] } }
        : url === '/api/transactions'
          ? [{ direction: 'debit', amount: 25, description: '<img src=x onerror=alert(1)>', created_at: new Date().toISOString(), balance_after: 500 }]
          : url === '/api/investments/portfolio' ? portfolio : url === '/api/markets' ? marketData : {} };
    },
  });
  vm.runInContext(script, context);
  await new Promise(resolve => setImmediate(resolve));
  return { element, requests, writes, redirects, intervals };
}

test('preview never calls authenticated APIs or writes to the real session', async () => {
  const app = await dashboard({ preview: true, user: { token: 'existing-session' } });
  assert.equal(app.element('heroAvailableBalance').textContent, '$48,250.80');
  assert.match(app.element('holdingsTable').innerHTML, /Gold futures/);
  assert.equal(app.element('previewBanner').hidden, false);
  assert.deepEqual(app.requests, []);
  assert.deepEqual(app.writes, []);
});

test('the real dashboard requires sign-in and never substitutes preview data', async () => {
  const app = await dashboard();
  assert.deepEqual(app.redirects, ['/login']);
  assert.deepEqual(app.requests, []);
  assert.equal(app.element('holdingsTable').innerHTML, '');
});

test('signed-in dashboard uses the bearer session and escapes transaction content', async () => {
  const app = await dashboard({ user: { token: 'test-token', id: 'test@example.com' } });
  assert.equal(app.element('heroAvailableBalance').textContent, '$500.00');
  assert.equal(app.element('investmentValue').textContent, '—');
  assert.equal(app.element('portfolioBadge').textContent, 'Not connected');
  assert.ok(app.requests.filter(request => request.url !== '/api/markets').every(request => request.authorization === 'Bearer test-token'));
  assert.equal(app.requests.find(request => request.url === '/api/markets').authorization, undefined);
  assert.match(app.element('transactionsTable').innerHTML, /−\$25\.00/);
  assert.doesNotMatch(app.element('transactionsTable').innerHTML, /<img/);
  assert.match(app.element('transactionsTable').innerHTML, /&lt;img/);
});

test('failed API reads do not display cached balances as current or erase the session', async () => {
  const app = await dashboard({ user: { token: 'test-token', available_balance: 99999 }, fail: true });
  assert.equal(app.element('heroAvailableBalance').textContent, '—');
  assert.equal(app.element('moneyIn').textContent, '—');
  assert.equal(app.element('loadNotice').hidden, false);
  assert.deepEqual(app.writes, []);
  assert.deepEqual(app.redirects, []);
});

test('expired sessions redirect and do not start background polling', async () => {
  const app = await dashboard({ user: { token: 'expired-token' }, unauthorized: true });
  assert.ok(app.redirects.includes('/login'));
  assert.deepEqual(app.intervals, []);
});

test('balance privacy replaces amounts and position quantities in rendered content', async () => {
  const app = await dashboard({ preview: true });
  app.element('privacyBtn').listeners.click();
  assert.equal(app.element('heroAvailableBalance').textContent, '••••••');
  assert.doesNotMatch(app.element('holdingsTable').innerHTML, /28,650|0\.3500/);
  assert.doesNotMatch(app.element('transactionsTable').innerHTML, /8,500/);
  app.element('privacyBtn').listeners.click();
  assert.equal(app.element('heroAvailableBalance').textContent, '$48,250.80');
});

test('connected holdings show real values without inventing investment returns', async () => {
  const app = await dashboard({ user: { token: 'test-token' }, portfolio: { status: 'connected', total: 800, holdings: [{ id: 'btc', name: 'Bitcoin', ticker: 'BTC', category: 'crypto', className: 'btc', symbol: '₿', detail: '0.01 BTC', value: 800, pnl: null, percent: null }] } });
  assert.equal(app.element('investmentValue').textContent, '$800.00');
  assert.match(app.element('holdingsTable').innerHTML, /Not supplied/);
  assert.doesNotMatch(app.element('holdingsTable').innerHTML, /NaN|undefined|\+\$0/);
  assert.equal(app.element('connectCoinbaseBtn').hidden, true);
  assert.equal(app.element('disconnectCoinbaseBtn').hidden, false);
});

test('missing Coinbase configuration is truthful and public quotes remain independent', async () => {
  const app = await dashboard({ user: { token: 'test-token' }, portfolio: { status: 'configuration_required', holdings: [] }, marketData: { quotes: [{ id: 'btc', name: 'Bitcoin', ticker: 'BTC / USD', symbol: '₿', className: 'btc', source: 'Coinbase', frequency: 'Market price', available: true, price: 80000, change: -1, asOf: '2026-10-15T10:00:00Z' }] } });
  assert.equal(app.element('connectCoinbaseBtn').disabled, true);
  assert.equal(app.element('investmentValue').textContent, '—');
  assert.equal(app.element('marketBadge').textContent, 'Connected');
  assert.match(app.element('marketList').innerHTML, /80,000\.00/);
});
