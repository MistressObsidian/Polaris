import crypto from 'node:crypto';

const COINBASE_API = 'https://api.coinbase.com';
const COINBASE_LOGIN = 'https://login.coinbase.com/oauth2';
const CALLBACK = '/api/investments/coinbase/callback';
const COOKIE = 'bc_coinbase_link';
const SCOPES = 'wallet:accounts:read offline_access';
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const random = () => crypto.randomBytes(32).toString('base64url');
const number = value => value === null || value === undefined || value === '' ? null : Number.isFinite(Number(value)) ? Number(value) : null;

export function coinbaseConfig(env = process.env) {
  const { COINBASE_CLIENT_ID: id, COINBASE_CLIENT_SECRET: secret, COINBASE_REDIRECT_URI: redirect, INVESTMENT_TOKEN_KEY: key } = env;
  if (!id || !secret || !redirect || !/^[a-f\d]{64}$/i.test(key || '')) return null;
  try {
    const url = new URL(redirect);
    const local = env.NODE_ENV !== 'production' && !globalThis.__POLARIS_WORKER__ && ['localhost', '127.0.0.1'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(local && url.protocol === 'http:')) || url.pathname !== CALLBACK || url.search || url.hash || url.username || url.password) return null;
    return { id, secret, redirect, key: Buffer.from(key, 'hex'), secure: url.protocol === 'https:' };
  } catch { return null; }
}

// Bind encrypted credentials to their owner as well as to the server key.
export function seal(value, key, owner) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(owner));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(part => part.toString('base64url')).join('.');
}
export function unseal(value, key, owner) {
  const [iv, tag, encrypted] = value.split('.').map(part => Buffer.from(part, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(owner)); decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8'));
}

class ProviderError extends Error {
  constructor(status) { super('Investment provider unavailable'); this.status = status; }
}
async function json(fetcher, url, options = {}) {
  const response = await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new ProviderError(response.status);
  return response.json();
}

export function createMarketFeed(fetcher = fetch) {
  // Only completed public data is shared. Private portfolios and pending I/O are never cached globally.
  let cached = null;
  return async () => {
    if (cached && Date.now() - cached.time < 60000) return cached.result;
    const observedAt = new Date().toISOString();
    const specs = [
      { id: 'btc', name: 'Bitcoin', ticker: 'BTC / USD', symbol: '₿', className: 'btc', source: 'Coinbase', sourceUrl: 'https://www.coinbase.com/price/bitcoin', frequency: 'Market price',
        load: async () => { const q = await json(fetcher, 'https://api.exchange.coinbase.com/products/BTC-USD/stats'); const price = number(q.last), open = number(q.open); return { price, change: price !== null && open > 0 ? (price / open - 1) * 100 : null, asOf: observedAt }; } },
      { id: 'eur', name: 'Euro / US Dollar', ticker: 'EUR / USD', symbol: '€', className: 'forex', source: 'Frankfurter', sourceUrl: 'https://frankfurter.dev/', frequency: 'Daily reference',
        load: async () => { const q = await json(fetcher, 'https://api.frankfurter.dev/v2/rate/eur/usd'); return { price: q.base === 'EUR' && q.quote === 'USD' ? number(q.rate) : null, change: null, asOf: q.date }; } },
      { id: 'btc-future', name: 'Bitcoin perpetual', ticker: 'BTC / USD · Futures', symbol: '₿', className: 'futures', source: 'Kraken', sourceUrl: 'https://futures.kraken.com/', frequency: 'Last trade',
        load: async () => { const data = await json(fetcher, 'https://futures.kraken.com/derivatives/api/v3/tickers?symbol=PI_XBTUSD'); const q = data.tickers?.find(item => item.symbol === 'PI_XBTUSD'); return { price: q && !q.suspended ? number(q.last) : null, change: number(q?.change24h), asOf: q?.lastTime }; } },
    ];
    const quotes = await Promise.all(specs.map(async ({ load, ...spec }) => {
      try { const quote = await load(); if (!(quote.price > 0) || !quote.asOf || !Number.isFinite(Date.parse(quote.asOf))) throw new Error('Invalid quote'); return { ...spec, ...quote, available: true }; }
      catch { return { ...spec, price: null, change: null, asOf: null, available: false }; }
    }));
    const result = { quotes, updatedAt: observedAt };
    cached = { time: Date.now(), result };
    return result;
  };
}

export async function readCoinbaseAccounts(accessToken, fetcher = fetch) {
  const accounts = [], seen = new Set();
  let next = '/v2/accounts?limit=100';
  for (let page = 0; next && page < 20; page++) {
    const url = new URL(next, COINBASE_API);
    if (url.origin !== COINBASE_API || url.pathname !== '/v2/accounts' || url.username || url.password || seen.has(url.href)) throw new Error('Invalid account pagination');
    seen.add(url.href);
    const data = await json(fetcher, url.href, { headers: { Authorization: `Bearer ${accessToken}`, 'CB-VERSION': '2024-01-01' } });
    if (!Array.isArray(data.data)) throw new Error('Invalid account response');
    accounts.push(...data.data);
    next = data.pagination?.next_uri;
  }
  if (next) throw new Error('Incomplete account response');
  return accounts;
}

export function normalizeHoldings(accounts, rates) {
  return accounts.filter(account => account.type !== 'fiat' && account.currency?.type !== 'fiat').map(account => {
    const amount = number(account.balance?.amount);
    if (amount === null || amount < 0) throw new Error('Invalid holding balance');
    const ticker = String(account.balance?.currency || account.currency?.code || '');
    if (!/^[A-Z0-9._-]{1,30}$/.test(ticker)) throw new Error('Invalid holding currency');
    const rate = number(rates?.[ticker]);
    return { id: String(account.id), name: String(account.currency?.name || ticker), ticker, category: 'crypto',
      className: ticker === 'BTC' ? 'btc' : 'eth', symbol: ticker === 'BTC' ? '₿' : ticker === 'ETH' ? 'Ξ' : ticker.slice(0, 2),
      detail: `${amount.toLocaleString('en-US', { maximumFractionDigits: 12 })} ${ticker}`, quantity: amount,
      value: rate > 0 && Number.isFinite(amount / rate) ? amount / rate : null, pnl: null, percent: null };
  }).filter(holding => holding.quantity > 0);
}

export function registerInvestmentRoutes(app, { getPool, auth, config = () => coinbaseConfig(), fetcher = fetch, isEnabled = async () => true }) {
  const noStore = (_req, res, next) => { res.set('Cache-Control', 'private, no-store'); next(); };
  app.use('/api/investments', noStore);
  const empty = status => ({ provider: 'Coinbase', status, holdings: [], total: null });
  const cookieOptions = cfg => ({ httpOnly: true, secure: cfg.secure, sameSite: 'lax', path: CALLBACK, maxAge: 600000 });
  async function exchange(cfg, fields) {
    const data = await json(fetcher, `${COINBASE_LOGIN}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: cfg.id, client_secret: cfg.secret, ...fields }).toString() });
    if (!data.access_token || !data.refresh_token || !(number(data.expires_in) > 0)) throw new Error('Invalid token response');
    const scopes = String(data.scope || '').split(/[ ,]+/);
    if (!scopes.includes('wallet:accounts:read') || scopes.some(scope => scope && !SCOPES.split(' ').includes(scope))) throw new Error('Unexpected token permissions');
    return { access: data.access_token, refresh: data.refresh_token, expires: Date.now() + Number(data.expires_in) * 1000 };
  }
  async function accessToken(owner, cfg) {
    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      // Refresh tokens rotate once; the row lock serializes requests for this customer.
      const { rows } = await client.query('SELECT token_cipher FROM coinbase_connections WHERE user_email = $1 FOR UPDATE', [owner]);
      if (!rows.length) { await client.query('COMMIT'); return null; }
      let token = unseal(rows[0].token_cipher, cfg.key, owner);
      if (token.expires < Date.now() + 60000) {
        token = await exchange(cfg, { grant_type: 'refresh_token', refresh_token: token.refresh });
        await client.query('UPDATE coinbase_connections SET token_cipher = $2, updated_at = NOW() WHERE user_email = $1', [owner, seal(token, cfg.key, owner)]);
      }
      await client.query('COMMIT');
      return token.access;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  app.post('/api/investments/coinbase/connect', auth, async (req, res) => {
    if (!await isEnabled()) return res.status(503).json({ error: 'Investment connections are temporarily paused.', status: 'paused' });
    const cfg = config();
    if (!cfg) return res.status(503).json({ error: 'Coinbase connections are not available yet.', status: 'configuration_required' });
    if (req.headers.origin && req.headers.origin !== new URL(cfg.redirect).origin) return res.status(403).json({ error: 'Open the dashboard on the configured application address.' });
    try {
      const state = random(), browser = random(), verifier = random(), owner = req.userId;
      await getPool().query('DELETE FROM coinbase_oauth_states WHERE user_email = $1 OR expires_at < NOW()', [owner]);
      await getPool().query('INSERT INTO coinbase_oauth_states (state_hash, user_email, browser_hash, verifier_cipher, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL \'10 minutes\')', [hash(state), owner, hash(browser), seal(verifier, cfg.key, owner)]);
      const url = new URL(`${COINBASE_LOGIN}/auth`);
      url.search = new URLSearchParams({ response_type: 'code', client_id: cfg.id, redirect_uri: cfg.redirect, scope: SCOPES, state, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
      res.cookie(COOKIE, browser, cookieOptions(cfg));
      res.json({ url: url.href });
    } catch { res.status(503).json({ error: 'Coinbase connection is temporarily unavailable.' }); }
  });

  app.get(CALLBACK, async (req, res) => {
    const cfg = config();
    res.set('Referrer-Policy', 'no-referrer');
    if (!cfg) return res.redirect('/dashboard?coinbase=unavailable#portfolio');
    const browser = String(req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1) || '';
    res.clearCookie(COOKIE, { ...cookieOptions(cfg), maxAge: undefined });
    try {
      if (!/^[\w-]{43}$/.test(req.query.state || '') || !/^[\w-]{43}$/.test(browser)) throw new Error('Invalid state');
      const { rows } = await getPool().query('DELETE FROM coinbase_oauth_states WHERE state_hash = $1 AND browser_hash = $2 AND expires_at > NOW() RETURNING user_email, verifier_cipher', [hash(req.query.state), hash(browser)]);
      if (rows.length !== 1) throw new Error('Expired state');
      if (req.query.error) return res.redirect('/dashboard?coinbase=cancelled#portfolio');
      if (!await isEnabled()) return res.redirect('/dashboard?coinbase=unavailable#portfolio');
      if (typeof req.query.code !== 'string' || req.query.code.length > 2048 || !req.query.code) throw new Error('Missing authorization code');
      const owner = rows[0].user_email;
      const token = await exchange(cfg, { grant_type: 'authorization_code', code: req.query.code, redirect_uri: cfg.redirect, code_verifier: unseal(rows[0].verifier_cipher, cfg.key, owner) });
      await getPool().query('INSERT INTO coinbase_connections (user_email, token_cipher) VALUES ($1, $2) ON CONFLICT (user_email) DO UPDATE SET token_cipher = EXCLUDED.token_cipher, updated_at = NOW()', [owner, seal(token, cfg.key, owner)]);
      return res.redirect('/dashboard?coinbase=connected#portfolio');
    } catch { return res.redirect('/dashboard?coinbase=failed#portfolio'); }
  });

  app.get('/api/investments/portfolio', auth, async (req, res) => {
    if (!await isEnabled()) return res.json(empty('paused'));
    const cfg = config();
    if (!cfg) return res.json(empty('configuration_required'));
    try {
      const token = await accessToken(req.userId, cfg);
      if (!token) return res.json(empty('disconnected'));
      const accounts = await readCoinbaseAccounts(token, fetcher);
      let rates = {};
      try { const data = await json(fetcher, `${COINBASE_API}/v2/exchange-rates?currency=USD`); if (data.data?.currency === 'USD') rates = data.data.rates; } catch { /* Quantities remain useful when valuation is unavailable. */ }
      const holdings = normalizeHoldings(accounts, rates);
      const total = holdings.every(holding => holding.value !== null) ? holdings.reduce((sum, holding) => sum + holding.value, 0) : null;
      return res.json({ provider: 'Coinbase', status: 'connected', holdings, total, asOf: new Date().toISOString(), currency: 'USD' });
    } catch (error) {
      if (error instanceof ProviderError && [400, 401, 403].includes(error.status)) return res.json(empty('reconnect_required'));
      return res.status(503).json({ ...empty('unavailable'), error: 'Your Coinbase holdings could not be refreshed.' });
    }
  });

  app.delete('/api/investments/coinbase', auth, async (req, res) => {
    const cfg = config();
    if (!cfg) return res.status(503).json({ error: 'Coinbase is not available.' });
    const client = await getPool().connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query('SELECT token_cipher FROM coinbase_connections WHERE user_email = $1 FOR UPDATE', [req.userId]);
      let revoked = !rows.length;
      if (rows.length) {
        const token = unseal(rows[0].token_cipher, cfg.key, req.userId);
        try {
          const response = await fetcher(`${COINBASE_LOGIN}/revoke`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(8000), headers: { Authorization: `Bearer ${token.access}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: token.access, client_id: cfg.id, client_secret: cfg.secret }).toString() });
          revoked = response.ok; await response.body?.cancel();
        } catch { /* Always allow the customer to remove credentials locally. */ }
      }
      await client.query('DELETE FROM coinbase_connections WHERE user_email = $1', [req.userId]);
      await client.query('DELETE FROM coinbase_oauth_states WHERE user_email = $1', [req.userId]);
      await client.query('COMMIT');
      res.json({ status: 'disconnected', revokeRequested: revoked });
    } catch { await client.query('ROLLBACK'); res.status(503).json({ error: 'Could not disconnect Coinbase. Please try again.' }); }
    finally { client.release(); }
  });
}
