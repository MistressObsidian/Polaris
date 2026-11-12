import { randomUUID } from 'node:crypto';
import { createBase58check, bech32, bech32m } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const base58check = createBase58check(sha256);
const NETWORKS = Object.freeze({ bitcoin: { name: 'Bitcoin', ticker: 'BTC', decimals: 8 }, ethereum: { name: 'Ethereum', ticker: 'ETH', decimals: 18 } });
const LIMIT = 5;
const invalid = () => Object.assign(new Error('Enter a valid public address for the selected network. Never enter a recovery phrase or private key.'), { status: 400 });

// Validate mainnet addresses and their checksums before persistence or any provider request.
export function normalizeWalletAddress(network, input) {
  if (!Object.hasOwn(NETWORKS, network) || typeof input !== 'string') throw invalid();
  const address = input.trim();
  if (!address || address.length > 90 || /\s/.test(address)) throw invalid();
  try {
    if (network === 'ethereum') {
      if (!/^0x[\da-fA-F]{40}$/.test(address)) throw invalid();
      const raw = address.slice(2), lower = raw.toLowerCase();
      if (raw !== lower && raw !== raw.toUpperCase()) {
        const hash = Buffer.from(keccak_256(new TextEncoder().encode(lower))).toString('hex');
        const checked = [...lower].map((char, i) => parseInt(hash[i], 16) >= 8 ? char.toUpperCase() : char).join('');
        if (raw !== checked) throw invalid();
      }
      return `0x${lower}`;
    }
    if (/^bc1/i.test(address)) {
      let decoded, codec;
      try { decoded = bech32.decode(address); codec = bech32; }
      catch { decoded = bech32m.decode(address); codec = bech32m; }
      const version = decoded.words[0], program = codec.fromWords(decoded.words.slice(1));
      if (decoded.prefix !== 'bc' || version > 16 || program.length < 2 || program.length > 40 ||
          (version === 0 ? codec !== bech32 || ![20, 32].includes(program.length) : codec !== bech32m)) throw invalid();
      return address.toLowerCase();
    }
    const payload = base58check.decode(address);
    if (payload.length !== 21 || ![0, 5].includes(payload[0])) throw invalid();
    return address;
  } catch { throw invalid(); }
}

async function providerJson(fetcher, url, options = {}, timeoutMs = 8000) {
  const response = await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) { await response.body?.cancel(); throw new Error('Provider unavailable'); }
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 131072) { await reader.cancel(); throw new Error('Provider response too large'); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function decimalAmount(units, decimals) {
  const scale = 10n ** BigInt(decimals);
  const fraction = (units % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${units / scale}${fraction ? `.${fraction}` : ''}`;
}
export async function readWalletBalance(network, input, fetcher = fetch) {
  const address = normalizeWalletAddress(network, input);
  let units;
  if (network === 'bitcoin') {
    const data = await providerJson(fetcher, `https://blockstream.info/api/address/${address}`);
    const { funded_txo_sum: funded, spent_txo_sum: spent } = data.chain_stats || {};
    if (data.address !== address || !Number.isSafeInteger(funded) || !Number.isSafeInteger(spent) || spent < 0 || funded < spent) throw new Error('Invalid Bitcoin balance');
    units = BigInt(funded) - BigInt(spent);
  } else {
    const data = await providerJson(fetcher, 'https://ethereum-rpc.publicnode.com', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [address, 'latest'] }) });
    if (data.jsonrpc !== '2.0' || data.id !== 1 || data.error || !/^0x[\da-f]{1,64}$/i.test(data.result || '')) throw new Error('Invalid Ethereum balance');
    units = BigInt(data.result);
  }
  return decimalAmount(units, NETWORKS[network].decimals);
}

export function registerExternalWalletRoutes(app, { getPool, auth, isEnabled = async () => true, fetcher = fetch }) {
  // Only completed public exchange rates are cached; customer addresses and balances stay request-local.
  let cachedRates;
  async function prices() {
    if (cachedRates && cachedRates.until > Date.now()) return cachedRates.rates;
    const rates = {};
    try {
      const data = await providerJson(fetcher, 'https://api.coinbase.com/v2/exchange-rates?currency=USD', {}, 4000);
      if (data.data?.currency !== 'USD') throw new Error('Wrong quote currency');
      for (const ticker of ['BTC', 'ETH']) {
        const rate = Number(data.data.rates?.[ticker]);
        if (rate > 0 && Number.isFinite(1 / rate)) rates[ticker] = { price: 1 / rate, source: 'Coinbase' };
      }
    } catch { /* The public fallback receives coin IDs only, never customer addresses. */ }
    if (!rates.BTC || !rates.ETH) {
      try {
        const data = await providerJson(fetcher, 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd&include_last_updated_at=true', {}, 4000);
        for (const [ticker, id] of [['BTC', 'bitcoin'], ['ETH', 'ethereum']]) {
          const quote = data[id];
          if (!rates[ticker] && typeof quote?.usd === 'number' && Number.isFinite(quote.usd) && quote.usd > 0 && Number.isFinite(quote.last_updated_at) && Math.abs(Date.now() - quote.last_updated_at * 1000) <= 300000) rates[ticker] = { price: quote.usd, source: 'CoinGecko' };
        }
      } catch { /* Keep native balances when every price source is unavailable. */ }
    }
    if (rates.BTC || rates.ETH) cachedRates = { rates, until: Date.now() + 60000 };
    return rates;
  }
  const route = '/api/investments/wallets';
  app.use(route, (_req, res, next) => { res.set('Cache-Control', 'private, no-store'); next(); });
  app.get(route, auth, async (req, res) => {
    try {
      const { rows } = await getPool().query('SELECT id, network, address, created_at FROM external_wallets WHERE user_email=$1 ORDER BY created_at, id LIMIT 5', [req.userId]);
      const enabled = await isEnabled();
      const ratesPromise = enabled && rows.length ? prices() : Promise.resolve({});
      const wallets = await Promise.all(rows.map(async row => {
        const wallet = { ...row, ...NETWORKS[row.network], quantity: null, value: null, asOf: null, status: enabled ? 'unavailable' : 'paused' };
        if (!enabled) return wallet;
        try {
          wallet.quantity = await readWalletBalance(row.network, row.address, fetcher);
          wallet.asOf = new Date().toISOString(); wallet.status = 'available';
          const quote = (await ratesPromise)[wallet.ticker];
          wallet.priceSource = quote?.source || null;
          const amount = Number(wallet.quantity);
          wallet.value = amount === 0 ? 0 : quote && Number.isFinite(amount * quote.price) ? amount * quote.price : null;
        } catch { /* Failed reads remain unavailable, never a fabricated zero balance. */ }
        return wallet;
      }));
      await ratesPromise;
      res.json({ status: enabled ? 'ready' : 'paused', wallets, limit: LIMIT });
    } catch { res.status(503).json({ error: 'Your saved wallets could not be loaded. Please try again.' }); }
  });
  app.post(route, auth, async (req, res) => {
    let client;
    try {
      if (!req.body || Object.keys(req.body).some(key => !['network', 'address'].includes(key))) throw invalid();
      const { network } = req.body;
      const address = normalizeWalletAddress(network, req.body.address);
      if (!await isEnabled()) return res.status(503).json({ error: 'Investment connections are temporarily paused.' });
      client = await getPool().connect();
      await client.query('BEGIN');
      // Lock the owner row so simultaneous additions cannot bypass the five-address limit.
      const owner = await client.query('SELECT user_email FROM users WHERE user_email=$1 FOR UPDATE', [req.userId]);
      if (!owner.rows.length) throw Object.assign(new Error('Please sign in again.'), { status: 401 });
      const existing = await client.query('SELECT id, network, address FROM external_wallets WHERE user_email=$1', [req.userId]);
      if (existing.rows.some(row => row.network === network && row.address === address)) throw Object.assign(new Error('This address is already in your wallet list.'), { status: 409 });
      if (existing.rows.length >= LIMIT) throw Object.assign(new Error('You can save up to five wallet addresses. Remove one before adding another.'), { status: 409 });
      const { rows } = await client.query('INSERT INTO external_wallets (id, user_email, network, address) VALUES ($1,$2,$3,$4) RETURNING id, network, address, created_at', [randomUUID(), req.userId, network, address]);
      await client.query('COMMIT');
      res.status(201).json({ wallet: rows[0] });
    } catch (error) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      res.status(error.status || 503).json({ error: error.status ? error.message : 'Your wallet could not be saved. Please try again.' });
    } finally { client?.release(); }
  });
  app.delete(`${route}/:id`, auth, async (req, res) => {
    if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(req.params.id)) return res.status(400).json({ error: 'Invalid wallet reference.' });
    try {
      // Removal remains available while investment connections are paused.
      const { rows } = await getPool().query('DELETE FROM external_wallets WHERE id=$1 AND user_email=$2 RETURNING id', [req.params.id, req.userId]);
      if (!rows.length) return res.status(404).json({ error: 'Wallet not found.' });
      res.json({ removed: true });
    } catch { res.status(503).json({ error: 'Your wallet could not be removed. Please try again.' }); }
  });
}
