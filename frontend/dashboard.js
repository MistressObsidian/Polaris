import { escapeHtml as esc, money, direction, transactions, monthlyIncome, balanceHistory } from './dashboard-data.js';

const $ = id => document.getElementById(id);
const preview = new URLSearchParams(location.search).get('preview') === '1';
const state = { user: null, rows: [], portfolio: null, wallets: null, walletStale: false, marketData: null, investmentStale: false, marketStale: false, hasRefreshed: false, range: '1M', filter: 'all', hidden: false, profileReady: false, transactionsReady: false, stream: null, reconnect: null, polling: null, stopped: false, refreshing: false };
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const classes = { crypto: 'Cryptocurrency', forex: 'Forex', futures: 'Futures' };
let walletRevision = 0, refreshAgain = false;
// Illustrative fixtures are confined to the explicitly labeled preview. They are never persisted.
const holdings = [
  { id: 'btc', name: 'Bitcoin', ticker: 'BTC', category: 'crypto', symbol: '₿', className: 'btc', detail: '0.3500 BTC', value: 28650.5, pnl: 2450.5, percent: 9.35 },
  { id: 'eth', name: 'Ethereum', ticker: 'ETH', category: 'crypto', symbol: 'Ξ', className: 'eth', detail: '4.2000 ETH', value: 13490, pnl: 890, percent: 7.06 },
  { id: 'eur', name: 'EUR / USD', ticker: 'EUR/USD', category: 'forex', symbol: '€', className: 'forex', detail: 'Foreign exchange position', value: 19200, pnl: -180, percent: -0.93 },
  { id: 'gold', name: 'Gold futures', ticker: 'GC', category: 'futures', symbol: 'Au', className: 'futures', detail: 'Futures account equity', value: 15500, pnl: 1550, percent: 11.11 },
];
const markets = [
  { name: 'Bitcoin', ticker: 'BTC / USD', symbol: '₿', className: 'btc', price: '$81,858.57', change: '+2.34%' },
  { name: 'Euro / US Dollar', ticker: 'EUR / USD', symbol: '€', className: 'forex', price: '1.0842', change: '−0.12%' },
  { name: 'Gold futures', ticker: 'GC', symbol: 'Au', className: 'futures', price: '$2,645.80', change: '+0.86%' },
];
function readJson(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } }
function storedToken() { try { return localStorage.getItem('bs-token') || ''; } catch { return ''; } }
function value(id, text) { $(id).textContent = text; }
function privateValue(text) { return state.hidden ? '••••••' : esc(text); }
function privateText(id, text) { value(id, state.hidden ? '••••••' : text); }
function notice(message) { $('loadNotice').hidden = !message; value('loadNotice', message); }
function showDialog(title, content, signIn = false) {
  value('dialogTitle', title); $('dialogContent').innerHTML = content;
  $('dialogSignIn').hidden = !signIn; $('detailDialog').showModal();
}
function publicAddressShape(network, address) {
  return network === 'ethereum' ? /^0x[\da-fA-F]{40}$/.test(address) : /^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[ac-hj-np-z02-9]{11,87})$/i.test(address);
}
function walletError(message) {
  value('walletError', message); $('walletError').hidden = !message;
  $('walletAddress').setAttribute('aria-invalid', String(Boolean(message)));
}
function wireWalletUI() {
  const openPublicWallet = () => {
    if (preview) { showDialog('Add external wallet', '<p>Sign in to save a Bitcoin or Ethereum public address and track its balance. Recovery phrases and private keys are never needed.</p>', true); return; }
    walletError(''); $('walletAddress').value = ''; $('walletDialog').showModal(); $('walletAddress').focus();
  };
  $('addWalletBtn').addEventListener('click', openPublicWallet);
  for (const id of ['closeWalletDialog', 'cancelWalletBtn']) $(id).addEventListener('click', () => $('walletDialog').close());
  $('walletDialog').addEventListener('close', () => { $('walletAddress').value = ''; walletError(''); });
  $('walletNetwork').addEventListener('change', () => { $('walletAddress').placeholder = $('walletNetwork').value === 'ethereum' ? '0x… Ethereum mainnet address' : 'bc1… or a Bitcoin address'; walletError(''); });
  $('walletAddress').addEventListener('input', () => walletError(''));
  $('walletAddress').addEventListener('paste', event => {
    const candidate = event.clipboardData?.getData('text')?.trim();
    // Do not put phrases, private keys or arbitrary text into the form or a network request.
    if (candidate && !publicAddressShape($('walletNetwork').value, candidate)) {
      event.preventDefault(); walletError('Paste only a public address for the selected network. Recovery phrases and private keys are not accepted.');
    }
  });
  $('walletForm').addEventListener('submit', async event => {
    event.preventDefault(); if (preview || $('saveWalletBtn').disabled) return;
    const network = $('walletNetwork').value, address = $('walletAddress').value.trim();
    if (!publicAddressShape(network, address)) { walletError('Enter a public address for the selected network. Do not enter a recovery phrase or private key.'); return; }
    $('saveWalletBtn').disabled = true; value('saveWalletBtn', 'Saving…'); walletError('');
    try {
      const result = await api('/investments/wallets', { method: 'POST', body: JSON.stringify({ network, address }) });
      if (!result.wallet?.id || result.wallet.network !== network) throw new Error('The wallet could not be confirmed. Please refresh and check your saved addresses.');
      const wallet = { ...result.wallet, name: network === 'bitcoin' ? 'Bitcoin' : 'Ethereum', ticker: network === 'bitcoin' ? 'BTC' : 'ETH', quantity: null, value: null, asOf: null, status: 'unavailable' };
      state.wallets = { status: 'ready', wallets: [...walletList().filter(item => item.id !== wallet.id), wallet] };
      walletRevision++;
      $('walletDialog').close(); value('walletNotice', 'Wallet saved. Updating its balance…'); renderInvestments();
      await refresh(); value('walletNotice', 'Wallet saved for read-only tracking.');
    } catch (error) { walletError(error.message); }
    finally { $('saveWalletBtn').disabled = false; value('saveWalletBtn', 'Add wallet'); }
  });
  $('walletList').addEventListener('click', event => {
    const button = event.target.closest('[data-remove-wallet]'); if (!button) return;
    const wallet = walletList().find(item => item.id === button.dataset.removeWallet); if (!wallet) return;
    showDialog('Remove this watched address?', `<p>Remove the ${esc(wallet.name)} address ending ${esc(wallet.address.slice(-7))} from your dashboard? Its funds stay in the external wallet.</p><button class="button button-primary" id="confirmRemoveWallet">Remove address</button><p id="removeWalletError" role="alert"></p>`);
    $('confirmRemoveWallet').addEventListener('click', async () => {
      $('confirmRemoveWallet').disabled = true;
      try {
        const result = await api(`/investments/wallets/${encodeURIComponent(wallet.id)}`, { method: 'DELETE' });
        if (!result.removed) throw new Error('Removal could not be confirmed. Please refresh and try again.');
        state.wallets.wallets = walletList().filter(item => item.id !== wallet.id); walletRevision++; renderInvestments();
        $('detailDialog').close(); value('walletNotice', 'Address removed.');
      } catch (error) { value('removeWalletError', error.message); $('confirmRemoveWallet').disabled = false; }
    });
  });
}
function assetMarkup(asset) {
  return `<span class="asset-icon ${esc(asset.className)}" aria-hidden="true">${esc(asset.symbol)}</span><div><strong>${esc(asset.name)}</strong><small>${asset.detail ? privateValue(asset.detail) : esc(asset.ticker)}</small></div>`;
}

function renderProfile() {
  const profile = state.user || {};
  const name = profile.fullname || profile.accountname || 'Your account';
  value('heroName', name === 'Your account' ? 'there' : name.split(/\s+/)[0]);
  value('profileTitle', name); value('profileEmail', profile.email || 'Personal banking');
  const initials = name.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();
  value('profileAvatar', initials);
  const balance = state.profileReady ? (profile.available_balance ?? profile.balances?.available ?? profile.balances?.total) : null;
  privateText('heroAvailableBalance', money(balance));
  value('balanceCaption', state.profileReady ? 'Available across your accounts' : state.hasRefreshed ? 'Account data unavailable' : 'Loading account balances…');
  const accounts = state.profileReady && Array.isArray(profile.balances?.accounts) ? profile.balances.accounts : [];
  $('accountList').innerHTML = accounts.length ? accounts.map(account => `<div class="account-row"><div><span class="account-symbol">${icon('wallet')}</span><div><strong>${esc(account.type === 'available' ? 'Personal account' : account.type || 'Account')}</strong><small>${esc(account.currency || 'USD')} account</small></div></div><span data-private>${privateValue(money(account.available ?? account.balance, account.currency || 'USD'))}</span></div>`).join('') : `<p class="empty-copy">${state.profileReady ? 'No accounts to display.' : state.hasRefreshed ? 'Your account details could not be loaded.' : 'Loading your accounts…'}</p>`;
}

function walletList() { return Array.isArray(state.wallets?.wallets) ? state.wallets.wallets : []; }
function activeHoldings() {
  if (preview) return holdings;
  return [ ...(state.portfolio?.status === 'connected' ? state.portfolio.holdings : []), ...walletList().map(wallet => ({
    id: `wallet-${wallet.id}`, name: wallet.name, ticker: wallet.ticker, category: 'crypto', symbol: wallet.network === 'bitcoin' ? '₿' : 'Ξ', className: wallet.network === 'bitcoin' ? 'btc' : 'eth',
    detail: wallet.quantity === null ? 'Balance unavailable' : `${wallet.quantity} ${wallet.ticker} · Watched address`, value: wallet.value, pnl: null, percent: null,
  })) ];
}
function renderInvestments() {
  const active = activeHoldings();
  const wallets = walletList();
  const coinbaseConnected = state.portfolio?.status === 'connected';
  const connected = preview || coinbaseConnected || wallets.length > 0;
  const total = connected && active.every(asset => asset.value !== null) ? active.reduce((sum, asset) => sum + asset.value, 0) : null;
  const status = state.portfolio?.status;
  const paused = state.wallets?.status === 'paused';
  const stale = state.walletStale || (state.investmentStale && (coinbaseConnected || !wallets.length));
  privateText('investmentValue', money(total)); privateText('allocationValue', money(total));
  value('holdingCount', active.length);
  value('portfolioBadge', preview ? 'Sample portfolio' : paused ? 'Temporarily paused' : stale ? 'Update unavailable' : wallets.some(wallet => wallet.status !== 'available' || wallet.value === null) ? 'Partial update' : connected ? 'Read only' : 'Add a wallet');
  value('allocationCaption', preview ? 'Across 3 asset classes' : connected ? (stale ? 'Last loaded holdings' : 'Tracked crypto balances') : 'No wallets added');
  $('addWalletBtn').disabled = !preview && (!state.wallets || paused || wallets.length >= 5);
  value('connectionDescription', paused ? 'Investment connections are temporarily paused.' : 'Track an existing wallet with its public address. Your funds stay in your wallet.');
  $('connectCoinbaseBtn').hidden = preview || coinbaseConnected || !['disconnected', 'reconnect_required'].includes(status);
  $('connectCoinbaseBtn').disabled = !preview && (!state.hasRefreshed || ['configuration_required', 'paused'].includes(status));
  value('connectCoinbaseBtn', status === 'reconnect_required' ? 'Reconnect Coinbase' : 'Connect Coinbase');
  $('disconnectCoinbaseBtn').hidden = preview || !['connected', 'reconnect_required', 'paused'].includes(status);
  $('walletList').innerHTML = wallets.map(wallet => `<div class="watched-wallet"><span class="wallet-network">${esc(wallet.name)} <small>Public address</small></span><span class="wallet-address" title="${state.hidden ? '' : esc(wallet.address)}">${privateValue(`${wallet.address.slice(0, 9)}…${wallet.address.slice(-7)}`)}</span><button class="text-link" data-remove-wallet="${esc(wallet.id)}" aria-label="Remove ${esc(wallet.name)} address ending ${esc(wallet.address.slice(-7))}">Remove</button></div>`).join('');
  $('walletList').hidden = !wallets.length;
  value('walletLimit', wallets.length ? `${wallets.length} of 5 addresses saved · Read-only tracking` : 'Bitcoin & Ethereum · Public addresses only');
  if (preview) {
    $('investmentCaption').innerHTML = `<span class="positive" data-private>${privateValue('+6.53%')} <span class="muted">sample return</span></span>`;
    value('portfolioNote', 'Illustrative positions only. Forex and futures values represent allocated equity, not notional exposure.');
  } else {
    value('investmentCaption', connected ? (stale ? 'Last loaded value · refresh unavailable' : total === null ? 'Some balances or prices are unavailable' : 'Tracked crypto · estimated USD value') : 'Add an external wallet to get started');
    const timestamps = [state.portfolio?.asOf, ...wallets.map(wallet => wallet.asOf)].filter(Boolean).sort();
    const asOf = timestamps.length ? new Date(timestamps[0]).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }) : '';
    const sources = [...new Set(wallets.map(wallet => wallet.priceSource).filter(Boolean))].join(' / ');
    value('portfolioNote', `${asOf ? `${stale ? 'Last loaded' : 'Balance data from'} ${asOf}. ` : ''}${sources ? `USD estimates: ${sources}. ` : ''}Tracks BTC and ETH at saved mainnet addresses only, not the entire wallet. Excludes tokens, NFTs and pending transactions. Addresses do not prove ownership. Values are separate from your bank balance; returns are unavailable.`);
  }
  const filtered = active.filter(asset => state.filter === 'all' || asset.category === state.filter);
  $('holdingsTable').innerHTML = filtered.length ? filtered.map(asset => `<tr><td><div class="asset-cell">${assetMarkup(asset)}</div></td><td><span class="class-chip">${asset.category === 'crypto' ? 'Crypto' : classes[asset.category]}</span></td><td class="align-right" data-private>${privateValue(money(asset.value))}</td><td class="align-right position-pnl ${asset.pnl === null ? 'muted' : asset.pnl < 0 ? 'negative' : 'positive'}" data-private>${privateValue(asset.pnl === null ? '—' : `${asset.pnl < 0 ? '−' : '+'}${money(Math.abs(asset.pnl))}`)}<span>${privateValue(asset.percent === null ? 'Not supplied' : `${asset.percent > 0 ? '+' : ''}${asset.percent.toFixed(2)}%`)}</span></td><td><button class="details-button" data-holding="${esc(asset.id)}" aria-label="View ${esc(asset.name)} position">${icon('up')}</button></td></tr>`).join('') : `<tr><td colspan="5" class="empty-cell">${state.filter === 'all' || state.filter === 'crypto' ? connected ? 'No crypto balances to display.' : '<strong>Your wallets, in one place.</strong><br>Add a public address to view your crypto balance here.' : `${classes[state.filter]} positions are not connected.`}</td></tr>`;
  const colors = ['#2d6bff', '#8b79e7', '#38bdf8'];
  let offset = 0; const stops = [];
  $('allocationLegend').innerHTML = Object.keys(classes).map((key, index) => {
    const allocation = total > 0 ? active.filter(asset => asset.category === key).reduce((sum, asset) => sum + asset.value, 0) / total * 100 : 0;
    if (total > 0) { stops.push(`${colors[index]} ${offset}% ${offset + allocation}%`); offset += allocation; }
    return `<div class="allocation-row"><span><i class="legend-dot" style="background:${colors[index]}"></i>${classes[key]}</span><strong data-private>${privateValue(total > 0 ? `${allocation.toFixed(1)}%` : '—')}</strong></div>`;
  }).join('');
  $('allocationChart').style.background = total > 0 ? `conic-gradient(${stops.join(',')})` : '';
  $('allocationChart').setAttribute('aria-label', state.hidden ? 'Allocation hidden' : preview ? 'Sample allocation across cryptocurrency, forex, and futures' : connected && total > 0 ? 'Tracked portfolio: cryptocurrency' : 'No investment allocation available');
}
function renderMarkets() {
  const quotes = preview ? markets : state.marketData?.quotes || [];
  $('marketList').innerHTML = quotes.length ? quotes.map(market => {
    const available = preview || market.available;
    const price = preview ? market.price : available ? market.id === 'eur' ? Number(market.price).toFixed(4) : money(market.price) : '—';
    const change = preview ? market.change : available && market.change !== null ? `${market.change >= 0 ? '+' : '−'}${Math.abs(market.change).toFixed(2)}%` : available ? 'Daily reference' : 'Unavailable';
    const date = !preview && market.asOf ? market.id === 'eur' ? market.asOf : new Date(market.asOf).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }) : '';
    return `<div class="market-row"><div><div class="asset-cell">${assetMarkup(market)}</div>${preview ? '' : `<div class="market-source">${esc(market.source)} · ${esc(market.frequency)}${date ? ` · ${esc(date)}` : ''}</div>`}</div><div class="market-price">${esc(price)}<small class="${change.startsWith('−') ? 'negative' : change.startsWith('+') ? 'positive' : 'muted'}">${esc(change)}</small></div></div>`;
  }).join('') : `<p class="empty-copy market-row">${state.marketStale || state.marketData ? 'Market prices are unavailable. Please refresh to try again.' : 'Market prices are loading.'}</p>`;
  const count = quotes.filter(quote => quote.available).length;
  value('marketBadge', preview ? 'Sample prices' : !state.hasRefreshed ? 'Loading…' : state.marketStale ? 'Update unavailable' : count === quotes.length && count ? 'Connected' : count ? 'Partial update' : 'Unavailable');
  value('marketNote', preview ? 'Illustrative prices and daily changes. Not live market data.' : state.marketStale ? 'Last loaded quotes. Prices could not be refreshed.' : 'Refreshes every minute. FX is a daily reference rate. Market prices are separate from your holdings.');
}

function renderTransactions() {
  const income = monthlyIncome(state.rows);
  privateText('moneyIn', state.transactionsReady ? money(income.total) : '—');
  value('moneyInCaption', state.transactionsReady ? `${income.count} posted ${income.count === 1 ? 'credit' : 'credits'} this month` : state.hasRefreshed ? 'Transaction data unavailable' : 'Loading transaction activity…');
  $('transactionsTable').innerHTML = state.rows.length ? state.rows.slice(0, 5).map(tx => {
    const credit = direction(tx) === 'credit';
    const date = new Date(tx.created_at);
    return `<tr><td><div class="asset-cell"><span class="transaction-icon ${credit ? '' : 'debit'}">${icon(credit ? 'down' : 'up')}</span><div><strong class="tx-description" title="${esc(tx.description || tx.type || 'Transaction')}">${esc(tx.description || tx.type || 'Transaction')}</strong><small>${esc(tx.status || (credit ? 'Credit' : 'Debit'))}</small></div></div></td><td class="muted">${Number.isNaN(date.getTime()) ? '—' : esc(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }))}</td><td class="tx-reference" title="${esc(tx.reference || tx.id || '')}">${esc(tx.reference || tx.id || '—')}</td><td class="align-right ${credit ? 'positive' : ''}" data-private>${privateValue(`${credit ? '+' : '−'}${money(Math.abs(Number(tx.amount)), tx.currency || 'USD')}`)}</td></tr>`;
  }).join('') : `<tr><td colspan="4" class="empty-cell">${state.transactionsReady ? 'No transactions yet. Your account activity will appear here.' : state.hasRefreshed ? 'Transactions are unavailable. Use the refresh button to try again.' : 'Loading your transactions…'}</td></tr>`;
}

function demoHistory() {
  const days = ({ '1M': 30, '3M': 90, '6M': 180, '1Y': 365 })[state.range];
  const baseline = ({ '1M': 42100, '3M': 36400, '6M': 28600, '1Y': 18200 })[state.range];
  const pattern = [0,.07,.04,.14,.1,.18,.13,.24,.22,.18,.32,.29,.45,.4,.47,.42,.52,.49,.64,.58,.69,.62,.77,.71,.82,.8,.9,.85,.94,1];
  return pattern.map((factor, index) => ({ date: new Date(Date.now() - days * 86400000 * (1 - index / (pattern.length - 1))), balance: baseline + factor * (48250.8 - baseline) }));
}

function renderChart() {
  const points = preview ? demoHistory() : balanceHistory(state.rows, state.range);
  privateText('chartBalance', points.length ? money(points.at(-1).balance) : '—');
  value('chartChange', preview ? 'Illustrative balance history' : 'Last recorded balance · USD');
  if (points.length < 2) {
    $('balanceChart').innerHTML = '<div class="chart-empty">Balance history will appear after two recorded transactions in this period.</div>';
    return;
  }
  const values = points.map(point => point.balance);
  const min = Math.min(...values), max = Math.max(...values), pad = Math.max((max - min) * .18, 1);
  const lower = min - pad, upper = max + pad;
  const width = 650, left = 0, right = 583, top = 10, bottom = 153;
  const earliest = points[0].date.getTime(), span = Math.max(1, points.at(-1).date.getTime() - earliest);
  const coords = points.map(point => [left + (point.date.getTime() - earliest) / span * right, bottom - (point.balance - lower) / (upper - lower) * (bottom - top)]);
  const line = coords.map(([x, y], index) => `${index ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const grid = [0, 1, 2, 3].map(index => {
    const y = top + index / 3 * (bottom - top), amount = upper - index / 3 * (upper - lower);
    return `<line class="chart-grid" x1="0" x2="${right}" y1="${y}" y2="${y}"/><text x="${width}" y="${y + 3}" text-anchor="end">${esc(new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', notation: 'compact', maximumFractionDigits: 1 }).format(amount))}</text>`;
  }).join('');
  const dates = [0, 1, 2, 3, 4].map(index => {
    const date = new Date(earliest + span * index / 4);
    return `<text x="${index / 4 * right}" y="177" text-anchor="${index === 0 ? 'start' : index === 4 ? 'end' : 'middle'}">${esc(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }))}</text>`;
  }).join('');
  $('balanceChart').innerHTML = `<svg viewBox="0 0 ${width} 185" preserveAspectRatio="none" role="img" aria-label="${preview ? 'Illustrative' : 'Recorded'} balance history for ${state.range}"><defs><linearGradient id="balanceFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--accent)" stop-opacity=".15"/><stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>${grid}<path d="${line} L${right},${bottom} L0,${bottom} Z" fill="url(#balanceFill)"/><path class="chart-line" d="${line}"/><circle cx="${coords.at(-1)[0]}" cy="${coords.at(-1)[1]}" r="3.5" fill="var(--accent)"/>${dates}</svg>`;
  $('balanceChart').querySelector('svg').setAttribute('aria-hidden', String(state.hidden));
}

function renderAll() { renderProfile(); renderInvestments(); renderMarkets(); renderTransactions(); renderChart(); }

async function api(path, options = {}) {
  const response = await fetch(`${window.API_BASE || '/api'}${path}`, { ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), Authorization: `Bearer ${state.user.token}` }, signal: AbortSignal.timeout(15000), cache: 'no-store' });
  if (response.status === 401) { stopSync(); location.replace('/login'); throw new Error('Session expired'); }
  if (response.status === 403) { stopSync(); location.replace('/login?reason=account-restricted'); throw new Error('Account restricted'); }
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.error || 'Account service unavailable'); }
  return response.json();
}

async function refresh() {
  if (state.refreshing) { refreshAgain = true; return; }
  const revision = walletRevision;
  state.refreshing = true; $('refreshBtn').disabled = true;
  try {
    if (preview) { renderAll(); value('syncPill', 'Preview · sample data'); return; }
    value('syncPill', 'Updating…');
    const [profile, activity, portfolio, quotes, wallets] = await Promise.allSettled([api('/users/me'), api('/transactions'), api('/investments/portfolio'), fetch(`${window.API_BASE || '/api'}/markets`, { signal: AbortSignal.timeout(15000), cache: 'no-store' }).then(response => { if (!response.ok) throw new Error('Prices unavailable'); return response.json(); }), api('/investments/wallets')]);
    state.hasRefreshed = true;
    const failures = [];
    if (profile.status === 'fulfilled' && profile.value) {
      state.user = { ...state.user, ...profile.value }; state.profileReady = true;
      try { localStorage.setItem('bs-user', JSON.stringify(state.user)); } catch {}
    } else { failures.push('Account details'); }
    if (activity.status === 'fulfilled') { state.rows = transactions(activity.value); state.transactionsReady = true; }
    else { failures.push('Transactions'); }
    state.investmentStale = portfolio.status !== 'fulfilled';
    if (portfolio.status === 'fulfilled') state.portfolio = { holdings: [], ...portfolio.value };
    else failures.push('Investment holdings');
    if (revision === walletRevision) {
      state.walletStale = wallets.status !== 'fulfilled';
      if (wallets.status === 'fulfilled') state.wallets = wallets.value;
      else failures.push('External wallets');
    }
    state.marketStale = quotes.status !== 'fulfilled';
    if (quotes.status === 'fulfilled') state.marketData = quotes.value;
    else failures.push('Market prices');
    renderAll();
    notice(failures.length ? `${failures.join(' and ')} could not be refreshed. Any previously loaded figures may be out of date. Please try again.` : '');
    value('syncPill', failures.length ? 'Update unavailable' : `Updated ${new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`);
    value('historyNote', 'Recorded transaction balances · latest 100 transactions');
  } finally {
    $('refreshBtn').disabled = false; state.refreshing = false;
    if (refreshAgain && !state.stopped) { refreshAgain = false; void refresh(); }
  }
}

async function startStream() {
  if (preview || state.stopped || !state.user?.token) return;
  try {
    const data = await api('/stream-token');
    if (!data.stream_token || state.stopped) return;
    const id = state.user.id || state.user.email || state.user.sub;
    if (!id) return;
    state.stream?.close();
    state.stream = new EventSource(`${window.API_BASE || '/api'}/stream/user/${encodeURIComponent(id)}?token=${encodeURIComponent(data.stream_token)}`);
    state.stream.onmessage = () => { void refresh(); };
    state.stream.onerror = () => {
      state.stream?.close();
      if (!state.stopped) state.reconnect = setTimeout(startStream, 15000);
    };
  } catch { /* Periodic refresh remains available when streaming is unavailable. */ }
}
function stopSync() { state.stopped = true; state.stream?.close(); clearTimeout(state.reconnect); clearInterval(state.polling); }

function wireQuickNoteUI() {
  // A page-local reminder: never included in account storage or API requests.
  let note = '';
  const input = $('quickNoteInput');
  const words = () => input.value.trim().split(/\s+/u).filter(Boolean);
  const validate = () => {
    const count = words().length;
    const tooLong = count > 12 || input.value.length > 240;
    value('quickNoteCount', count + ' / 12 words');
    input.setAttribute('aria-invalid', String(tooLong));
    value('quickNoteError', tooLong ? 'Please shorten your note to 12 words and 240 characters or fewer.' : '');
    $('quickNoteError').hidden = !tooLong;
    $('addQuickNote').disabled = !count || tooLong;
    return count > 0 && !tooLong;
  };
  const showEditor = () => {
    input.value = note;
    $('quickNoteForm').hidden = false;
    $('quickNoteDisplay').hidden = true;
    $('cancelQuickNote').hidden = !note;
    value('addQuickNote', note ? 'Update note' : 'Add note');
    validate();
  };
  const showNote = () => {
    value('quickNoteText', note);
    $('quickNoteForm').hidden = true;
    $('quickNoteDisplay').hidden = false;
  };
  input.addEventListener('input', validate);
  $('quickNoteForm').addEventListener('submit', event => {
    event.preventDefault();
    if (!validate()) { input.focus(); return; }
    note = words().join(' ');
    showNote();
    $('editQuickNote').focus();
  });
  $('editQuickNote').addEventListener('click', () => { showEditor(); input.focus(); });
  $('cancelQuickNote').addEventListener('click', () => { showNote(); input.value = note; $('editQuickNote').focus(); });
  $('clearQuickNote').addEventListener('click', () => { note = ''; value('quickNoteText', ''); showEditor(); input.focus(); });
  window.addEventListener('pagehide', () => { note = ''; value('quickNoteText', ''); showEditor(); });
  showEditor();
}

function wireUI() {
  const closeMenu = (restoreFocus = false) => {
    $('sidebar').classList.remove('active'); $('sidebarBackdrop').hidden = true;
    $('menuBtn').setAttribute('aria-expanded', 'false'); document.body.style.overflow = '';
    $('sidebar').removeAttribute('role'); $('sidebar').removeAttribute('aria-modal');
    document.querySelector('.app-shell').inert = false;
    if (restoreFocus) $('menuBtn').focus();
  };
  $('menuBtn').addEventListener('click', () => {
    if (innerWidth > 760) {
      const collapsed = document.body.classList.toggle('nav-collapsed');
      $('menuBtn').setAttribute('aria-expanded', String(!collapsed));
      return;
    }
    $('sidebar').classList.add('active'); $('sidebarBackdrop').hidden = false;
    $('menuBtn').setAttribute('aria-expanded', 'true'); document.body.style.overflow = 'hidden';
    $('sidebar').setAttribute('role', 'dialog'); $('sidebar').setAttribute('aria-modal', 'true');
    document.querySelector('.app-shell').inert = true; $('closeMenuBtn').focus();
  });
  $('closeMenuBtn').addEventListener('click', () => closeMenu(true));
  $('sidebarBackdrop').addEventListener('click', () => closeMenu(true));
  document.addEventListener('keydown', event => {
    if (!$('sidebar').classList.contains('active')) return;
    if (event.key === 'Escape') closeMenu(true);
    if (event.key === 'Tab') {
      const focusable = [...$('sidebar').querySelectorAll('a,button')].filter(el => el.getClientRects().length);
      const first = focusable[0], last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  window.addEventListener('resize', () => { closeMenu(); $('menuBtn').setAttribute('aria-expanded', String(innerWidth > 760 && !document.body.classList.contains('nav-collapsed'))); });
  $('menuBtn').setAttribute('aria-expanded', String(innerWidth > 760));
  document.querySelectorAll('.sidebar a').forEach(link => link.addEventListener('click', () => closeMenu()));
  document.querySelectorAll('.primary-nav a[href^="#"]').forEach(link => link.addEventListener('click', () => {
    document.querySelectorAll('.primary-nav a').forEach(item => { item.classList.remove('active'); item.removeAttribute('aria-current'); });
    link.classList.add('active'); link.setAttribute('aria-current', 'location');
  }));
  $('refreshBtn').addEventListener('click', refresh);
  $('privacyBtn').addEventListener('click', () => {
    state.hidden = !state.hidden; document.body.classList.toggle('privacy-hidden', state.hidden);
    $('privacyBtn').setAttribute('aria-pressed', String(state.hidden)); $('privacyBtn').setAttribute('aria-label', state.hidden ? 'Show balances' : 'Hide balances'); renderAll();
  });
  document.querySelectorAll('[data-range]').forEach(button => button.addEventListener('click', () => {
    state.range = button.dataset.range;
    document.querySelectorAll('[data-range]').forEach(item => { item.classList.toggle('selected', item === button); item.setAttribute('aria-pressed', String(item === button)); });
    renderChart();
  }));
  document.querySelectorAll('[data-asset]').forEach(button => button.addEventListener('click', () => {
    state.filter = button.dataset.asset;
    document.querySelectorAll('[data-asset]').forEach(item => { item.classList.toggle('selected', item === button); item.setAttribute('aria-pressed', String(item === button)); });
    renderInvestments();
  }));
  $('holdingsTable').addEventListener('click', event => {
    const button = event.target.closest('[data-holding]'); if (!button) return;
    const asset = activeHoldings().find(item => item.id === button.dataset.holding);
    if (!asset) return;
    showDialog(asset.name, `<div class="detail-line"><span>Asset class</span><strong>${classes[asset.category]}</strong></div><div class="detail-line"><span>Position value</span><strong>${privateValue(money(asset.value))}</strong></div><div class="detail-line"><span>Unrealized P&amp;L</span><strong>${privateValue(money(asset.pnl))}</strong></div><p class="dialog-disclaimer">${preview ? 'This is an illustrative position for the design preview.' : 'Read-only crypto balance. Estimated USD value is not an executable price or spendable bank balance. Cost basis and unrealized P&L are not supplied.'}</p>`);
  });
  wireWalletUI();
  wireQuickNoteUI();
  $('connectCoinbaseBtn').addEventListener('click', async () => {
    if (preview) { showDialog('Connect Coinbase', '<p>Sign in to link your own Coinbase account. You will authorize read-only access on Coinbase.</p>', true); return; }
    $('connectCoinbaseBtn').disabled = true;
    try { const data = await api('/investments/coinbase/connect', { method: 'POST' }); const url = new URL(data.url); if (url.origin !== 'https://login.coinbase.com' || url.pathname !== '/oauth2/auth') throw new Error('Invalid connection address'); location.assign(url.href); }
    catch (error) { showDialog('Coinbase connection', `<p>${esc(error.message)}</p>`); $('connectCoinbaseBtn').disabled = false; }
  });
  $('disconnectCoinbaseBtn').addEventListener('click', async () => {
    $('disconnectCoinbaseBtn').disabled = true;
    try { const result = await api('/investments/coinbase', { method: 'DELETE' }); state.portfolio = { status: 'disconnected', holdings: [] }; state.investmentStale = false; renderInvestments(); showDialog('Coinbase disconnected', `<p>Your Coinbase connection has been removed from Base Credit.</p><p>${result.revokeRequested ? 'You can also manage this app’s permissions in your Coinbase settings.' : 'Coinbase could not confirm the revocation request. Remove Base Credit from your Coinbase authorized applications to finish revoking access.'}</p>`); }
    catch (error) { showDialog('Unable to disconnect', `<p>${esc(error.message)}</p>`); }
    finally { $('disconnectCoinbaseBtn').disabled = false; }
  });
  for (const id of ['closeDialog', 'dismissDialog']) $(id).addEventListener('click', () => $('detailDialog').close());
  $('detailDialog').addEventListener('click', event => { if (event.target === $('detailDialog')) { const rect = $('detailDialog').getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $('detailDialog').close(); } });
  $('logoutBtn').addEventListener('click', () => {
    if (!preview) { stopSync(); localStorage.removeItem('bs-user'); localStorage.removeItem('bs-token'); }
    location.assign('/login');
  });
  if (preview) {
    document.querySelector('.brand').href = '/dashboard?preview=1';
    document.querySelectorAll('[data-banking-link]').forEach(link => link.addEventListener('click', event => {
      event.preventDefault(); showDialog('Your banking, connected.', '<p>This preview uses illustrative data. Sign in to access your accounts, transfers, transaction history, and settings.</p><p>No money can be moved from this preview.</p>', true);
    }));
  }
  window.addEventListener('pagehide', stopSync);
}

async function init() {
  value('footerYear', new Date().getFullYear());
  value('todayLabel', new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' }));
  if (preview) {
    document.body.classList.add('is-preview'); $('previewBanner').hidden = false; value('logoutLabel', 'Leave preview');
    state.user = { fullname: 'Alex Morgan', email: 'alex.morgan@example.com', available_balance: 48250.8, balances: { accounts: [{ type: 'Checking', available: 18450.8, currency: 'USD' }, { type: 'Savings', available: 29800, currency: 'USD' }] } };
    const sample = [['Salary deposit', 8500, 'credit', 'PAY-1048'], ['Online purchase', 128.5, 'debit', 'POS-2086'], ['Account transfer', 1250, 'credit', 'TRF-0932'], ['Utility payment', 186.4, 'debit', 'BILL-0764'], ['Interest payment', 320, 'credit', 'INT-0421']];
    const now = new Date();
    state.rows = sample.map(([description, amount, direction, reference], index) => ({ description, amount, direction, reference, status: 'completed', created_at: new Date(now.getFullYear(), now.getMonth(), Math.max(1, now.getDate() - index), 0).toISOString() }));
    state.profileReady = true; state.transactionsReady = true;
    value('historyNote', 'Illustrative history · USD');
  } else {
    state.user = readJson('bs-user', {}); state.user.token ||= storedToken();
    if (!state.user.token) { location.replace('/login'); return; }
    if (readJson('bs-prefs', {}).theme === 'light') document.documentElement.dataset.theme = 'light';
  }
  wireUI(); renderAll();
  await refresh();
  const outcome = new URLSearchParams(location.search).get('coinbase');
  if (!preview && outcome) {
    const messages = { connected: 'Your Coinbase connection is saved. Your crypto holdings will appear once they finish loading.', cancelled: 'You cancelled the Coinbase connection. Your accounts have not changed.', failed: 'The Coinbase connection could not be completed. Please connect again from this dashboard.', unavailable: 'Coinbase account linking is not available yet.' };
    if (outcome === 'connected' && state.portfolio?.status !== 'connected') messages.connected = 'Coinbase authorization returned, but your holdings could not be loaded. Refresh to check the connection.';
    if (messages[outcome]) showDialog('Coinbase connection', `<p>${messages[outcome]}</p>`);
    history.replaceState(null, '', '/dashboard#portfolio');
  }
  if (!preview && !state.stopped) { void startStream(); state.polling = setInterval(refresh, 60000); }
}
void init();
