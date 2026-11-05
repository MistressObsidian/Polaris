// Presentation helpers shared by the dashboard and its data-integrity checks.
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

export function money(value, currency = 'USD') {
  if (value == null || value === '' || !Number.isFinite(Number(value))) return '—';
  try { return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(Number(value)); }
  catch { return '—'; }
}

export function direction(tx) {
  // Bank amounts are often positive for both directions; the explicit direction wins.
  for (const field of [tx.direction, tx.type]) {
    const value = String(field || '').toLowerCase();
    if (['debit', 'withdrawal', 'outgoing'].includes(value)) return 'debit';
    if (['credit', 'deposit', 'incoming'].includes(value)) return 'credit';
  }
  return Number(tx.amount) < 0 ? 'debit' : 'credit';
}

export function transactions(payload) {
  const rows = Array.isArray(payload) ? payload : payload?.transactions ?? payload?.data;
  return (Array.isArray(rows) ? rows : []).filter(row => row && typeof row === 'object')
    .sort((a, b) => (Date.parse(b.created_at) || 0) - (Date.parse(a.created_at) || 0));
}

export function isPosted(tx) {
  return !tx.status || ['completed', 'complete', 'posted', 'success', 'successful', 'settled'].includes(String(tx.status).toLowerCase());
}

export function monthlyIncome(rows, now = new Date()) {
  const included = rows.filter(tx => {
    const date = new Date(tx.created_at);
    return direction(tx) === 'credit' && isPosted(tx) && date <= now &&
      date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear() && Number.isFinite(Number(tx.amount));
  });
  return { total: included.reduce((sum, tx) => sum + Math.abs(Number(tx.amount)), 0), count: included.length };
}

export function balanceHistory(rows, range = '1M', now = new Date()) {
  const days = ({ '1M': 30, '3M': 90, '6M': 180, '1Y': 365 })[range] || 30;
  const start = now.getTime() - days * 86400000;
  return rows.filter(isPosted).map(tx => ({
    date: new Date(tx.created_at),
    balance: tx.total_balance_after ?? tx.balance_after,
  })).filter(point => point.balance != null && point.balance !== '' && Number.isFinite(Number(point.balance)) &&
    point.date.getTime() >= start && point.date <= now)
    .map(point => ({ ...point, balance: Number(point.balance) }))
    .sort((a, b) => a.date - b.date);
}
