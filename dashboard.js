/*
  dashboard.js
  Full dashboard including hero, transactions, charts, SSE, sidebar, notifications, and loan modal.
  Cleaned + reconciled version.
*/

(() => {
  const LOAD_TX_DEBOUNCE_MS = 300;
  const SSE_RECONNECT_MS = 5000;

  let user = null;
  let _loadTxTimeout = null;
  let activeLoanId = null;
  let sseLoans = null;
  let sseTx = null;

  /* ---------------- API ---------------- */
  const API_BASE = 'https://polaris-uru5.onrender.com';

  function apiUrl(path = '') {
    const clean = `/${String(path).replace(/^\/+/, '')}`;
    return `${API_BASE}/api${clean}`;
  }

  /* ---------------- Utilities ---------------- */
  const fmt = n => `$${Number(n || 0).toFixed(2)}`;

  const safeGetJSON = (k, f = null) => {
    try { return JSON.parse(localStorage.getItem(k)) ?? f; }
    catch { return f; }
  };

  const safeSetJSON = (k, v) => {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch {}
  };

  /* ---------------- Session ---------------- */
  function getSessionToken() {
    return window.BSSession?.getToken?.() ||
           localStorage.getItem('bs-token') ||
           null;
  }

  async function resolveSessionToken() {
    const token = getSessionToken();
    if (!token) return null;

    if (!user) user = safeGetJSON('bs-user', null);
    if (user && user.token !== token) {
      user.token = token;
      safeSetJSON('bs-user', user);
    }

    window.BSSession?.setSession?.(user, token);
    return token;
  }

  async function clearSession() {
    try { window.BSSession?.clearSession?.(); } catch {}
    localStorage.removeItem('bs-token');
    safeSetJSON('bs-user', null);
    window.location.href = 'login.html';
  }

  /* ---------------- Fetch Helper ---------------- */
  async function fetchWithToken(path, options = {}) {
    const token = await resolveSessionToken();
    if (!token) return null;

    try {
      const res = await fetch(apiUrl(path), {
        ...options,
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      });

      if (res.status === 401) {
        await clearSession();
        return null;
      }

      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.error('Fetch error:', err);
      return null;
    }
  }

  /* ---------------- Bootstrap ---------------- */
  async function bootstrapSession() {
    const stored = safeGetJSON('bs-user', null);
    const token = getSessionToken() || stored?.token;
    if (!token) return null;

    user = { ...(stored || {}), token };
    safeSetJSON('bs-user', user);

    const profile = await fetchWithToken('users/me');
    if (!profile) return null;

    user = { ...profile, token };
    safeSetJSON('bs-user', user);

    syncProfileToUI(user);
    return user;
  }

  /* ---------------- Profile ---------------- */
  function syncProfileToUI(profile) {
    if (!profile) return;

    user = { ...(user || {}), ...profile };
    safeSetJSON('bs-user', user);

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    const checking = Number(profile.checking || 0);
    const savings = Number(profile.savings || 0);

    set('heroChecking', fmt(checking));
    set('heroSavings', fmt(savings));
    set('heroAvailable', fmt(checking + savings));
    set('heroName',
      profile.fullname ||
      profile.accountname ||
      profile.email ||
      'User'
    );

    const pill = document.getElementById('syncPill');
    if (pill) pill.textContent = 'Sync — ' + new Date().toLocaleTimeString();
  }

  async function loadUserProfile() {
    const profile = await fetchWithToken('users/me');
    if (profile) syncProfileToUI(profile);
  }

  /* ---------------- Transactions ---------------- */
  async function loadTransactions() {
    const rows = await fetchWithToken('transactions');
    const tbody = document.getElementById('transactionsTable');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!Array.isArray(rows) || !rows.length) {
      tbody.innerHTML =
        `<tr><td colspan="5" style="text-align:center;opacity:.6">
          No transactions yet
        </td></tr>`;
      return;
    }

    rows.slice(0, 10).forEach(tx => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${tx.created_at ? new Date(tx.created_at).toLocaleDateString() : '—'}</td>
        <td>${tx.description || (tx.type === 'credit' ? 'Credit' : 'Debit')}</td>
        <td>${tx.reference || tx.id || '—'}</td>
        <td class="${tx.type === 'credit' ? 'amount-positive' : 'amount-negative'}">
          ${tx.type === 'credit' ? '+' : '-'}${fmt(tx.amount)}
        </td>
        <td>${fmt(tx.total_balance_after)}</td>
      `;
      tr.onclick = () => {
        safeSetJSON('last-transfer', tx);
        window.location.href = 'transactions.html';
      };
      tbody.appendChild(tr);
    });
  }

  function scheduleLoadTransactions() {
    clearTimeout(_loadTxTimeout);
    _loadTxTimeout = setTimeout(loadTransactions, LOAD_TX_DEBOUNCE_MS);
  }

  /* ---------------- Charts ---------------- */
  function renderCharts() {
    if (!window.Chart) return;

    new Chart(document.getElementById('spendingChart'), {
      type: 'line',
      data: {
        labels: ['Apr','May','Jun','Jul','Aug','Sep'],
        datasets: [{
          data: [1200,950,1350,1100,1400,1250],
          borderColor: '#ef4444',
          fill: true
        }]
      },
      options: { plugins:{ legend:{ display:false } } }
    });

    new Chart(document.getElementById('savingsChart'), {
      type: 'bar',
      data: {
        labels: ['Apr','May','Jun','Jul','Aug','Sep'],
        datasets: [{
          data: [2000,2500,2800,3200,3500,4000],
          backgroundColor: '#10b981'
        }]
      },
      options: { plugins:{ legend:{ display:false } } }
    });
  }

  /* ---------------- Loans ---------------- */
  async function loadLoansAndUI() {
    const loans = await fetchWithToken('loans');
    if (!loans) return;

    const latest = loans[0];
    activeLoanId = latest?.id || null;

    const badge = document.getElementById('loanBadge');
    const payBtn = document.getElementById('payFeeBtn');

    if (!latest) return;

    badge.textContent = latest.status || 'Pending';
    badge.className = `badge ${latest.status}`;

    payBtn.style.display =
      latest.status === 'processing_fee_required'
        ? 'inline-block'
        : 'none';
  }

  /* ---------------- Loan Modal ---------------- */
  function initLoanModal() {
    const modal = document.getElementById('loanModal');
    const applyBtn = document.getElementById('applyLoanBtn');
    const closeBtn = document.getElementById('closeLoanModal');
    const submitBtn = document.getElementById('submitLoan');
    const payBtn = document.getElementById('payFeeBtn');

    applyBtn?.addEventListener('click', () => modal.classList.remove('hidden'));
    closeBtn?.addEventListener('click', () => modal.classList.add('hidden'));

    submitBtn?.addEventListener('click', async () => {
      const amount = Number(document.getElementById('loanAmount').value);
      const term = Number(document.getElementById('loanTerm').value);

      if (!amount || !term) return alert('Enter amount and term');

      await fetchWithToken('loans', {
        method: 'POST',
        body: JSON.stringify({ amount, term_months: term })
      });

      modal.classList.add('hidden');
      await loadLoansAndUI();
    });

    payBtn?.addEventListener('click', async () => {
      if (!activeLoanId) return;

      payBtn.disabled = true;
      payBtn.textContent = 'Processing...';

      await fetchWithToken(`loans/${activeLoanId}/pay-fee`, {
        method: 'POST'
      });

      payBtn.disabled = false;
      payBtn.textContent = 'Pay Processing Fee';
      await loadLoansAndUI();
    });
  }

  /* ---------------- SSE ---------------- */
  function connectSSE() {
    if (!user?.token || typeof EventSource !== 'function') return;

    if (sseLoans) sseLoans.close();
    if (sseTx) sseTx.close();

    const loanUrl = new URL(apiUrl('stream/loans'));
    loanUrl.searchParams.set('token', user.token);

    const txUrl = new URL(apiUrl('stream/transactions'));
    txUrl.searchParams.set('token', user.token);

    sseLoans = new EventSource(loanUrl);
    sseTx = new EventSource(txUrl);

    sseLoans.onmessage = loadLoansAndUI;
    sseTx.onmessage = scheduleLoadTransactions;

    sseLoans.onerror = sseTx.onerror = () => {
      sseLoans?.close();
      sseTx?.close();
      setTimeout(connectSSE, SSE_RECONNECT_MS);
    };
  }

  /* ---------------- Sidebar ---------------- */
  function wireSidebar() {
    const sidebar = document.getElementById('sidebar');
    const btn = document.getElementById('menuBtn');
    if (!sidebar || !btn) return;

    btn.onclick = e => {
      e.stopPropagation();
      sidebar.classList.toggle('active');
    };

    document.onclick = e => {
      if (sidebar.classList.contains('active') &&
          !sidebar.contains(e.target) &&
          e.target !== btn) {
        sidebar.classList.remove('active');
      }
    };
  }

  /* ---------------- Init ---------------- */
  async function init() {
    user = await bootstrapSession();
    if (!user?.token) return;

    wireSidebar();
    renderCharts();
    initLoanModal();
    scheduleLoadTransactions();
    await loadLoansAndUI();
    connectSSE();
  }

  document.addEventListener('DOMContentLoaded', init);

})();