/*
  dashboard.js
  Full dashboard including hero, transactions, charts, SSE, sidebar, notifications, and loan modal.
*/

(() => {
  const LOAD_TX_DEBOUNCE_MS = 250;
  const SSE_INITIAL_RETRY_MS = 1000;
  const SSE_MAX_RETRY_MS = 30000;
  const SSE_RETRY_FACTOR = 1.7;
  const AUTH_REDIRECT_DELAY_MS = 2500;

  let user = null;
  let _loadTxTimeout = null;
  let sse = null;
  let sseRetryDelay = SSE_INITIAL_RETRY_MS;

  // ---- Storage helpers ----
  async function safeGetJSON(key, fallback = null) {
    try {
      if (window.BSStorage?.getJSON) return await window.BSStorage.getJSON(key, fallback);
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch { try { localStorage.removeItem(key); } catch {} return fallback; }
  }

  async function safeSetJSON(key, obj) {
    try {
      if (window.BSStorage?.setJSON) return await window.BSStorage.setJSON(key, obj);
      localStorage.setItem(key, JSON.stringify(obj));
    } catch {}
  }

  async function extractApiErrorMessage(res, fallback = 'Unauthorized') {
    if (!res) return fallback;
    try {
      const text = await res.text();
      if (!text) return fallback;
      try {
        const data = JSON.parse(text);
        return data?.error || data?.message || fallback;
      } catch {
        return text;
      }
    } catch {
      return fallback;
    }
  }

  async function handleUnauthorized(res, source) {
    const details = await extractApiErrorMessage(res, 'Unauthorized');
    const message = `Unauthorized (${source}): ${details}. Redirecting to login...`;
    console.error(message);
    await clearSession();
    setTimeout(() => { window.location.href = 'login.html'; }, AUTH_REDIRECT_DELAY_MS);
  }

  function safeGetStorageValue(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  function safeSetStorageValue(key, value) {
    try {
      if (value === null || value === undefined || value === '') localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch {}
  }

  function getSessionTokenFromStorage() {
    return safeGetStorageValue('bs-token') || null;
  }

  function persistSessionToken(token) {
    if (!token) return;
    safeSetStorageValue('bs-token', token);
  }

  async function resolveSessionToken() {
    const token = user?.token || getSessionTokenFromStorage();
    if (!token) return null;

    if (!user) {
      user = await safeGetJSON('bs-user', null);
    }

    if (user && !user.token) {
      user.token = token;
      await safeSetJSON('bs-user', user);
    }

    persistSessionToken(token);
    return token;
  }

  async function clearSession() {
    await safeSetJSON('bs-user', null);
    safeSetStorageValue('bs-token', null);
  }

  async function bootstrapSession() {
    const storedUser = await safeGetJSON('bs-user', null);
    const fallbackToken = getSessionTokenFromStorage();
    const sessionToken = storedUser?.token || fallbackToken;

    if (!sessionToken) return null;

    if (storedUser?.token) {
      persistSessionToken(storedUser.token);
      return storedUser;
    }

    if (storedUser && !storedUser.token) {
      const merged = Object.assign({}, storedUser, { token: sessionToken });
      await safeSetJSON('bs-user', merged);
      persistSessionToken(sessionToken);
      return merged;
    }

    try {
      const res = await fetch(`/api/users/me`, {
        headers: { Authorization: `Bearer ${sessionToken}` }
      });
      if (!res.ok) {
        if (res.status === 401) await clearSession();
        return null;
      }
      const profile = await res.json();
      const hydrated = Object.assign({}, profile || {}, { token: sessionToken });
      await safeSetJSON('bs-user', hydrated);
      persistSessionToken(sessionToken);
      return hydrated;
    } catch {
      return null;
    }
  }

  // ---- Hero sync ----
  function fmt(n) {
    return `$${Number(n || 0).toFixed(2)}`;
  }

  function syncProfileToUI(profile) {
    if (!profile) return;
    try {
      const merged = Object.assign({}, user || {}, profile || {});
      user = merged;
      safeSetJSON('bs-user', merged);
    } catch {}
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    const checking = Number(profile.checking || 0);
    const savings = Number(profile.savings || 0);
    const available = checking + savings;
    set('heroChecking', `$${checking.toFixed(2)}`);
    set('heroSavings', `$${savings.toFixed(2)}`);
    set('heroAvailable', `$${available.toFixed(2)}`);
    set('heroName', profile.fullname || profile.accountname || profile.email || '');
    const syncPill = document.getElementById('syncPill');
    if (syncPill) syncPill.textContent = 'Sync — ' + new Date().toLocaleTimeString();
  }

  async function loadUserProfile() {
    const token = await resolveSessionToken();
    if (!token) return;
    try {
      const res = await fetch(`/api/users/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.status === 401) {
        await handleUnauthorized(res, '/api/users/me');
        return;
      }
      const profile = await res.json();
      if (!res.ok) throw new Error(profile?.error || 'Failed to load profile');
      syncProfileToUI(profile);
    } catch (err) {
      console.error('Profile load error:', err);
    }
  }

  async function loadTransactions() {
    const token = await resolveSessionToken();
    if (!token) return;
    try {
      const res = await fetch(`/api/transactions`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.status === 401) {
        await handleUnauthorized(res, '/api/transactions');
        return;
      }

      const txRows = await res.json();
      const tbody = document.getElementById('transactionsTable');
      if (!tbody) return;
      tbody.innerHTML = '';

      if (!Array.isArray(txRows) || !txRows.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;opacity:.6">No transactions yet</td></tr>`;
        return;
      }

      txRows.slice(0, 10).forEach((tx) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
        <td>${tx.created_at ? new Date(tx.created_at).toLocaleDateString() : '—'}</td>
        <td>${tx.description || (tx.type === 'credit' ? 'Credit' : 'Debit')}</td>
        <td>${tx.reference || tx.id || '—'}</td>
        <td class="${tx.type === 'credit' ? 'amount-positive' : 'amount-negative'}">
          ${tx.type === 'credit' ? '+' : '-'}$${Number(tx.amount || 0).toFixed(2)}
        </td>
        <td>$${Number(tx.total_balance_after ?? tx.balance_after ?? 0).toFixed(2)}</td>`;

        tr.addEventListener('click', () => {
          try {
            localStorage.setItem('last-transfer', JSON.stringify(tx));
          } catch {}
          window.location.href = 'transactions.html';
        });

        tbody.appendChild(tr);
      });
    } catch (err) {
      console.error('Transaction load error:', err);
    }
  }

  function renderCharts() {
    const spendingCanvas = document.getElementById('spendingChart');
    const savingsCanvas = document.getElementById('savingsChart');
    if (!window.Chart || !spendingCanvas || !savingsCanvas) return;

    const spendingCtx = spendingCanvas.getContext('2d');
    if (spendingCtx) {
      new Chart(spendingCtx, {
        type: 'line',
        data: {
          labels: ['Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'],
          datasets: [{
            label: 'Monthly Spending',
            data: [1200, 950, 1350, 1100, 1400, 1250],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239,68,68,.15)',
            fill: true,
            tension: .35,
            pointRadius: 2
          }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#1f2530' } }, y: { grid: { color: '#1f2530' } } } }
      });
    }

    const savingsCtx = savingsCanvas.getContext('2d');
    if (savingsCtx) {
      new Chart(savingsCtx, {
        type: 'bar',
        data: {
          labels: ['Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'],
          datasets: [{
            label: 'Savings Balance',
            data: [2000, 2500, 2800, 3200, 3500, 4000],
            backgroundColor: '#10b981'
          }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#1f2530' } }, y: { grid: { color: '#1f2530' } } } }
      });
    }
  }

  // ---- Transactions ----
  function scheduleLoadTransactions() {
    clearTimeout(_loadTxTimeout);
    _loadTxTimeout = setTimeout(async () => {
      if (typeof window.loadTransactions === 'function') {
        try { await window.loadTransactions(); } catch (err) { console.error(err); }
      }
    }, LOAD_TX_DEBOUNCE_MS);
  }

  // ---- Loan helpers ----
  function calculateLoan(P, annualRate, months) {
    const r = annualRate / 100 / 12;
    return (P * r * Math.pow(1 + r, months)) / (Math.pow(1 + r, months) - 1);
  }

  let activeLoanId = null;

  async function loadLoansAndUI() {
    const token = await resolveSessionToken();
    if (!token) return;
    try {
      const res = await fetch(`/api/loans`, { headers: { Authorization: `Bearer ${token}` } });
      const loans = await res.json();
      const latest = Array.isArray(loans) && loans[0] ? loans[0] : null;

      const badge = document.getElementById("loanBadge");
      const amountEl = document.getElementById("loanAmountText");
      const aprEl = document.getElementById("loanAprText");
      const monthlyEl = document.getElementById("loanMonthlyText");
      const payBtn = document.getElementById("payFeeBtn");

      if (latest) {
        activeLoanId = latest.id;
        const amount = Number(latest.amount || 0);
        const apr = Number(latest.apr_estimate || 8.5);
        const months = Number(latest.term_months || 12);
        const monthly = latest.monthly_payment_estimate || calculateLoan(amount, apr, months);

        amountEl.textContent = `Amount: $${amount.toLocaleString()}`;
        aprEl.textContent = `APR: ${apr}%`;
        monthlyEl.textContent = `Monthly: $${monthly.toFixed(2)}`;

        const status = String(latest.status || 'pending').toLowerCase();
        badge.className = `badge ${status}`;
        badge.textContent = status.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());

        payBtn.style.display = status === 'processing_fee_required' ? 'inline-block' : 'none';
        payBtn.disabled = false;
      } else {
        activeLoanId = null;
        badge.className = 'badge pending';
        badge.textContent = 'Pending Review';
        amountEl.textContent = 'Amount: $5,000';
        aprEl.textContent = 'APR: 8.5%';
        monthlyEl.textContent = 'Monthly: $416.66';
        payBtn.style.display = 'none';
      }

      // Update loan history container
      const container = document.getElementById("loanStatusContainer");
      if (container) {
        container.innerHTML = '';
        Array.isArray(loans) && loans.forEach(l => {
          const div = document.createElement('div');
          div.className = 'loan-card glass-card';
          div.innerHTML = `<h3>Loan $${l.amount}</h3><span class="badge ${l.status}">${String(l.status || "pending").replace("_", " ").toUpperCase()}</span>`;
          container.appendChild(div);
        });
      }

    } catch (err) { console.error('loadLoansAndUI error', err); }
  }

  // ---- Loan modal logic ----
  function initLoanModal() {
    const modal = document.getElementById("loanModal");
    const applyBtn = document.getElementById("applyLoanBtn");
    const closeBtn = document.getElementById("closeLoanModal");
    const submitBtn = document.getElementById("submitLoan");
    const amountInput = document.getElementById("loanAmount");
    const termInput = document.getElementById("loanTerm");
    const preview = document.getElementById("loanPreview");
    const payBtn = document.getElementById("payFeeBtn");

    if (applyBtn && modal) applyBtn.addEventListener("click", () => modal.classList.remove("hidden"));
    if (closeBtn && modal) closeBtn.addEventListener("click", () => modal.classList.add("hidden"));

    function updatePreview() {
      const P = Number(amountInput.value);
      const months = Number(termInput.value);
      if (!P || !months) return preview.innerHTML = '';
      const payment = calculateLoan(P, 8.5, months);
      preview.innerHTML = `<p>APR: 8.5%</p><p>Estimated Monthly: $${payment.toFixed(2)}</p>`;
    }

    amountInput?.addEventListener("input", updatePreview);
    termInput?.addEventListener("input", updatePreview);

    submitBtn?.addEventListener("click", async () => {
      const amount = amountInput.value;
      const term = termInput.value;
      if (!amount || !term) return alert("Enter amount and term");
      const token = await resolveSessionToken();
      if (!token) {
        alert("Session expired. Please login again.");
        window.location.href = 'login.html';
        return;
      }

      try {
        await fetch(`/api/loans`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ amount, term_months: term })
        });
        alert("Loan application submitted for review.");
        modal.classList.add("hidden");
        await loadLoansAndUI();
      } catch (err) {
        console.error(err);
        alert("Failed to submit loan.");
      }
    });

    payBtn?.addEventListener("click", async () => {
      if (!activeLoanId) return;
      const token = await resolveSessionToken();
      if (!token) {
        alert("Session expired. Please login again.");
        window.location.href = 'login.html';
        return;
      }
      payBtn.disabled = true; payBtn.textContent = "Processing...";
      try {
        await fetch(`/api/loans/${activeLoanId}/pay-fee`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` }
        });
        await loadLoansAndUI();
      } catch (err) { console.error(err); payBtn.disabled = false; payBtn.textContent = "Pay Processing Fee"; }
    });
  }

  // ---- SSE ----
  function getSseUrl() {
    return '';
  }

  function connectSSE() {
    return;
  }

  // ---- Notifications ----
  function initNotifications() {
    if (window.Notifications?.init) { try { window.Notifications.init(); } catch {} return; }
    if ('Notification' in window && Notification.permission !== 'granted') {
      try { Notification.requestPermission().catch(() => {}); } catch {}
    }
  }

  // ---- Sidebar ----
  function wireSidebar() {
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.getElementById('menuBtn');
    if (!sidebar || !menuBtn) return;
    menuBtn.addEventListener('click', e => { e.stopPropagation(); sidebar.classList.toggle('active'); });
    document.addEventListener('click', e => { if (!sidebar.classList.contains('active')) return; if (!sidebar.contains(e.target) && e.target!==menuBtn) sidebar.classList.remove('active'); });
    document.querySelectorAll('.nav-link').forEach(a=>a.addEventListener('click',()=>sidebar.classList.remove('active')));
    document.addEventListener('keydown', e=>{if(e.key==='Escape') sidebar.classList.remove('active');});
  }

  // ---- Init ----
  async function init() {
    initNotifications();
    user = await bootstrapSession();
    if (!user?.token) return window.location.href = 'login.html';

    try { wireSidebar(); } catch {}
    try { if (window.loadUserProfile) await window.loadUserProfile(); } catch {}
    try { scheduleLoadTransactions(); } catch {}
    try { if (window.renderCharts) window.renderCharts(); } catch {}
    try { connectSSE(); } catch {}
    try { initLoanModal(); } catch {}

    window.addEventListener('transfer-completed', scheduleLoadTransactions);
    window.addEventListener('storage', async e => {
      if (!e) return;
      if (e.key==='bs-user' && e.newValue) syncProfileToUI(JSON.parse(e.newValue));
      if (['transfer','last-transfer'].includes(e.key)) scheduleLoadTransactions();
      if (e.key==='bs-user' && !e.newValue) {
        user = await bootstrapSession();
        if (!user?.token) window.location.href='login.html';
      }
    });
    window.addEventListener('bs-user-updated', async ()=>syncProfileToUI(await safeGetJSON('bs-user', null)));
    await loadLoansAndUI();
  }

  if (document.readyState==='loading') document.addEventListener('DOMContentLoaded', init);
  else setTimeout(init,0);

  // ---- Expose hooks ----
  window._BS = window._BS || {};
  window.loadUserProfile = loadUserProfile;
  window.loadTransactions = loadTransactions;
  window.renderCharts = renderCharts;
  window._BS.connectSSE = connectSSE;
  window._BS.scheduleLoadTransactions = scheduleLoadTransactions;
  window._BS.getUserFromStorage = async ()=>await safeGetJSON('bs-user',null);
  window._BS.syncProfileToUI = syncProfileToUI;
  window._BS.loadLoansAndUI = loadLoansAndUI;
})();
