/*
  dashboard.js
  Full dashboard including hero, transactions, charts, SSE, sidebar, notifications, and loan modal.
  Supports real-time updates and cross-tab session sync.
*/

(() => {
  const LOAD_TX_DEBOUNCE_MS = 300;
  const SSE_RECONNECT_MS = 5000;

  let user = null;
  let _loadTxTimeout = null;
  let activeLoanId = null;
  let sseLoans = null;
  let sseTx = null;

  // ---- API Helpers ----
  const API_ORIGIN = 'https://polaris-uru5.onrender.com';

  function apiUrl(path = '') {
    const normalizedPath = `/${String(path || '').replace(/^\/+/, '')}`;
    const apiPath = /^\/api(\/|$)/i.test(normalizedPath) ? normalizedPath : `/api${normalizedPath}`;
    return `${API_ORIGIN}${apiPath}`;
  }

  // ------------------- Utilities -------------------
  function fmt(n) { return `$${Number(n || 0).toFixed(2)}`; }

  function safeGetJSON(key, fallback = null) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch { return fallback; }
  }

  function safeSetJSON(key, obj) {
    try { localStorage.setItem(key, JSON.stringify(obj)); } catch {}
  }

  // ------------------- Session Management -------------------
  function getSessionTokenFromStorage() {
    return window.BSSession?.getToken?.() || localStorage.getItem('bs-token') || null;
  }

  async function resolveSessionToken() {
    const token = getSessionTokenFromStorage();
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
    if (window.BSSession?.clearSession) {
      try { window.BSSession.clearSession(); } catch {}
    }
    safeSetJSON('bs-user', null);
    localStorage.removeItem('bs-token');
    user = null;
    window.location.href = 'login.html';
  }

  // ------------------- API Fetch Helper -------------------
  async function fetchWithToken(path, options = {}) {
    const token = await resolveSessionToken();
    if (!token) return null;

    const headers = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers
    };

    try {
      const res = await fetch(apiUrl(path), { ...options, headers });
      if (!res.ok) {
        if (res.status === 401) await clearSession();
        return null;
      }
      return await res.json();
    } catch (err) {
      console.error('Fetch error:', err);
      return null;
    }
  }

  // ------------------- Session Bootstrap -------------------
  async function bootstrapSession() {
    const storedUser = safeGetJSON('bs-user', null);
    const token = getSessionTokenFromStorage() || storedUser?.token;
    if (!token) return null;

    user = { ...(storedUser || {}), token };
    safeSetJSON('bs-user', user);
    window.BSSession?.setSession?.(user, token);

    const profile = await fetchWithToken('/api/users/me');
    if (!profile) return null;

    user = { ...profile, token };
    safeSetJSON('bs-user', user);
    window.BSSession?.setSession?.(user, token);

    syncProfileToUI(user);
    return user;
  }

  // ------------------- Profile Sync -------------------
  function syncProfileToUI(profile) {
    if (!profile) return;
    user = { ...(user || {}), ...profile };
    safeSetJSON('bs-user', user);

    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    const checking = Number(profile.checking || 0);
    const savings = Number(profile.savings || 0);

    setText('heroChecking', fmt(checking));
    setText('heroSavings', fmt(savings));
    setText('heroAvailable', fmt(checking + savings));
    setText('heroName', profile.fullname || profile.accountname || profile.email || '');

    const syncPill = document.getElementById('syncPill');
    if (syncPill) syncPill.textContent = 'Sync — ' + new Date().toLocaleTimeString();
  }

  // ------------------- Load User Profile (Manual Refresh) -------------------
  async function loadUserProfile() {
    const profile = await fetchWithToken('/api/users/me');
    if (profile) syncProfileToUI(profile);
  }
  // ------------------- Transactions -------------------
  async function loadTransactions() {
    const txRows = await fetchWithToken('/api/transactions');
    const tbody = document.getElementById('transactionsTable');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (!Array.isArray(txRows) || !txRows.length) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;opacity:.6">No transactions yet</td></tr>`;
      return;
    }

    txRows.slice(0, 10).forEach(tx => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${tx.created_at ? new Date(tx.created_at).toLocaleDateString() : '—'}</td>
        <td>${tx.description || (tx.type === 'credit' ? 'Credit' : 'Debit')}</td>
        <td>${tx.reference || tx.id || '—'}</td>
        <td class="${tx.type === 'credit' ? 'amount-positive' : 'amount-negative'}">
          ${tx.type === 'credit' ? '+' : '-'}$${Number(tx.amount || 0).toFixed(2)}
        </td>
        <td>$${Number(tx.total_balance_after || 0).toFixed(2)}</td>
      `;
      tr.addEventListener('click', () => {
        safeSetJSON('last-transfer', tx);
        window.location.href = 'transactions.html';
      });
      tbody.appendChild(tr);
    });
  }

  function scheduleLoadTransactions() {
    clearTimeout(_loadTxTimeout);
    _loadTxTimeout = setTimeout(loadTransactions, LOAD_TX_DEBOUNCE_MS);
  }

  // ---- Charts ----
  function renderCharts() {
    const spendingCanvas = document.getElementById('spendingChart');
    const savingsCanvas = document.getElementById('savingsChart');
    if (!window.Chart || !spendingCanvas || !savingsCanvas) return;

    new Chart(spendingCanvas.getContext('2d'), {
      type:'line', data:{labels:['Apr','May','Jun','Jul','Aug','Sep'], datasets:[{label:'Monthly Spending', data:[1200,950,1350,1100,1400,1250], borderColor:'#ef4444', backgroundColor:'rgba(239,68,68,.15)', fill:true, tension:.35, pointRadius:2}]},
      options:{responsive:true, plugins:{legend:{display:false}}, scales:{x:{grid:{color:'#1f2530'}},y:{grid:{color:'#1f2530'}}}}
    });

    new Chart(savingsCanvas.getContext('2d'), {
      type:'bar', data:{labels:['Apr','May','Jun','Jul','Aug','Sep'], datasets:[{label:'Savings Balance', data:[2000,2500,2800,3200,3500,4000], backgroundColor:'#10b981'}]},
      options:{responsive:true, plugins:{legend:{display:false}}, scales:{x:{grid:{color:'#1f2530'}},y:{grid:{color:'#1f2530'}}}}
    });
  }

  // ------------------- Loans -------------------
  function calculateLoan(P, annualRate = 8.5, months = 12) {
    const r = annualRate / 100 / 12;
    return (P * r * Math.pow(1 + r, months)) / (Math.pow(1 + r, months) - 1);
  }

  function getLoanStatusMeta(rawStatus) {
    const status = String(rawStatus || 'pending').toLowerCase();
    const labelByStatus = {
      pending: 'Pending Review',
      under_review: 'Under Review',
      processing_fee_required: 'Processing Fee Required',
      approved: 'Approved',
      rejected: 'Rejected',
      paid: 'Paid'
    };
    return { className: status, label: labelByStatus[status] || 'Pending Review' };
  }

  async function loadLoansAndUI() {
    const loans = await fetchWithToken('/api/loans');
    if (!loans) return;

    const latest = loans[0] || null;
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

      const statusMeta = getLoanStatusMeta(latest.status);
      badge.className = `badge ${statusMeta.className}`;
      badge.textContent = statusMeta.label;

      payBtn.style.display = statusMeta.className === 'processing_fee_required' ? 'inline-block' : 'none';
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

    const container = document.getElementById("loanStatusContainer");
    if (container) {
      container.innerHTML = '';
      loans.forEach(l => {
        const s = getLoanStatusMeta(l.status);
        const div = document.createElement('div');
        div.className = 'loan-card glass-card';
        div.innerHTML = `<h3>Loan $${l.amount}</h3><span class="badge ${s.className}">${s.label}</span>`;
        container.appendChild(div);
      });
    }
  }

  // ------------------- Loan Modal -------------------
  function initLoanModal() {
    const modal = document.getElementById("loanModal");
    if (!modal) return;

    const applyBtn = document.getElementById("applyLoanBtn");
    const closeBtn = document.getElementById("closeLoanModal");
    const submitBtn = document.getElementById("submitLoan");
    const amountInput = document.getElementById("loanAmount");
    const termInput = document.getElementById("loanTerm");
    const preview = document.getElementById("loanPreview");
    const payBtn = document.getElementById("payFeeBtn");

    applyBtn?.addEventListener("click", () => modal.classList.remove("hidden"));
    closeBtn?.addEventListener("click", () => modal.classList.add("hidden"));

    function updatePreview() {
      const P = Number(amountInput.value), months = Number(termInput.value);
      if (!P || !months) return preview.innerHTML = '';
      const payment = calculateLoan(P, 8.5, months);
      preview.innerHTML = `<p>APR: 8.5%</p><p>Estimated Monthly: $${payment.toFixed(2)}</p>`;
    }

    amountInput?.addEventListener("input", updatePreview);
    termInput?.addEventListener("input", updatePreview);

    submitBtn?.addEventListener("click", async () => {
      const amount = Number(amountInput.value), term = Number(termInput.value);
      if (!amount || !term) return alert("Enter amount and term");
      const token = await resolveSessionToken();
      if (!token) { alert("Session expired"); return; }

      try {
        await fetch(apiUrl('/loans'), {
          method: 'POST',
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ amount, term_months: term })
        });
        alert("Loan application submitted for review.");
        modal.classList.add("hidden");
        await loadLoansAndUI();
      } catch (err) { console.error(err); alert("Failed to submit loan."); }
    });

    payBtn?.addEventListener("click", async () => {
      if (!activeLoanId) return;
      const token = await resolveSessionToken();
      if (!token) { alert("Session expired"); return; }

      payBtn.disabled = true; payBtn.textContent = "Processing...";
      try {
        await fetch(apiUrl(`/api/loans/${activeLoanId}/pay-fee`), { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
        await loadLoansAndUI();
      } catch (err) { console.error(err); }
      payBtn.disabled = false; payBtn.textContent = "Pay Processing Fee";
    });
  }

  // ------------------- SSE -------------------
  function connectSSE() {
    const token = user?.token;
    if (!token || typeof EventSource !== 'function') return;

    // Loans SSE
    try {
      const url = new URL(apiUrl('/api/stream/loans'));
      url.searchParams.set('token', token);
      sseLoans = new EventSource(url);
      sseLoans.onmessage = async e => { await loadLoansAndUI(); };
      sseLoans.onerror = e => { sseLoans.close(); setTimeout(connectSSE, SSE_RECONNECT_MS); };
    } catch (err) { console.error('Loan SSE connection failed', err); }

    // Transactions SSE
    try {
      const url = new URL(apiUrl('/api/stream/transactions'));
      url.searchParams.set('token', token);
      sseTx = new EventSource(url);
      sseTx.onmessage = async e => { await loadTransactions(); };
      sseTx.onerror = e => { sseTx.close(); setTimeout(connectSSE, SSE_RECONNECT_MS); };
    } catch (err) { console.error('Tx SSE connection failed', err); }
  }

  // ---- Sidebar & Hero ----
  function wireSidebar(){ const sidebar=document.getElementById('sidebar'), menuBtn=document.getElementById('menuBtn'); if(!sidebar||!menuBtn)return; menuBtn.addEventListener('click',e=>{e.stopPropagation(); sidebar.classList.toggle('active');}); document.addEventListener('click',e=>{if(!sidebar.classList.contains('active'))return; if(!sidebar.contains(e.target)&&e.target!==menuBtn) sidebar.classList.remove('active');}); document.querySelectorAll('.nav-link').forEach(a=>a.addEventListener('click',()=>sidebar.classList.remove('active'))); document.addEventListener('keydown',e=>{if(e.key==='Escape')sidebar.classList.remove('active');}); }
  function wireHeroActions(){ const makeTransferBtn=document.getElementById('makeTransferBtn'); makeTransferBtn?.addEventListener('click',()=>{window.location.href='transfer.html';}); }

  // ---- Notifications ----
  function initNotifications(){ if('Notification' in window&&Notification.permission!=='granted'){ try{ Notification.requestPermission().catch(()=>{}); }catch{} } }

  // ---- Init ----
  async function init(){
    initNotifications();
    user=await bootstrapSession();
    if(!user?.token){window.location.href='login.html'; return;}
    try{wireSidebar();}catch{}
    try{wireHeroActions();}catch{}
    try{await loadUserProfile();}catch{}
    try{scheduleLoadTransactions();}catch{}
    try{renderCharts();}catch{}
    try{connectSSE();}catch{}
    try{initLoanModal();}catch{}
    window.addEventListener('transfer-completed',scheduleLoadTransactions);
    window.addEventListener('storage',async e=>{
      if(!e) return;
      if(e.key==='bs-user'&&e.newValue) syncProfileToUI(JSON.parse(e.newValue));
      if(['transfer','last-transfer'].includes(e.key)) scheduleLoadTransactions();
      if(e.key==='bs-user'&&!e.newValue){user=await bootstrapSession(); if(!user?.token) window.location.href='login.html';}
    });
    window.addEventListener('bs-user-updated',()=>syncProfileToUI(safeGetJSON('bs-user',null)));
    await loadLoansAndUI();
  }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init);
  else setTimeout(init,0);

})();