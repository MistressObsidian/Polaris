// Shared platform utilities: session + transfer sync (SheetDB + production API)
(function (global) {
  const API_BASE = 'https://www.shenzhenswift.online'; // production API only
  const SHEETDB_API_URL = 'https://sheetdb.io/api/v1/3g36t35kn6po0';
  const SHEETDB_API_TOKEN = 'bdqkosnudoi2kv7ilujkh192vndz3osnqkvh2mw3';

  global.API_BASE = API_BASE;
  global.SHEETDB_API_URL = SHEETDB_API_URL;
  global.SHEETDB_API_TOKEN = SHEETDB_API_TOKEN;

  // Generic API fetch with JSON handling + error swallow
  async function apiFetch(path, options = {}) {
    const url = path.startsWith('http') ? path : `${API_BASE}${path}`;
    const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    try {
      const res = await fetch(url, { ...options, headers });
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch {}
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    }
  }

  /* ---------------- SheetDB Helpers ---------------- */
  function sheetAuthHeaders(extra = {}) {
    return Object.assign({ Authorization: `Bearer ${SHEETDB_API_TOKEN}` }, extra);
  }

  async function sheetSearch(params = {}) {
    const qs = new URLSearchParams(params).toString();
    const url = `${SHEETDB_API_URL}/search?${qs}&casesensitive=false`;
    try {
      const res = await fetch(url, { headers: sheetAuthHeaders() });
      if (!res.ok) return [];
      return res.json();
    } catch { return []; }
  }

  async function sheetInsert(rows) {
    if (!Array.isArray(rows) || !rows.length) return false;
    try {
      const res = await fetch(SHEETDB_API_URL, {
        method: 'POST',
        headers: sheetAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ data: rows })
      });
      return res.ok;
    } catch { return false; }
  }

  async function sheetPatch(reference, fields) {
    if (!reference) return false;
    try {
      const payload = { data: [{ reference, ...fields }] };
      const res = await fetch(SHEETDB_API_URL, {
        method: 'PATCH',
        headers: sheetAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
      return res.ok;
    } catch { return false; }
  }

  /* ---------------- Session / Transfer Helpers ---------------- */
  function getUser() {
    try { return JSON.parse(sessionStorage.getItem('loggedInUser') || 'null'); } catch { return null; }
  }

  function shapeTransferRow(t) {
    return {
      formType: 'Transfer',
      reference: t.reference,
      email: t.email || (getUser() && getUser().email) || '',
      amount: t.amount,
      from: t.from || t.from_account || '',
      to: t.to || t.to_account || '',
      status: t.status || 'Pending',
      dateISO: t.dateISO || new Date().toISOString(),
      network: t.network || t.type || 'Transfer',
      note: t.note || ''
    };
  }

  function getLocalTransfers() {
    try {
      const arr = JSON.parse(sessionStorage.getItem('initiatedTransactions') || '[]');
      return Array.isArray(arr) ? arr : [];
    } catch { return []; }
  }

  function saveLocalTransfers(list) {
    try { sessionStorage.setItem('initiatedTransactions', JSON.stringify(list)); } catch {}
  }

  function upsertLocalTransfer(t) {
    if (!t || !t.reference) return;
    const list = getLocalTransfers();
    const i = list.findIndex(x => x.reference === t.reference);
    if (i >= 0) list[i] = { ...list[i], ...t };
    else list.push(t);
    saveLocalTransfers(list);
  }

  async function recordTransferToSheet(t) {
    if (!t || !t.reference) return;
    try {
      const existing = await sheetSearch({ formType: 'Transfer', reference: t.reference });
      if (existing.length) {
        const row = existing[0];
        if ((row.status || '') !== (t.status || '')) await sheetPatch(t.reference, { status: t.status });
        return;
      }
      await sheetInsert([shapeTransferRow(t)]);
    } catch {}
  }

  async function syncTransfer(t) {
    upsertLocalTransfer(t);
    await recordTransferToSheet(t);
  }

  global.Platform = Object.assign(global.Platform || {}, {
    API_BASE,
    SHEETDB_API_URL,
    SHEETDB_API_TOKEN,
    apiFetch,
    sheetSearch,
    sheetInsert,
    sheetPatch,
    getUser,
    getLocalTransfers,
    upsertLocalTransfer,
    saveLocalTransfers,
    recordTransferToSheet,
    syncTransfer
  });
})(window);
