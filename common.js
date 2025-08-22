// Shared platform utilities: user session, transfers sync (API + SheetDB fallback)
// Assumptions: API server at localhost:3001, SheetDB base URL constant reused across pages.
(function(global){
  const API_BASE = 'http://localhost:3001';
  const SHEETDB_API_URL = 'https://sheetdb.io/api/v1/3g36t35kn6po0';
  function getApiToken(){ return localStorage.getItem('api_token') || ''; }
  function getUser(){ try { return JSON.parse(sessionStorage.getItem('loggedInUser')||''); } catch { return null; } }

  // --- Sheet helpers ---
  async function sheetSearch(params){
    const qs = new URLSearchParams(params).toString();
    const url = `${SHEETDB_API_URL}/search?${qs}&casesensitive=false`;
    const res = await fetch(url);
    if(!res.ok) return [];
    return res.json();
  }
  async function sheetInsert(rows){
    if(!Array.isArray(rows) || !rows.length) return false;
    try{ const res = await fetch(SHEETDB_API_URL, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ data: rows }) }); return res.ok; }catch{ return false; }
  }
  async function sheetPatch(reference, fields){
    // Best-effort update: attempt PATCH (if supported); fallback to new row insert (may duplicate but keeps latest status visible)
    try {
      const payload = { data: [{ reference, ...fields }] };
      const res = await fetch(SHEETDB_API_URL, { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
      if(res.ok) return true;
    } catch {}
    try { return sheetInsert([{ formType:'Transfer', reference, ...fields }]); } catch { return false; }
  }

  function shapeRow(t){
    return {
      formType: 'Transfer',
      reference: t.reference,
      email: t.email || (getUser() && getUser().email) || '',
      amount: t.amount,
      from: t.from || t.from_account || '',
      to: t.to || t.to_account || '',
      status: t.status || 'Pending',
      dateISO: t.dateISO || new Date().toISOString(),
      network: t.type || t.network || 'Transfer'
    };
  }

  async function recordTransferToSheet(t){
    try { if(!t || !t.reference) return; const existing = await sheetSearch({ formType:'Transfer', reference: t.reference }); if(Array.isArray(existing) && existing.length){
      // If status changed, attempt patch
      const row = existing[0];
      if(row.status !== t.status){ await sheetPatch(t.reference, { status: t.status }); }
      return;
    }
    await sheetInsert([shapeRow(t)]); } catch {}
  }

  async function syncTransferToSheet(t){
    if(!t || !t.reference) return; return recordTransferToSheet(t); }

  async function fetchTransfersUnified(filter={}){
    const token = getApiToken();
    try { const qs = new URLSearchParams(filter).toString(); if(token){ const res = await fetch(`${API_BASE}/api/transfers${qs?`?${qs}`:''}`, { headers:{ Authorization:`Bearer ${token}` } }); if(res.ok){ const list = await res.json(); return list; } } } catch {}
    try { const params = { formType:'Transfer' }; if(filter.email) params.email = filter.email; if(filter.ref) params.reference = filter.ref; const rows = await sheetSearch(params); return rows.map(r => ({ reference: r.reference, email: r.email, amount: Number(r.amount||0), from: r.from, to: r.to, status: r.status, dateISO: r.dateISO, type: r.network || 'Transfer', source: 'sheet' })); } catch { return []; }
  }
  async function fetchTransferByRef(reference){ if(!reference) return null; const list = await fetchTransfersUnified({ ref: reference }); return list.find(t => t.reference === reference) || null; }

  // Expose
  global.Platform = Object.assign(global.Platform||{}, { getUser, getApiToken, recordTransferToSheet, syncTransferToSheet, fetchTransfersUnified, fetchTransferByRef });
})(window);
