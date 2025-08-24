// Shared platform utilities: session + transfer sync (SheetDB only for production)
(function (global) {
  // Production API endpoints
  const API_BASE = 'https://www.shenzhenswift.online';
  const SHEETDB_API_URL = 'https://sheetdb.io/api/v1/3g36t35kn6po0';
  const SHEETDB_API_TOKEN = 'bdqkosnudoi2kv7ilujkh192vndz3osnqkvh2mw3';

  // Export to global
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
      try { 
        data = text ? JSON.parse(text) : null; 
      } catch {}
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
    } catch { 
      return []; 
    }
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
    } catch { 
      return false; 
    }
  }

  async function sheetPatch(reference, fields) {
    if (!reference) return false;
    try {
      // Try to update existing record
      const payload = { 
        data: [{ 
          reference, 
          ...fields 
        }] 
      };
      const res = await fetch(`${SHEETDB_API_URL}/reference/${reference}`, {
        method: 'PATCH',
        headers: sheetAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload)
      });
      
      if (res.ok) return true;
      
      // If update failed, try to insert new record
      return sheetInsert([{ 
        formType: 'Transfer',
        reference, 
        ...fields 
      }]);
    } catch { 
      return false; 
    }
  }

  /* ---------------- Session / User Helpers ---------------- */
  function getUser() {
    try { 
      return JSON.parse(sessionStorage.getItem('loggedInUser') || 'null'); 
    } catch { 
      return null; 
    }
  }

  function setUser(user) {
    try {
      sessionStorage.setItem('loggedInUser', JSON.stringify(user));
    } catch {}
  }

  function isAuthenticated() {
    const user = getUser();
    return user && user.isAuthenticated === true;
  }

  /* ---------------- Transfer Management ---------------- */
  function shapeTransferRow(t) {
    const user = getUser();
    return {
      formType: 'Transfer',
      reference: t.reference,
      email: t.email || (user && user.email) || '',
      amount: t.amount || 0,
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
    } catch { 
      return []; 
    }
  }

  function saveLocalTransfers(list) {
    try { 
      sessionStorage.setItem('initiatedTransactions', JSON.stringify(list)); 
    } catch {}
  }

  function upsertLocalTransfer(t) {
    if (!t || !t.reference) return;
    const list = getLocalTransfers();
    const i = list.findIndex(x => x.reference === t.reference);
    if (i >= 0) {
      list[i] = { ...list[i], ...t };
    } else {
      list.unshift(t); // Add new transfers at the beginning
    }
    saveLocalTransfers(list);
  }

  async function recordTransferToSheet(t) {
    if (!t || !t.reference) return false;
    try {
      // Check if exists
      const existing = await sheetSearch({ 
        formType: 'Transfer', 
        reference: t.reference 
      });
      
      if (existing.length > 0) {
        // Update existing
        const row = existing[0];
        if ((row.status || '') !== (t.status || '')) {
          return await sheetPatch(t.reference, { status: t.status });
        }
        return true;
      }
      
      // Insert new
      return await sheetInsert([shapeTransferRow(t)]);
    } catch {
      return false;
    }
  }

  async function syncTransfer(t) {
    upsertLocalTransfer(t);
    return await recordTransferToSheet(t);
  }

  async function fetchTransferByRef(ref) {
    if (!ref) return null;
    try {
      const rows = await sheetSearch({ 
        formType: 'Transfer', 
        reference: ref 
      });
      return rows[0] || null;
    } catch {
      return null;
    }
  }

  async function fetchUserTransfers(email) {
    if (!email) return [];
    try {
      const rows = await sheetSearch({ 
        formType: 'Transfer', 
        email: email 
      });
      return rows;
    } catch {
      return [];
    }
  }

  /* ---------------- User Financial Data ---------------- */
  async function fetchUserFinancials(email) {
    if (!email) return null;
    try {
      const rows = await sheetSearch({ 
        formType: 'Registration', 
        email: email 
      });
      if (rows.length > 0) {
        return {
          baseAvailable: Number(rows[0].baseAvailable || 221540.20),
          totalBalance: Number(rows[0].totalBalance || 256780.00)
        };
      }
    } catch {}
    // Return defaults if not found
    return {
      baseAvailable: 221540.20,
      totalBalance: 256780.00
    };
  }

  async function updateUserFinancials(email, financials) {
    if (!email) return false;
    try {
      const rows = await sheetSearch({ 
        formType: 'Registration', 
        email: email 
      });
      
      if (rows.length > 0) {
        // Update existing user
        const payload = {
          data: [{
            email: email,
            baseAvailable: financials.baseAvailable,
            totalBalance: financials.totalBalance
          }]
        };
        
        const res = await fetch(`${SHEETDB_API_URL}/email/${email}`, {
          method: 'PATCH',
          headers: sheetAuthHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify(payload)
        });
        
        return res.ok;
      }
    } catch {}
    return false;
  }

  /* ---------------- Unified Transfer Sync ---------------- */
  async function syncAllTransfers() {
    const user = getUser();
    if (!user || !user.email) return;
    
    try {
      // Fetch all transfers from SheetDB
      const remoteTransfers = await fetchUserTransfers(user.email);
      
      // Get local transfers
      const localTransfers = getLocalTransfers();
      
      // Merge transfers (remote takes precedence for conflicts)
      const transferMap = new Map();
      
      // Add local transfers first
      localTransfers.forEach(t => {
        if (t.reference) {
          transferMap.set(t.reference, t);
        }
      });
      
      // Override/add remote transfers
      remoteTransfers.forEach(t => {
        if (t.reference) {
          const existing = transferMap.get(t.reference);
          if (existing) {
            transferMap.set(t.reference, { ...existing, ...t });
          } else {
            transferMap.set(t.reference, t);
          }
        }
      });
      
      // Save merged list
      const mergedList = Array.from(transferMap.values());
      saveLocalTransfers(mergedList);
      
      // Push any local-only transfers to SheetDB
      for (const transfer of localTransfers) {
        const remoteExists = remoteTransfers.some(r => r.reference === transfer.reference);
        if (!remoteExists) {
          await recordTransferToSheet(transfer);
        }
      }
      
      return mergedList;
    } catch (e) {
      console.error('Sync failed:', e);
      return getLocalTransfers();
    }
  }

  /* ---------------- Balance Calculation ---------------- */
  async function calculateAvailableBalance() {
    const user = getUser();
    if (!user || !user.email) return 0;
    
    try {
      // Get user's base available balance
      const financials = await fetchUserFinancials(user.email);
      const baseAvailable = financials.baseAvailable;
      
      // Get all transfers
      const transfers = getLocalTransfers();
      
      // Calculate spent amount (only completed transfers)
      const spent = transfers
        .filter(t => t.email === user.email && String(t.status || '').toLowerCase() === 'completed')
        .reduce((sum, t) => sum + (Number(t.amount) || 0), 0);
      
      // Return available balance
      return Math.max(0, baseAvailable - spent);
    } catch {
      return 0;
    }
  }

  // Export all functions to global Platform object
  global.Platform = {
    // Constants
    API_BASE,
    SHEETDB_API_URL,
    SHEETDB_API_TOKEN,
    
    // Core utilities
    apiFetch,
    
    // SheetDB operations
    sheetSearch,
    sheetInsert,
    sheetPatch,
    sheetAuthHeaders,
    
    // User session
    getUser,
    setUser,
    isAuthenticated,
    
    // Transfer management
    getLocalTransfers,
    saveLocalTransfers,
    upsertLocalTransfer,
    recordTransferToSheet,
    syncTransfer,
    fetchTransferByRef,
    fetchUserTransfers,
    shapeTransferRow,
    
    // Financial data
    fetchUserFinancials,
    updateUserFinancials,
    calculateAvailableBalance,
    
    // Sync operations
    syncAllTransfers
  };

  // Auto-sync on page load if authenticated
  if (global.Platform.isAuthenticated()) {
    global.Platform.syncAllTransfers();
  }

})(window);