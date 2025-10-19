/*
  dashboard.js
  Defensive startup, debounced transaction reloads, and robust SSE reconnect/backoff.
  Designed to replace the inline script previously in dashboard.html.

  - Uses window.BSStorage (if present) for JSON-safe storage access.
  - Uses window.Notifications (if present) but falls back gracefully.
  - Exposes window._BS hooks for testing.
*/

(() => {
  const LOAD_TX_DEBOUNCE_MS = 250;
  const SSE_INITIAL_RETRY_MS = 1000;
  const SSE_MAX_RETRY_MS = 30000;
  const SSE_RETRY_FACTOR = 1.7;

  let user = null;
  let _loadTxTimeout = null;
  let sse = null;
  let sseRetryDelay = SSE_INITIAL_RETRY_MS;
  let sseConnected = false;

  // ---- Storage helpers (use BSStorage if available) ----
  async function safeGetJSON(key, fallback = null) {
    try {
      if (window.BSStorage && typeof window.BSStorage.getJSON === 'function') {
        return await window.BSStorage.getJSON(key, fallback);
      }
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (err) {
      console.warn('safeGetJSON parse error for', key, err);
      try { localStorage.removeItem(key); } catch {}
      return fallback;
    }
  }

  async function safeSetJSON(key, obj) {
    try {
      if (window.BSStorage && typeof window.BSStorage.setJSON === 'function') {
        return await window.BSStorage.setJSON(key, obj);
      }
      localStorage.setItem(key, JSON.stringify(obj));
    } catch (err) {
      console.warn('safeSetJSON failed', key, err);
    }
  }

  // Debounced loader for transactions to coalesce multiple triggers
  function scheduleLoadTransactions() {
    clearTimeout(_loadTxTimeout);
    _loadTxTimeout = setTimeout(async () => {
      try {
        if (typeof window.loadTransactions === 'function') {
          await window.loadTransactions();
        } else {
          console.warn('scheduleLoadTransactions: window.loadTransactions is not defined.');
        }
      } catch (err) {
        console.error('Error while loading transactions:', err);
      }
    }, LOAD_TX_DEBOUNCE_MS);
  }

  // Safe Notifications init
  function initNotifications() {
    if (window.Notifications && typeof window.Notifications.init === 'function') {
      try { window.Notifications.init(); } catch (err) { console.warn('Notifications.init failed', err); }
      return;
    }
    if ('Notification' in window && Notification.permission !== 'granted') {
      try { Notification.requestPermission().catch(() => {}); } catch (err) {}
    }
  }

  // ---- SSE (Server-Sent Events) with reconnect/backoff ----
  function getSseUrl() {
    const cfg = window.BS_CONFIG || {};
    const base = cfg.sseUrl || '/sse';
    const tokenParam = cfg.sseTokenParam || 'token';
    const token = (user && user.token) ? encodeURIComponent(user.token) : null;
    if (token) return `${base}?${tokenParam}=${token}`;
    return base;
  }

  function connectSSE() {
    if (typeof EventSource === 'undefined') {
      console.warn('SSE not supported in this environment (EventSource missing).');
      return;
    }

    const url = getSseUrl();
    if (!url) {
      console.warn('connectSSE: no SSE URL available');
      return;
    }

    if (sse) {
      try { sse.close(); } catch (e) {}
      sse = null;
      sseConnected = false;
    }

    try {
      sse = new EventSource(url, { withCredentials: false });
    } catch (err) {
      console.error('Failed to create EventSource:', err);
      scheduleSseReconnect();
      return;
    }

    sse.onopen = () => {
      console.info('SSE connected to', url);
      sseConnected = true;
      sseRetryDelay = SSE_INITIAL_RETRY_MS;
    };

    sse.onmessage = (ev) => {
      if (!ev || !ev.data) return;
      let payload = null;
      try { payload = JSON.parse(ev.data); } catch (err) { payload = ev.data; }
      try {
        if (payload && payload.type === 'transfer') {
          window.dispatchEvent(new CustomEvent('transfer-completed', { detail: payload.data }));
        } else if (payload && payload.type === 'profile.updated') {
          if (payload.data) {
            (async () => {
              const existing = await safeGetJSON('bs-user', {});
              const merged = Object.assign({}, existing || {}, payload.data);
              await safeSetJSON('bs-user', merged);
              // Notify same-window listeners manually
              window.dispatchEvent(new Event('bs-user-updated'));
            })();
          }
        } else {
          scheduleLoadTransactions();
        }
      } catch (err) {
        console.error('Error handling SSE message:', err, payload);
      }
    };

    sse.onerror = (err) => {
      if (sse && sse.readyState === EventSource.CLOSED) {
        console.warn('SSE closed — scheduling reconnect', err);
      } else {
        console.warn('SSE error', err);
      }
      try { sse.close(); } catch (_) {}
      sse = null;
      sseConnected = false;
      scheduleSseReconnect();
    };
  }

  function scheduleSseReconnect() {
    setTimeout(() => {
      sseRetryDelay = Math.min(Math.ceil(sseRetryDelay * SSE_RETRY_FACTOR), SSE_MAX_RETRY_MS);
      connectSSE();
    }, sseRetryDelay);
  }

  // ---- Storage event handling ----
  async function onStorageEvent(e) {
    try {
      if (!e) return;
      if (e.key === 'bs-user' && e.newValue) {
        const updated = safeParseJSON(e.newValue, null);
        if (updated) syncProfileToUI(updated);
      }
      if (['transfer', 'last-transfer'].includes(e.key)) {
        scheduleLoadTransactions();
      }
      if (e.key === 'bs-user' && !e.newValue) {
        window.location.href = 'login.html';
      }
    } catch (err) {
      console.error('Error in onStorageEvent handler', err);
    }
  }

  // fallback safe parse used above in onStorageEvent (string parsing only)
  function safeParseJSON(raw, fallback = null) {
    if (!raw) return fallback;
    try { return JSON.parse(raw); } catch (err) { console.warn('safeParseJSON failed', err); return fallback; }
  }

  function syncProfileToUI(profile) {
    try {
      if (typeof window.syncProfileToUI === 'function') {
        window.syncProfileToUI(profile);
        return;
      }
      const hero = document.getElementById('heroName');
      if (hero) hero.textContent = profile.fullname || profile.accountname || profile.email || '';
    } catch (err) {
      console.warn('syncProfileToUI fallback failed', err);
    }
  }

  // ---- Defensive startup ----
  async function init() {
    initNotifications();

    // Load user from BSStorage or localStorage
    try {
      user = await safeGetJSON('bs-user', null);
    } catch (err) {
      user = null;
    }

    if (!user || !user.token) {
      try { window.location.href = 'login.html'; } catch (err) {}
      return;
    }

    try {
      const heroEl = document.getElementById('heroName');
      if (heroEl) heroEl.textContent = user.fullname || user.accountname || user.email || '';
    } catch (err) {}

    try {
      if (typeof window.wireSidebar === 'function') window.wireSidebar();
    } catch (err) { console.error('wireSidebar error', err); }

    try {
      if (typeof window.loadUserProfile === 'function') {
        await window.loadUserProfile();
      }
    } catch (err) { console.error('loadUserProfile failed', err); }

    try { scheduleLoadTransactions(); } catch (err) { console.error('scheduleLoadTransactions failed', err); }

    try { if (typeof window.renderCharts === 'function') window.renderCharts(); } catch (err) { console.error('renderCharts failed', err); }

    try { connectSSE(); } catch (err) { console.error('connectSSE failed at init', err); }

    try {
      window.addEventListener('transfer-completed', scheduleLoadTransactions);
      window.addEventListener('storage', onStorageEvent);
      window.addEventListener('bs-user-updated', async () => {
        const updated = await safeGetJSON('bs-user', null);
        if (updated) syncProfileToUI(updated);
      });
    } catch (err) { console.warn('Event registration failed', err); }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    setTimeout(init, 0);
  }

  window._BS = window._BS || {};
  window._BS.connectSSE = connectSSE;
  window._BS.scheduleLoadTransactions = scheduleLoadTransactions;
  window._BS.getUserFromStorage = async () => await safeGetJSON('bs-user', null);
})();