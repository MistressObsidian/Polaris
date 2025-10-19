(function () {
  const DB_NAME = 'bank-swift';
  const STORE = 'kv';
  const DB_VERSION = 1;

  function openDB() {
    return new Promise((resolve, reject) => {
      if (!('indexedDB' in window)) return resolve(null);
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = ev.target.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    });
  }

  async function idbGet(key) {
    const db = await openDB();
    if (!db) return null;
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(STORE, 'readonly');
        const s = tx.objectStore(STORE);
        const r = s.get(key);
        r.onsuccess = () => resolve(typeof r.result === 'undefined' ? null : r.result);
        r.onerror = () => resolve(null);
      } catch (err) {
        resolve(null);
      }
    });
  }

  async function idbSet(key, val) {
    const db = await openDB();
    if (!db) return;
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(STORE, 'readwrite');
        const s = tx.objectStore(STORE);
        const r = s.put(val, key);
        r.onsuccess = () => resolve();
        r.onerror = () => resolve();
      } catch (err) {
        resolve();
      }
    });
  }

  async function idbRemove(key) {
    const db = await openDB();
    if (!db) return;
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(STORE, 'readwrite');
        const s = tx.objectStore(STORE);
        const r = s.delete(key);
        r.onsuccess = () => resolve();
        r.onerror = () => resolve();
      } catch (err) {
        resolve();
      }
    });
  }

  const fallback = {
    get: (k) => Promise.resolve(localStorage.getItem(k)),
    set: (k, v) => { localStorage.setItem(k, v); return Promise.resolve(); },
    remove: (k) => { localStorage.removeItem(k); return Promise.resolve(); }
  };

  const BSStorage = {
    async get(key) {
      try {
        const v = await idbGet(key);
        if (v === null || v === undefined) return fallback.get(key);
        return v;
      } catch (err) { return fallback.get(key); }
    },
    async set(key, value) {
      try { await idbSet(key, value); } catch (err) { /* ignore */ }
      try { fallback.set(key, value); } catch (err) { /* ignore */ }
    },
    async remove(key) {
      try { await idbRemove(key); } catch (err) { /* ignore */ }
      try { fallback.remove(key); } catch (err) { /* ignore */ }
    },
    async getJSON(key, fallbackVal = null) {
      try {
        const raw = await this.get(key);
        if (raw === null || raw === undefined) return fallbackVal;
        if (typeof raw === 'object') return raw;
        return raw ? JSON.parse(raw) : fallbackVal;
      } catch (err) {
        try { await this.remove(key); } catch {}
        return fallbackVal;
      }
    },
    async setJSON(key, obj) {
      try {
        const raw = typeof obj === 'string' ? obj : JSON.stringify(obj);
        await this.set(key, raw);
      } catch (err) {
        console.warn('BSStorage.setJSON failed', err);
      }
    }
  };

  window.BSStorage = BSStorage;
})();