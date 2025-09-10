// Safe API fetch shim that defers to config.js if present
(function () {
  // If another definition already exists (from config.js), do nothing
  if (typeof window !== "undefined" && typeof window.bsApiFetch === "function") return;

  // Try to use window.API_BASE if set by config.js; otherwise, detect
  let ApiBase = (typeof window !== "undefined" && window.API_BASE) || null;
  if (!ApiBase) {
    try {
      const origin = location.origin || "";
      const isFile = origin.startsWith("file:");
      const isLocalhost = origin.includes("localhost") || origin.includes("127.0.0.1");
      if (isFile || isLocalhost) {
        ApiBase = "http://localhost:4000/api";
      } else if (origin.includes("shenzhenswift.online")) {
        ApiBase = "https://shenzhenswift.online/api";
      } else {
        ApiBase = "http://localhost:4000/api";
      }
    } catch {
      ApiBase = "http://localhost:4000/api";
    }
  }
  if (typeof window !== "undefined") window.API_BASE = ApiBase;

  window.bsApiFetch = async function (endpoint, options = {}) {
    const url = `${ApiBase}${endpoint}`;
    const defaultHeaders = { "Content-Type": "application/json" };

    // Attach token if available
    try {
      const user = JSON.parse(localStorage.getItem("bs-user") || "null");
      if (user?.token) defaultHeaders["Authorization"] = `Bearer ${user.token}`;
    } catch {}

    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    const res = await fetch(url, options);
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch {}
    if (!res.ok) throw new Error(data.error || `API request failed (${res.status})`);
    return data;
  };
})();
