// config.js
(function () {
  function getQueryParam(name) {
    try {
      const url = new URL(location.href);
      return url.searchParams.get(name);
    } catch { return null; }
  }

  function getMeta(name) {
    const el = document.querySelector(`meta[name="${name}"]`);
    return el?.getAttribute("content") || null;
  }

  let ApiBase = null;
  const override = window.BS_API_BASE || getQueryParam("api") || getMeta("api-base");

  if (override) {
    ApiBase = override.replace(/\/$/, "");
  } else {
    try {
      const origin = location.origin;
      const isFile = origin.startsWith("file:");
      const isLocalhost = origin.includes("localhost") || origin.includes("127.0.0.1");

      if (isFile || isLocalhost) {
        ApiBase = "http://localhost:4000/api";
      } else if (origin.includes("shenzhenswift.online")) {
        ApiBase = "https://shenzhenswift.online/api";
      } else {
        // Default to same-origin /api for production-like hosts
        ApiBase = `${origin}/api`;
      }
    } catch (err) {
      console.warn("⚠️ Config detection failed, fallback to localhost:", err);
      ApiBase = "http://localhost:4000/api";
    }
  }

  window.API_BASE = ApiBase;
  console.log("🌐 API_BASE set to:", ApiBase);

  // === API Fetch Wrapper (auto handles token) ===
  window.bsApiFetch = async function (endpoint, options = {}) {
    const ep = String(endpoint || "");
    const base = String(window.API_BASE || "").replace(/\/$/, "");
    const path = ep.startsWith("/") ? ep : `/${ep}`;
    const url = `${base}${path}`;

    const user = JSON.parse(localStorage.getItem("bs-user") || "null");

    const defaultHeaders = { "Content-Type": "application/json" };
    if (user?.token) defaultHeaders["Authorization"] = `Bearer ${user.token}`;
    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    const res = await fetch(url, options);
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch {}

    if (!res.ok) {
      const hint = data?.error ? `: ${data.error}` : "";
      console.error("API error", { status: res.status, url, body: options.body, response: text?.slice(0, 300) });
      throw new Error(`API request failed (${res.status})${hint}`);
    }
    return data;
  };
})();
