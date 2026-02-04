// config.js
// One-origin local setup (frontend + backend on http://localhost:4000)
// API is always served from /api

(function () {
  function getQueryParam(name) {
    try {
      return new URL(window.location.href).searchParams.get(name);
    } catch {
      return null;
    }
  }

  function stripTrailingSlash(url) {
    return String(url || "").replace(/\/+$/, "");
  }

  // Optional override (for debugging only)
  // Example: ?api=http://localhost:4000/api
  const override = window.BS_API_BASE || getQueryParam("api");

  // ✅ Default: SAME ORIGIN API (no CORS, no failures)
  let ApiBase = "/api";

  if (override) {
    ApiBase = stripTrailingSlash(override);
  }

  window.API_BASE = "/api";

  // Safe debug log (remove if you want)
  console.log("🌐 API_BASE set to:", window.API_BASE);
})();
