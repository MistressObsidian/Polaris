// config.js
// One-origin setup
// API routes are served under /api

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
  // Example: ?api=https://polaris-uru5.onrender.com
  const override = window.BS_API_BASE || getQueryParam("api");

  function normalizeApiBase(url) {
    const base = stripTrailingSlash(url);
    return base.replace(/\/api$/i, "");
  }

  // Default API base provided for this project.
  const API_BASE = "https://polaris-uru5.onrender.com/";
  let ApiBase = normalizeApiBase(API_BASE);

  if (override) {
    ApiBase = normalizeApiBase(override);
  }

  window.API_BASE = ApiBase;

  // Safe debug log (remove if you want)
  console.log("🌐 API_BASE set to:", window.API_BASE);
})();
