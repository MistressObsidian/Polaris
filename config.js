// config.js
(function () {
  function getQueryParam(name) {
    try {
      return new URL(window.location.href).searchParams.get(name);
    } catch {
      return null;
    }
  }

  const override = window.BS_API_BASE || getQueryParam("api");

  // Use same-origin by default and normalize to avoid /api/api in callers
  const rawBase = (override || window.location.origin || "").trim();
  const API_BASE = rawBase
    .replace(/\/+$/, "")
    .replace(/\/api$/, "");

  window.API_BASE = API_BASE;

  console.log("🌐 API_BASE set to:", window.API_BASE);
})();