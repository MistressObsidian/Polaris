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

  // Use same-origin by default
  const API_BASE = override || window.location.origin;

  window.API_BASE = "/api";

  console.log("🌐 API_BASE set to:", window.API_BASE);
})();