// config.js

(function () {
  const isLocal =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  // The Cloudflare Worker is the single public origin in production.
  // API calls stay same-origin, so there is no Render/BaseCrypto dependency.
  window.BACKEND_ORIGIN = isLocal ? "http://localhost:4000" : window.location.origin;
  window.API_BASE = "/api";

  window.resolveUserId = function (userId) {
    return String(userId || "").trim();
  };
})();