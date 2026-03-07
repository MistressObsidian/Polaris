// config.js

(function () {
  const isLocal =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  // Local development
  if (isLocal) {
    window.BACKEND_ORIGIN = "http://localhost:4000";
  } 
  // Production (Render)
  else {
    window.BACKEND_ORIGIN = "https://polaris-uru5.onrender.com";
  }

  // API base
  window.API_BASE = "/api";

  window.resolveUserId = function (userId) {
    return String(userId || "").trim();
  };
})();