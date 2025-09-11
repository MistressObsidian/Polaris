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
        // 🖥️ Local dev: Express backend
        ApiBase = "http://localhost:4000/api";
      } else {
        // 🌐 Production: always call same-origin /api (Netlify proxy will forward)
        ApiBase = `${origin}/api`;
      }
    } catch (err) {
      console.warn("⚠️ Config detection failed, fallback to localhost:", err);
      ApiBase = "http://localhost:4000/api";
    }
  }

  window.API_BASE = ApiBase;
  console.log("🌐 API_BASE set to:", ApiBase);
})();
