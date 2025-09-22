// config.js
(function () {
  function getQueryParam(name) {
    try {
      const url = new URL(location.href);
      return url.searchParams.get(name);
    } catch {
      return null;
    }
  }

  function getMeta(name) {
    const el = document.querySelector(`meta[name="${name}"]`);
    return el?.getAttribute("content") || null;
  }

  let ApiBase = null;
  const override =
    window.BS_API_BASE || getQueryParam("api") || getMeta("api-base");

  if (override) {
    ApiBase = override.replace(/\/$/, "");
  } else {
    try {
      const origin = location.origin;
      const isFile = origin.startsWith("file:");
      const isLocalhost =
        origin.includes("localhost") || origin.includes("127.0.0.1");

      if (isFile || isLocalhost) {
        // 🖥️ Local dev
        ApiBase = "http://localhost:4000/api";
      } else if (origin.includes("shenzhenswift.online")) {
        // 🌐 Production → Render backend for your domain
        ApiBase = "https://shenzhenswift.online.onrender.com/api/";
      } else {
        // Default fallback
        ApiBase = "http://localhost:4000/api";
      }

      // Only log in non-production
      if (!origin.includes("shenzhenswift.online")) {
        console.log("🌐 API_BASE set to:", ApiBase);
      }
    } catch (err) {
      console.warn("⚠️ Config detection failed, fallback to localhost:", err);
      ApiBase = "http://localhost:4000/api";
    }
  }

  window.API_BASE = ApiBase;
})();
