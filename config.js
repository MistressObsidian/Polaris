// config.js
(function () {
  let ApiBase;

  try {
    const isFile = location.origin.startsWith("file:");
    const isLocalhost =
      location.hostname === "localhost" ||
      location.hostname === "127.0.0.1";

    if (isFile) {
      // Opened directly as file:// → use local backend
      ApiBase = "http://localhost:4000/api";
    } else if (isLocalhost) {
      // Running locally in browser → use local backend
      const currentPort = location.port || "4000";
      ApiBase = `http://localhost:${currentPort}/api`;
    } else {
      // ✅ Production → your deployed backend (Express)
      ApiBase = "https://shenzhenswift.online/api";
    }
  } catch (err) {
    console.warn("Config detection failed, using fallback:", err);
    ApiBase = "http://localhost:4000/api";
  }

  window.API_BASE = ApiBase;
  console.log("🌐 API_BASE set to:", ApiBase);
})();
