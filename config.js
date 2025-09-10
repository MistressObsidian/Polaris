// config.js
(function () {
  let ApiBase;

  // Force localhost while developing
  const isLocal =
    location.hostname === "localhost" ||
    location.hostname === "127.0.0.1" ||
    location.origin.startsWith("file:");

  if (isLocal) {
    ApiBase = "http://localhost:4000/api";
  } else {
    // Production → your deployed Express backend
    ApiBase = "https://shenzhenswift.online/api";
  }

  window.API_BASE = ApiBase;
  console.log("🌐 API_BASE set to:", ApiBase);

  // === API Fetch Wrapper (auto handles token) ===
  window.bsApiFetch = async function (endpoint, options = {}) {
    const url = `${window.API_BASE}${endpoint}`;
    const user = JSON.parse(localStorage.getItem("bs-user") || "null");

    const defaultHeaders = {
      "Content-Type": "application/json",
    };

    // Include token if available
    if (user?.token) {
      defaultHeaders["Authorization"] = `Bearer ${user.token}`;
    }

    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    const res = await fetch(url, options);

    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {}

    if (!res.ok) {
      throw new Error(data.error || `API request failed (${res.status})`);
    }

    return data;
  };
})();
