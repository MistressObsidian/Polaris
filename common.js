// === Neon API Fetch Wrapper ===
const NEON_API_KEY = "napi_d1ok7sq00spa3j33sul3o5yoz15jtb74zrts8tukqvb3ofd0hkt6plfgs69brt2f"; // your Neon key

window.bsApiFetch = async function(endpoint, options = {}) {
  const url = `${window.API_BASE}${endpoint}`;

  const defaultHeaders = {
    "apikey": NEON_API_KEY,
    "Authorization": `Bearer ${NEON_API_KEY}`,
    "Content-Type": "application/json"
  };

  // Merge headers
  options.headers = { ...defaultHeaders, ...(options.headers || {}) };

  const res = await fetch(url, options);

  // Safe JSON parse (reuse helper from config.js if available)
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}

  if (!res.ok) {
    throw new Error(data.error || `API request failed (${res.status})`);
  }

  return data;
};
