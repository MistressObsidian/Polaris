// === Bank Swift API Fetch Wrapper ===
const API_BASE = "https://shenzhenswift.online/api"; // Your backend

window.bsApiFetch = async function(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const defaultHeaders = { "Content-Type": "application/json" };

  // 🔑 Auto-attach token if user is logged in
  try {
    const user = JSON.parse(localStorage.getItem("bs-user") || "{}");
    if (user.token) {
      defaultHeaders["Authorization"] = `Bearer ${user.token}`;
    }
  } catch (e) {
    console.warn("Token parse error", e);
  }

  // Merge headers
  options.headers = { ...defaultHeaders, ...(options.headers || {}) };

  const res = await fetch(url, options);

  // Parse safely
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}

  if (!res.ok) {
    throw new Error(data.error || `API request failed (${res.status})`);
  }

  return data;
};
