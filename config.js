// config.js
(function () {
let ApiBase;

try {
 const origin = location.origin;
 const isFile = origin.startsWith("file:");
 const isLocalhost =
   origin.includes("localhost") || origin.includes("127.0.0.1");

 if (isFile || isLocalhost) {
   // 🖥️ Local dev → Express backend on port 4000
   ApiBase = "http://localhost:4000/api";
 } else if (origin.includes("shenzhenswift.online")) {
   // 🌐 Production → your deployed backend
   ApiBase = "https://shenzhenswift.online/api";
 } else {
   // 🔄 Fallback: assume local
   ApiBase = "http://localhost:4000/api";
 }
} catch (err) {
 console.warn("⚠️ Config detection failed, fallback to localhost:", err);
 ApiBase = "http://localhost:4000/api";
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
