(function(global) {
// Client helper utilities for local API
const API_BASE = window.API_BASE || '/api';

function authUser(){
  const raw = localStorage.getItem('bs-user') || sessionStorage.getItem('bs-user');
  if(!raw) return null; try { return JSON.parse(raw); } catch { return null; }
}
function authToken(){ return authUser()?.token || ''; }

async function api(path, options = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json', Authorization: `Bearer ${authToken()}` }, options.headers||{});
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if(!res.ok) throw new Error(`API ${res.status}`); return res.json();
}

async function fetchUserFinancials(email){
  // Derive from transactions
  if(!email) return { baseAvailable:0, totalBalance:0 };
  try {
    const tx = await api(`/transactions?user_email=${encodeURIComponent(email)}`);
    let balance = 0; tx.forEach(t=>{ if(t.type==='credit') balance+=Number(t.amount); else if(t.type==='debit') balance-=Number(t.amount); });
    return { baseAvailable: balance, totalBalance: balance };
  } catch { return { baseAvailable:0, totalBalance:0 }; }
}

  // ---------- Session ----------
  function getUser(){ return authUser(); }
  function setUser(u){ if(u) localStorage.setItem('bs-user', JSON.stringify(u)); }
  function isAuthenticated(){ return !!authToken(); }

  // ---------- Inject Header/Footer ----------
  function buildLogoSVG() {
    return `<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><defs>
      <linearGradient id="logoGrad1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#667eea"/><stop offset="60%" stop-color="#764ba2"/><stop offset="100%" stop-color="#8b5cf6"/>
      </linearGradient>
      <linearGradient id="logoGrad2" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#06b6d4"/><stop offset="100%" stop-color="#4facfe"/>
      </linearGradient>
      <linearGradient id="logoGrad3" x1="0%" y1="100%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#f093fb" stop-opacity="0.8"/><stop offset="100%" stop-color="#f5576c" stop-opacity="0.8"/>
      </linearGradient></defs>
      <path fill="url(#logoGrad1)" d="M6 10 L34 32 L6 54 Z"/>
      <path fill="url(#logoGrad2)" d="M34 10 L58 32 L34 54 L22 44 L34 32 L22 20 Z"/>
      <path fill="url(#logoGrad3)" d="M6 10 L34 32 L22 44 L6 54 Z" opacity="0.35"/>
    </svg>`;
  }

  function currentPage() {
    try { return (location.pathname.split("/").pop() || "").toLowerCase(); }
    catch { return ""; }
  }

  function injectHeaderFooter() {
    if (document.querySelector(".app-header")) return;
    const authed = isAuthenticated();
    const page = currentPage();
    const header = document.createElement("header");
    header.className = "app-header";
    const isLanding = page === "" || page === "index.html";
    const marketingAnchors = isLanding ? `
      <li><a href="#home" data-anchor="home">Home</a></li>
      <li><a href="#features" data-anchor="features">Features</a></li>
      <li><a href="#services" data-anchor="services">Services</a></li>
      <li><a href="#about" data-anchor="about" class="hide-mobile">About</a></li>
      <li><a href="#contact" data-anchor="contact" class="hide-mobile">Contact</a></li>` : "";
    header.innerHTML = `
      <nav class="app-nav ${isLanding ? "landing-nav" : ""}">
        <a href="${page==="dashboard.html"?"dashboard.html":"index.html"}" class="app-logo"><span class="logo-icon">${buildLogoSVG()}</span><span class="brand-text">Bank Swift</span></a>
        <ul class="nav-links-shared" id="globalNavLinks">
          ${isLanding?marketingAnchors:`<li><a href="${page==="dashboard.html"?"dashboard.html":"index.html"}" data-page="${page==="dashboard.html"?"dashboard.html":"index.html"}">Home</a></li>`}
          ${authed?'<li><a href="dashboard.html" data-page="dashboard.html">Dashboard</a></li>':""}
          ${authed?'<li><a href="transfer.html" data-page="transfer.html">Transfers</a></li>':""}
          <li><a href="register.html" data-page="register.html" ${authed?'class="hidden"':""}>Register</a></li>
          <li><a href="login.html" data-page="login.html" ${authed?'class="hidden"':""}>Login</a></li>
        </ul>
        <div class="header-cta">${authed?'<button id="logoutBtn" class="btn-shared btn-outline">Logout</button>':'<a class="btn-shared btn-outline" href="login.html">Sign In</a><a class="btn-shared btn-primary-shared" href="register.html">Get Started</a>'}</div>
      </nav>`;
    document.body.prepend(header);

    header.querySelectorAll("#globalNavLinks a").forEach(a => { if (a.getAttribute("data-page")===page) a.classList.add("active"); });

    const logout = document.getElementById("logoutBtn");
  if (logout) logout.addEventListener("click", () => { localStorage.removeItem('bs-user'); sessionStorage.removeItem('bs-user'); location.href="login.html"; });
  }

  if (document.readyState==="loading") {
    document.addEventListener("DOMContentLoaded", injectHeaderFooter);
  } else {
    injectHeaderFooter();
  }

  // ---------- Balance Widget Hook ----------
  async function showBalanceWidget() {
    const widget = document.getElementById("balanceWidget");
    const val = document.getElementById("balanceValue");
    if (widget && isAuthenticated()) {
      const user = getUser();
      const f = await fetchUserFinancials(user.email);
      val.textContent = new Intl.NumberFormat("en-US", { style:"currency", currency:"USD" }).format(f.baseAvailable||0);
      widget.style.display="block";
    }
  }
  if (document.readyState==="loading") {
    document.addEventListener("DOMContentLoaded", showBalanceWidget);
  } else {
    showBalanceWidget();
  }

  // Export
  global.Platform = { fetchUserFinancials, getUser, setUser, isAuthenticated, injectHeaderFooter, showBalanceWidget };

})(window);
