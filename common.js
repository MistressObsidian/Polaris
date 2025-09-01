// Shared platform utilities: session + transfer sync (Neon backend)
(function (global) {
  const API_BASE = "https://app-cold-paper-96026916.dpl.myneon.app";
  const API_KEY  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aGVudGljYXRlZCIsImVtYWlsIjoieW91ckBlbWFpbC5jb20iLCJpYXQiOjE3NTY2ODc1OTYsImV4cCI6MTc1NjY5MTE5Nn0.eCyikKATDAhOJ1ukVDche9XG9N_uwxRUQQtt9PbHTyY";

  // ---------- Neon Helpers ----------
  async function neonFetch(path, options = {}) {
    const url = `${API_BASE}${path}`;
    const headers = Object.assign(
      { "Authorization": `Bearer ${API_KEY}`, "Content-Type": "application/json", "Accept": "application/json" },
      options.headers || {}
    );
    const res = await fetch(url, { ...options, headers });
    if (!res.ok) throw new Error(`Neon API ${res.status}`);
    return res.json();
  }

  // ---------- Users ----------
  async function sheetSearch(params = {}) {
    if (!params.email) return [];
    const email = encodeURIComponent(params.email);
    return await neonFetch(`/users?email=eq.${email}`);
  }

  async function sheetInsert(rows) {
    if (!Array.isArray(rows) || !rows.length) return false;
    try {
      await neonFetch(`/users`, {
        method: "POST",
        body: JSON.stringify(rows)
      });
      return true;
    } catch (err) {
      console.error("Neon insert failed", err);
      return false;
    }
  }

  async function registerUser(user) {
    if (!user || !user.email) throw new Error("Missing user/email");
    const email = user.email.toLowerCase();

    // Duplicate check
    const existing = await sheetSearch({ email });
    if (existing && existing.length) throw new Error("Email already registered");

    const row = Object.assign(
      {
        formType: "Registration",
        date: new Date().toISOString(),
        baseAvailable: 0,
        totalBalance: 0
      },
      user,
      { email }
    );

    await sheetInsert([row]);
    return row;
  }

  async function fetchUserFinancials(email) {
    if (!email) return { baseAvailable: 0, totalBalance: 0 };
    try {
      const rows = await sheetSearch({ email });
      if (rows.length > 0) {
        return {
          baseAvailable: Number(rows[0].baseavailable || 0),
          totalBalance: Number(rows[0].totalbalance || 0)
        };
      }
    } catch (e) {
      console.warn("fetchUserFinancials fallback", e);
    }
    return { baseAvailable: 0, totalBalance: 0 };
  }

  // ---------- Session ----------
  const AUTH_KEY = "bs-user";
  function getUser() {
    try { return JSON.parse(localStorage.getItem(AUTH_KEY) || "null"); }
    catch { return null; }
  }
  function setUser(u) {
    try { localStorage.setItem(AUTH_KEY, JSON.stringify(u)); }
    catch {}
  }
  function isAuthenticated() {
    const u = getUser();
    return u && u.isAuthenticated === true;
  }

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
    if (logout) logout.addEventListener("click", () => { localStorage.removeItem(AUTH_KEY); location.href="login.html"; });
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
  global.Platform = { sheetSearch, sheetInsert, registerUser, fetchUserFinancials, getUser, setUser, isAuthenticated, injectHeaderFooter, showBalanceWidget };

})(window);
