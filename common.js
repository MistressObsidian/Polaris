// Shared platform utilities: session + transfer sync (Google Apps Script backend)
(function (global) {
  const API_BASE = 'disabled'; // legacy disabled
  const APPS_SCRIPT_URL = null; // removed backend

  let __sheetCache = { time:0, rows:[] };
  const CACHE_TTL_MS = 10000;

  async function fetchAllRows(){
    // Return locally stored registrations only
    try { return JSON.parse(localStorage.getItem('bs-registered-users')||'[]'); } catch { return []; }
  }

  function matchesParams(row, params){
    return Object.entries(params).every(([k,v])=>{
      if(v==null||v==='') return true;
      return String(row[k]||'').toLowerCase()===String(v).toLowerCase();
    });
  }

  async function sheetSearch(params={}){
    const all = await fetchAllRows();
    if(!params||Object.keys(params).length===0) return all.slice();
    return all.filter(r=>matchesParams(r,params));
  }

  async function sheetInsert(rows){
    // Store locally and send to Formspree (fire & forget)
    if(!Array.isArray(rows)||!rows.length) return false;
    try {
      const list = JSON.parse(localStorage.getItem('bs-registered-users')||'[]');
      rows.forEach(r=>{ if(r && r.email && !list.some(x=>x.email===r.email)) list.push(r); });
      localStorage.setItem('bs-registered-users', JSON.stringify(list));
    } catch(e) { console.warn('local sheetInsert failed', e); }
    // Silently true (demo only)
    return true;
  }

  // High-level user registration (ensures no duplicate email)
  async function registerUser(user){
    if(!user || !user.email) throw new Error('Missing user/email');
    const email=user.email.toLowerCase();
    // Duplicate check
  let existing=[];
  try { existing = await sheetSearch({ formType:'Registration', email }); }catch(e){ console.warn('[registerUser] duplicate check failed (continuing)', e); }
    if(existing && existing.length){
      throw new Error('Email already registered');
    }
    const row = Object.assign({
      formType:'Registration',
      date:new Date().toISOString(),
      baseAvailable:0,
      totalBalance:0
    }, user, { email });
  await sheetInsert([row]);
  return row;
  }

  // ---------- Session ----------
  const AUTH_KEY='bs-user';
  function getUser(){ try{ return JSON.parse(localStorage.getItem(AUTH_KEY)||'null'); }catch{return null;} }
  function setUser(u){ try{ localStorage.setItem(AUTH_KEY,JSON.stringify(u)); }catch{} }
  function isAuthenticated(){ const u=getUser(); return u && u.isAuthenticated===true; }

  // ---------- Financials ----------
  async function fetchUserFinancials(email){
    if(!email) return { baseAvailable:0,totalBalance:0 };
    try{
      const rows=await sheetSearch({ formType:'Registration', email });
      if(rows.length>0){
        return {
          baseAvailable:Number(rows[0].baseAvailable||0),
          totalBalance:Number(rows[0].totalBalance||0)
        };
      }
    }catch{}
    return { baseAvailable:0,totalBalance:0 };
  }

  // ---------- Inject Global Header/Footer ----------
  function buildLogoSVG(){
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

  function currentPage(){ try{ return (location.pathname.split('/').pop()||'').toLowerCase(); }catch{return'';} }

  function injectHeaderFooter(){
    if(document.querySelector('.app-header')) return;
    const authed=isAuthenticated();
    const page=currentPage();
    const header=document.createElement('header');
    header.className='app-header';
    // If on landing page, include marketing anchor links replicating previous UI navigation
    const isLanding = page === '' || page === 'index.html';
    const marketingAnchors = isLanding ? `
          <li><a href="#home" data-anchor="home">Home</a></li>
          <li><a href="#features" data-anchor="features">Features</a></li>
          <li><a href="#services" data-anchor="services">Services</a></li>
          <li><a href="#about" data-anchor="about" class="hide-mobile">About</a></li>
          <li><a href="#contact" data-anchor="contact" class="hide-mobile">Contact</a></li>` : '';
    header.innerHTML=`
      <nav class="app-nav ${isLanding?'landing-nav':''}">
        <a href="${page==='dashboard.html'?'dashboard.html':'index.html'}" class="app-logo"><span class="logo-icon">${buildLogoSVG()}</span><span class="brand-text">Bank Swift</span></a>
        <ul class="nav-links-shared" id="globalNavLinks">
          ${isLanding?marketingAnchors:`<li><a href="${page==='dashboard.html'?'dashboard.html':'index.html'}" data-page="${page==='dashboard.html'?'dashboard.html':'index.html'}">Home</a></li>`}
          ${authed?'<li><a href="dashboard.html" data-page="dashboard.html">Dashboard</a></li>':''}
          ${authed?'<li><a href="transfer.html" data-page="transfer.html">Transfers</a></li>':''}
          <li><a href="register.html" data-page="register.html" ${authed?'class="hidden"':''}>Register</a></li>
          <li><a href="login.html" data-page="login.html" ${authed?'class="hidden"':''}>Login</a></li>
        </ul>
        <div class="header-cta">${authed?'<button id="logoutBtn" class="btn-shared btn-outline">Logout</button>':'<a class="btn-shared btn-outline" href="login.html">Sign In</a><a class="btn-shared btn-primary-shared" href="register.html">Get Started</a>'}</div>
      </nav>`;
    document.body.prepend(header);
    header.querySelectorAll('#globalNavLinks a').forEach(a=>{ if(a.getAttribute('data-page')===page) a.classList.add('active'); });
    if(isLanding){
      // Smooth scroll for marketing anchors
      header.querySelectorAll('a[data-anchor]').forEach(a=>{
        a.addEventListener('click',e=>{
          const id=a.getAttribute('data-anchor');
          const target=document.getElementById(id);
          if(target){
            e.preventDefault();
            target.scrollIntoView({behavior:'smooth'});
          }
        });
      });
    }
    const logout=document.getElementById('logoutBtn'); if(logout){ logout.addEventListener('click',()=>{ localStorage.removeItem(AUTH_KEY); location.href='login.html'; }); }
  }

  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', injectHeaderFooter); } else { injectHeaderFooter(); }

  // ---------- Balance Widget Hook ----------
  async function showBalanceWidget(){
    const widget=document.getElementById('balanceWidget');
    const val=document.getElementById('balanceValue');
    if(widget && isAuthenticated()){
      const user=getUser();
      const f=await fetchUserFinancials(user.email);
      val.textContent=new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(f.baseAvailable||0);
      widget.style.display='block';
    }
  }
  if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', showBalanceWidget); } else { showBalanceWidget(); }

  // Export
  global.Platform={ sheetSearch, sheetInsert, registerUser, fetchUserFinancials, getUser, setUser, isAuthenticated, injectHeaderFooter, showBalanceWidget };

})(window);
