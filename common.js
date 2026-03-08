// Notifications client and toast UI for Base Credit
// Usage: include config.js then common.js; call window.Notifications.init() once per page.

(function(){
	if (window.BSSession) return;

	function getUser(){
		try {
			return JSON.parse(localStorage.getItem("bs-user") || "null");
		} catch {
			return null;
		}
	}

	function getToken(){
		const user = getUser();
		return user?.token || localStorage.getItem("bs-token") || "";
	}

	function clearSession(){
		localStorage.removeItem("bs-user");
		localStorage.removeItem("bs-token");
	}

	function goToLogin(){
		window.location.href = "login.html";
	}

	function onAuthRequired({ message } = {}){
		if (message && window.Notifications?.toast) {
			window.Notifications.toast({ title: "Session", body: message, type: "error" });
		}
		goToLogin();
		return { redirected: true, message: message || "Session expired. Please log in." };
	}

	window.BSSession = {
		getUser,
		getToken,
		clearSession,
		goToLogin,
		onAuthRequired,
	};
})();

(function(){
	if (window.Notifications) return; // singleton

	function getStoredToken() {
		if (window.BSSession?.getToken) return window.BSSession.getToken() || "";
		try {
			const u = JSON.parse(localStorage.getItem("bs-user") || "null");
			return u?.token || localStorage.getItem("bs-token") || "";
		} catch {
			return localStorage.getItem("bs-token") || "";
		}
	}

	window.getAuthHeaders = function () {
		const token = getStoredToken();
		return token
			? { Authorization: `Bearer ${token}` }
			: {};
	};

	function ensureToastContainer(){
		let el = document.getElementById('toast-container');
		if (!el){
			el = document.createElement('div');
			el.id = 'toast-container';
			el.style.cssText = 'position:fixed;right:12px;bottom:12px;display:flex;flex-direction:column;gap:8px;z-index:9999;max-width:min(92vw,380px)';
			document.body.appendChild(el);
		}
		return el;
	}

	function toast({ title, body, type='info' }){
		const container = ensureToastContainer();
		const card = document.createElement('div');
		card.className = 'toast-card';
		const accent = type === 'transfer' ? '#2663ff' : (type === 'error' ? '#ef4444' : '#585fc8');
		card.style.cssText = `background:#0f141d;border:1px solid #223048;border-left:3px solid ${accent};border-radius:10px;padding:.65rem .75rem;color:#e9eef5;box-shadow:0 6px 18px rgba(0,0,0,.35);display:grid;gap:.25rem;animation:toastIn .25s ease`;
		card.innerHTML = `<div style="font-weight:800;letter-spacing:.2px">${title || 'Notification'}</div><div style="font-size:.85rem;color:#cfd8e3">${body || ''}</div>`;
		container.appendChild(card);
		setTimeout(()=>{ card.style.opacity = '0'; card.style.transform = 'translateY(8px)'; setTimeout(()=> card.remove(), 220); }, 6000);
	}

	function connect(){
		return null;
	}

	async function markRead(id){
		return;
	}

	async function markAllRead(){
		return;
	}

	window.Notifications = {
		init(){
			return;
		},
		toast,
		markRead,
		markAllRead
	};
})();

(function(){
	function bindLogoutButtons(){
		const buttons = document.querySelectorAll('#logoutBtn, [data-action="logout"]');
		buttons.forEach((button) => {
			if (button.dataset.logoutBound === "1") return;
			button.dataset.logoutBound = "1";
			button.addEventListener("click", () => {
				if (window.BSSession?.clearSession) window.BSSession.clearSession();
				else {
					localStorage.removeItem("bs-user");
					localStorage.removeItem("bs-token");
				}
				if (window.BSSession?.goToLogin) window.BSSession.goToLogin();
				else window.location.href = "login.html";
			});
		});
	}

	window.bindLogoutButtons = bindLogoutButtons;
	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", bindLogoutButtons);
	} else {
		bindLogoutButtons();
	}
})();

