// Notifications client and toast UI for Bank Swift
// Usage: include config.js then common.js; call window.Notifications.init() once per page.

(function(){
	if (window.Notifications) return; // singleton

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
		try{
			const user = JSON.parse(localStorage.getItem('bs-user')||'null');
			if (!user || !user.token) return null;
			const url = window.API_BASE.replace(/\/api$/, '') + `/api/stream/notifications?token=${encodeURIComponent(user.token)}`;
			const es = new EventSource(url);
			es.onmessage = (ev) => {
				try{
					const data = JSON.parse(ev.data);
					toast({ title: data.title, body: data.body, type: data.type });
					// track last id
					if (ev.lastEventId) localStorage.setItem('last-notif-id', String(ev.lastEventId));
				}catch{}
			};
			es.addEventListener('ping', ()=>{});
			es.onerror = ()=> { es.close(); setTimeout(connect, 7000); };
			return es;
		} catch { return null; }
	}

	async function markRead(id){
		const user = JSON.parse(localStorage.getItem('bs-user')||'null');
		if (!user || !user.token) return;
		await fetch(`${window.API_BASE}/notifications/read`,{ method:'POST', headers:{ 'Content-Type':'application/json', Authorization: `Bearer ${user.token}` }, body: JSON.stringify({ id }) });
	}

	async function markAllRead(){
		const user = JSON.parse(localStorage.getItem('bs-user')||'null');
		if (!user || !user.token) return;
		await fetch(`${window.API_BASE}/notifications/read-all`,{ method:'POST', headers:{ Authorization: `Bearer ${user.token}` } });
	}

	window.Notifications = {
		init(){
			connect();
		},
		toast,
		markRead,
		markAllRead
	};
})();

