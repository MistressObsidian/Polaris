window.API_BASE = window.location.origin;

try {
	if (localStorage.getItem("token") != null) {
		localStorage.removeItem("token");
	}
} catch {}