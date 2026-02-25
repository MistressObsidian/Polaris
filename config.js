window.API_BASE = window.location.origin;

try {
	const rawUser = localStorage.getItem("bs-user");
	const storedToken = localStorage.getItem("bs-token") || "";
	let user = null;

	try {
		user = rawUser ? JSON.parse(rawUser) : null;
	} catch {
		user = null;
	}

	const userToken = user?.token || "";
	const sessionToken = userToken || storedToken;

	if (sessionToken) {
		if (!storedToken) localStorage.setItem("bs-token", sessionToken);
		if (user && !user.token) {
			user.token = sessionToken;
			localStorage.setItem("bs-user", JSON.stringify(user));
		}
	}

	if (localStorage.getItem("token") != null) {
		localStorage.removeItem("token");
	}
} catch {}