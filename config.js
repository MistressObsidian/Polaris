window.API_BASE = window.location.origin;

if (typeof window.BS_AUTO_AUTH_REDIRECT === "undefined") {
	window.BS_AUTO_AUTH_REDIRECT = false;
}

(function () {
	const USER_KEY = "bs-user";
	const TOKEN_KEY = "bs-token";

	function shouldAutoRedirect() {
		return window.BS_AUTO_AUTH_REDIRECT === true;
	}

	function goToLogin() {
		window.location.href = "login.html";
	}

	function onAuthRequired(options = {}) {
		const message = String(options.message || "Session expired");
		if (shouldAutoRedirect()) {
			goToLogin();
			return { redirected: true, message };
		}
		return { redirected: false, message };
	}

	function readUser() {
		try {
			const raw = localStorage.getItem(USER_KEY);
			return raw ? JSON.parse(raw) : null;
		} catch {
			return null;
		}
	}

	function writeUser(user) {
		try {
			if (!user) localStorage.removeItem(USER_KEY);
			else localStorage.setItem(USER_KEY, JSON.stringify(user));
		} catch {}
	}

	function readToken() {
		try {
			return localStorage.getItem(TOKEN_KEY) || "";
		} catch {
			return "";
		}
	}

	function writeToken(token) {
		try {
			if (!token) localStorage.removeItem(TOKEN_KEY);
			else localStorage.setItem(TOKEN_KEY, token);
		} catch {}
	}

	function getToken() {
		const user = readUser();
		const userToken = user?.token || "";
		const storedToken = readToken();
		return userToken || storedToken;
	}

	function getUser() {
		const user = readUser();
		const token = getToken();
		if (!token) return null;
		if (!user) return { token };
		if (user.token === token) return user;
		const merged = Object.assign({}, user, { token });
		writeUser(merged);
		return merged;
	}

	function setSession(userLike, tokenLike) {
		const token = String(tokenLike || userLike?.token || "").trim();
		if (!token) return false;

		const nextUser = userLike
			? Object.assign({}, userLike, { token })
			: Object.assign({}, readUser() || {}, { token });

		writeToken(token);
		writeUser(nextUser);
		return true;
	}

	function clearSession() {
		writeUser(null);
		writeToken("");
	}

	function authHeaders(extraHeaders = {}) {
		const token = getToken();
		if (!token) return Object.assign({}, extraHeaders);
		return Object.assign({}, extraHeaders, { Authorization: `Bearer ${token}` });
	}

	window.BSSession = {
		USER_KEY,
		TOKEN_KEY,
		getToken,
		getUser,
		setSession,
		clearSession,
		authHeaders,
		shouldAutoRedirect,
		goToLogin,
		onAuthRequired
	};

	try {
		const token = getToken();
		if (token) setSession(readUser(), token);
		if (localStorage.getItem("token") != null) localStorage.removeItem("token");
	} catch {}
})();