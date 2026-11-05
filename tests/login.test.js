import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

const html = readFileSync(new URL("../frontend/login.html", import.meta.url), "utf8");
const code = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];

function mount({ status = 200, data, search = "" } = {}) {
  const storage = new Map();
  const requests = [];
  const elements = new Map();
  const window = { location: { href: "/login", search } };
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", disabled: false, type: "password",
      classList: { add() {}, remove() {} }, listeners: {},
      addEventListener(event, handler) { this.listeners[event] = handler; },
    });
    return elements.get(id);
  }
  runInNewContext(code, {
    window, URLSearchParams,
    document: {
      getElementById: element,
      addEventListener(event, handler) { if (event === "DOMContentLoaded") handler(); },
    },
    localStorage: {
      getItem: key => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, String(value)),
      removeItem: key => storage.delete(key),
    },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(data) };
    },
    console: { error() {} },
  });
  return { window, storage, element, requests,
    async submit() {
      element("email").value = "test@example.invalid";
      element("password").value = "test-password";
      await element("loginForm").listeners.submit({ preventDefault() {} });
    },
  };
}

test("server-confirmed admin credentials automatically open the admin page", async () => {
  const admin = { email: "test@example.invalid", role: "admin" };
  const page = mount({ data: { token: "admin-test-token", admin } });
  page.storage.set("bs-token", "old-customer-token");
  page.storage.set("bs-user", "{}");
  await page.submit();
  assert.equal(page.window.location.href, "/admin");
  assert.equal(page.storage.get("bs-admin-token"), "admin-test-token");
  assert.deepEqual(JSON.parse(page.storage.get("bs-admin-meta")), admin);
  assert.equal(page.storage.has("bs-token"), false);
  assert.equal(page.storage.has("bs-user"), false);
  assert.deepEqual(page.requests.map(({ url }) => url), ["/api/login"]);
});

test("customers keep their own dashboard and never receive an admin session", async () => {
  const page = mount({ data: { token: "customer-test-token", email: "test@example.invalid" } });
  page.storage.set("bs-admin-token", "stale-admin-token");
  page.storage.set("bs-admin-meta", "{}");
  await page.submit();
  assert.equal(page.window.location.href, "/dashboard");
  assert.equal(page.storage.get("bs-token"), "customer-test-token");
  assert.equal(page.storage.has("bs-admin-token"), false);
  assert.equal(page.storage.has("bs-admin-meta"), false);
});

for (const status of [401, 403, 429, 500]) {
  test(`HTTP ${status} preserves the login error without admin fallback`, async () => {
    const page = mount({ status, data: { error: "Login rejected" } });
    await page.submit();
    assert.equal(page.window.location.href, "/login");
    assert.equal(page.element("loginAlert").textContent, "Login rejected");
    assert.equal(page.element("loginBtn").disabled, false);
    assert.equal(page.requests.length, 1);
    assert.equal(page.storage.size, 0);
  });
}

test("expired admin sessions receive an explanation on the shared login page", () => {
  const page = mount({ search: "?reason=admin-session-expired" });
  assert.match(page.element("loginAlert").textContent, /admin session has expired/);
  assert.equal(page.requests.length, 0);
});

test("logout confirmation is displayed on the shared login page", () => {
  const page = mount({ search: "?reason=signed-out" });
  assert.equal(page.element("loginAlert").textContent, "You have been signed out.");
});

test("a duplicate submit cannot send a second sign-in request", async () => {
  const page = mount({ data: { token: "customer-test-token", email: "test@example.invalid" } });
  await Promise.all([page.submit(), page.submit()]);
  assert.equal(page.requests.length, 1);
});
