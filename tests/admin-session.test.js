import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext, Script } from "node:vm";

const html = readFileSync(new URL("../frontend/admin.html", import.meta.url), "utf8");
const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
new Script(script, { filename: "frontend/admin.html" });
// Run the actual page functions without auto-booting or exercising unrelated
// money/email actions. Rendering is covered by the live browser smoke test.
const functions = script.slice(0, script.indexOf('    els.createUserForm.addEventListener'));
assert.ok(functions.length > 1000, "admin page initialization boundary must exist");

function response(status, data = {}) {
  return { status, ok: status >= 200 && status < 300, text: async () => JSON.stringify(data) };
}

function mount({ stored = { "bs-admin-token": "test-admin-token", "bs-admin-meta": "{}" }, respond } = {}) {
  const storage = new Map(Object.entries(stored));
  const requests = [];
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => {
    const classes = new Set();
    return [id, {
      textContent: "", innerHTML: "", value: "", disabled: false, dataset: {}, style: {},
      classList: { toggle(name, force) { if (force) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    }];
  }));
  const window = { API_BASE: "/api", location: { href: "/admin", replace(url) { this.href = url; } } };
  const page = runInNewContext(functions + `
    let renderCount = 0;
    renderAll = () => { renderCount += 1; renderTemplateValidation(); };
    ({ api, boot, loadDashboard, handleLogout, handleTemplatesSave, handleManualTemplateSave,
       state, get renderCount() { return renderCount; } });`, {
    window,
    document: { getElementById: id => elements.get(id) || null, querySelectorAll: () => [] },
    localStorage: {
      getItem: key => storage.get(key) || null,
      setItem: (key, value) => storage.set(key, String(value)),
      removeItem: key => storage.delete(key),
    },
    AbortSignal: { timeout: () => undefined },
    setTimeout: callback => { callback(); return 1; },
    fetch: async (path, options) => {
      requests.push({ path, options });
      if (respond) return respond(path, options, requests);
      return response(200, path.includes("overview") ? { stats: {}, users: [] } : {});
    },
  });
  return { page, storage, requests, elements, window };
}

test("admin visitors without a session go to the regular login without API requests", async () => {
  const app = mount({ stored: {} });
  await app.page.boot();
  assert.equal(app.window.location.href, "/login");
  assert.equal(app.requests.length, 0);
});

test("a saved admin session opens the dashboard without another sign-in form", async () => {
  const app = mount();
  await app.page.boot();
  assert.equal(app.window.location.href, "/admin");
  assert.equal(app.page.renderCount, 1);
  assert.equal(app.elements.get("adminShell").classList.contains("hidden"), false);
  assert.equal(app.requests.length, 2);
  assert.ok(app.requests.every(({ options }) => options.headers.Authorization === "Bearer test-admin-token"));
  assert.ok(!html.includes('id="adminPassword"'));
});

test("a transient read failure is retried once while keeping the admin session", async () => {
  let overviewAttempts = 0;
  const app = mount({ respond: path => {
    if (path.includes("overview") && ++overviewAttempts === 1) return response(500, { error: "Server error" });
    return response(200, path.includes("overview") ? { stats: {}, users: [] } : {});
  } });
  await app.page.boot();
  assert.equal(overviewAttempts, 2);
  assert.equal(app.storage.get("bs-admin-token"), "test-admin-token");
  assert.equal(app.page.renderCount, 1);
});

for (const failure of ["server", "network"]) {
  test(`persistent ${failure} errors leave the session intact and show a refresh option`, async () => {
    const app = mount({ respond: () => {
      if (failure === "network") throw new TypeError("Failed to fetch");
      return response(500, { error: "Server error" });
    } });
    await app.page.boot();
    assert.equal(app.storage.get("bs-admin-token"), "test-admin-token");
    assert.equal(app.storage.get("bs-admin-meta"), "{}");
    assert.equal(app.window.location.href, "/admin");
    assert.equal(app.requests.length, 4);
    assert.match(app.elements.get("globalStatus").textContent, /still signed in.*Refresh/);
    assert.equal(app.elements.get("refreshBtn").disabled, false);
  });
}

for (const status of [401, 403]) {
  test(`HTTP ${status} clears the invalid session and redirects to regular login`, async () => {
    const app = mount({ respond: () => response(status, { error: "Unauthorized" }) });
    await app.page.boot();
    assert.equal(app.storage.has("bs-admin-token"), false);
    assert.equal(app.storage.has("bs-admin-meta"), false);
    assert.equal(app.window.location.href, "/login?reason=admin-session-expired");
    assert.equal(app.requests.length, 2, "auth failures must not be retried");
    assert.equal(app.page.renderCount, 0);
  });
}

test("a template service failure cannot block the main admin dashboard or overwrite templates", async () => {
  const app = mount({ respond: path => path.includes("email-templates")
    ? response(503, { error: "Unavailable" }) : response(200, { stats: {}, users: [] }) });
  await app.page.boot();
  assert.equal(app.page.renderCount, 1);
  assert.equal(app.page.state.templatesLoaded, false);
  assert.equal(app.elements.get("templatesSaveBtn").disabled, true);
  assert.equal(app.elements.get("manualEmailSaveTemplateBtn").disabled, true);
  assert.match(app.elements.get("globalStatus").textContent, /Dashboard loaded/);
  const count = app.requests.length;
  await app.page.handleTemplatesSave({ preventDefault() {} });
  await app.page.handleManualTemplateSave();
  assert.equal(app.requests.length, count, "unloaded templates must not be saved");
});

for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
  test(`failed ${method} actions are never automatically replayed`, async () => {
    const app = mount({ respond: () => response(500, { error: "Server error" }) });
    await assert.rejects(app.page.api("/api/admin/test-action", { method }), /Server error/);
    assert.equal(app.requests.length, 1);
    assert.equal(app.storage.has("bs-admin-token"), true);
  });
}

test("logout clears only the admin session and returns to the regular login", () => {
  const app = mount();
  app.page.handleLogout();
  assert.equal(app.storage.has("bs-admin-token"), false);
  assert.equal(app.storage.has("bs-admin-meta"), false);
  assert.equal(app.window.location.href, "/login?reason=signed-out");
});

test("Refresh can recover a failed dashboard load without signing in again", async () => {
  let healthy = false;
  const app = mount({ respond: path => healthy
    ? response(200, path.includes("overview") ? { stats: {}, users: [] } : {})
    : response(500, { error: "Server error" }) });
  await app.page.boot();
  assert.equal(app.page.renderCount, 0);
  healthy = true;
  await app.page.loadDashboard();
  assert.equal(app.page.renderCount, 1);
  assert.equal(app.storage.get("bs-admin-token"), "test-admin-token");
  assert.match(app.elements.get("globalStatus").textContent, /Dashboard refreshed/);
});

test("rate limiting does not invalidate a session or trigger more requests", async () => {
  const app = mount({ respond: () => response(429, { error: "Too many requests" }) });
  await assert.rejects(app.page.api("/api/admin/overview"), /Too many requests/);
  assert.equal(app.requests.length, 1);
  assert.equal(app.storage.has("bs-admin-token"), true);
});

test("shared customer logout code does not also bind the admin logout button", () => {
  const buttonMarkup = html.match(/<button\b[^>]*id="logoutBtn"[^>]*>/)[0];
  const button = {
    dataset: { logoutBound: buttonMarkup.match(/data-logout-bound="([^"]+)"/)?.[1] },
    addEventListener() { assert.fail("customer logout must not bind the admin button"); },
  };
  const common = readFileSync(new URL("../frontend/common.js", import.meta.url), "utf8");
  const binder = common.slice(common.lastIndexOf("(function(){"));
  runInNewContext(binder, {
    window: {}, document: { readyState: "complete", querySelectorAll: () => [button] },
  });
});
