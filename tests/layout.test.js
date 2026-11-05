import { after, before, describe, mock, test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import dotenv from "dotenv";
import express from "express";

const root = new URL("../", import.meta.url);

describe("organized project layout", () => {
  let server;
  let origin;

  before(async () => {
    // Node's test runner isolates this file in its own process. Never load real
    // credentials or allow the startup warmup to connect to external services.
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: "",
      SENDGRID_API_KEY: "",
      ADMIN_USER: "",
      ADMIN_PASS: "",
      JWT_SECRET: "layout-test-only-secret",
      APP_BASE_URL: "http://127.0.0.1",
    });
    globalThis.__POLARIS_WORKER__ = false;
    mock.method(dotenv, "config", () => ({ parsed: {} }));
    // Exercise Node's real static hosting, without binding its configured port.
    mock.method(express.application, "listen", () => undefined);
    const { app } = await import("../src/server.js");
    server = createServer(app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    origin = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) {
      const closed = new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
      });
      server.closeAllConnections();
      await closed;
    }
    mock.restoreAll();
  });

  test("package and Worker entry points resolve to the organized source", () => {
    const pkg = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));
    assert.equal(pkg.main, "src/server.js");
    const config = readFileSync(new URL("wrangler.jsonc", root), "utf8");
    const main = config.match(/"main"\s*:\s*"([^"]+)"/)[1];
    assert.equal(main, "src/worker.js");
    for (const file of [pkg.main, main, "src/bank.js", "src/utils/mailer.js",
      "scripts/db/migrate-db.js", "scripts/db/new-migration.js",
      "scripts/cloudflare/worker-admin.mjs"]) {
      assert.ok(existsSync(new URL(file, root)), `${file} must exist`);
    }
    assert.match(config, /"directory"\s*:\s*"\.\/frontend"/);
    assert.match(config, /"run_worker_first"\s*:\s*\["\/api\/\*"\]/);
  });

  for (const [route, file] of [
    ["/", "index.html"],
    ["/login", "login.html"],
    ["/admin", "admin.html"],
    ["/ui.css", "ui.css"],
    ["/assets/favicon-base-credit.svg", "assets/favicon-base-credit.svg"],
  ]) {
    test(`serves ${route} from frontend`, async () => {
      const response = await fetch(`${origin}${route}`);
      assert.equal(response.status, 200);
      assert.equal(await response.text(), readFileSync(new URL(`frontend/${file}`, root), "utf8"));
    });
  }

  test("legacy page URLs preserve their query when redirected", async () => {
    const response = await fetch(`${origin}/login.html?next=admin`, { redirect: "manual" });
    assert.equal(response.status, 301);
    assert.equal(response.headers.get("location"), "/login?next=admin");
    await response.text();
  });

  for (const route of [
    "/src/server.js", "/src/utils/mailer.js", "/docs/reference/domain-validation.csv",
    "/data/banking.db", "/uploads/private.txt", "/.env",
    "/scripts/cloudflare/worker-admin.mjs", "/tests/layout.test.js",
  ]) {
    test(`does not expose private path ${route}`, async () => {
      const response = await fetch(`${origin}${route}`);
      assert.equal(response.status, 404);
      await response.text();
    });
  }
});
