// Configure or verify the existing Polaris administrator without displaying
// credentials or session tokens. Only ADMIN_USER and ADMIN_PASS are uploaded.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { parse } from "dotenv";

const root = fileURLToPath(new URL("../", import.meta.url));
const origin = "https://polaris.dark-surf-56ad.workers.dev";
const mode = process.argv[2] || "check";

async function main() {
  if (!["check", "sync", "verify", "verify-shared"].includes(mode)) {
    throw new Error("Usage: node scripts/worker-admin.mjs [check|sync|verify|verify-shared]");
  }

  const local = parse(readFileSync(new URL("../.env", import.meta.url)));
  const secrets = {};
  for (const name of ["ADMIN_USER", "ADMIN_PASS"]) {
    if (!local[name]?.trim()) throw new Error(`${name} is missing or empty in .env`);
    secrets[name] = local[name].trim();
  }

  if (mode === "check") {
    console.log("ADMIN_USER and ADMIN_PASS are both configured locally (values hidden).");
    return;
  }

  if (mode === "sync") {
    const cli = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
    const child = spawn(process.execPath, [cli, "secret", "bulk", "--name", "polaris", "--config", "wrangler.jsonc"], {
      cwd: root,
      windowsHide: true,
      stdio: ["pipe", "inherit", "inherit"],
      env: { ...process.env, WRANGLER_LOG: "info" },
    });
    // No secret values in command arguments, files, or console output.
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(secrets));
    const [code] = await once(child, "close");
    if (code !== 0) throw new Error(`Wrangler secret upload failed (exit ${code})`);
    return;
  }

  const loginPath = mode === "verify-shared" ? "/api/login" : "/api/admin/login";
  const response = await fetch(`${origin}${loginPath}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: secrets.ADMIN_USER, password: secrets.ADMIN_PASS }),
    redirect: "error",
    signal: AbortSignal.timeout(45000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.token || data.admin?.role !== "admin") {
    throw new Error(`Admin login verification failed (HTTP ${response.status}); response values withheld`);
  }
  console.log(`Admin login via ${loginPath}: HTTP 200, admin session issued (credentials and token hidden).`);

  // Exercise the actual protected dashboard read, without logging user data.
  const overview = await fetch(`${origin}/api/admin/overview?limit=1`, {
    headers: { Authorization: `Bearer ${data.token}` },
    redirect: "error",
    signal: AbortSignal.timeout(45000),
  });
  const overviewData = await overview.json().catch(() => ({}));
  if (!overview.ok || !overviewData.stats || !Array.isArray(overviewData.users)) {
    throw new Error(`Protected admin dashboard verification failed (HTTP ${overview.status}); response values withheld`);
  }
  console.log("Protected admin dashboard: HTTP 200, expected data shape (user data hidden).");
}

main().catch((err) => {
  console.error(err.message);
  process.exitCode = 1;
});
