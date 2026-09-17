// Cloudflare Worker entry point for the existing Polaris Express backend.
// Cloudflare's Express adapter runs the existing app behind a Worker fetch handler.
import { env } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";

// server.js expects process.env because it was originally written for Node/Express.
// Populate those values from Worker vars/secrets before dynamically importing it.
const ENV_KEYS = [
  "ADMIN_PASS",
  "ADMIN_USER",
  "ALLOW_ANY_ORIGIN",
  "APP_BASE_URL",
  "BANKSWIFT_NOTIFY_EMAIL",
  "BRAND_LOGO_PATH",
  "BRAND_LOGO_URL",
  "BRAND_NAME",
  "CORS_ORIGINS",
  "DEFAULT_USER_EMAIL",
  "DEFAULT_USER_UUID",
  "GS_LOG_ENDPOINT",
  "GS_LOG_SECRET",
  "JWT_EXPIRES_IN",
  "JWT_SECRET",
  "JWT_SECRETS",
  "JWT_SECRET_FALLBACKS",
  "MAIL_FROM",
  "NODE_ENV",
  "PORT",
  "SENDGRID_API_KEY",
  "SHEETS_SECRET",
  "SUPPORT_EMAIL",
];

for (const key of ENV_KEYS) {
  const value = env[key];
  if (value !== undefined && value !== null && value !== "") {
    process.env[key] = String(value);
  }
}

// PostgreSQL on Workers should normally use Hyperdrive. If DATABASE_URL was not
// supplied directly, use Hyperdrive's generated connection string.
if (!process.env.DATABASE_URL && env.HYPERDRIVE?.connectionString) {
  process.env.DATABASE_URL = env.HYPERDRIVE.connectionString;
}

process.env.NODE_ENV ||= "production";
process.env.PORT ||= "3000";
process.env.APP_BASE_URL ||= "https://polaris.dark-surf-56ad.workers.dev";
process.env.CORS_ORIGINS ||= process.env.APP_BASE_URL;

globalThis.__POLARIS_WORKER__ = true;

const { app } = await import("./server.js");

// Express listens on an in-memory Worker HTTP server; httpServerHandler bridges it
// to the Cloudflare Fetch API.
app.listen(Number(process.env.PORT) || 3000);

export default httpServerHandler({ port: Number(process.env.PORT) || 3000 });
