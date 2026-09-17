// Cloudflare Worker entry point for the existing Polaris Express API.
import { env } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";

const ENV_KEYS = [
  "ADMIN_PASS", "ADMIN_USER", "ALLOW_ANY_ORIGIN", "APP_BASE_URL",
  "BANKSWIFT_NOTIFY_EMAIL", "BRAND_LOGO_PATH", "BRAND_LOGO_URL", "BRAND_NAME",
  "CORS_ORIGINS", "DATABASE_URL", "DEFAULT_USER_EMAIL", "DEFAULT_USER_UUID",
  "GS_LOG_ENDPOINT", "GS_LOG_SECRET", "JWT_EXPIRES_IN", "JWT_SECRET",
  "JWT_SECRETS", "JWT_SECRET_FALLBACKS", "MAIL_FROM", "NODE_ENV", "PORT",
  "SENDGRID_API_KEY", "SHEETS_SECRET", "SUPPORT_EMAIL"
];

for (const key of ENV_KEYS) {
  const value = env[key];
  if (value !== undefined && value !== null && value !== "") {
    process.env[key] = String(value);
  }
}

process.env.NODE_ENV ||= "production";
process.env.PORT ||= "3000";
process.env.APP_BASE_URL ||= "https://polaris.dark-surf-56ad.workers.dev";
process.env.CORS_ORIGINS ||= process.env.APP_BASE_URL;

globalThis.__POLARIS_WORKER__ = true;

const { app } = await import("./server.js");

app.listen(Number(process.env.PORT) || 3000);

// Static HTML/CSS/JS is handled by Wrangler Static Assets.
// Express handles the API routes through the Cloudflare Node HTTP bridge.
export default httpServerHandler({ port: Number(process.env.PORT) || 3000 });
