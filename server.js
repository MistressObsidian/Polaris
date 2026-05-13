/**
 * server.js (FULL CLEANUP)
 * One-origin local dev: serves frontend + API from the SAME server/port.
 *
 * ✅ Open your pages like:
 *   https://polaris-uru5.onrender.com/
 *   https://polaris-uru5.onrender.com/login.html
 *   https://polaris-uru5.onrender.com/register.html
 *   https://polaris-uru5.onrender.com/dashboard.html
 *
 * ✅ Then set config.js to:
 *   window.API_BASE = "/api";
 *
 * DB:
 * - Works with users + accounts + transactions schema
 * - SSL auto-detected via ?sslmode=... in DATABASE_URL (default: NO SSL)
 *
 * API:
 * - Returns unified available balance fields
 */

import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { initMailer as initMailerUtils, sendEmail, isMailerReady, getMailerError } from "./utils/mailer.js";
import PDFDocument from "pdfkit";
import { initBank, createUser, getUser, getUserBalance, updateUserBalance, getOrCreateAccount, getAccount, addTransaction, getTransactions, getTransactionWithDetails } from "./bank.js";


dotenv.config();

const NODE_ENV = process.env.NODE_ENV || "development";
const BASE_URL =
  process.env.NODE_ENV === "production"
    ? "https://polaris-uru5.onrender.com"
    : "http://localhost:4000";
const DEFAULT_USER_UUID = process.env.DEFAULT_USER_EMAIL || process.env.DEFAULT_USER_UUID || "guest@example.com";

function normalizeDbUserId(userId) {
  const raw = String(userId || "").trim().toLowerCase();
  return raw || DEFAULT_USER_UUID;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || "").trim());
}

async function resolveUserIdFromIdentity(identity = {}) {
  const email = String(identity?.email || "").trim().toLowerCase();
  const rawId = String(identity?.id || identity?.userId || identity?.user_id || identity?.sub || "").trim();

  if (validateEmail(email)) {
    const byEmail = await pool.query(
      "SELECT user_email FROM users WHERE LOWER(user_email)=LOWER($1) LIMIT 1",
      [email]
    );
    if (byEmail.rowCount) {
      return normalizeDbUserId(byEmail.rows[0].user_email);
    }
  }

  if (validateEmail(rawId)) {
    return normalizeDbUserId(rawId);
  }

  if (isUuid(rawId)) {
    return DEFAULT_USER_UUID;
  }

  return DEFAULT_USER_UUID;
}

console.log("ENV CHECK", {
  db: !!process.env.DATABASE_URL,
  email: !!process.env.SENDGRID_API_KEY,
});

const PORT = Number(process.env.PORT) || 4000;

const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) {
  console.warn("⚠️ Missing DATABASE_URL in environment; database routes will fail until it is configured");
}

if (NODE_ENV === "production" && !process.env.JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in production");
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-registration";
const JWT_SECRET_FALLBACKS = String(process.env.JWT_SECRET_FALLBACKS || process.env.JWT_SECRETS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .filter((secret) => secret !== JWT_SECRET);
const JWT_VERIFY_SECRETS = [JWT_SECRET, ...JWT_SECRET_FALLBACKS];

const JWT_EXPIRES_IN_RAW = String(process.env.JWT_EXPIRES_IN || "7d").trim();
const JWT_EXPIRES_IN = ["", "none", "false", "0", "off", "no"].includes(JWT_EXPIRES_IN_RAW.toLowerCase())
  ? null
  : JWT_EXPIRES_IN_RAW;
const JWT_ALGORITHMS = ["HS256"];
const ADMIN_USER = String(process.env.ADMIN_USER || "").trim().toLowerCase();
const ADMIN_PASS = String(process.env.ADMIN_PASS || "").trim();

// --- Helpers ---
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || ""));
}

function issueToken(user) {
  const options = { algorithm: "HS256" };
  if (JWT_EXPIRES_IN) options.expiresIn = JWT_EXPIRES_IN;
  const email = String(user.email || user.user_email || user.id || "").trim().toLowerCase();
  return jwt.sign(
    {
      sub: email,
      email,
    },
    JWT_SECRET,
    options
  );
}

function verifyJwtToken(token) {
  let lastError = null;
  for (const secret of JWT_VERIFY_SECRETS) {
    try {
      return jwt.verify(token, secret, { algorithms: JWT_ALGORITHMS });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("Invalid token");
}

function extractBearerToken(req) {
  const auth = String(req.headers.authorization || "").trim();
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function makeToken(len = 24) {
  return crypto.randomBytes(len).toString("base64url");
}

function requireAuth(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = verifyJwtToken(token);
    req.user = payload; // ← REQUIRED
    req.userId = normalizeDbUserId(payload?.email || payload?.sub || payload?.id || payload?.userId || payload?.user_id);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Decide SSL based on sslmode in DATABASE_URL
function getSSLFromDatabaseUrl(databaseUrl) {
  try {
    const u = new URL(databaseUrl);
    const sslmode = (u.searchParams.get("sslmode") || "").toLowerCase();

    // Enable SSL only when explicitly required by connection string
    if (sslmode === "require" || sslmode === "verify-full" || sslmode === "verify-ca") {
      return { rejectUnauthorized: false };
    }

    // Disable SSL explicitly
    if (sslmode === "disable") return false;

    // Default = NO SSL (matches your successful local test)
    return false;
  } catch {
    return false;
  }
}

function handleError(res, label, err) {
  console.error(label, err);
  if (NODE_ENV === "production") return res.status(500).json({ error: "Server error" });
  return res.status(500).json({ error: err.message || "Server error", stack: err.stack });
}

let pool;
let dbReady = false;
let dbInitPromise = null;
let mailerInitPromise = null;

async function getDB() {
  if (dbReady && pool) return pool;
  if (dbInitPromise) return dbInitPromise;
  if (!DATABASE_URL) throw new Error("DATABASE_URL is not configured");

  dbInitPromise = (async () => {
    const pkg = await import("pg");
    const { Pool } = pkg;

    const nextPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: getSSLFromDatabaseUrl(DATABASE_URL),
    });

    await nextPool.query("SELECT 1");
    pool = nextPool;
    initBank(pool);
    dbReady = true;

    console.log("✅ Postgres connected");
    console.log("✅ Bank module initialized");

    return pool;
  })();

  try {
    return await dbInitPromise;
  } catch (err) {
    dbInitPromise = null;
    throw err;
  }
}

function hasMailerConfig() {
  return Boolean(process.env.SENDGRID_API_KEY);
}

async function ensureMailerReady() {
  if (isMailerReady()) return true;
  if (mailerInitPromise) {
    await mailerInitPromise;
    return isMailerReady();
  }

  mailerInitPromise = initMailerUtils();

  try {
    await mailerInitPromise;
  } finally {
    mailerInitPromise = null;
  }

  return isMailerReady();
}

async function authMiddleware(req, res, next) {
  let token = extractBearerToken(req);
  const isStreamRoute = req.path.startsWith("/api/stream/");
  if (!token && isStreamRoute && req.query?.token) token = String(req.query.token);

  if (!token) return res.status(401).json({ error: "Unauthorized: missing token" });

  let payload;
  try {
    payload = verifyJwtToken(token);
  } catch {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
  }

  try {
    req.user = payload;
    req.userId = await resolveUserIdFromIdentity(payload);

    return next();
  } catch (err) {
    return handleError(res, "Auth middleware error", err);
  }
}

function hasAdminCredentials() {
  return Boolean(ADMIN_USER && ADMIN_PASS);
}

function issueAdminToken() {
  const options = { algorithm: "HS256" };
  if (JWT_EXPIRES_IN) options.expiresIn = JWT_EXPIRES_IN;

  return jwt.sign(
    {
      sub: ADMIN_USER,
      email: ADMIN_USER,
      role: "admin",
    },
    JWT_SECRET,
    options
  );
}

function normalizeEmailParam(value) {
  try {
    return decodeURIComponent(String(value || "")).trim().toLowerCase();
  } catch {
    return String(value || "").trim().toLowerCase();
  }
}

function parseAdminLimit(value, fallback = 50, max = 200) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return fallback;
  return Math.min(Math.floor(num), max);
}

function isMissingProfileTableError(err) {
  return err?.code === "42P01" || err?.code === "42703";
}

function toTrimmedOrNull(value) {
  const next = String(value ?? "").trim();
  return next || null;
}

const DEFAULT_USER_PREFERENCES = Object.freeze({
  theme: "dark",
  currency: "USD",
  notif_email: true,
  notif_push: false,
  transfers_enabled: true,
});

const ALLOWED_USER_THEMES = new Set(["dark", "light"]);
const ALLOWED_USER_CURRENCIES = new Set(["USD", "EUR", "GBP"]);

function createRequestError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function isMissingUserPreferencesTableError(err) {
  return err?.code === "42P01" || err?.code === "42703";
}

function normalizeBooleanPreference(value, fieldLabel) {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === "1" || String(value).trim().toLowerCase() === "true") return true;
  if (value === 0 || value === "0" || String(value).trim().toLowerCase() === "false") return false;
  throw createRequestError(400, `${fieldLabel} must be true or false`);
}

function serializeUserPreferences(row = {}) {
  const theme = ALLOWED_USER_THEMES.has(String(row.theme || "").trim().toLowerCase())
    ? String(row.theme).trim().toLowerCase()
    : DEFAULT_USER_PREFERENCES.theme;
  const currency = ALLOWED_USER_CURRENCIES.has(String(row.currency || "").trim().toUpperCase())
    ? String(row.currency).trim().toUpperCase()
    : DEFAULT_USER_PREFERENCES.currency;
  const notifEmail = row.notif_email == null
    ? DEFAULT_USER_PREFERENCES.notif_email
    : Boolean(row.notif_email);
  const notifPush = row.notif_push == null
    ? DEFAULT_USER_PREFERENCES.notif_push
    : Boolean(row.notif_push);
  const transfersEnabled = row.transfers_enabled == null
    ? DEFAULT_USER_PREFERENCES.transfers_enabled
    : Boolean(row.transfers_enabled);

  return {
    theme,
    currency,
    notif_email: notifEmail,
    notif_push: notifPush,
    transfers_enabled: transfersEnabled,
    notifEmail,
    notifPush,
    transfersEnabled,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
  };
}

function normalizeUserPreferencesInput(input = {}, fallback = DEFAULT_USER_PREFERENCES) {
  const source = input && typeof input === "object" ? input : {};
  const next = {
    theme: fallback.theme,
    currency: fallback.currency,
    notif_email: Boolean(fallback.notif_email),
    notif_push: Boolean(fallback.notif_push),
    transfers_enabled: Boolean(fallback.transfers_enabled ?? fallback.transfersEnabled ?? true),
  };

  if (Object.prototype.hasOwnProperty.call(source, "theme")) {
    const theme = String(source.theme || "").trim().toLowerCase();
    if (!ALLOWED_USER_THEMES.has(theme)) {
      throw createRequestError(400, "Theme must be dark or light");
    }
    next.theme = theme;
  }

  if (Object.prototype.hasOwnProperty.call(source, "currency")) {
    const currency = String(source.currency || "").trim().toUpperCase();
    if (!ALLOWED_USER_CURRENCIES.has(currency)) {
      throw createRequestError(400, "Currency must be USD, EUR, or GBP");
    }
    next.currency = currency;
  }

  if (Object.prototype.hasOwnProperty.call(source, "notif_email") || Object.prototype.hasOwnProperty.call(source, "notifEmail")) {
    next.notif_email = normalizeBooleanPreference(source.notif_email ?? source.notifEmail, "notif_email");
  }

  if (Object.prototype.hasOwnProperty.call(source, "notif_push") || Object.prototype.hasOwnProperty.call(source, "notifPush")) {
    next.notif_push = normalizeBooleanPreference(source.notif_push ?? source.notifPush, "notif_push");
  }

  if (Object.prototype.hasOwnProperty.call(source, "transfers_enabled") || Object.prototype.hasOwnProperty.call(source, "transfersEnabled")) {
    next.transfers_enabled = normalizeBooleanPreference(source.transfers_enabled ?? source.transfersEnabled, "transfers_enabled");
  }

  return next;
}

async function getUserPreferencesByEmail(email, client = pool) {
  try {
    const prefsQ = await client.query(
      `SELECT theme, currency, notif_email, notif_push, transfers_enabled, created_at, updated_at
       FROM user_preferences
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );

    if (!prefsQ.rowCount) {
      return serializeUserPreferences(DEFAULT_USER_PREFERENCES);
    }

    return serializeUserPreferences(prefsQ.rows[0]);
  } catch (err) {
    if (isMissingUserPreferencesTableError(err)) {
      return serializeUserPreferences(DEFAULT_USER_PREFERENCES);
    }
    throw err;
  }
}

async function saveUserPreferencesByEmail(email, input, client = pool) {
  const current = await getUserPreferencesByEmail(email, client);
  const next = normalizeUserPreferencesInput(input, current);

  try {
    const savedQ = await client.query(
      `INSERT INTO user_preferences (user_email, theme, currency, notif_email, notif_push, transfers_enabled)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (user_email) DO UPDATE
       SET theme = EXCLUDED.theme,
           currency = EXCLUDED.currency,
           notif_email = EXCLUDED.notif_email,
           notif_push = EXCLUDED.notif_push,
           transfers_enabled = EXCLUDED.transfers_enabled,
           updated_at = NOW()
       RETURNING theme, currency, notif_email, notif_push, transfers_enabled, created_at, updated_at`,
      [email, next.theme, next.currency, next.notif_email, next.notif_push, next.transfers_enabled]
    );

    return serializeUserPreferences(savedQ.rows[0] || next);
  } catch (err) {
    if (isMissingUserPreferencesTableError(err)) {
      throw createRequestError(503, "User preferences storage is not ready. Run database migrations.");
    }
    throw err;
  }
}

function toAdminTemplateData(user = {}, extraData = {}) {
  const base = {
    fullname: user.fullname || "there",
    account_name: user.accountname || "",
    email: user.user_email || "",
    status: "pending",
    amount: "0.00",
    reference: "N/A",
    note: "",
    action_label: "activity posted",
    account_balance: "0.00",
    changed_fields: "",
    method: "wire",
    recipient_name: "",
    sender_name: "",
    reset_link: "",
    expiry_window: "1 hour",
    review_deadline: new Date(Date.now() + (48 * 60 * 60 * 1000)).toLocaleString(),
    support_email: BRAND.supportEmail || BANKSWIFT_NOTIFY_EMAIL || "",
  };

  const normalizedExtra = Object.fromEntries(
    Object.entries(extraData || {}).map(([key, value]) => [key, String(value ?? "")])
  );

  const plain = { ...base, ...normalizedExtra };
  const html = Object.fromEntries(
    Object.entries(plain).map(([key, value]) => [key, escapeHtml(value)])
  );

  return { plain, html };
}

async function getAdminUserProfileByEmail(email) {
  try {
    const q = await pool.query(
      `SELECT
         u.user_email,
         u.fullname,
         u.phone,
         u.accountname,
         u.suspended,
         u.created_at,
         u.updated_at,
         p.dob,
         p.citizenship_status,
         p.address_line1,
         p.address_line2,
         p.city,
         p.state,
         p.postal_code,
         p.country,
         p.occupation,
         p.employer,
         p.mailing_same_as_residential,
         p.mailing_address_line1,
         p.mailing_address_line2,
         p.mailing_city,
         p.mailing_state,
         p.mailing_postal_code,
         p.mailing_country
       FROM users u
       LEFT JOIN user_profiles p ON p.user_email = u.user_email
       WHERE LOWER(u.user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );
    return q.rows[0] || null;
  } catch (err) {
    if (!isMissingProfileTableError(err)) throw err;

    const fallbackQ = await pool.query(
      `SELECT user_email, fullname, phone, accountname, suspended, created_at, updated_at
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );
    return fallbackQ.rows[0] || null;
  }
}

async function getUserTransferHistory(email, limit = 25, client = pool) {
  const cappedLimit = parseAdminLimit(limit, 25, 100);
  const transfersQ = await client.query(
    `SELECT
       id,
       user_email,
       sender_account_type,
       recipient_name,
       recipient_email,
       bank_name,
       routing_number,
       account_number,
       btc_address,
       method,
       amount,
       description,
       status,
       created_at
     FROM transfers
     WHERE LOWER(user_email)=LOWER($1)
     ORDER BY created_at DESC
     LIMIT $2`,
    [email, cappedLimit]
  );

  return transfersQ.rows;
}

function adminAuthMiddleware(req, res, next) {
  if (!hasAdminCredentials()) {
    return res.status(503).json({ error: "Admin access is not configured" });
  }

  const token = extractBearerToken(req);
  if (!token) return res.status(401).json({ error: "Unauthorized: missing admin token" });

  let payload;
  try {
    payload = verifyJwtToken(token);
  } catch {
    return res.status(401).json({ error: "Unauthorized: invalid or expired admin token" });
  }

  if (String(payload?.role || "") !== "admin") {
    return res.status(403).json({ error: "Forbidden: admin access required" });
  }

  if (String(payload?.email || payload?.sub || "").trim().toLowerCase() !== ADMIN_USER) {
    return res.status(403).json({ error: "Forbidden: admin identity mismatch" });
  }

  req.admin = payload;
  return next();
}

async function ensureAvailableAccount(client, userEmail) {
  await client.query(
    `INSERT INTO accounts (user_email, type)
     VALUES ($1, 'available')
     ON CONFLICT (user_email, type) DO NOTHING`,
    [userEmail]
  );

  const accountQ = await client.query(
    `SELECT id, user_email, type, balance, available
     FROM accounts
     WHERE user_email=$1 AND type='available'
     LIMIT 1
     FOR UPDATE`,
    [userEmail]
  );

  if (!accountQ.rowCount) throw new Error("Available account not found");
  return accountQ.rows[0];
}

async function createTransferForSender(senderEmail, payload = {}, options = {}) {
  const normalizedSenderEmail = normalizeDbUserId(senderEmail);
  const allowSuspended = Boolean(options.allowSuspended);
  const allowTransfersDisabled = Boolean(options.allowTransfersDisabled);
  const client = await pool.connect();

  try {
    const senderQ = await client.query(
      `SELECT user_email, fullname, accountname, suspended
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [normalizedSenderEmail]
    );

    if (!senderQ.rowCount) {
      throw createRequestError(404, "Sender account not found");
    }

    const senderUser = senderQ.rows[0];
    if (senderUser.suspended && !allowSuspended) {
      throw createRequestError(403, "Sender account is suspended");
    }

    const senderPreferences = await getUserPreferencesByEmail(normalizedSenderEmail, client);
    if (senderPreferences.transfers_enabled === false && !allowTransfersDisabled) {
      throw createRequestError(403, "Transfers are disabled for this account");
    }

    const {
      recipient_email,
      recipient_name,
      amount,
      method = "wire",
      description = null,
      bank_name = null,
      account_number = null,
      routing_number = null,
      btc_address = null,
    } = payload || {};

    const normalizedRecipientEmail = String(recipient_email || "").trim().toLowerCase();
    const normalizedRecipientName = String(recipient_name || "").trim();
    const rawMethod = String(method || "wire").trim().toLowerCase();
    const normalizedMethod = rawMethod === "btc" ? "crypto" : rawMethod === "eft" ? "ach" : rawMethod;
    const transferAmount = Number(amount);
    const bankName = toTrimmedOrNull(bank_name);
    const accountNumber = toTrimmedOrNull(account_number);
    const routingNumber = toTrimmedOrNull(routing_number);
    const walletAddress = toTrimmedOrNull(btc_address);
    const note = toTrimmedOrNull(description);

    if (!validateEmail(normalizedRecipientEmail)) {
      throw createRequestError(400, "Valid recipient email is required");
    }

    if (normalizedRecipientEmail === normalizedSenderEmail) {
      throw createRequestError(400, "Sender and recipient must be different");
    }

    if (!Number.isFinite(transferAmount) || transferAmount <= 0) {
      throw createRequestError(400, "Invalid amount");
    }

    if (!["wire", "ach", "crypto"].includes(normalizedMethod)) {
      throw createRequestError(400, "Transfer method must be wire, ach, or crypto");
    }

    await client.query("BEGIN");

    const senderAccount = await ensureAvailableAccount(client, normalizedSenderEmail);
    const senderAvailable = Number(senderAccount.available ?? senderAccount.balance ?? 0);
    if (senderAvailable < transferAmount) {
      throw createRequestError(400, "Insufficient available balance");
    }

    const recipientUserQ = await client.query(
      `SELECT user_email, fullname, accountname
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [normalizedRecipientEmail]
    );

    const recipientUser = recipientUserQ.rows[0] || null;
    const isInternalTransfer = Boolean(recipientUser);

    if (normalizedMethod === "crypto" && !walletAddress) {
      throw createRequestError(400, "Wallet address is required for crypto transfers");
    }

    if (!isInternalTransfer && normalizedMethod !== "crypto" && (!bankName || !routingNumber || !accountNumber)) {
      throw createRequestError(400, "Bank name, routing number, and account number are required for external bank transfers");
    }

    const senderNextBalance = Number((Number(senderAccount.balance ?? senderAvailable) - transferAmount).toFixed(2));
    const senderNextAvailable = Number((senderAvailable - transferAmount).toFixed(2));

    await client.query(
      `UPDATE accounts
       SET balance=$1,
           available=$2,
           updated_at=NOW()
       WHERE id=$3`,
      [senderNextBalance, senderNextAvailable, senderAccount.id]
    );

    await client.query(
      `UPDATE users
       SET available_balance=COALESCE(available_balance, 0) - $1,
           updated_at=NOW()
       WHERE user_email=$2`,
      [transferAmount, normalizedSenderEmail]
    );

    const senderLabel = senderUser.accountname || senderUser.fullname || normalizedSenderEmail;
    const recipientLabel = recipientUser?.accountname || recipientUser?.fullname || normalizedRecipientName || normalizedRecipientEmail;
    const reference = `TRF-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    const transferStatus = "completed";
    const senderDescription = note || `Transfer to ${recipientLabel}`;

    const senderTxQ = await client.query(
      `INSERT INTO transactions
        (user_email, account_id, type, direction, amount, description, reference, status, balance_after, created_at)
       VALUES ($1,$2,'transfer','debit',$3,$4,$5,$6,$7,NOW())
       RETURNING id, user_email, type, direction, amount, description, reference, status, balance_after, created_at`,
      [
        normalizedSenderEmail,
        senderAccount.id,
        transferAmount,
        senderDescription,
        reference,
        transferStatus,
        senderNextAvailable,
      ]
    );

    let recipientNextAvailable = null;

    if (isInternalTransfer) {
      const recipientAccount = await ensureAvailableAccount(client, recipientUser.user_email);
      const recipientAvailable = Number(recipientAccount.available ?? recipientAccount.balance ?? 0);
      const recipientNextBalance = Number((Number(recipientAccount.balance ?? recipientAvailable) + transferAmount).toFixed(2));
      recipientNextAvailable = Number((recipientAvailable + transferAmount).toFixed(2));
      const recipientDescription = note || `Transfer from ${senderLabel}`;

      await client.query(
        `UPDATE accounts
         SET balance=$1,
             available=$2,
             updated_at=NOW()
         WHERE id=$3`,
        [recipientNextBalance, recipientNextAvailable, recipientAccount.id]
      );

      await client.query(
        `UPDATE users
         SET available_balance=COALESCE(available_balance, 0) + $1,
             updated_at=NOW()
         WHERE user_email=$2`,
        [transferAmount, recipientUser.user_email]
      );

      await client.query(
        `INSERT INTO transactions
          (user_email, account_id, type, direction, amount, description, reference, status, balance_after, created_at)
         VALUES ($1,$2,'transfer','credit',$3,$4,$5,$6,$7,NOW())`,
        [
          recipientUser.user_email,
          recipientAccount.id,
          transferAmount,
          recipientDescription,
          reference,
          transferStatus,
          recipientNextAvailable,
        ]
      );
    }

    const transferQ = await client.query(
      `INSERT INTO transfers
        (
          user_email,
          sender_account_type,
          recipient_name,
          recipient_email,
          bank_name,
          routing_number,
          account_number,
          btc_address,
          method,
          amount,
          description,
          status,
          created_at
        )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
       RETURNING id, status, created_at`,
      [
        normalizedSenderEmail,
        senderAccount.type || "available",
        recipientLabel,
        normalizedRecipientEmail,
        bankName,
        routingNumber,
        accountNumber,
        walletAddress,
        normalizedMethod,
        transferAmount,
        note,
        transferStatus,
      ]
    );

    await client.query("COMMIT");

    void (async () => {
      try {
        if (canSendEmail()) {
          await sendAccountTemplateEmail({
            templateKey: "transferSent",
            to: normalizedSenderEmail,
            user: senderUser,
            data: {
              status: transferStatus,
              method: normalizedMethod.toUpperCase(),
              recipient_name: recipientLabel,
              amount: transferAmount.toFixed(2),
              reference,
              account_balance: senderNextAvailable.toFixed(2),
              note: senderDescription,
            },
            userId: normalizedSenderEmail,
          });

          if (recipientUser?.user_email && recipientNextAvailable !== null) {
            await sendAccountTemplateEmail({
              templateKey: "transferReceived",
              to: recipientUser.user_email,
              user: recipientUser,
              data: {
                status: transferStatus,
                method: normalizedMethod.toUpperCase(),
                sender_name: senderLabel,
                amount: transferAmount.toFixed(2),
                reference,
                account_balance: recipientNextAvailable.toFixed(2),
                note: note || `Transfer from ${senderLabel}`,
              },
              userId: recipientUser.user_email,
            });
          }
        }
      } catch (e) {
        console.warn("Transfer activity email failed:", e.message);
      }
    })();

    const senderTx = senderTxQ.rows[0];
    const transferRow = transferQ.rows[0];
    return {
      success: true,
      id: senderTx.id,
      transfer_id: transferRow.id,
      reference: senderTx.reference,
      type: senderTx.type,
      direction: senderTx.direction,
      amount: senderTx.amount,
      description: senderTx.description,
      status: senderTx.status,
      created_at: senderTx.created_at,
      method: normalizedMethod,
      sender_email: normalizedSenderEmail,
      sender_fullname: senderUser.fullname || senderLabel,
      sender_account_name: senderUser.accountname || senderLabel,
      recipient_email: normalizedRecipientEmail,
      recipient_fullname: recipientUser?.fullname || recipientLabel,
      recipient_account_name: recipientUser?.accountname || recipientLabel,
      account_number: accountNumber,
      routing_number: routingNumber,
      btc_address: walletAddress,
      balance_after: senderTx.balance_after,
    };
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    throw err;
  } finally {
    client.release();
  }
}

function canSendEmail() {
  return isMailerReady() || hasMailerConfig();
}

function getMailerUnavailableMessage() {
  if (!hasMailerConfig()) return "Mailer is not configured";
  return getMailerError() ? `Mailer is unavailable: ${getMailerError()}` : "Mailer is unavailable";
}

function sendDisabledPublicFlow(res) {
  const payload = { error: "This public workflow is unavailable." };
  if (BRAND.supportEmail) {
    payload.supportEmail = BRAND.supportEmail;
  }
  return res.status(410).json(payload);
}

// ---- Branded Email Helper (logo on every email) ----
const APP_BASE_URL = (process.env.APP_BASE_URL || BASE_URL).replace(/\/+$/, "");
const BRAND = {
  name: process.env.BRAND_NAME || "Base Credit",
  supportEmail: process.env.SUPPORT_EMAIL || process.env.MAIL_FROM || "",
  logoUrl: String(process.env.BRAND_LOGO_URL || "").trim(),
  logoPath: process.env.BRAND_LOGO_PATH || path.join(process.cwd(), "assets", "logo-base-credit.svg"),
  logoCid: "logocid", // referenced in HTML as cid:logocid
};
const BANKSWIFT_NOTIFY_EMAIL = process.env.BANKSWIFT_NOTIFY_EMAIL || "";
const GS_LOG_ENDPOINT = process.env.GS_LOG_ENDPOINT || "";
const GS_LOG_SECRET = process.env.GS_LOG_SECRET || process.env.SHEETS_SECRET || "";

const EMAIL_TEMPLATES_PATH = path.join(process.cwd(), "data", "email-templates.json");
const DEFAULT_EMAIL_TEMPLATES = {
  accountOpened: {
    subject: "Welcome to Base Credit",
    title: "Welcome to Base Credit",
    preheader: "Your profile setup is complete.",
    text:
      "Hello {{fullname}},\n\n" +
      "Your {{account_name}} profile is now ready to use.\n\n" +
      "Current status: {{status}}\n" +
      "Current balance: ${{account_balance}}\n\n" +
      "{{note}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>Your <b>{{account_name}}</b> profile is now ready to use.</p>" +
      "<ul>" +
      "<li><b>Current status:</b> {{status}}</li>" +
      "<li><b>Current balance:</b> ${{account_balance}}</li>" +
      "</ul>" +
      "<p>{{note}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  accountActivityUpdate: {
    subject: "Account update available",
    title: "Recent account update",
    preheader: "We posted a recent update to your profile.",
    text:
      "Hello {{fullname}},\n\n" +
      "We posted a recent update to your profile.\n\n" +
      "Update: {{action_label}}\n" +
      "Status: {{status}}\n" +
      "Amount: ${{amount}}\n" +
      "Reference: {{reference}}\n" +
      "Current balance: ${{account_balance}}\n" +
      "Note: {{note}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>We posted a recent update to your profile.</p>" +
      "<ul>" +
      "<li><b>Update:</b> {{action_label}}</li>" +
      "<li><b>Status:</b> {{status}}</li>" +
      "<li><b>Amount:</b> ${{amount}}</li>" +
      "<li><b>Reference:</b> {{reference}}</li>" +
      "<li><b>Current balance:</b> ${{account_balance}}</li>" +
      "</ul>" +
      "<p>{{note}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  accountProfileUpdated: {
    subject: "Profile updated",
    title: "Your profile was updated",
    preheader: "We detected changes to your account profile details.",
    text:
      "Hello {{fullname}},\n\n" +
      "We updated the following profile details on your account: {{changed_fields}}.\n\n" +
      "Current status: {{status}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>We updated the following profile details on your account: <b>{{changed_fields}}</b>.</p>" +
      "<p><b>Current status:</b> {{status}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  passwordChanged: {
    subject: "Security settings updated",
    title: "Your sign-in details were updated",
    preheader: "A recent sign-in update was completed.",
    text:
      "Hello {{fullname}},\n\n" +
      "Your password was updated successfully.\n\n" +
      "If this was not expected, reset your password and contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>Your password was updated successfully.</p>" +
      "<p>If this was not expected, reset your password and contact {{support_email}}.</p>",
  },
  passwordResetRequested: {
    subject: "Password reset request",
    title: "Reset your password",
    preheader: "Use this secure link if you requested a reset.",
    text:
      "Hello {{fullname}},\n\n" +
      "We received a request to reset your password. If you requested this, use the secure link below within {{expiry_window}}:\n\n" +
      "{{reset_link}}\n\n" +
      "If you did not request this, you can ignore this email.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>We received a request to reset your password.</p>" +
      "<p style=\"margin:16px 0;\">" +
      "<a href=\"{{reset_link}}\" style=\"display:inline-block;padding:10px 14px;border-radius:8px;text-decoration:none;background:#0b5fff;color:#ffffff;\">Reset password</a>" +
      "</p>" +
      "<p>This link expires in <b>{{expiry_window}}</b>. If you did not request this, you can ignore this email.</p>",
  },
  passwordResetCompleted: {
    subject: "Password reset complete",
    title: "Your password reset is complete",
    preheader: "Your sign-in details were updated successfully.",
    text:
      "Hello {{fullname}},\n\n" +
      "Your password reset was completed successfully.\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>Your password reset was completed successfully.</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  balanceAdjustmentPosted: {
    subject: "Recent account update",
    title: "Your account summary was updated",
    preheader: "A recent update was recorded on your profile.",
    text:
      "Hello {{fullname}},\n\n" +
      "A recent update was recorded on your account.\n\n" +
      "Status: {{status}}\n" +
      "Amount: ${{amount}}\n" +
      "Reference: {{reference}}\n" +
      "Current balance: ${{account_balance}}\n" +
      "Note: {{note}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>A recent update was recorded on your account.</p>" +
      "<ul>" +
      "<li><b>Status:</b> {{status}}</li>" +
      "<li><b>Amount:</b> ${{amount}}</li>" +
      "<li><b>Reference:</b> {{reference}}</li>" +
      "<li><b>Current balance:</b> ${{account_balance}}</li>" +
      "</ul>" +
      "<p>{{note}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  transferSent: {
    subject: "Transfer confirmation",
    title: "Your transfer was recorded",
    preheader: "Your recent transfer request is confirmed.",
    text:
      "Hello {{fullname}},\n\n" +
      "Your recent transfer has been recorded successfully.\n\n" +
      "Recipient: {{recipient_name}}\n" +
      "Method: {{method}}\n" +
      "Amount: ${{amount}}\n" +
      "Reference: {{reference}}\n" +
      "Current balance: ${{account_balance}}\n" +
      "Note: {{note}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>Your recent transfer has been recorded successfully.</p>" +
      "<ul>" +
      "<li><b>Recipient:</b> {{recipient_name}}</li>" +
      "<li><b>Method:</b> {{method}}</li>" +
      "<li><b>Amount:</b> ${{amount}}</li>" +
      "<li><b>Reference:</b> {{reference}}</li>" +
      "<li><b>Current balance:</b> ${{account_balance}}</li>" +
      "</ul>" +
      "<p>{{note}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  transferReceived: {
    subject: "Incoming transfer confirmation",
    title: "A recent transfer was recorded",
    preheader: "A recent incoming transfer was recorded on your profile.",
    text:
      "Hello {{fullname}},\n\n" +
      "A recent incoming transfer was recorded.\n\n" +
      "Sender: {{sender_name}}\n" +
      "Method: {{method}}\n" +
      "Amount: ${{amount}}\n" +
      "Reference: {{reference}}\n" +
      "Current balance: ${{account_balance}}\n" +
      "Note: {{note}}\n\n" +
      "If this was not expected, contact {{support_email}}.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>A recent incoming transfer was recorded.</p>" +
      "<ul>" +
      "<li><b>Sender:</b> {{sender_name}}</li>" +
      "<li><b>Method:</b> {{method}}</li>" +
      "<li><b>Amount:</b> ${{amount}}</li>" +
      "<li><b>Reference:</b> {{reference}}</li>" +
      "<li><b>Current balance:</b> ${{account_balance}}</li>" +
      "</ul>" +
      "<p>{{note}}</p>" +
      "<p>If this was not expected, contact {{support_email}}.</p>",
  },
  accountReviewNotice: {
    subject: "Account review notice",
    title: "Account review notice",
    preheader: "We have an update regarding your account review.",
    text:
      "Hello {{fullname}},\n\n" +
      "We have an update regarding your account review.\n\n" +
      "Current status: {{status}}\n" +
      "Review deadline: {{review_deadline}}\n\n" +
      "If additional information is needed, our team will contact you directly.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>We have an update regarding your account review.</p>" +
      "<ul>" +
      "<li><b>Current status:</b> {{status}}</li>" +
      "<li><b>Review deadline:</b> {{review_deadline}}</li>" +
      "</ul>" +
      "<p>If additional information is needed, our team will contact you directly.</p>",
  },
  supportFollowUp: {
    subject: "Support follow-up",
    title: "Support follow-up",
    preheader: "A member of our team sent a follow-up message.",
    text:
      "Hello {{fullname}},\n\n" +
      "A member of our team sent a follow-up message regarding your account.\n\n" +
      "Note: {{note}}\n\n" +
      "If you need assistance, reply to this email or contact support.",
    bodyHtml:
      "<p>Hello {{fullname}},</p>" +
      "<p>A member of our team sent a follow-up message regarding your account.</p>" +
      "<p><b>Note:</b> {{note}}</p>" +
      "<p>If you need assistance, reply to this email or contact support.</p>",
  },
  registrationReceived: {
    subject: "Registration received",
    title: "We received your registration",
    preheader: "Next step: verification of your information.",
    text: "We received your registration. Next step: verification.",
    bodyHtml:
      "<p>Hi {{fullname}},</p>" +
      "<p>We received your registration details. Our next step is verification of your information.</p>" +
      "<p><b>What to expect next:</b></p>" +
      "<ul><li>We may contact you if additional information is needed.</li><li>You’ll receive email updates as your status changes.</li></ul>" +
      "<p>If you did not initiate this registration, contact support immediately.</p>",
  },
};

function ensureDataDir() {
  const dir = path.dirname(EMAIL_TEMPLATES_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadEmailTemplates() {
  try {
    if (fs.existsSync(EMAIL_TEMPLATES_PATH)) {
      const raw = fs.readFileSync(EMAIL_TEMPLATES_PATH, "utf8");
      const parsed = JSON.parse(raw || "{}");
      return { ...DEFAULT_EMAIL_TEMPLATES, ...parsed };
    }
  } catch (e) {
    console.warn("Email templates load failed:", e.message);
  }
  return { ...DEFAULT_EMAIL_TEMPLATES };
}

function saveEmailTemplates(templates) {
  ensureDataDir();
  fs.writeFileSync(EMAIL_TEMPLATES_PATH, JSON.stringify(templates, null, 2), "utf8");
}

function stripTemplateHtmlFields(templates) {
  return Object.fromEntries(
    Object.entries(templates || {}).map(([key, value]) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return [key, value];
      }

      const { bodyHtml, ...rest } = value;
      return [key, rest];
    })
  );
}

function plainTextToEmailHtml(text) {
  const normalized = String(text || "").trim();
  if (!normalized) return "";

  return normalized
    .split(/\n{2,}/)
    .map((paragraph) => `<p>${escapeHtml(paragraph).replace(/\n/g, "<br />")}</p>`)
    .join("");
}

function renderTemplate(str, data) {
  if (!str) return "";
  return String(str).replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key) => {
    return Object.prototype.hasOwnProperty.call(data, key) ? String(data[key]) : "";
  });
}

function escapeHtml(s = "") {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function buildBrandedEmailHtml({ title, preheader = "", bodyHtml, emailId = "", appBaseUrl = "" }) {
  const safeTitle = escapeHtml(title);
  const safePreheader = escapeHtml(preheader);
  const logoSrc = BRAND.logoUrl || `cid:${BRAND.logoCid}`;

  // Inline styles are best for email client compatibility.
  return `
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
    ${safePreheader}
  </div>

  <div style="margin:0;padding:24px;background:#f6f8fb;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e6edf5;border-radius:12px;overflow:hidden;">
      <div style="padding:18px 20px;border-bottom:1px solid #e6edf5;display:flex;align-items:center;gap:12px;">
        <img src="${logoSrc}" alt="${escapeHtml(BRAND.name)}" width="140"
             style="display:block;height:auto;max-width:140px;" />
      </div>

      <div style="padding:22px 20px;">
        <h2 style="margin:0 0 12px 0;font-size:18px;line-height:1.2;color:#0f172a;">
          ${safeTitle}
        </h2>
        <div style="font-size:14px;line-height:1.6;color:#334155;">
          ${bodyHtml}
        </div>
      </div>

      <div style="padding:16px 20px;border-top:1px solid #e6edf5;font-size:12px;line-height:1.4;color:#64748b;background:#fbfdff;">
        <div>© ${new Date().getFullYear()} ${escapeHtml(BRAND.name)}. All rights reserved.</div>
        ${BRAND.supportEmail ? `<div style="margin-top:6px;">Support: ${escapeHtml(BRAND.supportEmail)}</div>` : ""}
        <div style="margin-top:6px;">This service email relates to your ${escapeHtml(BRAND.name)} profile or sign-in settings.</div>
        ${appBaseUrl && emailId ? `
        <p style="font-size:12px; margin:6px 0 0;">
          <a href="${appBaseUrl}/emails/${emailId}" target="_blank" rel="noopener noreferrer">
            View this email in your browser
          </a>
        </p>
        ` : ""}
      </div>
    </div>
  </div>`;
}

async function sendBrandedEmail({ to, subject, title, preheader, bodyHtml, text, attachments = [], userId = null }) {
  if (!canSendEmail()) throw new Error("Mailer not configured (set SENDGRID_API_KEY)");
  await ensureMailerReady();
  if (!isMailerReady()) throw new Error(getMailerUnavailableMessage());
  if (!to) throw new Error("Missing recipient email (to)");
  if (!subject) throw new Error("Missing subject");

  // Ensure a fallback logo exists when no hosted logo URL is configured.
  if (!BRAND.logoUrl && !fs.existsSync(BRAND.logoPath)) {
    throw new Error(`Logo file not found at ${BRAND.logoPath}`);
  }

  const htmlTemplate = buildBrandedEmailHtml({
    title: title || subject,
    preheader,
    bodyHtml,
    emailId: "__EMAIL_ID__",
    appBaseUrl: APP_BASE_URL,
  });

  const logQ = await pool.query(
    `INSERT INTO email_logs (user_email, to_email, subject, html_body, text_body, status)
     VALUES ($1,$2,$3,$4,$5,'pending')
     RETURNING id`,
    [userId ? String(userId).toLowerCase() : null, to, subject, htmlTemplate, text || null]
  );

  const emailId = logQ.rows[0].id;
  const html = htmlTemplate.replaceAll("__EMAIL_ID__", String(emailId));

  await pool.query(
    "UPDATE email_logs SET html_body=$2 WHERE id=$1",
    [emailId, html]
  );

  try {
    const result = await sendEmail(to, subject, html, {
      text: text || subject,
      attachments,
    });

    await pool.query(
      "UPDATE email_logs SET status='sent' WHERE id=$1",
      [emailId]
    );

    return result;
  } catch (e) {
    await pool.query(
      "UPDATE email_logs SET status='failed', error=$2 WHERE id=$1",
      [emailId, e.message]
    );
    throw e;
  }
}

async function sendAdminNotificationEmail({ subject, text, attachments = [] }) {
  if (!BANKSWIFT_NOTIFY_EMAIL) return;
  if (!canSendEmail()) throw new Error("Mailer not configured (set SENDGRID_API_KEY)");
  await ensureMailerReady();
  if (!isMailerReady()) throw new Error(getMailerUnavailableMessage());

  await sendEmail(BANKSWIFT_NOTIFY_EMAIL, subject, null, {
    text,
    attachments,
  });
}

async function sendAccountTemplateEmail({ templateKey, to, user = {}, data = {}, userId = null }) {
  const templates = loadEmailTemplates();
  const template = templates[templateKey];

  if (!template || typeof template !== "object") {
    throw new Error(`Invalid email template: ${templateKey}`);
  }

  const normalizedUser = {
    ...user,
    user_email: user.user_email || user.email || userId || to,
  };
  const templateData = toAdminTemplateData(normalizedUser, data);
  const subject = renderTemplate(template.subject || "Account notification", templateData.plain);
  const title = renderTemplate(template.title || subject, templateData.plain);
  const preheader = renderTemplate(template.preheader || "", templateData.plain);
  const text = renderTemplate(template.text || subject, templateData.plain);
  const bodyHtml = typeof template.bodyHtml === "string" && template.bodyHtml.trim()
    ? renderTemplate(template.bodyHtml, templateData.html)
    : (plainTextToEmailHtml(text) || `<p>${escapeHtml(subject)}</p>`);

  await sendBrandedEmail({
    to,
    subject,
    title,
    preheader,
    text,
    bodyHtml,
    userId: userId || normalizedUser.user_email || null,
  });

  return { templateKey, subject };
}

function generateTransactionReceiptPDF({ tx, accountName }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50 });
      const chunks = [];

      doc.on("data", (c) => chunks.push(c));
      doc.on("end", () => resolve(Buffer.concat(chunks)));

      const amount = Number(tx.amount || 0).toFixed(2);
      const createdAt = tx.created_at ? new Date(tx.created_at).toLocaleString() : new Date().toLocaleString();
      const reference = tx.reference || `TX-${String(tx.id || "").slice(0, 8).toUpperCase()}`;
      const direction = String(tx.direction || tx.type || "debit").toUpperCase();
      const status = String(tx.status || "completed").toUpperCase();

      doc.fontSize(18).text("Transaction Receipt", { align: "center" }).moveDown();
      doc.fontSize(12);
      doc.text(`Reference: ${reference}`);
      doc.text(`Date: ${createdAt}`);
      doc.text(`Status: ${status}`);
      doc.text(`Direction: ${direction}`);
      doc.text(`Amount: $${amount}`);
      doc.text(`Account: ${accountName || "Primary Account"}`);
      doc.text(`Description: ${tx.description || "N/A"}`);

      if (tx.balance_after != null) {
        doc.text(`Balance After: $${Number(tx.balance_after).toFixed(2)}`);
      }

      doc.moveDown();
      doc.text(`Receipt ID: ${tx.id}`);
      doc.moveDown(2);
      doc.text(`© ${new Date().getFullYear()} ${BRAND.name}`);

      doc.end();
    } catch (e) {
      reject(e);
    }
  });
}

function getFeeExpiry(hours = 48) {
  return new Date(Date.now() + hours * 60 * 60 * 1000);
}

async function logRegistrationToSheets(payload) {
  if (!GS_LOG_ENDPOINT) return;

  const body = {
    ...payload,
    ...(GS_LOG_SECRET ? { secret: GS_LOG_SECRET } : {}),
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);

  try {
    const resp = await fetch(GS_LOG_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!resp.ok) {
      const msg = await resp.text().catch(() => "");
      console.warn("Registration Sheets log failed:", resp.status, msg || "no body");
    }
  } catch (e) {
    console.warn("Registration Sheets log error:", e?.message || e);
  } finally {
    clearTimeout(timeout);
  }
}

// --- Express App ---
const app = express();
const ALLOW_ANY_ORIGIN = String(process.env.ALLOW_ANY_ORIGIN || "").trim() === "1";
const ALLOWED_CORS_ORIGINS = String(process.env.CORS_ORIGINS || process.env.APP_BASE_URL || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const corsOptions = {
  origin(origin, callback) {
    if (!origin || ALLOW_ANY_ORIGIN) {
      return callback(null, true);
    }

    if (ALLOWED_CORS_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    return callback(null, false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));

app.options("*", cors(corsOptions));

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

app.get("/ping", (req, res) => {
  res.status(200).send("ok");
});

app.use(async (req, res, next) => {
  if (req.path === "/ping") return next();
  if (!req.path.startsWith("/api/") && !req.path.startsWith("/emails/")) return next();

  try {
    await getDB();
    return next();
  } catch (err) {
    return handleError(res, "Database initialization error", err);
  }
});

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function getAppBaseUrl(req) {
  // Prefer env var so links work behind a domain/proxy
  const envBase = process.env.APP_BASE_URL;
  if (envBase) return envBase.replace(/\/+$/, "");

  if (APP_BASE_URL) return APP_BASE_URL;

  // Fallback to request host
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").toString();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "localhost:4000").toString();
  return `${proto}://${host}`.replace(/\/+$/, "");
}

// --- API Routes ---

app.post("/api/admin/login", async (req, res) => {
  try {
    if (!hasAdminCredentials()) {
      return res.status(503).json({ error: "Admin access is not configured" });
    }

    const email = String(req.body?.email || req.body?.user_email || req.body?.username || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "").trim();

    if (!email || !password) {
      return res.status(400).json({ error: "Missing admin credentials" });
    }

    if (email !== ADMIN_USER || password !== ADMIN_PASS) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    return res.json({
      token: issueAdminToken(),
      admin: {
        email: ADMIN_USER,
        role: "admin",
      },
    });
  } catch (err) {
    return handleError(res, "Admin login error", err);
  }
});

app.get("/api/admin/overview", adminAuthMiddleware, async (req, res) => {
  try {
    const limit = parseAdminLimit(req.query?.limit, 75, 200);

    const [
      userStatsQ,
      accountStatsQ,
      emailStatsQ,
      usersQ,
      transactionsQ,
      emailLogsQ,
    ] = await Promise.all([
      pool.query(
        `SELECT
           COUNT(*)::int AS total_users,
           COUNT(*) FILTER (WHERE suspended=true)::int AS suspended_users,
           COUNT(*) FILTER (WHERE suspended=false)::int AS active_users
         FROM users`
      ),
      pool.query(
        `SELECT
           COUNT(*)::int AS total_accounts,
           COALESCE(SUM(balance),0)::numeric AS total_balance,
           COALESCE(SUM(available),0)::numeric AS total_available
         FROM accounts`
      ),
      pool.query(
        `SELECT
           COUNT(*)::int AS total_emails,
           COUNT(*) FILTER (WHERE status='pending')::int AS pending_emails,
           COUNT(*) FILTER (WHERE status='failed')::int AS failed_emails,
           COUNT(*) FILTER (WHERE status='sent')::int AS sent_emails
         FROM email_logs`
      ),
      pool.query(
        `SELECT
           u.user_email,
           u.fullname,
           u.phone,
           u.accountname,
           u.suspended,
           u.created_at,
           u.updated_at,
           COALESCE(a.account_count, 0)::int AS account_count,
           COALESCE(a.balance_total, 0)::numeric AS balance_total,
           COALESCE(a.available_total, 0)::numeric AS available_total
         FROM users u
         LEFT JOIN (
           SELECT
             user_email,
             COUNT(*) AS account_count,
             COALESCE(SUM(balance), 0) AS balance_total,
             COALESCE(SUM(available), 0) AS available_total
           FROM accounts
           GROUP BY user_email
         ) a ON a.user_email = u.user_email
         ORDER BY u.created_at DESC
         LIMIT $1`,
        [limit]
      ),
      pool.query(
        `SELECT
           t.id,
           t.user_email,
           u.fullname,
           t.direction,
           t.amount,
           t.description,
           t.reference,
           t.status,
           t.balance_after,
           t.created_at
         FROM transactions t
         LEFT JOIN users u ON u.user_email = t.user_email
         ORDER BY t.created_at DESC
         LIMIT $1`,
        [limit]
      ),
      pool.query(
        `SELECT
           id,
           user_email,
           to_email,
           subject,
           status,
           error,
           created_at,
           updated_at
         FROM email_logs
         ORDER BY created_at DESC
         LIMIT $1`,
        [limit]
      ),
    ]);

    return res.json({
      stats: {
        ...(userStatsQ.rows[0] || {}),
        ...(accountStatsQ.rows[0] || {}),
        ...(emailStatsQ.rows[0] || {}),
      },
      system: {
        admin_user: ADMIN_USER,
        mailer_ready: isMailerReady(),
        mailer_configured: hasMailerConfig(),
        mailer_error: getMailerError(),
        notify_email: BANKSWIFT_NOTIFY_EMAIL,
        app_base_url: APP_BASE_URL,
      },
      users: usersQ.rows,
      transactions: transactionsQ.rows,
      email_logs: emailLogsQ.rows,
    });
  } catch (err) {
    return handleError(res, "Admin overview error", err);
  }
});

app.post("/api/admin/users", adminAuthMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const fullname = String(req.body?.fullname || "").trim();
    const emailRaw = String(req.body?.email || req.body?.user_email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    const phone = String(req.body?.phone || "").trim();
    const accountname = String(req.body?.accountname || "").trim();
    const suspended = Boolean(req.body?.suspended ?? req.body?.restricted);
    const initialBalance = Number(req.body?.initialBalance ?? 0);

    if (!fullname) return res.status(400).json({ error: "Full name is required" });
    if (!validateEmail(emailRaw)) return res.status(400).json({ error: "Valid email is required" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    if (!Number.isFinite(initialBalance) || initialBalance < 0) {
      return res.status(400).json({ error: "initialBalance must be a valid non-negative number" });
    }

    await client.query("BEGIN");

    const existingQ = await client.query(
      "SELECT user_email FROM users WHERE LOWER(user_email)=LOWER($1) LIMIT 1",
      [emailRaw]
    );
    if (existingQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const createdQ = await client.query(
      `INSERT INTO users (fullname, user_email, password_hash, phone, accountname, suspended, available_balance)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING user_email, fullname, phone, accountname, suspended, created_at, updated_at`,
      [fullname, emailRaw, passwordHash, phone, accountname, suspended, initialBalance]
    );

    try {
      await client.query(
        `INSERT INTO user_profiles (
           user_email,
           dob,
           citizenship_status,
           address_line1,
           address_line2,
           city,
           state,
           postal_code,
           country,
           occupation,
           employer,
           mailing_same_as_residential,
           mailing_address_line1,
           mailing_address_line2,
           mailing_city,
           mailing_state,
           mailing_postal_code,
           mailing_country
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
         )
         ON CONFLICT (user_email) DO UPDATE SET
           dob=COALESCE(EXCLUDED.dob, user_profiles.dob),
           citizenship_status=COALESCE(EXCLUDED.citizenship_status, user_profiles.citizenship_status),
           address_line1=COALESCE(EXCLUDED.address_line1, user_profiles.address_line1),
           address_line2=COALESCE(EXCLUDED.address_line2, user_profiles.address_line2),
           city=COALESCE(EXCLUDED.city, user_profiles.city),
           state=COALESCE(EXCLUDED.state, user_profiles.state),
           postal_code=COALESCE(EXCLUDED.postal_code, user_profiles.postal_code),
           country=COALESCE(EXCLUDED.country, user_profiles.country),
           occupation=COALESCE(EXCLUDED.occupation, user_profiles.occupation),
           employer=COALESCE(EXCLUDED.employer, user_profiles.employer),
           mailing_same_as_residential=COALESCE(EXCLUDED.mailing_same_as_residential, user_profiles.mailing_same_as_residential),
           mailing_address_line1=COALESCE(EXCLUDED.mailing_address_line1, user_profiles.mailing_address_line1),
           mailing_address_line2=COALESCE(EXCLUDED.mailing_address_line2, user_profiles.mailing_address_line2),
           mailing_city=COALESCE(EXCLUDED.mailing_city, user_profiles.mailing_city),
           mailing_state=COALESCE(EXCLUDED.mailing_state, user_profiles.mailing_state),
           mailing_postal_code=COALESCE(EXCLUDED.mailing_postal_code, user_profiles.mailing_postal_code),
           mailing_country=COALESCE(EXCLUDED.mailing_country, user_profiles.mailing_country),
           updated_at=NOW()`,
        [
          emailRaw,
          req.body?.dob || null,
          toTrimmedOrNull(req.body?.citizenship_status),
          toTrimmedOrNull(req.body?.address_line1),
          toTrimmedOrNull(req.body?.address_line2),
          toTrimmedOrNull(req.body?.city),
          toTrimmedOrNull(req.body?.state),
          toTrimmedOrNull(req.body?.postal_code),
          toTrimmedOrNull(req.body?.country) || "US",
          toTrimmedOrNull(req.body?.occupation),
          toTrimmedOrNull(req.body?.employer),
          Object.prototype.hasOwnProperty.call(req.body || {}, "mailing_same_as_residential")
            ? Boolean(req.body?.mailing_same_as_residential)
            : true,
          toTrimmedOrNull(req.body?.mailing_address_line1),
          toTrimmedOrNull(req.body?.mailing_address_line2),
          toTrimmedOrNull(req.body?.mailing_city),
          toTrimmedOrNull(req.body?.mailing_state),
          toTrimmedOrNull(req.body?.mailing_postal_code),
          toTrimmedOrNull(req.body?.mailing_country) || "US",
        ]
      );
    } catch (profileErr) {
      if (!isMissingProfileTableError(profileErr)) throw profileErr;
    }

    const account = await ensureAvailableAccount(client, emailRaw);
    if (initialBalance > 0) {
      await client.query(
        `UPDATE accounts
         SET balance=$1, available=$2, updated_at=NOW()
         WHERE id=$3`,
        [initialBalance, initialBalance, account.id]
      );

      const reference = `ADMCRT-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
      await client.query(
        `INSERT INTO transactions
          (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
         VALUES ($1,$2,'credit',$3,$4,$5,'completed',$6,NOW())`,
        [
          emailRaw,
          account.id,
          initialBalance,
          "Admin new user opening balance",
          reference,
          initialBalance,
        ]
      );
    }

    await client.query("COMMIT");

    const sendWelcome = req.body?.sendDefaultEmail !== false;
    let emailResult = null;
    if (sendWelcome) {
      try {
        await sendAccountTemplateEmail({
          templateKey: "accountOpened",
          to: emailRaw,
          user: createdQ.rows[0],
          data: {
            status: suspended ? "restricted" : "active",
            account_balance: initialBalance.toFixed(2),
            note: initialBalance > 0
              ? "Your opening balance has already been posted and is available in your account."
              : "Your account is active and ready to receive activity.",
          },
          userId: emailRaw,
        });
        emailResult = { sent: true, template: "accountOpened" };
      } catch (emailErr) {
        emailResult = { sent: false, error: emailErr.message || "Email send failed" };
      }
    }

    const profile = await getAdminUserProfileByEmail(emailRaw);
    return res.status(201).json({
      user: profile || createdQ.rows[0],
      opening_balance: Number(initialBalance.toFixed(2)),
      default_email: emailResult,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return handleError(res, "Admin user create error", err);
  } finally {
    client.release();
  }
});

app.get("/api/admin/users/:email/profile", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const user = await getAdminUserProfileByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    return res.json(user);
  } catch (err) {
    return handleError(res, "Admin profile fetch error", err);
  }
});

app.get("/api/admin/users/:email/preferences", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const user = await getAdminUserProfileByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const preferences = await getUserPreferencesByEmail(email);
    return res.json({ user_email: email, ...preferences });
  } catch (err) {
    return handleError(res, "Admin preferences fetch error", err);
  }
});

app.put("/api/admin/users/:email/preferences", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const user = await getAdminUserProfileByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const preferences = await saveUserPreferencesByEmail(email, req.body || {});
    return res.json({ user_email: email, ...preferences });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ error: err.message });
    return handleError(res, "Admin preferences update error", err);
  }
});

app.get("/api/admin/users/:email/transfers", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const user = await getAdminUserProfileByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const transfers = await getUserTransferHistory(email, req.query?.limit || 25);
    return res.json({ user_email: email, transfers });
  } catch (err) {
    return handleError(res, "Admin transfers fetch error", err);
  }
});

app.post("/api/admin/users/:email/transfers", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const result = await createTransferForSender(email, req.body || {}, { allowSuspended: true, allowTransfersDisabled: true });
    return res.status(201).json(result);
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ error: err.message });
    return handleError(res, "Admin transfer create error", err);
  }
});

app.post("/api/admin/users/:email/password", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    const newPassword = String(req.body?.new_password || req.body?.password || "");
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    const updateQ = await pool.query(
      `UPDATE users
       SET password_hash=$1,
           updated_at=NOW()
       WHERE LOWER(user_email)=LOWER($2)
       RETURNING user_email, fullname, accountname`,
      [passwordHash, email]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = updateQ.rows[0];

    void (async () => {
      try {
        if (!canSendEmail() || !user.user_email) return;
        await sendAccountTemplateEmail({
          templateKey: "passwordChanged",
          to: user.user_email,
          user,
          userId: user.user_email,
        });
      } catch (e) {
        console.warn("Admin password reset email failed:", e.message);
      }
    })();

    return res.json({ success: true, user_email: user.user_email });
  } catch (err) {
    return handleError(res, "Admin password update error", err);
  }
});

app.patch("/api/admin/users/:email", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid user email" });
    }

    const allowedFields = {
      fullname: "fullname",
      phone: "phone",
      accountname: "accountname",
      suspended: "suspended",
    };
    const changedFields = Object.keys(allowedFields).filter((key) =>
      Object.prototype.hasOwnProperty.call(req.body || {}, key)
    );

    const updates = [];
    const values = [];
    let idx = 1;

    Object.entries(allowedFields).forEach(([key, column]) => {
      if (!Object.prototype.hasOwnProperty.call(req.body || {}, key)) return;
      const rawValue = req.body[key];
      const value = key === "suspended" ? Boolean(rawValue) : String(rawValue ?? "").trim();
      updates.push(`${column}=$${idx++}`);
      values.push(value);
    });

    if (!updates.length) {
      return res.status(400).json({ error: "No user changes provided" });
    }

    values.push(email);

    const updateQ = await pool.query(
      `UPDATE users
       SET ${updates.join(", ")}, updated_at=NOW()
       WHERE LOWER(user_email)=LOWER($${idx})
       RETURNING user_email, fullname, phone, accountname, suspended, created_at, updated_at`,
      values
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const accountQ = await pool.query(
      `SELECT
         COALESCE(COUNT(*), 0)::int AS account_count,
         COALESCE(SUM(balance), 0)::numeric AS balance_total,
         COALESCE(SUM(available), 0)::numeric AS available_total
       FROM accounts
       WHERE LOWER(user_email)=LOWER($1)`,
      [email]
    );

    const updatedUser = updateQ.rows[0];
    const accountSummary = accountQ.rows[0] || {};

    void (async () => {
      try {
        if (!canSendEmail() || !updatedUser.user_email) return;

        const labelMap = {
          fullname: "full name",
          phone: "phone number",
          accountname: "account name",
          suspended: "account access",
        };
        const changedFieldLabels = changedFields
          .map((field) => labelMap[field] || field)
          .join(", ");

        if (changedFields.includes("suspended")) {
          await sendAccountTemplateEmail({
            templateKey: "accountActivityUpdate",
            to: updatedUser.user_email,
            user: updatedUser,
            data: {
              action_label: updatedUser.suspended ? "Account access restricted" : "Account access restored",
              status: updatedUser.suspended ? "restricted" : "active",
              amount: "0.00",
              reference: "PROFILE-UPDATE",
              account_balance: Number(accountSummary.available_total ?? 0).toFixed(2),
              note: changedFieldLabels
                ? `Updated details: ${changedFieldLabels}.`
                : "Your account access settings were updated.",
            },
            userId: updatedUser.user_email,
          });
        } else {
          await sendAccountTemplateEmail({
            templateKey: "accountProfileUpdated",
            to: updatedUser.user_email,
            user: updatedUser,
            data: {
              status: updatedUser.suspended ? "restricted" : "active",
              changed_fields: changedFieldLabels || "profile details",
              account_balance: Number(accountSummary.available_total ?? 0).toFixed(2),
            },
            userId: updatedUser.user_email,
          });
        }
      } catch (e) {
        console.warn("Admin user update email failed:", e.message);
      }
    })();

    return res.json({
      ...updatedUser,
      ...accountSummary,
    });
  } catch (err) {
    return handleError(res, "Admin user update error", err);
  }
});

app.delete("/api/admin/users/:email", adminAuthMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid user email" });
    }
    if (email === ADMIN_USER) {
      return res.status(400).json({ error: "Cannot delete the admin account" });
    }

    await client.query("BEGIN");

    const existingQ = await client.query(
      `SELECT user_email, fullname
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );

    if (!existingQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    const countsQ = await client.query(
      `SELECT
         (SELECT COUNT(*)::int FROM user_profiles WHERE LOWER(user_email)=LOWER($1)) AS profiles,
         (SELECT COUNT(*)::int FROM user_documents WHERE LOWER(user_email)=LOWER($1)) AS documents,
         (SELECT COUNT(*)::int FROM accounts WHERE LOWER(user_email)=LOWER($1)) AS accounts,
         (SELECT COUNT(*)::int FROM transactions WHERE LOWER(user_email)=LOWER($1)) AS transactions,
         (SELECT COUNT(*)::int FROM password_reset_tokens WHERE LOWER(user_email)=LOWER($1)) AS password_resets`,
      [email]
    );

    const deletedQ = await client.query(
      `DELETE FROM users
       WHERE LOWER(user_email)=LOWER($1)
       RETURNING user_email, fullname`,
      [email]
    );

    await client.query("COMMIT");

    return res.json({
      deleted: deletedQ.rows[0],
      cascaded: countsQ.rows[0] || {},
      note: "Email logs retain history and clear their user reference automatically.",
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return handleError(res, "Admin user delete error", err);
  } finally {
    client.release();
  }
});

app.post("/api/admin/users/:email/adjust-balance", adminAuthMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid user email" });
    }

    const direction = String(req.body?.direction || "credit").trim().toLowerCase();
    const amount = Number(req.body?.amount);
    const description = String(req.body?.description || "Admin manual balance adjustment").trim();

    if (!["credit", "debit"].includes(direction)) {
      return res.status(400).json({ error: "Direction must be credit or debit" });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: "Amount must be greater than 0" });
    }

    await client.query("BEGIN");

    const userQ = await client.query(
      `SELECT user_email, fullname, accountname
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1
       FOR UPDATE`,
      [email]
    );

    if (!userQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    const user = userQ.rows[0];
    const account = await ensureAvailableAccount(client, user.user_email);
    const delta = direction === "debit" ? -amount : amount;
    const nextBalance = Number(account.balance || 0) + delta;
    const nextAvailable = Number(account.available || 0) + delta;

    if (nextBalance < 0 || nextAvailable < 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient funds for manual debit" });
    }

    await client.query(
      `UPDATE accounts
       SET balance=$1,
           available=$2,
           updated_at=NOW()
       WHERE id=$3`,
      [nextBalance, nextAvailable, account.id]
    );

    await client.query(
      `UPDATE users
       SET available_balance=available_balance+$1,
           updated_at=NOW()
       WHERE user_email=$2`,
      [delta, user.user_email]
    );

    const reference = `ADMIN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    const txQ = await client.query(
      `INSERT INTO transactions
        (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,'completed',$7,NOW())
       RETURNING id, user_email, direction, amount, description, reference, status, balance_after, created_at`,
      [
        user.user_email,
        account.id,
        direction,
        amount,
        description,
        reference,
        nextAvailable,
      ]
    );

    await client.query("COMMIT");

    void (async () => {
      try {
        if (!canSendEmail() || !user.user_email) return;

        await sendAccountTemplateEmail({
          templateKey: "balanceAdjustmentPosted",
          to: user.user_email,
          user,
          data: {
            status: "completed",
            amount: amount.toFixed(2),
            reference,
            account_balance: nextAvailable.toFixed(2),
            note: description,
          },
          userId: user.user_email,
        });
      } catch (e) {
        console.warn("Balance adjustment email failed:", e.message);
      }
    })();

    return res.json({
      success: true,
      user_email: user.user_email,
      fullname: user.fullname,
      balance: nextBalance,
      available: nextAvailable,
      transaction: txQ.rows[0],
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return handleError(res, "Admin balance adjustment error", err);
  } finally {
    client.release();
  }
});

app.put("/api/admin/users/:email/profile", adminAuthMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    await client.query("BEGIN");

    const userExistsQ = await client.query(
      "SELECT user_email FROM users WHERE LOWER(user_email)=LOWER($1) LIMIT 1",
      [email]
    );
    if (!userExistsQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    const userAllowed = {
      fullname: "fullname",
      phone: "phone",
      accountname: "accountname",
      suspended: "suspended",
    };
    const userChangedFields = Object.keys(userAllowed).filter((field) =>
      Object.prototype.hasOwnProperty.call(req.body || {}, field)
    );

    const userUpdates = [];
    const userValues = [];
    let userIndex = 1;

    Object.entries(userAllowed).forEach(([key, column]) => {
      if (!Object.prototype.hasOwnProperty.call(req.body || {}, key)) return;
      const value = key === "suspended" ? Boolean(req.body[key]) : String(req.body[key] ?? "").trim();
      userUpdates.push(`${column}=$${userIndex++}`);
      userValues.push(value);
    });

    if (userUpdates.length) {
      userValues.push(email);
      await client.query(
        `UPDATE users
         SET ${userUpdates.join(", ")}, updated_at=NOW()
         WHERE LOWER(user_email)=LOWER($${userIndex})`,
        userValues
      );
    }

    const profileAllowed = [
      "dob",
      "citizenship_status",
      "address_line1",
      "address_line2",
      "city",
      "state",
      "postal_code",
      "country",
      "occupation",
      "employer",
      "mailing_same_as_residential",
      "mailing_address_line1",
      "mailing_address_line2",
      "mailing_city",
      "mailing_state",
      "mailing_postal_code",
      "mailing_country",
    ];

    const providedProfileFields = profileAllowed.filter((field) =>
      Object.prototype.hasOwnProperty.call(req.body || {}, field)
    );

    if (providedProfileFields.length) {
      const insertColumns = ["user_email", ...providedProfileFields];
      const insertValues = [email, ...providedProfileFields.map((field) => {
        if (field === "mailing_same_as_residential") {
          return Boolean(req.body[field]);
        }
        if (field === "dob") {
          return req.body[field] || null;
        }
        return toTrimmedOrNull(req.body[field]);
      })];

      const placeholders = insertColumns.map((_, i) => `$${i + 1}`);
      const updateClause = providedProfileFields
        .map((column) => `${column}=EXCLUDED.${column}`)
        .concat("updated_at=NOW()")
        .join(", ");

      try {
        await client.query(
          `INSERT INTO user_profiles (${insertColumns.join(", ")})
           VALUES (${placeholders.join(", ")})
           ON CONFLICT (user_email) DO UPDATE SET ${updateClause}`,
          insertValues
        );
      } catch (profileErr) {
        if (!isMissingProfileTableError(profileErr)) throw profileErr;
      }
    }

    await client.query("COMMIT");

    const updated = await getAdminUserProfileByEmail(email);

    void (async () => {
      try {
        if (!canSendEmail() || !updated?.user_email) return;

        const labelMap = {
          fullname: "full name",
          phone: "phone number",
          accountname: "account name",
          suspended: "account access",
          dob: "date of birth",
          citizenship_status: "citizenship status",
          address_line1: "address line 1",
          address_line2: "address line 2",
          city: "city",
          state: "state",
          postal_code: "postal code",
          country: "country",
          occupation: "occupation",
          employer: "employer",
          mailing_same_as_residential: "mailing preference",
          mailing_address_line1: "mailing address line 1",
          mailing_address_line2: "mailing address line 2",
          mailing_city: "mailing city",
          mailing_state: "mailing state",
          mailing_postal_code: "mailing postal code",
          mailing_country: "mailing country",
        };
        const changedFieldLabels = [...userChangedFields, ...providedProfileFields]
          .map((field) => labelMap[field] || field)
          .join(", ");
        const includesStatusChange = userChangedFields.includes("suspended");

        await sendAccountTemplateEmail({
          templateKey: includesStatusChange ? "accountActivityUpdate" : "accountProfileUpdated",
          to: updated.user_email,
          user: updated,
          data: includesStatusChange
            ? {
              action_label: updated.suspended ? "Account access restricted" : "Account access restored",
              status: updated.suspended ? "restricted" : "active",
              amount: "0.00",
              reference: "PROFILE-UPDATE",
              account_balance: Number(updated.available_total ?? 0).toFixed(2),
              note: changedFieldLabels
                ? `Updated details: ${changedFieldLabels}.`
                : "Your account profile details were updated.",
            }
            : {
              status: updated.suspended ? "restricted" : "active",
              changed_fields: changedFieldLabels || "profile details",
              account_balance: Number(updated.available_total ?? 0).toFixed(2),
            },
          userId: updated.user_email,
        });
      } catch (e) {
        console.warn("Admin profile update email failed:", e.message);
      }
    })();

    return res.json(updated || { user_email: email });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return handleError(res, "Admin profile update error", err);
  } finally {
    client.release();
  }
});

app.post("/api/admin/users/:email/send-default-email", adminAuthMiddleware, async (req, res) => {
  try {
    const email = normalizeEmailParam(req.params.email);
    if (!validateEmail(email)) return res.status(400).json({ error: "Invalid user email" });

    if (!canSendEmail()) {
      return res.status(503).json({ error: getMailerUnavailableMessage() });
    }

    await ensureMailerReady();
    if (!isMailerReady()) {
      return res.status(503).json({ error: getMailerUnavailableMessage() });
    }

    const userQ = await pool.query(
      `SELECT user_email, fullname, accountname
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });

    const mode = String(req.body?.mode || "template").trim().toLowerCase() === "custom"
      ? "custom"
      : "template";
    const templateKey = String(req.body?.templateKey || "accountOpened").trim();
    const toEmail = String(req.body?.to || email).trim().toLowerCase();
    if (!validateEmail(toEmail)) return res.status(400).json({ error: "Invalid recipient email" });

    const data = toAdminTemplateData(userQ.rows[0], req.body?.data || {});

    let responseTemplateKey = null;
    let subject = "";
    let title = "";
    let preheader = "";
    let text = "";
    let bodyHtml = "";

    if (mode === "custom") {
      subject = String(req.body?.subject || "").trim();
      title = String(req.body?.title || "").trim() || subject;
      preheader = String(req.body?.preheader || "").trim();
      text = String(req.body?.text || "").trim();

      if (!subject) {
        return res.status(400).json({ error: "Custom emails require a subject" });
      }

      if (!text) {
        return res.status(400).json({ error: "Custom emails require message text" });
      }

      bodyHtml = plainTextToEmailHtml(text) || `<p>${escapeHtml(subject)}</p>`;
    } else {
      const templates = loadEmailTemplates();
      const template = templates[templateKey];

      if (!template || typeof template !== "object") {
        return res.status(400).json({
          error: "Invalid templateKey",
          availableTemplates: Object.keys(templates),
        });
      }

      responseTemplateKey = templateKey;
      subject = renderTemplate(
        req.body?.subjectOverride || template.subject || "Notification",
        data.plain
      );
      title = renderTemplate(
        req.body?.titleOverride || template.title || subject,
        data.plain
      );
      preheader = renderTemplate(
        req.body?.preheaderOverride || template.preheader || "",
        data.plain
      );
      text = renderTemplate(
        req.body?.textOverride || template.text || subject,
        data.plain
      );
      bodyHtml = typeof template.bodyHtml === "string" && template.bodyHtml.trim()
        ? renderTemplate(template.bodyHtml, data.html)
        : (plainTextToEmailHtml(text) || `<p>${escapeHtml(subject)}</p>`);
    }

    await sendBrandedEmail({
      to: toEmail,
      subject,
      title,
      preheader,
      text,
      bodyHtml,
      userId: userQ.rows[0].user_email,
    });

    return res.json({
      success: true,
      to: toEmail,
      mode,
      templateKey: responseTemplateKey,
      subject,
      message: mode === "custom" ? "Custom email sent successfully" : "Default email sent successfully",
    });
  } catch (err) {
    return handleError(res, "Admin manual default email error", err);
  }
});

app.get("/api/admin/email-templates", adminAuthMiddleware, async (req, res) => {
  try {
    return res.json(stripTemplateHtmlFields(loadEmailTemplates()));
  } catch (err) {
    return handleError(res, "Admin email templates fetch error", err);
  }
});

app.put("/api/admin/email-templates", adminAuthMiddleware, async (req, res) => {
  try {
    const templates = req.body;
    if (!templates || typeof templates !== "object" || Array.isArray(templates)) {
      return res.status(400).json({ error: "Templates payload must be an object" });
    }

    const nextTemplates = stripTemplateHtmlFields({
      ...stripTemplateHtmlFields(DEFAULT_EMAIL_TEMPLATES),
      ...templates,
    });

    saveEmailTemplates(nextTemplates);
    return res.json(nextTemplates);
  } catch (err) {
    return handleError(res, "Admin email templates update error", err);
  }
});

// View email in browser
app.get("/emails/:id", async (req, res) => {
  const q = await pool.query(
    "SELECT html_body FROM email_logs WHERE id=$1 LIMIT 1",
    [req.params.id]
  );
  if (!q.rowCount) return res.status(404).send("Email not found");
  return res.send(q.rows[0].html_body);
});

// Register
app.post("/api/users", async (req, res) => {
  try {
    const {
      fullname,
      phone = "",
      email,
      user_email,
      password,
      accountname = "",
    } = req.body || {};

    const emailIn = email ?? user_email;

    if (!fullname || !emailIn || !password) {
      return res.status(400).json({ error: "Full name, email, and password required" });
    }
    if (!validateEmail(emailIn)) return res.status(400).json({ error: "Valid email required" });
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 chars" });
    }

    const normEmail = String(emailIn).trim().toLowerCase();

    const existing = await pool.query("SELECT user_email FROM users WHERE user_email = $1", [normEmail]);
    if (existing.rowCount) return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const insertUser = await client.query(
        `INSERT INTO users (fullname, user_email, password_hash, phone, accountname)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING fullname, user_email AS email, accountname`,
        [
          String(fullname).trim(),
          normEmail,
          passwordHash,
          String(phone || "").trim(),
          String(accountname || "").trim(),
        ]
      );

      const user = insertUser.rows[0];

      await ensureAvailableAccount(client, user.email);

      const allAccQ = await client.query(
        "SELECT id, type, balance, available, currency FROM accounts WHERE user_email=$1 ORDER BY created_at ASC NULLS LAST",
        [user.email]
      );

      await client.query("COMMIT");

      const accounts = allAccQ.rows || [];
      const availableBalance = Number(
        accounts.reduce((sum, account) => sum + Number(account.available ?? account.balance ?? 0), 0).toFixed(2)
      );
      const token = issueToken({ email: user.email });

      void (async () => {
        try {
          if (canSendEmail()) {
            await sendAccountTemplateEmail({
              templateKey: "accountOpened",
              to: user.email,
              user,
              data: {
                status: "active",
                account_balance: availableBalance.toFixed(2),
                note: "This public sign-up flow does not request Social Security numbers or document uploads.",
              },
              userId: user.email,
            });
          }
        } catch (e) {
          console.warn("Welcome email failed:", e.message);
        }

        try {
          if (canSendEmail() && BANKSWIFT_NOTIFY_EMAIL) {
            await sendAdminNotificationEmail({
              subject: "New registration received",
              text:
                `New registration received.\n\n` +
                `User: ${user.fullname || "N/A"} (${normEmail})\n` +
                `Phone: ${String(phone || "").trim() || "N/A"}\n` +
                `Account name: ${String(accountname || "").trim() || "N/A"}`,
            });
          }
        } catch (e) {
          console.warn("Registration notify email failed:", e.message);
        }
      })();

      return res.status(201).json({
        message: "User created successfully",
        token,
        id: user.email,
        fullname: user.fullname,
        email: user.email,
        accountname: user.accountname,
        available_balance: availableBalance,
        balances: { available: availableBalance, total: availableBalance, accounts },

      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      return handleError(res, "Registration error", err);
    } finally {
      client.release();
    }
  } catch (err) {
    return handleError(res, "Registration error (outer)", err);
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const sendError = (status, message) => {
    res.status(status);
    return res.json({ error: message });
  };

  try {
    const emailRaw = req.body.user_email || req.body.email || ""; // accept both frontend fields
    const email = String(emailRaw).trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return sendError(400, "Missing credentials");
    }

    const q = await pool.query(
      `SELECT
         fullname,
         user_email,
         accountname,
         COALESCE(available_balance, 0) AS available_balance,
         password_hash,
         suspended
       FROM users
       WHERE user_email = $1
       LIMIT 1`,
      [email.toLowerCase()]
    );

    if (!q.rowCount) {
      return sendError(401, "Invalid email or password");
    }

    const user = q.rows[0];
    user.email = user.user_email;

    if (user.suspended) {
      return sendError(403, "Account restricted");
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return sendError(401, "Invalid email or password");
    }

    const generatedJWT = issueToken({
      email: user.user_email,
    });

    const accQ = await pool.query(
      "SELECT COALESCE(SUM(available), 0) AS available_balance FROM accounts WHERE user_email=$1",
      [user.user_email]
    );
    const accountsAvailable = Number(accQ.rows?.[0]?.available_balance ?? 0);
    const availableBalance = accountsAvailable || Number(user.available_balance ?? 0);

    return res.json({
      id: user.email,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      available_balance: availableBalance,
      token: generatedJWT
    });
  } catch (err) {
    console.error("Login error", err);
    res.status(500);
    if (NODE_ENV === "production") return res.json({ error: "Server error" });
    return res.json({ error: err?.message || "Server error", stack: err?.stack });
  }
});

// Current user
app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || DEFAULT_USER_UUID;

    // Use bank.js to fetch user
    const user = await getUser(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Fetch accounts
    const accQ = await pool.query(
      "SELECT id, type, balance, available, currency FROM accounts WHERE user_email=$1",
      [userId]
    );
    const accounts = accQ.rows || [];
    const accountsAvailable = Number(
      accounts.reduce((sum, account) => sum + Number(account.available ?? account.balance ?? 0), 0).toFixed(2)
    );
    const availableBalance = accounts.length
      ? accountsAvailable
      : Number(user.available_balance ?? 0);

    return res.json({
      id: user.user_email,
      fullname: user.fullname,
      phone: user.phone || "",
      email: user.user_email,
      accountname: user.accountname,
      available_balance: availableBalance,
      balances: { available: availableBalance, total: availableBalance, accounts },
    });
  } catch (err) {
    return handleError(res, "Profile fetch error", err);
  }
});

app.put("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || DEFAULT_USER_UUID;
    const fullname = String(req.body?.fullname || "").trim();
    const phone = String(req.body?.phone || "").trim();

    if (!fullname) {
      return res.status(400).json({ error: "Full name is required" });
    }

    const updateQ = await pool.query(
      `UPDATE users
       SET fullname = $1,
           phone = $2
       WHERE user_email = $3
       RETURNING user_email AS id, fullname, phone, user_email AS email, accountname, suspended`,
      [fullname, phone, userId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedUser = updateQ.rows[0];

    try {
      if (canSendEmail() && updatedUser.email) {
        await sendAccountTemplateEmail({
          templateKey: "accountProfileUpdated",
          to: updatedUser.email,
          user: updatedUser,
          data: {
            status: updatedUser.suspended ? "restricted" : "active",
            changed_fields: "full name, phone number",
          },
          userId: updatedUser.email,
        });
      }
    } catch (e) {
      console.warn("Profile update email failed:", e.message);
    }

    return res.json(updatedUser);
  } catch (err) {
    return handleError(res, "Profile update error", err);
  }
});

app.get("/api/users/preferences", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || normalizeDbUserId(req.user?.sub);
    const user = await getUser(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const preferences = await getUserPreferencesByEmail(userId);
    return res.json({ user_email: userId, ...preferences });
  } catch (err) {
    return handleError(res, "Preferences fetch error", err);
  }
});

app.put("/api/users/preferences", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || normalizeDbUserId(req.user?.sub);
    const user = await getUser(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const preferences = await saveUserPreferencesByEmail(userId, req.body || {});
    return res.json({ user_email: userId, ...preferences });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ error: err.message });
    return handleError(res, "Preferences update error", err);
  }
});

app.get("/api/stream/user/:id", authMiddleware, async (req, res) => {
  const userId = normalizeDbUserId(req.params.id);
  const authedUserId = req.userId || normalizeDbUserId(req.user?.sub);

  if (!userId || userId !== authedUserId) {
    return res.status(403).json({ error: "Forbidden" });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  if (typeof res.flushHeaders === "function") res.flushHeaders();

  res.write(`data: ${JSON.stringify({ connected: true })}\n\n`);

  let closed = false;

  const sendSnapshot = async () => {
    if (closed) return;
    try {
      const userQ = await pool.query(
        "SELECT user_email AS id, fullname, user_email AS email, accountname, COALESCE(available_balance, 0) AS available_balance FROM users WHERE user_email=$1",
        [userId]
      );

      if (!userQ.rowCount) {
        res.write(`event: error\ndata: ${JSON.stringify({ error: "User not found" })}\n\n`);
        return;
      }

      const profile = userQ.rows[0];
      const accQ = await pool.query(
        "SELECT id, type, balance, available, currency FROM accounts WHERE user_email=$1",
        [userId]
      );
      const accounts = accQ.rows || [];
      const accountsAvailable = Number(
        accounts.reduce((sum, account) => sum + Number(account.available ?? account.balance ?? 0), 0).toFixed(2)
      );
      const availableBalance = accounts.length
        ? accountsAvailable
        : Number(profile.available_balance ?? 0);
      const payload = {
        id: profile.id,
        fullname: profile.fullname,
        email: profile.email,
        accountname: profile.accountname,
        available_balance: availableBalance,
      };

      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch (err) {
      res.write(`event: error\ndata: ${JSON.stringify({ error: "stream_update_failed" })}\n\n`);
    }
  };

  await sendSnapshot();

  const updateInterval = setInterval(sendSnapshot, 15000);
  const keepAlive = setInterval(() => {
    if (!closed) res.write(`: keep-alive\n\n`);
  }, 20000);

  req.on("close", () => {
    closed = true;
    clearInterval(updateInterval);
    clearInterval(keepAlive);
    try {
      res.end();
    } catch {}
  });
});

// Change password (settings.html expects POST /api/users/password with { new_password })
app.post("/api/users/password", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || normalizeDbUserId(req.user?.sub);
    const { new_password } = req.body || {};

    if (typeof new_password !== "string" || new_password.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    const newHash = await bcrypt.hash(new_password, 10);

    const updateQ = await pool.query(
      `UPDATE users
       SET password_hash = $1,
           updated_at = now()
       WHERE user_email = $2
       RETURNING fullname, accountname, user_email AS email`,
      [newHash, userId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const accountUser = updateQ.rows[0];

    try {
      if (canSendEmail() && accountUser.email) {
        await sendAccountTemplateEmail({
          templateKey: "passwordChanged",
          to: accountUser.email,
          user: accountUser,
          userId: accountUser.email,
        });
      }
    } catch (e) {
      console.warn("Password change email failed:", e.message);
    }

    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Change password error", err);
  }
});

// Forgot password (forgot-password.html posts to /api/password/forgot with { email })
app.post("/api/password/forgot", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Valid email required" });
    }

    // Always return generic success to prevent email enumeration
    const generic = {
      success: true,
      message: "If that email exists, a reset link has been sent.",
    };

    // If mailer is essential, fail loudly (your request said essential)
    if (!canSendEmail()) {
      return res.status(501).json({
        error: "Email is not configured on this server. Set SENDGRID_API_KEY.",
      });
    }

    await ensureMailerReady();
    if (!isMailerReady()) {
      return res.status(503).json({ error: getMailerUnavailableMessage() });
    }

    const uQ = await pool.query(
      `SELECT user_email, fullname, accountname
       FROM users
       WHERE user_email = $1
       LIMIT 1`,
      [email]
    );

    if (!uQ.rowCount) return res.json(generic);

    const user = uQ.rows[0];

    // Create token + store hash
    const rawToken = makeToken(32); // base64url string
    const tokenHash = sha256Hex(rawToken);

    // 1 hour expiry
    const expires = new Date(Date.now() + 60 * 60 * 1000);

    // Optional: clean old tokens for this user (keeps table tidy)
    await pool.query(
      `DELETE FROM password_reset_tokens
       WHERE user_email = $1 OR expires_at < now() OR used_at IS NOT NULL`,
      [user.user_email]
    );

    await pool.query(
      `INSERT INTO password_reset_tokens (user_email, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.user_email, tokenHash, expires]
    );

    const base = getAppBaseUrl(req);
    const resetLink = `${base}/reset-password.html?token=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}`;

    await sendAccountTemplateEmail({
      templateKey: "passwordResetRequested",
      to: email,
      user,
      data: {
        reset_link: resetLink,
        expiry_window: "1 hour",
      },
      userId: user.user_email,
    });

    return res.json(generic);
  } catch (err) {
    return handleError(res, "Forgot password error", err);
  }
});

// Reset password (POST /api/password/reset with { token, email, new_password })
app.post("/api/password/reset", async (req, res) => {
  const client = await pool.connect();
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const token = String(req.body?.token || "").trim();
    const new_password = String(req.body?.new_password || "");

    if (!validateEmail(email)) return res.status(400).json({ error: "Valid email required" });
    if (!token) return res.status(400).json({ error: "Missing token" });
    if (new_password.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    const tokenHash = sha256Hex(token);

    await client.query("BEGIN");

    // Find matching token + user
    const q = await client.query(
      `SELECT
         t.id AS token_id,
         t.user_email,
         t.expires_at,
         t.used_at,
         u.fullname,
         u.accountname
       FROM password_reset_tokens t
       JOIN users u ON u.user_email = t.user_email
       WHERE t.user_email = $1
         AND t.token_hash = $2
       LIMIT 1
       FOR UPDATE`,
      [email, tokenHash]
    );

    if (!q.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid or expired reset link" });
    }

    const row = q.rows[0];

    if (row.used_at) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "This reset link has already been used" });
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Reset link expired. Request a new one." });
    }

    const newHash = await bcrypt.hash(new_password, 10);

    await client.query(
      `UPDATE users
       SET password_hash = $1,
           updated_at = now()
       WHERE user_email = $2`,
      [newHash, row.user_email]
    );

    await client.query(
      `UPDATE password_reset_tokens
       SET used_at = now()
       WHERE id = $1`,
      [row.token_id]
    );

    await client.query("COMMIT");

    try {
      if (canSendEmail() && row.user_email) {
        await sendAccountTemplateEmail({
          templateKey: "passwordResetCompleted",
          to: row.user_email,
          user: row,
          userId: row.user_email,
        });
      }
    } catch (e) {
      console.warn("Password reset confirmation email failed:", e.message);
    }

    return res.json({ success: true, message: "Password has been reset." });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    return handleError(res, "Reset password error", err);
  } finally {
    client.release();
  }
});

// Transactions (recent)
app.get("/api/transactions", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || DEFAULT_USER_UUID;

    // Get the default account for the user
    const account = await getOrCreateAccount(userId, "available");
    if (!account) return res.json([]);

    // Fetch transactions for this user using bank.js
    const transactions = await getTransactions(userId, 100);

    // Enrich with account type and currency
    const enriched = transactions.map(t => ({
      ...t,
      account_type: account.type,
      currency: account.currency || "USD",
      total_balance_after: t.balance_after
    }));

    return res.json(enriched);
  } catch (err) {
    return handleError(res, "Transactions error", err);
  }
});

app.get("/api/transactions/:id/receipt", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || DEFAULT_USER_UUID;
    const txId = String(req.params.id || "").trim();
    if (!txId) return res.status(400).json({ error: "Transaction id is required" });
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(txId)) {
      return res.status(400).json({ error: "Invalid transaction id" });
    }

    const q = await pool.query(
      `SELECT
          t.id,
          t.user_email,
          t.account_id,
          COALESCE(NULLIF(t.type, ''), t.direction) AS type,
          t.direction,
          COALESCE(NULLIF(t.status, ''), 'completed') AS status,
          t.amount,
          t.description,
          t.reference,
          t.created_at,
          t.balance_after,
          a.type AS account_type,
          u.accountname,
          u.fullname
       FROM transactions t
       JOIN accounts a ON a.id = t.account_id
       JOIN users u ON u.user_email = a.user_email
       WHERE t.id = $1
         AND a.user_email = $2
       LIMIT 1`,
      [txId, userId]
    );

    if (!q.rowCount) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    const tx = q.rows[0];
    const pdf = await generateTransactionReceiptPDF({
      tx,
      accountName: tx.accountname || tx.fullname || tx.account_type || "Account",
    });

    const fileName = `receipt-${String(tx.reference || tx.id || "transaction").replace(/[^a-zA-Z0-9_-]/g, "")}.pdf`;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    return res.send(pdf);
  } catch (err) {
    return handleError(res, "Transaction receipt error", err);
  }
});

app.get("/api/payments", authMiddleware, async (req, res) => {
  return sendDisabledPublicFlow(res);
});

app.post("/api/payments", authMiddleware, async (req, res) => {
  return sendDisabledPublicFlow(res);
});

// Transfer and disabled public flow routes
app.post("/api/transfers", authMiddleware, async (req, res) => {
  try {
    const senderEmail = normalizeDbUserId(req.userId || req.user?.email || DEFAULT_USER_UUID);
    const result = await createTransferForSender(senderEmail, req.body || {});
    return res.json(result);
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ error: err.message });
    return handleError(res, "Transfers create error", err);
  }
});

app.post("/api/loans", authMiddleware, async (req, res) => {
  return sendDisabledPublicFlow(res);
});

app.get("/api/loans", authMiddleware, async (req, res) => {
  return sendDisabledPublicFlow(res);
});

app.post("/api/loans/:id/pay-fee", authMiddleware, async (req, res) => {
  return sendDisabledPublicFlow(res);
});

// --- Static hosting (frontend) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STATIC_PRIVATE_PATHS = [
  /^\/(?:server|bank|generate-jwt(?:-with-new-secret)?|index)\.js$/i,
  /^\/(?:package(?:-lock)?\.json|README\.md|CONTRIBUTING\.md|LICENSE|neon_workflow\.yml|postgres-schema(?:-user-email-reference)?\.sql)$/i,
  /^\/(?:cypress|data|scripts|uploads|utils)(?:\/|$)/i,
];

app.use((req, res, next) => {
  const requestPath = (() => {
    try {
      return decodeURIComponent(req.path || "/");
    } catch {
      return req.path || "/";
    }
  })();

  if (STATIC_PRIVATE_PATHS.some((pattern) => pattern.test(requestPath))) {
    return res.status(404).end();
  }

  return next();
});

// Serve files from your project folder (index.html, login.html, ui.css, etc.)
app.use(express.static(__dirname, { dotfiles: "ignore", extensions: ["html"], index: false }));

// If you hit "/", serve index.html
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// SPA-like fallback (optional): any non-api route serves index.html
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// --- Start ---
app.listen(PORT, () => {
  console.log(`🚀 Server running at ${BASE_URL} (env=${NODE_ENV})`);
  console.log(`🚀 Server listening on port ${PORT}`);
});

setTimeout(() => {
  getDB().catch((err) => {
    console.warn("Background DB warmup failed:", err?.message || err);
  });

  ensureMailerReady().catch((err) => {
    console.warn("Background mailer warmup failed:", err?.message || err);
  });
}, 2000);
