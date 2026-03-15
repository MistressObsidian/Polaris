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
 * - Works with users + accounts + transactions + transfers schema
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
import { Pool } from "pg";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { initMailer as initMailerUtils, sendEmail, isMailerReady } from "./utils/mailer.js";
import multer from "multer";
import PDFDocument from "pdfkit";
import { initBank, createUser, getUser, getUserBalance, updateUserBalance, getOrCreateAccount, getAccount, addTransaction, getTransactions, getTransactionWithDetails, makeInternalTransfer, makeExternalTransfer, getTransfers, applyLoan, approveLoan, getUserLoans, getLoan, payLoanFee } from "./bank.js";


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
  email: !!(process.env.SMTP_HOST || process.env.EMAIL_HOST),
});

const PORT = Number(process.env.PORT) || 4000;

const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL in environment");
  process.exit(1);
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

function normalizeSSN(input) {
  const digits = String(input || "").replace(/\D/g, "");
  return digits.length === 9 ? digits : "";
}

function ssnHash(ssnDigits) {
  const secret = process.env.SSN_HASH_SECRET || "";
  if (!secret) return "";
  return crypto.createHmac("sha256", secret).update(String(ssnDigits)).digest("hex");
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

    try {
      const loanLock = await pool.query(
        "SELECT locked FROM loans WHERE user_email=$1 AND locked=true LIMIT 1",
        [req.userId]
      );

      if (loanLock.rowCount) {
        return res.status(403).json({
          error: "Account temporarily locked pending loan processing fee."
        });
      }
    } catch (err) {
      if (err?.code !== "42P01" && err?.code !== "42703") {
        throw err;
      }
    }

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

function toAdminTemplateData(user = {}, extraData = {}) {
  const base = {
    fullname: user.fullname || "there",
    borrower_name: user.fullname || "there",
    recipient_name: user.fullname || "there",
    account_name: user.accountname || "",
    email: user.user_email || "",
    status: "pending",
    amount: "0.00",
    term: "N/A",
    apr_estimate: "N/A",
    monthly_payment_estimate: "N/A",
    bank_name: "N/A",
    routing_number: "N/A",
    account_number: "N/A",
    fee: "0.00",
    expires_at: new Date(Date.now() + (48 * 60 * 60 * 1000)).toLocaleString(),
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

async function adminApproveLoanRecord(loanId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const loanQ = await client.query(
      `SELECT id, user_email, amount, term_months, status, fee_paid, locked
       FROM loans
       WHERE id=$1
       LIMIT 1
       FOR UPDATE`,
      [loanId]
    );

    if (!loanQ.rowCount) {
      await client.query("ROLLBACK");
      return null;
    }

    const loan = loanQ.rows[0];
    if (String(loan.status || "").toLowerCase() === "approved") {
      await client.query("COMMIT");
      return loan;
    }

    const amount = Number(loan.amount || 0);
    const account = await ensureAvailableAccount(client, loan.user_email);
    const nextBalance = Number(account.balance || 0) + amount;
    const nextAvailable = Number(account.available || 0) + amount;

    await client.query(
      `UPDATE loans
       SET status='approved',
           locked=false,
           updated_at=NOW()
       WHERE id=$1`,
      [loanId]
    );

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
      [amount, loan.user_email]
    );

    const reference = `ADMLOAN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    await client.query(
      `INSERT INTO transactions
        (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
       VALUES ($1,$2,'credit',$3,$4,$5,'completed',$6,NOW())`,
      [
        loan.user_email,
        account.id,
        amount,
        `Admin approved loan ${loan.id}`,
        reference,
        nextAvailable,
      ]
    );

    const updatedLoanQ = await client.query(
      `SELECT id, user_email, amount, term_months, status, fee_paid, locked, created_at, updated_at
       FROM loans
       WHERE id=$1
       LIMIT 1`,
      [loanId]
    );

    await client.query("COMMIT");
    return updatedLoanQ.rows[0] || loan;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---- Uploads (KYC docs) ----
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase() || "";
    const safeExt = [".png", ".jpg", ".jpeg", ".webp", ".pdf"].includes(ext) ? ext : "";
    cb(null, `${crypto.randomUUID()}${safeExt}`);
  },
});

function fileFilter(req, file, cb) {
  const ok = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/pdf",
  ].includes(file.mimetype);
  if (!ok) return cb(new Error("Only PNG, JPG, WEBP, or PDF files are allowed"));
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB per file
});

// Fields we accept from the register form
const registerUploads = upload.fields([
  { name: "gov_id_front", maxCount: 1 },
  { name: "gov_id_back", maxCount: 1 },
  { name: "proof_of_address", maxCount: 1 },
]);

// --- Postgres Pool ---
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: getSSLFromDatabaseUrl(DATABASE_URL),
});

// Initialize bank module and verify DB
(async function verifyDB() {
  try {
    await pool.query("SELECT 1");
    
    // Initialize bank module with pool
    initBank(pool);

    console.log("✅ Postgres connected");
    console.log("✅ Bank module initialized");
  } catch (e) {
    console.error("❌ Postgres connection failed at startup:", e);
    process.exit(1);
  }
})();

function canSendEmail() {
  return isMailerReady();
}

// ---- Branded Email Helper (logo on every email) ----
const APP_BASE_URL = (process.env.APP_BASE_URL || BASE_URL).replace(/\/+$/, "");
const BRAND = {
  name: process.env.BRAND_NAME || "Base Credit",
  supportEmail: process.env.SUPPORT_EMAIL || process.env.MAIL_FROM || "",
  logoPath: process.env.BRAND_LOGO_PATH || path.join(process.cwd(), "assets", "logo-base-credit.svg"),
  logoCid: "logocid", // referenced in HTML as cid:logocid
};
const BANKSWIFT_NOTIFY_EMAIL = process.env.BANKSWIFT_NOTIFY_EMAIL || "";
const GS_LOG_ENDPOINT = process.env.GS_LOG_ENDPOINT || "";
const GS_LOG_SECRET = process.env.GS_LOG_SECRET || process.env.SHEETS_SECRET || "";

const EMAIL_TEMPLATES_PATH = path.join(process.cwd(), "data", "email-templates.json");
const APP_SETTINGS_PATH = path.join(process.cwd(), "data", "app-settings.json");
const DEFAULT_EMAIL_TEMPLATES = {
  transferSender: {
    subject: "Transfer update",
    title: "Transfer update",
    preheader: "Your transfer of ${{amount}} is {{status}}.",
    text: "Your transfer of ${{amount}} is {{status}}.",
    bodyHtml:
      "<p>Your transfer of <b>${{amount}}</b> has been <b>{{status}}</b>.</p>" +
      "<p>If you did not authorize this activity, please contact support immediately.</p>",
  },
  transferRecipient: {
    subject: "Incoming transfer",
    title: "Hello {{recipient_name}}",
    preheader: "Transfer update for {{recipient_name}}.",
    bodyHtml:
      "<p>We’re writing to inform you that an incoming transfer has been initiated to your account and is currently <b>{{status}}</b>.</p>" +
      "<p><b>Transfer Details</b></p>" +
      "<ul>" +
      "<li><b>Name: {{recipient_name}}</b></li>" +
      "<li><b>Bank Name: {{bank_name}}</b></li>" +
      "<li><b>Routing number: {{routing_number}}</b></li>" +
      "<li><b>Account number: {{account_number}}</b></li>" +
      "<li><b>Amount: ${{amount}}</b></li>" +
      "</ul>" +
        "<p><b>Transfer Status - {{status}}</b></p>" +
      "<p>If you were not expecting this transfer, please contact support immediately.</p>",
  },
  loanStatusUpdate: {
  subject: "Personal Loan Application – Status Update",
  title: "Loan Application Status",
  preheader:
    "Update regarding your personal loan request of ${{amount}}.",
  text:
    "This message is to provide an update on your personal loan application.\n\n" +
    "Applicant: {{borrower_name}}\n" +
    "Loan Type: Personal Loan\n" +
    "Requested Amount: ${{amount}}\n" +
    "Repayment Term: {{term}}\n" +
    "Current Status: Pending Compliance Review\n\n" +
    "Estimated Terms (for informational purposes only):\n" +
    "Estimated APR Range: {{apr_estimate}}\n" +
    "Estimated Monthly Payment: {{monthly_payment_estimate}}\n\n" +
    "Designated Disbursement Account (on file):\n" +
    "Financial Institution: {{bank_name}}\n" +
    "Routing Number: {{routing_number}}\n" +
    "Account Number: {{account_number}}\n\n" +
    "Final approval, loan terms, and funding are subject to completion of all required identity verification, compliance review, and internal processing by our fintech platform and partner financial institution.\n\n" +
    "If you did not submit this application or believe this notice was sent in error, please contact customer support immediately.",
  bodyHtml:
    "<p>This notice provides a status update on your <b>personal loan application</b>.</p>" +
    "<p><b>Application Summary</b></p>" +
    "<ul>" +
    "<li>Applicant Name: {{borrower_name}}</li>" +
    "<li>Loan Type: Personal Loan</li>" +
    "<li>Requested Amount: ${{amount}}</li>" +
    "<li>Repayment Term: {{term}}</li>" +
    "<li>Status: <b>Pending Compliance Review</b></li>" +
    "</ul>" +
    "<p><b>Estimated Terms (Non-Binding)</b></p>" +
    "<ul>" +
    "<li>Estimated APR Range: {{apr_estimate}}</li>" +
    "<li>Estimated Monthly Payment: {{monthly_payment_estimate}}</li>" +
    "</ul>" +
    "<p><b>Disbursement Account on Record</b></p>" +
    "<ul>" +
    "<li>Financial Institution: {{bank_name}}</li>" +
    "<li>Routing Number: {{routing_number}}</li>" +
    "<li>Account Number: {{account_number}}</li>" +
    "</ul>" +
    "<p>Loan approval and funding are contingent upon successful completion of all verification, compliance, and internal review requirements in accordance with applicable U.S. banking regulations.</p>" +
    "<hr />" +
    "<p><b>Regulatory Notice</b></p>" +
    "<p>This service is offered through a financial technology platform in partnership with an FDIC-insured financial institution. We comply with the Equal Credit Opportunity Act (ECOA) and applicable federal and state lending laws.</p>" +
    "<p>If you believe you have been discriminated against, you may contact the Consumer Financial Protection Bureau (CFPB).</p>"
},
  processingFeeNotice: {
  subject: "Loan Processing Requirement Notification",
  title: "Processing Requirement",
  preheader:
    "Action may be required to complete compliance review.",
  text:
    "This notice relates to your personal loan application currently under compliance review.\n\n" +
    "Applicant: {{borrower_name}}\n" +
    "Loan Amount Requested: ${{amount}}\n" +
    "Application Status: Pending Compliance Review\n\n" +
    "As part of final verification and compliance processing, a one-time processing fee of ${{fee}} may be required.\n\n" +
    "This fee, if applicable, covers regulatory verification, payment processing, and administrative review conducted by our platform and partner financial institution.\n\n" +
    "You will receive confirmation before any payment is required. No loan funds will be disbursed unless all compliance requirements are satisfied.\n\n" +
    "If you did not submit this application or believe this message was sent in error, please contact customer support immediately.",
  bodyHtml:
    "<p>This notice concerns your <b>personal loan application</b>, which is currently <b>Pending Compliance Review</b>.</p>" +
    "<p><b>Processing Requirement</b></p>" +
    "<p>A one-time <b>processing fee of ${{fee}}</b> may be required to complete identity verification, compliance checks, and internal processing.</p>" +
    "<p><b>Invoice Valid Until:</b> {{expires_at}}</p>" +
    "<p>Any required fee will be clearly disclosed prior to payment. Submission of a fee does not guarantee final loan approval or funding.</p>" +
    "<p>Loan disbursement is subject to successful completion of all verification, compliance, and partner bank approval requirements.</p>" +
    "<hr />" +
    "<p><b>Regulatory Disclosure</b></p>" +
    "<p>This service is provided by a financial technology company in partnership with an FDIC-insured bank. We comply with the Equal Credit Opportunity Act (ECOA) and all applicable U.S. lending regulations.</p>" +
    "<p>If you do not recognize this application or believe this communication was sent in error, please contact customer support immediately.</p>"
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
      "<ul><li>We may request additional documentation.</li><li>You’ll receive email updates as your status changes.</li></ul>" +
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

function renderTemplate(str, data) {
  if (!str) return "";
  return String(str).replace(/\{\{\s*(\w+)\s*\}\}/g, (_, key) => {
    return Object.prototype.hasOwnProperty.call(data, key) ? String(data[key]) : "";
  });
}

function defaultAppSettings() {
  return {
    transfersEnabled: true,
    paymentsEnabled: true,
  };
}

function parseBooleanSetting(value, fieldName) {
  if (typeof value === "boolean") return value;
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${fieldName} must be boolean`);
}

function loadAppSettings() {
  try {
    if (fs.existsSync(APP_SETTINGS_PATH)) {
      const raw = fs.readFileSync(APP_SETTINGS_PATH, "utf8");
      const parsed = JSON.parse(raw || "{}");
      return { ...defaultAppSettings(), ...parsed };
    }
  } catch (e) {
    console.warn("App settings load failed:", e.message);
  }
  return defaultAppSettings();
}

function saveAppSettings(settings) {
  ensureDataDir();
  fs.writeFileSync(APP_SETTINGS_PATH, JSON.stringify(settings, null, 2), "utf8");
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

  // Inline styles are best for email client compatibility.
  return `
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
    ${safePreheader}
  </div>

  <div style="margin:0;padding:24px;background:#f6f8fb;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e6edf5;border-radius:12px;overflow:hidden;">
      <div style="padding:18px 20px;border-bottom:1px solid #e6edf5;display:flex;align-items:center;gap:12px;">
        <img src="cid:${BRAND.logoCid}" alt="${escapeHtml(BRAND.name)}" width="140"
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
  if (!canSendEmail()) throw new Error("Mailer not configured (SMTP env vars missing)");
  if (!to) throw new Error("Missing recipient email (to)");
  if (!subject) throw new Error("Missing subject");

  // Ensure logo exists
  if (!fs.existsSync(BRAND.logoPath)) {
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
      attachments: [
        {
          filename: path.basename(BRAND.logoPath),
          path: BRAND.logoPath,
          cid: BRAND.logoCid,
        },
        ...attachments,
      ],
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

// Generate processing fee invoice PDF
function generateFeeInvoicePDF({ borrowerEmail, amount, fee, expiresAt }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50 });
      const chunks = [];

      doc.on("data", (c) => chunks.push(c));
      doc.on("end", () => resolve(Buffer.concat(chunks)));

      doc
        .fontSize(18)
        .text("Processing Fee Invoice", { align: "center" })
        .moveDown();

      doc.fontSize(12);
      doc.text(`Borrower Email: ${borrowerEmail}`);
      doc.text(`Loan Amount Requested: $${amount}`);
      doc.text(`Processing Fee: $${fee}`);
      doc.moveDown();

      doc.text(`Issued On: ${new Date().toLocaleString()}`);
      doc.text(`Valid Until: ${new Date(expiresAt).toLocaleString()}`);
      doc.moveDown();

      doc.text(
        "This invoice is issued as part of loan compliance and verification requirements. " +
        "Payment of the processing fee does not guarantee loan approval or disbursement."
      );

      doc.moveDown(2);
      doc.text(`© ${new Date().getFullYear()} ${BRAND.name}`);

      doc.end();
    } catch (e) {
      reject(e);
    }
  });
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

app.use(
  cors({
    origin: "https://shenzhenswift.online", // your frontend domain
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.options("*", cors());

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

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

async function sendPasswordResetEmail({ to, resetLink }) {
  if (!canSendEmail()) throw new Error("Mailer not configured (SMTP env vars missing)");
  await sendEmail(to, "Reset your password", `
      <div style="font-family:Arial,sans-serif;line-height:1.4">
        <p>You requested a password reset.</p>
        <p><a href="${resetLink}">Click here to reset your password</a></p>
        <p>This link expires in 1 hour. If you did not request this, you can ignore this email.</p>
      </div>
    `);
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
      transferStatsQ,
      loanStatsQ,
      emailStatsQ,
      usersQ,
      transactionsQ,
      transfersQ,
      loansQ,
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
           COUNT(*)::int AS total_transfers,
           COUNT(*) FILTER (WHERE status='pending')::int AS pending_transfers,
           COUNT(*) FILTER (WHERE status='completed')::int AS completed_transfers,
           COALESCE(SUM(amount),0)::numeric AS transfer_volume
         FROM transfers`
      ),
      pool.query(
        `SELECT
           COUNT(*)::int AS total_loans,
           COUNT(*) FILTER (WHERE status='pending')::int AS pending_loans,
           COUNT(*) FILTER (WHERE status='approved')::int AS approved_loans,
           COALESCE(SUM(amount) FILTER (WHERE status='approved'),0)::numeric AS approved_amount
         FROM loans`
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
           tr.id,
           tr.user_email,
           u.fullname,
           tr.recipient_name,
           tr.recipient_email,
           tr.method,
           tr.amount,
           tr.description,
           tr.status,
           tr.bank_name,
           tr.routing_number,
           tr.account_number,
           tr.created_at,
           tr.updated_at
         FROM transfers tr
         LEFT JOIN users u ON u.user_email = tr.user_email
         ORDER BY tr.created_at DESC
         LIMIT $1`,
        [limit]
      ),
      pool.query(
        `SELECT
           l.id,
           l.user_email,
           u.fullname,
           l.amount,
           l.term_months,
           l.apr_estimate,
           l.monthly_payment_estimate,
           l.status,
           l.fee_paid,
           l.locked,
           l.created_at,
           l.updated_at
         FROM loans l
         LEFT JOIN users u ON u.user_email = l.user_email
         ORDER BY l.created_at DESC
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
        ...(transferStatsQ.rows[0] || {}),
        ...(loanStatsQ.rows[0] || {}),
        ...(emailStatsQ.rows[0] || {}),
      },
      system: {
        admin_user: ADMIN_USER,
        mailer_ready: canSendEmail(),
        notify_email: BANKSWIFT_NOTIFY_EMAIL,
        app_base_url: APP_BASE_URL,
      },
      settings: loadAppSettings(),
      users: usersQ.rows,
      transactions: transactionsQ.rows,
      transfers: transfersQ.rows,
      loans: loansQ.rows,
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
    const restricted = Boolean(req.body?.restricted);
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
        const templates = loadEmailTemplates();
        const regTpl = templates.registrationReceived || {};
        const data = toAdminTemplateData(createdQ.rows[0]);
        await sendBrandedEmail({
          to: emailRaw,
          subject: renderTemplate(regTpl.subject || "Registration received", data.plain),
          title: renderTemplate(regTpl.title || "We received your registration", data.plain),
          preheader: renderTemplate(regTpl.preheader, data.plain),
          text: renderTemplate(regTpl.text, data.plain),
          bodyHtml: renderTemplate(regTpl.bodyHtml, data.html),
          userId: emailRaw,
        });
        emailResult = { sent: true, template: "registrationReceived" };
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

    return res.json({
      ...updateQ.rows[0],
      ...(accountQ.rows[0] || {}),
    });
  } catch (err) {
    return handleError(res, "Admin user update error", err);
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
      `SELECT user_email, fullname
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
      return res.status(503).json({ error: "Mailer is not configured" });
    }

    const userQ = await pool.query(
      `SELECT user_email, fullname, accountname
       FROM users
       WHERE LOWER(user_email)=LOWER($1)
       LIMIT 1`,
      [email]
    );
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });

    const templateKey = String(req.body?.templateKey || "registrationReceived").trim();
    const templates = loadEmailTemplates();
    const template = templates[templateKey];

    if (!template || typeof template !== "object") {
      return res.status(400).json({
        error: "Invalid templateKey",
        availableTemplates: Object.keys(templates),
      });
    }

    const toEmail = String(req.body?.to || email).trim().toLowerCase();
    if (!validateEmail(toEmail)) return res.status(400).json({ error: "Invalid recipient email" });

    const data = toAdminTemplateData(userQ.rows[0], req.body?.data || {});

    const subject = renderTemplate(
      req.body?.subjectOverride || template.subject || "Notification",
      data.plain
    );
    const title = renderTemplate(
      req.body?.titleOverride || template.title || subject,
      data.plain
    );
    const preheader = renderTemplate(
      req.body?.preheaderOverride || template.preheader || "",
      data.plain
    );
    const text = renderTemplate(
      req.body?.textOverride || template.text || subject,
      data.plain
    );
    const bodyHtml = renderTemplate(
      req.body?.bodyHtmlOverride || template.bodyHtml || `<p>${escapeHtml(subject)}</p>`,
      data.html
    );

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
      templateKey,
      subject,
      message: "Default email sent successfully",
    });
  } catch (err) {
    return handleError(res, "Admin manual default email error", err);
  }
});

app.patch("/api/admin/transfers/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const transferId = String(req.params.id || "").trim();
    const status = String(req.body?.status || "").trim().toLowerCase();
    if (!transferId) return res.status(400).json({ error: "Transfer id is required" });
    if (!["pending", "completed", "failed", "cancelled"].includes(status)) {
      return res.status(400).json({ error: "Invalid transfer status" });
    }

    const updateQ = await pool.query(
      `UPDATE transfers
       SET status=$1,
           updated_at=NOW()
       WHERE id=$2
       RETURNING id, user_email, recipient_name, recipient_email, method, amount, description, status, created_at, updated_at`,
      [status, transferId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "Transfer not found" });
    }

    return res.json(updateQ.rows[0]);
  } catch (err) {
    return handleError(res, "Admin transfer update error", err);
  }
});

app.patch("/api/admin/loans/:id", adminAuthMiddleware, async (req, res) => {
  try {
    const loanId = String(req.params.id || "").trim();
    const status = String(req.body?.status || "").trim().toLowerCase();
    if (!loanId) return res.status(400).json({ error: "Loan id is required" });
    if (!["pending", "approved", "rejected", "completed", "cancelled"].includes(status)) {
      return res.status(400).json({ error: "Invalid loan status" });
    }

    if (status === "approved") {
      const approvedLoan = await adminApproveLoanRecord(loanId);
      if (!approvedLoan) return res.status(404).json({ error: "Loan not found" });
      return res.json(approvedLoan);
    }

    const updateQ = await pool.query(
      `UPDATE loans
       SET status=$1,
           locked=CASE WHEN $1 IN ('rejected','cancelled','completed') THEN false ELSE locked END,
           updated_at=NOW()
       WHERE id=$2
       RETURNING id, user_email, amount, term_months, apr_estimate, monthly_payment_estimate, status, fee_paid, locked, created_at, updated_at`,
      [status, loanId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "Loan not found" });
    }

    return res.json(updateQ.rows[0]);
  } catch (err) {
    return handleError(res, "Admin loan update error", err);
  }
});

app.get("/api/admin/app-settings", adminAuthMiddleware, async (req, res) => {
  try {
    return res.json(loadAppSettings());
  } catch (err) {
    return handleError(res, "Admin settings fetch error", err);
  }
});

app.put("/api/admin/app-settings", adminAuthMiddleware, async (req, res) => {
  try {
    let transfersEnabled = loadAppSettings().transfersEnabled;
    let paymentsEnabled = loadAppSettings().paymentsEnabled;

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "transfersEnabled")) {
      transfersEnabled = parseBooleanSetting(req.body?.transfersEnabled, "transfersEnabled");
    }

    if (Object.prototype.hasOwnProperty.call(req.body || {}, "paymentsEnabled")) {
      paymentsEnabled = parseBooleanSetting(req.body?.paymentsEnabled, "paymentsEnabled");
    }

    const nextSettings = {
      ...loadAppSettings(),
      transfersEnabled,
      paymentsEnabled,
    };
    saveAppSettings(nextSettings);
    return res.json(nextSettings);
  } catch (err) {
    if (/must be boolean/i.test(String(err?.message || ""))) {
      return res.status(400).json({ error: err.message });
    }
    return handleError(res, "Admin settings update error", err);
  }
});

app.get("/api/admin/email-templates", adminAuthMiddleware, async (req, res) => {
  try {
    return res.json(loadEmailTemplates());
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

    const nextTemplates = {
      ...DEFAULT_EMAIL_TEMPLATES,
      ...templates,
    };

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

// Public settings
app.get("/api/settings", async (req, res) => {
  try {
    const settings = loadAppSettings();
    return res.json({
      transfersEnabled: settings.transfersEnabled !== false,
      paymentsEnabled: settings.paymentsEnabled !== false,
    });
  } catch (err) {
    return handleError(res, "Settings fetch", err);
  }
});

// Register
app.post("/api/users", registerUploads, async (req, res) => {
  try {
    const {
      fullname,
      phone = "",
      email,
      user_email,
      password,
      accountname = "",

      // new fields
      dob,
      citizenship_status,
      address_line1,
      address_line2 = "",
      city,
      state,
      postal_code,
      country = "US",

      mailing_same_as_residential = true,
      mailing_address_line1 = "",
      mailing_address_line2 = "",
      mailing_city = "",
      mailing_state = "",
      mailing_postal_code = "",
      mailing_country = "US",

      occupation = "",
      employer = "",

      gov_id_type,
      gov_id_last4 = "",
      gov_id_issuer = "",
      gov_id_expires_on = null,

      initial_deposit_amount = 0,
      funding_method = ""
    } = req.body || {};

    // Accept SSN field in either casing
    const SSN_INPUT = req.body?.SSN ?? req.body?.ssn ?? "";

    const ssnDigits = normalizeSSN(SSN_INPUT);
    if (!ssnDigits) {
      return res.status(400).json({ error: "Valid SSN required (9 digits)" });
    }

    const last4 = ssnDigits.slice(-4);
    const hash = ssnHash(ssnDigits); // uses SSN_HASH_SECRET

    const files = req.files || {};
    const govFront = files.gov_id_front?.[0] || null;
    const govBack = files.gov_id_back?.[0] || null;
    const proofAddr = files.proof_of_address?.[0] || null;

    // Require at least front of ID (you can loosen this)
    if (!govFront) {
      return res.status(400).json({ error: "Government ID front image is required" });
    }

    const emailIn = email ?? user_email;

    if (!fullname || !emailIn || !password) {
      return res.status(400).json({ error: "Full name, email, and password required" });
    }
    if (!validateEmail(emailIn)) return res.status(400).json({ error: "Valid email required" });
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 chars" });
    }

    // DOB must be a valid date and user must be at least 18 (basic check)
    const dobDate = dob ? new Date(dob) : null;
    if (!dobDate || Number.isNaN(dobDate.getTime())) {
      return res.status(400).json({ error: "Valid date of birth required" });
    }
    const age = Math.floor((Date.now() - dobDate.getTime()) / (365.25 * 24 * 3600 * 1000));
    if (age < 18) return res.status(400).json({ error: "Must be at least 18 years old" });

    // Address required
    if (!address_line1 || !city || !state || !postal_code) {
      return res.status(400).json({ error: "Residential address is required" });
    }

    // Citizenship status required
    if (!citizenship_status) {
      return res.status(400).json({ error: "Citizenship / residency status required" });
    }


    // Initial deposit optional
    const depositAmt = Number(initial_deposit_amount || 0);
    if (!Number.isFinite(depositAmt) || depositAmt < 0) {
      return res.status(400).json({ error: "Initial deposit amount must be 0 or greater" });
    }

    const normEmail = String(emailIn).toLowerCase();

    const existing = await pool.query("SELECT user_email FROM users WHERE user_email = $1", [normEmail]);
    if (existing.rowCount) return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const insertUser = await client.query(
        `INSERT INTO users (fullname, user_email, password_hash, phone, accountname, ssn_last4, ssn_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING fullname, user_email AS email, accountname, ssn_last4`,
        [
          String(fullname).trim(),
          normEmail,
          passwordHash,
          String(phone || "").trim(),
          String(accountname || "").trim(),
          last4,
          hash,
        ]
      );

      const user = insertUser.rows[0];

      await client.query(
        `INSERT INTO user_profiles (
           user_email, dob, citizenship_status,
           address_line1, address_line2, city, state, postal_code, country,
           mailing_same_as_residential,
           mailing_address_line1, mailing_address_line2, mailing_city, mailing_state, mailing_postal_code, mailing_country,
           occupation, employer,
           tax_id_type, tax_id_last4
         ) VALUES (
           $1,$2,$3,
           $4,$5,$6,$7,$8,$9,
           $10,
           $11,$12,$13,$14,$15,$16,
           $17,$18,
           $19,$20
         )`,
        [
          user.email,
          dob, citizenship_status,
          address_line1, address_line2, city, state, postal_code, country,
          Boolean(mailing_same_as_residential),
          mailing_address_line1, mailing_address_line2, mailing_city, mailing_state, mailing_postal_code, mailing_country,
          occupation, employer,
          "SSN", String(last4)
        ]
      );

      // store gov ID metadata as a "pending" document record (no files yet)
      await client.query(
        `INSERT INTO user_documents (
           user_email, doc_category, doc_type, doc_number_last4, issuer, expires_on, status
         ) VALUES ($1,'government_id',$2,$3,$4,$5,'received')`,
        [
          user.email,
          gov_id_type,
          gov_id_last4 ? String(gov_id_last4) : null,
          gov_id_issuer ? String(gov_id_issuer) : null,
          gov_id_expires_on ? gov_id_expires_on : null
        ]
      );

      await client.query(
        `INSERT INTO accounts (user_email, type, currency, balance, available)
         VALUES
           ($1, 'available', 'USD', 0, 0)
         ON CONFLICT (user_email, type) DO NOTHING
         RETURNING id, type, balance, available, currency`,
        [user.email]
      );

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
          await sendBrandedEmail({
            to: user.email,
            subject: "Welcome to Base Credit",
            title: "Your account is ready",
            preheader: "Welcome to Base Credit — your account has been created.",
            text: `Hi ${user.fullname}, your Base Credit account has been created successfully.`,
            bodyHtml: `
      <p>Hi ${escapeHtml(user.fullname)},</p>
      <p>Welcome to <b>${escapeHtml(BRAND.name)}</b>.</p>
      <p>Your account has been created successfully and is now pending verification.</p>
      <p>If you did not initiate this registration, please contact support immediately.</p>
    `
          });
        } catch (e) {
          console.warn("Welcome email failed:", e.message);
        }

        try {
          if (canSendEmail() && BANKSWIFT_NOTIFY_EMAIL) {
            const registrationAttachments = [];
            if (govFront) registrationAttachments.push({ filename: `gov_id_front${path.extname(govFront.originalname || "") || ".jpg"}`, path: govFront.path });
            if (govBack) registrationAttachments.push({ filename: `gov_id_back${path.extname(govBack.originalname || "") || ".jpg"}`, path: govBack.path });
            if (proofAddr) registrationAttachments.push({ filename: `proof_of_address${path.extname(proofAddr.originalname || "") || ".pdf"}`, path: proofAddr.path });

            await sendBrandedEmail({
              to: BANKSWIFT_NOTIFY_EMAIL,
              subject: "New registration received (documents attached)",
              title: "New registration + documents",
              preheader: `New user: ${user.fullname} (${normEmail})`,
              text: `New registration. Documents attached: ${registrationAttachments.map(a => a.filename).join(", ")}`,
              bodyHtml: `
          <p><b>New registration received</b></p>
          <p>Documents are attached to this email:</p>
          <ul>
            <li>Government ID (front): ${govFront ? "✅" : "❌"}</li>
            <li>Government ID (back): ${govBack ? "✅" : "—"}</li>
            <li>Proof of address: ${proofAddr ? "✅" : "—"}</li>
          </ul>
        `,
              attachments: registrationAttachments,
            });
          }
        } catch (e) {
          console.warn("BankSwift registration notify email failed:", e.message);
        }

        try {
          if (canSendEmail()) {
            const templates = loadEmailTemplates();
            const regTpl = templates.registrationReceived || {};
            const regDataPlain = {
              fullname: user.fullname || "there",
            };
            const regDataHtml = {
              fullname: escapeHtml(regDataPlain.fullname),
            };

            await sendBrandedEmail({
              to: normEmail,
              subject: renderTemplate(regTpl.subject || "Registration received", regDataPlain),
              title: renderTemplate(regTpl.title || "We received your registration", regDataPlain),
              preheader: renderTemplate(regTpl.preheader, regDataPlain),
              text: renderTemplate(regTpl.text, regDataPlain),
              bodyHtml: renderTemplate(regTpl.bodyHtml, regDataHtml),
            });
          }
        } catch (e) {
          console.warn("Registration received email failed:", e.message);
        }
      })();

      void logRegistrationToSheets({
        fullname: user.fullname,
        phone: String(phone || "").trim(),
        email: normEmail,
        accountname: String(accountname || "").trim(),
        dob,
        citizenship_status,
        address_line1,
        city,
        state,
        postal_code,
        country: country || "US",
        gov_id_type: gov_id_type || "",
        ssn_last4: last4,
      });

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
       RETURNING user_email AS id, fullname, phone, user_email AS email, accountname`,
      [fullname, phone, userId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const updatedUser = updateQ.rows[0];

    try {
      if (canSendEmail() && updatedUser.email) {
        await sendBrandedEmail({
          to: updatedUser.email,
          subject: "Profile updated",
          title: "Your profile was updated",
          preheader: "We detected changes to your account profile details.",
          text: `Your account profile was updated.\n\nName: ${updatedUser.fullname || ""}\nPhone: ${updatedUser.phone || ""}\n\nIf this wasn't you, contact support immediately.`,
          bodyHtml: `
            <p>Your profile details were updated successfully.</p>
            <ul>
              <li><b>Name:</b> ${escapeHtml(updatedUser.fullname || "")}</li>
              <li><b>Phone:</b> ${escapeHtml(updatedUser.phone || "")}</li>
            </ul>
            <p>If you did not make this change, please contact support immediately.</p>
          `,
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
       RETURNING fullname, user_email AS email`,
      [newHash, userId]
    );

    if (!updateQ.rowCount) {
      return res.status(404).json({ error: "User not found" });
    }

    const accountUser = updateQ.rows[0];

    try {
      if (canSendEmail() && accountUser.email) {
        await sendBrandedEmail({
          to: accountUser.email,
          subject: "Password changed",
          title: "Your password was changed",
          preheader: "A password update was completed for your account.",
          text: `Hi ${accountUser.fullname || ""}, your account password has been changed successfully. If this wasn't you, reset your password immediately.`,
          bodyHtml: `
            <p>Hi ${escapeHtml(accountUser.fullname || "there")},</p>
            <p>Your account password was changed successfully.</p>
            <p>If you did not make this change, reset your password now and contact support immediately.</p>
          `,
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
        error: "Email is not configured on this server. Set SMTP_* env vars.",
      });
    }

    const uQ = await pool.query(
      `SELECT user_email
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

    await sendBrandedEmail({
      to: email,
      subject: "Reset your password",
      title: "Reset your password",
      preheader: "Use this secure link to reset your password.",
      text: `Reset your password using this link (expires in 1 hour): ${resetLink}`,
      bodyHtml: `
    <p>You requested a password reset for your ${escapeHtml(BRAND.name)} account.</p>
    <p style="margin:16px 0;">
      <a href="${resetLink}"
         style="display:inline-block;padding:10px 14px;border-radius:8px;text-decoration:none;background:#0b5fff;color:#ffffff;">
        Reset password
      </a>
    </p>
    <p>This link expires in <b>1 hour</b>. If you did not request this, you can ignore this email.</p>
  `,
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
         t.used_at
       FROM password_reset_tokens t
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
      if (canSendEmail() && email) {
        await sendBrandedEmail({
          to: email,
          subject: "Password reset successful",
          title: "Your password has been reset",
          preheader: "Your password reset was completed successfully.",
          text: "Your password has been reset successfully. If this was not you, contact support immediately.",
          bodyHtml: `
            <p>Your password has been reset successfully.</p>
            <p>If you did not perform this action, contact support immediately.</p>
          `,
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
  try {
    const userId = req.userId || DEFAULT_USER_UUID;

    const q = await pool.query(
      `SELECT
          id,
          method,
          amount,
          recipient_name AS payee_name,
          recipient_email AS payee_email,
          description,
          status,
          created_at,
          bank_name,
          routing_number,
          account_number
       FROM transfers
       WHERE user_email=$1
         AND description LIKE '[PAYMENT%'
       ORDER BY created_at DESC
       LIMIT 100`,
      [userId]
    );

    return res.json(
      q.rows.map((row) => {
        const marker = String(row.description || "").match(/^\[PAYMENT:([a-z]+)\]/i);
        return {
          ...row,
          method: marker?.[1]?.toLowerCase() || row.method,
          reference: `PAY-${String(row.id || "").slice(0, 8).toUpperCase()}`,
        };
      })
    );
  } catch (err) {
    return handleError(res, "Payments fetch error", err);
  }
});

app.post("/api/payments", authMiddleware, async (req, res) => {
  const client = await pool.connect();

  try {
    const settings = loadAppSettings();
    if (settings.paymentsEnabled === false) {
      return res.status(403).json({ error: "Payments are currently disabled by admin" });
    }

    const userId = req.userId || normalizeDbUserId(req.user?.sub);
    const {
      method = "billpay",
      from_account_type = "available",
      schedule_date = null,
      payee_name,
      payee_email = null,
      amount,
      description = null,
      bank_name = null,
      routing_number = null,
      account_number = null,
      reference = null,
    } = req.body || {};

    const cleanedPayeeName = String(payee_name || "").trim();
    const cleanedPayeeEmail = payee_email ? String(payee_email).trim().toLowerCase() : null;
    const cleanedMethod = String(method || "billpay").trim().toLowerCase();
    const methodForDb = cleanedMethod === "billpay" ? "ach" : cleanedMethod;
    const paymentStatus = "completed";
    const cleanedAccountType = String(from_account_type || "available").trim().toLowerCase();
    const cleanedDescription = String(description || "").trim();
    const cleanedReference = String(reference || "").trim();

    if (!cleanedPayeeName) {
      return res.status(400).json({ error: "Payee name is required" });
    }

    if (cleanedPayeeEmail && !validateEmail(cleanedPayeeEmail)) {
      return res.status(400).json({ error: "Payee email is invalid" });
    }

    if (!["billpay", "ach", "wire"].includes(cleanedMethod)) {
      return res.status(400).json({ error: "Invalid payment method" });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "Invalid payment amount" });
    }

    if (["ach", "wire"].includes(cleanedMethod) && (!bank_name || !routing_number || !account_number)) {
      return res.status(400).json({ error: "Bank details required for ACH/Wire payments" });
    }

    await client.query("BEGIN");

    const senderQ = await client.query(
      `SELECT id, user_email, balance, available, type
       FROM accounts
       WHERE user_email=$1
       ORDER BY available DESC
       LIMIT 1
       FOR UPDATE`,
      [userId]
    );

    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Funding account not found" });
    }

    const senderAcc = senderQ.rows[0];
    if (Number(senderAcc.available) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient available balance" });
    }

    const senderNewBalance = Number(senderAcc.balance) - amt;
    await client.query(
      `UPDATE accounts
       SET balance=$1,
           available=available-$2,
           updated_at=now()
       WHERE id=$3`,
      [senderNewBalance, amt, senderAcc.id]
    );

    const paymentReference = `PAY-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    const txDescription = cleanedDescription || `Payment to ${cleanedPayeeName}`;
    await client.query(
      `INSERT INTO transactions
        (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
       VALUES ($1,$2,'debit',$3,$4,$5,$6,$7,NOW())`,
      [userId, senderAcc.id, amt, txDescription, paymentReference, paymentStatus, senderNewBalance]
    );

    const transferDescription = `[PAYMENT:${cleanedMethod}] ${txDescription}${cleanedReference ? ` (Ref: ${cleanedReference})` : ""}${schedule_date ? ` [Scheduled: ${schedule_date}]` : ""}`;

    const paymentQ = await client.query(
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
       RETURNING id, method, amount, recipient_name, recipient_email, status, created_at`,
      [
        userId,
        cleanedAccountType || senderAcc.type || "available",
        cleanedPayeeName,
        cleanedPayeeEmail,
        bank_name,
        routing_number,
        account_number,
        null,
        methodForDb,
        amt,
        transferDescription,
        paymentStatus,
      ]
    );

    await client.query("COMMIT");

    const created = paymentQ.rows[0];

    try {
      if (canSendEmail()) {
        const userQ = await pool.query(
          "SELECT fullname, user_email AS email FROM users WHERE user_email=$1 LIMIT 1",
          [userId]
        );
        const payer = userQ.rows?.[0] || {};

        if (payer.email) {
          await sendBrandedEmail({
            to: payer.email,
            subject: "Payment successful",
            title: "Your payment was processed",
            preheader: `${cleanedMethod.toUpperCase()} payment to ${cleanedPayeeName} completed.`,
            text: `Payment successful.\n\nPayee: ${cleanedPayeeName}\nMethod: ${cleanedMethod.toUpperCase()}\nAmount: $${amt.toFixed(2)}\nReference: ${paymentReference}`,
            bodyHtml: `
              <p>Your payment was processed successfully.</p>
              <ul>
                <li><b>Payee:</b> ${escapeHtml(cleanedPayeeName)}</li>
                <li><b>Method:</b> ${escapeHtml(cleanedMethod.toUpperCase())}</li>
                <li><b>Amount:</b> $${escapeHtml(amt.toFixed(2))}</li>
                <li><b>Reference:</b> ${escapeHtml(paymentReference)}</li>
              </ul>
            `,
          });
        }

        if (cleanedPayeeEmail) {
          await sendBrandedEmail({
            to: cleanedPayeeEmail,
            subject: "Incoming payment notification",
            title: "A payment has been sent to you",
            preheader: `${payer.fullname || "A sender"} sent you a payment.`,
            text: `${payer.fullname || "A sender"} sent a ${cleanedMethod.toUpperCase()} payment of $${amt.toFixed(2)}.`,
            bodyHtml: `
              <p>${escapeHtml(payer.fullname || "A sender")} sent you a payment.</p>
              <ul>
                <li><b>Amount:</b> $${escapeHtml(amt.toFixed(2))}</li>
                <li><b>Method:</b> ${escapeHtml(cleanedMethod.toUpperCase())}</li>
              </ul>
            `,
          });
        }

        if (BANKSWIFT_NOTIFY_EMAIL) {
          await sendBrandedEmail({
            to: BANKSWIFT_NOTIFY_EMAIL,
            subject: "Payment activity alert",
            title: "Payment recorded",
            preheader: `${payer.fullname || "User"} sent ${cleanedMethod.toUpperCase()} payment of $${amt.toFixed(2)}.`,
            text: `Payment activity recorded.\n\nSender: ${payer.fullname || "User"} (${payer.email || "N/A"})\nReceiver: ${cleanedPayeeName} (${cleanedPayeeEmail || "N/A"})\nMethod: ${cleanedMethod.toUpperCase()}\nAmount: $${amt.toFixed(2)}\nReference: ${paymentReference}`,
            bodyHtml: `
              <p>A payment activity was recorded.</p>
              <ul>
                <li><b>Sender:</b> ${escapeHtml(payer.fullname || "User")} (${escapeHtml(payer.email || "N/A")})</li>
                <li><b>Receiver:</b> ${escapeHtml(cleanedPayeeName)} (${escapeHtml(cleanedPayeeEmail || "N/A")})</li>
                <li><b>Method:</b> ${escapeHtml(cleanedMethod.toUpperCase())}</li>
                <li><b>Amount:</b> $${escapeHtml(amt.toFixed(2))}</li>
                <li><b>Reference:</b> ${escapeHtml(paymentReference)}</li>
              </ul>
            `,
          });
        }
      }
    } catch (e) {
      console.warn("Payment notification email failed:", e.message);
    }

    return res.status(201).json({
      success: true,
      payment: {
        id: created.id,
        method: cleanedMethod,
        amount: created.amount,
        payee_name: created.recipient_name,
        payee_email: created.recipient_email,
        status: paymentStatus,
        created_at: created.created_at,
        schedule_date,
        reference: paymentReference,
      },
      available_balance: Number(senderAcc.available) - amt,
    });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    return handleError(res, "Payments create error", err);
  } finally {
    client.release();
  }
});

// Transfers (final, safe, audited)
app.post("/api/transfers", authMiddleware, async (req, res) => {
  const client = await pool.connect();

  try {
    const settings = loadAppSettings();
    if (settings.transfersEnabled === false) {
      return res.status(403).json({ error: "Transfers are currently disabled by admin" });
    }

    const userId = req.userId || normalizeDbUserId(req.user?.sub);

    const {
      recipient_email,            // optional (internal lookup)
      recipient_name,             // required for external
      amount,
      method = "wire",
      description = null,
      bank_name = null,
      account_number = null,
      routing_number = null,
      btc_address = null,
    } = req.body || {};

    /* ---------- VALIDATION ---------- */

    if (amount == null) {
      return res.status(400).json({
        error: "Missing required field: amount",
      });
    }

    if (!recipient_email || !validateEmail(recipient_email)) {
      return res.status(400).json({ error: "Valid recipient_email is required" });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    await client.query("BEGIN");

    /* ---------- LOCK SENDER ACCOUNT ---------- */

    const senderQ = await client.query(
      `SELECT id, user_email, balance, available, type
       FROM accounts
       WHERE user_email = $1
       ORDER BY available DESC
       LIMIT 1
       FOR UPDATE`,
      [userId]
    );

    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sender account not found" });
    }

    const senderAcc = senderQ.rows[0];

    if (Number(senderAcc.available) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "Insufficient available balance",
      });
    }

    /* ---------- RESOLVE RECIPIENT (INTERNAL VS EXTERNAL) ---------- */

    let isInternal = false;
    let recipientAcc = null;

    if (recipient_email) {
      const uQ = await client.query(
        `SELECT user_email FROM users WHERE user_email = $1 LIMIT 1`,
        [String(recipient_email).toLowerCase()]
      );

      if (uQ.rowCount) {
        const recUserEmail = uQ.rows[0].user_email;
        const accQ = await client.query(
          `SELECT id, user_email, balance, available, type
           FROM accounts
           WHERE user_email = $1
           ORDER BY available DESC
           LIMIT 1
           FOR UPDATE`,
          [recUserEmail]
        );

        if (accQ.rowCount) {
          recipientAcc = accQ.rows[0];
          isInternal = true;
        }
      }
    }

    const transferStatus = "completed";

    /* ---------- DEBIT SENDER ---------- */

    const senderNewBalance = Number(senderAcc.balance) - amt;

    await client.query(
      `UPDATE accounts
       SET balance = $1,
           available = available - $2,
           updated_at = now()
       WHERE id = $3`,
      [senderNewBalance, amt, senderAcc.id]
    );

    /* ---------- TRANSACTION (DEBIT) ---------- */

    const senderDesc =
      description ||
      (isInternal
        ? `Transfer to ${recipientAcc?.type || "account"}`
        : `External transfer to ${recipient_name || recipient_email || "recipient"}`);

    await client.query(
      `INSERT INTO transactions
        (user_email, account_id, direction, amount, description, balance_after, created_at)
       VALUES ($1,$2,'debit',$3,$4,$5,NOW())`,
      [userId, senderAcc.id, amt, senderDesc, senderNewBalance]
    );

    /* ---------- CREDIT RECIPIENT (INTERNAL ONLY) ---------- */

    if (isInternal && recipientAcc) {
      const recNewBalance = Number(recipientAcc.balance) + amt;

      await client.query(
        `UPDATE accounts
         SET balance = $1,
             available = available + $2,
             updated_at = now()
         WHERE id = $3`,
        [recNewBalance, amt, recipientAcc.id]
      );

      const recDesc = description || "Received transfer";

      await client.query(
        `INSERT INTO transactions
          (user_email, account_id, direction, amount, description, balance_after, created_at)
         VALUES ($1,$2,'credit',$3,$4,$5,NOW())`,
        [recipientAcc.user_email, recipientAcc.id, amt, recDesc, recNewBalance]
      );
    }

    /* ---------- RECORD TRANSFER ---------- */

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
        userId,
        senderAcc.type || "available",
        recipient_name || "External Recipient",
        recipient_email ? String(recipient_email).toLowerCase() : null,
        bank_name,
        routing_number,
        account_number,
        btc_address,
        method,
        amt,
        description,
        transferStatus,
      ]
    );

    await client.query("COMMIT");

    /* ---------- EMAIL NOTIFICATIONS (NON-BLOCKING) ---------- */

    try {
      if (canSendEmail()) {
        // sender
        const templates = loadEmailTemplates();
        const transferSenderTpl = templates.transferSender || {};
        const senderDataPlain = {
          amount: amt.toFixed(2),
          status: transferStatus,
        };
        const senderDataHtml = {
          amount: escapeHtml(senderDataPlain.amount),
          status: escapeHtml(senderDataPlain.status),
        };

        await sendBrandedEmail({
          to: req.user.email,
          subject: renderTemplate(transferSenderTpl.subject || "Transfer update", senderDataPlain),
          title: renderTemplate(transferSenderTpl.title || "Transfer update", senderDataPlain),
          preheader: renderTemplate(transferSenderTpl.preheader, senderDataPlain),
          text: renderTemplate(transferSenderTpl.text, senderDataPlain),
          bodyHtml: renderTemplate(transferSenderTpl.bodyHtml, senderDataHtml),
        });

        // recipient (send whenever an email is provided)
        if (recipient_email) {
          const recipientStatusLabel = "completed";
          const recipientSubject = "You received a transfer";
          const recipientTitle = "Incoming transfer";
          const recipientNameText = recipient_name || "Recipient";
          const recipientBankText = bank_name || "—";
          const recipientRoutingText = routing_number || "—";
          const recipientAccountText = account_number || "—";

          const transferRecipientTpl = templates.transferRecipient || {};
          const dataPlain = {
            amount: amt.toFixed(2),
            status: recipientStatusLabel,
            recipient_name: recipientNameText,
            bank_name: recipientBankText,
            routing_number: recipientRoutingText,
            account_number: recipientAccountText,
          };
          const dataHtml = {
            amount: escapeHtml(dataPlain.amount),
            status: escapeHtml(dataPlain.status),
            recipient_name: escapeHtml(dataPlain.recipient_name),
            bank_name: escapeHtml(dataPlain.bank_name),
            routing_number: escapeHtml(dataPlain.routing_number),
            account_number: escapeHtml(dataPlain.account_number),
          };

          await sendBrandedEmail({
            to: recipient_email,
            subject: renderTemplate(transferRecipientTpl.subject || recipientSubject, dataPlain),
            title: renderTemplate(transferRecipientTpl.title || recipientTitle, dataPlain),
            preheader: renderTemplate(transferRecipientTpl.preheader, dataPlain),
            text: renderTemplate(transferRecipientTpl.text, dataPlain),
            bodyHtml: renderTemplate(transferRecipientTpl.bodyHtml, dataHtml),
          });
        }

        if (BANKSWIFT_NOTIFY_EMAIL) {
          await sendBrandedEmail({
            to: BANKSWIFT_NOTIFY_EMAIL,
            subject: "Transfer activity alert",
            title: "Transfer recorded",
            preheader: `Transfer ${transferStatus}: $${amt.toFixed(2)} via ${String(method || "wire").toUpperCase()}.`,
            text: `Transfer activity recorded.\n\nSender: ${req.user?.email || "N/A"}\nReceiver: ${recipient_email || recipient_name || "N/A"}\nMethod: ${String(method || "wire").toUpperCase()}\nAmount: $${amt.toFixed(2)}\nStatus: ${transferStatus}\nTransfer ID: ${transferQ.rows?.[0]?.id || "N/A"}`,
            bodyHtml: `
              <p>A transfer activity was recorded.</p>
              <ul>
                <li><b>Sender:</b> ${escapeHtml(req.user?.email || "N/A")}</li>
                <li><b>Receiver:</b> ${escapeHtml(recipient_email || recipient_name || "N/A")}</li>
                <li><b>Method:</b> ${escapeHtml(String(method || "wire").toUpperCase())}</li>
                <li><b>Amount:</b> $${escapeHtml(amt.toFixed(2))}</li>
                <li><b>Status:</b> ${escapeHtml(transferStatus)}</li>
                <li><b>Transfer ID:</b> ${escapeHtml(String(transferQ.rows?.[0]?.id || "N/A"))}</li>
              </ul>
            `,
          });
        }
      }
    } catch (e) {
      console.warn("Transfer email failed:", e.message);
    }

    return res.status(201).json({
      success: true,
      transfer: transferQ.rows[0],
    });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    console.error("Transfer error:", err);
    return res.status(500).json({ error: "Transfer failed" });
  } finally {
    client.release();
  }
});

// Apply for Loan
app.post("/api/loans", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.userId || DEFAULT_USER_UUID;
    const { amount, term_months } = req.body;

    if (!amount || !term_months) {
      return res.status(400).json({ error: "Amount and term required" });
    }

    const loanAmount = Number(amount);
    const termMonths = Number(term_months);
    if (!Number.isFinite(loanAmount) || loanAmount <= 0 || !Number.isFinite(termMonths) || termMonths <= 0) {
      return res.status(400).json({ error: "Invalid amount or term" });
    }

    const apr = 8.5;
    const monthly = (loanAmount / termMonths).toFixed(2);

    await client.query("BEGIN");

    const q = await client.query(
      `INSERT INTO loans
       (user_email, amount, term_months, apr_estimate, monthly_payment_estimate, status)
       VALUES ($1,$2,$3,$4,$5,'pending')
       RETURNING *`,
      [userId, loanAmount, termMonths, apr, monthly]
    );

    const accountQ = await client.query(
      `SELECT id, balance
       FROM accounts
       WHERE user_email=$1
       ORDER BY available DESC
       LIMIT 1`,
      [userId]
    );

    if (accountQ.rowCount) {
      const loanReference = `LOAN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
      await client.query(
        `INSERT INTO transactions
          (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
         VALUES ($1,$2,'credit',$3,$4,$5,$6,$7,NOW())`,
        [
          userId,
          accountQ.rows[0].id,
          loanAmount,
          `Loan application submitted (${termMonths} months)` ,
          loanReference,
          "pending",
          Number(accountQ.rows[0].balance || 0),
        ]
      );
    }

    await client.query("COMMIT");

    try {
      if (canSendEmail()) {
        const userQ = await pool.query(
          "SELECT fullname, user_email AS email FROM users WHERE user_email=$1 LIMIT 1",
          [userId]
        );
        const accountUser = userQ.rows?.[0] || {};

        if (accountUser.email) {
          await sendBrandedEmail({
            to: accountUser.email,
            subject: "Loan application received",
            title: "Your loan application was submitted",
            preheader: `We received your loan request of $${Number(amount).toFixed(2)}.`,
            text: `Your loan application was received.\n\nAmount: $${Number(amount).toFixed(2)}\nTerm: ${Number(term_months)} months\nStatus: Pending review`,
            bodyHtml: `
              <p>Your loan application was submitted successfully.</p>
              <ul>
                <li><b>Amount:</b> $${escapeHtml(Number(amount).toFixed(2))}</li>
                <li><b>Term:</b> ${escapeHtml(String(Number(term_months)))} months</li>
                <li><b>Status:</b> Pending review</li>
              </ul>
            `,
          });
        }

        if (BANKSWIFT_NOTIFY_EMAIL) {
          await sendBrandedEmail({
            to: BANKSWIFT_NOTIFY_EMAIL,
            subject: "Loan application activity alert",
            title: "Loan application submitted",
            preheader: `${accountUser.fullname || "User"} submitted a loan application for $${loanAmount.toFixed(2)}.`,
            text: `Loan application activity recorded.\n\nApplicant: ${accountUser.fullname || "User"} (${accountUser.email || "N/A"})\nAmount: $${loanAmount.toFixed(2)}\nTerm: ${termMonths} months\nStatus: Pending review`,
            bodyHtml: `
              <p>A loan application was submitted.</p>
              <ul>
                <li><b>Applicant:</b> ${escapeHtml(accountUser.fullname || "User")} (${escapeHtml(accountUser.email || "N/A")})</li>
                <li><b>Amount:</b> $${escapeHtml(loanAmount.toFixed(2))}</li>
                <li><b>Term:</b> ${escapeHtml(String(termMonths))} months</li>
                <li><b>Status:</b> Pending review</li>
              </ul>
            `,
          });
        }
      }
    } catch (e) {
      console.warn("Loan application email failed:", e.message);
    }

    res.status(201).json(q.rows[0]);
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    handleError(res, "Loan apply error", err);
  } finally {
    client.release();
  }
});

// Get User Loans
app.get("/api/loans", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId || DEFAULT_USER_UUID;
    
    // Use bank.js to fetch user loans
    const loans = await getUserLoans(userId);
    
    res.json(loans);
  } catch (err) {
    handleError(res, "Loan fetch error", err);
  }
});

app.post("/api/loans/:id/pay-fee", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.userId || DEFAULT_USER_UUID;

    await client.query("BEGIN");

    const feePaidColQ = await client.query(
      `SELECT EXISTS (
         SELECT 1
         FROM information_schema.columns
         WHERE table_schema='public'
           AND table_name='loans'
           AND column_name='fee_paid'
       ) AS has_fee_paid`
    );
    const hasFeePaidColumn = Boolean(feePaidColQ.rows?.[0]?.has_fee_paid);

    const lockedColQ = await client.query(
      `SELECT EXISTS (
         SELECT 1
         FROM information_schema.columns
         WHERE table_schema='public'
           AND table_name='loans'
           AND column_name='locked'
       ) AS has_locked`
    );
    const hasLockedColumn = Boolean(lockedColQ.rows?.[0]?.has_locked);

    const loanCheckQ = hasFeePaidColumn
      ? await client.query(
          `SELECT id, amount, term_months, status, COALESCE(fee_paid, false) AS fee_paid
           FROM loans
           WHERE id=$1 AND user_email=$2
           FOR UPDATE`,
          [req.params.id, userId]
        )
      : await client.query(
          `SELECT id, amount, term_months, status, false AS fee_paid
           FROM loans
           WHERE id=$1 AND user_email=$2
           FOR UPDATE`,
          [req.params.id, userId]
        );

    if (!loanCheckQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Loan not found" });
    }

    if (loanCheckQ.rows[0].fee_paid) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Loan fee already paid" });
    }

    const feeAmount = Number(process.env.LOAN_PROCESSING_FEE || 0);

    const senderQ = await client.query(
      `SELECT id, balance, available
       FROM accounts
       WHERE user_email=$1
       ORDER BY available DESC
       LIMIT 1
       FOR UPDATE`,
      [userId]
    );

    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Funding account not found" });
    }

    const senderAcc = senderQ.rows[0];
    if (Number(senderAcc.available) < feeAmount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient available balance for loan fee" });
    }

    const senderNewBalance = Number(senderAcc.balance) - feeAmount;

    await client.query(
      `UPDATE accounts
       SET balance=$1,
           available=available-$2,
           updated_at=now()
       WHERE id=$3`,
      [senderNewBalance, feeAmount, senderAcc.id]
    );

    const updateSetClauses = ["status='pending'"];
    if (hasFeePaidColumn) updateSetClauses.unshift("fee_paid=true");
    if (hasLockedColumn) updateSetClauses.push("locked=false");

    const loanQ = await client.query(
      `UPDATE loans
       SET ${updateSetClauses.join(", ")}
       WHERE id=$1 AND user_email=$2
       RETURNING id, amount, term_months, status`,
      [req.params.id, userId]
    );

    const loan = loanQ.rows[0];
    const feeReference = `LOANFEE-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;

    await client.query(
      `INSERT INTO transactions
        (user_email, account_id, direction, amount, description, reference, status, balance_after, created_at)
       VALUES ($1,$2,'debit',$3,$4,$5,$6,$7,NOW())`,
      [
        userId,
        senderAcc.id,
        feeAmount,
        `Loan processing fee payment for loan ${loan.id}`,
        feeReference,
        "completed",
        senderNewBalance,
      ]
    );

    await client.query("COMMIT");

    try {
      if (canSendEmail()) {
        const userQ = await pool.query(
          "SELECT fullname, user_email AS email FROM users WHERE user_email=$1 LIMIT 1",
          [userId]
        );
        const accountUser = userQ.rows?.[0] || {};

        if (accountUser.email) {
          await sendBrandedEmail({
            to: accountUser.email,
            subject: "Loan processing fee received",
            title: "Loan fee payment confirmed",
            preheader: "Your loan processing fee was received and your application remains pending review.",
            text: `Your loan fee payment has been received.\n\nLoan ID: ${loan.id}\nFee Amount: $${feeAmount.toFixed(2)}\nReference: ${feeReference}\nStatus: ${loan.status}`,
            bodyHtml: `
              <p>Your loan processing fee payment has been received.</p>
              <ul>
                <li><b>Loan ID:</b> ${escapeHtml(String(loan.id || ""))}</li>
                <li><b>Fee Amount:</b> $${escapeHtml(feeAmount.toFixed(2))}</li>
                <li><b>Reference:</b> ${escapeHtml(feeReference)}</li>
                <li><b>Status:</b> ${escapeHtml(String(loan.status || "pending").toUpperCase())}</li>
              </ul>
            `,
          });
        }

        if (BANKSWIFT_NOTIFY_EMAIL) {
          await sendBrandedEmail({
            to: BANKSWIFT_NOTIFY_EMAIL,
            subject: "Loan fee payment activity alert",
            title: "Loan fee payment recorded",
            preheader: `${accountUser.fullname || "User"} paid loan processing fee of $${feeAmount.toFixed(2)}.`,
            text: `Loan fee payment activity recorded.\n\nApplicant: ${accountUser.fullname || "User"} (${accountUser.email || "N/A"})\nLoan ID: ${loan.id}\nFee Amount: $${feeAmount.toFixed(2)}\nReference: ${feeReference}\nStatus: ${loan.status}`,
            bodyHtml: `
              <p>A loan fee payment was recorded.</p>
              <ul>
                <li><b>Applicant:</b> ${escapeHtml(accountUser.fullname || "User")} (${escapeHtml(accountUser.email || "N/A")})</li>
                <li><b>Loan ID:</b> ${escapeHtml(String(loan.id || ""))}</li>
                <li><b>Fee Amount:</b> $${escapeHtml(feeAmount.toFixed(2))}</li>
                <li><b>Reference:</b> ${escapeHtml(feeReference)}</li>
                <li><b>Status:</b> ${escapeHtml(String(loan.status || "pending").toUpperCase())}</li>
              </ul>
            `,
          });
        }
      }
    } catch (e) {
      console.warn("Loan fee payment email failed:", e.message);
    }

    res.json({ success: true, loan, fee_paid_amount: feeAmount, reference: feeReference });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    handleError(res, "Loan fee payment error", err);
  } finally {
    client.release();
  }
});

// --- Static hosting (frontend) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve files from your project folder (index.html, login.html, ui.css, etc.)
app.use(express.static(__dirname, { extensions: ["html"] }));

// If you hit "/", serve index.html
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// SPA-like fallback (optional): any non-api route serves index.html
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// --- Start ---
app.listen(PORT, () => {
  console.log(`🚀 Server running at ${BASE_URL} (env=${NODE_ENV})`);

  (async () => {
    await initMailerUtils();
  })().catch((err) => {
    console.warn("Mailer startup init failed:", err?.message || err);
  });
});
