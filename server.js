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
 * - Returns both modern balances + legacy-friendly fields:
 *   checking, savings, totalbalance
 */

import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { initMailer as initMailerUtils, sendEmail, renderEmail } from "./utils/mailer.js";
import multer from "multer";
import PDFDocument from "pdfkit";


dotenv.config();

const NODE_ENV = process.env.NODE_ENV || "development";

console.log("ENV CHECK", {
  db: !!process.env.DATABASE_URL,
  email: !!(process.env.SMTP_HOST || process.env.EMAIL_HOST),
});

if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) {
  if (NODE_ENV !== "production") {
    console.warn("⚠️  ADMIN_USER/ADMIN_PASS not set. Using default admin credentials for development.");
  }
}
const PORT = Number(process.env.PORT) || 4000;

const DATABASE_URL = process.env.DATABASE_URL || "";
if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL in environment");
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const DEFAULT_ADMIN_USER = "info@shenzhenswift.online";
const DEFAULT_ADMIN_PASS = "Rancho@601$";
const ADMIN_USER = process.env.ADMIN_USER || (NODE_ENV !== "production" ? DEFAULT_ADMIN_USER : "");
const ADMIN_PASS = process.env.ADMIN_PASS || (NODE_ENV !== "production" ? DEFAULT_ADMIN_PASS : "");

const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const ADMIN_SECRET = process.env.ADMIN_SECRET ? String(process.env.ADMIN_SECRET) : "";

// --- Helpers ---
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || ""));
}

function issueToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      is_admin: user.is_admin === true
    },
    JWT_SECRET,
    { expiresIn: "2h" }
  );
}

function issueAdminToken(username) {
  return jwt.sign({ sub: "admin", username, is_admin: true }, JWT_SECRET, { expiresIn: "2h" });
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

function isAdminEmail(email) {
  const admins = [
    process.env.ADMIN_USER.toLowerCase()
  ];
  return admins.includes(email.toLowerCase());
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // ← REQUIRED
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.is_admin !== true) {
    if (res?.status) res.status(403).json({ error: "Admin only" });
    return false;
  }
  if (typeof next === "function") {
    next();
  }
  return true;
}

function requireAdminSecret(req, res) {
  if (!ADMIN_SECRET) {
    res.status(403).json({ error: "Admin secret not configured" });
    return false;
  }
  const provided = String(req.body?.admin_secret || "");
  if (!provided || provided !== ADMIN_SECRET) {
    res.status(403).json({ error: "Forbidden" });
    return false;
  }
  return true;
}

function requireAdminToken(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Unauthorized: missing admin token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const email = payload?.email || "";
    const isAdmin = payload?.is_admin === true || isAdminEmail(email);
    if (!payload || !isAdmin) {
      return res.status(403).json({ error: "Admin access only" });
    }
    req.admin = payload?.is_admin === true ? payload : { username: email || "admin", email };
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized: invalid or expired admin token" });
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

/**
 * Legacy compatibility:
 * Your frontend expects: checking, savings, totalbalance
 * We compute these from accounts rows.
 */
function buildBalanceSummary(accounts = []) {
  const byType = accounts.reduce((acc, a) => {
    const t = String(a.type || "").toLowerCase();
    acc[t] = (acc[t] || 0) + Number(a.balance || 0);
    return acc;
  }, {});

  const checking = Number((byType.checking || 0).toFixed(2));
  const savings = Number((byType.savings || 0).toFixed(2));
  const totalbalance = Number(
    accounts.reduce((s, a) => s + Number(a.balance || 0), 0).toFixed(2)
  );

  return { checking, savings, totalbalance };
}

function handleError(res, label, err) {
  console.error(label, err);
  if (NODE_ENV === "production") return res.status(500).json({ error: "Server error" });
  return res.status(500).json({ error: err.message || "Server error", stack: err.stack });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token && req.query?.token) token = String(req.query.token);

  if (!token) return res.status(401).json({ error: "Unauthorized: missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const isAdmin = payload?.is_admin === true || isAdminEmail(payload?.email);

    // Admin impersonation (optional)
    const asEmail = String(req.headers["x-admin-user-email"] || req.query?.as_user_email || "").trim().toLowerCase();
    if (isAdmin && asEmail) {
      try {
        const q = await pool.query("SELECT id, user_email AS email FROM users WHERE user_email=$1 LIMIT 1", [asEmail]);
        if (!q.rowCount) return res.status(404).json({ error: "User not found" });
        req.user = { sub: q.rows[0].id, email: q.rows[0].email, admin_override: true };
        return next();
      } catch (err) {
        return handleError(res, "Impersonation lookup error", err);
      }
    }

    req.user = payload;

    // Block locked accounts (admins bypass)
    if (!isAdmin) {
      const flags = loadAdminFlags();
      const userFlags = flags[String(req.user.sub)] || {};
      if (userFlags.locked === true) {
        return res.status(403).json({ error: "Account is locked" });
      }

      const loanLock = await pool.query(
        "SELECT locked FROM loans WHERE user_id=$1 AND locked=true LIMIT 1",
        [req.user.sub]
      );

      if (loanLock.rowCount) {
        return res.status(403).json({
          error: "Account temporarily locked pending loan processing fee."
        });
      }
    }

    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
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

// Fail-fast DB check
(async function verifyDB() {
  try {
    await pool.query("SELECT 1");

    console.log("✅ Postgres connected");
  } catch (e) {
    console.error("❌ Postgres connection failed at startup:", e);
    process.exit(1);
  }
})();

// --- Mailer (optional) ---
// --- Mailer (safe + correct) ---
let mailer = null;

async function initMailer() {
  const host = process.env.SMTP_HOST || process.env.EMAIL_HOST;
  const port = Number(process.env.SMTP_PORT || process.env.EMAIL_PORT || 587);
  const user = process.env.SMTP_USER || process.env.EMAIL_USER;
  const pass = process.env.SMTP_PASS || process.env.EMAIL_PASS;
  const from = process.env.MAIL_FROM || process.env.EMAIL_FROM || user;

  if (!host || !user || !pass || !from) {
    console.warn("✉️  Mailer disabled: missing SMTP env vars");
    return;
  }

  try {
    mailer = nodemailer.createTransport({
      host,
      port,
      secure: port === 465, // ✅ FIXED
      auth: { user, pass },
    });

    await mailer.verify(); // ❗ do NOT swallow errors
    mailer.from = from;

    console.log("✉️  Mailer ready");
  } catch (e) {
    mailer = null;
    console.warn("❌ Mailer init failed:", e.message);
  }
}

await initMailer();
await initMailerUtils();

// ---- Branded Email Helper (logo on every email) ----
const APP_BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/+$/, "");
const BRAND = {
  name: process.env.BRAND_NAME || "Bank Swift",
  supportEmail: process.env.SUPPORT_EMAIL || process.env.MAIL_FROM || "",
  logoPath: process.env.BRAND_LOGO_PATH || path.join(process.cwd(), "assets", "logo.png"),
  logoCid: "logocid", // referenced in HTML as cid:logocid
};
const BANKSWIFT_NOTIFY_EMAIL = process.env.BANKSWIFT_NOTIFY_EMAIL || "";
const GS_LOG_ENDPOINT = process.env.GS_LOG_ENDPOINT || "";
const GS_LOG_SECRET = process.env.GS_LOG_SECRET || process.env.SHEETS_SECRET || "";

const EMAIL_TEMPLATES_PATH = path.join(process.cwd(), "data", "email-templates.json");
const ADMIN_FLAGS_PATH = path.join(process.cwd(), "data", "admin-flags.json");
const ADMIN_SETTINGS_PATH = path.join(process.cwd(), "data", "admin-settings.json");
const ADMIN_AUDIT_PATH = path.join(process.cwd(), "data", "admin-audit.log");
const DEFAULT_EMAIL_TEMPLATES = {
  transferSender: {
    subject: "Transfer update",
    title: "Transfer update",
    preheader: "Your transfer of ${{amount}} is {{status}}.",
    text: "Your transfer of ${{amount}} is {{status}}.",
    bodyHtml:
      "<p>Your transfer of <b>${{amount}}</b> has been <b>{{status}}</b>.</p>" +
      "<p>Fee required to complete the transfer</p>" +
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
      "<p><b>Transfer Processing - {{status}}  (A fee is required to complete the transfer)</b></p>" +
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

function loadAdminFlags() {
  try {
    if (fs.existsSync(ADMIN_FLAGS_PATH)) {
      const raw = fs.readFileSync(ADMIN_FLAGS_PATH, "utf8");
      return JSON.parse(raw || "{}");
    }
  } catch (e) {
    console.warn("Admin flags load failed:", e.message);
  }
  return {};
}

function saveAdminFlags(flags) {
  ensureDataDir();
  fs.writeFileSync(ADMIN_FLAGS_PATH, JSON.stringify(flags, null, 2), "utf8");
}

function loadAdminSettings() {
  try {
    if (fs.existsSync(ADMIN_SETTINGS_PATH)) {
      const raw = fs.readFileSync(ADMIN_SETTINGS_PATH, "utf8");
      const parsed = JSON.parse(raw || "{}");
      return { feeRate: 0.235, ...parsed };
    }
  } catch (e) {
    console.warn("Admin settings load failed:", e.message);
  }
  return { feeRate: 0.235 };
}

function saveAdminSettings(settings) {
  ensureDataDir();
  fs.writeFileSync(ADMIN_SETTINGS_PATH, JSON.stringify(settings, null, 2), "utf8");
}

function logAdminAction(admin, action, details) {
  try {
    ensureDataDir();
    const entry = {
      ts: new Date().toISOString(),
      admin: admin?.username || "admin",
      action,
      details: details || null,
    };
    fs.appendFileSync(ADMIN_AUDIT_PATH, JSON.stringify(entry) + "\n", "utf8");
  } catch (e) {
    console.warn("Admin audit log failed:", e.message);
  }
}

async function recomputeUserBalances(client, userId) {
  const accQ = await client.query(
    "SELECT type, balance, available, currency FROM accounts WHERE user_id=$1",
    [userId]
  );
  const accounts = accQ.rows || [];
  const summary = buildBalanceSummary(accounts);
  await client.query(
    "UPDATE users SET checking=$1, savings=$2, totalbalance=$3 WHERE id=$4",
    [summary.checking, summary.savings, summary.totalbalance, userId]
  );
  return { accounts, ...summary };
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
  if (!mailer) throw new Error("Mailer not configured (SMTP env vars missing)");
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
    `INSERT INTO email_logs (user_id, to_email, subject, html_body, text_body, status)
     VALUES ($1,$2,$3,$4,$5,'pending')
     RETURNING id`,
    [userId || null, to, subject, htmlTemplate, text || null]
  );

  const emailId = logQ.rows[0].id;
  const html = htmlTemplate.replaceAll("__EMAIL_ID__", String(emailId));

  await pool.query(
    "UPDATE email_logs SET html_body=$2 WHERE id=$1",
    [emailId, html]
  );

  try {
    const result = await mailer.sendMail({
      from: mailer.from,
      to,
      subject,
      text: text || subject,
      html,
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

app.use(cors({
  origin: "https://shenzhenswift.online",
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(morgan("dev"));

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function getAppBaseUrl(req) {
  // Prefer env var so links work behind a domain/proxy
  const envBase = process.env.APP_BASE_URL;
  if (envBase) return envBase.replace(/\/+$/, "");

  // Fallback to request host
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").toString();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "polaris-uru5.onrender.com").toString();
  return `${proto}://${host}`.replace(/\/+$/, "");
}

async function sendPasswordResetEmail({ to, resetLink }) {
  if (!mailer) throw new Error("Mailer not configured (SMTP env vars missing)");
  await mailer.sendMail({
    from: mailer.from,
    to,
    subject: "Reset your password",
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.4">
        <p>You requested a password reset.</p>
        <p><a href="${resetLink}">Click here to reset your password</a></p>
        <p>This link expires in 1 hour. If you did not request this, you can ignore this email.</p>
      </div>
    `,
  });
}

// --- API Routes ---

// View email in browser
app.get("/emails/:id", async (req, res) => {
  const q = await pool.query(
    "SELECT html_body FROM email_logs WHERE id=$1 LIMIT 1",
    [req.params.id]
  );
  if (!q.rowCount) return res.status(404).send("Email not found");
  return res.send(q.rows[0].html_body);
});

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    if (!ADMIN_USER || !ADMIN_PASS) {
      return res.status(501).json({ error: "Admin login is not configured" });
    }
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username and password required" });
    }
    if (String(username) !== String(ADMIN_USER) || String(password) !== String(ADMIN_PASS)) {
      return res.status(401).json({ error: "Invalid admin credentials" });
    }
    const token = issueAdminToken(String(username));
    return res.json({ token });
  } catch (err) {
    return handleError(res, "Admin login error", err);
  }
});

// Public settings
app.get("/api/settings", async (req, res) => {
  try {
    const settings = loadAdminSettings();
    return res.json({ feeRate: Number(settings.feeRate) || 0.235 });
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

    const existing = await pool.query("SELECT id FROM users WHERE user_email = $1", [normEmail]);
    if (existing.rowCount) return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const insertUser = await client.query(
        `INSERT INTO users (fullname, user_email, password_hash, phone, accountname, ssn_last4, ssn_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING id, fullname, user_email AS email, accountname, ssn_last4`,
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
           user_id, dob, citizenship_status,
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
          user.id,
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
           user_id, doc_category, doc_type, doc_number_last4, issuer, expires_on, status
         ) VALUES ($1,'government_id',$2,$3,$4,$5,'received')`,
        [
          user.id,
          gov_id_type,
          gov_id_last4 ? String(gov_id_last4) : null,
          gov_id_issuer ? String(gov_id_issuer) : null,
          gov_id_expires_on ? gov_id_expires_on : null
        ]
      );

      const accQ = await client.query(
        `INSERT INTO accounts (user_id, type, currency, balance, available)
         VALUES
           ($1, 'checking', 'USD', 0, 0),
           ($1, 'savings',  'USD', 0, 0)
         ON CONFLICT (user_id, type) DO NOTHING
         RETURNING id, type, balance, available, currency`,
        [user.id]
      );

      // Let Postgres calculate/maintain aggregate balances (e.g., via generated columns/triggers)
      const balQ = await client.query(
        "SELECT checking, savings, totalbalance FROM users WHERE id=$1",
        [user.id]
      );

      await client.query("COMMIT");

      const accounts = accQ.rows || [];
      const balancesRow = balQ.rows?.[0] || {};
      const checking = Number(balancesRow.checking ?? 0);
      const savings = Number(balancesRow.savings ?? 0);
      const totalbalance = Number(balancesRow.totalbalance ?? 0);
      const token = issueToken({ id: user.id, email: user.email });

      try {
        await sendBrandedEmail({
          to: user.email,
          subject: "Welcome to Bank Swift",
          title: "Your account is ready",
          preheader: "Welcome to Bank Swift — your account has been created.",
          text: `Hi ${user.fullname}, your Bank Swift account has been created successfully.`,
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
        if (mailer && BANKSWIFT_NOTIFY_EMAIL) {
          const adminAttachments = [];
          if (govFront) adminAttachments.push({ filename: `gov_id_front${path.extname(govFront.originalname || "") || ".jpg"}`, path: govFront.path });
          if (govBack) adminAttachments.push({ filename: `gov_id_back${path.extname(govBack.originalname || "") || ".jpg"}`, path: govBack.path });
          if (proofAddr) adminAttachments.push({ filename: `proof_of_address${path.extname(proofAddr.originalname || "") || ".pdf"}`, path: proofAddr.path });

          await sendBrandedEmail({
            to: BANKSWIFT_NOTIFY_EMAIL,
            subject: "New registration received (documents attached)",
            title: "New registration + documents",
            preheader: `New user: ${user.fullname} (${normEmail})`,
            text: `New registration. Documents attached: ${adminAttachments.map(a => a.filename).join(", ")}`,
            bodyHtml: `
        <p><b>New registration received</b></p>
        <p>Documents are attached to this email:</p>
        <ul>
          <li>Government ID (front): ${govFront ? "✅" : "❌"}</li>
          <li>Government ID (back): ${govBack ? "✅" : "—"}</li>
          <li>Proof of address: ${proofAddr ? "✅" : "—"}</li>
        </ul>
      `,
            attachments: adminAttachments,
          });
        }
      } catch (e) {
        console.warn("BankSwift registration notify email failed:", e.message);
      }

      try {
        if (mailer) {
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
        id: user.id,
        fullname: user.fullname,
        email: user.email,
        accountname: user.accountname,

        // legacy-friendly
  checking,
  savings,
  totalbalance,

        // modern
  balances: { total: totalbalance, accounts },

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
  try {
    const emailRaw = req.body.user_email || req.body.email || ""; // accept both frontend fields
    const email = String(emailRaw).trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Missing credentials" });
    }

    // ✅ ADMIN LOGIN via standard login endpoint (/api/login)
    const adminUser = String(ADMIN_USER || "").trim().toLowerCase();
    const adminPass = String(ADMIN_PASS || "");

    if (adminUser && adminPass && email === adminUser && password === adminPass) {
      const token = issueToken({
        id: "admin",
        email: adminUser,
        is_admin: true,
      });

      return res.json({
        id: "admin",
        fullname: "Administrator",
        email: adminUser,
        accountname: "Admin Console",
        is_admin: true,
        token,
      });
    }

    const q = await pool.query(
      `SELECT
         id,
         fullname,
         user_email,
         accountname,
         password_hash,
         suspended
       FROM users
       WHERE user_email = $1
       LIMIT 1`,
      [email.toLowerCase()]
    );

    if (!q.rowCount) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = q.rows[0];

    if (user.suspended) {
      return res.status(403).json({ error: "Account suspended" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const is_admin = isAdminEmail(user.user_email);

    const token = issueToken({
      id: user.id,
      email: user.user_email,
      is_admin,
    });

    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.user_email,
      accountname: user.accountname,
      is_admin,
      token,
    });
  } catch (err) {
    return handleError(res, "Login error", err);
  }
});

// Current user
app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.sub;

    const userQ = await pool.query(
      "SELECT id, fullname, user_email AS email, accountname, checking, savings, totalbalance FROM users WHERE id=$1",
      [userId]
    );
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });

    const user = userQ.rows[0];

    const accQ = await pool.query(
      "SELECT id, type, balance, available, currency FROM accounts WHERE user_id=$1",
      [userId]
    );
    const accounts = accQ.rows || [];
    const checking = Number(user.checking ?? 0);
    const savings = Number(user.savings ?? 0);
    const totalbalance = Number(user.totalbalance ?? 0);

    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,

      // legacy-friendly
      checking,
      savings,
      totalbalance,

      // modern
      balances: { total: totalbalance, accounts },
    });
  } catch (err) {
    return handleError(res, "Profile fetch error", err);
  }
});

// Change password (settings.html expects POST /api/users/password with { new_password })
app.post("/api/users/password", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { new_password } = req.body || {};

    if (typeof new_password !== "string" || new_password.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters" });
    }

    const newHash = await bcrypt.hash(new_password, 10);

    await pool.query(
      `UPDATE users
       SET password_hash = $1,
           updated_at = now()
       WHERE id = $2`,
      [newHash, userId]
    );

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
    if (!mailer) {
      return res.status(501).json({
        error: "Email is not configured on this server. Set SMTP_* env vars.",
      });
    }

    const uQ = await pool.query(
      `SELECT id, user_email
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
       WHERE user_id = $1 OR expires_at < now() OR used_at IS NOT NULL`,
      [user.id]
    );

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expires]
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
         t.user_id,
         t.expires_at,
         t.used_at
       FROM password_reset_tokens t
       JOIN users u ON u.id = t.user_id
       WHERE u.user_email = $1
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
       WHERE id = $2`,
      [newHash, row.user_id]
    );

    await client.query(
      `UPDATE password_reset_tokens
       SET used_at = now()
       WHERE id = $1`,
      [row.token_id]
    );

    await client.query("COMMIT");

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
    const userId = req.user.sub;

    const accQ = await pool.query("SELECT id FROM accounts WHERE user_id=$1", [userId]);
    const accIds = accQ.rows.map((r) => r.id);
    if (!accIds.length) return res.json([]);

    // If your table doesn't store balance_after fields,
    // we still return them as null to keep the UI stable.
    const q = await pool.query(
      `SELECT
          t.id,
          t.account_id,
          t.type,
          t.amount,
          t.description,
          t.reference,
          t.created_at,
          a.type AS account_type,
          a.currency,
          NULL::numeric AS balance_after,
          NULL::numeric AS total_balance_after
       FROM transactions t
       JOIN accounts a ON a.id = t.account_id
       WHERE t.account_id = ANY($1::uuid[])
       ORDER BY t.created_at DESC
       LIMIT 100`,
      [accIds]
    );

    return res.json(q.rows);
  } catch (err) {
    return handleError(res, "Transactions error", err);
  }
});

// Transfers (final, safe, audited)
app.post("/api/transfers", authMiddleware, async (req, res) => {
  const client = await pool.connect();

  try {
    const userId = req.user.sub;

    const {
      sender_account_type,        // "checking" | "savings"
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

    if (!sender_account_type || amount == null) {
      return res.status(400).json({
        error: "Missing required fields: sender_account_type and amount",
      });
    }

    if (!recipient_email || !validateEmail(recipient_email)) {
      return res.status(400).json({ error: "Valid recipient_email is required" });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    const flags = loadAdminFlags();
    const userFlags = flags[String(userId)] || {};
    if (userFlags.transfers_disabled === true) {
      return res.status(403).json({ error: "Transfers are disabled for this account" });
    }

    await client.query("BEGIN");

    /* ---------- LOCK SENDER ACCOUNT ---------- */

    const senderQ = await client.query(
      `SELECT id, user_id, balance, available, type
       FROM accounts
       WHERE user_id = $1 AND type = $2
       LIMIT 1
       FOR UPDATE`,
      [userId, sender_account_type]
    );

    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sender account not found" });
    }

    const senderAcc = senderQ.rows[0];

    if (Number(senderAcc.available) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: `Insufficient funds in ${senderAcc.type}`,
      });
    }

    /* ---------- RESOLVE RECIPIENT (INTERNAL VS EXTERNAL) ---------- */

    let isInternal = false;
    let recipientAcc = null;

    if (recipient_email) {
      const uQ = await client.query(
        `SELECT id FROM users WHERE user_email = $1 LIMIT 1`,
        [String(recipient_email).toLowerCase()]
      );

      if (uQ.rowCount) {
        const recUserId = uQ.rows[0].id;
        const accQ = await client.query(
          `SELECT id, user_id, balance, available, type
           FROM accounts
           WHERE user_id = $1 AND type = 'checking'
           LIMIT 1
           FOR UPDATE`,
          [recUserId]
        );

        if (accQ.rowCount) {
          recipientAcc = accQ.rows[0];
          isInternal = true;
        }
      }
    }

    const transferStatus = "pending";

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
        (user_id, account_id, direction, amount, description, balance_after, created_at)
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

      const recDesc = description || `Received from ${senderAcc.type} account`;

      await client.query(
        `INSERT INTO transactions
          (user_id, account_id, direction, amount, description, balance_after, created_at)
         VALUES ($1,$2,'credit',$3,$4,$5,NOW())`,
        [recipientAcc.user_id, recipientAcc.id, amt, recDesc, recNewBalance]
      );
    }

    /* ---------- RECORD TRANSFER ---------- */

    const transferQ = await client.query(
      `INSERT INTO transfers
        (
          user_id,
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
        senderAcc.type,
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
      if (mailer) {
        // sender
        const templates = loadEmailTemplates();
        const transferSenderTpl = templates.transferSender || {};
        const { feeRate } = loadAdminSettings();
        const feeAmount = amt * Number(feeRate || 0);
        const feeText = feeAmount.toFixed(2);
        const senderDataPlain = {
          amount: amt.toFixed(2),
          status: transferStatus,
          fee: feeText,
        };
        const senderDataHtml = {
          amount: escapeHtml(senderDataPlain.amount),
          status: escapeHtml(senderDataPlain.status),
          fee: escapeHtml(senderDataPlain.fee),
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
          const recipientStatusLabel = transferStatus === "pending" ? "pending" : "completed";
          const recipientSubject = transferStatus === "pending"
            ? "Incoming transfer pending"
            : "You received a transfer";
          const recipientTitle = transferStatus === "pending"
            ? "Incoming transfer pending"
            : "Incoming transfer";
          const recipientNameText = recipient_name || "Recipient";
          const recipientBankText = bank_name || "—";
          const recipientRoutingText = routing_number || "—";
          const recipientAccountText = account_number || "—";
          const feeText = feeAmount.toFixed(2);

          const transferRecipientTpl = templates.transferRecipient || {};
          const dataPlain = {
            amount: amt.toFixed(2),
            status: recipientStatusLabel,
            recipient_name: recipientNameText,
            bank_name: recipientBankText,
            routing_number: recipientRoutingText,
            account_number: recipientAccountText,
            fee: feeText,
          };
          const dataHtml = {
            amount: escapeHtml(dataPlain.amount),
            status: escapeHtml(dataPlain.status),
            recipient_name: escapeHtml(dataPlain.recipient_name),
            bank_name: escapeHtml(dataPlain.bank_name),
            routing_number: escapeHtml(dataPlain.routing_number),
            account_number: escapeHtml(dataPlain.account_number),
            fee: escapeHtml(dataPlain.fee),
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

// Confirm pending transfers (admin secret)
app.post("/api/transfers/confirm", async (req, res) => {
  if (!requireAdminSecret(req, res)) return;

  const client = await pool.connect();
  try {
    const transferId = String(req.body?.transfer_id || "");
    if (!transferId) return res.status(400).json({ error: "transfer_id required" });

    await client.query("BEGIN");
    const q = await client.query(
      "SELECT id, status FROM transfers WHERE id=$1 FOR UPDATE",
      [transferId]
    );
    if (!q.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Transfer not found" });
    }

    const row = q.rows[0];
    if (String(row.status) !== "pending") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Transfer is not pending" });
    }

    try {
      await client.query(
        "UPDATE transfers SET status='pending', updated_at=NOW() WHERE id=$1",
        [transferId]
      );
    } catch {
      await client.query(
        "UPDATE transfers SET status='pending' WHERE id=$1",
        [transferId]
      );
    }

    await client.query("COMMIT");
    return res.json({ success: true, status: "pending" });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    return handleError(res, "Confirm transfer error", err);
  } finally {
    client.release();
  }
});

// Apply for Loan
app.post("/api/loans", authMiddleware, async (req, res) => {
  try {
    const { amount, term_months } = req.body;

    if (!amount || !term_months) {
      return res.status(400).json({ error: "Amount and term required" });
    }

    const apr = 8.5;
    const monthly = (Number(amount) / Number(term_months)).toFixed(2);

    const q = await pool.query(
      `INSERT INTO loans
       (user_id, amount, term_months, apr_estimate, monthly_payment_estimate)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [req.user.sub, amount, term_months, apr, monthly]
    );

    res.status(201).json(q.rows[0]);
  } catch (err) {
    handleError(res, "Loan apply error", err);
  }
});

// Get User Loans
app.get("/api/loans", authMiddleware, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT * FROM loans WHERE user_id=$1 ORDER BY created_at DESC`,
      [req.user.sub]
    );

    res.json(q.rows);
  } catch (err) {
    handleError(res, "Loan fetch error", err);
  }
});

app.post("/api/loans/:id/pay-fee", authMiddleware, async (req, res) => {
  await pool.query(
    `UPDATE loans
     SET fee_paid=true,
         locked=false,
         status='under_review'
     WHERE id=$1 AND user_id=$2`,
    [req.params.id, req.user.sub]
  );

  res.json({ success: true });
});

// --- Admin ---
// Admin: dashboard stats
app.get("/api/admin/stats", requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await pool.query("SELECT COUNT(*) FROM users");
    const pendingTransfers = await pool.query(
      "SELECT COUNT(*) FROM transfers WHERE status = 'pending'"
    );
    const suspendedUsers = await pool.query(
      "SELECT COUNT(*) FROM users WHERE suspended = true"
    );

    res.json({
      total_users: Number(users.rows[0].count),
      pending_transfers: Number(pendingTransfers.rows[0].count),
      locked_users: Number(suspendedUsers.rows[0].count),
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    res.status(500).json({ error: "Failed to load admin stats" });
  }
});

// Admin: transfers list by status
app.get("/api/admin/transfers", requireAdminToken, async (req, res) => {
  const status = req.query.status || "pending";

  const q = await pool.query(
    `SELECT id, amount, recipient_name, recipient_email, created_at
     FROM transfers
     WHERE status = $1
     ORDER BY created_at DESC`,
    [status]
  );

  res.json(q.rows);
});

app.post("/api/admin/loans/:id/status", requireAdminToken, async (req, res) => {
  const { status, processing_fee } = req.body;
  const loanId = req.params.id;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const loanQ = await client.query(
      "SELECT * FROM loans WHERE id=$1 FOR UPDATE",
      [loanId]
    );

    if (!loanQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Loan not found" });
    }

    const loan = loanQ.rows[0];

    await client.query(
      `UPDATE loans
       SET status=$1,
           processing_fee=$2,
           locked=$3,
           updated_at=NOW()
       WHERE id=$4`,
      [
        status,
        processing_fee || null,
        status === "processing_fee_required",
        loanId
      ]
    );

    if (status === "approved") {
      await client.query(
        `UPDATE accounts
         SET balance = balance + $1,
             available = available + $1
         WHERE user_id=$2 AND type='checking'`,
        [loan.amount, loan.user_id]
      );
    }

    await client.query("COMMIT");

    // 🔔 AUTO EMAIL
    if (mailer) {
      if (status === "processing_fee_required") {
        const expiresAt = getFeeExpiry(48);

        const invoicePdf = await generateFeeInvoicePDF({
          borrowerEmail: loan.user_id,
          amount: loan.amount,
          fee: processing_fee,
          expiresAt
        });

        await sendBrandedEmail({
          to: loan.user_email,
          subject: "Processing Fee Required",
          title: "Processing Fee Required",
          bodyHtml: `
            <p>Your loan requires a processing fee of <b>$${processing_fee}</b>.</p>
            <p>Please complete payment to proceed.</p>
          `,
          attachments: [{
            filename: "processing-fee-invoice.pdf",
            content: invoicePdf,
            contentType: "application/pdf"
          }]
        });
      }

      if (status === "approved") {
        await sendBrandedEmail({
          to: loan.user_email,
          subject: "Loan Approved",
          title: "Loan Approved",
          bodyHtml: `
            <p>Your loan of <b>$${loan.amount}</b> has been approved.</p>
          `
        });
      }
    }

    res.json({ success: true });

  } catch (err) {
    await client.query("ROLLBACK");
    handleError(res, "Loan status update", err);
  } finally {
    client.release();
  }
});

// Admin: email templates
app.get("/api/admin/email-templates", requireAdminToken, async (req, res) => {
  try {
    return res.json(loadEmailTemplates());
  } catch (err) {
    return handleError(res, "Admin email templates get", err);
  }
});

// Admin: send manual email
app.post("/api/admin/send-email", requireAdminToken, async (req, res) => {
  try {
    const {
      to,
      subject,
      title,
      preheader = "",
      bodyHtml,
      text = ""
    } = req.body || {};

    if (!to || !subject || !bodyHtml) {
      return res.status(400).json({
        error: "to, subject, and bodyHtml are required"
      });
    }

    await sendBrandedEmail({
      to,
      subject,
      title: title || subject,
      preheader,
      text,
      bodyHtml
    });

    // 🔒 Audit log
    logAdminAction(req.admin, "send_manual_email", {
      to,
      subject
    });

    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin send manual email", err);
  }
});

// Admin: send processing fee notice
app.post("/api/admin/send-processing-fee-notice", requireAdminToken, async (req, res) => {
  try {
    const { email, amount, fee } = req.body || {};
    if (!email || !amount || !fee) {
      return res.status(400).json({
        error: "email, amount, and fee are required"
      });
    }

    const templates = loadEmailTemplates();
    const tpl = templates.processingFeeNotice;
    if (!tpl) {
      return res.status(500).json({ error: "processingFeeNotice template not found" });
    }

    const expiresAt = getFeeExpiry(48);

    // Generate invoice PDF
    const invoicePdf = await generateFeeInvoicePDF({
      borrowerEmail: email,
      amount: Number(amount).toFixed(2),
      fee: Number(fee).toFixed(2),
      expiresAt
    });

    const dataPlain = {
      borrower_name: email,
      amount: Number(amount).toFixed(2),
      fee: Number(fee).toFixed(2),
      expires_at: expiresAt.toLocaleString()
    };

    const dataHtml = {
      borrower_name: escapeHtml(dataPlain.borrower_name),
      amount: escapeHtml(dataPlain.amount),
      fee: escapeHtml(dataPlain.fee),
      expires_at: escapeHtml(dataPlain.expires_at)
    };

    await sendBrandedEmail({
      to: email,
      subject: renderTemplate(tpl.subject, dataPlain),
      title: renderTemplate(tpl.title, dataPlain),
      preheader: renderTemplate(tpl.preheader, dataPlain),
      text: renderTemplate(tpl.text, dataPlain),
      bodyHtml: renderTemplate(tpl.bodyHtml, dataHtml),
      attachments: [
        {
          filename: "processing-fee-invoice.pdf",
          content: invoicePdf,
          contentType: "application/pdf"
        }
      ]
    });

    // 🔒 Audit log
    logAdminAction(req.admin, "send_processing_fee_notice", {
      email,
      amount: dataPlain.amount,
      fee: dataPlain.fee,
      expires_at: expiresAt.toISOString()
    });

    return res.json({
      success: true,
      expires_at: expiresAt
    });
  } catch (err) {
    return handleError(res, "Send processing fee notice", err);
  }
});

app.post("/api/admin/email-templates", requireAdminToken, async (req, res) => {
  try {
    const { key, template, templates } = req.body || {};
    const current = loadEmailTemplates();

    if (templates && typeof templates === "object") {
      saveEmailTemplates({ ...current, ...templates });
      logAdminAction(req.admin, "email_template_bulk_update", { keys: Object.keys(templates) });
      return res.json({ success: true });
    }

    if (!key || !template || typeof template !== "object") {
      return res.status(400).json({ error: "key and template are required" });
    }

    if (!Object.prototype.hasOwnProperty.call(current, key)) {
      return res.status(400).json({ error: "Unknown template key" });
    }

    const updated = { ...current, [key]: { ...current[key], ...template } };
    saveEmailTemplates(updated);
    logAdminAction(req.admin, "email_template_update", { key });
    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin email templates update", err);
  }
});

// Admin: impersonate user (issue a user token)
app.post("/api/admin/impersonate", requireAdminToken, async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ error: "email is required" });

    const q = await pool.query(
      "SELECT id, fullname, user_email AS email, accountname FROM users WHERE user_email=$1 LIMIT 1",
      [email]
    );
    if (!q.rowCount) return res.status(404).json({ error: "User not found" });

    const user = q.rows[0];
    const token = issueToken({ id: user.id, email: user.email });
    return res.json({ user, token });
  } catch (err) {
    return handleError(res, "Admin impersonate", err);
  }
});

// Admin: settings
app.get("/api/admin/settings", requireAdminToken, async (req, res) => {
  try {
    return res.json(loadAdminSettings());
  } catch (err) {
    return handleError(res, "Admin settings get", err);
  }
});

app.post("/api/admin/settings", requireAdminToken, async (req, res) => {
  try {
    const { feeRate } = req.body || {};
    const rate = Number(feeRate);
    if (!Number.isFinite(rate) || rate < 0 || rate > 1) {
      return res.status(400).json({ error: "feeRate must be between 0 and 1" });
    }
    saveAdminSettings({ feeRate: rate });
    logAdminAction(req.admin, "settings_update", { feeRate: rate });
    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin settings update", err);
  }
});

// Admin: audit logs
app.get("/api/admin/audit", requireAdminToken, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query?.limit || 200), 500);
    if (!fs.existsSync(ADMIN_AUDIT_PATH)) return res.json([]);
    const raw = fs.readFileSync(ADMIN_AUDIT_PATH, "utf8");
    const lines = raw.trim().split("\n").filter(Boolean);
    const sliced = lines.slice(-limit);
    const entries = sliced.map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    return res.json(entries);
  } catch (err) {
    return handleError(res, "Admin audit log", err);
  }
});

// Admin: user lookup
app.get("/api/admin/user", requireAdminToken, async (req, res) => {
  try {
    const email = String(req.query?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ error: "email is required" });

    const userQ = await pool.query(
      "SELECT id, fullname, user_email AS email, accountname, checking, savings, totalbalance FROM users WHERE user_email=$1 LIMIT 1",
      [email]
    );
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });

    const user = userQ.rows[0];
    const accQ = await pool.query(
      "SELECT id, type, balance, available, currency FROM accounts WHERE user_id=$1",
      [user.id]
    );
    const flags = loadAdminFlags();
    const userFlags = flags[String(user.id)] || {};
    return res.json({
      user,
      accounts: accQ.rows || [],
      flags: userFlags,
    });
  } catch (err) {
    return handleError(res, "Admin user lookup", err);
  }
});

// Admin: list all users (summary)
app.get("/api/admin/users", requireAdminToken, async (req, res) => {
  try {
    const q = await pool.query(`
      SELECT
        id,
        fullname,
        user_email AS email,
        accountname,
        checking,
        savings,
        totalbalance,
        suspended,
        created_at
      FROM users
      ORDER BY created_at DESC
      LIMIT 1000
    `);

    return res.json(q.rows);
  } catch (err) {
    return handleError(res, "Admin list users", err);
  }
});

// Admin: list recent emails for a user
app.get("/api/admin/users/:id/emails", authMiddleware, async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const q = await pool.query(
    `SELECT id, subject, status, created_at
     FROM email_logs
     WHERE user_id=$1
     ORDER BY created_at DESC
     LIMIT 50`,
    [req.params.id]
  );

  res.json(q.rows);
});

// Admin: update user profile fields
app.post("/api/admin/user/update", requireAdminToken, async (req, res) => {
  try {
    const { email, new_email, fullname, accountname } = req.body || {};
    const currentEmail = String(email || "").trim().toLowerCase();
    if (!currentEmail) return res.status(400).json({ error: "email is required" });

    if (new_email && !validateEmail(new_email)) {
      return res.status(400).json({ error: "Valid new_email required" });
    }

    if (new_email) {
      const exists = await pool.query("SELECT id FROM users WHERE user_email=$1", [String(new_email).toLowerCase()]);
      if (exists.rowCount) return res.status(409).json({ error: "Email already in use" });
    }

    const q = await pool.query(
      `UPDATE users
       SET user_email = COALESCE($1, user_email),
           fullname = COALESCE($2, fullname),
           accountname = COALESCE($3, accountname),
           updated_at = now()
       WHERE user_email = $4
       RETURNING id, fullname, user_email AS email, accountname, checking, savings, totalbalance`,
      [new_email ? String(new_email).toLowerCase() : null, fullname || null, accountname || null, currentEmail]
    );

    if (!q.rowCount) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.admin, "user_update", { email: currentEmail, new_email, fullname, accountname });
    return res.json({ user: q.rows[0] });
  } catch (err) {
    return handleError(res, "Admin user update", err);
  }
});

// Admin: update user flags (lock, transfers disabled, KYC status)
app.post("/api/admin/user/flags", requireAdminToken, async (req, res) => {
  try {
    const { email, locked, transfers_disabled, kyc_status } = req.body || {};
    const userEmail = String(email || "").trim().toLowerCase();
    if (!userEmail) return res.status(400).json({ error: "email is required" });

    const userQ = await pool.query("SELECT id FROM users WHERE user_email=$1 LIMIT 1", [userEmail]);
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });
    const userId = userQ.rows[0].id;

    const flags = loadAdminFlags();
    const current = flags[String(userId)] || {};
    const updated = {
      ...current,
      ...(typeof locked === "boolean" ? { locked } : {}),
      ...(typeof transfers_disabled === "boolean" ? { transfers_disabled } : {}),
      ...(typeof kyc_status === "string" && kyc_status ? { kyc_status } : {}),
    };
    flags[String(userId)] = updated;
    saveAdminFlags(flags);
    logAdminAction(req.admin, "user_flags_update", { email: userEmail, ...updated });
    return res.json({ success: true, flags: updated });
  } catch (err) {
    return handleError(res, "Admin user flags update", err);
  }
});

// Admin: reset user password
app.post("/api/admin/user/reset-password", requireAdminToken, async (req, res) => {
  try {
    const { email, new_password } = req.body || {};
    const userEmail = String(email || "").trim().toLowerCase();
    if (!userEmail) return res.status(400).json({ error: "email is required" });
    if (typeof new_password !== "string" || new_password.length < 6) {
      return res.status(400).json({ error: "new_password must be at least 6 characters" });
    }

    const newHash = await bcrypt.hash(new_password, 10);
    const q = await pool.query(
      "UPDATE users SET password_hash=$1, updated_at=now() WHERE user_email=$2 RETURNING id",
      [newHash, userEmail]
    );
    if (!q.rowCount) return res.status(404).json({ error: "User not found" });
    logAdminAction(req.admin, "reset_password", { email: userEmail });
    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin reset password", err);
  }
});

// Admin: suspend user (block login)
app.post("/api/admin/user/suspend", requireAdminToken, async (req, res) => {
  await pool.query(
    "UPDATE users SET suspended = true WHERE user_email = $1",
    [req.body.email]
  );
  res.json({ ok: true });
});

// Admin: resume user (unsuspend)
app.post("/api/admin/user/resume", requireAuth, requireAdmin, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  await pool.query(
    "UPDATE users SET suspended = false WHERE user_email = $1",
    [email.toLowerCase()]
  );

  res.json({ ok: true });
});

// Admin: delete user (hard delete)
app.post("/api/admin/user/delete", requireAdminToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { email } = req.body || {};
    const userEmail = String(email || "").trim().toLowerCase();
    if (!userEmail) return res.status(400).json({ error: "email is required" });

    await client.query("BEGIN");
    const userQ = await client.query("SELECT id FROM users WHERE user_email=$1 LIMIT 1", [userEmail]);
    if (!userQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }
    const userId = userQ.rows[0].id;

    const safeDelete = async (sql, params) => {
      try { await client.query(sql, params); } catch (err) {
        if (err?.code !== "42P01") throw err;
      }
    };

    await safeDelete("DELETE FROM password_reset_tokens WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM user_documents WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM user_profiles WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM transfers WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM transactions WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM accounts WHERE user_id=$1", [userId]);
    await safeDelete("DELETE FROM users WHERE id=$1", [userId]);

    const flags = loadAdminFlags();
    delete flags[String(userId)];
    saveAdminFlags(flags);

    await client.query("COMMIT");
    logAdminAction(req.admin, "user_delete", { email: userEmail });
    return res.json({ success: true });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    return handleError(res, "Admin delete user", err);
  } finally {
    client.release();
  }
});

// Admin: adjust balances
app.post("/api/admin/accounts/adjust", requireAdminToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, account_type, amount, mode = "increment" } = req.body || {};
    const userEmail = String(email || "").trim().toLowerCase();
    if (!userEmail) return res.status(400).json({ error: "email is required" });
    if (!account_type || !["checking", "savings"].includes(String(account_type).toLowerCase())) {
      return res.status(400).json({ error: "account_type must be checking or savings" });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt)) return res.status(400).json({ error: "Valid amount required" });

    await client.query("BEGIN");

    const userQ = await client.query("SELECT id FROM users WHERE user_email=$1 LIMIT 1", [userEmail]);
    if (!userQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }
    const userId = userQ.rows[0].id;

    const accQ = await client.query(
      `SELECT id, balance, available FROM accounts
       WHERE user_id=$1 AND type=$2
       LIMIT 1 FOR UPDATE`,
      [userId, String(account_type).toLowerCase()]
    );
    if (!accQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Account not found" });
    }

    const acc = accQ.rows[0];
    const newBalance = mode === "set" ? amt : Number(acc.balance) + amt;
    const newAvailable = mode === "set" ? amt : Number(acc.available) + amt;

    await client.query(
      "UPDATE accounts SET balance=$1, available=$2, updated_at=now() WHERE id=$3",
      [newBalance, newAvailable, acc.id]
    );

    const summary = await recomputeUserBalances(client, userId);
    await client.query("COMMIT");

    logAdminAction(req.admin, "balance_adjust", { email: userEmail, account_type, mode, amount: amt });
    return res.json({ success: true, balances: summary });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    return handleError(res, "Admin adjust balance", err);
  } finally {
    client.release();
  }
});

// Admin: resend transfer email
app.post("/api/admin/resend/transfer-email", requireAdminToken, async (req, res) => {
  try {
    const { transfer_id, target = "recipient" } = req.body || {};
    if (!transfer_id) return res.status(400).json({ error: "transfer_id required" });

    const tQ = await pool.query(
      "SELECT id, user_id, amount, recipient_name, recipient_email, bank_name, routing_number, account_number, status FROM transfers WHERE id=$1",
      [transfer_id]
    );
    if (!tQ.rowCount) return res.status(404).json({ error: "Transfer not found" });
    const tx = tQ.rows[0];

    const senderQ = await pool.query(
      "SELECT user_email AS email, fullname, accountname FROM users WHERE id=$1",
      [tx.user_id]
    );
    const sender = senderQ.rows?.[0] || {};

    if (!mailer) return res.status(501).json({ error: "Mailer not configured" });

    const amt = Number(tx.amount) || 0;
    const status = String(tx.status || "pending");
    const { feeRate } = loadAdminSettings();
    const feeAmount = amt * Number(feeRate || 0);
    const feeText = feeAmount.toFixed(2);

    if (String(target).toLowerCase() === "sender") {
      if (!sender.email) return res.status(400).json({ error: "Sender email not found" });
      await sendBrandedEmail({
        to: sender.email,
        subject: "Transfer update",
        title: "Transfer update",
        preheader: `Your transfer of $${amt.toFixed(2)} is ${status}.`,
        text: `Your transfer of $${amt.toFixed(2)} is ${status}.`,
        bodyHtml: `
    <p>Your transfer of <b>$${amt.toFixed(2)}</b> has been <b>${escapeHtml(status)}</b>.</p>
    <p>If you did not authorize this activity, please contact support immediately.</p>
  `,
      });
    } else {
      const recipientEmail = tx.recipient_email;
      if (!recipientEmail) return res.status(400).json({ error: "Recipient email not found" });
      const recipientNameText = tx.recipient_name || "Recipient";
      const dataPlain = {
        amount: amt.toFixed(2),
        status,
        recipient_name: recipientNameText,
        bank_name: tx.bank_name || "—",
        routing_number: tx.routing_number || "—",
        account_number: tx.account_number || "—",
        fee: feeText,
      };
      const dataHtml = {
        amount: escapeHtml(dataPlain.amount),
        status: escapeHtml(dataPlain.status),
        recipient_name: escapeHtml(dataPlain.recipient_name),
        bank_name: escapeHtml(dataPlain.bank_name),
        routing_number: escapeHtml(dataPlain.routing_number),
        account_number: escapeHtml(dataPlain.account_number),
        fee: escapeHtml(dataPlain.fee),
      };
      const templates = loadEmailTemplates();
      const tpl = templates.transferRecipient || {};

      await sendBrandedEmail({
        to: recipientEmail,
        subject: renderTemplate(tpl.subject || "Incoming transfer", dataPlain),
        title: renderTemplate(tpl.title || "Incoming transfer", dataPlain),
        preheader: renderTemplate(tpl.preheader, dataPlain),
        text: renderTemplate(tpl.text, dataPlain),
        bodyHtml: renderTemplate(tpl.bodyHtml, dataHtml),
      });
    }

    logAdminAction(req.admin, "resend_transfer_email", { transfer_id, target });
    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin resend transfer email", err);
  }
});

// Admin: resend registration emails
app.post("/api/admin/resend/registration-email", requireAdminToken, async (req, res) => {
  try {
    const { email } = req.body || {};
    const userEmail = String(email || "").trim().toLowerCase();
    if (!userEmail) return res.status(400).json({ error: "email is required" });

    const q = await pool.query(
      "SELECT fullname, user_email AS email FROM users WHERE user_email=$1 LIMIT 1",
      [userEmail]
    );
    if (!q.rowCount) return res.status(404).json({ error: "User not found" });
    const user = q.rows[0];
    if (!mailer) return res.status(501).json({ error: "Mailer not configured" });

    await sendBrandedEmail({
      to: user.email,
      subject: "Registration received",
      title: "We received your registration",
      preheader: "Next step: verification of your information.",
      text: `We received your registration. Next step: verification.`,
      bodyHtml: `
    <p>Hi ${escapeHtml(user.fullname || "there")},</p>
    <p>We received your registration details. Our next step is verification of your information.</p>
    <p><b>What to expect next:</b></p>
    <ul>
      <li>We may request additional documentation.</li>
      <li>You’ll receive email updates as your status changes.</li>
    </ul>
    <p>If you did not initiate this registration, contact support immediately.</p>
  `,
    });

    logAdminAction(req.admin, "resend_registration_email", { email: userEmail });
    return res.json({ success: true });
  } catch (err) {
    return handleError(res, "Admin resend registration email", err);
  }
});

// Admin: pending transfers list
app.get("/api/admin/transfers/pending", requireAdminToken, async (req, res) => {
  try {
    const q = await pool.query(
      "SELECT id, amount, recipient_name, recipient_email, created_at FROM transfers WHERE status='pending' ORDER BY created_at DESC LIMIT 200"
    );
    return res.json(q.rows);
  } catch (err) {
    return handleError(res, "Admin pending transfers", err);
  }
});

// Admin: confirm pending transfer
app.post("/api/admin/transfers/confirm", requireAdminToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const transferId = String(req.body?.transfer_id || "");
    if (!transferId) return res.status(400).json({ error: "transfer_id required" });

    await client.query("BEGIN");
    const q = await client.query(
      "SELECT id, status FROM transfers WHERE id=$1 FOR UPDATE",
      [transferId]
    );
    if (!q.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Transfer not found" });
    }

    const row = q.rows[0];
    if (String(row.status) !== "pending") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Transfer is not pending" });
    }

    try {
      await client.query(
        "UPDATE transfers SET status='completed', updated_at=NOW() WHERE id=$1",
        [transferId]
      );
    } catch {
      await client.query(
        "UPDATE transfers SET status='completed' WHERE id=$1",
        [transferId]
      );
    }

    await client.query("COMMIT");
    logAdminAction(req.admin, "transfer_confirm", { transfer_id: transferId });
    return res.json({ success: true });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    return handleError(res, "Admin confirm transfer", err);
  } finally {
    client.release();
  }
});
app.get("/api/admin/reconciliation", authMiddleware, async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const q = await pool.query(
      "SELECT * FROM admin_user_balance_recon ORDER BY ABS(balance_delta) DESC"
    );
    return res.json(q.rows);
  } catch (err) {
    // If the view doesn't exist yet, return a helpful error instead of crashing.
    if (err?.code === "42P01") {
      return res.status(501).json({ error: "admin_user_balance_recon view not found" });
    }
    return handleError(res, "Admin reconciliation error", err);
  }
});

app.post("/api/admin/fix-balance", authMiddleware, async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const email = String(req.body?.user_email || "").toLowerCase();
  if (!email) return res.status(400).json({ error: "user_email required" });

  try {
    const q = await pool.query(
      "SELECT admin_fix_user_balance($1) AS new_total",
      [email]
    );
    return res.json({ success: true, new_total: q.rows[0]?.new_total ?? null });
  } catch (err) {
    if (err?.code === "42883") {
      return res.status(501).json({ error: "admin_fix_user_balance(...) not found" });
    }
    return handleError(res, "Admin fix-balance error", err);
  }
});

// Pending transfers list (admin secret)
app.post("/api/admin/pending", async (req, res) => {
  if (!requireAdminSecret(req, res)) return;
  try {
    const q = await pool.query(
      "SELECT id, amount, recipient_name, recipient_email, created_at FROM transfers WHERE status='pending' ORDER BY created_at DESC LIMIT 200"
    );
    return res.json(q.rows);
  } catch (err) {
    return handleError(res, "Admin pending transfers error", err);
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
  console.log(`🚀 Server running at https://polaris-uru5.onrender.com (env=${NODE_ENV})`);
});
