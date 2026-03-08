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
import nodemailer from "nodemailer";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { initMailer as initMailerUtils, sendEmail, renderEmail } from "./utils/mailer.js";
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

// ---- Branded Email Helper (logo on every email) ----
const APP_BASE_URL = (process.env.APP_BASE_URL || BASE_URL).replace(/\/+$/, "");
const BRAND = {
  name: process.env.BRAND_NAME || "Base Credit",
  supportEmail: process.env.SUPPORT_EMAIL || process.env.MAIL_FROM || "",
  logoPath: process.env.BRAND_LOGO_PATH || path.join(process.cwd(), "assets", "logo.png"),
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

function loadAppSettings() {
  try {
    if (fs.existsSync(APP_SETTINGS_PATH)) {
      const raw = fs.readFileSync(APP_SETTINGS_PATH, "utf8");
      const parsed = JSON.parse(raw || "{}");
      return { feeRate: 0.235, ...parsed };
    }
  } catch (e) {
    console.warn("App settings load failed:", e.message);
  }
  return { feeRate: 0.235 };
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

// Public settings
app.get("/api/settings", async (req, res) => {
  try {
    const settings = loadAppSettings();
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
          if (mailer && BANKSWIFT_NOTIFY_EMAIL) {
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
      return sendError(403, "Account suspended");
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
      if (mailer && updatedUser.email) {
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
      if (mailer && accountUser.email) {
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
    if (!mailer) {
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
      if (mailer && email) {
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
      if (mailer) {
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
      if (mailer) {
        // sender
        const templates = loadEmailTemplates();
        const transferSenderTpl = templates.transferSender || {};
        const { feeRate } = loadAppSettings();
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
      if (mailer) {
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

    const loanAmount = Number(loanCheckQ.rows[0].amount || 0);
    const { feeRate } = loadAppSettings();
    const feeAmount = Number((loanAmount * Number(feeRate || 0)).toFixed(2));

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
      if (mailer) {
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
    await initMailer();
    await initMailerUtils();
  })().catch((err) => {
    console.warn("Mailer startup init failed:", err?.message || err);
  });
});
