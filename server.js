import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

// PostgreSQL pool (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : false,
});

// Ensure schema
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      fullname TEXT NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      accountname TEXT DEFAULT '',
      baseavailable NUMERIC DEFAULT 0,
      totalbalance NUMERIC DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_email TEXT NOT NULL,
      type TEXT NOT NULL CHECK (type IN ('debit','credit')),
      amount NUMERIC NOT NULL CHECK (amount >= 0),
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id SERIAL PRIMARY KEY,
      sender_email TEXT NOT NULL,
      recipient_email TEXT NOT NULL,
      amount NUMERIC NOT NULL CHECK (amount >= 0),
      status TEXT NOT NULL DEFAULT 'completed',
      account_number TEXT,
      routing_number TEXT,
      btc_address TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    -- Ensure method column exists for tracking transfer method
    ALTER TABLE transfers
      ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT 'standard';

    -- Bring users schema in sync with app fields used elsewhere
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS checking NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS savings NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS credit NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS investments NUMERIC DEFAULT 0,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

    -- Notifications for user activities
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_email TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT DEFAULT '',
      type TEXT DEFAULT 'info',
      meta JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now(),
      read_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_notifications_user_email_id ON notifications(user_email, id);
    -- Password reset tokens
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_email TEXT NOT NULL,
      token TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_password_reset_user_email_token ON password_reset_tokens(user_email, token);
  `);
}
ensureSchema().catch((e) => console.error("Schema init error", e));

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const app = express();
// Email transport (optional, configured via env)
let mailer = null;
async function initMailer(){
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.MAIL_FROM || user;
  if (!host || !user || !pass || !from) return;
  try{
    mailer = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
    // verify lazily
    mailer.verify().then(()=>console.log('✉️  Mailer ready')).catch(()=>{});
    mailer.from = from;
  } catch (e){ console.warn('Mailer init failed', e); }
}
initMailer();

async function sendEmail(to, subject, html){
  if (!mailer || !to) return;
  try{
    await mailer.sendMail({ from: mailer.from, to, subject, html });
  } catch (e){ console.warn('sendEmail failed', e); }
}

function makeToken(len = 36){
  return crypto.randomBytes(len).toString('base64url');
}

// Password reset: request a token (email will be sent if account exists)
app.post('/api/password/forgot', async (req, res) => {
  try{
    const { email } = req.body || {};
    if (!email || !validateEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    const norm = String(email).toLowerCase().trim();

    const q = await pool.query('SELECT id, fullname, email FROM users WHERE email=$1', [norm]);
    if (!q.rowCount) {
      // For security, respond OK even if no account — don't reveal existence
      return res.json({ ok: true });
    }
    const user = q.rows[0];

    const token = makeToken(32);
    const expires = new Date(Date.now() + (1000 * 60 * 60)); // 1 hour

    await pool.query(`INSERT INTO password_reset_tokens (user_email, token, expires_at) VALUES ($1,$2,$3)`, [user.email, token, expires]);

    // Build reset link (frontend page: reset-password.html?token=...)
    const origin = process.env.FRONTEND_ORIGIN || (process.env.BASE_URL || `http://localhost:5173`);
    const resetUrl = `${origin.replace(/\/$/, '')}/reset-password.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;

    // Send email (fire-and-forget)
    sendEmail(user.email, 'Password reset request', `
      <p>Hi ${user.fullname || ''},</p>
      <p>We received a request to reset your password. Click the link below to set a new password. This link expires in one hour.</p>
      <p><a href="${resetUrl}">Reset your password</a></p>
      <p>If you didn't request this, you can safely ignore this email.</p>
    `);

    // Insert notification
    await pool.query(`INSERT INTO notifications (user_email, title, body, type, meta) VALUES ($1,$2,$3,$4,$5)`, [
      user.email,
      'Password reset requested',
      'A password reset link was requested for your account. If this was not you, please secure your account.',
      'security',
      JSON.stringify({ action: 'password_forgot' })
    ]);

    return res.json({ ok: true });
  } catch (e){
    console.error('POST /api/password/forgot', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Password reset: set new password with token
app.post('/api/password/reset', async (req, res) => {
  try{
    const { token, email, new_password } = req.body || {};
    if (!token || !email || !new_password) return res.status(400).json({ error: 'token, email and new_password required' });
    if (typeof new_password !== 'string' || new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const norm = String(email).toLowerCase().trim();
    const q = await pool.query(`SELECT id, token, expires_at, used FROM password_reset_tokens WHERE token=$1 AND user_email=$2 ORDER BY id DESC LIMIT 1`, [token, norm]);
    if (!q.rowCount) return res.status(400).json({ error: 'Invalid or expired token' });
    const row = q.rows[0];
    if (row.used) return res.status(400).json({ error: 'Token already used' });
    const expires = new Date(row.expires_at);
    if (expires.getTime() < Date.now()) return res.status(400).json({ error: 'Token expired' });

    const hash = await bcrypt.hash(new_password, 10);
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query(`UPDATE users SET password_hash=$1, updated_at=NOW() WHERE email=$2`, [hash, norm]);
      await client.query(`UPDATE password_reset_tokens SET used=true WHERE token=$1 AND user_email=$2`, [token, norm]);

      // notification + email
      await client.query(`INSERT INTO notifications (user_email, title, body, type, meta) VALUES ($1,$2,$3,$4,$5)`, [
        norm,
        'Password changed',
        'Your account password was successfully changed. If this was not you, contact support immediately.',
        'security',
        JSON.stringify({ action: 'password_reset' })
      ]);

      await client.query('COMMIT');
    } catch (e){
      await client.query('ROLLBACK');
      throw e;
    } finally { client.release(); }

    // send email notification
    sendEmail(norm, 'Your password was changed', `<p>Your account password was changed successfully. If you did not perform this action, please contact support immediately.</p>`);

    return res.json({ ok: true });
  } catch (e){
    console.error('POST /api/password/reset', e);
    return res.status(500).json({ error: 'Server error' });
  }
});


// ✅ CORS for frontend (local + production)
const allowedOrigins = new Set([
  "http://localhost:5173", // http-server dev
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5500", // VS Code Live Server
  "http://localhost:5500",
  "shenzhenswift.online", // your domain
  "https://shenzhenswift.online",
]);

// Allow user-provided extra origins via env (comma-separated)
if (process.env.CORS_ORIGINS) {
  process.env.CORS_ORIGINS.split(",").map(s => s.trim()).filter(Boolean).forEach(o => allowedOrigins.add(o));
}

// Helper: allow any localhost/127.0.0.1 (any port) during dev
function isLocalDevOrigin(orig) {
  try {
    const u = new URL(orig);
    return (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

app.use(
  cors(
    process.env.ALLOW_ANY_ORIGIN === "1"
      ? { origin: true, credentials: true }
      : {
          origin: (origin, callback) => {
            // Allow same-origin requests (no Origin header)
            if (!origin) return callback(null, true);

            // Explicit allowlist
            if (allowedOrigins.has(origin)) return callback(null, true);

            // Allow any localhost or 127.0.0.1 regardless of port for local development
            if (isLocalDevOrigin(origin)) return callback(null, true);

            // Optional: allow file:// pages which send Origin "null" when explicitly enabled
            if (origin === "null" && process.env.ALLOW_FILE_ORIGIN === "1") return callback(null, true);

            return callback(new Error(`Not allowed by CORS: ${origin}`));
          },
          credentials: true,
        }
  )
);

// Handle preflight for all routes
app.options("*", cors());

app.use(express.json());
app.use(morgan("dev"));

// Helpers
function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "2h",
  });
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = auth.startsWith("Bearer ") ? auth.replace("Bearer ", "") : "";
  // Fallback: allow token via query for SSE/EventSource where headers aren't supported
  if (!token && req.query && req.query.token) token = String(req.query.token);
  if (!token) return res.status(401).json({ error: "Unauthorized: missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
  }
}

// === USERS ===
// Health check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// Avoid favicon 404 when hitting API root in a browser
app.get("/favicon.ico", (req, res) => res.status(204).end());

app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const q = await pool.query(
      "SELECT id, fullname, email, accountname, checking, savings, totalbalance FROM users WHERE id=$1",
      [req.user.sub]
    );
    if (!q.rowCount) return res.status(404).json({ error: "User not found" });

    const row = q.rows[0];
    return res.json({
      id: row.id,
      fullname: row.fullname,
      email: row.email,
      checking: Number(row.checking || 0),
      savings: Number(row.savings || 0),
      totalbalance: Number(row.totalbalance || 0), // ← direct from DB
      credit: 0,
      investments: 0,
    });
  } catch (err) {
    console.error("Profile fetch error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Minimal user lookup by email (for receipts)
app.get("/api/users/lookup", authMiddleware, async (req, res) => {
  try {
    const email = String(req.query.email || "").toLowerCase().trim();
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: "Valid email query param required" });
    }
    const q = await pool.query(
      "SELECT fullname, email, accountname FROM users WHERE email=$1",
      [email]
    );
    if (!q.rowCount) return res.status(404).json({ error: "User not found" });
    return res.json(q.rows[0]);
  } catch (err) {
    console.error("Lookup error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Register
app.post("/api/users", async (req, res) => {
  try {
    const { fullname, phone = "", email, password, accountname = "" } = req.body || {};
    if (!fullname || !email || !password) {
      return res.status(400).json({ error: "Full name, email, and password required" });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Valid email required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 chars" });
    }

    const normEmail = email.toLowerCase();
    const existing = await pool.query("SELECT id FROM users WHERE email=$1", [normEmail]);
    if (existing.rowCount) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const insert = await pool.query(
  `INSERT INTO users (fullname, phone, email, password_hash, accountname, checking, savings)
   VALUES ($1,$2,$3,$4,$5,0,0)
   RETURNING id, fullname, email, accountname, checking, savings, totalbalance`,
  [fullname.trim(), phone.trim(), normEmail, passwordHash, accountname.trim()]
);

const user = insert.rows[0];
const token = issueToken(user);

return res.status(201).json({ ...user, token });
  } catch (err) {
    console.error("Registration error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const normEmail = email.toLowerCase();
    const q = await pool.query(
  "SELECT id, fullname, email, password_hash, accountname, checking, savings, totalbalance FROM users WHERE email=$1",
  [normEmail]
);
const user = q.rows[0];
if (!user) return res.status(401).json({ error: "Invalid email or password" });

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = issueToken(user);
    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      checking: Number(user.checking || 0),
      savings: Number(user.savings || 0),
      totalbalance: Number(user.totalbalance || 0), // ← direct from DB
      token,
    });
  } catch (err) {
    console.error("Login error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Update current user's profile (fullname, phone)
app.put("/api/users/me", authMiddleware, express.json(), async (req, res) => {
  try {
    const { fullname, phone } = req.body || {};
    if (fullname !== undefined && typeof fullname !== "string") {
      return res.status(400).json({ error: "Invalid fullname" });
    }
    if (phone !== undefined && typeof phone !== "string") {
      return res.status(400).json({ error: "Invalid phone" });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET fullname = COALESCE($1, fullname),
          phone    = COALESCE($2, phone),
          updated_at = NOW()
      WHERE id = $3
      RETURNING id, email, fullname, phone, checking, savings, credit, investments
      `,
      [fullname?.trim() ?? null, phone?.trim() ?? null, req.user.sub]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: "User not found" });
    res.json(result.rows[0]);
  } catch (e) {
    console.error("PUT /api/users/me", e);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// Change password for current user
app.post("/api/users/password", authMiddleware, express.json(), async (req, res) => {
  try {
    const { new_password } = req.body || {};
    if (typeof new_password !== "string" || new_password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query(
      `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
      [hash, req.user.sub]
    );
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error("POST /api/users/password", e);
    res.status(500).json({ error: "Failed to change password" });
  }
});

// === TRANSFERS ===
app.post("/api/transfers", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    let { sender_email, recipient_email, recipient_name, amount, 
          sender_account_type = "checking", 
          recipient_account_type = "checking",
          account_number, routing_number, btc_address, method } = req.body || {};

    sender_email = (sender_email || req.user?.email || "").toLowerCase().trim();
    recipient_email = (recipient_email || "").toLowerCase().trim();
    const recipient_name_norm = (recipient_name || "").toString().trim().toLowerCase();

    // Find recipient by name if email not provided
    if (!recipient_email && recipient_name_norm) {
      const byAccount = await client.query(
        "SELECT email FROM users WHERE lower(accountname)=$1 OR lower(fullname)=$1",
        [recipient_name_norm]
      );
      if (byAccount.rowCount) {
        recipient_email = byAccount.rows[0].email.toLowerCase();
      }
    }

    if (!sender_email || !recipient_email || amount == null) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (sender_email === recipient_email) {
      return res.status(400).json({ error: "Cannot transfer to the same account" });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    // Validate account types
    const validAccounts = new Set(["checking", "savings"]);
    if (!validAccounts.has(sender_account_type) || !validAccounts.has(recipient_account_type)) {
      return res.status(400).json({ error: "Invalid account type" });
    }

    await client.query("BEGIN");

    // Sender
    const senderQ = await client.query("SELECT * FROM users WHERE email=$1", [sender_email]);
    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sender not found" });
    }
    const sender = senderQ.rows[0];

    if (Number(sender[sender_account_type]) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient funds in " + sender_account_type });
    }

    // Recipient
    const recQ = await client.query("SELECT * FROM users WHERE email=$1", [recipient_email]);
    if (!recQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Recipient not found" });
    }
    const rec = recQ.rows[0];

    // Update balances
    await client.query(
      `UPDATE users SET ${sender_account_type}=${sender_account_type}-$1 WHERE id=$2`,
      [amt, sender.id]
    );
    await client.query(
      `UPDATE users SET ${recipient_account_type}=${recipient_account_type}+$1 WHERE id=$2`,
      [amt, rec.id]
    );

    // Log transactions
    await client.query(
      `INSERT INTO transactions (user_email, type, amount, description)
       VALUES ($1,'debit',$2,$3)`,
      [sender.email, amt, `Transfer from ${sender_account_type} to ${rec.accountname || rec.email}`]
    );
    await client.query(
      `INSERT INTO transactions (user_email, type, amount, description)
       VALUES ($1,'credit',$2,$3)`,
      [rec.email, amt, `Received in ${recipient_account_type} from ${sender.accountname || sender.email}`]
    );

    // Record transfer
    const transferInsert = await client.query(
      `INSERT INTO transfers (sender_email, recipient_email, amount, status, account_number, routing_number, btc_address, method)
       VALUES ($1,$2,$3,'completed',$4,$5,$6,$7)
       RETURNING *`,
      [sender.email, rec.email, amt, account_number || null, routing_number || null, btc_address || null, method || "standard"]
    );

    // Create notifications for sender and recipient
    const t = transferInsert.rows[0];
    const prettySenderTarget = rec.accountname || rec.fullname || rec.email;
    const prettyRecipientSource = sender.accountname || sender.fullname || sender.email;
    const fmtAmount = amt.toFixed(2);

    await client.query(
      `INSERT INTO notifications (user_email, title, body, type, meta)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        sender.email,
        'Transfer sent',
        `You sent $${fmtAmount} to ${prettySenderTarget}`,
        'transfer',
        JSON.stringify({ transfer_id: t.id, direction: 'debit', amount: amt, counterparty: rec.email, method })
      ]
    );

    await client.query(
      `INSERT INTO notifications (user_email, title, body, type, meta)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        rec.email,
        'Transfer received',
        `You received $${fmtAmount} from ${prettyRecipientSource}`,
        'transfer',
        JSON.stringify({ transfer_id: t.id, direction: 'credit', amount: amt, counterparty: sender.email, method })
      ]
    );

    await client.query("COMMIT");
  const createdTx = transferInsert.rows[0];
  res.status(201).json(createdTx);

  // Fire-and-forget email notifications (after response)
  const fmt = (n)=> Number(n).toLocaleString(undefined,{ style:'currency', currency:'USD' });
  const amountFmt = fmt(amt);
  // to sender
  sendEmail(sender.email, 'Transfer sent', `<p>You sent ${amountFmt} to ${prettySenderTarget} via ${method?.toUpperCase() || 'TRANSFER'}.</p><p>Reference: ${createdTx.id}</p>`);
  // to recipient
  sendEmail(rec.email, 'Transfer received', `<p>You received ${amountFmt} from ${prettyRecipientSource} via ${method?.toUpperCase() || 'TRANSFER'}.</p><p>Reference: ${createdTx.id}</p>`);
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch {}
    console.error("Transfer error:", err, req.body);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

// === TRANSACTIONS ===
app.get("/api/transactions", authMiddleware, async (req, res) => {
  try {
    // Fetch the user's transactions, most recent first
    const q = await pool.query(
      `SELECT id, type, amount, description, created_at 
       FROM transactions 
       WHERE user_email=$1 
       ORDER BY created_at DESC 
       LIMIT 20`,
      [req.user.email]
    );

    if (!q.rowCount) return res.json([]);

    // Get current balances
    const userQ = await pool.query(
      "SELECT checking, savings, totalbalance FROM users WHERE email=$1",
      [req.user.email]
    );
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });

    let checkingBal = Number(userQ.rows[0].checking || 0);
    let savingsBal = Number(userQ.rows[0].savings || 0);
    let totalBal = Number(userQ.rows[0].totalbalance || 0);

    // Walk through transactions (DESC order) and adjust balances in reverse
    const transactionsWithBalance = await Promise.all(
      q.rows.map(async (tx) => {
        let amt = Number(tx.amount);

        // Look up a prettier description (replace email with account name if possible)
        let prettyDescription = tx.description;
        const emailMatch = tx.description.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)/);
        if (emailMatch) {
          const targetEmail = emailMatch[1].toLowerCase();
          try {
            const recQ = await pool.query(
              "SELECT accountname, fullname FROM users WHERE email=$1",
              [targetEmail]
            );
            if (recQ.rowCount) {
              const rec = recQ.rows[0];
              const displayName = rec.accountname || rec.fullname || targetEmail;
              prettyDescription = tx.description.replace(targetEmail, displayName);
            }
          } catch (e) {
            console.warn("Description lookup failed", e);
          }
        }

        // Adjust running balances (reverse since sorted DESC)
        if (tx.type === "credit") {
          checkingBal -= amt;
          totalBal -= amt;
        } else {
          checkingBal += amt;
          totalBal += amt;
        }

        return {
          ...tx,
          description: prettyDescription,
          checking_balance_after: checkingBal.toFixed(2),
          savings_balance_after: savingsBal.toFixed(2),
          total_balance_after: totalBal.toFixed(2),
        };
      })
    );

    return res.json(transactionsWithBalance);
  } catch (err) {
    console.error("Transactions error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// === NOTIFICATIONS ===
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const since = Number(req.query.since || 0);
    const args = [req.user.email];
    let sql = `SELECT id, title, body, type, meta, created_at, read_at FROM notifications WHERE user_email=$1`;
    if (since > 0) { sql += ` AND id > $2`; args.push(since); }
    sql += ` ORDER BY id DESC LIMIT 50`;
    const q = await pool.query(sql, args);
    res.json(q.rows);
  } catch (e) {
    console.error('GET /api/notifications', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications/read', authMiddleware, async (req, res) => {
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ error: 'id required' });
    await pool.query(`UPDATE notifications SET read_at = NOW() WHERE id=$1 AND user_email=$2`, [id, req.user.email]);
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/notifications/read', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await pool.query(`UPDATE notifications SET read_at = NOW() WHERE user_email=$1 AND read_at IS NULL`, [req.user.email]);
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/notifications/read-all', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Notifications SSE
app.get('/api/stream/notifications', authMiddleware, async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const lastEventHeader = req.headers['last-event-id'];
  let lastId = 0;
  if (lastEventHeader) {
    const n = Number(lastEventHeader);
    if (Number.isFinite(n) && n > 0) lastId = n;
  }
  if (req.query && req.query.lastId) {
    const n = Number(req.query.lastId);
    if (Number.isFinite(n) && n > 0) lastId = n;
  }

  let alive = true;
  req.on('close', () => { alive = false; clearInterval(pulse); clearInterval(poll); });

  // Heartbeat
  const pulse = setInterval(() => {
    try { res.write(`event: ping\ndata: {"t":${Date.now()}}\n\n`); } catch {}
  }, 15000);

  const poll = setInterval(async () => {
    if (!alive) return;
    try {
      const q = await pool.query(
        `SELECT id, title, body, type, meta, created_at FROM notifications WHERE user_email=$1 AND id > $2 ORDER BY id ASC LIMIT 50`,
        [req.user.email, lastId]
      );
      if (q.rowCount) {
        for (const row of q.rows) {
          lastId = row.id;
          res.write(`id: ${row.id}\n`);
          res.write(`data: ${JSON.stringify(row)}\n\n`);
        }
      }
    } catch (e) {
      console.error('SSE notifications error', e);
    }
  }, 2000);
});

// === SSE Stream for balances ===
app.get("/api/stream/user/:id", authMiddleware, async (req, res) => {
  const userId = req.params.id;

  if (String(req.user.sub) !== String(userId)) {
    return res.status(403).json({ error: "Forbidden: mismatched user" });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  console.log(`🔌 SSE client connected for user ${userId}`);
  let lastData = null;

  const interval = setInterval(async () => {
    try {
      const q = await pool.query(
  "SELECT id, fullname, email, accountname, checking, savings, totalbalance FROM users WHERE id=$1",
  [userId]
);
if (!q.rowCount) return;
const row = q.rows[0];
const profile = {
  id: row.id,
  fullname: row.fullname,
  email: row.email,
  checking: Number(row.checking || 0),
  savings: Number(row.savings || 0),
  totalbalance: Number(row.totalbalance || 0), // ← direct from DB
  credit: 0,
  investments: 0,
};
res.write(`data: ${JSON.stringify(profile)}\n\n`);
      } catch (err) {
      console.error("SSE query error", err);
    }
  }, 2000);

  req.on("close", () => {
    clearInterval(interval);
    console.log(`❌ SSE client disconnected for user ${userId}`);
  });
});

// ✅ Only API, no static fallback
const PORT = Number(process.env.PORT) || 4000;
app.listen(PORT, () => {
  console.log(`🚀 API server running on http://localhost:${PORT}`);
});
