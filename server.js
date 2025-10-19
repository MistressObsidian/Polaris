/**
 * server.js
 * Updated to work with the new DB schema (users + accounts + transactions + transfers)
 *
 * Notes:
 * - Assumes `users` uses UUID primary key and `accounts` table exists.
 * - Registration now creates a user + a checking account.
 * - Login aggregates account balances (sums across accounts).
 * - /api/transactions returns recent transactions across the user's accounts.
 * - /api/transfers performs transfer logic using SELECT ... FOR UPDATE to avoid races.
 * - Adds a startup DB connectivity check (fail-fast).
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
import fs from "fs";
import path from "path";

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL || "";
const PGSSLMODE = process.env.PGSSLMODE || "";
const NODE_ENV = process.env.NODE_ENV || "development";

const useSsl = PGSSLMODE === "require" || process.env.NODE_ENV === "production";
const pool = new Pool({
  connectionString: DATABASE_URL || undefined,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});

// fail-fast DB check
(async function verifyDB() {
  try {
    await pool.query("SELECT 1");
    console.log("✅ Postgres connected");
  } catch (e) {
    console.error("❌ Postgres connection failed at startup:", e);
    process.exit(1);
  }
})();

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const app = express();
let mailer = null;
async function initMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.MAIL_FROM || user;
  if (!host || !user || !pass || !from) return;
  try {
    mailer = nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
    mailer.verify().then(() => console.log("✉️  Mailer ready")).catch(() => {});
    mailer.from = from;
  } catch (e) {
    console.warn("Mailer init failed", e);
  }
}
initMailer();

function makeToken(len = 24) {
  return crypto.randomBytes(len).toString("base64url");
}
function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "2h" });
}
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || ""));
}

app.use(
  cors(
    process.env.ALLOW_ANY_ORIGIN === "1"
      ? { origin: true, credentials: true }
      : {
          origin: (origin, callback) => {
            if (!origin) return callback(null, true);
            try {
              const u = new URL(origin);
              if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return callback(null, true);
            } catch {}
            const allowed = (process.env.CORS_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
            if (allowed.includes(origin)) return callback(null, true);
            return callback(new Error(`Not allowed by CORS: ${origin}`));
          },
          credentials: true,
        }
  )
);

app.options("*", cors());
app.use(express.json());
app.use(morgan("dev"));

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  let token = auth.startsWith("Bearer ") ? auth.replace("Bearer ", "") : "";
  if (!token && req.query && req.query.token) token = String(req.query.token);
  if (!token) return res.status(401).json({ error: "Unauthorized: missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: invalid or expired token" });
  }
}

function handleError(res, label, err) {
  console.error(label, err);
  if (NODE_ENV === "production") {
    return res.status(500).json({ error: "Server error" });
  }
  return res.status(500).json({ error: err.message || "Server error", stack: err.stack });
}

// --- USERS ---
app.post("/api/users", async (req, res) => {
  try {
    const { fullname, phone = "", email, password, accountname = "" } = req.body || {};
    if (!fullname || !email || !password) return res.status(400).json({ error: "Full name, email, and password required" });
    if (!validateEmail(email)) return res.status(400).json({ error: "Valid email required" });
    if (typeof password !== "string" || password.length < 6) return res.status(400).json({ error: "Password must be at least 6 chars" });

    const normEmail = String(email).toLowerCase();
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normEmail]);
    if (existing.rowCount) return res.status(409).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const insertUser = await client.query(
        `INSERT INTO users (fullname, email, password_hash, phone, accountname)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id, fullname, email, accountname`,
        [fullname.trim(), normEmail, passwordHash, phone.trim(), accountname.trim()]
      );
      const user = insertUser.rows[0];
      const acc = await client.query(
        `INSERT INTO accounts (user_id, type, currency, balance, available)
         VALUES ($1, 'checking', 'USD', 0, 0)
         RETURNING id, balance, available, type`,
        [user.id]
      );
      await client.query("COMMIT");

      const token = issueToken({ id: user.id, email: user.email });
      return res.status(201).json({
        id: user.id,
        fullname: user.fullname,
        email: user.email,
        accountname: user.accountname,
        balances: { total: 0, accounts: acc.rows },
        token,
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      if (err && err.code === "23505") return res.status(409).json({ error: "Email already registered" });
      return handleError(res, "Registration error", err);
    } finally {
      client.release();
    }
  } catch (err) {
    return handleError(res, "Registration error (outer)", err);
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const normEmail = String(email).toLowerCase();
    const q = await pool.query("SELECT id, fullname, email, password_hash, accountname FROM users WHERE email=$1", [normEmail]);
    const user = q.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid email or password" });

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) return res.status(401).json({ error: "Invalid email or password" });

    const accQ = await pool.query("SELECT id, type, balance, available, currency FROM accounts WHERE user_id=$1", [user.id]);
    const accounts = accQ.rows || [];
    const total = accounts.reduce((s, a) => s + Number(a.balance || 0), 0);

    const token = issueToken({ id: user.id, email: user.email });

    try {
      await pool.query("UPDATE users SET last_login_at = NOW(), last_login_ip = $1, last_login_ua = $2 WHERE id = $3", [
        req.ip || req.headers["x-forwarded-for"] || null,
        req.get("user-agent") || null,
        user.id,
      ]);
    } catch (e) {
      console.warn("Failed to update last_login", e);
    }

    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      balances: { total: Number(total.toFixed(2)), accounts },
      token,
    });
  } catch (err) {
    return handleError(res, "Login error", err);
  }
});

app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.sub;
    const userQ = await pool.query("SELECT id, fullname, email, accountname FROM users WHERE id=$1", [userId]);
    if (!userQ.rowCount) return res.status(404).json({ error: "User not found" });
    const user = userQ.rows[0];

    const accQ = await pool.query("SELECT id, type, balance, available, currency FROM accounts WHERE user_id=$1", [user.id]);
    const accounts = accQ.rows || [];
    const total = accounts.reduce((s, a) => s + Number(a.balance || 0), 0);

    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      balances: { total: Number(total.toFixed(2)), accounts },
    });
  } catch (err) {
    return handleError(res, "Profile fetch error", err);
  }
});

app.get("/api/transactions", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.sub;
    const accQ = await pool.query("SELECT id FROM accounts WHERE user_id=$1", [userId]);
    const accIds = accQ.rows.map((r) => r.id);
    if (!accIds.length) return res.json([]);

    const q = await pool.query(
      `SELECT t.id, t.account_id, t.type, t.amount, t.description, t.reference, t.created_at,
              a.type AS account_type, a.currency
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

app.post("/api/transfers", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.user.sub;
    let {
      sender_account_id,
      recipient_account_id,
      recipient_email,
      recipient_name,
      amount,
      method = "standard",
      description = null,
      bank_name = null,
      account_number = null,
      routing_number = null,
      btc_address = null,
    } = req.body || {};

    if (!sender_account_id || amount == null) return res.status(400).json({ error: "Missing required fields: sender_account_id and amount" });
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount" });

    await client.query("BEGIN");

    const senderQ = await client.query("SELECT id, user_id, balance, available, type FROM accounts WHERE id=$1 FOR UPDATE", [sender_account_id]);
    if (!senderQ.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sender account not found" });
    }
    const senderAcc = senderQ.rows[0];
    if (String(senderAcc.user_id) !== String(userId)) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "Forbidden: sender account does not belong to authenticated user" });
    }
    if (Number(senderAcc.available) < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `Insufficient funds in ${senderAcc.type}` });
    }

    let isInternal = false;
    let recipientAcc = null;
    if (recipient_account_id) {
      const recQ = await client.query("SELECT id, user_id, balance, available, type FROM accounts WHERE id=$1 FOR UPDATE", [recipient_account_id]);
      if (recQ.rowCount) {
        recipientAcc = recQ.rows[0];
        isInternal = true;
      } else {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Recipient account not found" });
      }
    } else if (recipient_email) {
      const uQ = await client.query("SELECT id FROM users WHERE email=$1 LIMIT 1", [String(recipient_email).toLowerCase()]);
      if (uQ.rowCount) {
        const urow = uQ.rows[0];
        const userAccQ = await client.query("SELECT id, user_id, balance, available, type FROM accounts WHERE user_id=$1 AND type='checking' LIMIT 1 FOR UPDATE", [urow.id]);
        if (userAccQ.rowCount) {
          recipientAcc = userAccQ.rows[0];
          isInternal = true;
        }
      }
    }

    let transferStatus = isInternal ? "completed" : "pending";
    let claimToken = null;
    let claimExpires = null;
    if (!isInternal && transferStatus === "pending") {
      claimToken = makeToken(18);
      const days = Number(process.env.CLAIM_TOKEN_DAYS || 7);
      claimExpires = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    }

    await client.query("UPDATE accounts SET balance = balance - $1, available = available - $1 WHERE id=$2", [amt, senderAcc.id]);

    if (isInternal && recipientAcc) {
      await client.query("UPDATE accounts SET balance = balance + $1, available = available + $1 WHERE id=$2", [amt, recipientAcc.id]);
    }

    const senderDesc = description || (isInternal ? `Transfer to ${recipientAcc.type || 'account'}` : `External transfer to ${recipient_name || recipient_email || 'recipient'}`);
    await client.query(
      `INSERT INTO transactions (account_id, type, amount, description, reference, created_at)
       VALUES ($1, 'debit', $2, $3, $4, NOW())`,
      [senderAcc.id, amt, senderDesc, null]
    );

    if (isInternal && recipientAcc) {
      const recDesc = description || `Received from ${senderAcc.type || 'account'}`;
      await client.query(
        `INSERT INTO transactions (account_id, type, amount, description, reference, created_at)
         VALUES ($1, 'credit', $2, $3, $4, NOW())`,
        [recipientAcc.id, amt, recDesc, null]
      );
    }

    const tRes = await client.query(
      `INSERT INTO transfers
        (sender_account_id, recipient_account_id, recipient_email, recipient_name, amount, currency, method, status, bank_name, account_number, routing_number, btc_address, description, claim_token, claim_expires, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
       RETURNING id, status, created_at`,
      [
        senderAcc.id,
        isInternal && recipientAcc ? recipientAcc.id : null,
        recipient_email ? String(recipient_email).toLowerCase() : null,
        recipient_name || null,
        amt,
        "USD",
        method || "standard",
        transferStatus,
        bank_name || null,
        account_number || null,
        routing_number || null,
        btc_address || null,
        description || null,
        claimToken,
        claimExpires,
      ]
    );

    await client.query("COMMIT");
    const createdTx = tRes.rows[0];
    res.status(201).json(createdTx);

    (async () => {
      try {
        await pool.query(
          `INSERT INTO notifications (user_id, title, body, type, meta, created_at)
           VALUES ($1,$2,$3,$4,$5,NOW())`,
          [userId, "Transfer sent", `You sent $${amt.toFixed(2)} ${isInternal ? "to an internal account" : "to an external recipient"}`, "transfer", JSON.stringify({ transfer_id: createdTx.id })]
        );
      } catch (e) {
        console.warn("post-transfer notification failed", e);
      }
    })();
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {}
    return handleError(res, "Transfer error", err);
  } finally {
    client.release();
  }
});

const staticDir = path.join(process.cwd());
app.use(express.static(staticDir, { extensions: ["html"] }));
app.get("/", (req, res) => res.sendFile(path.join(staticDir, "index.html")));
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(staticDir, "index.html")));

const PORT = Number(process.env.PORT) || 4000;
app.listen(PORT, () => {
  console.log(`🚀 API server running on http://localhost:${PORT} (env=${NODE_ENV})`);
});