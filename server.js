import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";

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
  `);
}
ensureSchema().catch((e) => console.error("Schema init error", e));

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const app = express();

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
      [hash, req.user.id]
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

    await client.query("COMMIT");
    res.status(201).json(transferInsert.rows[0]);
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
