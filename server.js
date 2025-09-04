import express from "express";
import pkg from "pg";
import dotenv from "dotenv";
import cors from "cors";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

dotenv.config();
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Resolve directory for static hosting
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve all static assets (HTML, CSS, JS, images) from project root
app.use(express.static(__dirname));

// Root route -> index.html (works even if a client-side router added later)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const { PGHOST, PGDATABASE, PGUSER, PGPASSWORD, NEON_API_BASE, NEON_PERSONAL_KEY, JWT_SECRET = "dev_secret" } = process.env;

const pool = new Pool({
  host: PGHOST,
  database: PGDATABASE,
  user: PGUSER,
  password: PGPASSWORD,
  ssl: { rejectUnauthorized: false },
});

// Rate limiter
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', authLimiter);

// Helper: auth middleware
function auth(req,res,next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ')? hdr.slice(7): null;
  if(!token) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(token, JWT_SECRET); return next(); } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// Ensure tables exist (simple auto-migrate)
async function ensureTables(){
  await pool.query(`CREATE TABLE IF NOT EXISTS register (
    id SERIAL PRIMARY KEY,
    fullname TEXT,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  );`);
  await pool.query(`CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    user_email TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('credit','debit')),
    amount NUMERIC NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  );`);
  await pool.query(`CREATE TABLE IF NOT EXISTS transfers (
    id SERIAL PRIMARY KEY,
    sender_email TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    status TEXT DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT now()
  );`);
}
ensureTables().catch(e=>console.error('Table init failed', e));

// Get users from DB
app.get("/api/users", async (req,res) => {
  try {
    const r = await pool.query("SELECT id, fullname, email, phone, created_at FROM register ORDER BY id DESC" );
    res.json(r.rows);
  } catch(err){
    console.error(err);res.status(500).json({ error: 'Failed to fetch users'});
  }
});

// Example: add new user (direct SQL insert)
app.post("/api/users", async (req, res) => {
  const { fullname, email, phone, password } = req.body;
  const client = await pool.connect();
  try {
    // Hash password before storing
    const hashed = await bcrypt.hash(password, 10);
    const result = await client.query(
      "INSERT INTO register (fullname, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [fullname, email, phone, hashed]
    );
    const { password: _, ...safe } = result.rows[0];
    const token = jwt.sign({ sub: safe.id, email: safe.email }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ ...safe, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add user" });
  } finally {
    client.release();
  }
});

// Login route with password verification
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const result = await pool.query("SELECT * FROM register WHERE email = $1", [email]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid email or password" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });
    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ id: user.id, fullname: user.fullname, email: user.email, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Transactions
app.get('/api/transactions', auth, async (req,res) => {
  const { user_email } = req.query;
  if(!user_email) return res.json([]);
  try {
    const r = await pool.query('SELECT id,user_email,type,amount,description,created_at FROM transactions WHERE user_email = $1 ORDER BY id DESC', [user_email]);
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Failed to fetch transactions'}); }
});

app.post('/api/transactions', auth, async (req,res) => {
  const { user_email, type, amount, description } = req.body;
  if(!user_email || !type || !amount) return res.status(400).json({ error: 'Missing fields' });
  try {
    const r = await pool.query('INSERT INTO transactions (user_email,type,amount,description) VALUES ($1,$2,$3,$4) RETURNING id,user_email,type,amount,description,created_at',[user_email,type,amount,description||'']);
    res.json(r.rows[0]);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Failed to add transaction'}); }
});

// Transfers
app.get('/api/transfers', auth, async (req,res) => {
  const { user_email } = req.query;
  try {
    let r;
    if(user_email){
      r = await pool.query('SELECT * FROM transfers WHERE sender_email = $1 OR recipient = $1 ORDER BY id DESC', [user_email]);
    } else {
      r = await pool.query('SELECT * FROM transfers ORDER BY id DESC');
    }
    res.json(r.rows);
  } catch(e){ console.error(e); res.status(500).json({ error: 'Failed to fetch transfers'}); }
});

app.post('/api/transfers', auth, async (req,res) => {
  const { sender_email, recipient, amount, status } = req.body;
  if(!sender_email || !recipient || !amount) return res.status(400).json({ error: 'Missing fields' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tr = await client.query('INSERT INTO transfers (sender_email,recipient,amount,status) VALUES ($1,$2,$3,$4) RETURNING *',[sender_email,recipient,amount,status||'completed']);
    await client.query('INSERT INTO transactions (user_email,type,amount,description) VALUES ($1,$2,$3,$4)', [sender_email,'debit',amount,`Transfer to ${recipient}`]);
    await client.query('INSERT INTO transactions (user_email,type,amount,description) VALUES ($1,$2,$3,$4)', [recipient,'credit',amount,`Received from ${sender_email}`]);
    await client.query('COMMIT');
    res.json(tr.rows[0]);
  } catch(e){
    await client.query('ROLLBACK');
    console.error(e); res.status(500).json({ error: 'Transfer failed'});
  } finally { client.release(); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
