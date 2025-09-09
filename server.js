import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { Pool } from 'pg';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// PostgreSQL pool (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : false
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
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
}
ensureSchema().catch(e => console.error('Schema init error', e));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const app = express();

// ✅ CORS for Netlify frontend
app.use(cors({
  origin: "https://shenzhenswift.online", // Netlify frontend
  credentials: true
}));

app.use(express.json());
app.use(morgan('dev'));

function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

// === USERS ===

// Register
app.post('/api/users', async (req, res) => {
  try {
    const { fullname, phone = '', email, password, accountname = '' } = req.body || {};

    if (!fullname || !email || !password) {
      return res.status(400).json({ error: 'Full name, email, and password required' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 chars' });
    }

    const normEmail = email.toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [normEmail]);
    if (existing.rowCount) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const insert = await pool.query(
      `INSERT INTO users (fullname, phone, email, password_hash, accountname, baseavailable, totalbalance)
       VALUES ($1,$2,$3,$4,$5,0,0)
       RETURNING id, fullname, email, accountname, baseavailable, totalbalance`,
      [fullname.trim(), phone.trim(), normEmail, passwordHash, accountname.trim()]
    );

    const user = insert.rows[0];
    const token = issueToken(user);

    return res.status(201).json({ ...user, token });
  } catch (err) {
    console.error('Registration error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const normEmail = email.toLowerCase();
    const q = await pool.query(
      'SELECT id, fullname, email, password_hash, accountname, baseavailable, totalbalance FROM users WHERE email=$1',
      [normEmail]
    );
    if (!q.rowCount) return res.status(401).json({ error: 'Invalid credentials' });

    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = issueToken(user);

    return res.json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      baseavailable: user.baseavailable,
      totalbalance: user.totalbalance,
      token
    });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === TRANSFERS ===
app.post('/api/transfers', async (req, res) => {
  const client = await pool.connect();
  try {
    const { sender_email, recipient, amount } = req.body;
    if (!sender_email || !recipient || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    await client.query('BEGIN');

    // Sender
    const senderQ = await client.query(
      'SELECT id, email, baseavailable, totalbalance FROM users WHERE email=$1',
      [sender_email.toLowerCase()]
    );
    if (!senderQ.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Sender not found' });
    }
    const sender = senderQ.rows[0];

    if (Number(sender.baseavailable) < amt) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Recipient
    const recQ = await client.query(
      'SELECT id, email, baseavailable, totalbalance FROM users WHERE email=$1',
      [recipient.toLowerCase()]
    );
    if (!recQ.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Recipient not found' });
    }
    const rec = recQ.rows[0];

    // Update balances
    await client.query(
      'UPDATE users SET baseavailable=baseavailable-$1, totalbalance=totalbalance-$1 WHERE id=$2',
      [amt, sender.id]
    );
    await client.query(
      'UPDATE users SET baseavailable=baseavailable+$1, totalbalance=totalbalance+$1 WHERE id=$2',
      [amt, rec.id]
    );

    // Log transactions
    await client.query(
      `INSERT INTO transactions (user_email, type, amount, description)
       VALUES ($1,'debit',$2,$3)`,
      [sender.email, amt, `Transfer to ${rec.email}`]
    );
    await client.query(
      `INSERT INTO transactions (user_email, type, amount, description)
       VALUES ($1,'credit',$2,$3)`,
      [rec.email, amt, `Received from ${sender.email}`]
    );

    // Record transfer
    const transferInsert = await client.query(
      `INSERT INTO transfers (sender_email, recipient_email, amount, status)
       VALUES ($1,$2,$3,'completed')
       RETURNING *`,
      [sender.email, rec.email, amt]
    );

    await client.query('COMMIT');
    res.status(201).json(transferInsert.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Transfer error", err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// === TRANSACTIONS ===
app.get('/api/transactions', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);

    const q = await pool.query(
      'SELECT id, type, amount, description, created_at FROM transactions WHERE user_email=$1 ORDER BY created_at DESC LIMIT 20',
      [decoded.email]
    );

    return res.json(q.rows);
  } catch (err) {
    console.error('Transactions error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === SSE Stream for balances ===
app.get('/api/stream/user/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    let token = req.query.token || '';
    if (!token) {
      const auth = req.headers.authorization || '';
      token = auth.replace('Bearer ', '');
    }
    if (!token) return res.status(401).json({ error: 'Unauthorized: no token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);
    if (String(decoded.sub) !== String(userId)) {
      return res.status(403).json({ error: 'Forbidden: mismatched user' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    console.log(`🔌 SSE client connected for user ${userId}`);
    let lastData = null;

    const interval = setInterval(async () => {
      try {
        const q = await pool.query(
          'SELECT id, fullname, email, accountname, baseavailable, totalbalance FROM users WHERE id=$1',
          [userId]
        );
        if (!q.rowCount) return;
        const profile = q.rows[0];
        const data = JSON.stringify(profile);
        if (data !== lastData) {
          res.write(`data: ${data}\n\n`);
          lastData = data;
        }
      } catch (err) {
        console.error("SSE query error", err);
      }
    }, 2000);

    req.on('close', () => {
      clearInterval(interval);
      console.log(`❌ SSE client disconnected for user ${userId}`);
    });

  } catch (err) {
    console.error("SSE auth error", err);
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
});

// Serve static files
app.use(express.static(__dirname));

const PORT = Number(process.env.PORT) || 4000;
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
