import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { Pool } from 'pg';
// Node 18+ has global fetch; if older: import fetch from 'node-fetch';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// PostgreSQL pool (Neon)
const pool = new Pool({
	connectionString: process.env.DATABASE_URL,
	ssl: process.env.PGSSLMODE ? { rejectUnauthorized: false } : false
});

async function ensureSchema(){
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
  `);
}
ensureSchema().catch(e=> console.error('Schema init error', e));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));



function issueToken(user){
	return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
}

// Validation helper
function validateEmail(email){ return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email); }

// POST /api/users  (registration)
app.post('/api/users', async (req,res) => {
  try {
    const { fullname, phone = '', email, password, accountname = '' } = req.body || {};

    if(!fullname || typeof fullname !== 'string' || !fullname.trim()){
      return res.status(400).json({ error:'Full name required' });
    }
    if(!email || !validateEmail(email)){
      return res.status(400).json({ error:'Valid email required' });
    }
    if(!password || password.length < 6){
      return res.status(400).json({ error:'Password must be at least 6 chars' });
    }

    const normEmail = email.toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [normEmail]);
    if(existing.rowCount){
      return res.status(409).json({ error:'Email already registered' });
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

    return res.status(201).json({
      id: user.id,
      fullname: user.fullname,
      email: user.email,
      accountname: user.accountname,
      baseavailable: user.baseavailable,
      totalbalance: user.totalbalance,
      token
    });
  } catch(err){
    console.error('Registration error', err);
    return res.status(500).json({ error:'Server error' });
  }
});

// POST /api/login
app.post('/api/login', async (req,res) => {
  try {
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({ error:'Email and password required' });

    const normEmail = email.toLowerCase();
    const q = await pool.query(
      'SELECT id, fullname, email, password_hash, accountname, baseavailable, totalbalance FROM users WHERE email=$1',
      [normEmail]
    );
    if(!q.rowCount) return res.status(401).json({ error:'Invalid credentials' });

    const user = q.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ error:'Invalid credentials' });

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
  } catch(err){
    console.error('Login error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/me
app.get('/api/users/me', async (req,res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);

    const q = await pool.query(
      'SELECT id, fullname, email, accountname, baseavailable, totalbalance FROM users WHERE id=$1',
      [decoded.sub]
    );

    if(!q.rowCount) return res.status(404).json({ error:'Not found' });
    return res.json(q.rows[0]);
  } catch(err){
    console.error('Get me error', err);
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// (B) Sync Neon rows to Google Sheet (manual trigger)
app.post('/api/sync/users-to-sheet', async (req,res) => {
  try {
    const { auth } = req.headers;
    if(!auth || auth !== (process.env.INTERNAL_SYNC_TOKEN||'')){
      return res.status(401).json({ error:'Unauthorized' });
    }
    const rows = await pool.query('SELECT id, fullname, email, password_hash, accountname, baseavailable, totalbalance FROM users ORDER BY id');
    await Promise.all(rows.rows.map(r=> logToSheet({ type:'user_sync', ...r })));
    return res.json({ ok:true, count: rows.rowCount });
  } catch(err){
    console.error('sync users->sheet error', err);
    return res.status(500).json({ error:'Server error' });
  }
});

// (C) Pull Google Sheet rows into app
app.get('/api/sheet/users', async (req,res) => {
  try {
    const url = process.env.GS_USERS_ENDPOINT;
    if(!url) return res.status(500).json({ error:'Sheet endpoint not configured' });
    const fetchRes = await fetch(url);
    let data = [];
    try { data = await fetchRes.json(); } catch { data = []; }
    return res.json({ ok:true, rows: data });
  } catch(err){
    console.error('sheet pull error', err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Health check
app.get('/api/health', async (req,res)=> {
	try {
		const r = await pool.query('SELECT count(*)::int AS c FROM users');
		res.json({ ok:true, users: r.rows[0].c });
	} catch { res.json({ ok:true, users: 'n/a' }); }
});

// Simple sheet logging util (server side) using Apps Script (expects no auth) or SheetDB
async function logToSheet(entry){
	const appsScriptUrl = process.env.GS_LOG_ENDPOINT; // Provide in .env
	if(!appsScriptUrl) return; // silently skip if not set
	try {
		await fetch(appsScriptUrl, {
			method:'POST',
			headers:{ 'Content-Type':'application/json', 'X-APP-TOKEN': process.env.GS_SHARED_SECRET||'' },
			body: JSON.stringify(entry)
		});
	} catch(_){ /* swallow */ }
}

// Serve static files (frontend)
app.use(express.static(__dirname));

// SSE: Stream user balance updates (JWT protected)
app.get('/api/stream/user/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    // Accept token from query string or Authorization header
    let token = req.query.token || '';
    if (!token) {
      const auth = req.headers.authorization || '';
      token = auth.replace('Bearer ', '');
    }

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: no token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    // Ensure the user can only connect to their own stream
    if (String(decoded.sub) !== String(userId)) {
      return res.status(403).json({ error: 'Forbidden: mismatched user' });
    }

    // SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    console.log(`🔌 SSE client connected for user ${userId}`);

    let lastData = null;

    // Poll Neon every 2 seconds for balance changes
    const interval = setInterval(async () => {
      try {
        const q = await pool.query(
          'SELECT id, fullname, email, accountname, baseavailable, totalbalance FROM users WHERE id=$1',
          [userId]
        );
        if (!q.rowCount) return;

        const profile = q.rows[0];
        const data = JSON.stringify(profile);

        // Send only if changed
        if (data !== lastData) {
          res.write(`data: ${data}\n\n`);
          lastData = data;
        }
      } catch (err) {
        console.error("SSE query error", err);
      }
    }, 2000);

    // Cleanup when client disconnects
    req.on('close', () => {
      clearInterval(interval);
      console.log(`❌ SSE client disconnected for user ${userId}`);
    });

  } catch (err) {
    console.error("SSE auth error", err);
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
});

const PORT = Number(process.env.PORT) || 4000;
const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
server.on('error', err => {
  if(err.code === 'EADDRINUSE'){
    const alt = PORT + 1;
    console.warn(`Port ${PORT} in use. Retrying on ${alt}...`);
    setTimeout(()=> {
      app.listen(alt, () => console.log(`Server running on http://localhost:${alt}`));
    }, 300);
  } else {
    console.error('Server start error', err);
  }
});
