// Bank-to-bank API with SQLite, Bearer auth, idempotency, signed webhooks, and SSE
// Endpoints:
//  - GET    /api/health
//  - GET    /api/transfers            (optional ?email=... or ?ref=...)
//  - POST   /api/transfers            (create transfer) [auth + idempotency]
//  - PATCH  /api/transfers/:ref       (update transfer) [auth]
//  - POST   /api/webhooks/transfer-updated  (inbound webhook, HMAC verified)
//  - GET    /api/stream               (SSE stream of transfer events) [auth]

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'banking.db');
const API_TOKEN = process.env.API_TOKEN || 'dev-token';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'dev-secret';
const WEBHOOK_TARGET = process.env.WEBHOOK_TARGET || '';

app.use(cors());
app.use(express.json());

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS transfers (
    reference TEXT PRIMARY KEY,
    email TEXT,
    amount REAL,
    type TEXT,
    from_account TEXT,
    to_account TEXT,
    status TEXT,
    dateISO TEXT,
    source TEXT,
    createdAt TEXT,
    updatedAt TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT PRIMARY KEY,
    request_hash TEXT,
    response_json TEXT,
    createdAt TEXT
  )`);
});

// SSE clients
const sseClients = new Set();
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch { /* ignore */ }
  }
}

function authMiddleware(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (token !== API_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  next();
}

function idempotencyMiddleware(req, res, next) {
  const key = req.headers['idempotency-key'];
  if (!key) return next();
  const bodyHash = crypto.createHash('sha256').update(JSON.stringify(req.body||{})).digest('hex');
  db.get('SELECT response_json, request_hash FROM idempotency WHERE key = ?', [key], (err, row) => {
    if (row) {
      if (row.request_hash === bodyHash) {
        try { return res.status(201).json(JSON.parse(row.response_json)); } catch { return res.status(201).end(row.response_json); }
      } else {
        return res.status(409).json({ error: 'Idempotency-Key re-use with different payload' });
      }
    }
    // attach helper to save response
    res.saveIdempotent = (obj) => {
      db.run('INSERT OR REPLACE INTO idempotency (key, request_hash, response_json, createdAt) VALUES (?,?,?,?)',
        [key, bodyHash, JSON.stringify(obj), new Date().toISOString()]);
    };
    next();
  });
}

function signPayload(payload) {
  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
  hmac.update(payload);
  return hmac.digest('hex');
}

async function postWithRetries(url, options, retries = 3) {
  let delay = 500;
  for (let i=0; i<=retries; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
    } catch {}
    await new Promise(r => setTimeout(r, delay));
    delay = Math.min(delay * 2, 5000);
  }
  throw new Error('Failed to POST after retries');
}

async function emitWebhook(event, data) {
  if (!WEBHOOK_TARGET) return; // optional
  const payload = JSON.stringify({ event, data, sentAt: new Date().toISOString() });
  const signature = signPayload(payload);
  await postWithRetries(WEBHOOK_TARGET, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': signature,
      'Idempotency-Key': data.reference || crypto.randomUUID()
    },
    body: payload
  }).catch(()=>{});
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'banking-sim', time: new Date().toISOString() });
});

app.get('/api/transfers', (req, res) => {
  const { email, ref } = req.query;
  const params = [];
  let sql = 'SELECT * FROM transfers';
  if (email || ref) {
    const where = [];
    if (email) { where.push('LOWER(email) = LOWER(?)'); params.push(email); }
    if (ref) { where.push('reference = ?'); params.push(ref); }
    sql += ' WHERE ' + where.join(' AND ');
  }
  sql += ' ORDER BY updatedAt DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    // Map DB columns to prior JSON structure
    const list = rows.map(r => ({
      reference: r.reference,
      email: r.email,
      amount: r.amount,
      type: r.type,
      from: r.from_account,
      to: r.to_account,
      status: r.status,
      dateISO: r.dateISO,
      source: r.source,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt
    }));
    res.json(list);
  });
});

app.post('/api/transfers', authMiddleware, idempotencyMiddleware, (req, res) => {
  const body = req.body || {};
  if (!body.reference) return res.status(400).json({ error: 'reference is required' });
  const nowISO = new Date().toISOString();
  const item = {
    reference: String(body.reference),
    email: body.email || null,
    amount: Number(body.amount || 0),
    type: body.type || body.network || 'Transfer',
    from: body.from || null,
    to: body.to || null,
    status: body.status || 'Pending',
    dateISO: body.dateISO || nowISO,
    source: body.source || 'transfer',
    createdAt: nowISO,
    updatedAt: nowISO
  };
  db.run(
    `INSERT INTO transfers (reference, email, amount, type, from_account, to_account, status, dateISO, source, createdAt, updatedAt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(reference) DO UPDATE SET
       email=excluded.email,
       amount=excluded.amount,
       type=excluded.type,
       from_account=excluded.from_account,
       to_account=excluded.to_account,
       status=excluded.status,
       dateISO=excluded.dateISO,
       source=excluded.source,
       updatedAt=excluded.updatedAt`,
    [item.reference, item.email, item.amount, item.type, item.from, item.to, item.status, item.dateISO, item.source, item.createdAt, item.updatedAt],
    (err) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (typeof res.saveIdempotent === 'function') res.saveIdempotent(item);
      res.status(201).json(item);
      broadcast('transfer.created', item);
      emitWebhook('transfer.created', item);
    }
  );
});

app.patch('/api/transfers/:ref', authMiddleware, (req, res) => {
  const { ref } = req.params;
  const updates = req.body || {};
  const nowISO = new Date().toISOString();
  db.get('SELECT * FROM transfers WHERE reference = ?', [ref], (err, row) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    if (!row) return res.status(404).json({ error: 'not found' });
    const merged = {
      reference: row.reference,
      email: 'email' in updates ? updates.email : row.email,
      amount: 'amount' in updates ? Number(updates.amount) : row.amount,
      type: 'type' in updates ? updates.type : row.type,
      from: 'from' in updates ? updates.from : row.from_account,
      to: 'to' in updates ? updates.to : row.to_account,
      status: 'status' in updates ? updates.status : row.status,
      dateISO: 'dateISO' in updates ? updates.dateISO : row.dateISO,
      source: 'source' in updates ? updates.source : row.source,
      createdAt: row.createdAt,
      updatedAt: nowISO
    };
    db.run(
      `UPDATE transfers SET email=?, amount=?, type=?, from_account=?, to_account=?, status=?, dateISO=?, source=?, updatedAt=? WHERE reference=?`,
      [merged.email, merged.amount, merged.type, merged.from, merged.to, merged.status, merged.dateISO, merged.source, merged.updatedAt, ref],
      (err2) => {
        if (err2) return res.status(500).json({ error: 'db_error' });
        res.json(merged);
        broadcast('transfer.updated', merged);
        emitWebhook('transfer.updated', merged);
      }
    );
  });
});

// Inbound webhook receiver with HMAC verification
app.post('/api/webhooks/transfer-updated', express.json({ type: '*/*' }), (req, res) => {
  const raw = JSON.stringify(req.body || {});
  const sig = req.headers['x-signature'] || '';
  const expect = signPayload(raw);
  if (sig !== expect) return res.status(401).json({ error: 'invalid signature' });
  const data = req.body && req.body.data;
  if (!data || !data.reference) return res.status(400).json({ error: 'invalid payload' });
  // Apply update
  const nowISO = new Date().toISOString();
  db.run(
    `UPDATE transfers SET status=?, updatedAt=? WHERE reference=?`,
    [data.status || 'Completed', nowISO, data.reference],
    function(err){
      if (err) return res.status(500).json({ error: 'db_error' });
      broadcast('transfer.updated', { reference: data.reference, status: data.status || 'Completed', updatedAt: nowISO });
      res.json({ ok: true });
    }
  );
});

// SSE stream
app.get('/api/stream', (req, res) => {
  // token via query for EventSource convenience
  const token = req.query.token || '';
  if (token !== API_TOKEN) return res.status(401).end();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders && res.flushHeaders();
  res.write(`event: ready\ndata: {"ok":true}\n\n`);
  sseClients.add(res);
  req.on('close', () => {
    sseClients.delete(res);
    try { res.end(); } catch {}
  });
});

app.listen(PORT, () => {
  console.log(`API server running on http://localhost:${PORT}`);
});
