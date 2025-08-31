// server.js
import express from "express";
import { Client } from "pg";
import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

client.connect();

// Register
app.post("/api/register", async (req, res) => {
  const { fullname, email, phone, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    await client.query(
      "INSERT INTO users (fullname, email, phone, password_hash) VALUES ($1,$2,$3,$4)",
      [fullname, email.toLowerCase(), phone, hash]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await client.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
  if (result.rows.length === 0) return res.status(401).json({ error: "User not found" });

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: "Invalid password" });

  res.json({
    ok: true,
    user: { id: user.id, fullname: user.fullname, email: user.email, balance: user.total_balance }
  });
});

// Transfers
app.post("/api/transfers", async (req, res) => {
  const { user_id, amount, note } = req.body;
  const ref = "TXN" + Date.now();
  await client.query(
    "INSERT INTO transfers (reference, user_id, amount, note) VALUES ($1,$2,$3,$4)",
    [ref, user_id, amount, note]
  );
  res.json({ ok: true, reference: ref });
});

app.listen(3001, () => console.log("API running on http://localhost:3001"));
