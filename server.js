
import express from "express";
import pkg from "pg";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const { PGHOST, PGDATABASE, PGUSER, PGPASSWORD } = process.env;

const pool = new Pool({
  host: PGHOST,
  database: PGDATABASE,
  user: PGUSER,
  password: PGPASSWORD,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Example: get all users
app.get("/api/users", async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query("SELECT * FROM register");
    res.json(result.rows);
  } catch (errors) {
    console.log(errors);
    res.status(500).json({ error: "Failed to fetch users" });
  } finally {
    client.release();
  }
});


// Example: add new user
app.post("/api/users", async (req, res) => {
  const { fullname, email, phone, password } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query(
      "INSERT INTO register (fullname, email, phone, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [fullname, email, phone, password]
    );
    res.json(result.rows[0]);
  } catch (errors) {
    console.log(errors);
    res.status(500).json({ error: "Failed to add user" });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
