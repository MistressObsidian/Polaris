import "dotenv/config";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const migrationsDir = path.join(projectRoot, "data", "migrations");
const databaseUrl = String(process.env.DATABASE_URL || "").trim();
const command = String(process.argv[2] || "up").trim().toLowerCase();
const supportedCommands = new Set(["up", "status"]);

function getSslFromDatabaseUrl(connectionString) {
  if (!connectionString) return false;
  try {
    const parsed = new URL(connectionString);
    const sslmode = String(parsed.searchParams.get("sslmode") || "").trim().toLowerCase();
    if (["require", "verify-ca", "verify-full"].includes(sslmode)) {
      return { rejectUnauthorized: false };
    }
    if (sslmode === "disable") return false;
    return false;
  } catch {
    return false;
  }
}

function ensureEnvironment() {
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is not configured");
  }
  if (!supportedCommands.has(command)) {
    throw new Error(`Unsupported command \"${command}\". Use \"up\" or \"status\".`);
  }
}

function hashMigration(source) {
  return crypto.createHash("sha256").update(source).digest("hex");
}

function stripTransactionWrappers(source) {
  const lines = String(source || "").replace(/^\uFEFF/, "").split(/\r?\n/);

  const firstStatementIndex = lines.findIndex((line) => {
    const trimmed = line.trim();
    return trimmed && !trimmed.startsWith("--");
  });

  if (firstStatementIndex >= 0 && /^BEGIN\s*;?$/i.test(lines[firstStatementIndex].trim())) {
    lines[firstStatementIndex] = "";
  }

  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const trimmed = lines[index].trim();
    if (!trimmed || trimmed.startsWith("--")) continue;
    if (/^COMMIT\s*;?$/i.test(trimmed)) {
      lines[index] = "";
    }
    break;
  }

  return lines.join("\n").trim();
}

function readMigrations() {
  if (!fs.existsSync(migrationsDir)) return [];

  return fs
    .readdirSync(migrationsDir)
    .filter((fileName) => fileName.toLowerCase().endsWith(".sql"))
    .sort((left, right) => left.localeCompare(right))
    .map((fileName) => {
      const filePath = path.join(migrationsDir, fileName);
      const source = fs.readFileSync(filePath, "utf8");
      return {
        fileName,
        filePath,
        source,
        checksum: hashMigration(source),
        sql: stripTransactionWrappers(source),
      };
    });
}

async function getClient() {
  const { Pool } = pg;
  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: getSslFromDatabaseUrl(databaseUrl),
  });
  const client = await pool.connect();
  return { pool, client };
}

async function ensureMigrationsTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id BIGSERIAL PRIMARY KEY,
      filename TEXT NOT NULL UNIQUE,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function getAppliedMigrations(client) {
  const result = await client.query(
    `SELECT filename, checksum, applied_at
     FROM schema_migrations
     ORDER BY filename ASC`
  );
  return result.rows;
}

function compareMigrations(allMigrations, appliedRows) {
  const appliedMap = new Map(appliedRows.map((row) => [row.filename, row]));
  const drift = [];
  const pending = [];

  for (const migration of allMigrations) {
    const applied = appliedMap.get(migration.fileName);
    if (!applied) {
      pending.push(migration);
      continue;
    }
    if (applied.checksum !== migration.checksum) {
      drift.push({
        fileName: migration.fileName,
        appliedChecksum: applied.checksum,
        currentChecksum: migration.checksum,
        appliedAt: applied.applied_at,
      });
    }
  }

  return { pending, drift };
}

function printStatus(allMigrations, appliedRows, pending, drift) {
  console.log(`Migration directory: ${path.relative(projectRoot, migrationsDir)}`);
  console.log(`Tracked migrations: ${appliedRows.length}`);
  console.log(`Pending migrations: ${pending.length}`);

  if (pending.length) {
    console.log("Pending:");
    pending.forEach((migration) => console.log(`- ${migration.fileName}`));
  }

  if (!allMigrations.length) {
    console.log("No SQL migration files found.");
  }

  if (drift.length) {
    console.log("Checksum drift detected:");
    drift.forEach((item) => {
      console.log(`- ${item.fileName}`);
      console.log(`  applied: ${item.appliedChecksum}`);
      console.log(`  current: ${item.currentChecksum}`);
    });
  }

  if (!pending.length && !drift.length && allMigrations.length) {
    console.log("Schema migration status is clean.");
  }
}

async function applyMigrations(client, pending, drift) {
  if (drift.length) {
    throw new Error("Migration checksum drift detected. Resolve the changed migration files before applying new ones.");
  }

  if (!pending.length) {
    console.log("No pending migrations.");
    return;
  }

  for (const migration of pending) {
    console.log(`Applying ${migration.fileName}...`);
    await client.query("BEGIN");
    try {
      if (migration.sql) {
        await client.query(migration.sql);
      }
      await client.query(
        `INSERT INTO schema_migrations (filename, checksum)
         VALUES ($1, $2)`,
        [migration.fileName, migration.checksum]
      );
      await client.query("COMMIT");
      console.log(`Applied ${migration.fileName}`);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw new Error(`Migration ${migration.fileName} failed: ${error.message}`);
    }
  }
}

async function main() {
  ensureEnvironment();

  const allMigrations = readMigrations();
  const { pool, client } = await getClient();

  try {
    await ensureMigrationsTable(client);
    const appliedRows = await getAppliedMigrations(client);
    const { pending, drift } = compareMigrations(allMigrations, appliedRows);

    if (command === "status") {
      printStatus(allMigrations, appliedRows, pending, drift);
      if (drift.length) process.exitCode = 1;
      return;
    }

    await applyMigrations(client, pending, drift);
    const nextAppliedRows = await getAppliedMigrations(client);
    const nextState = compareMigrations(allMigrations, nextAppliedRows);
    printStatus(allMigrations, nextAppliedRows, nextState.pending, nextState.drift);
    if (nextState.drift.length) process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});