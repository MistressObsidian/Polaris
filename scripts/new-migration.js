import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const migrationsDir = path.join(projectRoot, "data", "migrations");
const rawName = process.argv.slice(2).join(" ").trim();

function printUsage() {
  console.log("Usage: npm run db:migrate:new -- <migration-name>");
}

function toTimestamp(date = new Date()) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hour = String(date.getUTCHours()).padStart(2, "0");
  const minute = String(date.getUTCMinutes()).padStart(2, "0");
  const second = String(date.getUTCSeconds()).padStart(2, "0");
  return `${year}-${month}-${day}_${hour}${minute}${second}`;
}

function slugify(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function buildTemplate(name) {
  return `-- Migration: ${name}\n-- Write forward-only, non-destructive SQL here.\n\nBEGIN;\n\n-- Example:\n-- ALTER TABLE users ADD COLUMN IF NOT EXISTS some_column TEXT;\n\nCOMMIT;\n`;
}

if (!rawName || rawName === "--help" || rawName === "-h") {
  printUsage();
  process.exitCode = rawName ? 0 : 1;
} else {
  const slug = slugify(rawName);
  if (!slug) {
    printUsage();
    process.exitCode = 1;
  } else {
    fs.mkdirSync(migrationsDir, { recursive: true });
    const fileName = `${toTimestamp()}_${slug}.sql`;
    const filePath = path.join(migrationsDir, fileName);
    if (fs.existsSync(filePath)) {
      console.error(`Migration already exists: ${path.relative(projectRoot, filePath)}`);
      process.exitCode = 1;
    } else {
      fs.writeFileSync(filePath, buildTemplate(rawName), "utf8");
      console.log(`Created ${path.relative(projectRoot, filePath)}`);
    }
  }
}