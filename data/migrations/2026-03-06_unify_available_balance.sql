-- Polaris: unify balances to a single available balance model
-- Fixes: chk_accounts_type (SQLSTATE 23514)

BEGIN;

-- 1) Ensure users has unified balance column
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS available_balance NUMERIC(14,2) NOT NULL DEFAULT 0;

-- Optional pre-check: inspect dependent objects before dropping legacy columns
-- SELECT
--   d.classid::regclass AS dependent_catalog,
--   d.objid::regclass AS dependent_object,
--   a.attname AS referenced_column
-- FROM pg_depend d
-- JOIN pg_attribute a
--   ON a.attrelid = 'users'::regclass
--  AND a.attnum = d.refobjsubid
-- WHERE d.refobjid = 'users'::regclass
--   AND a.attname IN ('checking', 'savings', 'totalbalance');

-- 2) Drop old account type constraint first (will re-add later)
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS chk_accounts_type;

-- 3) Backfill users.available_balance from existing account availability
UPDATE users u
SET available_balance = COALESCE(a.total_available, 0)
FROM (
  SELECT user_email, COALESCE(SUM(available), 0)::NUMERIC(14,2) AS total_available
  FROM accounts
  GROUP BY user_email
) a
WHERE a.user_email = u.user_email;

-- 4) Create one available account per user if missing
INSERT INTO accounts (user_email, type, currency, balance, available)
SELECT u.user_email, 'available', 'USD', u.available_balance, u.available_balance
FROM users u
WHERE NOT EXISTS (
  SELECT 1 FROM accounts a WHERE a.user_email = u.user_email AND a.type = 'available'
);

-- 5) Remove legacy account rows
DELETE FROM accounts
WHERE type IN ('checking', 'savings');

-- 6) Drop legacy user aggregate columns
ALTER TABLE users DROP COLUMN IF EXISTS checking CASCADE;
ALTER TABLE users DROP COLUMN IF EXISTS savings CASCADE;
ALTER TABLE users DROP COLUMN IF EXISTS totalbalance CASCADE;

-- 7) Normalize transfer sender account type values first
--    Drop any existing CHECK constraint that references transfers.sender_account_type,
--    regardless of the constraint name (e.g. transfers_sender_account_type_check).
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE t.relname = 'transfers'
      AND c.contype = 'c'
      AND pg_get_constraintdef(c.oid) ILIKE '%sender_account_type%'
  LOOP
    EXECUTE format('ALTER TABLE transfers DROP CONSTRAINT IF EXISTS %I', r.conname);
  END LOOP;
END $$;

-- Optional data normalization for existing transfer rows
UPDATE transfers
SET sender_account_type = 'available'
WHERE sender_account_type IS NULL OR sender_account_type IN ('checking', 'savings');

-- 8) Re-add updated constraints
ALTER TABLE accounts
  ADD CONSTRAINT chk_accounts_type CHECK (type = 'available');

ALTER TABLE transfers
  ADD CONSTRAINT chk_transfers_sender_account_type CHECK (sender_account_type = 'available');

COMMIT;
