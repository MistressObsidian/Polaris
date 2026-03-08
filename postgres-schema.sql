-- Polaris / Base PostgreSQL schema
-- Email-primary-key variant.
-- This replaces the users UUID primary key with user_email.
-- IMPORTANT: this rebuilds the related tables so it can run on an existing UUID-based schema.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- Reset existing UUID-based tables first
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS email_logs CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS loans CASCADE;
DROP TABLE IF EXISTS transfers CASCADE;
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;
DROP TABLE IF EXISTS user_documents CASCADE;
DROP TABLE IF EXISTS user_profiles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ---------------------------------------------------------------------------
-- Shared updated_at trigger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  user_email CITEXT PRIMARY KEY,
  fullname TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  phone TEXT,
  accountname TEXT,
  available_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
  ssn_last4 VARCHAR(4),
  ssn_hash TEXT,
  suspended BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT users_user_email_chk CHECK (position('@' IN user_email::TEXT) > 1)
);

CREATE INDEX IF NOT EXISTS users_accountname_idx
  ON users (accountname);

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- User profile / KYC
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_profiles (
  user_email CITEXT PRIMARY KEY REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  dob DATE,
  citizenship_status TEXT,
  address_line1 TEXT,
  address_line2 TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  country TEXT DEFAULT 'US',
  mailing_same_as_residential BOOLEAN NOT NULL DEFAULT TRUE,
  mailing_address_line1 TEXT,
  mailing_address_line2 TEXT,
  mailing_city TEXT,
  mailing_state TEXT,
  mailing_postal_code TEXT,
  mailing_country TEXT DEFAULT 'US',
  occupation TEXT,
  employer TEXT,
  tax_id_type TEXT,
  tax_id_last4 VARCHAR(4),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_user_profiles_updated_at ON user_profiles;
CREATE TRIGGER trg_user_profiles_updated_at
BEFORE UPDATE ON user_profiles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS user_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  doc_category TEXT NOT NULL,
  doc_type TEXT,
  doc_number_last4 VARCHAR(4),
  issuer TEXT,
  expires_on DATE,
  status TEXT NOT NULL DEFAULT 'received',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_documents_user_email_idx
  ON user_documents (user_email, created_at DESC);

DROP TRIGGER IF EXISTS trg_user_documents_updated_at ON user_documents;
CREATE TRIGGER trg_user_documents_updated_at
BEFORE UPDATE ON user_documents
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Accounts
-- Single-balance model: only 'available' is used by the app now.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  type TEXT NOT NULL DEFAULT 'available',
  currency TEXT NOT NULL DEFAULT 'USD',
  balance NUMERIC(14,2) NOT NULL DEFAULT 0,
  available NUMERIC(14,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_accounts_type CHECK (type = 'available'),
  CONSTRAINT chk_accounts_currency CHECK (currency = 'USD'),
  CONSTRAINT chk_accounts_balance_nonnegative CHECK (balance >= 0),
  CONSTRAINT chk_accounts_available_nonnegative CHECK (available >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_email_type_uidx
  ON accounts (user_email, type);

CREATE INDEX IF NOT EXISTS accounts_user_email_idx
  ON accounts (user_email);

DROP TRIGGER IF EXISTS trg_accounts_updated_at ON accounts;
CREATE TRIGGER trg_accounts_updated_at
BEFORE UPDATE ON accounts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Transactions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  type TEXT,
  direction TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  description TEXT,
  reference TEXT,
  status TEXT NOT NULL DEFAULT 'completed',
  balance_after NUMERIC(14,2),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_transactions_direction CHECK (direction IN ('credit', 'debit')),
  CONSTRAINT chk_transactions_status CHECK (status IN ('pending', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS transactions_user_email_created_idx
  ON transactions (user_email, created_at DESC);

CREATE INDEX IF NOT EXISTS transactions_account_created_idx
  ON transactions (account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS transactions_reference_idx
  ON transactions (reference);

DROP TRIGGER IF EXISTS trg_transactions_updated_at ON transactions;
CREATE TRIGGER trg_transactions_updated_at
BEFORE UPDATE ON transactions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Transfers / payments metadata
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transfers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  sender_account_type TEXT NOT NULL DEFAULT 'available',
  recipient_name TEXT,
  recipient_email CITEXT,
  bank_name TEXT,
  routing_number TEXT,
  account_number TEXT,
  btc_address TEXT,
  method TEXT NOT NULL DEFAULT 'wire',
  amount NUMERIC(14,2) NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_transfers_sender_account_type CHECK (sender_account_type = 'available'),
  CONSTRAINT chk_transfers_method CHECK (method IN ('wire', 'ach', 'crypto')),
  CONSTRAINT chk_transfers_status CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  CONSTRAINT chk_transfers_amount_positive CHECK (amount > 0)
);

CREATE INDEX IF NOT EXISTS transfers_user_email_created_idx
  ON transfers (user_email, created_at DESC);

CREATE INDEX IF NOT EXISTS transfers_recipient_email_idx
  ON transfers (recipient_email);

DROP TRIGGER IF EXISTS trg_transfers_updated_at ON transfers;
CREATE TRIGGER trg_transfers_updated_at
BEFORE UPDATE ON transfers
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Loans
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS loans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  amount NUMERIC(14,2) NOT NULL,
  term_months INTEGER NOT NULL,
  apr_estimate NUMERIC(6,2),
  monthly_payment_estimate NUMERIC(14,2),
  status TEXT NOT NULL DEFAULT 'pending',
  fee_paid BOOLEAN NOT NULL DEFAULT FALSE,
  locked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_loans_amount_positive CHECK (amount > 0),
  CONSTRAINT chk_loans_term_positive CHECK (term_months > 0),
  CONSTRAINT chk_loans_status CHECK (status IN ('pending', 'approved', 'rejected', 'completed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS loans_user_email_created_idx
  ON loans (user_email, created_at DESC);

DROP TRIGGER IF EXISTS trg_loans_updated_at ON loans;
CREATE TRIGGER trg_loans_updated_at
BEFORE UPDATE ON loans
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Password resets
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_email_idx
  ON password_reset_tokens (user_email, created_at DESC);

CREATE INDEX IF NOT EXISTS password_reset_tokens_hash_idx
  ON password_reset_tokens (token_hash);

-- ---------------------------------------------------------------------------
-- Email logs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email CITEXT REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE SET NULL,
  to_email CITEXT NOT NULL,
  subject TEXT NOT NULL,
  html_body TEXT,
  text_body TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_email_logs_status CHECK (status IN ('pending', 'sent', 'failed'))
);

CREATE INDEX IF NOT EXISTS email_logs_user_email_created_idx
  ON email_logs (user_email, created_at DESC);

CREATE INDEX IF NOT EXISTS email_logs_to_email_idx
  ON email_logs (to_email);

DROP TRIGGER IF EXISTS trg_email_logs_updated_at ON email_logs;
CREATE TRIGGER trg_email_logs_updated_at
BEFORE UPDATE ON email_logs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Helpful seed pattern for account creation after a new user is inserted.
-- Run this manually after creating a user if needed:
-- INSERT INTO accounts (user_email, type, currency, balance, available)
-- VALUES ('user@example.com', 'available', 'USD', 0, 0)
-- ON CONFLICT (user_email, type) DO NOTHING;
-- ---------------------------------------------------------------------------
