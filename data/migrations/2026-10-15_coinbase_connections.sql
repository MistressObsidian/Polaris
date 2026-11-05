-- Customer-owned, read-only Coinbase OAuth connections. Tokens are encrypted by the app.
CREATE TABLE IF NOT EXISTS coinbase_connections (
  user_email CITEXT PRIMARY KEY REFERENCES users(user_email) ON DELETE CASCADE,
  token_cipher TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coinbase_oauth_states (
  state_hash TEXT PRIMARY KEY,
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON DELETE CASCADE,
  browser_hash TEXT NOT NULL,
  verifier_cipher TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS coinbase_oauth_states_user_idx ON coinbase_oauth_states(user_email);
CREATE INDEX IF NOT EXISTS coinbase_oauth_states_expiry_idx ON coinbase_oauth_states(expires_at);
