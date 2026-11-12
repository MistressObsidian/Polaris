-- Read-only address watchlist. No recovery phrases, private keys or signing permissions.
CREATE TABLE external_wallets (
  id UUID PRIMARY KEY,
  user_email CITEXT NOT NULL REFERENCES users(user_email) ON DELETE CASCADE,
  network TEXT NOT NULL CHECK (network IN ('bitcoin', 'ethereum')),
  address VARCHAR(90) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_email, network, address)
);
