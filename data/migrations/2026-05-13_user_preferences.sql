-- Persist user settings so the user app and admin console share one source of truth.

CREATE TABLE IF NOT EXISTS user_preferences (
  user_email CITEXT PRIMARY KEY REFERENCES users(user_email) ON UPDATE CASCADE ON DELETE CASCADE,
  theme TEXT NOT NULL DEFAULT 'dark',
  currency TEXT NOT NULL DEFAULT 'USD',
  notif_email BOOLEAN NOT NULL DEFAULT TRUE,
  notif_push BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_user_preferences_theme CHECK (theme IN ('dark', 'light')),
  CONSTRAINT chk_user_preferences_currency CHECK (currency IN ('USD', 'EUR', 'GBP'))
);

CREATE INDEX IF NOT EXISTS user_preferences_theme_idx
  ON user_preferences (theme);

CREATE INDEX IF NOT EXISTS user_preferences_currency_idx
  ON user_preferences (currency);

DROP TRIGGER IF EXISTS trg_user_preferences_updated_at ON user_preferences;
CREATE TRIGGER trg_user_preferences_updated_at
BEFORE UPDATE ON user_preferences
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

INSERT INTO user_preferences (user_email)
SELECT user_email
FROM users
ON CONFLICT (user_email) DO NOTHING;