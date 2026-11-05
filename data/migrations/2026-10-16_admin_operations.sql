ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO platform_settings (key, value) VALUES ('features',
  '{"registration_enabled":true,"transfers_enabled":true,"investments_enabled":true}')
ON CONFLICT (key) DO NOTHING;

-- No passwords, access tokens, message bodies, or account numbers are recorded here.
-- No foreign key: retain the operational record when an empty user account is removed.
CREATE TABLE IF NOT EXISTS activity_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_email TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('admin','customer')),
  target_email TEXT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'started' CHECK (outcome IN ('started','succeeded','failed')),
  http_status INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS activity_events_created_idx ON activity_events(created_at DESC, id);
CREATE INDEX IF NOT EXISTS activity_events_target_idx ON activity_events(target_email, created_at DESC);

CREATE TABLE IF NOT EXISTS loan_reviews (
  loan_id UUID PRIMARY KEY REFERENCES loans(id) ON DELETE CASCADE,
  decision TEXT NOT NULL CHECK (decision IN ('approved','rejected','cancelled')),
  reason TEXT NOT NULL,
  reviewed_by TEXT NOT NULL,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
