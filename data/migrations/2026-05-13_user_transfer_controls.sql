-- Allow admins to disable self-service transfers for specific users.

ALTER TABLE user_preferences
ADD COLUMN IF NOT EXISTS transfers_enabled BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE user_preferences
SET transfers_enabled = TRUE
WHERE transfers_enabled IS DISTINCT FROM TRUE;
