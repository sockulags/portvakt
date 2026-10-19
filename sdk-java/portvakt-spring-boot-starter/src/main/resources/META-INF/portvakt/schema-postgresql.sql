-- Portvakt starter: the JDBC token store (portvakt.login.token-store=jdbc). Contents are sealed
-- (AES-256-GCM, portvakt.login.token-encryption-key); no token is stored in the clear.
-- The runtime role needs SELECT, INSERT, UPDATE and DELETE on the table.
CREATE TABLE IF NOT EXISTS portvakt_grant (
  grant_id VARCHAR(128) PRIMARY KEY,
  sealed BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS portvakt_grant_expires_at ON portvakt_grant (expires_at);
