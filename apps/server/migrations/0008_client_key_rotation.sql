-- Rotation of the per-login-method upstream client key (private_key_jwt). See CLAUDE.md and
-- docs/login-methods.md ("Rotating the client key").
--
-- * The active key stays in client_key_kid / client_public_jwk / client_private_jwk_encrypted.
-- * client_next_*: a prepared key, published in /t/{slug}/federation/{id}/jwks next to the active
--   one but not used to sign until it is promoted. Its private key is a SecretBox envelope with
--   the same context as the active one (`login_method:<id>:client_private_jwk`), so promotion
--   moves the envelope without decrypting it.
-- * client_retiring_*: the key that was active before the last promotion, public half only (it
--   never signs again), still published until client_retiring_until, so client assertions
--   signed just before the promotion still verify upstream.

ALTER TABLE login_methods
  ADD COLUMN client_next_key_kid text CHECK (client_next_key_kid ~ '^[A-Za-z0-9_-]{1,128}$'),
  ADD COLUMN client_next_public_jwk jsonb
    CHECK (jsonb_typeof(client_next_public_jwk) = 'object' AND NOT (client_next_public_jwk ? 'd')),
  ADD COLUMN client_next_private_jwk_encrypted text
    CHECK (client_next_private_jwk_encrypted LIKE 'pv1.%'),
  ADD COLUMN client_next_key_created_at timestamptz,
  ADD COLUMN client_retiring_key_kid text
    CHECK (client_retiring_key_kid ~ '^[A-Za-z0-9_-]{1,128}$'),
  ADD COLUMN client_retiring_public_jwk jsonb
    CHECK (jsonb_typeof(client_retiring_public_jwk) = 'object'
           AND NOT (client_retiring_public_jwk ? 'd')),
  ADD COLUMN client_retiring_until timestamptz,
  ADD CONSTRAINT login_methods_client_next_key_columns CHECK (
    (client_next_key_kid IS NULL) = (client_next_public_jwk IS NULL)
    AND (client_next_public_jwk IS NULL) = (client_next_private_jwk_encrypted IS NULL)
    AND (client_next_private_jwk_encrypted IS NULL) = (client_next_key_created_at IS NULL)
  ),
  ADD CONSTRAINT login_methods_client_retiring_key_columns CHECK (
    (client_retiring_key_kid IS NULL) = (client_retiring_public_jwk IS NULL)
    AND (client_retiring_public_jwk IS NULL) = (client_retiring_until IS NULL)
  ),
  -- A next key exists only next to an active one.
  ADD CONSTRAINT login_methods_client_next_key_needs_active CHECK (
    client_next_key_kid IS NULL OR client_key_kid IS NOT NULL
  );
