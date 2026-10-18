-- Upstream OIDC federation (M3). See docs/plan.md, "Milestones" (M3) and CLAUDE.md.
--
-- * login_methods gains how Portvakt authenticates at the upstream token endpoint, whether the
--   upstream userinfo endpoint is called, and a per-login-method key pair for private_key_jwt.
--   The private key is a SecretBox envelope (context `login_method:<id>:client_private_jwk`);
--   the public half is published at /t/{slug}/federation/{loginMethodId}/jwks.
-- * federation_states holds one row per upstream authorization request: the state (hashed),
--   the interaction it belongs to, the PKCE verifier (encrypted) and the nonce. The upstream
--   callback consumes it once; the login is then finished on the interaction path, where the
--   interaction cookie is sent, by consuming the completion reference once. One pending row per
--   (interaction, login method) is reused while it is valid.
-- * persons gains protected_identity: sticky once any linked identity was flagged upstream
--   (only an admin action clears it).

ALTER TABLE login_methods
  ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'private_key_jwt')),
  ADD COLUMN use_userinfo boolean NOT NULL DEFAULT false,
  -- Multi-tenant issuers (Entra /common, /organizations, {tenantid}): the upstream tenant ids
  -- (ID token `tid`) allowed to sign in. Empty for single-tenant issuers.
  ADD COLUMN allowed_upstream_tenants text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(allowed_upstream_tenants) <= 100),
  -- Map the email claim without email_verified (an upstream that verifies addresses itself).
  ADD COLUMN trust_upstream_email boolean NOT NULL DEFAULT false,
  -- aud of private_key_jwt client assertions: the token endpoint (Entra) or the issuer.
  ADD COLUMN client_assertion_audience text NOT NULL DEFAULT 'token_endpoint'
    CHECK (client_assertion_audience IN ('token_endpoint', 'issuer')),
  ADD COLUMN client_key_kid text CHECK (client_key_kid ~ '^[A-Za-z0-9_-]{1,128}$'),
  ADD COLUMN client_public_jwk jsonb
    CHECK (jsonb_typeof(client_public_jwk) = 'object' AND NOT (client_public_jwk ? 'd')),
  ADD COLUMN client_private_jwk_encrypted text CHECK (client_private_jwk_encrypted LIKE 'pv1.%'),
  ADD CONSTRAINT login_methods_client_key_columns CHECK (
    (client_key_kid IS NULL) = (client_public_jwk IS NULL)
    AND (client_public_jwk IS NULL) = (client_private_jwk_encrypted IS NULL)
  );

CREATE TABLE federation_states (
  -- SHA-256 (base64url) of the state value sent upstream; the value itself is never stored.
  state_hash              text PRIMARY KEY CHECK (state_hash ~ '^[A-Za-z0-9_-]{43}$'),
  tenant_id               uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  login_method_id         uuid NOT NULL,
  interaction_uid         text NOT NULL CHECK (length(interaction_uid) BETWEEN 1 AND 128),
  -- The state itself, encrypted, so a pending request can be sent upstream again.
  state_encrypted         text NOT NULL CHECK (state_encrypted LIKE 'pv1.%'),
  code_verifier_encrypted text NOT NULL CHECK (code_verifier_encrypted LIKE 'pv1.%'),
  nonce                   text NOT NULL CHECK (length(nonce) BETWEEN 1 AND 128),
  max_age                 integer CHECK (max_age >= 0),
  expires_at              timestamptz NOT NULL,
  -- Set by the upstream callback (single use).
  callback_at             timestamptz,
  -- SHA-256 (base64url) of the completion reference handed to the interaction path.
  completion_hash         text UNIQUE CHECK (completion_hash ~ '^[A-Za-z0-9_-]{43}$'),
  -- What the callback established (person, acr, amr); ids and protocol values only.
  completion              jsonb CHECK (jsonb_typeof(completion) = 'object'),
  -- Set when the interaction consumed the completion (single use).
  completed_at            timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT federation_states_completion CHECK ((completion_hash IS NULL) = (completion IS NULL)),
  CONSTRAINT federation_states_order CHECK (
    (completion IS NULL OR callback_at IS NOT NULL) AND (completed_at IS NULL OR completion IS NOT NULL)
  ),
  FOREIGN KEY (tenant_id, login_method_id) REFERENCES login_methods (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX federation_states_expires_idx ON federation_states (expires_at);
CREATE INDEX federation_states_login_method_idx ON federation_states (login_method_id);
CREATE UNIQUE INDEX federation_states_one_pending
  ON federation_states (tenant_id, interaction_uid, login_method_id) WHERE callback_at IS NULL;

ALTER TABLE persons ADD COLUMN protected_identity boolean NOT NULL DEFAULT false;
