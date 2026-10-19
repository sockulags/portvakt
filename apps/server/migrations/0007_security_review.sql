-- Pre-release security review fixes. See CLAUDE.md and docs/claims.md ("client_credentials").
--
-- * applications.service_audiences: the client_ids an application may request
--   client_credentials (service) tokens for. Empty (the default): no service tokens for other
--   applications; a token for the application itself stays possible. The target must also be
--   enabled in the same tenant.

ALTER TABLE applications
  ADD COLUMN service_audiences text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(service_audiences) <= 50
           AND array_position(service_audiences, NULL) IS NULL);
