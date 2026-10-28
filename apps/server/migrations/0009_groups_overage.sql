-- Entra ID groups overage through Microsoft Graph. See CLAUDE.md, docs/claims.md ("Groups") and
-- docs/login-methods.md ("Entra ID").
--
-- * login_methods.resolve_groups_overage: when an ID token names a source for the groups claim
--   instead of carrying it (`_claim_names`), the groups are read from Microsoft Graph
--   (GRAPH_API_URL, /me/transitiveMemberOf) with the upstream access token; a failed lookup
--   fails the login. Off (the default): the groups count as empty, as before.

ALTER TABLE login_methods
  ADD COLUMN resolve_groups_overage boolean NOT NULL DEFAULT false;
