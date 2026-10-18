-- Portvakt domain model (M1). See docs/plan.md, "Domain model".
--
-- Conventions:
-- * Objects are created unqualified, in the first schema of search_path, so tests can isolate
--   themselves in a private schema.
-- * Every tenant-scoped table carries tenant_id. Tables that reference another tenant-scoped row
--   use a composite foreign key (tenant_id, x_id), so a row can never point into another tenant.
-- * Global tables: applications (registered once per install), signing_keys.
-- * Secrets and personal identity numbers are never stored in clear: `*_encrypted` columns hold
--   SecretBox envelopes (`pv1.` prefix) and `*_index` columns hold a keyed blind index
--   (HMAC-SHA256, key derived from the master key) for equality lookups; `*_index_key` records
--   which master key derived the index, so it can be recomputed after master key rotation.
-- * Privileges for the runtime role are applied by the migration runner from
--   migrations/grants/runtime-role.sql after every run (audit_events: SELECT and INSERT only).

CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- Tenants --------------------------------------------------------------------------------------

CREATE TABLE tenants (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug       text NOT NULL UNIQUE
             CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
  name       text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER tenants_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Applications (global) -------------------------------------------------------------------------

CREATE TABLE applications (
  id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id                 text NOT NULL UNIQUE CHECK (client_id ~ '^[A-Za-z0-9._~-]{3,128}$'),
  name                      text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
  enabled                   boolean NOT NULL DEFAULT true,
  token_endpoint_auth_method text NOT NULL
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'private_key_jwt')),
  client_secret_encrypted   text CHECK (client_secret_encrypted LIKE 'pv1.%'),
  jwks_uri                  text CHECK (jwks_uri ~ '^https?://'),
  jwks                      jsonb CHECK (jsonb_typeof(jwks) = 'object' AND jsonb_typeof(jwks -> 'keys') = 'array'),
  redirect_uris             text[] NOT NULL CHECK (cardinality(redirect_uris) >= 1),
  post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
  allowed_extra_scopes      text[] NOT NULL DEFAULT '{}'
    CHECK (allowed_extra_scopes <@ ARRAY['pin']::text[]),
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT applications_client_auth CHECK (
    (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post')
      AND client_secret_encrypted IS NOT NULL AND jwks_uri IS NULL AND jwks IS NULL)
    OR
    (token_endpoint_auth_method = 'private_key_jwt'
      AND client_secret_encrypted IS NULL AND ((jwks_uri IS NULL) <> (jwks IS NULL)))
  )
);
CREATE TRIGGER applications_updated_at BEFORE UPDATE ON applications
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Roles an application declares; assignments and rules reference these.
CREATE TABLE application_roles (
  application_id uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
  role           text NOT NULL CHECK (role ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$'),
  description    text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, role)
);

-- Attribute keys an application declares; attribute assignments reference these.
CREATE TABLE application_attribute_keys (
  application_id uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
  key            text NOT NULL CHECK (key ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$'),
  description    text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (application_id, key)
);

-- An application enabled for a tenant. Only enabled applications authenticate in that tenant.
CREATE TABLE tenant_applications (
  tenant_id      uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  application_id uuid NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
  enabled        boolean NOT NULL DEFAULT true,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, application_id)
);
CREATE INDEX tenant_applications_application_idx ON tenant_applications (application_id);
CREATE TRIGGER tenant_applications_updated_at BEFORE UPDATE ON tenant_applications
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Login methods (upstream OIDC per tenant) ------------------------------------------------------

CREATE TABLE login_methods (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  kind                    text NOT NULL CHECK (kind IN ('employee', 'citizen')),
  display_name            text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
  issuer                  text NOT NULL CHECK (issuer ~ '^https?://'),
  client_id               text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 512),
  client_secret_encrypted text CHECK (client_secret_encrypted LIKE 'pv1.%'),
  scopes                  text[] NOT NULL DEFAULT ARRAY['openid']::text[]
                          CHECK ('openid' = ANY (scopes)),
  claim_mapping           jsonb NOT NULL CHECK (jsonb_typeof(claim_mapping) = 'object'),
  asserted_acr            text NOT NULL CHECK (length(asserted_acr) BETWEEN 1 AND 255),
  secret_expires_at       timestamptz,
  max_age_seconds         integer NOT NULL CHECK (max_age_seconds > 0),
  idle_seconds            integer NOT NULL CHECK (idle_seconds > 0),
  allow_sso               boolean NOT NULL DEFAULT true,
  -- Citizen methods asserting the same personal identity number may share one person.
  link_by_pin             boolean NOT NULL DEFAULT false,
  enabled                 boolean NOT NULL DEFAULT true,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CONSTRAINT login_methods_idle_within_max_age CHECK (idle_seconds <= max_age_seconds)
);
CREATE INDEX login_methods_tenant_idx ON login_methods (tenant_id) WHERE enabled;
CREATE INDEX login_methods_secret_expiry_idx ON login_methods (secret_expires_at)
  WHERE secret_expires_at IS NOT NULL;
CREATE TRIGGER login_methods_updated_at BEFORE UPDATE ON login_methods
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Home realm discovery: an email domain maps to at most one login method per tenant.
CREATE TABLE login_method_domains (
  tenant_id       uuid NOT NULL,
  login_method_id uuid NOT NULL,
  domain          text NOT NULL
                  CHECK (domain ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$'),
  PRIMARY KEY (tenant_id, domain),
  FOREIGN KEY (tenant_id, login_method_id) REFERENCES login_methods (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX login_method_domains_method_idx ON login_method_domains (login_method_id);

-- Persons and identities ------------------------------------------------------------------------

CREATE TABLE persons (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (tenant_id, id)
);
CREATE TRIGGER persons_updated_at BEFORE UPDATE ON persons
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Link from a person to (login method, upstream subject). Deleting a login method that still has
-- identities is refused (NO ACTION): disable it instead, so persons keep their identity links.
CREATE TABLE identities (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  person_id       uuid NOT NULL,
  login_method_id uuid NOT NULL,
  subject         text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  -- Latest mapped attributes, without the personal identity number (held below).
  attributes      jsonb NOT NULL DEFAULT '{}'
                  CHECK (jsonb_typeof(attributes) = 'object' AND NOT (attributes ? 'pin')),
  pin_encrypted   text CHECK (pin_encrypted LIKE 'pv1.%'),
  pin_index       text,
  pin_index_key   text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  last_login_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (login_method_id, subject),
  CONSTRAINT identities_pin_columns CHECK (
    (pin_encrypted IS NULL) = (pin_index IS NULL) AND (pin_index IS NULL) = (pin_index_key IS NULL)
  ),
  FOREIGN KEY (tenant_id, person_id) REFERENCES persons (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, login_method_id) REFERENCES login_methods (tenant_id, id)
);
CREATE INDEX identities_person_idx ON identities (tenant_id, person_id);
CREATE INDEX identities_pin_idx ON identities (tenant_id, pin_index) WHERE pin_index IS NOT NULL;
CREATE TRIGGER identities_updated_at BEFORE UPDATE ON identities
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Roles and attributes --------------------------------------------------------------------------

CREATE TABLE role_assignments (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  person_id      uuid NOT NULL,
  application_id uuid NOT NULL,
  role           text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, person_id, application_id, role),
  FOREIGN KEY (tenant_id, person_id) REFERENCES persons (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE,
  FOREIGN KEY (application_id, role)
    REFERENCES application_roles (application_id, role) ON DELETE CASCADE
);

-- In tenant T, upstream group G from login method M gives role R in application X. Evaluated at
-- every login. The login method is required: group values are only meaningful per IdP.
CREATE TABLE role_rules (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL,
  application_id  uuid NOT NULL,
  login_method_id uuid NOT NULL,
  group_value     text NOT NULL CHECK (length(group_value) BETWEEN 1 AND 512),
  role            text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT role_rules_unique
    UNIQUE (tenant_id, application_id, login_method_id, group_value, role),
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, login_method_id)
    REFERENCES login_methods (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (application_id, role)
    REFERENCES application_roles (application_id, role) ON DELETE CASCADE
);
CREATE INDEX role_rules_lookup_idx
  ON role_rules (tenant_id, application_id, login_method_id, group_value);

CREATE TABLE attribute_assignments (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  person_id      uuid NOT NULL,
  application_id uuid NOT NULL,
  key            text NOT NULL,
  value          text NOT NULL CHECK (length(value) <= 2000),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, person_id, application_id, key),
  FOREIGN KEY (tenant_id, person_id) REFERENCES persons (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE,
  FOREIGN KEY (application_id, key)
    REFERENCES application_attribute_keys (application_id, key) ON DELETE CASCADE
);
CREATE TRIGGER attribute_assignments_updated_at BEFORE UPDATE ON attribute_assignments
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Representation (ombud) ------------------------------------------------------------------------

CREATE TABLE parties (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  type         text NOT NULL CHECK (type IN ('person', 'organisation')),
  -- Canonical personnummer (12 digits) or organisationsnummer (10 digits), encrypted.
  identifier_encrypted text NOT NULL CHECK (identifier_encrypted LIKE 'pv1.%'),
  identifier_index     text NOT NULL,
  identifier_index_key text NOT NULL,
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, type, identifier_index),
  UNIQUE (tenant_id, id)
);
CREATE TRIGGER parties_updated_at BEFORE UPDATE ON parties
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- An agent may act for party Q within [valid_from, valid_to), until revoked. The agent is either
-- a known person or, before their first sign-in, a personal identity number (blind index, matched
-- against identities.pin_index at login). all_applications = false limits the grant to the rows
-- in representation_grant_applications; with no rows left it is valid for no application.
-- created_by / revoked_by hold the acting admin's person id, which may belong to the system
-- tenant, so they carry no foreign key.
CREATE TABLE representation_grants (
  id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                  uuid NOT NULL,
  agent_person_id            uuid,
  agent_identifier_encrypted text CHECK (agent_identifier_encrypted LIKE 'pv1.%'),
  agent_identifier_index     text,
  agent_identifier_index_key text,
  party_id                   uuid NOT NULL,
  all_applications           boolean NOT NULL,
  valid_from      timestamptz NOT NULL DEFAULT now(),
  valid_to        timestamptz,
  revoked_at      timestamptz,
  revoked_by      uuid,
  created_by      uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CONSTRAINT representation_grants_window CHECK (valid_to IS NULL OR valid_to > valid_from),
  CONSTRAINT representation_grants_revoked_by CHECK (revoked_at IS NOT NULL OR revoked_by IS NULL),
  CONSTRAINT representation_grants_one_agent CHECK (
    (agent_person_id IS NOT NULL
      AND agent_identifier_encrypted IS NULL AND agent_identifier_index IS NULL
      AND agent_identifier_index_key IS NULL)
    OR
    (agent_person_id IS NULL
      AND agent_identifier_encrypted IS NOT NULL AND agent_identifier_index IS NOT NULL
      AND agent_identifier_index_key IS NOT NULL)
  ),
  FOREIGN KEY (tenant_id, agent_person_id) REFERENCES persons (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, party_id) REFERENCES parties (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX representation_grants_agent_idx
  ON representation_grants (tenant_id, agent_person_id) WHERE revoked_at IS NULL;
CREATE INDEX representation_grants_agent_identifier_idx
  ON representation_grants (tenant_id, agent_identifier_index)
  WHERE revoked_at IS NULL AND agent_identifier_index IS NOT NULL;
CREATE INDEX representation_grants_party_idx ON representation_grants (tenant_id, party_id);

CREATE TABLE representation_grant_applications (
  tenant_id      uuid NOT NULL,
  grant_id       uuid NOT NULL,
  application_id uuid NOT NULL,
  PRIMARY KEY (grant_id, application_id),
  FOREIGN KEY (tenant_id, grant_id) REFERENCES representation_grants (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE
);

-- Signing keys (global) -------------------------------------------------------------------------

CREATE TABLE signing_keys (
  kid                   text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_-]{1,128}$'),
  alg                   text NOT NULL CHECK (alg IN ('ES256')),
  -- Cleared when the key is retired: a retired key never signs or verifies again.
  private_jwk_encrypted text CHECK (private_jwk_encrypted LIKE 'pv1.%'),
  public_jwk            jsonb NOT NULL
                        CHECK (jsonb_typeof(public_jwk) = 'object' AND NOT (public_jwk ? 'd')),
  state                 text NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
  created_at            timestamptz NOT NULL DEFAULT now(),
  activated_at          timestamptz,
  retiring_at           timestamptz,
  retired_at            timestamptz,
  CONSTRAINT signing_keys_state_timestamps CHECK (
    CASE state
      WHEN 'next' THEN activated_at IS NULL AND retiring_at IS NULL AND retired_at IS NULL
                       AND private_jwk_encrypted IS NOT NULL
      WHEN 'active' THEN activated_at IS NOT NULL AND retiring_at IS NULL AND retired_at IS NULL
                         AND private_jwk_encrypted IS NOT NULL
      WHEN 'retiring' THEN retiring_at IS NOT NULL AND retired_at IS NULL
                           AND private_jwk_encrypted IS NOT NULL
      WHEN 'retired' THEN retired_at IS NOT NULL AND private_jwk_encrypted IS NULL
    END
  )
);
-- At most one active key and at most one key waiting to become active.
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys ((true)) WHERE state = 'active';
CREATE UNIQUE INDEX signing_keys_one_next ON signing_keys ((true)) WHERE state = 'next';

-- Audit (append-only) ---------------------------------------------------------------------------

-- tenant_id has no foreign key on purpose: audit history outlives deleted tenants, and an
-- append-only table cannot take part in ON DELETE CASCADE. NULL means a platform-level event.
CREATE TABLE audit_events (
  seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id           uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  tenant_id    uuid,
  actor_type   text NOT NULL CHECK (actor_type IN ('person', 'application', 'system')),
  actor_id     text,
  subject_type text,
  subject_id   text,
  action       text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  outcome      text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure')),
  details      jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
  CONSTRAINT audit_events_subject CHECK ((subject_type IS NULL) = (subject_id IS NULL))
);
CREATE INDEX audit_events_tenant_seq_idx ON audit_events (tenant_id, seq DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, seq DESC);
CREATE INDEX audit_events_subject_idx ON audit_events (subject_id, seq DESC) WHERE subject_id IS NOT NULL;
CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, seq DESC) WHERE actor_id IS NOT NULL;

CREATE FUNCTION audit_events_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_reject_change();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_change();

-- oidc-provider storage (adapter in M2) ---------------------------------------------------------

-- One row per oidc-provider model instance (Session, AccessToken, Grant, ...). Providers are per
-- tenant, so every lookup is scoped by tenant_id as well.
CREATE TABLE oidc_payloads (
  tenant_id   uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
  id          text NOT NULL CHECK (length(id) BETWEEN 1 AND 512),
  payload     jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  grant_id    text,
  user_code   text,
  uid         text,
  expires_at  timestamptz,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, kind, id)
);
CREATE INDEX oidc_payloads_grant_idx ON oidc_payloads (tenant_id, grant_id) WHERE grant_id IS NOT NULL;
CREATE INDEX oidc_payloads_uid_idx ON oidc_payloads (tenant_id, kind, uid) WHERE uid IS NOT NULL;
CREATE INDEX oidc_payloads_user_code_idx ON oidc_payloads (tenant_id, kind, user_code)
  WHERE user_code IS NOT NULL;
CREATE INDEX oidc_payloads_expires_idx ON oidc_payloads (expires_at) WHERE expires_at IS NOT NULL;
