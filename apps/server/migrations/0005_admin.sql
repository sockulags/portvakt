-- Administration (M6). See docs/plan.md ("Admin"), docs/admin-api.md and CLAUDE.md.
--
-- * pending_role_assignments / pending_attribute_assignments: assignments made before the person
--   has signed in. The target is either an identity reference (login method, upstream subject)
--   or a personal identity number (SecretBox envelope with context
--   `pending_role_assignment:<id>:pin` / `pending_attribute_assignment:<id>:pin`, plus a blind
--   index for the lookup). At the login that creates or refreshes a matching identity they are
--   turned into ordinary role or attribute assignments of that person and deleted, in the JIT
--   transaction. A pin target matches only a login through a method trusted for personal
--   identity numbers (`trust_pin_for_representation`: at least loa3, maps the number) and only
--   the number that login asserted.
-- * created_by holds the acting administrator's person id, which may belong to the system tenant,
--   so it carries no foreign key (as representation_grants.created_by).

CREATE TABLE pending_role_assignments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL,
  application_id  uuid NOT NULL,
  role            text NOT NULL,
  login_method_id uuid,
  subject         text CHECK (length(subject) BETWEEN 1 AND 255),
  pin_encrypted   text CHECK (pin_encrypted LIKE 'pv1.%'),
  pin_index       text,
  pin_index_key   text,
  created_by      uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CONSTRAINT pending_role_assignments_target CHECK (
    (login_method_id IS NOT NULL AND subject IS NOT NULL
      AND pin_encrypted IS NULL AND pin_index IS NULL AND pin_index_key IS NULL)
    OR
    (login_method_id IS NULL AND subject IS NULL
      AND pin_encrypted IS NOT NULL AND pin_index IS NOT NULL AND pin_index_key IS NOT NULL)
  ),
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE,
  FOREIGN KEY (application_id, role)
    REFERENCES application_roles (application_id, role) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, login_method_id) REFERENCES login_methods (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX pending_role_assignments_subject_key
  ON pending_role_assignments (tenant_id, login_method_id, subject, application_id, role)
  WHERE login_method_id IS NOT NULL;
CREATE UNIQUE INDEX pending_role_assignments_pin_key
  ON pending_role_assignments (tenant_id, pin_index, application_id, role)
  WHERE pin_index IS NOT NULL;

CREATE TABLE pending_attribute_assignments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL,
  application_id  uuid NOT NULL,
  key             text NOT NULL,
  value           text NOT NULL CHECK (length(value) <= 2000),
  login_method_id uuid,
  subject         text CHECK (length(subject) BETWEEN 1 AND 255),
  pin_encrypted   text CHECK (pin_encrypted LIKE 'pv1.%'),
  pin_index       text,
  pin_index_key   text,
  created_by      uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CONSTRAINT pending_attribute_assignments_target CHECK (
    (login_method_id IS NOT NULL AND subject IS NOT NULL
      AND pin_encrypted IS NULL AND pin_index IS NULL AND pin_index_key IS NULL)
    OR
    (login_method_id IS NULL AND subject IS NULL
      AND pin_encrypted IS NOT NULL AND pin_index IS NOT NULL AND pin_index_key IS NOT NULL)
  ),
  FOREIGN KEY (tenant_id, application_id)
    REFERENCES tenant_applications (tenant_id, application_id) ON DELETE CASCADE,
  FOREIGN KEY (application_id, key)
    REFERENCES application_attribute_keys (application_id, key) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, login_method_id) REFERENCES login_methods (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX pending_attribute_assignments_subject_key
  ON pending_attribute_assignments (tenant_id, login_method_id, subject, application_id, key)
  WHERE login_method_id IS NOT NULL;
CREATE UNIQUE INDEX pending_attribute_assignments_pin_key
  ON pending_attribute_assignments (tenant_id, pin_index, application_id, key)
  WHERE pin_index IS NOT NULL;
CREATE TRIGGER pending_attribute_assignments_updated_at BEFORE UPDATE ON pending_attribute_assignments
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Admin person search: name and email prefixes of a tenant's identities.
CREATE INDEX identities_name_prefix_idx
  ON identities (tenant_id, lower(attributes ->> 'name') text_pattern_ops);
CREATE INDEX identities_email_prefix_idx
  ON identities (tenant_id, lower(attributes ->> 'email') text_pattern_ops);

-- Dashboard: logins per tenant and period.
CREATE INDEX audit_events_tenant_action_time_idx ON audit_events (tenant_id, action, occurred_at);
