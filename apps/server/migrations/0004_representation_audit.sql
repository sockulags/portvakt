-- Representation, step-up and audit retention (M4). See docs/plan.md ("Milestones", M4),
-- docs/claims.md (`rep`) and CLAUDE.md.
--
-- * applications.representation_mode: whether an application offers the representation chooser
--   (`none`: never, no `rep`; `optional`: the person may act for themselves or a party;
--   `required`: the person must act for a party).
-- * tenants.representation_sources: the representation sources a tenant uses (v1: the internal
--   register only; Bolagsverket or Mina ombud are later sources).
-- * parties.protected_identity: an administrator marks a person party as protected (skyddad
--   identitet); its name is then never issued in `rep`, and the chooser shows no identifier.
-- * login_methods.pin_login_hint: an OIDC upstream that accepts the personal identity number as
--   `login_hint` gets it for a step-up of a known person (off by default).
-- * login_methods.trust_pin_for_representation: a login through this method may use
--   representation grants made out to the personal identity number it asserted (off by
--   default; the repository allows it only for methods asserting at least loa3 that map a pin).
-- * audit_events retention: the append-only trigger now lets one path delete: a role owning the
--   table, with a transaction-local cutoff at least 90 days in the past, deleting only older rows.
--   The owner-only function audit_events_prune (npm run audit:prune) is that path. The runtime
--   role has neither DELETE on the table nor EXECUTE on the function; a plain DELETE by the owner
--   is refused, and so is one with a cutoff younger than 90 days. (The owner can always drop the
--   trigger: the guarantee is against the runtime role and against accidents.)

ALTER TABLE applications
  ADD COLUMN representation_mode text NOT NULL DEFAULT 'none'
    CHECK (representation_mode IN ('none', 'optional', 'required'));

ALTER TABLE tenants
  ADD COLUMN representation_sources text[] NOT NULL DEFAULT ARRAY['internal']::text[]
    CHECK (representation_sources <@ ARRAY['internal']::text[]);

ALTER TABLE parties ADD COLUMN protected_identity boolean NOT NULL DEFAULT false;

ALTER TABLE login_methods
  ADD COLUMN pin_login_hint boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT login_methods_pin_login_hint_oidc CHECK (NOT pin_login_hint OR protocol = 'oidc'),
  ADD COLUMN trust_pin_for_representation boolean NOT NULL DEFAULT false;

-- Retention deletes by age.
CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at);

-- Replaces M1's trigger function (the triggers stay bound to it): UPDATE and TRUNCATE are always
-- rejected; DELETE only for rows older than the cutoff that audit_events_prune sets for its own
-- transaction, only when that cutoff is at least 90 days in the past, and only when the deleting
-- role owns the table. A custom setting can be set by any role, which is why the ownership check
-- is part of the condition (the runtime role also has no DELETE privilege at all).
CREATE OR REPLACE FUNCTION audit_events_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  prune_before text := current_setting('portvakt.audit_prune_before', true);
BEGIN
  IF TG_OP = 'DELETE'
     AND prune_before IS NOT NULL AND prune_before <> ''
     AND pg_has_role(current_user,
                     (SELECT c.relowner FROM pg_class c WHERE c.oid = TG_RELID), 'USAGE')
     AND prune_before::timestamptz <= now() - interval '90 days'
     AND OLD.occurred_at < prune_before::timestamptz THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_events is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- Deletes at most batch_size events that occurred before cutoff (never less than 90 days ago)
-- and returns how many. Run it once per transaction; the cutoff setting is transaction-local.
CREATE FUNCTION audit_events_prune(cutoff timestamptz, batch_size integer) RETURNS integer
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
  deleted integer;
BEGIN
  IF cutoff IS NULL OR cutoff > now() - interval '90 days' THEN
    RAISE EXCEPTION 'audit retention must keep at least 90 days'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF batch_size IS NULL OR batch_size < 1 OR batch_size > 100000 THEN
    RAISE EXCEPTION 'batch_size must be between 1 and 100000'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  PERFORM set_config('portvakt.audit_prune_before', cutoff::text, true);
  WITH doomed AS (
    SELECT seq FROM audit_events WHERE occurred_at < cutoff ORDER BY seq LIMIT batch_size
  )
  DELETE FROM audit_events a USING doomed WHERE a.seq = doomed.seq;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  PERFORM set_config('portvakt.audit_prune_before', '', true);
  RETURN deleted;
END;
$$;
REVOKE ALL ON FUNCTION audit_events_prune(timestamptz, integer) FROM PUBLIC;
