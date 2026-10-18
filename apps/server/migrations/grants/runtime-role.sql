-- Privileges of the runtime role (the DATABASE_URL user). Applied by the migration runner, as the
-- schema owner, after every run; idempotent. The runner passes the role name in the
-- `portvakt.runtime_role` setting and refuses to use the owner itself as runtime role.
--
-- The runtime role owns nothing, so it can never ALTER, DROP or disable triggers. It gets plain
-- DML on every table, except:
-- * audit_events: SELECT and INSERT only (append-only even without the trigger),
-- * schema_migrations: SELECT only.
DO $grants$
DECLARE
  runtime_role text := current_setting('portvakt.runtime_role');
  target_schema text := current_schema();
BEGIN
  IF runtime_role = '' OR runtime_role = current_user THEN
    RAISE EXCEPTION 'runtime role must be set and differ from the migration role';
  END IF;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', target_schema, runtime_role);
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', target_schema, runtime_role);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I',
                 target_schema, runtime_role);
  EXECUTE format('REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA %I FROM %I',
                 target_schema, runtime_role);
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I',
                 target_schema, runtime_role);
  EXECUTE format('REVOKE UPDATE, DELETE ON TABLE %I.audit_events FROM %I',
                 target_schema, runtime_role);
  EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON TABLE %I.schema_migrations FROM %I',
                 target_schema, runtime_role);
END
$grants$;
