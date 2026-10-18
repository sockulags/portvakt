-- Runtime role for development and tests. The app connects as portvakt_app (DATABASE_URL,
-- TEST_DATABASE_URL); migrations run as the owner portvakt (MIGRATION_DATABASE_URL,
-- TEST_MIGRATION_DATABASE_URL), which grants this role its privileges after every run.
-- Roles are cluster-wide, so this covers both portvakt and portvakt_test. Idempotent: CI and old
-- dev volumes run it by hand (see CLAUDE.md).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'portvakt_app') THEN
    CREATE ROLE portvakt_app LOGIN PASSWORD 'portvakt_app'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$;
