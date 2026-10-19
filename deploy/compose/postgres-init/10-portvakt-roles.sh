#!/bin/sh
# Runs once, when the compose stack's database volume is first initialised (as the superuser).
# Four login roles, none of them a superuser; the long-running services get runtime roles only:
#
# - portvakt              owns the database `portvakt`: migrations (migrate job), audit
#                         retention and the re-wrap; never given to the server;
# - portvakt_app          Portvakt's runtime role: DML only, granted by the migration runner
#                         after every run (apps/server/migrations/grants/runtime-role.sql);
# - portvakt_admin_owner  owns the database `portvakt_admin`: creates the admin portal's session
#                         table (admin-migrate job);
# - portvakt_admin        the admin portal's runtime role: DML on the tables the owner creates
#                         there (default privileges), no access to Portvakt's database.
#
# Passwords come from the environment (deploy/docker-compose.yml), never from this file.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_password="$PORTVAKT_OWNER_DB_PASSWORD" \
  -v app_password="$PORTVAKT_APP_DB_PASSWORD" \
  -v admin_owner_password="$PORTVAKT_ADMIN_OWNER_DB_PASSWORD" \
  -v admin_password="$PORTVAKT_ADMIN_DB_PASSWORD" <<'SQL'
CREATE ROLE portvakt LOGIN PASSWORD :'owner_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE portvakt_app LOGIN PASSWORD :'app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE portvakt_admin_owner LOGIN PASSWORD :'admin_owner_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE portvakt_admin LOGIN PASSWORD :'admin_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE DATABASE portvakt OWNER portvakt;
CREATE DATABASE portvakt_admin OWNER portvakt_admin_owner;

-- Only the roles that need a database may connect to it.
REVOKE ALL ON DATABASE portvakt FROM PUBLIC;
GRANT CONNECT ON DATABASE portvakt TO portvakt_app;
REVOKE ALL ON DATABASE portvakt_admin FROM PUBLIC;
GRANT CONNECT ON DATABASE portvakt_admin TO portvakt_admin;
SQL

# The public schema of a new database is owned by pg_database_owner (Postgres 15+), so the
# owner role creates its tables there; nobody else may create anything in it.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname portvakt \
  -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC"

# The admin portal's runtime role may use what its owner creates (the session table), nothing more.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname portvakt_admin <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO portvakt_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE portvakt_admin_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO portvakt_admin;
SQL
