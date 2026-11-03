#!/bin/sh
# Create the LLM gateway's OWN database + role inside the division's EXISTING Postgres
# (the one backing OpenFGA), so the gateway adds no second Postgres. Idempotent: safe on
# every start; re-applies the role password so a rotated LITELLM_DB_PASSWORD takes effect.
#
# Shared by the Compose division stack (service llm-gateway-db-init) and the k8s component
# (init container of deploy/llm-gateway). Runs as the division's Postgres superuser
# (PGHOST/PGUSER/PGPASSWORD/PGDATABASE from the environment); the gateway itself connects
# as the unprivileged `litellm` role, which owns only the `litellm` database.
set -eu
: "${LITELLM_DB_PASSWORD:?LITELLM_DB_PASSWORD is required}"

until pg_isready -q; do echo "waiting for postgres at ${PGHOST:-?}"; sleep 2; done

psql -v ON_ERROR_STOP=1 -v pw="$LITELLM_DB_PASSWORD" <<'SQL'
SELECT 'CREATE ROLE litellm LOGIN'
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'litellm')\gexec
ALTER ROLE litellm WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'pw';
SELECT 'CREATE DATABASE litellm OWNER litellm'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'litellm')\gexec
REVOKE ALL ON DATABASE litellm FROM PUBLIC;
-- Defence in depth: the gateway role may not even connect to the authorization store.
REVOKE CONNECT ON DATABASE openfga FROM PUBLIC;
SQL
echo "llm-gateway database ready"
