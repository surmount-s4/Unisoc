#!/usr/bin/env bash
set -euo pipefail

# ULS PostgreSQL bootstrap for Linux
# - Creates/updates app role
# - Creates app database if missing
# - Applies full schema initializer
# - Grants table/sequence/default privileges
#
# Usage:
#   chmod +x init-scripts/setup-postgres-linux.sh
#   ./init-scripts/setup-postgres-linux.sh
#
# Optional Docker mode:
#   DOCKER_CONTAINER=uls-timescaledb ./init-scripts/setup-postgres-linux.sh

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
ADMIN_DB="${ADMIN_DB:-postgres}"
ADMIN_USER="${ADMIN_USER:-postgres}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-postgres}"
APP_DB="${APP_DB:-uls_detection}"
APP_USER="${APP_USER:-uls_user}"
APP_PASSWORD="${APP_PASSWORD:-ChangeThisPassword123!}"
SCHEMA_FILE="${SCHEMA_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/02-init-uls-schema.sql}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-}"

log() {
  printf '[setup-postgres] %s\n' "$*"
}

die() {
  printf '[setup-postgres] ERROR: %s\n' "$*" >&2
  exit 1
}

require_simple_identifier() {
  local value="$1"
  local label="$2"
  if [[ ! "$value" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    die "$label must match ^[A-Za-z_][A-Za-z0-9_]*$ (got: $value)"
  fi
}

escape_sql_literal() {
  # Escape single quotes for SQL string literals
  printf "%s" "$1" | sed "s/'/''/g"
}

psql_query() {
  local db="$1"
  local sql="$2"

  if [[ -n "$DOCKER_CONTAINER" ]]; then
    docker exec -i \
      -e "PGPASSWORD=$ADMIN_PASSWORD" \
      "$DOCKER_CONTAINER" \
      psql -v ON_ERROR_STOP=1 -U "$ADMIN_USER" -d "$db" -c "$sql"
  else
    PGPASSWORD="$ADMIN_PASSWORD" \
      psql -v ON_ERROR_STOP=1 \
      -h "$DB_HOST" \
      -p "$DB_PORT" \
      -U "$ADMIN_USER" \
      -d "$db" \
      -c "$sql"
  fi
}

psql_query_tuples() {
  local db="$1"
  local sql="$2"

  if [[ -n "$DOCKER_CONTAINER" ]]; then
    docker exec -i \
      -e "PGPASSWORD=$ADMIN_PASSWORD" \
      "$DOCKER_CONTAINER" \
      psql -v ON_ERROR_STOP=1 -t -A -U "$ADMIN_USER" -d "$db" -c "$sql"
  else
    PGPASSWORD="$ADMIN_PASSWORD" \
      psql -v ON_ERROR_STOP=1 -t -A \
      -h "$DB_HOST" \
      -p "$DB_PORT" \
      -U "$ADMIN_USER" \
      -d "$db" \
      -c "$sql"
  fi
}

psql_file() {
  local db="$1"
  local file="$2"

  [[ -f "$file" ]] || die "Schema file not found: $file"

  if [[ -n "$DOCKER_CONTAINER" ]]; then
    cat "$file" | docker exec -i \
      -e "PGPASSWORD=$ADMIN_PASSWORD" \
      "$DOCKER_CONTAINER" \
      psql -v ON_ERROR_STOP=1 -U "$ADMIN_USER" -d "$db"
  else
    PGPASSWORD="$ADMIN_PASSWORD" \
      psql -v ON_ERROR_STOP=1 \
      -h "$DB_HOST" \
      -p "$DB_PORT" \
      -U "$ADMIN_USER" \
      -d "$db" \
      -f "$file"
  fi
}

main() {
  require_simple_identifier "$APP_DB" "APP_DB"
  require_simple_identifier "$APP_USER" "APP_USER"

  if [[ -z "$DOCKER_CONTAINER" ]] && ! command -v psql >/dev/null 2>&1; then
    die "psql not found in PATH. Install postgresql-client or use DOCKER_CONTAINER mode."
  fi

  if [[ -n "$DOCKER_CONTAINER" ]] && ! command -v docker >/dev/null 2>&1; then
    die "docker not found in PATH, but DOCKER_CONTAINER was provided."
  fi

  local app_db_literal
  local app_user_literal
  local app_pass_literal
  app_db_literal="$(escape_sql_literal "$APP_DB")"
  app_user_literal="$(escape_sql_literal "$APP_USER")"
  app_pass_literal="$(escape_sql_literal "$APP_PASSWORD")"

  log "Ensuring application role exists: $APP_USER"
  psql_query "$ADMIN_DB" "DO \\$\\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$app_user_literal') THEN ALTER ROLE \"$APP_USER\" WITH LOGIN PASSWORD '$app_pass_literal'; ELSE CREATE ROLE \"$APP_USER\" WITH LOGIN PASSWORD '$app_pass_literal'; END IF; END \\$\\$;"

  log "Ensuring database exists: $APP_DB"
  local exists
  exists="$(psql_query_tuples "$ADMIN_DB" "SELECT 1 FROM pg_database WHERE datname = '$app_db_literal';" | tr -d '[:space:]')"
  if [[ "$exists" != "1" ]]; then
    psql_query "$ADMIN_DB" "CREATE DATABASE \"$APP_DB\" OWNER \"$APP_USER\";"
    log "Created database $APP_DB"
  else
    log "Database already exists: $APP_DB"
  fi

  log "Granting database privileges"
  psql_query "$ADMIN_DB" "GRANT ALL PRIVILEGES ON DATABASE \"$APP_DB\" TO \"$APP_USER\";"

  log "Applying schema file: $SCHEMA_FILE"
  psql_file "$APP_DB" "$SCHEMA_FILE"

  log "Granting schema/table/sequence privileges"
  psql_query "$APP_DB" "GRANT USAGE, CREATE ON SCHEMA public TO \"$APP_USER\";"
  psql_query "$APP_DB" "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"$APP_USER\";"
  psql_query "$APP_DB" "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"$APP_USER\";"
  psql_query "$APP_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO \"$APP_USER\";"
  psql_query "$APP_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO \"$APP_USER\";"

  log "Verifying expected tables"
  psql_query "$APP_DB" "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('security_events','firewall_events','scada_logs','llm_pass_1','correlation_incidents','correlation_windows','bart_event_decisions','process_chain') ORDER BY tablename;"

  log "Setup completed successfully"
  printf '\nUse these environment values for the Go server:\n'
  printf 'POSTGRES_HOST=%s\n' "$DB_HOST"
  printf 'POSTGRES_PORT=%s\n' "$DB_PORT"
  printf 'POSTGRES_USER=%s\n' "$APP_USER"
  printf 'POSTGRES_PASS=%s\n' "$APP_PASSWORD"
  printf 'POSTGRES_DB=%s\n' "$APP_DB"
}

main "$@"
