#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
ENV_EXAMPLE="${ROOT_DIR}/.env.example"
SETUP_PG_SCRIPT="${SCRIPT_DIR}/setup-postgres-linux.sh"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

SKIP_PREREQS=false
INFRA_ONLY=false
NO_BUILD=false

log() {
  printf '[bootstrap] %s\n' "$*"
}

die() {
  printf '[bootstrap] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo bash init-scripts/bootstrap-ubuntu.sh [options]

Bootstraps a fresh Ubuntu VM for ULS detection server:
1) Installs Docker Engine + Docker Compose plugin (unless skipped)
2) Creates .env from .env.example (first run only)
3) Starts TimescaleDB + RabbitMQ (+ server/receiver unless infra-only)
4) Applies DB schema bootstrap
5) Prints health and verification hints

Options:
  --skip-prereqs   Do not install Docker/prerequisites
  --infra-only     Start only timescaledb and rabbitmq containers
  --no-build       Skip docker compose --build
  -h, --help       Show this help
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      --skip-prereqs)
        SKIP_PREREQS=true
        shift
        ;;
      --infra-only)
        INFRA_ONLY=true
        shift
        ;;
      --no-build)
        NO_BUILD=true
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    die "Run as root or with sudo (example: sudo bash init-scripts/bootstrap-ubuntu.sh)."
  fi
}

check_ubuntu() {
  if [[ ! -r /etc/os-release ]]; then
    die "Cannot detect OS (/etc/os-release missing)."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "This bootstrap script currently supports Ubuntu only (detected: ${ID:-unknown})."
  fi
}

install_prerequisites() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker and Docker Compose already available."
    systemctl enable --now docker >/dev/null 2>&1 || true
    return
  fi

  log "Installing Docker Engine and Docker Compose plugin..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release openssl git

  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /tmp/docker.gpg
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    rm -f /tmp/docker.gpg
  fi

  local arch codename
  arch="$(dpkg --print-architecture)"
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable
EOF

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker

  log "Docker installation complete."
}

random_secret() {
  openssl rand -hex 16
}

set_env_value() {
  local key="$1"
  local value="$2"

  if grep -q "^${key}=" "${ENV_FILE}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${ENV_FILE}"
  fi
}

bootstrap_env() {
  [[ -f "${ENV_EXAMPLE}" ]] || die "Missing ${ENV_EXAMPLE}"

  if [[ -f "${ENV_FILE}" ]]; then
    log ".env already exists; preserving existing values."
    return
  fi

  cp "${ENV_EXAMPLE}" "${ENV_FILE}"

  local pg_pass rmq_pass
  pg_pass="$(random_secret)"
  rmq_pass="$(random_secret)"

  set_env_value "POSTGRES_USER" "admin"
  set_env_value "POSTGRES_PASSWORD" "${pg_pass}"
  set_env_value "POSTGRES_PASS" "${pg_pass}"
  set_env_value "POSTGRES_DB" "uls_detection"

  set_env_value "RABBITMQ_USER" "admin"
  set_env_value "RABBITMQ_PASSWORD" "${rmq_pass}"
  set_env_value "RABBITMQ_PASS" "${rmq_pass}"

  # Safe ingest-first defaults for fresh VM startup.
  set_env_value "OLLAMA_URL" ""
  set_env_value "LLM_PASS_ENABLED" "false"
  set_env_value "CORRELATION_ENGINE_V2_ENABLED" "false"

  chmod 600 "${ENV_FILE}"

  log "Created ${ENV_FILE} with generated credentials. Save these values:"
  log "  POSTGRES_USER=admin"
  log "  POSTGRES_PASSWORD=${pg_pass}"
  log "  RABBITMQ_USER=admin"
  log "  RABBITMQ_PASSWORD=${rmq_pass}"
}

load_env() {
  [[ -f "${ENV_FILE}" ]] || die "Missing ${ENV_FILE}"

  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a

  : "${POSTGRES_USER:?POSTGRES_USER missing in .env}"
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD missing in .env}"
  : "${RABBITMQ_USER:?RABBITMQ_USER missing in .env}"
  : "${RABBITMQ_PASSWORD:?RABBITMQ_PASSWORD missing in .env}"

  POSTGRES_DB="${POSTGRES_DB:-uls_detection}"
  POSTGRES_PASS="${POSTGRES_PASS:-${POSTGRES_PASSWORD}}"
}

compose_up() {
  local services=(timescaledb rabbitmq)
  if [[ "${INFRA_ONLY}" == false ]]; then
    services+=(uls-server syslog-receiver)
  fi

  local cmd=(docker compose -f "${COMPOSE_FILE}" up -d)
  if [[ "${NO_BUILD}" == false && "${INFRA_ONLY}" == false ]]; then
    cmd+=(--build)
  fi
  cmd+=("${services[@]}")

  log "Starting containers: ${services[*]}"
  (cd "${ROOT_DIR}" && "${cmd[@]}")
}

wait_for_container() {
  local container="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))

  while ((SECONDS < deadline)); do
    local status
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}" 2>/dev/null || true)"

    if [[ "${status}" == "healthy" || "${status}" == "running" ]]; then
      log "${container} is ${status}."
      return 0
    fi

    sleep 2
  done

  docker ps -a --filter "name=${container}" || true
  die "Timed out waiting for ${container} to become healthy/running."
}

bootstrap_schema() {
  [[ -f "${SETUP_PG_SCRIPT}" ]] || die "Missing ${SETUP_PG_SCRIPT}"

  log "Applying PostgreSQL schema bootstrap..."
  ADMIN_DB="postgres" \
  ADMIN_USER="${POSTGRES_USER}" \
  ADMIN_PASSWORD="${POSTGRES_PASSWORD}" \
  APP_DB="${POSTGRES_DB}" \
  APP_USER="${POSTGRES_USER}" \
  APP_PASSWORD="${POSTGRES_PASS}" \
  DOCKER_CONTAINER="uls-timescaledb" \
    bash "${SETUP_PG_SCRIPT}"
}

verify_database_tables() {
  local table_count
  table_count="$(docker exec uls-timescaledb psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -A -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('security_events','firewall_events','scada_logs','llm_pass_1','correlation_incidents','correlation_windows','bart_event_decisions','process_chain');" | tr -d '[:space:]')"

  if [[ -z "${table_count}" || "${table_count}" -lt 8 ]]; then
    die "Expected 8 core tables, found ${table_count:-0}."
  fi

  log "Verified core database tables (${table_count}/8)."
}

print_summary() {
  log "Bootstrap completed successfully."
  printf '\n'
  printf 'Quick checks:\n'
  printf '  docker ps\n'
  printf '  docker exec uls-timescaledb psql -U %s -d %s -c "\\dt"\n' "${POSTGRES_USER}" "${POSTGRES_DB}"
  printf '  docker exec uls-rabbitmq rabbitmqctl list_queues name messages consumers\n'

  if [[ "${INFRA_ONLY}" == false ]]; then
    printf '  docker logs --tail 50 uls-server\n'
    printf '  docker logs --tail 50 uls-syslog-receiver\n'
  fi

  printf '\nSource-side mapping:\n'
  printf '  Windows agent queue: security_events\n'
  printf '  Syslog/firewall queue: firewall_events\n'
  printf '  SCADA queue: scada_logs\n'
}

main() {
  parse_args "$@"
  require_root
  check_ubuntu

  if [[ "${SKIP_PREREQS}" == false ]]; then
    install_prerequisites
  else
    log "Skipping prerequisite installation (--skip-prereqs)."
  fi

  bootstrap_env
  load_env
  compose_up

  wait_for_container "uls-timescaledb" 180
  wait_for_container "uls-rabbitmq" 180

  bootstrap_schema
  verify_database_tables

  if [[ "${INFRA_ONLY}" == false ]]; then
    wait_for_container "uls-server" 180
    wait_for_container "uls-syslog-receiver" 180
  fi

  print_summary
}

main "$@"
