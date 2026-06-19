#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_ENV_DIR="$ROOT/env/local"
CREDENTIALS_FILE="$LOCAL_ENV_DIR/credentials.txt"

COMPOSE_BASE=(-f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml)

rand() {
  python3 - "$1" <<'PY'
import secrets
import string
import sys

length = int(sys.argv[1])
alphabet = string.ascii_letters + string.digits
print("".join(secrets.choice(alphabet) for _ in range(length)))
PY
}

token_urlsafe() {
  python3 - "$1" <<'PY'
import secrets
import sys

print(secrets.token_urlsafe(int(sys.argv[1])))
PY
}

ensure_dir() {
  mkdir -p "$LOCAL_ENV_DIR"
  chmod 700 "$LOCAL_ENV_DIR"
}

write_once() {
  local file="$1"
  local content="$2"
  if [[ ! -e "$file" ]]; then
    printf "%s\n" "$content" > "$file"
    chmod 600 "$file"
  fi
}

get_value() {
  local file="$1"
  local key="$2"
  if [[ -f "$file" ]]; then
    grep -E "^${key}=" "$file" | tail -n1 | cut -d= -f2- || true
  fi
}

append_missing_key() {
  local file="$1"
  local key="$2"
  local value="$3"
  touch "$file"
  chmod 600 "$file"
  if ! grep -qE "^${key}=" "$file"; then
    printf "%s=%s\n" "$key" "$value" >> "$file"
  fi
}

bootstrap_files() {
  ensure_dir

  if [[ ! -f "$ROOT/.env" ]]; then
    cp "$ROOT/.env.example" "$ROOT/.env"
  fi

  local db_password redis_password redis_cache_password secret_key api_pepper superuser_password mcp_auth
  db_password="$(get_value "$LOCAL_ENV_DIR/netbox.env" DB_PASSWORD)"
  redis_password="$(get_value "$LOCAL_ENV_DIR/netbox.env" REDIS_PASSWORD)"
  redis_cache_password="$(get_value "$LOCAL_ENV_DIR/netbox.env" REDIS_CACHE_PASSWORD)"
  secret_key="$(get_value "$LOCAL_ENV_DIR/netbox.env" SECRET_KEY)"
  api_pepper="$(get_value "$LOCAL_ENV_DIR/netbox.env" API_TOKEN_PEPPER_1)"
  superuser_password="$(get_value "$LOCAL_ENV_DIR/netbox.env" SUPERUSER_PASSWORD)"
  mcp_auth="$(get_value "$LOCAL_ENV_DIR/mcp.env" MCP_AUTH_TOKEN)"

  db_password="${db_password:-$(rand 32)}"
  redis_password="${redis_password:-$(rand 32)}"
  redis_cache_password="${redis_cache_password:-$(rand 32)}"
  secret_key="${secret_key:-$(token_urlsafe 64)}"
  api_pepper="${api_pepper:-$(token_urlsafe 48)}"
  superuser_password="${superuser_password:-$(rand 24)}"
  mcp_auth="${mcp_auth:-$(token_urlsafe 48)}"

  write_once "$LOCAL_ENV_DIR/netbox.env" "API_TOKEN_PEPPER_1=$api_pepper
DB_PASSWORD=$db_password
REDIS_PASSWORD=$redis_password
REDIS_CACHE_PASSWORD=$redis_cache_password
SECRET_KEY=$secret_key
SKIP_SUPERUSER=false
SUPERUSER_NAME=admin
SUPERUSER_EMAIL=admin@example.invalid
SUPERUSER_PASSWORD=$superuser_password"

  write_once "$LOCAL_ENV_DIR/postgres.env" "POSTGRES_PASSWORD=$db_password"
  write_once "$LOCAL_ENV_DIR/redis.env" "REDIS_PASSWORD=$redis_password"
  write_once "$LOCAL_ENV_DIR/redis-cache.env" "REDIS_PASSWORD=$redis_cache_password"
  write_once "$LOCAL_ENV_DIR/mcp.env" "MCP_AUTH_TOKEN=$mcp_auth"

  write_once "$CREDENTIALS_FILE" "NetBox local bootstrap credentials
admin_username=admin
admin_password=$superuser_password
mcp_auth_token=$mcp_auth

Generated for local HITL/testing only. Keep this file out of git."
}

create_mcp_token() {
  ensure_dir
  bootstrap_files

  if grep -qE "^NETBOX_TOKEN=nbt_" "$LOCAL_ENV_DIR/mcp.env"; then
    echo "MCP NetBox token already exists in env/local/mcp.env"
    return 0
  fi

  local key raw full
  key="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(6))
PY
)"
  raw="$(token_urlsafe 32)"
  full="nbt_${key}.${raw}"

  (
    cd "$ROOT"
    docker compose "${COMPOSE_BASE[@]}" exec -T \
      -e MCP_TOKEN_KEY="$key" \
      -e MCP_TOKEN_RAW="$raw" \
      netbox \
      /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell <<'PY'
import os
from users.choices import TokenVersionChoices
from users.models import Token, User

user, _ = User.objects.get_or_create(
    username="mcp-reader",
    defaults={"email": "mcp-reader@example.invalid", "is_superuser": True},
)
user.email = "mcp-reader@example.invalid"
user.is_superuser = True
user.set_unusable_password()
user.save()

Token.objects.create(
    user=user,
    key=os.environ["MCP_TOKEN_KEY"],
    token=os.environ["MCP_TOKEN_RAW"],
    version=TokenVersionChoices.V2,
    write_enabled=False,
    description="NetBox MCP read-only token",
)
PY
  )

  append_missing_key "$LOCAL_ENV_DIR/mcp.env" NETBOX_TOKEN "$full"
  printf "\nmcp_netbox_token=%s\n" "$full" >> "$CREDENTIALS_FILE"
  echo "Created read-only MCP NetBox token in env/local/mcp.env"
}

case "${1:-}" in
  --create-mcp-token)
    create_mcp_token
    ;;
  ""|--init)
    bootstrap_files
    echo "Generated local runtime secrets under env/local/"
    ;;
  *)
    echo "Usage: $0 [--init|--create-mcp-token]" >&2
    exit 2
    ;;
esac
