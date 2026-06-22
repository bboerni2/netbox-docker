# Project Agent Instructions

## NetBox dev deployment context

- Primary dev checkout: `/home/bhauser/projects/netbox-docker-dev-test` in WSL `Ubuntu-24.04`.
- Windows UNC path: `\\wsl.localhost\Ubuntu-24.04\home\bhauser\projects\netbox-docker-dev-test`.
- Current deployment branch observed on 2026-06-22: `codex/sync-safe-netbox-platform`.
- Initial local dev bootstrap commit: `2f26109 Add sync-safe NetBox platform bootstrap`.
- Remotes:
  - `origin`: `https://github.com/bboerni2/netbox-docker.git`
  - `upstream`: `https://github.com/netbox-community/netbox-docker.git`
  - `forgejo`: `http://localhost:3000/bhauser/netbox-docker-dev-test.git`

## How this dev deployment was set up

- The project is a fork of `netbox-community/netbox-docker`, with the sync-safe dev setup added in commit `2f26109`.
- Portainer deployment documentation is in `README-INSTALL.md`.
- Portainer stack type: Repository stack.
- Portainer compose path: `docker-compose.yml`.
- Additional compose files:
  - `docker-compose.runtime.yml`
  - `docker-compose.override.yml`
  - optional MCP: `docker-compose.mcp.yml`
- Portainer relative path volumes: enabled.
- Portainer base path documented as `/var/docker`.
- Runtime secrets are generated with `scripts/bootstrap-secrets.sh --init`.
- Real secrets live only under `env/local/` and `.env`; do not print or commit them.

## Local run commands

Run from `/home/bhauser/projects/netbox-docker-dev-test`:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  up -d --build
```

NetBox is published as `8000:8080` by `docker-compose.override.yml`. If host port
`8000` is already allocated, do not assume NetBox is broken; inspect the holder
with `docker ps` or `ss -ltnp`.

Optional MCP:

```bash
scripts/bootstrap-secrets.sh --create-mcp-token

docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  -f docker-compose.mcp.yml \
  --profile mcp \
  up -d netbox-mcp-server
```

MCP defaults to `127.0.0.1:8081` and points at `http://netbox:8080/` inside the
compose network.

## Plugin/dependency context

- Local plugin path: `local-plugins/netbox-ipam-automation`.
- The plugin is copied into the custom image by `Dockerfile-withplugins`.
- Plugin and community dependencies are installed from `requirements-plugins.txt`.
- Local plugin activation lives in `configuration/zz_local_plugins.py`, loaded after the base config.
- `netbox_diode_plugin` is optional and only enabled when `ENABLE_DIODE`, `DIODE_GRPC_TARGET`, and `NETBOX_TO_DIODE_CLIENT_SECRET` are set.

## Verification commands

Use `docker compose run --rm netbox ...` when host port `8000` is occupied; it
does not bind service ports.

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  run --rm netbox \
  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py check

docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  run --rm netbox \
  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py makemigrations --check --dry-run netbox_ipam_automation
```

## Operating rules

- Treat the WSL checkout as the dev deployment source of truth for this project.
- Do not work in the Windows OneDrive checkout unless explicitly asked; it is not the known lauffaehige dev deployment.
- Prefer evidence from Git, compose files, README-INSTALL.md, and running containers over memory.
- Do not expose secrets from `.env`, `env/local/`, or Portainer.
- Keep changes small and sync-safe with upstream netbox-docker.
