# Project Agent Instructions

## Source of truth

- Runnable dev checkout: `/home/bhauser/projects/netbox-docker-dev-test` in WSL `Ubuntu-24.04`.
- Windows path to the same checkout: `\\wsl.localhost\Ubuntu-24.04\home\bhauser\projects\netbox-docker-dev-test`.
- The Windows OneDrive checkout is not the runnable deployment. Do not edit or start a second stack there unless explicitly requested.
- `/home/ubuntu/netbox-docker` is not this deployment. Do not copy configuration there.
- Verify mutable facts with Git, Compose, `README-INSTALL.md`, and running containers before relying on this file.

## Git and deployment chain

- Fork: `bboerni2/netbox-docker`; upstream: `netbox-community/netbox-docker`.
- Remotes:
  - `origin`: `https://github.com/bboerni2/netbox-docker.git`
  - `upstream`: `https://github.com/netbox-community/netbox-docker.git`
  - `forgejo`: `http://localhost:3000/bhauser/netbox-docker-dev-test.git`
- Active dev branch verified 2026-06-23: `codex/sync-safe-netbox-platform`.
- Initial sync-safe bootstrap: `2f26109`. Use `git log -1` for the current verified head; do not persist a moving commit as project truth.
- Default publication target is `origin/codex/sync-safe-netbox-platform`. Do not push to `upstream` or `forgejo` unless requested.
- WSL Git may lack GitHub credentials. The tested fallback uses Windows Git Credential Manager:

```powershell
& 'C:\Users\b.hauser\AppData\Local\Programs\Git\cmd\git.exe' `
  -c safe.directory='//wsl.localhost/Ubuntu-24.04/home/bhauser/projects/netbox-docker-dev-test' `
  -C '\\wsl.localhost\Ubuntu-24.04\home\bhauser\projects\netbox-docker-dev-test' `
  push origin codex/sync-safe-netbox-platform
```

- Portainer is documented in `README-INSTALL.md` as a Repository stack using `docker-compose.yml`, plus `docker-compose.runtime.yml` and `docker-compose.override.yml`; relative path volumes are enabled with base path `/var/docker`.
- The exact branch and automatic redeploy behavior configured in Portainer must be verified in Portainer. A Git push does not prove that Portainer redeployed.
- Local WSL Compose is independent of Portainer and is the verification target for plugin changes.

## Local runtime

Run from the WSL checkout:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  up -d --build
```

- NetBox UI: `http://127.0.0.1:8000/` (`8000:8080`).
- Custom image: `netbox-withplugins:local`, built by `Dockerfile-withplugins`.
- Base image verified 2026-06-23: `netboxcommunity/netbox:v4.6-5.0.1`, carrying NetBox `v4.6.3`.
- Required healthy services: `netbox`, `netbox-worker`, `postgres`, `redis`, `redis-cache`. `netbox-housekeeping` runs without a healthcheck.
- Plugin source is copied into the image, not live-mounted. After code changes, rebuild the stack; a container restart alone does not install changed plugin code.
- If port 8000 fails, inspect `docker compose ps`, `docker ps`, and the port holder before starting another stack.
- Unauthenticated `/api/status/` can return 403 under current permissions; that is not a health failure.

Useful operations:

```bash
docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml ps
docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml logs --tail=200 netbox netbox-worker
docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml down
```

## Secrets and access

- Generate local secrets with `scripts/bootstrap-secrets.sh --init`.
- Real secrets exist only in `.env` and `env/local/`; both are ignored by Git. Never print, paste, copy to tracked files, or commit them.
- Local admin bootstrap data is in `env/local/netbox.env`; the generated password is in `env/local/credentials.txt`.
- MCP credentials are in `env/local/mcp.env`. Refer to the path only; never expose the token.
- Git credentials are not stored in this repository. HTTPS push normally uses Windows Git Credential Manager.

## Optional NetBox MCP

- MCP Compose file: `docker-compose.mcp.yml`; image default: `netboxlabs/netbox-mcp-server:1.2.1`.
- Local endpoint: `127.0.0.1:8081`; container target: `http://netbox:8080/`.
- No MCP container was present when verified on 2026-06-23. The main dev deployment does not require it.

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

- Start MCP only after NetBox is healthy. If discovery previously failed during startup, restart only `netbox-mcp-server` and inspect its logs without displaying tokens.

## Plugin architecture

- Plugin: `local-plugins/netbox-ipam-automation`.
- Activation: `configuration/zz_local_plugins.py`, loaded after base configuration.
- Dependencies: `requirements-plugins.txt`; local plugin is installed by `Dockerfile-withplugins`.
- `Dockerfile-withplugins` also installs `nmap` in the custom NetBox image.
- `configuration/initializers/extras/custom_fields.yml` is the 23-row mapping generated from `/mnt/c/Users/b.hauser/Downloads/netbox_custom fields.csv`; `MacAddress` targets `dcim.models.Device` and `ipam.models.IPAddress`.
- Core implementation: models/forms/jobs/services plus native NetBox tables, views, API serializers, migrations, and tests.
- Use native NetBox 4.6 UI patterns. Do not add React, Vue, CSS frameworks, icon libraries, or a separate dashboard.
- Scanner v2 uses `nmap` XML host discovery from the NetBox worker. It does not use the old Semaphore script, API tokens, or Python nmap wrappers.
- Discovery modes are `routed` (default), `local_l2`, and `auto` (safe fallback to routed without reliable interface evidence). Hostname enrichment is separate from activity evidence.
- Current Docker worker runs nmap without root/raw-socket privileges, so routed scans may log `Warning: You are not root -- using TCP pingscan rather than ICMP`. This is expected in the dev container and must be re-tested on any future scanner VM/runtime with full scan privileges or `CAP_NET_RAW`.

## IPAM automation policies

- RangePolicy targets a NetBox `IPRange`, not a Prefix. Scan start/end are plain IPv4 addresses; blank means the first/last address of the selected range.
- Network and broadcast addresses are included in the range. HITL initialization creates missing network/broadcast IPAddress records as `reserved`; gateway is mandatory human input and is created as `gateway`.
- Initialization never overwrites an existing IPAddress or status.
- Automated scan changes are allowed only for IPAddress statuses `active`, `free`, and `deprecated`.
- `reserved`, `gateway`, `dhcp`, and any unknown/custom status are protected and counted as `skipped_protected`.
- Lifecycle defaults: unseen active IP becomes `deprecated` after 2 days; deprecated remains unavailable for 14 days before becoming `free`.
- `GlobalSettings.enabled` is the scheduler master switch.
- `scan_all_active_ranges` implicitly scans active NetBox IPRanges without a RangePolicy at `default_scan_interval_minutes`. It does not create policy rows.
- Any RangePolicy for an IPRange overrides implicit scanning. A disabled policy explicitly excludes that range; enabled policies use Global default, Interval, or Cron as configured.
- Only active IPRanges are enrolled implicitly. Explicit policies may target other IPRange statuses.
- Scheduler prevents duplicate runs for the same policy/range and respects `max_concurrent_scans`.
- Before counting concurrency, the scheduler marks orphaned `queued`/`running` ScanRuns as `failed` when their Core/RQ job is terminal or missing beyond `RQ_DEFAULT_TIMEOUT`.
- At worker startup, the plugin repairs only its own periodic scheduler entry when NetBox still says `scheduled` but the RQ job is missing or failed. It must not clean unrelated NetBox jobs.
- With `max_concurrent_scans=1`, due explicit policies run first and implicit ranges then proceed one at a time; do not expect every active range to appear immediately.
- `max_tasks_per_template` retains the newest terminal ScanRuns per effective IPRange/NetID (default 100). Explicit and implicit runs share the limit; active runs are never pruned.
- Retention runs in the existing minutely scheduler even when scan scheduling is disabled. Pruning a ScanRun also removes its related Core Job/logs; PostgreSQL task IDs remain monotonic.
- ScanRun history stores target range, task state, counters, summary, errors, hostnames, MAC observations, discovery mode, and dry-run plans in native NetBox views.

Last observed mutable settings on 2026-06-23 (verify before acting): scheduler enabled, scan-all-active enabled, interval 55 minutes, retention 100 tasks per NetID, deprecation 2/14 days.

## NetBox status and import traps

- `configuration/extra.py` extends `ipam.IPAddress.status` with: `free`, `deprecated`, `reserved`, `dhcp`, `active`, `gateway`.
- These choices apply to IPAddress only. NetBox IPRange status remains `active`, `reserved`, or `deprecated`; `/ipam/ip-ranges/add/` will not show gateway/free/DHCP.
- NetBox exports are not reusable import templates. Export headers such as `ID`, `Size`, `usage`, `Utilization`, `Created`, and `Last updated` must not be blindly re-imported.
- Import headers are case-sensitive and use model field names. Status values use lowercase internal slugs (`active`, not `Active`).
- For new IPRange imports, normally omit `id`. Global VRF is blank, not the text `Global`. Referenced roles, tenants, owners, and tag slugs must exist before import or be omitted.
- Before importing, validate against the live import form and keep a separate cleaned CSV; never overwrite the source export.

## Verification gate

After plugin changes, rebuild first, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml exec -T netbox \
  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py check

docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml exec -T netbox \
  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py makemigrations --check --dry-run netbox_ipam_automation

docker compose -f docker-compose.yml -f docker-compose.runtime.yml -f docker-compose.override.yml exec -T netbox \
  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py test netbox_ipam_automation.tests --keepdb --verbosity 1
```

- Verify relevant authenticated plugin routes return 200 and the expected field/label appears in rendered HTML.
- Verify all required services are healthy and `nmap` discovery from `netbox-worker` to the intended target network before claiming real-network scan readiness.
- Run `git diff --check`; preserve unrelated user changes; commit and push only after checks pass.

## Operating rules

- Load the NetBox hub skill, then the relevant specialist skill; retrieve current NetBox 4.6 docs/source when APIs are version-sensitive.
- Use Ponytail full mode: smallest correct native change, no speculative dependencies or abstractions.
- Treat infrastructure, configuration, and inventories as evidence. If this file conflicts with the running system, verify and update this file in the same change.
- Never expose secrets, start a parallel Windows stack, mutate protected IP statuses, or claim Portainer/MCP state without direct evidence.
