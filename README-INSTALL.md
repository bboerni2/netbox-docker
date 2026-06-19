# · NetBox-Docker on Portainer

> **Status:** User forked original netbox docker repository 

## 1) Portainer: Repository-Stack vorbereiten

**Portainer UI → Stacks → Add stack → Repository**

- **Git repository**: Unser geforktes `netbox-docker` Repository eintragen.
- **Repository reference**: Branch wählen (z. B. `main`).
- **Compose path**: `docker-compose.yml`
- **Additional paths +Add file**:
  - `docker-compose.runtime.yml`
  - `docker-compose.override.yml`
  - optional: `docker-compose.mcp.yml`
- **Enable relative path volumes**: aktivieren.
- **Base path**: `/var/docker` als relative path setzen.

Vor dem ersten Deploy lokal oder in WSL die Runtime-Secrets erzeugen:

```bash
scripts/bootstrap-secrets.sh --init
```

Das Script schreibt echte Secrets nur nach `env/local/` und `.env`; beide Pfade
sind ignoriert. Die getrackten `env/*.env` bleiben absichtlich harmlos.

---

## 2) NetBox-Plugins

- `netbox-ipam-automation` – Lokales Plugin für IPAM-Automation, Scheduling und spätere Proxmox-Anbindung.
- `netbox-topology-views` – Interaktive L2/L3-Topologieansicht.
- `netbox-lifecycle` – Lifecycle-/EoX-Verwaltung für Geräte.
- `netbox-floorplan-plugin` – Visualisierung von Racks/Assets in 2D-Gebäudeplänen.
- `pynetbox` – Python-Client für die NetBox-API.
- `netbox-lists` – Flexible Listen-/Tabellenansichten für Objekte.
- `netbox-inventory` – Inventar- und Asset-Verwaltung in NetBox.
- `netbox-reorder-rack` – Intuitive Drag-and-Drop Reorganisation von Racks.
- `netboxlabs-diode-netbox-plugin` – Optional, standardmäßig deaktiviert.

**Temporär deaktiviert da Versionskonflikt (auskommentiert in `requirements-plugins.txt`):**
- `netbox-proxbox` (≥0.0.6b2) – Integration von Proxmox Clustern in NetBox.
- `proxbox-api` (≥0.0.2) – API-Helper für Proxbox.


### 2.1 Plugin-Installation mit netbox-docker
netbox-docker unterstützt eine separate **`requirements-plugins.txt`**, die beim Image-Build installiert wird.

### 2.2 `requirements-plugins.txt`
```text
netbox-topology-views==4.5.1
netbox-lifecycle==1.1.9
netbox-floorplan-plugin==0.9.2
pynetbox==7.8.0
netbox-initializers==4.6.0
netbox-lists==4.0.4
netbox-inventory==2.6.0
netbox-reorder-rack==1.1.4
# netbox-proxbox>=0.0.6b2
# proxbox-api>=0.0.2
```

### 2.3 Plugin-Konfiguration

Lokale Plugin-Konfiguration liegt in `configuration/zz_local_plugins.py`. Diese
Datei wird nach der upstream-nahen Basiskonfiguration geladen und reduziert
Fork-Sync-Konflikte.

Diode ist optional und bleibt standardmäßig aus. Aktivieren nur mit:

- `ENABLE_DIODE=true`
- `DIODE_GRPC_TARGET=grpc://<dein-diode-server:port>/diode`
- `NETBOX_TO_DIODE_CLIENT_SECRET=<set-secret>`

## 3) Stack deploy

### 3.1 Starten

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  up -d --build
```

Der Admin-User wird über `env/local/netbox.env` erzeugt. Das Passwort steht
lokal in `env/local/credentials.txt`.

### 3.2 MCP Token erzeugen

Nach dem ersten erfolgreichen Start:

```bash
scripts/bootstrap-secrets.sh --create-mcp-token
```

Danach MCP optional starten:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.runtime.yml \
  -f docker-compose.override.yml \
  -f docker-compose.mcp.yml \
  --profile mcp \
  up -d netbox-mcp-server
```

### 3.3 Defaults initialisieren

Der hinterlegte default value stack für netbox_initializers plugin

**Command**
```bash
docker exec -it netbox-docker-netbox-1   /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py   load_initializer_data --path /etc/netbox/config/initializers/extras
```

## 4) Optionale Zusatzprofile

- `proxbox-api`: nur mit Compose-Profil `proxbox`
- `netbox-mcp-server`: nur mit `-f docker-compose.mcp.yml --profile mcp`; nutzt `env/local/mcp.env`

