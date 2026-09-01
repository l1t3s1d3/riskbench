#!/usr/bin/env bash
# =============================================================================
# PLI Security Platform — Single-VM Deployment Script
#
# Deploys RiskDesk + the DevSecOps pipeline on a single Ubuntu VM.
#
# What it does:
#   1. Installs system dependencies (Docker, Python, Cloudflared)
#   2. Creates a service user and directory structure
#   3. Deploys RiskDesk as a systemd service (port 8080)
#   4. Deploys the DevSecOps pipeline via Docker Compose
#   5. Generates strong random secrets for every credential
#   6. Configures UFW firewall
#   7. Sets up nightly housekeeping (expired decisions, session cleanup)
#   8. Wires RiskDesk to the pipeline with an API token
#
# Prerequisites:
#   - Ubuntu 22.04 or 24.04 (amd64)
#   - Root or sudo access
#   - Internet access for package downloads
#   - Minimum 4 CPU cores, 8 GB RAM, 40 GB disk (B2ms on Azure works)
#   - DNS name or IP address for the server
#
# Usage:
#   chmod +x deploy.sh
#   sudo ./deploy.sh
#
# After deployment:
#   - RiskDesk:     http://<host>:8080
#   - Gitea:        http://<host>:3000
#   - Woodpecker:   http://<host>:8000
#   - SonarQube:    http://<host>:9090
#   - DefectDojo:   http://<host>:8880
#   - ZAP API:      http://<host>:8090
#
# First-time setup (manual, after script completes):
#   1. Open Gitea, create an admin account
#   2. Create OAuth app → copy Client ID + Secret
#   3. Run: sudo /opt/pli-security/scripts/configure-woodpecker.sh <client_id> <client_secret>
#   4. Open Woodpecker, log in via Gitea
# =============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------

INSTALL_DIR="/opt/pli-security"
SERVICE_USER="plisec"
RISKDESK_PORT=8080
PYTHON_VERSION="python3"

# Detect the host's primary IP for callback URLs
HOST_IP=$(hostname -I | awk '{print $1}')
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || echo "$HOST_IP")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight checks -------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)."
    exit 1
fi

if ! grep -qiE 'ubuntu' /etc/os-release 2>/dev/null; then
    warn "This script is designed for Ubuntu. Other distros may need adjustments."
fi

TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM_MB" -lt 6000 ]; then
    warn "This VM has ${TOTAL_RAM_MB}MB RAM. The full stack needs ~8GB."
    warn "SonarQube alone wants 4GB. Consider a B2ms (8GB) or larger."
    read -rp "Continue anyway? [y/N] " yn
    [ "$yn" = "y" ] || [ "$yn" = "Y" ] || exit 1
fi

log "Deploying PLI Security Platform to ${INSTALL_DIR}"
log "Host IP: ${HOST_IP} | FQDN: ${HOSTNAME_FQDN}"
log "RAM: ${TOTAL_RAM_MB}MB | Cores: $(nproc)"

# --- Generate secrets --------------------------------------------------------

generate_secret() { openssl rand -base64 "$1" | tr -d '/+=' | head -c "$1"; }
generate_hex()    { openssl rand -hex "$1"; }

POSTGRES_PASSWORD=$(generate_secret 32)
SONAR_DB_PASSWORD=$(generate_secret 32)
DOJO_DB_PASSWORD=$(generate_secret 32)
DOJO_SECRET_KEY=$(generate_secret 48)
DOJO_AES_KEY=$(generate_hex 16)
WOODPECKER_AGENT_SECRET=$(generate_secret 40)
ZAP_API_KEY=$(generate_secret 24)

log "Generated unique secrets for all services"

# --- Install system packages -------------------------------------------------

log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

log "Installing dependencies..."
apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    unzip \
    jq \
    "${PYTHON_VERSION}" \
    "${PYTHON_VERSION}-venv" \
    "${PYTHON_VERSION}-dev" \
    python3-pip \
    ufw \
    cron

# --- Install Docker -----------------------------------------------------------

if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
      https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    log "Docker installed: $(docker --version)"
else
    log "Docker already installed: $(docker --version)"
fi

# --- SonarQube kernel tuning -------------------------------------------------

log "Setting kernel parameters for SonarQube..."
sysctl_conf="/etc/sysctl.d/99-pli-security.conf"
cat > "$sysctl_conf" <<'SYSCTL'
# Required by SonarQube (Elasticsearch)
vm.max_map_count=524288
fs.file-max=131072

# General hardening
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
SYSCTL
sysctl --system -q

# --- Create service user and directory structure -----------------------------

log "Creating service user and directories..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
fi
usermod -aG docker "$SERVICE_USER"

mkdir -p \
    "${INSTALL_DIR}/riskdesk" \
    "${INSTALL_DIR}/pipeline" \
    "${INSTALL_DIR}/scripts" \
    "${INSTALL_DIR}/backups"

# --- Deploy RiskDesk ---------------------------------------------------------

log "Deploying RiskDesk..."

# If the archive exists in the same directory as this script, extract it.
# Otherwise assume the riskdesk directory is already at INSTALL_DIR/riskdesk.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/riskdesk.zip" ]; then
    log "Extracting riskdesk.zip..."
    cd /tmp
    rm -rf riskdesk_extract
    mkdir riskdesk_extract
    unzip -qo "${SCRIPT_DIR}/riskdesk.zip" -d riskdesk_extract
    # Handle nested directory (riskdesk/riskdesk or just riskdesk)
    if [ -d riskdesk_extract/riskdesk/app ]; then
        cp -a riskdesk_extract/riskdesk/* "${INSTALL_DIR}/riskdesk/"
    elif [ -d riskdesk_extract/app ]; then
        cp -a riskdesk_extract/* "${INSTALL_DIR}/riskdesk/"
    fi
    rm -rf riskdesk_extract
elif [ ! -f "${INSTALL_DIR}/riskdesk/app/main.py" ]; then
    err "No riskdesk.zip found and ${INSTALL_DIR}/riskdesk/app/main.py does not exist."
    err "Place riskdesk.zip next to this script, or copy the riskdesk directory to ${INSTALL_DIR}/riskdesk/"
    exit 1
fi

# Create Python virtual environment
log "Setting up Python virtual environment..."
cd "${INSTALL_DIR}/riskdesk"
${PYTHON_VERSION} -m venv .venv
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
deactivate

# Write RiskDesk .env
log "Writing RiskDesk configuration..."
cat > "${INSTALL_DIR}/riskdesk/.env" <<RISKDESK_ENV
# Auto-generated by deploy.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Do not commit this file.

# --- Connector credentials (configure from the UI or fill in here) ----------
WIZ_CLIENT_ID=
WIZ_CLIENT_SECRET=
WIZ_API_URL=https://api.us17.app.wiz.io/graphql
WIZ_AUTH_URL=https://auth.app.wiz.io/oauth/token
WIZ_AUDIENCE=wiz-api
WIZ_PAGE_SIZE=500

FALCON_CLIENT_ID=
FALCON_CLIENT_SECRET=
FALCON_BASE_URL=https://api.crowdstrike.com
FALCON_MEMBER_CID=
FALCON_PAGE_SIZE=400
FALCON_FILTER_FQL=status:!'closed'

GITHUB_TOKEN=
GITHUB_ORG=
GITHUB_API_URL=https://api.github.com
GITHUB_DEPENDABOT=1
GITHUB_CODE_SCANNING=1
GITHUB_SECRET_SCANNING=1

# --- People -----------------------------------------------------------------
RISKDESK_ORG_NAME=PLI
RISKDESK_USERS=lucas,liang,ezechias,derron,igor,eric.poon,chris
RISKDESK_APPROVERS=chris,eric.poon,lucas,liang
RISKDESK_DEFAULT_USER=lucas
RISKDESK_REQUIRE_SEPARATE_APPROVER=1
RISKDESK_STALE_DAYS=14

# --- Authentication ---------------------------------------------------------
RISKDESK_AUTH_MODE=none
RISKDESK_SESSION_HOURS=12
RISKDESK_SCHEDULER_ENABLED=1
RISKDESK_ENV


# Initialize the database
log "Initializing RiskDesk database..."
cd "${INSTALL_DIR}/riskdesk"
.venv/bin/python -m app.cli init

# Create systemd service for RiskDesk
log "Creating RiskDesk systemd service..."
cat > /etc/systemd/system/riskdesk.service <<UNIT
[Unit]
Description=RiskDesk Vulnerability Adjudication
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/riskdesk
Environment=PATH=${INSTALL_DIR}/riskdesk/.venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=${INSTALL_DIR}/riskdesk/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${RISKDESK_PORT} \
    --workers 2 \
    --log-level info \
    --access-log
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=riskdesk

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}/riskdesk/data
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

# --- Deploy DevSecOps Pipeline -----------------------------------------------

log "Deploying DevSecOps pipeline..."

if [ -f "${SCRIPT_DIR}/devsecops-pipeline.zip" ]; then
    log "Extracting devsecops-pipeline.zip..."
    cd /tmp
    rm -rf pipeline_extract
    mkdir pipeline_extract
    unzip -qo "${SCRIPT_DIR}/devsecops-pipeline.zip" -d pipeline_extract
    if [ -d pipeline_extract/devsecops-pipeline/docker-compose.yml ]; then
        cp -a pipeline_extract/devsecops-pipeline/* "${INSTALL_DIR}/pipeline/"
    elif [ -f pipeline_extract/docker-compose.yml ]; then
        cp -a pipeline_extract/* "${INSTALL_DIR}/pipeline/"
    fi
    rm -rf pipeline_extract
elif [ ! -f "${INSTALL_DIR}/pipeline/docker-compose.yml" ]; then
    err "No devsecops-pipeline.zip found and ${INSTALL_DIR}/pipeline/docker-compose.yml does not exist."
    exit 1
fi

# Write pipeline .env with generated secrets
log "Writing pipeline configuration..."
cat > "${INSTALL_DIR}/pipeline/.env" <<PIPELINE_ENV
# Auto-generated by deploy.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

HOST_IP=${HOST_IP}

# Gitea → Woodpecker OAuth (fill in after first-time Gitea setup)
GITEA_OAUTH_CLIENT_ID=
GITEA_OAUTH_CLIENT_SECRET=

# Woodpecker
WOODPECKER_ADMIN=lucas
WOODPECKER_AGENT_SECRET=${WOODPECKER_AGENT_SECRET}

# Database passwords (auto-generated, unique to this deployment)
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
SONAR_DB_PASSWORD=${SONAR_DB_PASSWORD}
DOJO_DB_PASSWORD=${DOJO_DB_PASSWORD}

# DefectDojo
DOJO_SECRET_KEY=${DOJO_SECRET_KEY}
DOJO_AES_KEY=${DOJO_AES_KEY}
DOJO_API_TOKEN=

# OWASP ZAP
ZAP_API_KEY=${ZAP_API_KEY}

# RiskDesk integration (auto-configured after first boot)
RISKDESK_PIPELINE_TOKEN=

# Agent intervals
TRIVY_SCAN_INTERVAL=3600
OPENSCAP_SCAN_INTERVAL=86400
PIPELINE_ENV

# Update postgres init script with generated passwords
mkdir -p "${INSTALL_DIR}/pipeline/configs/postgres"
cat > "${INSTALL_DIR}/pipeline/configs/postgres/init.sql" <<PGSQL
CREATE USER sonarqube WITH PASSWORD '${SONAR_DB_PASSWORD}';
CREATE DATABASE sonarqube OWNER sonarqube;
CREATE USER defectdojo WITH PASSWORD '${DOJO_DB_PASSWORD}';
CREATE DATABASE defectdojo OWNER defectdojo;
PGSQL

# Remap DefectDojo port to 8880 to avoid collision with RiskDesk on 8080
log "Adjusting DefectDojo port mapping to 8880..."
if grep -q '"8080:8080"' "${INSTALL_DIR}/pipeline/docker-compose.yml"; then
    sed -i 's/"8080:8080"/"8880:8080"/' "${INSTALL_DIR}/pipeline/docker-compose.yml"
fi

# --- Build and start the pipeline stack --------------------------------------

log "Building and starting Docker Compose stack..."
cd "${INSTALL_DIR}/pipeline"
docker compose build --quiet 2>/dev/null || true
docker compose up -d

log "Waiting for containers to stabilize..."
sleep 15

# Check container health
RUNNING=$(docker ps --format '{{.Names}}' | grep -c '^pli-' || true)
log "Pipeline containers running: ${RUNNING}"

# --- Create Woodpecker helper script ----------------------------------------

cat > "${INSTALL_DIR}/scripts/configure-woodpecker.sh" <<'WPHELPER'
#!/usr/bin/env bash
# Usage: configure-woodpecker.sh <gitea_oauth_client_id> <gitea_oauth_client_secret>
set -euo pipefail
if [ $# -ne 2 ]; then
    echo "Usage: $0 <client_id> <client_secret>"
    echo ""
    echo "Steps:"
    echo "  1. Open Gitea at http://$(hostname -I | awk '{print $1}'):3000"
    echo "  2. Create an admin account"
    echo "  3. Go to Settings → Applications → OAuth2 Applications"
    echo "  4. Create a new app:"
    echo "     Name: Woodpecker CI"
    echo "     Redirect URI: http://$(hostname -I | awk '{print $1}'):8000/authorize"
    echo "  5. Copy the Client ID and Client Secret"
    echo "  6. Run: $0 <client_id> <client_secret>"
    exit 1
fi

ENV_FILE="/opt/pli-security/pipeline/.env"
sed -i "s|^GITEA_OAUTH_CLIENT_ID=.*|GITEA_OAUTH_CLIENT_ID=$1|" "$ENV_FILE"
sed -i "s|^GITEA_OAUTH_CLIENT_SECRET=.*|GITEA_OAUTH_CLIENT_SECRET=$2|" "$ENV_FILE"

cd /opt/pli-security/pipeline
docker compose restart woodpecker-server woodpecker-agent
echo "Woodpecker restarted with OAuth credentials."
echo "Open http://$(hostname -I | awk '{print $1}'):8000 and log in via Gitea."
WPHELPER
chmod +x "${INSTALL_DIR}/scripts/configure-woodpecker.sh"

# --- Wire RiskDesk to the pipeline -------------------------------------------

log "Creating RiskDesk pipeline API token..."
cd "${INSTALL_DIR}/riskdesk"
PIPELINE_TOKEN=$(.venv/bin/python -c "
from app.db import SessionLocal
from app.models import User
from app.tokens import create_token

db = SessionLocal()
user = db.query(User).filter(User.username == 'lucas').first()
if not user:
    print('ERROR: no lucas user')
    exit(1)
_, plaintext = create_token(db, user, 'DevSecOps Pipeline', expires_days=365)
db.close()
print(plaintext)
" 2>/dev/null || echo "")

if [ -n "$PIPELINE_TOKEN" ] && [ "$PIPELINE_TOKEN" != "ERROR: no lucas user" ]; then
    # Write the token into the pipeline .env
    sed -i "s|^RISKDESK_PIPELINE_TOKEN=.*|RISKDESK_PIPELINE_TOKEN=${PIPELINE_TOKEN}|" \
        "${INSTALL_DIR}/pipeline/.env"
    log "Pipeline API token created and configured"

    # Restart agents so they pick up the token
    cd "${INSTALL_DIR}/pipeline"
    docker compose restart trivy-agent openscap-agent 2>/dev/null || true
else
    warn "Could not create pipeline API token. Create one manually from the RiskDesk Settings tab."
fi

# --- Set ownership -----------------------------------------------------------

log "Setting file ownership..."
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
# Docker socket needs to stay root-accessible; the service user is in the docker group
chmod 600 "${INSTALL_DIR}/riskdesk/.env"
chmod 600 "${INSTALL_DIR}/pipeline/.env"

# --- Start RiskDesk ----------------------------------------------------------

log "Starting RiskDesk service..."
mkdir -p "${INSTALL_DIR}/riskdesk/data"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}/riskdesk/data"
systemctl daemon-reload
systemctl enable riskdesk
systemctl start riskdesk

# Wait for RiskDesk to be ready
log "Waiting for RiskDesk to start..."
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${RISKDESK_PORT}/api/findings?page_size=1" >/dev/null 2>&1; then
        log "RiskDesk is ready"
        break
    fi
    sleep 2
done

# --- Cron jobs ---------------------------------------------------------------

log "Setting up nightly housekeeping..."
cat > /etc/cron.d/pli-security <<CRON
# PLI Security Platform — nightly housekeeping
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

# Expire lapsed decisions and clean up sessions (2:00 AM)
0 2 * * * ${SERVICE_USER} cd ${INSTALL_DIR}/riskdesk && .venv/bin/python -m app.cli expire >> /var/log/riskdesk-housekeeping.log 2>&1

# EPSS + KEV feed enrichment (3:00 AM)
0 3 * * * ${SERVICE_USER} cd ${INSTALL_DIR}/riskdesk && .venv/bin/python -c "from app.enrichment import enrich_all; from app.db import SessionLocal; db=SessionLocal(); enrich_all(db); db.close()" >> /var/log/riskdesk-enrichment.log 2>&1

# Backup RiskDesk database (4:00 AM)
0 4 * * * ${SERVICE_USER} cp ${INSTALL_DIR}/riskdesk/data/riskdesk.db ${INSTALL_DIR}/backups/riskdesk-\$(date +\%Y\%m\%d).db 2>/dev/null; find ${INSTALL_DIR}/backups -name 'riskdesk-*.db' -mtime +30 -delete

# Backup Docker volumes (Sunday 5:00 AM)
0 5 * * 0 root cd ${INSTALL_DIR}/pipeline && docker compose pause && tar czf ${INSTALL_DIR}/backups/pipeline-volumes-\$(date +\%Y\%m\%d).tar.gz -C /var/lib/docker/volumes . 2>/dev/null && docker compose unpause; find ${INSTALL_DIR}/backups -name 'pipeline-volumes-*.tar.gz' -mtime +60 -delete
CRON
chmod 644 /etc/cron.d/pli-security

# --- Firewall ----------------------------------------------------------------

log "Configuring UFW firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

# RiskDesk
ufw allow "${RISKDESK_PORT}/tcp" comment "RiskDesk"

# Pipeline services (restrict to your network in production)
ufw allow 3000/tcp comment "Gitea"
ufw allow 8000/tcp comment "Woodpecker CI"
ufw allow 9090/tcp comment "SonarQube"
ufw allow 8880/tcp comment "DefectDojo"
# ZAP API should NOT be exposed externally — internal only
# ufw allow 8090/tcp comment "ZAP API"

ufw --force enable
log "Firewall configured"

# --- Create status check script ----------------------------------------------

cat > "${INSTALL_DIR}/scripts/status.sh" <<'STATUS'
#!/usr/bin/env bash
echo "=========================================="
echo "PLI Security Platform — Status"
echo "=========================================="
echo ""
echo "--- RiskDesk ---"
systemctl is-active riskdesk && echo "  URL: http://$(hostname -I | awk '{print $1}'):8080" || echo "  NOT RUNNING"
echo ""
echo "--- Pipeline Containers ---"
docker ps --format "  {{.Names}}\t{{.Status}}" --filter "name=pli-" 2>/dev/null || echo "  Docker not available"
echo ""
echo "--- Disk Usage ---"
echo "  RiskDesk DB: $(du -sh /opt/pli-security/riskdesk/data/ 2>/dev/null | cut -f1)"
echo "  Docker:      $(docker system df --format '{{.Size}}' 2>/dev/null | head -1)"
echo "  Backups:     $(du -sh /opt/pli-security/backups/ 2>/dev/null | cut -f1)"
echo ""
echo "--- Memory ---"
free -h | head -2
echo ""
echo "--- Services ---"
echo "  RiskDesk:    http://$(hostname -I | awk '{print $1}'):8080"
echo "  Gitea:       http://$(hostname -I | awk '{print $1}'):3000"
echo "  Woodpecker:  http://$(hostname -I | awk '{print $1}'):8000"
echo "  SonarQube:   http://$(hostname -I | awk '{print $1}'):9090"
echo "  DefectDojo:  http://$(hostname -I | awk '{print $1}'):8880"
STATUS
chmod +x "${INSTALL_DIR}/scripts/status.sh"

# --- Create uninstall script -------------------------------------------------

cat > "${INSTALL_DIR}/scripts/uninstall.sh" <<'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail
echo "This will stop all services and remove the PLI Security Platform."
read -rp "Are you sure? [y/N] " yn
[ "$yn" = "y" ] || [ "$yn" = "Y" ] || exit 1

systemctl stop riskdesk 2>/dev/null || true
systemctl disable riskdesk 2>/dev/null || true
rm -f /etc/systemd/system/riskdesk.service
systemctl daemon-reload

cd /opt/pli-security/pipeline 2>/dev/null && docker compose down -v 2>/dev/null || true

rm -f /etc/cron.d/pli-security
rm -f /etc/sysctl.d/99-pli-security.conf

echo "Services stopped. Data remains at /opt/pli-security/"
echo "To fully remove: rm -rf /opt/pli-security && userdel plisec"
UNINSTALL
chmod +x "${INSTALL_DIR}/scripts/uninstall.sh"

# --- Summary -----------------------------------------------------------------

echo ""
echo "=========================================================================="
echo -e "${GREEN}  PLI Security Platform — Deployment Complete${NC}"
echo "=========================================================================="
echo ""
echo "  Services:"
echo "    RiskDesk      http://${HOST_IP}:${RISKDESK_PORT}"
echo "    Gitea         http://${HOST_IP}:3000"
echo "    Woodpecker    http://${HOST_IP}:8000"
echo "    SonarQube     http://${HOST_IP}:9090"
echo "    DefectDojo    http://${HOST_IP}:8880"
echo ""
echo "  Files:"
echo "    Install dir   ${INSTALL_DIR}/"
echo "    RiskDesk env  ${INSTALL_DIR}/riskdesk/.env"
echo "    Pipeline env  ${INSTALL_DIR}/pipeline/.env"
echo "    Backups       ${INSTALL_DIR}/backups/"
echo "    Logs          journalctl -u riskdesk"
echo ""
echo "  Helper scripts:"
echo "    Status        ${INSTALL_DIR}/scripts/status.sh"
echo "    Uninstall     ${INSTALL_DIR}/scripts/uninstall.sh"
echo ""
echo "  Nightly jobs:"
echo "    2:00 AM       Expire lapsed decisions, clean sessions"
echo "    3:00 AM       Update EPSS + KEV feeds"
echo "    4:00 AM       Backup RiskDesk database"
echo "    Sunday 5 AM   Backup Docker volumes"
echo ""
echo -e "${YELLOW}  First-time setup (manual):${NC}"
echo "    1. Open Gitea at http://${HOST_IP}:3000"
echo "       Create an admin account (username: lucas)"
echo ""
echo "    2. In Gitea → Settings → Applications → OAuth2 Applications:"
echo "       Create app: Name='Woodpecker CI'"
echo "       Redirect URI: http://${HOST_IP}:8000/authorize"
echo ""
echo "    3. Run:"
echo "       sudo ${INSTALL_DIR}/scripts/configure-woodpecker.sh <client_id> <client_secret>"
echo ""
echo "    4. Open Woodpecker at http://${HOST_IP}:8000 and log in via Gitea"
echo ""
echo "    5. Add connector credentials in RiskDesk → Sources tab"
echo "       (Wiz, Falcon, GitHub — or configure in ${INSTALL_DIR}/riskdesk/.env)"
echo ""
if [ -n "$PIPELINE_TOKEN" ] && [ "$PIPELINE_TOKEN" != "ERROR: no lucas user" ]; then
echo -e "  ${GREEN}Pipeline API token auto-configured.${NC}"
echo "  Agents will report to RiskDesk automatically."
else
echo -e "  ${YELLOW}Create a pipeline API token in RiskDesk → Settings → API tokens${NC}"
echo "  and add it to ${INSTALL_DIR}/pipeline/.env as RISKDESK_PIPELINE_TOKEN"
fi
echo ""
echo "=========================================================================="
