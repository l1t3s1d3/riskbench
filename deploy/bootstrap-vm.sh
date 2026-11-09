#!/usr/bin/env bash
# One-shot VM bootstrap for RiskDesk. Run as root (or with sudo) on a fresh
# Debian 12 / Ubuntu 24.04 host. Idempotent: safe to re-run.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
fi

APP_USER=riskdesk
DEPLOY_USER=deploy
APP_DIR=/opt/riskdesk
DATA_DIR=/var/lib/riskdesk
LOG_DIR=/var/log/riskdesk
ETC_DIR=/etc/riskdesk
GIT_DIR=/srv/git/riskbench.git
HERE="$(cd "$(dirname "$0")" && pwd)"

msg() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

msg "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    git curl ca-certificates software-properties-common gnupg lsb-release \
    ufw unattended-upgrades fail2ban \
    sqlite3 cron rsync debian-keyring debian-archive-keyring apt-transport-https

# ---- Pick a Python >= 3.11 ------------------------------------------------
# Debian 12 and Ubuntu 24.04+ have 3.11 or newer in the default repos; on
# older Ubuntu we add the deadsnakes PPA. If none of that works we fall back
# to the system python3 if it is already 3.11 or newer.
msg "Installing Python 3.11+"
PY_BIN=""
if apt-get install -y -qq python3.11 python3.11-venv python3.11-distutils 2>/dev/null; then
    PY_BIN=python3.11
elif [[ -f /etc/lsb-release ]] && grep -q Ubuntu /etc/lsb-release; then
    msg "Enabling deadsnakes PPA for Python 3.11"
    add-apt-repository -y ppa:deadsnakes/ppa >/dev/null
    apt-get update -qq
    apt-get install -y -qq python3.11 python3.11-venv python3.11-distutils
    PY_BIN=python3.11
elif command -v python3 >/dev/null; then
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=${PY_VER%.*}; PY_MINOR=${PY_VER#*.}
    if (( PY_MAJOR == 3 && PY_MINOR >= 11 )); then
        msg "Using system python3 ($PY_VER) — new enough"
        apt-get install -y -qq python3-venv python3-pip
        PY_BIN=python3
    fi
fi
if [[ -z "$PY_BIN" ]]; then
    echo "No usable Python 3.11+ found. Install one and re-run." >&2
    echo "On Debian/Ubuntu: 'apt install python3.11 python3.11-venv'" >&2
    exit 1
fi
# Record for deploy.sh and anything else that needs to know which binary to use.
install -d -m 0755 /etc/riskdesk
echo "$PY_BIN" > /etc/riskdesk/python-binary
chmod 0644 /etc/riskdesk/python-binary
msg "Using Python interpreter: $PY_BIN ($(command -v $PY_BIN))"

# Caddy from its own apt repo
if ! command -v caddy >/dev/null; then
    msg "Installing Caddy"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    apt-get update -qq
    apt-get install -y -qq caddy
fi

# gitleaks (secret scanning) - static binary release
if ! command -v gitleaks >/dev/null; then
    msg "Installing gitleaks"
    GITLEAKS_VERSION=8.21.2
    curl -fsSL \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tgz
    tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks
    rm -f /tmp/gitleaks.tgz /tmp/gitleaks
fi

msg "Creating service and deploy users"
id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$APP_DIR" "$APP_USER"
id -u "$DEPLOY_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$DEPLOY_USER"
usermod -aG "$APP_USER" "$DEPLOY_USER"

msg "Creating directories"
install -d -o "$APP_USER" -g "$APP_USER" -m 0755 "$APP_DIR"
install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$DATA_DIR"
install -d -o "$APP_USER" -g "$APP_USER" -m 0755 "$LOG_DIR"
install -d -o root       -g "$APP_USER" -m 0750 "$ETC_DIR"

# App venv is created once; deploy.sh keeps it fresh.
if [[ ! -d "$APP_DIR/.venv" ]]; then
    msg "Creating Python virtualenv with $PY_BIN"
    sudo -u "$APP_USER" "$PY_BIN" -m venv "$APP_DIR/.venv"
    sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
fi

msg "Installing deploy scripts to $APP_DIR"
install -o root -g "$APP_USER" -m 0750 "$HERE/deploy.sh"        "$APP_DIR/deploy.sh"
install -o root -g "$APP_USER" -m 0750 "$HERE/security-scan.sh" "$APP_DIR/security-scan.sh"
install -o root -g "$APP_USER" -m 0750 "$HERE/backup.sh"        "$APP_DIR/backup.sh"
install -o root -g "$APP_USER" -m 0750 "$HERE/rollback.sh"      "$APP_DIR/rollback.sh"

msg "Installing systemd unit"
install -o root -g root -m 0644 "$HERE/riskdesk.service" /etc/systemd/system/riskdesk.service
systemctl daemon-reload

msg "Installing Caddy configuration"
install -o root -g root -m 0644 "$HERE/Caddyfile" /etc/caddy/Caddyfile

# Env file -- do not overwrite an existing one on re-run.
if [[ ! -f "$ETC_DIR/env" ]]; then
    msg "Writing env template to $ETC_DIR/env (fill it in before starting the service)"
    install -o root -g "$APP_USER" -m 0640 "$HERE/riskdesk.env.example" "$ETC_DIR/env"
fi

# Bare git repo + hook
if [[ ! -d "$GIT_DIR" ]]; then
    msg "Initialising bare git repo at $GIT_DIR"
    install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 0755 "$(dirname "$GIT_DIR")"
    sudo -u "$DEPLOY_USER" git init --bare --initial-branch=main "$GIT_DIR" >/dev/null
fi
install -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 0755 \
    "$HERE/post-receive" "$GIT_DIR/hooks/post-receive"

# SSH auth for deploy user
if [[ ! -d /home/$DEPLOY_USER/.ssh ]]; then
    install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 0700 /home/$DEPLOY_USER/.ssh
fi
if [[ ! -f /home/$DEPLOY_USER/.ssh/authorized_keys ]]; then
    install -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 0600 /dev/null \
        /home/$DEPLOY_USER/.ssh/authorized_keys
    msg "Append your dev-machine public key to /home/$DEPLOY_USER/.ssh/authorized_keys"
fi

# sudoers: deploy user may restart the app only. Write to a staging file,
# validate with visudo -c, then move it into place -- a bad sudoers file
# locks everyone out, including root in some cases.
STAGE=$(mktemp)
cat > "$STAGE" <<EOF
$DEPLOY_USER ALL=(root) NOPASSWD: /bin/systemctl restart riskdesk, /bin/systemctl status riskdesk, /bin/systemctl enable riskdesk, /bin/systemctl start riskdesk
$APP_USER    ALL=(root) NOPASSWD: /bin/systemctl restart riskdesk, /bin/systemctl status riskdesk
EOF
chmod 0440 "$STAGE"
if ! visudo -cf "$STAGE" >/dev/null; then
    echo "sudoers fragment failed syntax check:" >&2
    cat "$STAGE" >&2
    rm -f "$STAGE"
    exit 1
fi
mv "$STAGE" /etc/sudoers.d/riskdesk-deploy
# Remove any broken fragment from a previous run.
rm -f /etc/sudoers.d/riskdesk-deploy.bak

# Firewall
msg "Configuring firewall (ufw)"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH' >/dev/null
ufw allow 443/tcp comment 'HTTPS' >/dev/null
ufw allow 80/tcp comment 'HTTP for ACME challenge' >/dev/null
ufw --force enable >/dev/null

# Unattended security updates
msg "Enabling unattended security upgrades"
dpkg-reconfigure -f noninteractive unattended-upgrades

# Daily backup cron
msg "Installing daily backup cron"
cat > /etc/cron.daily/riskdesk-backup <<EOF
#!/bin/sh
exec $APP_DIR/backup.sh
EOF
chmod 0755 /etc/cron.daily/riskdesk-backup

cat <<EOF

$(printf '\033[1;32mDone.\033[0m')

Next steps:
  1. Fill in secrets:        sudoedit $ETC_DIR/env
  2. Add your SSH key:       nano /home/$DEPLOY_USER/.ssh/authorized_keys
  3. Edit Caddyfile:         sudoedit /etc/caddy/Caddyfile  (set your hostname)
  4. Start Caddy:            sudo systemctl enable --now caddy
  5. From your dev machine:  git remote add vm $DEPLOY_USER@<vm-host>:$GIT_DIR
                             git push vm HEAD:main
     The push populates /opt/riskdesk/current and deploy.sh starts the
     service. DO NOT run 'systemctl start riskdesk' before the first push:
     the venv does not exist yet, so the service will crash-loop.
     After the first successful push: sudo systemctl enable riskdesk

Logs:
  journalctl -u riskdesk -f
  tail -f $LOG_DIR/deploy-*.log
EOF
