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
    python3.11 python3.11-venv python3-pip \
    git curl ca-certificates \
    ufw unattended-upgrades fail2ban \
    sqlite3 cron rsync debian-keyring debian-archive-keyring apt-transport-https

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
    msg "Creating Python virtualenv"
    sudo -u "$APP_USER" python3.11 -m venv "$APP_DIR/.venv"
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

# sudoers: deploy user may restart the app only
cat > /etc/sudoers.d/riskdesk-deploy <<EOF
Defaults!/bin/systemctl !requiretty
$DEPLOY_USER ALL=(root) NOPASSWD: /bin/systemctl restart riskdesk, /bin/systemctl status riskdesk
$APP_USER   ALL=(root) NOPASSWD: /bin/systemctl restart riskdesk, /bin/systemctl status riskdesk
EOF
chmod 0440 /etc/sudoers.d/riskdesk-deploy

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
  4. Start services:         sudo systemctl enable --now riskdesk caddy
  5. From your dev machine:  git remote add vm $DEPLOY_USER@<vm-host>:$GIT_DIR
                             git push vm HEAD:main

Logs:
  journalctl -u riskdesk -f
  tail -f $LOG_DIR/deploy-*.log
EOF
